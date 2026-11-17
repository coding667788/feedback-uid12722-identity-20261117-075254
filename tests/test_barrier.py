"""进程屏障检验撤权边界。

场景（题目硬性验收项）：
1. 多个 worker 进程在屏障前各自打开判定句柄——此时数据库快照已固定；
2. 主进程在屏障处等待，确认所有 worker 都已固定快照后才提交撤权；
3. 屏障放行后 worker 才执行判定，必须仍按旧快照得到 allow（在途请求按旧快照完成）；
4. 撤权提交之后才“开始”的新请求（新句柄、新快照）必须得到 deny，
   即使本地缓存里留有旧 allow 条目也不能命中。

Windows 使用 spawn 启动子进程，因此 worker 全部是模块级函数，
数据库路径用绝对路径传递，进程间只通过 multiprocessing 屏障/队列通信。
"""

from __future__ import annotations

import json
import multiprocessing as mp
import tempfile
import unittest
from pathlib import Path

from solution.engine import Engine
from solution.store import Store

SCHEMA = {
    "subject": {"dept": "string", "roles": "set", "clearance": "integer"},
    "resource": {"owner_dept": "string", "sensitivity": "integer"},
}


def _seed_database(db_path: str) -> None:
    store = Store(db_path)
    store.replace_policy("acme", {
        "version": 1,
        "rules": [{
            "id": "read-allow", "action": "read", "effect": "allow",
            "expression": {
                "op": "and",
                "children": [
                    {"op": "eq",
                     "left": {"op": "attr", "kind": "subject", "name": "dept"},
                     "right": {"op": "attr", "kind": "resource",
                               "name": "owner_dept"}},
                    {"op": "in",
                     "left": {"op": "lit", "value": "reader"},
                     "right": {"op": "attr", "kind": "subject", "name": "roles"}},
                ],
            },
        }],
    }, SCHEMA)
    store.put_subject_attrs(
        "acme", "u1", 1, {"dept": "eng", "roles": ["reader"], "clearance": 9}
    )
    store.put_resource_attrs(
        "acme", "doc1", 1, {"owner_dept": "eng", "sensitivity": 2}
    )
    store.close()


def worker_open_snapshot(db_path: str, barrier, queue) -> None:
    """子进程：打开句柄固定快照 -> 屏障等待 -> 屏障后判定。"""
    try:
        store = Store(db_path)
        engine = Engine(store)
        request = {"tenant": "acme", "subject": "u1",
                   "resource": "doc1", "action": "read"}
        # 1) 先做一次判定填充本进程缓存，再重新打开句柄固定新快照。
        warm = engine.decide("acme", "u1", "doc1", "read")
        with engine.open_decision(request) as handle:
            # 2) 快照在此固定；通知主进程“我已在途”，然后在屏障处阻塞。
            queue.put({"phase": "snapshot_fixed",
                       "policy_version": handle._snapshot["policy_version"]})
            barrier.wait()
            # 4) 撤权已在屏障期间由主进程提交；在途请求按旧快照完成。
            result = handle.decide()
        # 5) 句柄结束后开启的全新请求必须看到撤权。
        after = engine.decide("acme", "u1", "doc1", "read")
        store.close()
        queue.put({
            "phase": "done",
            "warm": warm["decision"],
            "inflight": result["decision"],
            "inflight_policy_version": result["versions"]["policy_version"],
            "inflight_cache_hit": result["cache_hit"],
            "after": after["decision"],
            "after_policy_version": after["versions"]["policy_version"],
            "after_cache_hit": after["cache_hit"],
        })
    except Exception as exc:  # pragma: no cover - 失败证据回传
        queue.put({"phase": "error", "error": repr(exc)})


def worker_post_revocation(db_path: str, queue) -> None:
    """撤权提交之后才启动的进程：第一次请求就必须是 deny。"""
    try:
        store = Store(db_path)
        engine = Engine(store)  # 全新进程，缓存为空
        result = engine.decide("acme", "u1", "doc1", "read")
        store.close()
        queue.put({
            "phase": "latecomer",
            "decision": result["decision"],
            "policy_version": result["versions"]["policy_version"],
        })
    except Exception as exc:  # pragma: no cover
        queue.put({"phase": "error", "error": repr(exc)})


class ProcessBarrierRevocationTests(unittest.TestCase):
    def test_revocation_boundary_with_process_barrier(self):
        ctx = mp.get_context("spawn")
        tmpdir = Path(tempfile.mkdtemp(prefix="abac-barrier-"))
        db_path = str((tmpdir / "barrier.db").resolve())
        _seed_database(db_path)

        worker_count = 3
        # 屏障参与方 = worker 数 + 主进程，保证主进程亲眼见到全部快照固定。
        barrier = ctx.Barrier(worker_count + 1)
        queue = ctx.Queue()
        workers = [
            ctx.Process(
                target=worker_open_snapshot,
                args=(db_path, barrier, queue),
            )
            for _ in range(worker_count)
        ]
        for proc in workers:
            proc.start()

        # 收集“快照已固定”信号，全部到齐才允许撤权。
        fixed = []
        for _ in range(worker_count):
            msg = queue.get(timeout=30)
            self.assertEqual(msg["phase"], "snapshot_fixed")
            self.assertEqual(msg["policy_version"], 1)
            fixed.append(msg)
        self.assertEqual(len(fixed), worker_count)

        # 所有在途请求都固定在 v1 快照上后，主进程提交撤权（v2 全量 deny）。
        revoker = Store(db_path)
        revoker.replace_policy("acme", {
            "version": 2,
            "rules": [{
                "id": "deny-all", "action": "read", "effect": "deny",
                "expression": {"op": "eq",
                               "left": {"op": "lit", "value": 1},
                               "right": {"op": "lit", "value": 1}},
            }],
        }, SCHEMA)
        revoker.close()

        # 启动一个撤权后才开始的迟到进程。
        latecomer = ctx.Process(
            target=worker_post_revocation, args=(db_path, queue)
        )
        latecomer.start()

        barrier.wait()  # 放行在途 worker

        for proc in workers:
            proc.join(timeout=30)
            self.assertEqual(proc.exitcode, 0)
        latecomer.join(timeout=30)
        self.assertEqual(latecomer.exitcode, 0)

        # 汇总队列证据并逐条断言。
        done_reports = []
        late_reports = []
        while not queue.empty():
            msg = queue.get_nowait()
            self.assertNotEqual(msg["phase"], "error", msg)
            if msg["phase"] == "done":
                done_reports.append(msg)
            elif msg["phase"] == "latecomer":
                late_reports.append(msg)

        self.assertEqual(len(done_reports), worker_count)
        for report in done_reports:
            self.assertEqual(report["warm"], "allow")
            # 在途请求：按旧快照 allow，证据是版本号仍为 1。
            self.assertEqual(report["inflight"], "allow")
            self.assertEqual(report["inflight_policy_version"], 1)
            # 撤权后的新请求：deny，版本号 2，且不可能命中旧 allow 缓存。
            self.assertEqual(report["after"], "deny")
            self.assertEqual(report["after_policy_version"], 2)
            self.assertFalse(report["after_cache_hit"])

        self.assertEqual(len(late_reports), 1)
        self.assertEqual(late_reports[0]["decision"], "deny")
        self.assertEqual(late_reports[0]["policy_version"], 2)

        # 证据落盘，便于人工核查（固定内容、可重放）。
        evidence = tmpdir / "barrier_evidence.json"
        evidence.write_text(
            json.dumps({"inflight": done_reports, "latecomer": late_reports},
                       ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        self.assertTrue(evidence.is_file())


if __name__ == "__main__":
    unittest.main()
