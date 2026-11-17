"""判定引擎测试：deny 优先、默认拒绝、版本化缓存、快照隔离。"""

from __future__ import annotations

import threading

from solution.engine import Engine
from solution.errors import ABACError, ErrorCode
from solution.store import Store
from tests._helpers import AND, NOT, OR, SCHEMA, StoreTestBase, attr, eq, inn, lit, lt, rule


class DecisionSemanticsTests(StoreTestBase):
    def test_deny_takes_precedence_over_allow(self):
        doc = {
            "version": 1,
            "rules": [
                rule("allow-all", "read", "allow", eq(lit(1), lit(1))),
                rule("deny-all", "read", "deny", eq(lit(1), lit(1))),
            ],
        }
        self.store.replace_policy("acme", doc, SCHEMA)
        result = self.engine.decide("acme", "u1", "r1", "read")
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["matched_rules"]["allow"], ["allow-all"])
        self.assertEqual(result["matched_rules"]["deny"], ["deny-all"])
        self.assertIn("deny 优先", result["reason"])

    def test_default_deny_when_no_rule_matches(self):
        self.install_v1()
        # 主体/资源都不存在：所有比较 unknown，无明确 true。
        result = self.engine.decide("acme", "nobody", "nothing", "read")
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["matched_rules"], {"allow": [], "deny": []})
        self.assertIn("默认拒绝", result["reason"])
        self.assertTrue(
            all(item["tribool"] == "unknown"
                for item in result["evaluated_rules"])
        )

    def test_unknown_action_default_deny(self):
        self.install_v1()
        self._seed()
        result = self.engine.decide("acme", "u1", "doc1", "drop-table")
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["evaluated_rules"], [])
        self.assertEqual(result["matched_rules"], {"allow": [], "deny": []})

    def test_decision_log_persists_versions_and_cache_flag(self):
        self.install_v1()
        self._seed()
        first = self.engine.decide("acme", "u1", "doc1", "read")
        second = self.engine.decide("acme", "u1", "doc1", "read")
        self.assertFalse(first["cache_hit"])
        self.assertTrue(second["cache_hit"])
        log = self.store.list_decision_log(limit=10)
        self.assertEqual(len(log), 2)
        self.assertEqual({row["decision"] for row in log}, {"allow"})
        self.assertEqual({row["policy_version"] for row in log}, {1})
        cache_flags = sorted(row["cache_hit"] for row in log)
        self.assertEqual(cache_flags, [0, 1])
        # 最新一条记录了三元组与匹配规则。
        newest = log[0]
        self.assertEqual((newest["subject_version"], newest["resource_version"]),
                         (1, 1))
        self.assertIn("read-allow", newest["matched_rule_ids"])

    def _seed(self):
        self.store.put_subject_attrs(
            "acme", "u1", 1,
            {"dept": "eng", "roles": ["reader"], "clearance": 9},
        )
        self.store.put_resource_attrs(
            "acme", "doc1", 1, {"owner_dept": "eng", "sensitivity": 2}
        )

    def test_full_decision_payload_contains_three_versions(self):
        self.install_v1()
        self._seed()
        result = self.engine.decide("acme", "u1", "doc1", "read")
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["versions"], {
            "policy_version": 1, "subject_version": 1, "resource_version": 1,
        })
        # 可解释判定树存在且根节点是 AND。
        root = result["evaluated_rules"][0]["tree"]
        self.assertTrue(root["expr"].startswith("(("))
        self.assertEqual(root["result"], "true")
        self.assertEqual(len(root["children"]), 3)

    def test_missing_field_negation_does_not_grant(self):
        # 规则：NOT(dept == "eng")。dept 缺失时 NOT unknown = unknown -> 拒绝。
        doc = {"version": 1, "rules": [
            rule("r", "read", "allow",
                 NOT(eq(attr("subject", "dept"), lit("eng")))),
        ]}
        self.store.replace_policy("acme", doc, SCHEMA)
        missing = self.engine.decide("acme", "u1", "r1", "read")
        self.assertEqual(missing["decision"], "deny")
        self.assertEqual(
            missing["evaluated_rules"][0]["tribool"], "unknown"
        )
        self.store.put_subject_attrs("acme", "u1", 1, {"dept": "sales"})
        present = self.engine.decide("acme", "u1", "r1", "read")
        self.assertEqual(present["decision"], "allow")


class VersionedCacheTests(StoreTestBase):
    def _setup(self):
        self.install_v1()
        self.store.put_subject_attrs(
            "acme", "u1", 1,
            {"dept": "eng", "roles": ["reader"], "clearance": 9},
        )
        self.store.put_resource_attrs(
            "acme", "doc1", 1, {"owner_dept": "eng", "sensitivity": 2}
        )

    def test_cache_hit_then_version_bump_misses(self):
        self._setup()
        first = self.engine.decide("acme", "u1", "doc1", "read")
        second = self.engine.decide("acme", "u1", "doc1", "read")
        self.assertFalse(first["cache_hit"])
        self.assertTrue(second["cache_hit"])
        stats = self.engine.cache_stats()
        self.assertEqual(stats["entries"], 1)
        self.assertEqual(stats["hits"], 1)

        # 资源属性推进版本 -> 新缓存键，旧条目不会被命中。
        self.store.put_resource_attrs(
            "acme", "doc1", 2, {"owner_dept": "eng", "sensitivity": 10}
        )
        third = self.engine.decide("acme", "u1", "doc1", "read")
        self.assertFalse(third["cache_hit"])
        self.assertEqual(third["versions"]["resource_version"], 2)
        self.assertEqual(self.engine.cache_stats()["entries"], 2)

    def test_cache_key_includes_all_identifiers_and_versions(self):
        self._setup()
        snap = {
            "tenant": "t", "subject": "s", "resource": "r",
            "policy_version": 1, "subject_version": 2, "resource_version": 3,
        }
        key = self.engine.cache_key(snap, "read")
        self.assertEqual(key, ("t", "s", "r", "read", 1, 2, 3))
        # 任一维度变化都产生不同键。
        changed = dict(snap, policy_version=2)
        self.assertNotEqual(
            self.engine.cache_key(changed, "read"), key
        )

    def test_revoked_permission_not_served_from_cache(self):
        self._setup()
        allowed = self.engine.decide("acme", "u1", "doc1", "read")
        self.assertEqual(allowed["decision"], "allow")
        # 撤权：新版本策略只保留 deny。
        revoked = {"version": 2, "rules": [
            rule("deny-all", "read", "deny", eq(lit(1), lit(1))),
        ]}
        self.store.replace_policy("acme", revoked, SCHEMA)
        after = self.engine.decide("acme", "u1", "doc1", "read")
        self.assertEqual(after["decision"], "deny")
        self.assertFalse(after["cache_hit"])
        self.assertEqual(after["versions"]["policy_version"], 2)

    def test_disabled_cache_never_hits(self):
        from solution.engine import Engine
        engine = Engine(self.store, cache_enabled=False)
        self._setup()
        engine.decide("acme", "u1", "doc1", "read")
        again = engine.decide("acme", "u1", "doc1", "read")
        self.assertFalse(again["cache_hit"])


class SnapshotIsolationTests(StoreTestBase):
    def test_inflight_request_keeps_old_snapshot(self):
        self.install_v1()
        self.store.put_subject_attrs(
            "acme", "u1", 1,
            {"dept": "eng", "roles": ["reader"], "clearance": 9},
        )
        self.store.put_resource_attrs(
            "acme", "doc1", 1, {"owner_dept": "eng", "sensitivity": 2}
        )
        request = {"tenant": "acme", "subject": "u1",
                   "resource": "doc1", "action": "read"}
        with self.engine.open_decision(request) as handle:
            # 快照已在此固定；另起连接提交撤权。
            other = Store(self.db_path)
            other.replace_policy("acme", {
                "version": 2,
                "rules": [rule("d", "read", "deny", eq(lit(1), lit(1)))],
            }, SCHEMA)
            other.close()
            result = handle.decide()  # 仍按 v1 快照完成
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["versions"]["policy_version"], 1)
        # 句柄结束后，新请求看到撤权后的 v2。
        later = self.engine.decide("acme", "u1", "doc1", "read")
        self.assertEqual(later["decision"], "deny")
        self.assertEqual(later["versions"]["policy_version"], 2)

    def test_concurrent_policy_replace_and_read(self):
        self.install_v1()
        self.store.put_subject_attrs(
            "acme", "u1", 1,
            {"dept": "eng", "roles": ["reader"], "clearance": 9},
        )
        self.store.put_resource_attrs(
            "acme", "doc1", 1, {"owner_dept": "eng", "sensitivity": 2}
        )
        # 读线程使用独立连接，避免与写线程共享同一 SQLite 事务状态。
        reader_store = Store(self.db_path)
        reader_engine = Engine(reader_store)
        errors: list[Exception] = []

        def reader():
            try:
                for _ in range(30):
                    result = reader_engine.decide("acme", "u1", "doc1", "read")
                    # 结果只可能是 allow 或 deny，绝不出现异常或半成品状态。
                    self.assertIn(result["decision"], ("allow", "deny"))
                    self.assertGreaterEqual(
                        result["versions"]["policy_version"], 1
                    )
            except Exception as exc:  # pragma: no cover - 失败证据
                errors.append(exc)

        def writer():
            try:
                for version in range(2, 12):
                    self.store.replace_policy("acme", {
                        "version": version,
                        "rules": [rule(
                            "r", "read",
                            "deny" if version % 2 == 0 else "allow",
                            eq(lit(1), lit(1)),
                        )],
                    }, SCHEMA)
            except ABACError as exc:  # pragma: no cover
                errors.append(exc)

        t1 = threading.Thread(target=reader)
        t2 = threading.Thread(target=writer)
        t1.start(); t2.start()
        t1.join(); t2.join()
        reader_store.close()
        self.assertEqual(errors, [])

    def test_handle_cannot_decide_twice(self):
        self.install_v1()
        with self.engine.open_decision(
            {"tenant": "acme", "subject": "u", "resource": "r", "action": "read"}
        ) as handle:
            handle.decide()
            with self.assertRaises(ABACError) as ctx:
                handle.decide()
            self.assertEqual(ctx.exception.code, ErrorCode.SNAPSHOT_NOT_FINALIZED)


if __name__ == "__main__":
    unittest.main()
