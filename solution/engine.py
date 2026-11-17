"""判定引擎：同一快照读策略与属性，版本化缓存，deny 优先、默认拒绝。

典型用法（显式句柄，用于需要把“快照固定点”和“判定点”分开的并发场景）::

    with engine.open_decision(request) as handle:
        # __enter__ 中已 begin_snapshot + read_snapshot，WAL 快照在此固定
        barrier.wait()
        result = handle.decide()   # 即使其它进程已提交撤权，仍按旧快照判定

便捷用法（内部就是上面的完整流程）::

    result = engine.decide(tenant, subject, resource, action)
"""

from __future__ import annotations

import copy
from typing import Any

from .errors import ABACError, ErrorCode
from .model import check_identifier, value_to_json
from .policy import evaluate_rule
from .store import Store


def _attrs_to_json(attrs: dict) -> dict:
    return {key: value_to_json(value) for key, value in sorted(attrs.items())}


class DecisionHandle:
    """一次判定请求的快照句柄；只能在 with 块内调用 :meth:`decide`。"""

    def __init__(self, engine: "Engine", request: dict):
        self._engine = engine
        self.tenant = check_identifier(request.get("tenant"), "tenant")
        self.subject = check_identifier(request.get("subject"), "subject")
        self.resource = check_identifier(request.get("resource"), "resource")
        self.action = check_identifier(request.get("action"), "action")
        self._snapshot: dict | None = None
        self._cache_hit = False
        self._result: dict | None = None
        self._decided = False

    # ---- 上下文管理：进入即固定数据库快照 ---- #
    def __enter__(self) -> "DecisionHandle":
        store = self._engine.store
        store.begin_snapshot()
        try:
            self._snapshot = store.read_snapshot(
                self.tenant, self.subject, self.resource
            )
            key = self._engine.cache_key(self._snapshot, self.action)
            cached = self._engine.cache_get(key)
            if cached is not None:
                # 命中的缓存条目一定由完全相同的版本三元组计算而来；
                # 旧快照内命中旧版本结果与“按旧快照完成”的语义一致。
                self._cache_hit = True
                self._result = copy.deepcopy(cached)
                self._result["cache_hit"] = True
        except BaseException:
            store.rollback_snapshot()
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        store = self._engine.store
        if exc_type is not None:
            store.rollback_snapshot()
            return None
        store.commit_snapshot()
        if self._result is not None:
            # 提交后再发布缓存与日志：只有完整走完快照的结果才会被缓存。
            if not self._cache_hit:
                self._engine.cache_put(
                    self._engine.cache_key(self._snapshot, self.action),
                    self._result,
                )
            store.append_decision_log(self._result)
        return None

    # ---- 判定 ---- #
    def decide(self) -> dict:
        if self._snapshot is None:
            raise ABACError(
                ErrorCode.SNAPSHOT_NOT_ACTIVE,
                "decide 必须在 open_decision 的 with 块内调用",
            )
        if self._decided:
            raise ABACError(
                ErrorCode.SNAPSHOT_NOT_FINALIZED, "同一个句柄不能重复判定"
            )
        self._decided = True
        if self._cache_hit:
            return copy.deepcopy(self._result)

        snapshot = self._snapshot
        rules = snapshot["policy_doc"].get("rules", [])
        action_rules = [rule for rule in rules if rule.get("action") == self.action]

        rule_reports = []
        matched_allow: list[str] = []
        matched_deny: list[str] = []
        for rule in action_rules:
            report = evaluate_rule(
                rule, snapshot["subject_attrs"], snapshot["resource_attrs"]
            )
            rule_reports.append(report)
            if report["matched"]:
                if report["effect"] == "deny":
                    matched_deny.append(rule["id"])
                else:
                    matched_allow.append(rule["id"])

        # deny 优先；没有任何明确 true 命中（含全 unknown）-> 默认拒绝。
        if matched_deny:
            decision = "deny"
            reason = "命中 deny 规则，deny 优先"
        elif matched_allow:
            decision = "allow"
            reason = "命中 allow 规则且无 deny"
        else:
            decision = "deny"
            reason = "无明确 true 的 allow 命中（含 unknown），默认拒绝"

        self._result = {
            "tenant": self.tenant,
            "subject": self.subject,
            "resource": self.resource,
            "action": self.action,
            "decision": decision,
            "reason": reason,
            "cache_hit": False,
            "versions": {
                "policy_version": snapshot["policy_version"],
                "subject_version": snapshot["subject_version"],
                "resource_version": snapshot["resource_version"],
            },
            "matched_rules": {
                "allow": matched_allow,
                "deny": matched_deny,
            },
            "evaluated_rules": [
                {
                    "rule_id": report["rule_id"],
                    "effect": report["effect"],
                    "tribool": report["tribool"],
                    "matched": report["matched"],
                    "tree": report["tree"],
                }
                for report in rule_reports
            ],
            "snapshot": {
                "subject_attrs": _attrs_to_json(snapshot["subject_attrs"]),
                "resource_attrs": _attrs_to_json(snapshot["resource_attrs"]),
            },
        }
        return copy.deepcopy(self._result)


class Engine:
    """封装 Store、版本化缓存与判定流程。"""

    def __init__(self, store: Store, cache_enabled: bool = True):
        self.store = store
        self._cache: dict[tuple, dict] = {}
        self._cache_enabled = cache_enabled
        self._hits = 0
        self._misses = 0

    # ---- 版本化缓存 ---- #
    @staticmethod
    def cache_key(snapshot: dict, action: str) -> tuple:
        # 键同时包含租户/主体/资源/动作与三个版本；任一版本推进都会产生新键，
        # 撤权提交之后开始的请求不可能再命中旧 allow 条目。
        return (
            snapshot["tenant"],
            snapshot["subject"],
            snapshot["resource"],
            action,
            snapshot["policy_version"],
            snapshot["subject_version"],
            snapshot["resource_version"],
        )

    def cache_get(self, key: tuple) -> dict | None:
        if not self._cache_enabled:
            return None
        value = self._cache.get(key)
        if value is not None:
            self._hits += 1
        return value

    def cache_put(self, key: tuple, result: dict) -> None:
        if self._cache_enabled:
            self._cache[key] = copy.deepcopy(result)

    def cache_clear(self) -> None:
        self._cache.clear()

    def cache_stats(self) -> dict:
        return {
            "enabled": self._cache_enabled,
            "entries": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
        }

    # ---- 入口 ---- #
    def open_decision(self, request: dict) -> DecisionHandle:
        return DecisionHandle(self, request)

    def decide(self, tenant: str, subject: str, resource: str,
               action: str) -> dict[str, Any]:
        request = {
            "tenant": tenant, "subject": subject,
            "resource": resource, "action": action,
        }
        with self.open_decision(request) as handle:
            result = handle.decide()
        if not result["cache_hit"]:
            self._misses += 1
        return result
