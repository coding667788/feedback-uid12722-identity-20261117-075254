"""有限属性域上的旧/新策略差分。

思路：在题目允许的小域上做笛卡尔积穷举（每个属性额外加入“缺失”取值，
使缺字段三值逻辑也被覆盖），对每个 (主体属性, 资源属性, 动作) 组合分别用
旧策略与新策略各判定一次，找出“旧拒绝且新允许”的反例——这是策略替换
最需要警惕的权限放大方向。同时给出反向（旧允许新拒绝，即被收窄的权限）。

判定规则与引擎完全一致：deny 优先、默认拒绝、只有明确 true 才算命中。
有限域中 MISSING 取值就是“该属性不出现”，直接走引擎的三值逻辑代码路径。
"""

from __future__ import annotations

import itertools
from typing import Any

from .errors import ABACError, ErrorCode
from .model import MISSING
from .policy import evaluate_rule


def merge_schemas(old_schema: dict, new_schema: dict) -> dict:
    """合并两份 schema：同名属性类型必须一致，否则报 TYPE_MISMATCH。"""
    merged = {"subject": {}, "resource": {}}
    for kind in ("subject", "resource"):
        for schema in (old_schema, new_schema):
            section = schema.get(kind, {})
            for name, attr_type in section.items():
                if name in merged[kind] and merged[kind][name] != attr_type:
                    raise ABACError(
                        ErrorCode.TYPE_MISMATCH,
                        f"属性 {kind}.{name} 在两份 schema 中类型不一致："
                        f"{merged[kind][name]} vs {attr_type}",
                    )
                merged[kind][name] = attr_type
    return merged


def _ordered(values: list[Any]) -> list[Any]:
    """稳定排序：字符串/整数混合域按 (类型名, 值) 排，保证可重放。"""
    return sorted(values, key=lambda x: (type(x).__name__, x))


def _domain_for(kind: str, name: str, attr_type: str,
                domains: dict) -> list[list[Any]]:
    """返回某属性的取值列表，头部插入 MISSING 哨兵。"""
    custom = domains.get(kind, {}).get(name)
    if custom is not None:
        if not isinstance(custom, list) or not custom:
            raise ABACError(
                ErrorCode.INVALID_INPUT,
                f"domain {kind}.{name} 必须是非空列表",
            )
        values = list(custom)
    elif attr_type == "integer":
        # 默认整数小域，固定值保证可重放。
        values = [0, 1]
    elif attr_type == "string":
        values = ["a", "b"]
    else:
        # set：默认 {空集, 单元素集, 双元素集}，元素取标量域。
        scalar = domains.get(kind, {}).get(f"{name}#elements", ["x", "y"])
        values = [frozenset(), frozenset([scalar[0]]), frozenset(scalar[:2])]
    return [MISSING] + values


def _enumerate_assignments(schema: dict, domains: dict) -> list[dict]:
    """枚举主体/资源属性空间，每个点都是一份“属性缺失/取值”组合。"""
    axes: list[tuple[str, str, list[Any]]] = []
    for kind in ("subject", "resource"):
        for name, attr_type in sorted(schema.get(kind, {}).items()):
            axes.append((kind, name, _domain_for(kind, name, attr_type, domains)))

    points: list[dict] = []
    for combo in itertools.product(*(axis[2] for axis in axes)):
        point = {"subject": {}, "resource": {}}
        for (kind, name, _), value in zip(axes, combo):
            if value is not MISSING:
                point[kind][name] = value
        points.append(point)
    return points


def decide_with_doc(doc: dict, subject_attrs: dict, resource_attrs: dict,
                    action: str) -> dict:
    """与 Engine 同语义的纯函数判定（差分不触碰数据库）。"""
    matched_allow: list[str] = []
    matched_deny: list[str] = []
    tribools: dict[str, str] = {}
    for rule in doc.get("rules", []):
        if rule.get("action") != action:
            continue
        report = evaluate_rule(rule, subject_attrs, resource_attrs)
        tribools[rule["id"]] = report["tribool"]
        if report["matched"]:
            if report["effect"] == "deny":
                matched_deny.append(rule["id"])
            else:
                matched_allow.append(rule["id"])
    if matched_deny:
        decision = "deny"
    elif matched_allow:
        decision = "allow"
    else:
        decision = "deny"
    return {
        "decision": decision,
        "matched_allow": matched_allow,
        "matched_deny": matched_deny,
        "tribools": tribools,
    }


def _assignment_to_json(point: dict) -> dict:
    def convert(attrs: dict) -> dict:
        out = {}
        for name, value in sorted(attrs.items()):
            if isinstance(value, frozenset):
                out[name] = {"present": True, "value": _ordered(list(value))}
            else:
                out[name] = {"present": True, "value": value}
        return out

    return {"subject": convert(point["subject"]), "resource": convert(point["resource"])}


def _missing_layout(schema: dict) -> dict:
    """列出每个属性的缺失状态，便于反例直接体现缺字段。"""
    layout = {"subject": {}, "resource": {}}
    for kind in ("subject", "resource"):
        for name in sorted(schema.get(kind, {})):
            layout[kind][name] = "missing"
    return layout


def diff_policies(old_doc: dict, new_doc: dict,
                  old_schema: dict | None = None,
                  new_schema: dict | None = None,
                  *, domains: dict | None = None,
                  actions: list[str] | None = None,
                  limit: int = 100) -> dict:
    """穷举有限域，返回旧/新策略差异，重点输出旧拒绝新允许的反例。

    参数：
        domains: 自定义属性域 ``{"subject": {"name": [..]}, "resource": {...}}``，
                 未声明的属性使用默认小域；所有域自动追加 MISSING。
        actions: 参与差分的动作列表；缺省取两份文档 action 的并集。
        limit:   每类反例最多返回条数（超出部分只计数，不静默丢弃）。
    """
    old_schema = old_schema or {"subject": {}, "resource": {}}
    new_schema = new_schema or {"subject": {}, "resource": {}}
    domains = domains or {}
    schema = merge_schemas(old_schema, new_schema)

    if actions is None:
        action_set = set()
        for doc in (old_doc, new_doc):
            for rule in doc.get("rules", []):
                action_set.add(rule["action"])
        actions = sorted(action_set)
    if not actions:
        raise ABACError(ErrorCode.INVALID_INPUT, "差分至少需要一个 action")

    points = _enumerate_assignments(schema, domains)
    space_size = len(points) * len(actions)

    gained: list[dict] = []   # 旧 deny -> 新 allow（权限放大，必须给反例）
    lost: list[dict] = []     # 旧 allow -> 新 deny（权限收窄）
    stable_same = 0
    gained_truncated = 0
    lost_truncated = 0

    for action in actions:
        for point in points:
            old_result = decide_with_doc(
                old_doc, point["subject"], point["resource"], action
            )
            new_result = decide_with_doc(
                new_doc, point["subject"], point["resource"], action
            )
            if old_result["decision"] == new_result["decision"]:
                stable_same += 1
                continue
            counterexample = {
                "action": action,
                "assignment": _assignment_to_json(point),
                "missing_attrs": {
                    kind: [
                        name for name in sorted(schema.get(kind, {}))
                        if name not in point[kind]
                    ]
                    for kind in ("subject", "resource")
                },
                "old": old_result,
                "new": new_result,
            }
            if old_result["decision"] == "deny" and new_result["decision"] == "allow":
                if len(gained) < limit:
                    gained.append(counterexample)
                else:
                    gained_truncated += 1
            else:
                if len(lost) < limit:
                    lost.append(counterexample)
                else:
                    lost_truncated += 1

    return {
        "summary": {
            "space_size": space_size,
            "assignment_points": len(points),
            "actions": actions,
            "stable_same": stable_same,
            "gained_allow_count": len(gained) + gained_truncated,
            "lost_allow_count": len(lost) + lost_truncated,
            "gained_truncated": gained_truncated,
            "lost_truncated": lost_truncated,
            "limit": limit,
        },
        "schema": schema,
        "missing_layout_template": _missing_layout(schema),
        "gained_allow_examples": gained,
        "lost_allow_examples": lost,
    }
