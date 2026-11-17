"""策略语言：静态校验、三值逻辑求值、可解释判定树。

表达式 AST（JSON 形式）：
    {"op": "attr", "kind": "subject"|"resource", "name": "<属性名>"}
    {"op": "lit",  "value": <字符串|整数|集合>}
    {"op": "eq", "left": <expr>, "right": <expr>}
    {"op": "in", "left": <expr>, "right": <expr>}   # right 静态类型必须是 set
    {"op": "lt", "left": <expr>, "right": <expr>}   # 两侧静态类型必须是 integer
    {"op": "and"|"or", "children": [<expr>, ...]}
    {"op": "not", "child": <expr>}

规则：
    {"id": "...", "action": "...", "effect": "allow"|"deny", "expression": <expr>}

三值逻辑（Kleene 强三值逻辑，未知记为 unknown）：
    NOT unknown = unknown
    AND：含 false 即 false；否则含 unknown 即 unknown；否则 true
    OR ：含 true 即 true；否则含 unknown 即 unknown；否则 false
比较运算（eq/in/lt）任一操作数属性缺失 -> unknown。
只有明确 true 才算规则命中；unknown 不命中。
"""

from __future__ import annotations

from typing import Any

from .errors import ABACError, ErrorCode
from .model import MISSING, normalize

TRIBOOL_LABELS = {True: "true", False: "false", None: "unknown"}

_ATTR_KINDS = ("subject", "resource")
_COMPARISONS = ("eq", "in", "lt")
_BOOLEAN_OPS = ("and", "or", "not")


# --------------------------------------------------------------------------- #
# 静态校验
# --------------------------------------------------------------------------- #

def _require_dict(node: Any, path: str, errors: list[str]) -> bool:
    if not isinstance(node, dict):
        errors.append(f"{path}: 表达式必须是对象，得到 {type(node).__name__}")
        return False
    return True


def _validate_expr(node: Any, schema: dict, path: str, errors: list[str]) -> str:
    """校验表达式，返回静态类型：string / integer / set / bool。"""
    if not _require_dict(node, path, errors):
        return "bool"
    op = node.get("op")
    if not isinstance(op, str):
        errors.append(f"{path}: 缺少字符串类型的 op 字段")
        return "bool"

    if op == "attr":
        kind = node.get("kind")
        name = node.get("name")
        if kind not in _ATTR_KINDS:
            errors.append(f"{path}: attr.kind 必须是 subject 或 resource，得到 {kind!r}")
            return "bool"
        if not isinstance(name, str) or not name:
            errors.append(f"{path}: attr.name 必须是非空字符串")
            return "bool"
        # 引用检查：属性必须在 schema 中声明，拒绝未知属性引用。
        declared = schema.get(kind, {}).get(name)
        if declared is None:
            errors.append(
                f"{path}: 引用了未声明的属性 {kind}.{name}，"
                f"请先在 schema 中声明或修正属性名"
            )
            return "bool"
        return declared

    if op == "lit":
        if "value" not in node:
            errors.append(f"{path}: lit 节点缺少 value 字段")
            return "bool"
        try:
            value = normalize(node["value"])
        except ABACError as exc:
            errors.append(f"{path}: {exc.message}")
            return "bool"
        if isinstance(value, frozenset):
            return "set"
        return "integer" if isinstance(value, int) else "string"

    if op in _COMPARISONS:
        left = _validate_expr(node.get("left"), schema, f"{path}.left", errors)
        right = _validate_expr(node.get("right"), schema, f"{path}.right", errors)
        if op == "eq":
            # 同类型才能比较；bool 是谓词类型，不能参与值比较。
            if left != right or left == "bool":
                errors.append(
                    f"{path}: eq 两侧必须是相同的值类型(string/integer/set)，"
                    f"得到 {left} 与 {right}"
                )
        elif op == "in":
            if right != "set":
                errors.append(f"{path}: in 的右侧必须是集合类型，得到 {right}")
            if left not in ("string", "integer"):
                errors.append(
                    f"{path}: in 的左侧必须是字符串或整数，得到 {left}"
                )
            else:
                # 集合元素类型需与左操作数一致（schema 已保证集合声明为 set，
                # 元素类型由字面量在运行时确定，这里再对字面量做一次配对检查）。
                right_node = node.get("right")
                if isinstance(right_node, dict) and right_node.get("op") == "lit":
                    try:
                        lit = normalize(right_node["value"])
                    except ABACError:
                        lit = frozenset()
                    element_kinds = {
                        "integer" if isinstance(x, int) else "string" for x in lit
                    }
                    if element_kinds and element_kinds != {left}:
                        errors.append(
                            f"{path}: 集合元素类型 {sorted(element_kinds)} "
                            f"与左操作数类型 {left} 不一致"
                        )
        else:  # lt
            if left != "integer" or right != "integer":
                errors.append(
                    f"{path}: lt 两侧必须都是 integer，得到 {left} 与 {right}"
                )
        return "bool"

    if op in ("and", "or"):
        children = node.get("children")
        if not isinstance(children, list) or not children:
            errors.append(f"{path}: {op} 需要非空 children 列表")
            return "bool"
        for index, child in enumerate(children):
            child_type = _validate_expr(
                child, schema, f"{path}.children[{index}]", errors
            )
            if child_type != "bool":
                errors.append(
                    f"{path}.children[{index}]: {op} 的子表达式必须是谓词，"
                    f"得到值类型 {child_type}"
                )
        return "bool"

    if op == "not":
        child_type = _validate_expr(node.get("child"), schema, f"{path}.child", errors)
        if child_type != "bool":
            errors.append(f"{path}: not 的子表达式必须是谓词，得到值类型 {child_type}")
        return "bool"

    errors.append(f"{path}: 未知运算符 {op!r}，允许 eq/in/lt/and/or/not/attr/lit")
    return "bool"


def validate_rule(rule: Any, schema: dict, seen_ids: set[str], errors: list[str],
                  path: str = "rule") -> None:
    if not isinstance(rule, dict):
        errors.append(f"{path}: 规则必须是对象")
        return
    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        errors.append(f"{path}: 规则 id 必须是非空字符串")
    elif rule_id in seen_ids:
        errors.append(f"{path}: 规则 id 重复: {rule_id}")
    else:
        seen_ids.add(rule_id)
    action = rule.get("action")
    if not isinstance(action, str) or not action:
        errors.append(f"{path}[{rule_id!r}]: action 必须是非空字符串")
    effect = rule.get("effect")
    if effect not in ("allow", "deny"):
        errors.append(
            f"{path}[{rule_id!r}]: effect 必须是 allow 或 deny，得到 {effect!r}"
        )
    if "expression" not in rule:
        errors.append(f"{path}[{rule_id!r}]: 缺少 expression")
        return
    _validate_expr(rule["expression"], schema, f"{path}[{rule_id!r}].expression",
                   errors)


def validate_policy_doc(doc: Any, schema: dict | None = None) -> dict:
    """校验整份策略文档，返回规范化文档。失败抛 POLICY_VALIDATION_FAILED。

    规范化：集合字面量转 frozenset 后重新 JSON 化的工作在 store 层完成，
    这里只做结构/引用/类型检查并原样返回文档。
    """
    schema = schema or {"subject": {}, "resource": {}}
    errors: list[str] = []
    if not isinstance(doc, dict):
        raise ABACError(
            ErrorCode.POLICY_VALIDATION_FAILED,
            "策略文档必须是对象",
            {"errors": ["文档根节点不是对象"]},
        )
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ABACError(
            ErrorCode.POLICY_VALIDATION_FAILED,
            "策略文档必须包含非空 rules 列表",
            {"errors": ["rules 缺失或为空"]},
        )
    seen_ids: set[str] = set()
    for index, rule in enumerate(rules):
        validate_rule(rule, schema, seen_ids, errors, f"rules[{index}]")
    if errors:
        raise ABACError(
            ErrorCode.POLICY_VALIDATION_FAILED,
            f"策略校验失败，共 {len(errors)} 个问题",
            {"errors": errors},
        )
    return doc


# --------------------------------------------------------------------------- #
# 三值逻辑求值
# --------------------------------------------------------------------------- #

def _render(node: dict) -> str:
    """生成表达式的紧凑可读表示，写入判定树。"""
    op = node["op"]
    if op == "attr":
        return f"{node['kind']}.{node['name']}"
    if op == "lit":
        value = normalize(node["value"])
        if isinstance(value, frozenset):
            body = ", ".join(sorted(repr(x) for x in value))
            return "{" + body + "}"
        return repr(value)
    if op in ("eq", "in", "lt"):
        symbol = {"eq": "==", "in": "in", "lt": "<"}[op]
        return f"({_render(node['left'])} {symbol} {_render(node['right'])})"
    if op in ("and", "or"):
        joiner = " AND " if op == "and" else " OR "
        return "(" + joiner.join(_render(c) for c in node["children"]) + ")"
    return f"(NOT {_render(node['child'])})"


def _resolve_value(node: dict, subject: dict, resource: dict):
    """求 attr/lit 节点的值；属性缺失返回 MISSING。

    注意空集合是合法值，不能用真值判断，必须用 ``in`` 判断键存在性。
    """
    op = node["op"]
    if op == "lit":
        return normalize(node["value"])
    source = subject if node["kind"] == "subject" else resource
    if node["name"] not in source:
        return MISSING
    return source[node["name"]]


def _explain(node: dict, result: bool | None, reasons: list[str],
             children: list[dict]) -> dict:
    return {
        "expr": _render(node),
        "result": TRIBOOL_LABELS[result],
        "reasons": reasons,
        "children": children,
    }


def evaluate_expr(node: dict, subject: dict, resource: dict) -> tuple[bool | None, dict]:
    """递归求值，返回 (三值布尔, 判定树节点)。

    三值用 True / False / None(unknown) 表示。
    """
    op = node["op"]

    if op in ("attr", "lit"):
        value = _resolve_value(node, subject, resource)
        if value is MISSING:
            # 值节点回传 MISSING 哨兵；谓词节点才用 None 表示 unknown。
            return MISSING, _explain(node, None, ["属性缺失，取值为 unknown"], [])
        return value, _explain(node, None, [], [])  # 值节点 result 占位不使用

    if op in _COMPARISONS:
        left_value, left_tree = evaluate_expr(node["left"], subject, resource)
        right_value, right_tree = evaluate_expr(node["right"], subject, resource)
        children = [left_tree, right_tree]
        if left_value is MISSING or right_value is MISSING:
            missing = []
            if left_value is MISSING:
                missing.append(_render(node["left"]))
            if right_value is MISSING:
                missing.append(_render(node["right"]))
            return None, _explain(
                node, None, [f"操作数缺失({', '.join(missing)})，比较结果为 unknown"],
                children,
            )
        if op == "eq":
            outcome = left_value == right_value
        elif op == "in":
            outcome = left_value in right_value
        else:
            outcome = left_value < right_value
        return outcome, _explain(
            node, outcome,
            [f"比较求值为 {TRIBOOL_LABELS[outcome]}"], children,
        )

    if op == "not":
        child_result, child_tree = evaluate_expr(node["child"], subject, resource)
        if child_result is None:
            # 题目明确：NOT unknown 仍为 unknown。
            return None, _explain(
                node, None, ["NOT unknown = unknown（缺失属性取反不产生 true）"],
                [child_tree],
            )
        outcome = not child_result
        return outcome, _explain(
            node, outcome, [f"NOT {TRIBOOL_LABELS[child_result]} = {TRIBOOL_LABELS[outcome]}"],
            [child_tree],
        )

    child_results = []
    child_trees = []
    for child in node["children"]:
        child_result, child_tree = evaluate_expr(child, subject, resource)
        child_results.append(child_result)
        child_trees.append(child_tree)

    if op == "and":
        if False in child_results:
            outcome: bool | None = False
            reason = "AND 含 false，结果为 false"
        elif None in child_results:
            outcome = None
            reason = "AND 无 false 但含 unknown，结果为 unknown"
        else:
            outcome = True
            reason = "AND 全部为 true，结果为 true"
    else:  # or
        if True in child_results:
            outcome = True
            reason = "OR 含 true，结果为 true"
        elif None in child_results:
            outcome = None
            reason = "OR 无 true 但含 unknown，结果为 unknown"
        else:
            outcome = False
            reason = "OR 全部为 false，结果为 false"
    return outcome, _explain(node, outcome, [reason], child_trees)


def evaluate_rule(rule: dict, subject: dict, resource: dict) -> dict:
    """对单条规则求值。返回含命中标志与判定树的结构（不做 action 过滤）。"""
    tribool, tree = evaluate_expr(rule["expression"], subject, resource)
    return {
        "rule_id": rule["id"],
        "action": rule["action"],
        "effect": rule["effect"],
        "tribool": TRIBOOL_LABELS[tribool],
        "matched": tribool is True,  # 只有明确 true 才算命中
        "tree": tree,
    }
