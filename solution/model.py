"""值类型、JSON 编解码与版本号工具。

支持的值（题目限定）：
- 字符串 str
- 整数 int（不允许 bool，bool 在 Python 中是 int 子类，需显式排除）
- 集合 set（集合元素只能是字符串或整数，集合不可嵌套）

存储层另外用 :data:`MISSING` 哨兵表示“属性缺失”，它不会出现在持久化数据中，
只在三值逻辑求值与有限域差分里使用。
"""

from __future__ import annotations

import json
from typing import Any

from .errors import ABACError, ErrorCode

# 三值逻辑 / 有限域差分使用的“属性缺失”哨兵。
MISSING = object()

VALUE_KINDS = ("string", "integer", "set")


def kind_name(value: Any) -> str:
    """返回值的类型名，用于 schema 与报错。"""
    if isinstance(value, bool):
        # 显式拒绝 bool：True/False 不是题目允许的值。
        raise ABACError(
            ErrorCode.TYPE_MISMATCH,
            "布尔值不是受支持的属性值，请使用字符串/整数/集合",
        )
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, (set, frozenset, list, tuple)):
        return "set"
    raise ABACError(
        ErrorCode.TYPE_MISMATCH,
        f"不支持的值类型: {type(value).__name__}，仅允许字符串、整数、集合",
    )


def _check_scalar(value: Any) -> None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ABACError(
            ErrorCode.TYPE_MISMATCH,
            f"集合元素只能是字符串或整数，得到 {type(value).__name__}",
        )


def normalize(value: Any) -> Any:
    """把外部输入规范化为内部规范形式：set/list/tuple -> frozenset，并校验。"""
    kind = kind_name(value)
    if kind == "set":
        items: list[Any] = []
        for item in value:
            _check_scalar(item)
            items.append(item)
        if len(items) != len(set(items)):
            raise ABACError(
                ErrorCode.TYPE_MISMATCH,
                "集合存在重复元素，集合值必须无重复",
            )
        return frozenset(items)
    return value


def encode_value(value: Any) -> str:
    """把值编码为可写入 SQLite TEXT 列的规范 JSON。

    集合排序后编码，保证语义相同的集合字节一致——重复版本内容冲突检测
    依赖这一点（见 store.replace_policy）。
    """
    value = normalize(value)
    if isinstance(value, frozenset):
        payload: Any = sorted(value, key=lambda x: (type(x).__name__, x))
    else:
        payload = value
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def decode_value(raw: str) -> Any:
    """解码存储层 JSON，列表还原为 frozenset。"""
    data = json.loads(raw)
    if isinstance(data, list):
        return frozenset(data)
    return data


def value_to_json(value: Any) -> Any:
    """把内部值转成可放进结果 JSON 的普通对象（frozenset -> 排序列表）。"""
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=lambda x: (type(x).__name__, x))
    return value


def value_from_json(data: Any) -> Any:
    """外部 JSON（列表/标量）-> 内部值。"""
    return normalize(data)


def check_version(version: Any, *, field: str = "version") -> int:
    """校验版本号：必须是非负整数（bool 除外）。0 仅用于“尚无数据”的空快照。"""
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise ABACError(
            ErrorCode.INVALID_INPUT,
            f"{field} 必须是非负整数，得到 {version!r}",
        )
    return version


def check_identifier(value: Any, field: str) -> str:
    """租户/主体/资源/动作等标识符：非空字符串。"""
    if not isinstance(value, str) or not value:
        raise ABACError(
            ErrorCode.INVALID_INPUT,
            f"{field} 必须是非空字符串，得到 {value!r}",
        )
    return value


def canonical_json(obj: Any) -> str:
    """确定性 JSON 序列化，用于同版本内容冲突比较。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
