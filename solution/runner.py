"""cases.json 批处理运行器。

cases.json 顶层结构::

    {
      "cases": [
        {
          "name": "...",
          "db": "relative/path.db",          // 相对 case 文件所在目录
          "steps": [ { "type": "...", ... }, ... ]
        }
      ]
    }

支持的 step：
    put_subject / put_resource  写属性（版本单调检查交给 store）
    replace_policy              原子策略替换（可带 schema、冲突内容用例）
    decide                      判定，可内联 expect_decision / expect_matched /
                                expect_versions / expect_cache_hit / expect_tribool
    diff                        有限域差分，可 expect_gained_allow_count 等
    diff_stored                 从数据库取两个历史策略版本做差分
    expect_error                断言前一步抛出指定错误码
    inspect_cache               读取缓存统计

文件引用标记（可出现在任意字符串值里，runner 统一解析）：
    {"$file": "path"}                 UTF-8 文本文件，解析为 JSON
    {"$binary": "path", "encoding": "base64"|"hex"|"utf-8"}
                                      读取项目内二进制/文本样例
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

from .diff import diff_policies
from .engine import Engine
from .errors import ABACError, ErrorCode
from .model import value_from_json
from .store import Store

_FILE_MARKER = "$file"
_BINARY_MARKER = "$binary"


def _resolve_markers(obj: Any, base_dir: Path) -> Any:
    if isinstance(obj, dict):
        if set(obj.keys()) >= {_FILE_MARKER}:
            path = base_dir / obj[_FILE_MARKER]
            if not path.is_file():
                raise ABACError(
                    ErrorCode.FILE_NOT_FOUND,
                    f"引用文件不存在: {path}",
                )
            return json.loads(path.read_text(encoding="utf-8"))
        if set(obj.keys()) >= {_BINARY_MARKER}:
            path = base_dir / obj[_BINARY_MARKER]
            if not path.is_file():
                raise ABACError(
                    ErrorCode.FILE_NOT_FOUND,
                    f"引用文件不存在: {path}",
                )
            encoding = obj.get("encoding", "base64")
            raw = path.read_bytes()
            if encoding == "base64":
                return base64.b64encode(raw).decode("ascii")
            if encoding == "hex":
                return raw.hex()
            if encoding == "utf-8":
                return raw.decode("utf-8")
            raise ABACError(
                ErrorCode.UNSUPPORTED_FILE_ENCODING,
                f"不支持的 encoding: {encoding}",
            )
        return {key: _resolve_markers(value, base_dir) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_resolve_markers(item, base_dir) for item in obj]
    return obj


def _attrs_from_json(raw: dict) -> dict:
    return {key: value_from_json(value) for key, value in raw.items()}


def _assert_equal(label: str, actual: Any, expected: Any, failures: list[str]) -> None:
    if actual != expected:
        failures.append(f"{label}: 期望 {expected!r}，实际 {actual!r}")


def _check_expectations(step: dict, result: dict, failures: list[str]) -> None:
    if "expect_decision" in step:
        _assert_equal(
            "expect_decision", result["decision"], step["expect_decision"], failures
        )
    if "expect_cache_hit" in step:
        _assert_equal(
            "expect_cache_hit", result["cache_hit"], step["expect_cache_hit"],
            failures,
        )
    if "expect_versions" in step:
        for key, expected in step["expect_versions"].items():
            _assert_equal(
                f"expect_versions.{key}",
                result["versions"][key], expected, failures,
            )
    if "expect_matched" in step:
        expected = step["expect_matched"]
        actual = result["matched_rules"]
        for effect in ("allow", "deny"):
            if effect in expected:
                _assert_equal(
                    f"expect_matched.{effect}",
                    sorted(actual[effect]), sorted(expected[effect]), failures,
                )
    if "expect_tribool" in step:
        actual_map = {
            item["rule_id"]: item["tribool"]
            for item in result["evaluated_rules"]
        }
        for rule_id, expected in step["expect_tribool"].items():
            _assert_equal(
                f"expect_tribool.{rule_id}",
                actual_map.get(rule_id), expected, failures,
            )


def _run_diff(step: dict) -> dict:
    return diff_policies(
        step["old_doc"], step["new_doc"],
        step.get("old_schema"), step.get("new_schema"),
        domains=step.get("domains"),
        actions=step.get("actions"),
        limit=step.get("limit", 100),
    )


def run_cases(payload: dict, base_dir: Path) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise ABACError(
            ErrorCode.INVALID_INPUT,
            "cases.json 顶层必须是含 cases 列表的对象",
        )

    output_cases: list[dict] = []
    overall_ok = True

    # Store/Engine 按 db 路径复用，同一 case 内多步共享缓存与连接。
    stores: dict[str, Store] = {}
    engines: dict[str, Engine] = {}

    try:
        for case_index, case in enumerate(payload["cases"]):
            case_name = case.get("name", f"case-{case_index}")
            # 每个 case 在独立子目录下建库，重跑时先清理，杜绝历史版本残留。
            db_path = base_dir / case["db"]
            db_path.parent.mkdir(parents=True, exist_ok=True)
            for suffix in ("", "-wal", "-shm"):
                stale = Path(str(db_path) + suffix)
                if stale.exists():
                    stale.unlink()
            db_key = str(db_path)
            if db_key not in stores:
                stores[db_key] = Store(db_path)
                engines[db_key] = Engine(stores[db_key])
            store = stores[db_key]
            engine = engines[db_key]

            case_result: dict[str, Any] = {"name": case_name, "steps": []}
            case_ok = True
            last_result: Any = None
            # 上一步抛出的错误先“挂起”，由紧随其后的 expect_error 消费；
            # 若下一步不是 expect_error，则在该步开头转成未预期错误。
            pending_error: ABACError | None = None

            for step_index, raw_step in enumerate(case["steps"]):
                step = _resolve_markers(copy.deepcopy(raw_step), base_dir)
                step_record: dict[str, Any] = {
                    "index": step_index, "type": step["type"],
                }
                step_failures: list[str] = []
                stype = step["type"]

                if pending_error is not None and stype != "expect_error":
                    step_failures.append(
                        f"上一步抛出了未被 expect_error 消费的错误 "
                        f"{pending_error.code.value}: {pending_error.message}"
                    )
                    case_ok = False
                    overall_ok = False
                    pending_error = None

                if stype == "expect_error":
                    expected_code = step["code"]
                    if pending_error is None:
                        step_failures.append(
                            f"expect_error: 期望上一步抛出 {expected_code}，"
                            "但上一步成功了"
                        )
                    else:
                        if pending_error.code.value != expected_code:
                            step_failures.append(
                                "expect_error.code: "
                                f"期望 {expected_code}，实际 {pending_error.code.value}"
                            )
                        else:
                            # 错误被正确预期并消费：回标上一步为通过。
                            case_result["steps"][-1]["ok"] = True
                            case_result["steps"][-1]["expected_error"] = expected_code
                        step_record["error"] = pending_error.to_dict()
                    pending_error = None
                    step_record["ok"] = not step_failures
                    if step_failures:
                        case_ok = False
                        overall_ok = False
                        step_record["assertion_failures"] = step_failures
                    case_result["steps"].append(step_record)
                    continue

                try:
                    if stype == "put_subject":
                        last_result = store.put_subject_attrs(
                            step["tenant"], step["subject"], step["version"],
                            _attrs_from_json(step["attrs"]),
                        )
                    elif stype == "put_resource":
                        last_result = store.put_resource_attrs(
                            step["tenant"], step["resource"], step["version"],
                            _attrs_from_json(step["attrs"]),
                        )
                    elif stype == "replace_policy":
                        last_result = store.replace_policy(
                            step["tenant"], step["doc"], step.get("schema")
                        )
                    elif stype == "decide":
                        last_result = engine.decide(
                            step["tenant"], step["subject"],
                            step["resource"], step["action"],
                        )
                        _check_expectations(step, last_result, step_failures)
                    elif stype == "diff":
                        last_result = _run_diff(step)
                        if "expect_gained_allow_count" in step:
                            _assert_equal(
                                "expect_gained_allow_count",
                                last_result["summary"]["gained_allow_count"],
                                step["expect_gained_allow_count"], step_failures,
                            )
                        if "expect_lost_allow_count" in step:
                            _assert_equal(
                                "expect_lost_allow_count",
                                last_result["summary"]["lost_allow_count"],
                                step["expect_lost_allow_count"], step_failures,
                            )
                        if "expect_space_size" in step:
                            _assert_equal(
                                "expect_space_size",
                                last_result["summary"]["space_size"],
                                step["expect_space_size"], step_failures,
                            )
                    elif stype == "diff_stored":
                        old_bundle = store.get_policy_version(
                            step["tenant"], step["old_version"]
                        )
                        new_bundle = store.get_policy_version(
                            step["tenant"], step["new_version"]
                        )
                        last_result = diff_policies(
                            old_bundle["doc"], new_bundle["doc"],
                            old_bundle["schema"], new_bundle["schema"],
                            domains=step.get("domains"),
                            actions=step.get("actions"),
                            limit=step.get("limit", 100),
                        )
                    elif stype == "inspect_cache":
                        last_result = engine.cache_stats()
                    elif stype == "cache_clear":
                        engine.cache_clear()
                        last_result = {"cleared": True}
                    elif stype == "list_versions":
                        last_result = {
                            "policy_versions": store.list_policy_versions(
                                step["tenant"]
                            )
                        }
                    elif stype == "assert_equal":
                        # 通用断言：可配合 $file/$binary 标记校验项目内样例。
                        equal = step["actual"] == step["expected"]
                        last_result = {
                            "actual": step["actual"],
                            "expected": step["expected"],
                            "equal": equal,
                        }
                        if not equal:
                            step_failures.append(
                                "assert_equal: actual 与 expected 不相等"
                            )
                    else:
                        raise ABACError(
                            ErrorCode.INVALID_INPUT,
                            f"未知 step 类型: {stype}",
                        )
                    step_record["result"] = last_result
                except ABACError as exc:
                    # 挂起错误，等待下一步的 expect_error 显式消费。
                    pending_error = exc
                    last_result = None
                    step_record["error"] = exc.to_dict()

                if step_failures:
                    case_ok = False
                    overall_ok = False
                    step_record["assertion_failures"] = step_failures
                step_record["ok"] = not step_failures and pending_error is None
                case_result["steps"].append(step_record)

            if pending_error is not None:
                # case 结束仍有未消费的错误。
                case_ok = False
                overall_ok = False
                case_result["unconsumed_error"] = pending_error.to_dict()

            case_result["ok"] = case_ok
            output_cases.append(case_result)
    finally:
        for store in stores.values():
            store.close()

    return {"ok": overall_ok, "cases": output_cases}


def run_file(input_path: str | Path) -> tuple[dict, Path]:
    input_path = Path(input_path)
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    base_dir = input_path.parent
    return run_cases(payload, base_dir), base_dir
