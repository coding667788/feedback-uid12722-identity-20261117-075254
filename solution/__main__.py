"""命令行入口：python -m solution --input cases.json --output result.json

退出码：
    0  所有 case 的显式断言通过（步骤内未预期的业务错误也算失败）
    1  存在失败的 case 或输入文件本身无法解析
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .errors import ABACError
from .runner import run_file


def _json_default(obj):
    """frozenset 等非常规类型的兜底序列化（正常路径已在 model 层转换）。"""
    if isinstance(obj, frozenset):
        return sorted(obj, key=lambda x: (type(x).__name__, x))
    return str(obj)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="多租户 ABAC 授权服务批处理入口",
    )
    parser.add_argument("--input", required=True, help="cases.json 路径")
    parser.add_argument("--output", required=True, help="结果 JSON 输出路径")
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    output_path = Path(args.output)
    try:
        result, _ = run_file(input_path)
    except ABACError as exc:
        result = {"ok": False, "fatal": exc.to_dict(), "cases": []}
    except FileNotFoundError as exc:
        result = {
            "ok": False,
            "fatal": {"code": "FILE_NOT_FOUND", "message": str(exc)},
            "cases": [],
        }
    except json.JSONDecodeError as exc:
        result = {
            "ok": False,
            "fatal": {
                "code": "INVALID_INPUT",
                "message": f"输入 JSON 解析失败: {exc}",
            },
            "cases": [],
        }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, default=_json_default),
        encoding="utf-8",
    )
    print(
        f"写入 {output_path}：{'全部通过' if result.get('ok') else '存在失败'}，"
        f"case 数 {len(result.get('cases', []))}"
    )
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
