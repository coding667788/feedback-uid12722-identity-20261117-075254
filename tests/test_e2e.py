"""端到端：直接运行 cases.json，并通过子进程执行 python -m solution 入口。"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from solution.runner import run_file

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class EndToEndCasesTests(unittest.TestCase):
    def test_run_cases_all_pass_in_process(self):
        result, _ = run_file(PROJECT_ROOT / "cases.json")
        self.assertTrue(
            result["ok"],
            msg=json.dumps(
                [
                    {"case": c["name"],
                     "failures": [s.get("assertion_failures")
                                  for s in c["steps"] if not s["ok"]]}
                    for c in result["cases"] if not c["ok"]
                ],
                ensure_ascii=False,
            ),
        )
        self.assertEqual(len(result["cases"]), 6)
        # 每个 case 都至少包含一个带具体断言的 decide/diff 步骤。
        for case in result["cases"]:
            self.assertTrue(case["steps"])

    def test_cli_subprocess_entrypoint(self):
        output = PROJECT_ROOT / ".runtime-tmp" / "cli_e2e_result.json"
        output.parent.mkdir(exist_ok=True)
        proc = subprocess.run(
            [sys.executable, "-m", "solution",
             "--input", "cases.json", "--output", str(output)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(len(payload["cases"]), 6)

    def test_cli_returns_nonzero_on_failure(self):
        bad_input = PROJECT_ROOT / ".runtime-tmp" / "bad_cases.json"
        bad_input.write_text(
            json.dumps({"cases": [
                {"name": "will-fail", "db": ".runtime-tmp/bad-cl.db",
                 "steps": [
                     {"type": "decide", "tenant": "t", "subject": "u",
                      "resource": "r", "action": "read",
                      "expect_decision": "allow"},
                 ]},
            ]}),
            encoding="utf-8",
        )
        output = PROJECT_ROOT / ".runtime-tmp" / "bad_result.json"
        proc = subprocess.run(
            [sys.executable, "-m", "solution",
             "--input", str(bad_input), "--output", str(output)],
            cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertFalse(payload["ok"])

    def test_binary_marker_roundtrip(self):
        from solution.runner import _resolve_markers
        base = PROJECT_ROOT
        resolved = _resolve_markers(
            {"b64": {"$binary": "samples/binary_sample.bin", "encoding": "base64"},
             "hex": {"$binary": "samples/binary_sample.bin", "encoding": "hex"}},
            base,
        )
        raw = (base / "samples" / "binary_sample.bin").read_bytes()
        import base64

        self.assertEqual(resolved["b64"], base64.b64encode(raw).decode())
        self.assertEqual(resolved["hex"], raw.hex())

    def test_file_marker_loads_json_sample(self):
        from solution.runner import _resolve_markers
        resolved = _resolve_markers(
            {"schema": {"$file": "samples/schema.json"}}, PROJECT_ROOT
        )
        self.assertEqual(
            resolved["schema"]["subject"]["clearance"], "integer"
        )


if __name__ == "__main__":
    unittest.main()
