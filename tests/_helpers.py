"""测试公共工具：临时目录、固定 schema/策略构造。"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from solution.engine import Engine
from solution.store import Store

SCHEMA = {
    "subject": {
        "dept": "string",
        "level": "integer",
        "roles": "set",
        "clearance": "integer",
    },
    "resource": {
        "owner_dept": "string",
        "sensitivity": "integer",
        "tags": "set",
    },
}


def rule(rule_id: str, action: str, effect: str, expression: dict) -> dict:
    return {
        "id": rule_id,
        "action": action,
        "effect": effect,
        "expression": expression,
    }


def attr(kind: str, name: str) -> dict:
    return {"op": "attr", "kind": kind, "name": name}


def lit(value) -> dict:
    return {"op": "lit", "value": value}


def eq(left: dict, right: dict) -> dict:
    return {"op": "eq", "left": left, "right": right}


def inn(left: dict, right: dict) -> dict:
    return {"op": "in", "left": left, "right": right}


def lt(left: dict, right: dict) -> dict:
    return {"op": "lt", "left": left, "right": right}


def AND(*children: dict) -> dict:
    return {"op": "and", "children": list(children)}


def OR(*children: dict) -> dict:
    return {"op": "or", "children": list(children)}


def NOT(child: dict) -> dict:
    return {"op": "not", "child": child}


class StoreTestBase(unittest.TestCase):
    """每个测试方法一套独立临时目录与 Store。"""

    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="abac-test-"))
        self.db_path = self.tmpdir / "test.db"
        self.store = Store(self.db_path)
        self.engine = Engine(self.store)

    def tearDown(self) -> None:
        self.store.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def install_v1(self, tenant: str = "acme") -> None:
        doc = {
            "version": 1,
            "rules": [
                rule(
                    "read-allow", "read", "allow",
                    AND(
                        eq(attr("subject", "dept"), attr("resource", "owner_dept")),
                        inn(lit("reader"), attr("subject", "roles")),
                        lt(attr("resource", "sensitivity"),
                           attr("subject", "clearance")),
                    ),
                ),
                rule(
                    "read-deny-guest", "read", "deny",
                    inn(lit("guest"), attr("subject", "roles")),
                ),
            ],
        }
        self.store.replace_policy(tenant, doc, SCHEMA)
        return doc
