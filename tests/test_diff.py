"""有限域差分测试：小域穷举、独立暴力复核、反例具体化。"""

from __future__ import annotations

import itertools
import unittest

from solution.diff import decide_with_doc, diff_policies
from solution.errors import ABACError
from solution.model import MISSING
from tests._helpers import AND, NOT, attr, eq, inn, lit, rule


def _bruteforce_space(schema, domains, actions):
    """独立实现的笛卡尔积枚举，不调用被测的 _enumerate_assignments。"""
    axes = []
    for kind in ("subject", "resource"):
        for name in sorted(schema.get(kind, {})):
            values = [MISSING] + list(domains[kind][name])
            axes.append((kind, name, values))
    points = []
    for combo in itertools.product(*(axis[2] for axis in axes)):
        point = {"subject": {}, "resource": {}}
        for (kind, name, _), value in zip(axes, combo):
            if value is not MISSING:
                point[kind][name] = value
        points.append(point)
    return points


class DiffExhaustiveTests(unittest.TestCase):
    SCHEMA = {
        "subject": {"dept": "string", "level": "integer"},
        "resource": {"owner_dept": "string"},
    }
    DOMAINS = {
        "subject": {"dept": ["eng", "sales"], "level": [1, 2]},
        "resource": {"owner_dept": ["eng", "sales"]},
    }

    def _docs(self):
        old = {"rules": [rule(
            "old", "read", "allow",
            AND(
                eq(attr("subject", "dept"), attr("resource", "owner_dept")),
                eq(attr("subject", "level"), lit(2)),
            ),
        )]}
        # 新策略放宽：同部门即可，不再要求 level=2。
        new = {"rules": [rule(
            "new", "read", "allow",
            eq(attr("subject", "dept"), attr("resource", "owner_dept")),
        )]}
        return old, new

    def test_space_size_matches_bruteforce(self):
        old, new = self._docs()
        result = diff_policies(
            old, new, self.SCHEMA, self.SCHEMA,
            domains=self.DOMAINS, actions=["read"],
        )
        points = _bruteforce_space(self.SCHEMA, self.DOMAINS, ["read"])
        # 每个属性 3 个取值（含 MISSING）：3^3 = 27 个属性点。
        self.assertEqual(len(points), 27)
        self.assertEqual(result["summary"]["assignment_points"], 27)
        self.assertEqual(result["summary"]["space_size"], 27)

    def test_gained_allow_matches_independent_bruteforce(self):
        old, new = self._docs()
        result = diff_policies(
            old, new, self.SCHEMA, self.SCHEMA,
            domains=self.DOMAINS, actions=["read"],
        )
        # 独立暴力统计，不依赖被测 summary。
        expected_gained = []
        points = _bruteforce_space(self.SCHEMA, self.DOMAINS, ["read"])
        for point in points:
            old_d = decide_with_doc(old, point["subject"], point["resource"], "read")
            new_d = decide_with_doc(new, point["subject"], point["resource"], "read")
            if old_d["decision"] == "deny" and new_d["decision"] == "allow":
                expected_gained.append(point)
        self.assertEqual(
            result["summary"]["gained_allow_count"], len(expected_gained)
        )
        self.assertEqual(len(result["gained_allow_examples"]), len(expected_gained))

    def test_counterexample_is_concrete_and_correct(self):
        old, new = self._docs()
        result = diff_policies(
            old, new, self.SCHEMA, self.SCHEMA,
            domains=self.DOMAINS, actions=["read"],
        )
        examples = result["gained_allow_examples"]
        self.assertTrue(examples)
        # 找到一个 level 明确出现且为 1 的具体反例（枚举顺序保证存在）。
        concrete = next(
            ex for ex in examples
            if "level" in ex["assignment"]["subject"]
            and ex["assignment"]["subject"]["level"]["value"] == 1
        )
        first = concrete
        self.assertEqual(first["action"], "read")
        self.assertEqual(first["old"]["decision"], "deny")
        self.assertEqual(first["new"]["decision"], "allow")
        # 反例必须是具体赋值：level=1（不满足旧规则的 level==2）且部门相同。
        assignment = first["assignment"]
        self.assertEqual(
            assignment["subject"]["dept"]["value"],
            assignment["resource"]["owner_dept"]["value"],
        )
        # 用反例回放到两个策略，验证差分结论本身可复现。
        sub = {k: v["value"] for k, v in assignment["subject"].items()
               if v["present"]}
        res = {k: v["value"] for k, v in assignment["resource"].items()
               if v["present"]}
        self.assertEqual(decide_with_doc(old, sub, res, "read")["decision"], "deny")
        self.assertEqual(decide_with_doc(new, sub, res, "read")["decision"], "allow")

    def test_missing_value_is_part_of_domain(self):
        old, new = self._docs()
        result = diff_policies(
            old, new, self.SCHEMA, self.SCHEMA,
            domains=self.DOMAINS, actions=["read"],
        )
        # 至少有一个反例涉及属性缺失，证明 MISSING 进入了枚举空间。
        involves_missing = any(
            ex["missing_attrs"]["subject"] or ex["missing_attrs"]["resource"]
            for ex in result["gained_allow_examples"]
        )
        self.assertTrue(involves_missing)

    def test_identical_policies_have_no_diff(self):
        old, _ = self._docs()
        result = diff_policies(
            old, old, self.SCHEMA, self.SCHEMA,
            domains=self.DOMAINS, actions=["read"],
        )
        self.assertEqual(result["summary"]["gained_allow_count"], 0)
        self.assertEqual(result["summary"]["lost_allow_count"], 0)
        self.assertEqual(result["summary"]["stable_same"],
                         result["summary"]["space_size"])

    def test_not_missing_semantics_in_diff(self):
        # 旧：dept == eng；新：NOT(dept == sales)。缺 dept 时两边都 unknown->deny，
        # 不会因为取反而凭空 allow。
        old = {"rules": [rule("o", "read", "allow",
                              eq(attr("subject", "dept"), lit("eng")))]}
        new = {"rules": [rule("n", "read", "allow",
                              NOT(eq(attr("subject", "dept"), lit("sales"))))]}
        schema = {"subject": {"dept": "string"}, "resource": {}}
        result = diff_policies(
            old, new, schema, schema,
            domains={"subject": {"dept": ["eng", "sales"]}, "resource": {}},
            actions=["read"],
        )
        # 空间 3 点：missing / eng / sales；没有任何 deny->allow。
        self.assertEqual(result["summary"]["space_size"], 3)
        self.assertEqual(result["summary"]["gained_allow_count"], 0)

    def test_deny_rule_counts_as_strict_in_diff(self):
        old = {"rules": [rule("a", "read", "allow",
                              inn(lit("reader"), attr("subject", "roles")))]}
        new = {"rules": [
            rule("a", "read", "allow",
                 inn(lit("reader"), attr("subject", "roles"))),
            rule("d", "read", "deny",
                 inn(lit("blocked"), attr("subject", "roles"))),
        ]}
        schema = {"subject": {"roles": "set"}, "resource": {}}
        domains = {"subject": {"roles": [["reader"], ["reader", "blocked"]]},
                   "resource": {}}
        result = diff_policies(
            old, new, schema, schema, domains=domains, actions=["read"]
        )
        # blocked 组合：旧 allow -> 新 deny，属于 lost。
        self.assertGreaterEqual(result["summary"]["lost_allow_count"], 1)
        self.assertEqual(result["summary"]["gained_allow_count"], 0)

    def test_schema_type_conflict_rejected(self):
        with self.assertRaises(ABACError):
            diff_policies(
                {"rules": []}, {"rules": []},
                {"subject": {"x": "string"}, "resource": {}},
                {"subject": {"x": "integer"}, "resource": {}},
            )

    def test_limit_truncation_is_reported(self):
        old = {"rules": []}  # 全部默认拒绝
        new = {"rules": [rule("a", "read", "allow", eq(lit(1), lit(1)))]}
        schema = {"subject": {"dept": "string"}, "resource": {}}
        result = diff_policies(
            old, new, schema, schema,
            domains={"subject": {"dept": ["eng", "sales", "ops"]}, "resource": {}},
            actions=["read"], limit=2,
        )
        # 4 个点（含 MISSING）全部 deny->allow，截断到 2 条但计数保留 4。
        self.assertEqual(result["summary"]["gained_allow_count"], 4)
        self.assertEqual(len(result["gained_allow_examples"]), 2)
        self.assertEqual(result["summary"]["gained_truncated"], 2)


if __name__ == "__main__":
    unittest.main()
