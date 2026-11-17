"""三值逻辑（Kleene 强三值逻辑）与策略静态校验测试。"""

from __future__ import annotations

import unittest

from solution.errors import ABACError, ErrorCode
from solution.model import MISSING
from solution.policy import evaluate_expr, evaluate_rule, validate_policy_doc
from tests._helpers import AND, NOT, OR, attr, eq, inn, lit, lt, rule

LABEL = {True: "true", False: "false", None: "unknown"}


def label_of(value):
    if value is MISSING:
        return "MISSING"
    return LABEL[value]


class TriboolComparisonTests(unittest.TestCase):
    def setUp(self):
        self.eq_expr = eq(attr("subject", "dept"), lit("eng"))
        self.lt_expr = lt(attr("resource", "sensitivity"), lit(5))
        self.in_expr = inn(lit("reader"), attr("subject", "roles"))

    def test_missing_attribute_comparison_is_unknown(self):
        for expr in (self.eq_expr, self.lt_expr, self.in_expr):
            value, tree = evaluate_expr(expr, {}, {})
            self.assertIsNone(value)
            self.assertEqual(tree["result"], "unknown")

    def test_missing_empty_set_is_a_real_value_not_missing(self):
        # 空集合是合法属性值：in 求值为明确 false，而不是 unknown。
        value, _ = evaluate_expr(self.in_expr, {"roles": frozenset()}, {})
        self.assertFalse(value)

    def test_eq_present_values(self):
        self.assertTrue(evaluate_expr(self.eq_expr, {"dept": "eng"}, {})[0])
        self.assertFalse(evaluate_expr(self.eq_expr, {"dept": "sales"}, {})[0])

    def test_lt_present_values(self):
        self.assertTrue(evaluate_expr(self.lt_expr, {}, {"sensitivity": 3})[0])
        self.assertFalse(evaluate_expr(self.lt_expr, {}, {"sensitivity": 9})[0])

    def test_in_set_membership(self):
        value, _ = evaluate_expr(
            self.in_expr, {"roles": frozenset(["reader", "writer"])}, {}
        )
        self.assertTrue(value)


class BooleanTriboolTests(unittest.TestCase):
    def setUp(self):
        # p: 明确谓词；q: 依赖缺失属性 -> unknown
        self.p = eq(attr("subject", "dept"), lit("eng"))
        self.q = eq(attr("subject", "clearance_missing"), lit(1))

    def test_not_unknown_stays_unknown(self):
        # 题目硬性要求：NOT unknown = unknown（缺字段取反不能产生 true）。
        value, tree = evaluate_expr(NOT(self.q), {}, {})
        self.assertIsNone(value)
        self.assertEqual(tree["result"], "unknown")
        self.assertIn("NOT unknown", tree["reasons"][0])

    def test_not_true_false(self):
        self.assertFalse(evaluate_expr(NOT(self.p), {"dept": "eng"}, {})[0])
        self.assertTrue(evaluate_expr(NOT(self.p), {"dept": "x"}, {})[0])

    def test_and_truth_table_with_unknown(self):
        cases = [
            (AND(self.p, self.q), {"dept": "eng"}, None),       # true AND unknown
            (AND(self.p, self.q), {"dept": "x"}, False),        # false AND unknown
        ]
        for expr, sub, expected in cases:
            self.assertEqual(evaluate_expr(expr, sub, {})[0], expected)

    def test_or_truth_table_with_unknown(self):
        cases = [
            (OR(self.p, self.q), {"dept": "eng"}, True),        # true OR unknown
            (OR(self.p, self.q), {"dept": "x"}, None),          # false OR unknown
        ]
        for expr, sub, expected in cases:
            self.assertEqual(evaluate_expr(expr, sub, {})[0], expected)

    def test_nested_boolean_mix(self):
        # NOT(false OR unknown) = NOT unknown = unknown
        expr = NOT(OR(eq(lit(1), lit(2)), self.q))
        self.assertIsNone(evaluate_expr(expr, {}, {})[0])
        # (true AND unknown) OR false = unknown
        expr2 = OR(AND(self.p, self.q), eq(lit(1), lit(2)))
        self.assertIsNone(evaluate_expr(expr2, {"dept": "eng"}, {})[0])
        # (false AND unknown) OR true = true
        expr3 = OR(
            AND(eq(lit(1), lit(2)), self.q), eq(attr("subject", "dept"), lit("eng"))
        )
        self.assertTrue(evaluate_expr(expr3, {"dept": "eng"}, {})[0])

    def test_only_explicit_true_matches_rule(self):
        r = rule("r", "read", "allow", self.q)
        report = evaluate_rule(r, {}, {})
        self.assertEqual(report["tribool"], "unknown")
        self.assertFalse(report["matched"])  # unknown 不算命中 -> 默认拒绝


class ValidationTests(unittest.TestCase):
    SCHEMA = {"subject": {"dept": "string", "level": "integer",
                          "roles": "set"}, "resource": {}}

    def _validate(self, expression):
        doc = {"rules": [rule("r", "read", "allow", expression)]}
        validate_policy_doc(doc, self.SCHEMA)

    def test_unknown_attribute_reference_rejected(self):
        with self.assertRaises(ABACError) as ctx:
            self._validate(eq(attr("subject", "ghost"), lit("x")))
        self.assertEqual(ctx.exception.code, ErrorCode.POLICY_VALIDATION_FAILED)
        self.assertIn("未声明", ctx.exception.details["errors"][0])

    def test_lt_type_mismatch_rejected(self):
        with self.assertRaises(ABACError) as ctx:
            self._validate(lt(attr("subject", "dept"), lit(3)))
        self.assertEqual(ctx.exception.code, ErrorCode.POLICY_VALIDATION_FAILED)

    def test_in_right_side_must_be_set(self):
        with self.assertRaises(ABACError):
            self._validate(inn(attr("subject", "dept"), lit("eng")))

    def test_boolean_value_rejected(self):
        with self.assertRaises(ABACError) as ctx:
            self._validate(eq(attr("subject", "dept"), lit(True)))
        # bool 不是受支持值 -> TYPE_MISMATCH，整体归为策略校验失败。
        self.assertEqual(ctx.exception.code, ErrorCode.POLICY_VALIDATION_FAILED)

    def test_and_requires_predicate_children(self):
        with self.assertRaises(ABACError):
            self._validate(AND(attr("subject", "dept"), lit("x")))

    def test_well_formed_doc_passes(self):
        doc = {"rules": [
            rule("r1", "read", "allow",
                 AND(eq(attr("subject", "dept"), lit("eng")),
                     inn(lit("a"), attr("subject", "roles")))),
        ]}
        validate_policy_doc(doc, self.SCHEMA)  # 不抛异常即通过

    def test_duplicate_rule_id_rejected(self):
        doc = {"rules": [
            rule("dup", "read", "allow", eq(lit(1), lit(1))),
            rule("dup", "read", "deny", eq(lit(1), lit(1))),
        ]}
        with self.assertRaises(ABACError) as ctx:
            validate_policy_doc(doc, self.SCHEMA)
        self.assertIn("id 重复", str(ctx.exception.details))


if __name__ == "__main__":
    unittest.main()
