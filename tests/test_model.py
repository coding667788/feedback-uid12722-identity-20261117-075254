"""model 层：值规范化、布尔拒绝、确定性编码、版本校验。"""

from __future__ import annotations

import unittest

from solution.errors import ABACError, ErrorCode
from solution.model import (
    canonical_json,
    check_identifier,
    check_version,
    decode_value,
    encode_value,
    normalize,
)


class ValueModelTests(unittest.TestCase):
    def test_bool_is_rejected(self):
        with self.assertRaises(ABACError) as ctx:
            normalize(True)
        self.assertEqual(ctx.exception.code, ErrorCode.TYPE_MISMATCH)

    def test_set_normalized_to_frozenset(self):
        value = normalize(["a", "b", 1])
        self.assertIsInstance(value, frozenset)
        self.assertEqual(value, frozenset(["a", "b", 1]))

    def test_duplicate_set_elements_rejected(self):
        with self.assertRaises(ABACError):
            normalize(["a", "a"])

    def test_nested_set_rejected(self):
        with self.assertRaises(ABACError):
            normalize([["inner"]])

    def test_unsupported_type_rejected(self):
        with self.assertRaises(ABACError) as ctx:
            normalize(1.5)
        self.assertEqual(ctx.exception.code, ErrorCode.TYPE_MISMATCH)

    def test_encode_decode_roundtrip_and_determinism(self):
        value = frozenset(["b", "a", 2])
        encoded = encode_value(value)
        # 集合排序编码：相同语义值字节一致（重复版本内容检测依赖它）。
        self.assertEqual(encoded, encode_value(frozenset([2, "a", "b"])))
        self.assertEqual(decode_value(encoded), value)
        self.assertEqual(encode_value("x"), '"x"')
        self.assertEqual(decode_value(encode_value(7)), 7)

    def test_canonical_json_is_order_independent(self):
        a = canonical_json({"x": 1, "y": [1, 2]})
        b = canonical_json({"y": [1, 2], "x": 1})
        self.assertEqual(a, b)


class VersionAndIdentifierTests(unittest.TestCase):
    def test_version_must_be_non_negative_int(self):
        self.assertEqual(check_version(0), 0)
        self.assertEqual(check_version(3), 3)
        for bad in (-1, "1", 1.0, True):
            with self.assertRaises(ABACError) as ctx:
                check_version(bad)
            self.assertEqual(ctx.exception.code, ErrorCode.INVALID_INPUT)

    def test_identifier_must_be_non_empty_string(self):
        self.assertEqual(check_identifier("acme", "tenant"), "acme")
        for bad in ("", 1, None):
            with self.assertRaises(ABACError):
                check_identifier(bad, "tenant")


if __name__ == "__main__":
    unittest.main()
