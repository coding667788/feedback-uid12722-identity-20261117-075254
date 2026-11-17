"""存储层：单调版本、原子替换、同版本冲突与跨租户隔离测试。"""

from __future__ import annotations

from solution.errors import ABACError, ErrorCode
from tests._helpers import SCHEMA, StoreTestBase


class MonotonicVersionTests(StoreTestBase):
    def test_subject_version_must_increase(self):
        self.store.put_subject_attrs("acme", "u1", 1, {"dept": "eng"})
        # 同版本同内容：幂等重放，成功且带 idempotent 标记。
        replay = self.store.put_subject_attrs("acme", "u1", 1, {"dept": "eng"})
        self.assertTrue(replay["idempotent"])
        # 同版本异内容：冲突拒绝。
        with self.assertRaises(ABACError) as ctx:
            self.store.put_subject_attrs("acme", "u1", 1, {"dept": "sales"})
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_VERSION_CONTENT)
        # 版本回退：单调拒绝。
        with self.assertRaises(ABACError) as ctx2:
            self.store.put_subject_attrs("acme", "u1", 3, {"dept": "eng"})
            self.store.put_subject_attrs("acme", "u1", 2, {"dept": "eng"})
        self.assertEqual(ctx2.exception.code, ErrorCode.VERSION_NOT_MONOTONIC)

    def test_duplicate_version_different_content_rejected(self):
        self.store.put_subject_attrs("acme", "u1", 1, {"dept": "eng"})
        with self.assertRaises(ABACError) as ctx:
            self.store.put_subject_attrs("acme", "u1", 1, {"dept": "sales"})
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_VERSION_CONTENT)
        # 原数据保持不变。
        self.store.begin_snapshot()
        snap = self.store.read_snapshot("acme", "u1", "r1")
        self.store.commit_snapshot()
        self.assertEqual(snap["subject_attrs"]["dept"], "eng")
        self.assertEqual(snap["subject_version"], 1)

    def test_zero_version_reserved(self):
        with self.assertRaises(ABACError) as ctx:
            self.store.put_subject_attrs("acme", "u1", 0, {"dept": "eng"})
        self.assertEqual(ctx.exception.code, ErrorCode.VERSION_NOT_MONOTONIC)

    def test_set_values_round_trip(self):
        from tests._helpers import rule
        self.store.replace_policy(
            "acme",
            {"version": 1, "rules": [
                rule("placeholder", "read", "allow",
                     {"op": "eq",
                      "left": {"op": "lit", "value": 1},
                      "right": {"op": "lit", "value": 1}}),
            ]},
            SCHEMA,
        )
        self.store.put_subject_attrs(
            "acme", "u1", 1, {"roles": ["reader", "writer"], "dept": "eng"}
        )
        self.store.begin_snapshot()
        snap = self.store.read_snapshot("acme", "u1", "r1")
        self.store.commit_snapshot()
        self.assertEqual(
            snap["subject_attrs"]["roles"], frozenset(["reader", "writer"])
        )

    def test_attribute_type_check_against_schema(self):
        from tests._helpers import rule
        self.store.replace_policy(
            "acme",
            {"version": 1, "rules": [
                rule("placeholder", "read", "allow",
                     {"op": "eq",
                      "left": {"op": "lit", "value": 1},
                      "right": {"op": "lit", "value": 1}}),
            ]},
            SCHEMA,
        )
        with self.assertRaises(ABACError) as ctx:
            self.store.put_subject_attrs("acme", "u1", 1, {"level": "high"})
        self.assertEqual(ctx.exception.code, ErrorCode.TYPE_MISMATCH)
        with self.assertRaises(ABACError) as ctx:
            self.store.put_subject_attrs("acme", "u1", 1, {"unknown_attr": 1})
        self.assertEqual(ctx.exception.code, ErrorCode.POLICY_VALIDATION_FAILED)


class AtomicPolicyReplaceTests(StoreTestBase):
    def test_invalid_policy_keeps_previous_policy(self):
        doc1 = self.install_v1()
        bad_doc = {
            "version": 2,
            "rules": [{
                "id": "bad", "action": "read", "effect": "allow",
                "expression": {"op": "eq",
                               "left": {"op": "attr", "kind": "subject",
                                        "name": "ghost"},
                               "right": {"op": "lit", "value": "x"}},
            }],
        }
        with self.assertRaises(ABACError) as ctx:
            self.store.replace_policy("acme", bad_doc, SCHEMA)
        self.assertEqual(ctx.exception.code, ErrorCode.POLICY_VALIDATION_FAILED)
        versions = self.store.list_policy_versions("acme")
        self.assertEqual(versions, [1])
        bundle = self.store.get_policy_version("acme", 1)
        self.assertEqual(bundle["doc"], doc1)

    def test_duplicate_policy_version_conflict_rejected_and_preserved(self):
        self.install_v1()
        conflicting = {
            "version": 1,
            "rules": [{
                "id": "other", "action": "read", "effect": "allow",
                "expression": {"op": "eq",
                               "left": {"op": "attr", "kind": "subject",
                                        "name": "dept"},
                               "right": {"op": "lit", "value": "eng"}},
            }],
        }
        with self.assertRaises(ABACError) as ctx:
            self.store.replace_policy("acme", conflicting, SCHEMA)
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_VERSION_CONTENT)
        self.assertEqual(self.store.list_policy_versions("acme"), [1])

    def test_same_version_same_content_is_idempotent(self):
        doc = self.install_v1()
        result = self.store.replace_policy("acme", doc, SCHEMA)
        self.assertTrue(result["idempotent"])
        self.assertEqual(self.store.list_policy_versions("acme"), [1])

    def test_monotonic_policy_version(self):
        self.install_v1()
        with self.assertRaises(ABACError) as ctx:
            # 空规则列表先触发策略校验失败（rules 必须非空）。
            self.store.replace_policy(
                "acme", {"version": 1, "rules": []}, SCHEMA
            )
        self.assertEqual(ctx.exception.code, ErrorCode.POLICY_VALIDATION_FAILED)
        # 合法文档但版本回退 -> VERSION_NOT_MONOTONIC。
        with self.assertRaises(ABACError) as ctx2:
            self.store.replace_policy(
                "acme",
                {"version": 1, "rules": [
                    {"id": "x", "action": "read", "effect": "allow",
                     "expression": {"op": "eq",
                                    "left": {"op": "lit", "value": 1},
                                    "right": {"op": "lit", "value": 1}}},
                ]},
                SCHEMA,
            )
        self.assertEqual(ctx2.exception.code, ErrorCode.DUPLICATE_VERSION_CONTENT)

    def test_history_versions_persist(self):
        self.install_v1()
        doc2 = {"version": 2, "rules": [
            {"id": "v2-rule", "action": "read", "effect": "deny",
             "expression": {"op": "eq",
                            "left": {"op": "lit", "value": 1},
                            "right": {"op": "lit", "value": 1}}},
        ]}
        self.store.replace_policy("acme", doc2, SCHEMA)
        self.assertEqual(self.store.list_policy_versions("acme"), [1, 2])
        self.assertEqual(self.store.get_policy_version("acme", 2)["doc"], doc2)
        self.assertEqual(
            self.store.get_policy_version("acme", 1)["doc"]["version"], 1
        )


class CrossTenantIsolationTests(StoreTestBase):
    def test_same_subject_name_isolated_per_tenant(self):
        self.install_v1("alpha")
        self.install_v1("beta")
        self.store.put_subject_attrs(
            "alpha", "alice", 1,
            {"dept": "eng", "roles": ["reader"], "clearance": 9},
        )
        self.store.put_subject_attrs(
            "beta", "alice", 1,
            {"dept": "sales", "roles": ["reader"], "clearance": 9},
        )
        self.store.put_resource_attrs(
            "alpha", "r1", 1, {"owner_dept": "eng", "sensitivity": 1}
        )
        self.store.put_resource_attrs(
            "beta", "r1", 1, {"owner_dept": "eng", "sensitivity": 1}
        )
        alpha = self.engine.decide("alpha", "alice", "r1", "read")
        beta = self.engine.decide("beta", "alice", "r1", "read")
        self.assertEqual(alpha["decision"], "allow")
        self.assertEqual(beta["decision"], "deny")
        # 两个租户各自独立计版本。
        self.assertEqual(alpha["versions"]["subject_version"], 1)
        self.assertEqual(beta["versions"]["subject_version"], 1)

    def test_unknown_tenant_default_deny_with_zero_versions(self):
        result = self.engine.decide("ghost", "u", "r", "read")
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(result["versions"], {
            "policy_version": 0, "subject_version": 0, "resource_version": 0,
        })


if __name__ == "__main__":
    unittest.main()
