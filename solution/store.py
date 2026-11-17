"""SQLite 持久化层。

并发模型（SQLite WAL）：
- 每个 Store 持有一条连接；读判定以 ``BEGIN`` 开启延迟事务，WAL 在事务内
  第一次读时固定快照，事务提交前其它连接的写入对本事务不可见——这正是
  “已经开始的请求允许按旧快照完成”的语义来源。
- 写事务统一 ``BEGIN IMMEDIATE``，全库串行化；配合 busy_timeout，锁冲突
  转为 :class:`ABACError`（STORE_BUSY）而不是脏写。
- 版本表只追加（*_versions），另建 *_latest 表保存当前指针；单调递增在
  写事务内检查，非法版本回滚后原数据原样保留。
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import ABACError, ErrorCode
from .model import (
    canonical_json,
    check_identifier,
    check_version,
    normalize,
    value_from_json,
)

_EMPTY_POLICY = {"version": 0, "rules": []}
_EMPTY_SCHEMA = {"subject": {}, "resource": {}}


def _json_safe(value: Any) -> Any:
    """frozenset 转为排序列表，其余标量原样返回（写入普通 JSON）。"""
    if isinstance(value, frozenset):
        return sorted(value, key=lambda x: (type(x).__name__, x))
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False：配合 BEGIN IMMEDIATE 写串行化与每请求短事务，
        # 允许多线程压测共享连接；WAL 保证读写不互斥。
        self.conn = sqlite3.connect(
            self.path, timeout=5.0, check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row
        self._in_snapshot = False
        self._lock = threading.RLock()
        with self.conn:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA busy_timeout=5000")
        self._create_schema()

    # ------------------------------------------------------------------ #
    # 建表
    # ------------------------------------------------------------------ #
    def _create_schema(self) -> None:
        with self.conn:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS subject_versions (
                    tenant TEXT NOT NULL,
                    entity TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    attrs_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant, entity, version)
                );
                CREATE TABLE IF NOT EXISTS subject_latest (
                    tenant TEXT NOT NULL,
                    entity TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    attrs_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant, entity)
                );
                CREATE TABLE IF NOT EXISTS resource_versions (
                    tenant TEXT NOT NULL,
                    entity TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    attrs_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant, entity, version)
                );
                CREATE TABLE IF NOT EXISTS resource_latest (
                    tenant TEXT NOT NULL,
                    entity TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    attrs_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant, entity)
                );
                CREATE TABLE IF NOT EXISTS policy_versions (
                    tenant TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    doc_json TEXT NOT NULL,
                    schema_json TEXT NOT NULL,
                    rule_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant, version)
                );
                CREATE TABLE IF NOT EXISTS policy_latest (
                    tenant TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    doc_json TEXT NOT NULL,
                    schema_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tenant_schema (
                    tenant TEXT PRIMARY KEY,
                    schema_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS decision_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    action TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    policy_version INTEGER NOT NULL,
                    subject_version INTEGER NOT NULL,
                    resource_version INTEGER NOT NULL,
                    matched_rule_ids TEXT NOT NULL,
                    cache_hit INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------ #
    # 事务边界
    # ------------------------------------------------------------------ #
    def begin_snapshot(self) -> None:
        """开启只读快照事务（延迟事务，首次读固定 WAL 快照）。"""
        with self._lock:
            if self._in_snapshot:
                raise ABACError(
                    ErrorCode.SNAPSHOT_NOT_ACTIVE, "已存在未结束的快照事务"
                )
            try:
                self.conn.execute("BEGIN")
            except sqlite3.OperationalError as exc:  # pragma: no cover - 防御
                raise ABACError(ErrorCode.INTERNAL_ERROR, str(exc)) from exc
            self._in_snapshot = True

    def commit_snapshot(self) -> None:
        with self._lock:
            if not self._in_snapshot:
                raise ABACError(
                    ErrorCode.SNAPSHOT_NOT_FINALIZED, "没有活动的快照事务可提交"
                )
            self.conn.execute("COMMIT")
            self._in_snapshot = False

    def rollback_snapshot(self) -> None:
        with self._lock:
            if not self._in_snapshot:
                return
            self.conn.execute("ROLLBACK")
            self._in_snapshot = False

    def _begin_write(self) -> None:
        # 写事务不得嵌套在快照事务中；调用方需先结束快照。
        if self._in_snapshot:
            raise ABACError(
                ErrorCode.SNAPSHOT_NOT_ACTIVE,
                "不能在活动的快照事务内开启写事务，请先提交或回滚快照",
            )
        try:
            self.conn.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            raise ABACError(
                ErrorCode.STORE_BUSY,
                f"数据库写锁获取失败: {exc}",
            ) from exc

    # ------------------------------------------------------------------ #
    # 快照读取
    # ------------------------------------------------------------------ #
    def _read_entity(self, latest_table: str,
                     tenant: str, name: str) -> tuple[int, dict[str, Any]]:
        import json

        row = self.conn.execute(
            f"SELECT version, attrs_json FROM {latest_table} "
            "WHERE tenant = ? AND entity = ?",
            (tenant, name),
        ).fetchone()
        if row is None:
            return 0, {}
        # attrs_json 是普通 JSON（{属性名: 值}），列表还原为 frozenset。
        attrs = {
            key: value_from_json(raw)
            for key, raw in json.loads(row["attrs_json"]).items()
        }
        return row["version"], attrs

    def read_snapshot(self, tenant: str, subject: str, resource: str) -> dict:
        """在活动快照事务内一次性读取策略与两类属性（同一数据库快照）。"""
        if not self._in_snapshot:
            raise ABACError(
                ErrorCode.SNAPSHOT_NOT_ACTIVE,
                "read_snapshot 必须在 begin_snapshot 之后调用",
            )
        check_identifier(tenant, "tenant")
        check_identifier(subject, "subject")
        check_identifier(resource, "resource")

        subject_version, subject_attrs = self._read_entity(
            "subject_latest", tenant, subject
        )
        resource_version, resource_attrs = self._read_entity(
            "resource_latest", tenant, resource
        )

        policy_row = self.conn.execute(
            "SELECT version, doc_json, schema_json FROM policy_latest WHERE tenant = ?",
            (tenant,),
        ).fetchone()
        if policy_row is None:
            policy_version, policy_doc, schema = 0, dict(_EMPTY_POLICY), dict(_EMPTY_SCHEMA)
        else:
            import json

            policy_version = policy_row["version"]
            policy_doc = json.loads(policy_row["doc_json"])
            schema = json.loads(policy_row["schema_json"])

        return {
            "tenant": tenant,
            "subject": subject,
            "resource": resource,
            "policy_version": policy_version,
            "policy_doc": policy_doc,
            "schema": schema,
            "subject_version": subject_version,
            "subject_attrs": subject_attrs,
            "resource_version": resource_version,
            "resource_attrs": resource_attrs,
        }

    # ------------------------------------------------------------------ #
    # 属性写入（全量替换、单调版本）
    # ------------------------------------------------------------------ #
    def _latest_schema(self, tenant: str) -> dict | None:
        row = self.conn.execute(
            "SELECT schema_json FROM tenant_schema WHERE tenant = ?", (tenant,)
        ).fetchone()
        if row is None:
            return None
        import json

        return json.loads(row["schema_json"])

    def _validate_attrs_against_schema(self, attrs: dict, schema: dict, kind: str) -> None:
        declared = schema.get(kind, {})
        for name, value in attrs.items():
            if not isinstance(name, str) or not name:
                raise ABACError(
                    ErrorCode.INVALID_INPUT, f"{kind} 属性名必须是非空字符串"
                )
            if name not in declared:
                raise ABACError(
                    ErrorCode.POLICY_VALIDATION_FAILED,
                    f"属性 {kind}.{name} 未在租户 schema 中声明",
                )
            expected = declared[name]
            actual = "set" if isinstance(value, frozenset) else (
                "integer" if isinstance(value, int) else "string"
            )
            if actual != expected:
                raise ABACError(
                    ErrorCode.TYPE_MISMATCH,
                    f"属性 {kind}.{name} 声明类型为 {expected}，实际为 {actual}",
                )

    def _put_entity(self, kind: str, tenant: str, entity: str,
                    version: int, attrs: dict) -> dict:
        check_identifier(tenant, "tenant")
        check_identifier(entity, kind)
        check_version(version)
        if version == 0:
            raise ABACError(
                ErrorCode.VERSION_NOT_MONOTONIC,
                "写入版本号必须 >= 1（0 保留给“尚无数据”的空快照）",
            )
        if not isinstance(attrs, dict):
            raise ABACError(ErrorCode.INVALID_INPUT, "attrs 必须是对象")
        normalized = {key: normalize(value) for key, value in attrs.items()}

        latest_table = f"{kind}_latest"
        version_table = f"{kind}_versions"
        with self._lock:
            try:
                self._begin_write()
                schema = self._latest_schema(tenant)
                if schema is not None:
                    self._validate_attrs_against_schema(normalized, schema, kind)

                row = self.conn.execute(
                    f"SELECT version FROM {latest_table} WHERE tenant = ? AND entity = ?",
                    (tenant, entity),
                ).fetchone()
                current = 0 if row is None else row["version"]
                duplicate = self.conn.execute(
                    f"SELECT attrs_json FROM {version_table} "
                    "WHERE tenant = ? AND entity = ? AND version = ?",
                    (tenant, entity, version),
                ).fetchone()

                import json

                attrs_json = json.dumps(
                    {key: _json_safe(value) for key, value in normalized.items()},
                    ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                )

                if duplicate is not None:
                    # 同版本冲突检查优先：内容相同是幂等重放（直接成功），
                    # 内容不同必须拒绝（DUPLICATE_VERSION_CONTENT）。
                    if duplicate["attrs_json"] != attrs_json:
                        raise ABACError(
                            ErrorCode.DUPLICATE_VERSION_CONTENT,
                            f"{kind} 版本 {version} 已存在且属性内容不同",
                            {"version": version, "current_version": current},
                        )
                    self.conn.execute("COMMIT")
                    return {
                        "tenant": tenant, "entity": entity, "kind": kind,
                        "version": version, "attribute_count": len(normalized),
                        "idempotent": True,
                    }
                if version <= current:
                    raise ABACError(
                        ErrorCode.VERSION_NOT_MONOTONIC,
                        f"{kind} 版本必须单调递增：当前 {current}，提交 {version}",
                        {"current": current, "submitted": version},
                    )

                now = _utc_now()
                self.conn.execute(
                    f"INSERT INTO {version_table} "
                    "(tenant, entity, version, attrs_json, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (tenant, entity, version, attrs_json, now),
                )
                self.conn.execute(
                    f"INSERT INTO {latest_table} (tenant, entity, version, attrs_json, updated_at) "
                    "VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(tenant, entity) DO UPDATE SET "
                    "version=excluded.version, attrs_json=excluded.attrs_json, "
                    "updated_at=excluded.updated_at",
                    (tenant, entity, version, attrs_json, now),
                )
                self.conn.execute("COMMIT")
            except Exception:
                  self.conn.execute("ROLLBACK")
                  raise
        return {
            "tenant": tenant, "entity": entity, "kind": kind,
            "version": version, "attribute_count": len(normalized),
        }

    def put_subject_attrs(self, tenant: str, subject: str, version: int,
                          attrs: dict) -> dict:
        return self._put_entity("subject", tenant, subject, version, attrs)

    def put_resource_attrs(self, tenant: str, resource: str, version: int,
                           attrs: dict) -> dict:
        return self._put_entity("resource", tenant, resource, version, attrs)

    # ------------------------------------------------------------------ #
    # 策略批量替换（原子：先引用/类型检查，再版本检查，最后提交）
    # ------------------------------------------------------------------ #
    def replace_policy(self, tenant: str, doc: dict, schema: dict | None = None) -> dict:
        check_identifier(tenant, "tenant")
        if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
            raise ABACError(ErrorCode.INVALID_INPUT, "策略文档必须含 rules 列表")
        version = check_version(doc.get("version"), field="policy.version")
        if version == 0:
            raise ABACError(
                ErrorCode.VERSION_NOT_MONOTONIC,
                "策略版本号必须 >= 1（0 保留给空快照）",
            )
        schema = schema or _EMPTY_SCHEMA
        if not isinstance(schema, dict):
            raise ABACError(ErrorCode.INVALID_INPUT, "schema 必须是对象")
        # 先做引用与类型检查；失败直接抛错，此时尚未开启写事务，原策略不动。
        from .policy import validate_policy_doc

        validate_policy_doc(doc, schema)
        self._validate_schema_shape(schema)

        import json

        doc_json = canonical_json(doc)
        schema_json = canonical_json(schema)
        with self._lock:
            try:
                self._begin_write()
                row = self.conn.execute(
                    "SELECT version FROM policy_latest WHERE tenant = ?", (tenant,)
                ).fetchone()
                current = 0 if row is None else row["version"]
                duplicate = self.conn.execute(
                    "SELECT doc_json FROM policy_versions WHERE tenant = ? AND version = ?",
                    (tenant, version),
                ).fetchone()
                if duplicate is not None:
                    # 重复版本内容冲突检查优先于单调性检查：
                    # 同版本同内容 -> 幂等重放成功；同版本异内容 -> 拒绝，原策略不动。
                    if duplicate["doc_json"] != doc_json:
                        raise ABACError(
                            ErrorCode.DUPLICATE_VERSION_CONTENT,
                            f"租户 {tenant} 策略版本 {version} 已存在且内容不同",
                            {"version": version, "current_version": current},
                        )
                    self.conn.execute("COMMIT")
                    return {
                        "tenant": tenant, "version": version,
                        "rule_count": len(doc["rules"]), "idempotent": True,
                    }
                if version <= current:
                    raise ABACError(
                        ErrorCode.VERSION_NOT_MONOTONIC,
                        f"策略版本必须单调递增：当前 {current}，提交 {version}",
                        {"current": current, "submitted": version},
                    )
                now = _utc_now()
                self.conn.execute(
                    "INSERT INTO policy_versions "
                    "(tenant, version, doc_json, schema_json, rule_count, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (tenant, version, doc_json, schema_json, len(doc["rules"]), now),
                )
                self.conn.execute(
                    "INSERT INTO policy_latest "
                    "(tenant, version, doc_json, schema_json, updated_at) "
                    "VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(tenant) DO UPDATE SET "
                    "version=excluded.version, doc_json=excluded.doc_json, "
                    "schema_json=excluded.schema_json, updated_at=excluded.updated_at",
                    (tenant, version, doc_json, schema_json, now),
                )
                self.conn.execute(
                    "INSERT INTO tenant_schema (tenant, schema_json, updated_at) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT(tenant) DO UPDATE SET "
                    "schema_json=excluded.schema_json, updated_at=excluded.updated_at",
                    (tenant, schema_json, now),
                )
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
        return {"tenant": tenant, "version": version, "rule_count": len(doc["rules"])}

    @staticmethod
    def _validate_schema_shape(schema: dict) -> None:
        for kind in ("subject", "resource"):
            section = schema.get(kind, {})
            if not isinstance(section, dict):
                raise ABACError(
                    ErrorCode.INVALID_INPUT, f"schema.{kind} 必须是对象"
                )
            for attr_name, attr_type in section.items():
                if not isinstance(attr_name, str) or not attr_name:
                    raise ABACError(
                        ErrorCode.INVALID_INPUT, "schema 属性名必须是非空字符串"
                    )
                if attr_type not in ("string", "integer", "set"):
                    raise ABACError(
                        ErrorCode.TYPE_MISMATCH,
                        f"schema.{kind}.{attr_name} 类型必须是 "
                        "string/integer/set",
                    )

    # ------------------------------------------------------------------ #
    # 历史版本读取（差分与测试证据）
    # ------------------------------------------------------------------ #
    def get_policy_version(self, tenant: str, version: int) -> dict:
        check_identifier(tenant, "tenant")
        check_version(version)
        if version == 0:
            return {"version": 0, "doc": dict(_EMPTY_POLICY),
                    "schema": dict(_EMPTY_SCHEMA)}
        row = self.conn.execute(
            "SELECT doc_json, schema_json FROM policy_versions "
            "WHERE tenant = ? AND version = ?",
            (tenant, version),
        ).fetchone()
        if row is None:
            raise ABACError(
                ErrorCode.VERSION_CONFLICT,
                f"租户 {tenant} 不存在策略版本 {version}",
            )
        import json

        return {
            "version": version,
            "doc": json.loads(row["doc_json"]),
            "schema": json.loads(row["schema_json"]),
        }

    def list_policy_versions(self, tenant: str) -> list[int]:
        check_identifier(tenant, "tenant")
        rows = self.conn.execute(
            "SELECT version FROM policy_versions WHERE tenant = ? ORDER BY version",
            (tenant,),
        ).fetchall()
        return [row["version"] for row in rows]

    def latest_versions(self, tenant: str, subject: str, resource: str) -> dict:
        """自动提交模式下读取当前三个版本号（缓存键构造前的快速探测也走它）。"""
        check_identifier(tenant, "tenant")
        check_identifier(subject, "subject")
        check_identifier(resource, "resource")
        sub = self.conn.execute(
            "SELECT version FROM subject_latest WHERE tenant = ? AND entity = ?",
            (tenant, subject),
        ).fetchone()
        res = self.conn.execute(
            "SELECT version FROM resource_latest WHERE tenant = ? AND entity = ?",
            (tenant, resource),
        ).fetchone()
        pol = self.conn.execute(
            "SELECT version FROM policy_latest WHERE tenant = ?", (tenant,)
        ).fetchone()
        return {
            "policy_version": 0 if pol is None else pol["version"],
            "subject_version": 0 if sub is None else sub["version"],
            "resource_version": 0 if res is None else res["version"],
        }

    # ------------------------------------------------------------------ #
    # 判定日志（快照提交后独立短事务写入，失败不影响判定）
    # ------------------------------------------------------------------ #
    def append_decision_log(self, entry: dict) -> None:
        import json

        versions = entry["versions"]
        with self._lock:
            try:
                self.conn.execute(
                    "INSERT INTO decision_log "
                    "(tenant, subject, resource, action, decision, policy_version, "
                    "subject_version, resource_version, matched_rule_ids, cache_hit, "
                    "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        entry["tenant"], entry["subject"], entry["resource"],
                        entry["action"], entry["decision"],
                        versions["policy_version"], versions["subject_version"],
                        versions["resource_version"],
                        json.dumps(entry["matched_rules"], sort_keys=True),
                        1 if entry["cache_hit"] else 0, _utc_now(),
                    ),
                )
                self.conn.commit()
            except sqlite3.Error:  # pragma: no cover - 日志失败不影响主流程
                self.conn.rollback()

    def list_decision_log(self, limit: int = 100) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM decision_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]
