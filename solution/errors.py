"""错误码定义。

所有可预期的失败都抛出 :class:`ABACError`，携带稳定的机器可读错误码
``code`` 与人类可读说明 ``message``。CLI/批处理入口不吞掉错误码，
而是原样写入结果 JSON，便于测试断言。
"""

from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    # 输入 / schema 类
    INVALID_INPUT = "INVALID_INPUT"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    UNSUPPORTED_FILE_ENCODING = "UNSUPPORTED_FILE_ENCODING"

    # 版本类
    VERSION_CONFLICT = "VERSION_CONFLICT"
    VERSION_NOT_MONOTONIC = "VERSION_NOT_MONOTONIC"
    DUPLICATE_VERSION_CONTENT = "DUPLICATE_VERSION_CONTENT"

    # 策略类
    POLICY_VALIDATION_FAILED = "POLICY_VALIDATION_FAILED"
    UNKNOWN_RULE_REFERENCED = "UNKNOWN_RULE_REFERENCED"
    TYPE_MISMATCH = "TYPE_MISMATCH"

    # 存储 / 并发类
    SNAPSHOT_NOT_ACTIVE = "SNAPSHOT_NOT_ACTIVE"
    SNAPSHOT_NOT_FINALIZED = "SNAPSHOT_NOT_FINALIZED"
    STORE_BUSY = "STORE_BUSY"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ABACError(Exception):
    """带稳定错误码的业务异常。"""

    def __init__(self, code: ErrorCode, message: str, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict:
        return {
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
        }

    def __str__(self) -> str:  # pragma: no cover - 调试用
        return f"{self.code.value}: {self.message}"
