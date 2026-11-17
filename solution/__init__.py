"""多租户 ABAC 授权服务。

模块划分：
- errors:  带错误码的异常体系
- model:   值类型、JSON 编解码、版本号工具
- policy:  策略表达式三值逻辑求值与静态校验
- store:   SQLite 持久化（WAL 快照、单调版本、原子替换）
- engine:  快照判定、版本化缓存、可解释判定树
- diff:    有限属性域上的旧/新策略差分
- runner:  cases.json 批处理入口
"""

from .errors import ABACError, ErrorCode
from .model import MISSING, decode_value, encode_value
from .policy import evaluate_rule, validate_policy_doc
from .store import Store
from .engine import Engine, DecisionHandle
from .diff import diff_policies

__all__ = [
    "ABACError",
    "ErrorCode",
    "MISSING",
    "decode_value",
    "encode_value",
    "evaluate_rule",
    "validate_policy_doc",
    "Store",
    "Engine",
    "DecisionHandle",
    "diff_policies",
]
