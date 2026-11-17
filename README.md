# 多租户 ABAC 授权服务

基于 SQLite（WAL 模式）的多租户属性访问控制（ABAC）授权服务。策略、主体属性、
资源属性全部携带**单调递增版本号**；每次判定在**同一数据库快照**上读取三类数据；
支持三值逻辑（含缺失属性）、版本化结果缓存、原子策略批量替换、可解释判定树，
以及有限属性域上的旧/新策略穷举差分。

仅使用 Python 3.12 标准库（`sqlite3`、`multiprocessing`、`threading`、`json` 等），
无第三方依赖、无 Docker、无外部服务，CPU-only，可直接在 Windows 上运行。

## 1. 目录结构

```
.
├── solution/                # 交付的包
│   ├── __init__.py          # 公共导出
│   ├── __main__.py          # python -m solution 命令行入口
│   ├── errors.py            # 错误码与 ABACError
│   ├── model.py             # 值类型、JSON 编解码、版本/标识符校验
│   ├── policy.py            # 策略 AST、静态校验、三值逻辑、判定树
│   ├── store.py             # SQLite 持久化、WAL 快照、原子替换、版本历史
│   ├── engine.py            # 快照判定句柄、版本化缓存、deny 优先
│   ├── diff.py              # 有限域穷举差分（旧拒绝→新允许反例）
│   └── runner.py            # cases.json 批处理运行器
├── tests/                   # unittest 自动化测试（57 个用例）
│   ├── _helpers.py
│   ├── test_tribool.py      # 三值逻辑真值表与策略静态校验
│   ├── test_store.py        # 单调版本、原子替换、冲突、跨租户隔离
│   ├── test_engine.py       # deny 优先、默认拒绝、缓存、快照隔离、并发
│   ├── test_diff.py         # 小域穷举 + 独立暴力复核 + 反例回放
│   ├── test_barrier.py      # 多进程屏障检验撤权边界（spawn）
│   └── test_e2e.py          # cases.json 与 CLI 子进程端到端
├── samples/                 # 策略/schema/二进制样例
│   ├── schema.json
│   ├── policy_v1.json
│   ├── policy_v2.json
│   ├── policy_v3_relaxed.json
│   ├── policy_bad_reference.json
│   ├── policy_bad_type.json
│   ├── policy_bad_bool_lit.json
│   └── binary_sample.bin
├── cases.json               # 批处理输入（6 个验收场景 case）
└── README.md
```

## 2. 两个规定入口

```bash
# 批处理：读 cases.json，写 result.json；全部断言通过退出码 0，否则 1
python -m solution --input cases.json --output .runtime-tmp/result.json

# 自动化测试（详细输出）
python -m unittest discover -s tests -v
```

所有数据库与临时产物只写入项目内的 `.runtime-tmp/`（已在 `.gitignore` 忽略
`*.db`、`*.db-wal`、`*.db-shm`、`.runtime-tmp/`）。

## 3. 值类型与策略语言

### 3.1 值

仅支持三种值，布尔值（`true`/`false`）**不是合法属性值**：

| 类型 | JSON 形态 | 内部表示 |
|---|---|---|
| 字符串 | `"eng"` | `str` |
| 整数 | `7` | `int`（拒绝 `bool`） |
| 集合 | `["a", "b"]`（元素只能是字符串/整数，不可嵌套） | `frozenset` |

### 3.2 表达式 AST

| 节点 | 形态 | 静态类型约束 |
|---|---|---|
| 属性引用 | `{"op":"attr","kind":"subject"|"resource","name":...}` | 取 schema 声明类型 |
| 字面量 | `{"op":"lit","value":...}` | string/integer/set |
| 相等 | `{"op":"eq","left":...,"right":...}` | 两侧同类型 |
| 属于 | `{"op":"in","left":...,"right":...}` | 左标量、右集合，元素类型匹配 |
| 小于 | `{"op":"lt","left":...,"right":...}` | 两侧均 integer |
| 与/或 | `{"op":"and"|"or","children":[...]}` | 子节点必须都是谓词 |
| 非 | `{"op":"not","child":...}` | 子节点必须是谓词 |

规则：`{"id","action","effect":"allow"|"deny","expression"}`。

### 3.3 三值逻辑（Kleene 强三值逻辑）

三值为 `true` / `false` / `unknown`。属性**缺失**时，取该属性的比较运算
（eq/in/lt）结果为 `unknown`：

- `NOT unknown = unknown`（缺字段取反**不会**产生 true）
- `AND`：任一子式为 `false` → `false`；否则含 `unknown` → `unknown`；否则 `true`
- `OR`：任一子式为 `true` → `true`；否则含 `unknown` → `unknown`；否则 `false`

判定语义：

1. 只有表达式明确为 `true` 才算规则**命中**；`unknown` 不命中。
2. 命中的 `deny` 优先于命中的 `allow`。
3. 没有任何 allow 命中（全部 false/unknown）时**默认拒绝**。

注意：**空集合是合法属性值**。`roles` 存在但为 `[]` 时，`"x" in roles`
是明确 `false`，只有属性键不存在才是 `unknown`。

## 4. 版本号与快照语义

- 版本号为非负整数；`0` 保留给“尚无数据”的空快照，写入必须 `>= 1`。
- 主体/资源属性按 `(租户, 实体)` 独立计版本，策略按租户计版本，三者互不影响。
- 每次写入全量替换该实体属性，版本必须**严格大于**当前最新版本。
- **同版本提交**：
  - 内容与已存版本字节一致（规范化 JSON 后比较）→ 幂等重放，返回 `"idempotent": true`；
  - 内容不同 → `DUPLICATE_VERSION_CONTENT` 拒绝，原数据保持不变。
  - 该检查在写事务内、单调性检查之前执行，因此“同版本冲突”优先报冲突码。
- 每次判定通过 `Engine.open_decision()` 进入 `BEGIN` 只读事务，SQLite WAL
  在事务首次读时固定快照；策略与两类属性在**同一快照**内读取，结果附带
  `policy_version / subject_version / resource_version` 三个版本。
- 在途请求持有旧快照期间，其它连接提交的写入对它不可见（旧快照完成）；
  句柄关闭后开启的新请求看到新数据。

## 5. 版本化缓存

缓存键为七元组：

```
(tenant, subject, resource, action, policy_version, subject_version, resource_version)
```

任一标识符或任一版本变化都会产生新键，因此撤权提交后新开始的请求不可能命中
旧 allow 条目。缓存只在快照事务成功提交后发布；可通过 `Engine(cache_enabled=False)`
关闭，或调用 `cache_clear()` 清空。判定结果中的 `cache_hit` 与 `decision_log`
表中的 `cache_hit` 列提供命中证据。

## 6. 策略批量替换的原子性

`Store.replace_policy(tenant, doc, schema)` 顺序：

1. **事务外**先做完整静态校验：结构、未知属性引用、eq/in/lt 类型、布尔嵌套、
   规则 id 唯一、effect 合法、schema 形状。任何失败直接抛
   `POLICY_VALIDATION_FAILED`（细节在 `details.errors`），数据库完全不接触。
2. 开启 `BEGIN IMMEDIATE` 写事务（全库写串行化）。
3. 同版本内容冲突检查 → 单调版本检查 → 写 `policy_versions` 历史表、
   更新 `policy_latest` 指针与 `tenant_schema`，统一 `COMMIT`。
4. 任何异常都 `ROLLBACK`，非法版本/非法文档出现后原策略与原 schema 原样保留
   （测试 `test_invalid_policy_keeps_previous_policy` 断言）。

## 7. 有限域差分

`diff_policies(old_doc, new_doc, old_schema, new_schema, domains=..., actions=...)`：

- 对 schema 中每个属性构造有限域，**每个域自动在头部加入 `MISSING` 取值**，
  因此缺字段三值逻辑同样被穷举。默认域：integer `[0,1]`、string `["a","b"]`、
  set `[∅, {x}, {x,y}]`；可通过 `domains` 显式覆盖。
- 笛卡尔积枚举所有 (主体属性, 资源属性, 动作) 组合，用与引擎完全相同的
  `evaluate_rule` 分别跑旧/新策略。
- 输出：
  - `gained_allow_examples`：**旧拒绝 → 新允许**的具体反例（权限放大，重点项），
    每条含动作、具体赋值、缺失属性清单、两边各自的命中规则与三值；
  - `lost_allow_examples`：旧允许 → 新拒绝（权限收窄）；
  - `summary`：空间大小、稳定点数、两类计数与截断信息（`limit` 之外只计数不丢弃）。
- 测试用一份**独立实现的笛卡尔积暴力枚举**复核计数，并把反例回放到两份策略
  验证结论可复现。

## 8. cases.json 输入 / result.json 输出 schema

### 8.1 输入

```json
{
  "cases": [
    {
      "name": "可读名称",
      "db": ".runtime-tmp/xxx.db",
      "steps": [ {"type": "...", ...} ]
    }
  ]
}
```

`db` 相对 cases.json 所在目录；每个 case 运行前自动清理同名 db/wal/shm，
保证可重放。步骤类型：

| type | 关键字段 | 说明 |
|---|---|---|
| `put_subject` / `put_resource` | tenant, subject/resource, version, attrs | 写属性（全量替换） |
| `replace_policy` | tenant, doc, schema? | 原子策略替换 |
| `decide` | tenant, subject, resource, action + 可选 expect_* | 判定并内联断言 |
| `diff` | old_doc, new_doc, old_schema, new_schema, domains?, actions? | 纯函数差分 |
| `diff_stored` | tenant, old_version, new_version | 取两个历史策略版本差分 |
| `expect_error` | code | 消费上一步抛出的预期错误码 |
| `inspect_cache` / `cache_clear` | — | 缓存统计 / 清空 |
| `list_versions` | tenant | 列出策略历史版本 |
| `assert_equal` | actual, expected | 通用断言（配合文件标记） |

`decide` 支持的内联断言：`expect_decision`、`expect_cache_hit`、
`expect_versions`、`expect_matched`（`{"allow":[...], "deny":[...]}`）、
`expect_tribool`（规则 id → true/false/unknown）。
`diff` 支持 `expect_space_size`、`expect_gained_allow_count`、
`expect_lost_allow_count`。

### 8.2 文件引用标记

任意字符串值位置可引用项目内源文件或二进制样例（路径相对 cases.json）：

```json
{"$file": "samples/policy_v1.json"}
{"$binary": "samples/binary_sample.bin", "encoding": "base64|hex|utf-8"}
```

### 8.3 输出

```json
{
  "ok": true,
  "cases": [
    {
      "name": "...",
      "ok": true,
      "steps": [
        {
          "index": 0, "type": "decide", "ok": true,
          "result": {
            "tenant": "...", "subject": "...", "resource": "...",
            "action": "read",
            "decision": "allow|deny",
            "reason": "...",
            "cache_hit": false,
            "versions": {"policy_version": 1, "subject_version": 2,
                         "resource_version": 1},
            "matched_rules": {"allow": ["..."], "deny": []},
            "evaluated_rules": [
              {"rule_id": "...", "effect": "allow",
               "tribool": "true|false|unknown", "matched": true,
               "tree": {"expr": "(...)", "result": "true",
                        "reasons": ["..."], "children": [...]}}
            ],
            "snapshot": {"subject_attrs": {...}, "resource_attrs": {...}}
          }
        }
      ]
    }
  ]
}
```

错误步骤记录 `"error": {"code", "message", "details"}`；断言失败记录
`"assertion_failures"`；未被 `expect_error` 消费的错误会使整个 case 失败并在
case 级输出 `unconsumed_error`。

## 9. 错误码

| code | 触发场景 |
|---|---|
| `INVALID_INPUT` | 入参结构/标识符非法、未知 step 类型、属性名非法 |
| `FILE_NOT_FOUND` | `$file`/`$binary` 引用的项目内文件不存在 |
| `UNSUPPORTED_FILE_ENCODING` | 二进制标记使用了 base64/hex/utf-8 之外的编码 |
| `VERSION_CONFLICT` | 读取不存在的历史版本等版本冲突 |
| `VERSION_NOT_MONOTONIC` | 写入版本不大于当前版本，或提交版本号为 0 |
| `DUPLICATE_VERSION_CONTENT` | 同版本号已存在且内容不同（策略与属性通用） |
| `POLICY_VALIDATION_FAILED` | 策略引用未声明属性、类型不符、布尔值作属性值、空 rules、id 重复等 |
| `TYPE_MISMATCH` | 属性值与 schema 声明类型不符、集合元素类型非法、schema 类型名非法 |
| `SNAPSHOT_NOT_ACTIVE` | 快照事务外调用读接口、快照内开启写事务、重复打开快照 |
| `SNAPSHOT_NOT_FINALIZED` | 无活动快照却提交、同一句柄重复判定 |
| `STORE_BUSY` | `BEGIN IMMEDIATE` 获取写锁失败（busy_timeout 5s） |
| `INTERNAL_ERROR` | 其它防御性 SQLite 异常 |

## 10. 验收场景映射

| 题目要求 | 覆盖位置 |
|---|---|
| 缺字段取反（NOT unknown=unknown） | `test_tribool.py::BooleanTriboolTests`、cases 01、`test_missing_field_negation_does_not_grant` |
| 跨租户同名主体 | `test_store.py::CrossTenantIsolationTests`、cases 02 |
| 缓存期间属性变化 | `test_engine.py::VersionedCacheTests`、cases 03 |
| 策略替换与读取并发 | `test_concurrent_policy_replace_and_read`（双连接线程）、`test_inflight_request_keeps_old_snapshot` |
| 冲突版本 | `test_duplicate_version_different_content_rejected`、`test_duplicate_policy_version_conflict_rejected_and_preserved`、cases 04 |
| 布尔嵌套（AND/OR/NOT + unknown） | `test_nested_boolean_mix`、cases 01、samples/policy_v2.json |
| 小域穷举核对差分 | `test_diff.py` 全部用例（含独立暴力复核与反例回放）、cases 05/06 |
| 进程屏障检验撤权边界 | `test_barrier.py`（spawn 3 worker + 主进程屏障 + 迟到进程，证据落盘） |

## 11. 可重放性与范围约束

- 无随机数、无时间依赖的断言；时间戳仅用于 `updated_at` 审计列，不参与判定。
- 所有文件操作限定在项目目录；进程测试只用 `multiprocessing` 屏障/队列与
  本机 SQLite 文件，无网络监听、无外部服务。
- 子进程通过 `sys.executable` 以 spawn 方式启动（Windows 默认），worker 为
  模块级函数，数据库路径传绝对路径。
