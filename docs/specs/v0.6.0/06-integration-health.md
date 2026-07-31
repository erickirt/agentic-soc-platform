# Integration Health

Status: Confirmed

## 1. Purpose

通过独立定时 Worker 主动验证正式支持的外部集成和关键依赖，并在 Admin Operations 页面展示每个配置实例的当前状态。

该功能表达“最近一次轻量检查是否成功”，不保证所有业务查询、数据权限或具体动作都可用。

## 2. Targets

定时检查：

- Splunk singleton config。
- ELK singleton config。
- 每个 enabled OpenAI-compatible LLM Provider。
- AlienVault OTX。
- OpenCTI。
- LDAP。
- Redis。
- S3-compatible object storage。

不检查 PostgreSQL；Web/API 本身已依赖 PostgreSQL。

大量 EnrichmentProvider 枚举值不等于可检查的官方集成。

## 3. Dedicated Worker

新增 `run_integration_health_worker`：

- 使用公共 `run_worker()`。
- 作为第六类 singleton Worker 出现在 Worker Health。
- 固定每 5 分钟检查一次。
- 串行检查目标。
- 单目标超时 10 秒。
- 单项失败后继续其他目标。
- iteration 中任一失败使 Integration Health Worker 本轮 `failure_count > 0`，因此 Worker 状态 Degraded。

页面加载不直接 fan-out 外部请求。

## 4. States

持久状态只有：

- Healthy
- Unhealthy
- Disabled

附加 reason 表达细节：

| Situation | State | Reason |
| --- | --- | --- |
| enabled, never checked | Unhealthy | never_checked |
| check running | 保持原状态 | transient `checking=true` |
| last check succeeded | Healthy | ok |
| last check failed | Unhealthy | normalized failure code |
| config disabled | Disabled | disabled |
| config incomplete/not configured | Disabled | not_configured |

不使用 Unknown/Degraded/Checking 作为持久 state。

未配置和 Disabled 是中性状态，不算健康也不算故障。页面不计算整体 platform/integration status。

## 5. Data model

建议模型 `IntegrationHealth`：

| Field | Type | Notes |
| --- | --- | --- |
| id | UUID | primary key |
| integration_type | string enum | splunk/elk/llm/otx/opencti/ldap/redis/storage |
| config_object_id | nullable string | LLM Provider UUID；singleton/dependency 使用稳定 sentinel |
| display_name | string | safe display label |
| state | enum | Healthy/Unhealthy/Disabled |
| reason_code | string | normalized |
| message | string | fixed safe message |
| checking_started_at | nullable datetime | transient check marker |
| last_checked_at | nullable datetime | any completed check |
| last_success_at | nullable datetime | successful check |
| last_failure_at | nullable datetime | failed check |
| duration_ms | nullable integer | latest check |
| consecutive_failures | nonnegative integer | reset on success |
| updated_at | datetime | auto |

Constraints:

- unique `(integration_type, config_object_id)`，null/sentinel 处理必须稳定。
- index `(state, integration_type)`。
- 不保存完整 config、URL、username、Secret、response body。

只保存当前状态，不保存历史行或趋势。

## 6. Configuration synchronization

### Create

- 新 enabled config：创建 Unhealthy/never_checked。
- 新 disabled config：创建 Disabled/disabled。

### Update

相关配置字段改变：

- Enabled：立即 Unhealthy/configuration_changed。
- Disabled：Disabled/disabled。
- 不保留旧 Healthy 到下一个检查。

现有 Settings 保存逻辑应在同一 transaction commit 后同步 health 状态。

### Delete

- 多实例配置（例如 LLM Provider）删除时同步硬删除 health row。
- singleton config 不删除；Disabled 时保留 Disabled row。
- 配置 CRUD 自身继续由现有 AuditLog 追溯。

## 7. Check depth by target

### LLM

- 对每个 enabled Provider 发最小 Chat Completions 请求。
- 验证 base URL、认证、model 和实际推理路径。
- 限制最大 token，接受每 5 分钟极低但非零费用。
- 不保存 prompt/response content。

### Splunk

- 使用轻量认证管理/信息接口。
- 不执行 SPL。
- 不依赖 index、time field 或数据存在。

### ELK

- 使用集群 info/health 或等价轻量认证接口。
- 不搜索用户 index。
- 不将 yellow 等集群业务状态自动扩展为复杂 Degraded；检查器应按能否满足现有连接需求返回 Healthy/Unhealthy，并在 reason code 中规范化。

### LDAP

- 连接服务器。
- 使用配置的 bind DN/password 进行 service bind。
- 验证 search base 可访问。
- 不保存或使用专用普通用户测试密码。
- 没有 bind DN 时执行当前支持模式下可行的基础连接/search check。

### OTX/OpenCTI

- 调用轻量身份/账户 endpoint。
- 验证 Token。
- 不执行 IOC 搜索。

### Redis

- PING。
- 读取安全的基础 INFO：版本、内存、连接状态。
- 不写测试 key。
- 不重复 Module stream backlog diagnostics。

### Object storage

- 验证 endpoint、凭据和目标 bucket metadata/list 权限。
- 不写入或删除 probe object。

## 8. Check service contract

统一内部结果：

```python
@dataclass(frozen=True)
class IntegrationCheckResult:
    success: bool
    reason_code: str
    message: str
    duration_ms: int
```

规范 reason_code 至少包括：

- ok
- never_checked
- configuration_changed
- not_configured
- disabled
- authentication_failed
- timeout
- tls_error
- connection_refused
- dns_error
- invalid_response
- permission_denied
- service_unavailable
- unknown_error

message 必须来自固定映射，不直接使用 exception message。

## 9. State update rules

检查开始：

- 设置 checking_started_at。
- 不改变当前 state。

成功：

- state=Healthy。
- reason_code=ok。
- last_checked_at/last_success_at=now。
- consecutive_failures=0。
- 清空 checking_started_at。

失败：

- 第一次失败立即 state=Unhealthy。
- last_checked_at/last_failure_at=now。
- consecutive_failures += 1。
- 保存 normalized reason/message。
- 清空 checking_started_at。

Worker 崩溃遗留 checking_started_at 时，下次 Worker 可覆盖；持久 state 仍是上一次结果。

## 10. Manual Settings tests

保留现有各配置页 Test：

- 用于测试未保存或已保存配置。
- 已保存配置的 Test 结果更新对应 IntegrationHealth。
- 未保存临时配置的 Test 不更新 health。
- Manual Test 继续写现有 AuditLog。
- Unified Integration Health 页面不提供 Check Now。

普通业务调用的成功/失败永不更新 IntegrationHealth，避免查询输入、限流或业务权限错误污染集成状态。

## 11. API

建议：

`GET /api/settings/operations/integrations/`

仅 Admin。

返回每个目标/配置实例的独立状态：

```json
{
  "results": [
    {
      "integration_type": "llm",
      "config_object_id": "...",
      "display_name": "OpenAI Production",
      "state": "Healthy",
      "reason_code": "ok",
      "message": "The provider responded successfully.",
      "checking": false,
      "checking_started_at": null,
      "last_checked_at": "...",
      "last_success_at": "...",
      "last_failure_at": null,
      "duration_ms": 821,
      "consecutive_failures": 0,
      "settings_route": "/system/llm-providers/..."
    }
  ]
}
```

- 不返回 overall status。
- 不返回 Secret、完整 endpoint、username 或 response preview。
- API 只读取 PostgreSQL，不执行检查。
- Redis target 的健康状态也是定时检查结果；与 Worker Health Redis 503 是不同语义。

## 12. Error safety

UI/API 只显示：

- normalized reason code。
- 固定安全 message。
- check time/duration。

禁止：

- 原始 exception。
- traceback。
- response body。
- URL query。
- username。
- API key/token/password。

完整异常进入 Integration Health Worker log，仍需遵循现有日志 Secret 规范。

## 13. Permissions and audit

- 仅 Admin 可看 API/UI。
- User/Viewer 403。
- Scheduled check 不写 AuditLog。
- 定时状态变化不写 AuditLog。
- Manual saved-config Test 写现有 AuditLog。
- 不发送 Inbox/Webhook 健康通知。

## 14. Frontend

位置：`System Settings → Operations → Integration Health`。

- 与 Worker Health 独立表格/API。
- 每 30 秒读取 PostgreSQL 当前状态。
- 提供页面手动 Refresh，但不触发外部检查。
- 展示 integration type/name/state/reason/last check/duration/consecutive failures。
- Disabled/Not configured 可见且使用中性样式。
- enabled never checked 显示 Unhealthy + Never checked。
- checking 时保留原 state Tag并显示 Checking 辅助标记。
- 行可跳转对应 Settings 页面。
- 不显示 overall status。
- 不提供 Check Now。

## 15. Worker Health interaction

Integration Health Worker 自身：

- 使用第六个 Worker type。
- heartbeat/lease 遵循 Worker Health Spec。
- 本轮任一集成失败时 WorkerIterationResult.failure_count > 0，Worker Health 显示 Degraded。
- Integration 表显示具体失败目标。
- Redis health target 失败可能同时导致 Worker 心跳不可用；此时 Worker Health API 可能 503，但 PostgreSQL 中最后 Integration Health 结果仍可显示。

## 16. Migration

- 创建 IntegrationHealth 表。
- 为现有配置生成初始行：
  - enabled/configured → Unhealthy/never_checked。
  - disabled/incomplete → Disabled。
- 不在 migration 中访问外部服务。
- 添加 Integration Health Worker Compose service。
- 更新 log role mapping。

## 17. Acceptance criteria

1. Worker 每 5 分钟串行检查所有 eligible targets。
2. 每项超时 10 秒，失败不阻止后续目标。
3. 各目标使用已确认的轻量检查深度。
4. enabled 首次检查前 Unhealthy/never_checked。
5. 一次失败立即 Unhealthy，一次成功立即恢复。
6. config 修改立即 configuration_changed。
7. saved-config Test 更新状态，unsaved Test 不更新。
8. 业务请求不更新状态。
9. 删除 LLM Provider 同步删除 health row。
10. API 不执行外部请求、不返回敏感信息。
11. Admin-only 和 30 秒 UI 刷新正确。
12. Worker 自身出现在 Worker Health。

## 18. Known tradeoffs

- 没有历史趋势和整体状态。
- 没有统一 Check Now。
- LLM 检查产生持续小额调用成本。
- 一次瞬时失败立即 Unhealthy，可能产生短暂抖动，但当前不发送通知。
- 轻量管理接口 Healthy 不等于所有索引、模型能力或业务查询均正常。
