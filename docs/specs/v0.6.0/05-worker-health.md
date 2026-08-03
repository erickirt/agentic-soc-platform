# Worker Health

Status: Confirmed

## 1. Purpose

让 Admin 不依赖 Docker CLI 或日志文件，就能判断后台 Worker 是否仍在运行、最近一次轮询是否成功，以及当前是否正在执行任务。

Worker Health 只表达 Worker 进程和轮询循环状态，不表达单个 Playbook、Case Analysis、Module 或告警处理结果。

## 2. Workers

监控五类长期运行 Worker：

1. Agentic Module。
2. Case Analysis。
3. Playbook。
4. ELK Action。
5. Dashboard Cache。

当前 Compose 每类 Worker 只运行一个实例。简化版不实现 singleton lease、多实例聚合或自动扩缩容。

## 3. Excluded

- 业务任务失败聚合。
- Queue、Redis Stream 或缓存 backlog diagnostics。
- Worker Restart、Stop 或 Run Now。
- 日志读取或下载。
- 健康通知。
- 历史趋势和 uptime。
- 自动 Stalled 判定。
- PostgreSQL 持久化。

单个业务任务的失败继续由对应 Run/Job、日志和业务页面表达。

## 4. Redis state

每类 Worker 使用一个固定 Redis hash：

```text
worker-health:v1:{worker_type}
```

状态不设 TTL。API 根据 `heartbeat_at` 判断是否过期，因此 Worker 崩溃后仍能展示最后一次心跳、成功和失败信息。

字段：

| Field | Meaning |
| --- | --- |
| worker_type | 稳定类型标识 |
| state | Starting/Idle/Running/Degraded/Down |
| reason | 固定安全 reason |
| started_at | 当前进程开始时间 |
| heartbeat_at | 最近心跳 |
| iteration_started_at | 当前 iteration 开始时间 |
| last_iteration_success_at | 最近成功轮询 |
| last_processed_at | 最近处理到业务工作 |
| last_failure_at | 最近轮询基础设施失败 |
| last_duration_ms | 最近完成 iteration 耗时 |
| last_message | 安全任务摘要 |
| last_error | 规范化安全错误 |

不保存 PID、command、环境变量、Secret、原始异常或 traceback。

## 5. Heartbeat

- 长期运行 Worker 启动 daemon heartbeat thread。
- 每 10 秒更新 `heartbeat_at`。
- 长任务执行期间 heartbeat 继续更新。
- API 发现 heartbeat 超过 30 秒未更新时计算为 `Down/heartbeat_expired`。
- Redis 中没有状态时返回 `Down/never_reported`。
- `--once` 不写 Worker Health，避免覆盖正式 Worker 状态。

状态 key 不提供并发 owner 保护；同类型多实例会互相覆盖，属于当前明确不支持的部署方式。

## 6. Lifecycle

### Start

Worker 写入：

- `state=Starting`
- `started_at=now`
- `heartbeat_at=now`

### Iteration start

Worker 写入：

- `state=Running`
- `iteration_started_at=now`

不设置统一运行超时。页面显示当前运行时长，由 Admin 判断是否异常。

### Iteration success

Worker 写入：

- `state=Idle`
- `last_iteration_success_at=now`
- `last_duration_ms`
- 安全 `last_message`

只有 `WorkerIterationResult.processed=true` 时更新 `last_processed_at`。

### Iteration failure

只有逃逸到公共 Worker loop 的轮询基础设施异常才写入：

- `state=Degraded`
- `reason=iteration_failed`
- `last_failure_at=now`
- `last_duration_ms`
- 固定安全 `last_error`

下一次成功 iteration 恢复 `Idle`。

自定义 Playbook、Module 或单个 Case Analysis 等已被业务层捕获的任务失败不改变 Worker Health。

### Exit

KeyboardInterrupt 等优雅退出写入 `Down/graceful`。进程被强杀时无法写退出状态，API 在心跳过期后计算为 Down。

## 7. API

```text
GET /api/settings/workers/
```

- 仅 Admin。
- User/Viewer 返回 403。
- 固定返回五类 expected Worker。
- API 只读取 Redis，不触发任务或健康检查。
- Redis 不可访问时返回 HTTP 503：

```json
{
  "detail": "Worker health monitoring is unavailable."
}
```

每行返回核心运行字段、`display_name`、安全 `log_role`，并在 Running 时计算 `running_duration_seconds`。

## 8. Frontend

位置：`System Settings → Workers`。

- 页面进入时立即加载。
- 每 10 秒自动刷新。
- 不提供手动 Refresh。
- 展示 Worker、状态、当前或最近任务摘要、最后心跳、最后成功、最后处理、最后失败、耗时和安全错误。
- 不展示 hostname、instance ID、累计计数器、backlog、日志内容或运维命令。
- Redis 不可访问时显示页面级错误，并在下一刷新周期自动重试。

## 9. Error safety

API 中的 `last_error` 只包含：

- exception type。
- 固定 message：`Worker iteration failed.`

完整异常只进入 Worker 日志。API 不得返回 exception message、traceback、HTTP response、业务输入、username、password、token 或 API key。

## 10. Audit

- Health read 不写 AuditLog。
- heartbeat 和状态变化不写 AuditLog。
- 页面没有 mutation 操作。

## 11. Acceptance criteria

1. 五类长期 Worker 启动后显示 Starting，并在 iteration 完成后显示 Idle。
2. iteration 执行期间显示 Running，长任务 heartbeat 不停止。
3. 轮询基础设施异常立即显示 Degraded，下一次成功恢复 Idle。
4. 单个业务任务失败不改变 Worker Health。
5. `processed=true` 才更新 last_processed_at。
6. 强杀 Worker 后约 30 秒显示 Down/heartbeat_expired。
7. 从未上报显示 Down/never_reported。
8. `--once` 不覆盖长期 Worker 状态。
9. Redis 不可用时 API 返回 503。
10. API 不泄露原始异常或 Secret。
11. User/Viewer 403，Admin 页面每 10 秒刷新且没有手动 Refresh。

## 12. Known tradeoffs

- Redis 故障时无法独立展示 Worker Health。
- 不支持同类型多实例。
- daemon heartbeat 在线时，主线程死循环仍显示 Running。
- 没有 backlog 时无法判断 Worker 是否跟得上业务量。
- 没有通知，Admin 需要进入 Workers 页面查看状态。
