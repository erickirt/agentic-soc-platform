# Worker Health

Status: Confirmed

## 1. Purpose

让 Admin 不依赖 Docker CLI 或日志文件，就能判断后台 Worker 是否存活、正在做什么、是否失败以及业务积压情况。

v0.6.0 最终监控五个逻辑 Worker：

1. Agentic Module。
2. Case Analysis。
3. Playbook。
4. ELK Action。
5. Dashboard Cache。

监控粒度是逻辑进程类型，不是每个 Module/Playbook definition，也不是 Docker container ID。

## 2. Architecture

Worker Health 基础设施集成进 `apps.common.worker_runner.run_worker()`。

每个 Worker：

- 启动时获取 Redis singleton lease。
- 启动 daemon heartbeat thread。
- 主线程在 iteration 边界更新执行状态与计数。
- 优雅退出时释放 lease并留下安全退出原因。

Admin API 从 Redis 读取当前状态，并按 Worker 类型附加 backlog diagnostics。

## 3. Redis keys

建议：

```text
worker-health:v1:{worker_type}:lease
worker-health:v1:{worker_type}:state
worker-health:v1:{worker_type}:last-exit
```

### Lease

- value 至少包含随机 instance_id。
- TTL 30 秒。
- heartbeat 每 10 秒 compare-and-refresh，只有 owner instance_id 可续租。
- 第二个同类型 Worker 发现有效 lease 后拒绝启动。
- lease 过期后新实例可获取。
- 不允许 last-writer-wins 覆盖。

### State

state 可与 lease 同一个 JSON key，也可独立；必须保证 owner 才能更新。

建议字段：

| Field | Meaning |
| --- | --- |
| worker_type | stable logical identifier |
| instance_id | random UUID per process |
| hostname | safe host/container hostname |
| state | Starting/Idle/Running/Degraded |
| started_at | process start |
| heartbeat_at | last heartbeat |
| iteration_started_at | current/last iteration start |
| last_iteration_success_at | any successful iteration, including idle |
| last_processed_at | last iteration that processed work |
| last_failure_at | last failed/partial-failed iteration |
| last_duration_ms | last iteration duration |
| consecutive_failures | reset on successful iteration |
| iteration_count | process-lifetime count |
| processed_iteration_count | iterations with processed=true |
| success_count | successful iterations |
| failure_count | failed or partial-failed iterations |
| last_message | safe WorkerIterationResult message |
| last_error | normalized safe error |
| log_role | log file role |

PID、完整 command、环境变量和 Secret 不通过 API 暴露。

### Last exit

优雅退出时记录短 TTL 或非租约型安全信息：

- instance_id
- exited_at
- reason=`graceful`

意外退出没有 last-exit update，API 通过 lease expired 判定。

## 4. Heartbeat

- daemon thread 每 10 秒刷新 lease。
- 主线程运行长任务或 sleep 时仍持续刷新。
- heartbeat Redis 写失败应记录安全日志；如果长期失败 lease 会过期。
- heartbeat thread 不改变业务 iteration 状态。
- Running 不设最大时长，也没有 Stalled。
- 只要 heartbeat 存活，任意长任务保持 Running。

线程退出规则：

- Worker 正常 SIGTERM/KeyboardInterrupt 时停止 heartbeat。
- 释放仅属于自身 instance_id 的 lease。
- 不能删除新实例已取得的 lease。

## 5. Singleton startup

Worker 启动：

1. 生成 instance_id。
2. 原子 SET NX 获取 lease。
3. 失败则抛 CommandError 并退出，Compose 可记录重启失败。
4. 成功写 Starting state。
5. 启动 heartbeat thread。
6. 进入主循环。

这适用于所有五个正式 Worker。`--once` 是运维命令，不应长期占用 singleton lease；如果它会与正式 Worker 并行影响同一数据，需要显式决定是否短暂获取 lease，默认建议获取以避免并发。

## 6. States

API 状态：

| State | Definition |
| --- | --- |
| Starting | live lease exists, first iteration not completed |
| Idle | live lease, last iteration successful, currently no work |
| Running | live lease, iteration currently executing |
| Degraded | live lease, latest iteration has any failure |
| Down | expected Worker has no live lease |

### Never reported

系统知道六种 expected worker type。没有 lease 且没有 state/last-exit 时：

- state=Down
- reason=`never_reported`
- UI 显示 Never reported

### Graceful and expired

- 正常退出：Down / graceful。
- 意外崩溃或进程被杀：30 秒后 Down / heartbeat_expired。
- Redis 本身不可用不是 Unknown/Down；整个 Worker Health API 返回 503。

### Degraded recovery

- 一次完整失败立即 Degraded。
- `WorkerIterationResult.failure_count > 0` 的部分失败也立即 Degraded。
- consecutive_failures 增加。
- 下一次无失败的 iteration 清零并恢复 Idle 或完成后的健康状态。

## 7. WorkerIterationResult contract

扩展当前 dataclass：

```python
@dataclass(frozen=True)
class WorkerIterationResult:
    processed: bool = False
    message: str = ""
    failure_count: int = 0
```

语义：

- `processed` 表示至少完成一个业务工作项。
- `failure_count` 表示 iteration 内被捕获的业务失败数。
- 抛异常是完整 iteration failure。
- `message` 必须是安全摘要。

### Time semantics

- 正常 idle polling 更新 `last_iteration_success_at`。
- 只有 `processed=True` 更新 `last_processed_at`。
- partial failure 不更新 success timestamp；是否同时有 processed 由结果如实记录。

## 8. Backlog diagnostics

不得强制统一为 queue_depth。

### Playbook

- Pending Run count。
- oldest Pending age。
- Running count。

### Case Analysis

- Pending job count。
- oldest eligible scheduled job age。
- Running count。

### Module

复用 Redis Stream health：

- stream length。
- consumer group pending。
- consumer count。
- last-delivered-id。
- 可计算的 lag。
- 每个 Module definition 仍在现有 Custom 页面展示；Worker Health 可给汇总和跳转。

### ELK Action

外部索引完整积压不可可靠得知，只显示：

- last poll time。
- last poll actions/sent/skipped。
- last successful processed time。
- current configured interval。

### Dashboard Cache

- 24h/7d/30d 各缓存 age。
- generated/refreshed time。
- configured interval。
- cache missing 标记。

Backlog 查询失败不应使 heartbeat 消失。API 行级 diagnostics 可返回 safe warning。

## 9. Error safety

`last_error` 只包含：

- exception type。
- 标准 reason code 或固定安全摘要。
- failure time。
- log role。

不包含：

- 原始 exception message。
- traceback。
- HTTP response。
- SIEM query/event。
- username、password、token、API key。

完整排查信息留在 Worker 日志。

## 10. API

建议：

`GET /api/settings/operations/workers/`

仅 Admin。

正常返回六行：

```json
{
  "results": [
    {
      "worker_type": "playbook",
      "display_name": "Playbook Worker",
      "state": "Idle",
      "reason": "",
      "instance_id": "...",
      "hostname": "asp-worker-playbook",
      "started_at": "...",
      "heartbeat_at": "...",
      "last_iteration_success_at": "...",
      "last_processed_at": "...",
      "last_failure_at": null,
      "last_duration_ms": 8,
      "consecutive_failures": 0,
      "counters": {},
      "last_message": "",
      "last_error": null,
      "log_role": "agentic-playbook-worker",
      "backlog": {
        "pending_count": 0,
        "oldest_pending_age_seconds": null,
        "running_count": 0
      }
    }
  ]
}
```

Redis health storage 无法访问：

- HTTP 503。
- 固定信息：`Worker health monitoring is unavailable.`
- 不返回五个伪造 Down 状态。

API 不提供：

- Restart。
- Run Now。
- Stop。
- Tail/download logs。
- 历史趋势。

## 11. Permissions and audit

- 仅 Admin 可访问 API/UI。
- User/Viewer 403。
- Health read 不写 AuditLog。
- heartbeat/state change 不写 AuditLog。
- 没有 Worker health notification。

## 12. Frontend

最终位置：`System Settings → Operations → Worker Health`。

行为：

- 每 10 秒自动刷新。
- 提供手动 Refresh。
- 503 显示页面级 monitoring unavailable，不显示全红 Down。
- 状态 Tag：Starting、Idle、Running、Degraded、Down。
- 每行显示心跳、最后处理、最后失败、错误摘要、积压和 log reference。
- Worker-specific backlog 使用不同 detail 展示，不强行同列 JSON。
- 不提供任何 mutation 按钮。
- 可展示运维命令文本，但 Operations Center TODO 尚未确认具体命令 UX。

## 13. History and retention

- Redis 只保存当前状态。
- 计数从进程启动开始。
- Worker 重启后计数重置。
- 不提供 uptime 百分比、趋势图或历史事件。
- 日志是历史排查来源。

## 14. Compose changes

- 五个 Worker 使用明确 command 和 log role。
- 不挂载 Docker socket。
- 不通过 Web app 重启容器。
- Worker singleton 冲突应在日志中明确显示。

## 15. Acceptance criteria

1. 五类 Worker 正常显示 Starting→Idle/Running。
2. 第二个同类型实例拒绝启动。
3. heartbeat 10 秒、30 秒过期行为正确。
4. 长 Running 任务保持 heartbeat，不被判 Stalled/Down。
5. 进程被强杀后约 30 秒显示 Down/heartbeat expired。
6. 优雅退出显示 Down/graceful。
7. 第一次 iteration/partial failure 立即 Degraded，后续成功恢复。
8. idle success 与 actual processed 时间分离。
9. Redis 不可用 API 503。
10. 错误 API 不泄露原始异常或 Secret。
11. 每类 backlog 数据符合专属 schema。
12. User/Viewer 403，Admin 页面每 10 秒刷新。

## 16. Known tradeoffs

- Redis 故障时无法独立判断 Worker 健康。
- 当前状态和计数不会跨进程重启保留。
- daemon thread 增加少量线程复杂度，但解决了长任务 liveness。
- Running 永不按时长 Stalled，业务死循环只要 heartbeat thread 活着就仍显示 Running。
