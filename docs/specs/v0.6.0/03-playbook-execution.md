# Playbook Execution

Status: Confirmed

## 1. Purpose

保留低心智成本的 Python `run()` 编程模型，同时增加可持久化的结构化执行阶段、明确时间、取消、完整重试、崩溃恢复和只读运行历史。

该设计不是工作流引擎。Stage 是观测事件，不是独立调度、恢复或重试的 Step。

## 2. Authoring model

Playbook 继续由 Python 代码定义：

```python
class Playbook(BasePlaybook):
    NAME = "Contain Endpoint"
    DESC = "Contain the endpoint associated with the case."
    TAGS = ["EDR", "Response"]
    RISK_LEVEL = "High"

    def run(self):
        with self.stage("collect", "Collect endpoint context") as stage:
            endpoints = collect_endpoints(self.case)
            stage.summary = f"Collected {len(endpoints)} endpoint(s)."

        for endpoint in endpoints:
            with self.stage("contain", f"Contain {endpoint.hostname}") as stage:
                contain(endpoint)
                stage.summary = "Containment request accepted."

        return f"Contained {len(endpoints)} endpoint(s)."
```

规则：

- `run()` 仍是唯一执行入口。
- Stage 完全可选；现有 v0.5.2 Playbook 无需修改即可运行。
- Stage 不保存 Python 返回值或跨阶段输入。
- Stage 不独立调度、不暂停、不恢复、不单步重试。
- `run()` 未捕获异常导致整个 Run Failed。
- 开发者可以在 Stage 内捕获可容忍错误，并显式写安全 summary。
- Playbook 可直接使用 `httpx` 或厂商 SDK；平台不提供通用 Connector。

## 3. Explicit exclusions

- 可视化/表单式编排器。
- DAG、分支、并行 Step。
- 中途人工审批；点击 Run 即授权整个 Playbook。
- Running hard cancel 或 cooperative cancel。
- 单步 retry/resume。
- 源码、hash 或定义版本锁定。
- 结构化 input schema。
- HTTP/Webhook Connection profile。
- 自动轮询或 WebSocket 进度。

## 4. Definition metadata

定义扫描继续读取：

- `NAME`
- `DESC`
- `TAGS`
- 新增 `RISK_LEVEL`

风险枚举：

- Low
- Medium
- High
- Critical

默认 Low。风险只用于 UI 展示，不改变权限、确认或执行流程。

Run 不保存 DESC/TAGS/RISK_LEVEL 快照。历史页面按 name 解析当前定义：

- 定义仍存在：展示当前 metadata。
- 定义已删除或改名：只展示 Run 保存的 name，并标记 definition unavailable。

Pending/Retry 执行时始终加载当前最新 Python 代码。

## 5. Run model

现有 `Playbook` 记录继续作为 Run，可考虑重命名 Python 类但不要求修改 db_table。

新增/调整字段：

| Field | Type | Semantics |
| --- | --- | --- |
| job_status | enum | Pending/Running/Success/Failed/Cancelled |
| job_id | string/UUID | 当前执行标识 |
| retry_of | nullable self FK | Failed Run 的重试来源 |
| started_at | nullable datetime | claim 成功时间 |
| finished_at | nullable datetime | terminal 时间 |
| cancelled_by | nullable FK User | Pending cancel actor |
| remark | text | 终态安全摘要 |

保留：

- case
- name
- user
- user_input
- created_at/updated_at

### Status transitions

| Current | Allowed next |
| --- | --- |
| Pending | Running, Cancelled |
| Running | Success, Failed |
| Success | none |
| Failed | none; Retry creates new Run |
| Cancelled | none |

不允许直接修改 job_status。所有状态变化通过 domain service。

### Timing

- Pending 创建时 started_at/finished_at 为空。
- Pending→Running 设置 started_at。
- Running→Success/Failed 设置 finished_at。
- Pending→Cancelled 设置 finished_at，不设置 started_at。
- duration_seconds 由 started_at 和 finished_at 计算；Running 使用 now-started_at。

## 6. Stage model

建议模型 `PlaybookStage`：

| Field | Type | Notes |
| --- | --- | --- |
| id | UUID | primary key |
| playbook_run | FK | CASCADE at DB level, though Run API cannot delete |
| sequence | positive bigint | per Run append order |
| key | string | developer supplied, may repeat |
| label | string | human-readable |
| status | enum | Running/Success/Failed |
| summary | text | explicit safe summary |
| error_type | string | sanitized exception class |
| error_message | text | sanitized length-limited message |
| started_at | datetime | context enter |
| finished_at | nullable datetime | context exit |
| duration_ms | nullable bigint | derived/persisted |

Constraints/indexes:

- unique `(playbook_run, sequence)`.
- index `(playbook_run, sequence)`.
- index `(playbook_run, status)`.
- key/label 长度必须有限，但 Stage 数量不限。

### Stage context behavior

进入 `with self.stage(key, label)`：

1. 原子分配下一个 sequence。
2. 创建 Running Stage。
3. 返回可设置 `summary` 的 context object。

正常退出：

1. 保存显式 summary。
2. 设置 Success、finished_at、duration。

异常退出：

1. 设置 Failed。
2. 保存异常类型。
3. 保存经过敏感字段过滤和长度限制的安全错误。
4. 完整 traceback 只进入 Worker log。
5. 原异常继续抛出，使 Run Failed。

Stage key/label 可以重复，支持循环动态生成。Stage 是扁平 sequence，不支持 parent。

### Output safety

- 不自动 `str()` 或 JSON serialize 任意函数输出。
- 不自动保存 HTTP response、LLM output、SIEM records 或变量值。
- summary 由自定义代码显式提供。
- error_message 使用统一 sanitizer，至少屏蔽 password/token/api_key/secret/authorization 等值。
- API 不返回 traceback。

## 7. Queue and Worker behavior

### Supported topology

- 正式支持一个 Playbook Worker。
- 全局 FIFO，按 created_at/id claim。
- 不按 Case Severity 或用户优先级排序。

### Per-Case concurrency

同一 Case 最多一个 Running Run：

- claim 时跳过已经存在 Running Run 的 Case。
- 同 Case 的其他 Pending 保持队列。
- 不同 Case 在未来多 Worker 实现中可并行，但 v0.6.0 不支持多 Worker。

### Duplicate launch

Run endpoint 不提供 idempotency。重复请求可以创建多条 Pending Run，这是已接受行为。

### Worker loss

Playbook Worker 使用 Worker Health 心跳。检测到前一实例丢失后：

- 遗留 Running Run 标记 Failed。
- 遗留 Running Stage 标记 Failed。
- remark 使用固定安全文本，说明 Worker stopped before completion。
- 不自动重置 Pending 或重跑。
- 用户检查后手动 Retry。

实现可在 Worker 成功获取 singleton lease 后执行 orphan recovery。不得仅按运行时长把合法长任务判失败。

## 8. Cancellation

只有 Pending 可取消。

`POST /api/playbooks/{id}/cancel/`

- Admin/User 可取消任意 Pending Run。
- Viewer 403。
- 非 Pending 返回 409。
- 设置 Cancelled、finished_at、cancelled_by 和安全 remark。
- 写 AuditLog。
- 不发送 completion notification。

Running 无取消入口。Playbook 中每个外部调用必须自行设置超时。

## 9. Retry

`POST /api/playbooks/{id}/retry/`

- 仅 Failed Run。
- Admin/User 可重试任意 Failed Run。
- Viewer 403。
- 创建新的 Pending Run。
- `retry_of` 指向原 Run。
- 复制 case、name、user_input。
- 新 Run 的 user 是执行 Retry 的当前用户。
- 使用当前 Case 数据和最新 Playbook 代码。
- 原 Run/Stage 不修改。
- 写 retry AuditLog，关联新旧 Run。
- Retry 不受幂等保护；重复点击可能创建多个 Run。

## 10. Launch

`POST /api/playbooks/run/`

- Admin/User 可运行，Viewer 403。
- 任何 Case 均可运行，包括 Closed。
- Case Relationship 不影响运行 eligibility。
- name 必须能在当前定义扫描中找到。
- user_input 是可选自由文本。
- 点击 Run 直接创建 Pending，不增加确认。
- risk level 只展示。

## 11. API shape

Playbook Run 资源改为 read-only：

- GET list。
- GET retrieve。
- GET definitions。
- POST run。
- POST cancel。
- POST retry。
- GET stages（detail action 或独立 nested endpoint）。

禁止：

- 普通 POST create。
- PUT/PATCH。
- DELETE。

Stage API：

- 只读。
- 必须按 sequence 分页。
- 支持 status 筛选可选，但不得一次返回无限 Stage。

### Run response additions

```json
{
  "id": "...",
  "playbook_id": "playbook_000123",
  "job_status": "Running",
  "retry_of": null,
  "started_at": "2026-07-30T08:00:00Z",
  "finished_at": null,
  "duration_seconds": 42,
  "current_stage": {
    "sequence": 8,
    "key": "contain",
    "label": "Contain endpoint-7",
    "status": "Running"
  },
  "stage_count": 8,
  "definition": {
    "available": true,
    "risk_level": "High",
    "tags": ["EDR", "Response"]
  }
}
```

## 12. Remark semantics

| Terminal state | Remark |
| --- | --- |
| Success | `str(run() return value)`，经长度限制和安全处理 |
| Failed | 固定安全摘要，可引用失败 Stage label/sequence |
| Cancelled | 固定文本并记录取消 actor |

过程日志不得拼接到 remark。原始异常只进服务器日志。

## 13. Notifications

遵循发起用户现有 `notify_on_playbook_completion` 偏好：

- Success 通知。
- Failed 通知。
- Cancelled 不通知。
- Stage 状态变化不通知。
- Retry 新 Run 按新发起用户偏好处理。

## 14. Audit

只记录用户动作：

- launch
- cancel
- retry

Worker 自动状态变化不写全局 AuditLog，因为 Run/Stage 已是状态事实。

Audit metadata 不包含 user_input 全文、Stage summary 或任何 Secret。

## 15. Frontend

### Definition selection

- 显示 name、description、tags、risk level。
- 点击 Run 直接排队。
- 保留自由文本 user_input。

### Run list/detail

- 状态、Case、发起人、时间、duration、retry relation。
- Pending 显示 Cancel。
- Failed 显示 Retry。
- Run/Stage 无 Delete/Edit。
- Stage 使用分页的扁平时间线或表格。
- 页面不自动轮询、不使用 WebSocket；提供 Refresh。
- definition 删除后显示 unavailable，而不是报页面错误。

## 16. Migration

- 现有四状态数据直接保留。
- 新 Cancelled 只用于 v0.6.0 后记录。
- 已有 Success/Failed Run 的 started_at 可为空，不伪造历史时间。
- 旧 Running Run 在升级后由首次 Worker recovery 处理。
- retry_of、timing、cancel actor 均 nullable。

## 17. Acceptance criteria

1. v0.5.2 旧 Playbook 不修改即可运行。
2. 可选 Stage 正确保存动态重复 key 和 sequence。
3. Stage 异常导致 Stage/Run Failed，API 不泄露 traceback。
4. Pending 可取消，Running 不可取消。
5. Failed Retry 创建新 Run并保留原历史。
6. Run/Stage 所有普通 mutation/delete 被拒绝。
7. 同一 Case 不同时 Running 两个 Run。
8. FIFO claim 可预测。
9. Worker 崩溃后遗留 Running 标记 Failed且不自动重跑。
10. Closed Case 可运行，Case Relationship 不影响运行。
11. Success/Failed 通知符合用户偏好。
12. Stage 数量大时 API 正确分页。

## 18. Known tradeoffs

- 最新代码执行使 Pending Run 语义可能在排队期间变化。
- 不保存 metadata 快照，历史 risk/tags 会随定义变化。
- 重复 launch/retry 可产生重复外部副作用。
- Running 不可取消。
- 动态无限 Stage 可能产生大量数据，开发者需自律；平台只通过分页保护读取。
- 直接 httpx 调用的重试、幂等和 Secret 安全由自定义代码负责。
