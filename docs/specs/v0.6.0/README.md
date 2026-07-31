# ASP v0.6.0 specification index

本目录是 v0.6.0 的跨会话实施依据。已完成讨论的功能使用实施级 Spec 固化；尚未完成讨论的功能只记录 TODO 和待决策问题，不得把 TODO 中的推荐项当作已经确认的需求。

## 已确认 Spec

| 文档 | 状态 | 内容 |
| --- | --- | --- |
| [00-release-scope.md](00-release-scope.md) | Confirmed | 版本目标、部署边界、兼容矩阵、容量、权限与排除项 |
| [01-bulk-case-triage.md](01-bulk-case-triage.md) | Confirmed | Case 批量分诊、共享状态机、通知与审计 |
| [02-case-merge.md](02-case-merge.md) | Confirmed | 多源案件合并、数据迁移、只读源案件与幂等 |
| [03-playbook-execution.md](03-playbook-execution.md) | Confirmed | Playbook Run、结构化 Stage、取消、重试与 Worker 语义 |
| [04-custom-variables.md](04-custom-variables.md) | Confirmed | Playbook/Module 可读取的 UI 管理变量 |
| [05-worker-health.md](05-worker-health.md) | Confirmed | Redis 心跳、Worker 状态、积压指标与 Admin API |
| [06-integration-health.md](06-integration-health.md) | Confirmed | 定时集成检查、当前状态持久化与安全错误 |
| [07-sla-management.md](07-sla-management.md) | Confirmed | TTD/TTA/TTR 时限、Severity 策略、通知和 Dashboard 达标率 |

## 待讨论

[TODO-remaining-domains.md](TODO-remaining-domains.md) 记录 AI 质量评估、抑制规则、Operations 页面整合和版本验收。继续讨论时应逐项把决定写回独立 Spec。

## 实施顺序

1. 先完成 Case 状态机，再实现批量分诊和案件合并。
2. 完成 Playbook Run/Stage 后实现 Custom Variables。
3. 完成通用 Worker Health 基础设施，再接入六类 Worker。
4. 完成 Integration Health 数据层和 Worker，再实现 Operations 页面。
5. 待剩余三个业务域定稿后，统一补齐 v0.6.0 验收规范。

## Spec 使用规则

- `Confirmed` 表示产品决策已确认，实施不得自行改变行为。
- Spec 中的模型名和 URL 是目标设计；若代码库已有命名约束冲突，可以做等价调整，但外部行为必须一致。
- 每项功能必须同时覆盖后端、前端、权限、审计、迁移和失败行为。
- v0.6.0 允许破坏性 API 调整，不需要兼容旧 CLI 或插件。
- 不得把本目录复制到 `asp-doc` 作为用户文档；用户文档应在功能实现定型后另行编写。
