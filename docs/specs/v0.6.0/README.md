# ASP v0.6.0 specification index

本目录是 v0.6.0 的跨会话实施依据。已完成讨论的功能使用实施级 Spec 固化；尚未完成讨论的功能只记录 TODO 和待决策问题，不得把 TODO 中的推荐项当作已经确认的需求。

## Spec 状态

| 文档 | 状态 | 内容 |
| --- | --- | --- |
| [00-release-scope.md](00-release-scope.md) | Confirmed | 版本目标、部署边界、兼容矩阵、容量、权限与排除项 |
| [01-bulk-case-triage.md](01-bulk-case-triage.md) | Deferred | Case 批量分诊、共享状态机、通知与审计 |
| [07-sla-management.md](07-sla-management.md) | Deferred | TTD/TTA/TTR 时限、Severity 策略、通知和 Dashboard 达标率 |
| [08-ai-quality-evaluation.md](08-ai-quality-evaluation.md) | Deferred | AI–Human Agreement、Coverage、混淆矩阵和样本下钻 |

`Deferred` 表示设计已确认但延期到后续版本，不作为 v0.6.0 发布阻断项。已实现的功能域（Case Relationships、Custom Variables、Playbook 执行、Worker Health）按仓库惯例在验收后移除对应 Spec 文件。

## 待讨论

无。所有 v0.6.0 功能域均已实现或明确延期。

## 实施顺序

1. Case Relationships 已完成；Case 批量分诊延期。
2. Playbook Run/Stage 已完成。
3. 通用 Worker Health 基础设施已完成并接入五类 Worker。
4. SLA 和 AI Quality 延期到后续版本。
5. 最后统一补齐 v0.6.0 验收规范。

## Spec 使用规则

- `Confirmed` 表示产品决策已确认，实施不得自行改变行为。
- Spec 中的模型名和 URL 是目标设计；若代码库已有命名约束冲突，可以做等价调整，但外部行为必须一致。
- 每项功能必须同时覆盖后端、前端、权限、审计、迁移和失败行为。
- v0.6.0 允许破坏性 API 调整，不需要兼容旧 CLI 或插件。
- 不得把本目录复制到 `asp-doc` 作为用户文档；用户文档应在功能实现定型后另行编写。
