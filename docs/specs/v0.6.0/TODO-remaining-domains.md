# v0.6.0 remaining domain TODO

Status: Acceptance only

所有功能域已经确认或明确排除。剩余工作只有版本验收规范。

## TODO 1: v0.6.0 acceptance

Release blocking: Yes

需要根据全部 Confirmed Spec 定义：

- 从 v0.5.2 生产备份副本升级的完整演练。
- 全新 Docker Compose 安装。
- medium 数据规模下的关键 API/页面性能阈值。
- Admin/User/Viewer 权限矩阵回归。
- Case 单条和批量状态机一致性。
- 部分成功批量分诊、Case Relationship 约束、Artifact 候选和 Agent 读取。
- Playbook Pending/Running/终态、Cancel、Retry、Stage 和 Worker 崩溃恢复。
- Custom Variables 的 Secret masking、Reveal audit 和 Module/Playbook 读取。
- Worker Redis 故障、重复实例、优雅退出和心跳过期。
- SLA 的 TTD/TTA/TTR、通知、Reopen 和 Dashboard 达标率。
- AI Quality 的回填、Coverage、Agreement 和权限。
- 已明确排除的 Integration Health、Suppression Rules、Operations Center 不得误入发布范围。
- 备份、恢复和回滚演练。
- 文档、release notes、已知限制和功能冻结条件。
- P0/P1 缺陷门槛和 RC 观察周期。

输出目标：`11-release-acceptance.md`。

## Suggested continuation prompt

> 阅读 `docs/specs/v0.6.0/README.md` 和全部 Confirmed/Excluded 决策。不要重新讨论功能范围。根据这些 Spec 一次只确认一个发布验收决策，完成后输出 `11-release-acceptance.md`。
