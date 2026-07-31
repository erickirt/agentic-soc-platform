# v0.6.0 remaining domain TODO

Status: Not discussed

本文件用于在另一台电脑或新会话中继续产品讨论。以下内容仅是讨论清单，不是已确认需求。

## TODO 1: AI quality evaluation

Release blocking: Yes

Goal: 用人工最终判断评估 AI 严重度、置信度、影响、优先级和 Verdict 的质量，形成可解释的反馈闭环。

需要逐项决定：

- 评估对象是所有 AI 字段，还是先只做 Verdict/Severity。
- 何时生成评价记录：字段修改、Case Close 或定时快照。
- AI 输出与人工输出为空时如何处理。
- 一次 Case 多次 AI 分析如何选择被评估版本。
- 是否必须保存 model、provider、prompt slug/version 和 analysis job。
- 指标使用 agreement rate、confusion matrix、precision/recall 还是更简单统计。
- Verdict 多分类如何归并，Unknown/Insufficient Data 是否排除。
- 分析师是否提供显式 thumbs up/down 和错误原因。
- 是否允许抽样复核和争议标记。
- 时间窗口、Provider、Model、Playbook/Trigger、Case category 等筛选维度。
- 数据保留、历史不可变性和模型配置删除后的展示。
- Dashboard/独立页面的信息架构。
- 权限和匿名化要求。
- 是否将反馈用于自动 prompt 优化；建议 v0.6.0 排除自动学习。
- 审计、迁移和验收案例。

输出目标：`08-ai-quality-evaluation.md`。

## TODO 2: suppression rules

Release blocking: Yes

Goal: 在告警进入 Case 流程前降低已知噪声，同时保留可审计的命中记录，避免简单删除安全数据。

需要逐项决定：

- Rule 匹配对象是原始 Webhook、标准化 Alert 字段还是 Module 输出。
- 可匹配字段白名单以及 text/exact/list/CIDR/regex 运算符。
- 多条件 AND/OR 能力和是否允许嵌套。
- Rule 作用域：全局、Module、rule_id、产品或数据源。
- 动作是 drop、mark suppressed、route to existing Case 还是不创建 Case。
- 被抑制事件是否持久化；存储多少原始数据。
- Rule 优先级、first-match 或 all-match。
- Enabled、有效期、自动过期和命中计数。
- 模拟/预览如何在历史样本上运行，是否必须先模拟再启用。
- 如何防止一条宽泛 Rule 隐藏大量真实告警。
- Admin/User/Viewer 权限；建议至少创建/修改仅 Admin。
- 命中 AuditLog、Rule 变更审计和 Secret/PII 脱敏。
- Module correlation 与 merged source routing 的执行顺序。
- 列表、详情、命中历史和筛选 UX。
- 数据库索引、性能目标和验收案例。

输出目标：`09-suppression-rules.md`。

## TODO 3: Operations Center

Release blocking: Depends on final scope

已确认的固定边界：

- 位于 `System Settings → Operations`。
- 包含 Worker Health 和 Integration Health 两个独立区块。
- 仅 Admin 可访问。
- Worker 每 10 秒刷新，Integration 每 30 秒刷新。
- 不提供 Worker Restart、Run Now、日志读取或健康通知。
- Integration 不提供统一 Check Now；保留各 Settings 页的 Test。
- 不计算整体 Integration Health。

仍需决定：

- 页面布局、过滤、排序、状态颜色和移动端是否考虑。
- Worker backlog 的不同数据结构如何展示。
- 如何从 Integration 行跳转到对应 Settings。
- Redis 监控不可用时页面局部还是整体错误。
- Operations 导航徽标是否显示异常数量。
- 是否显示 Compose 修复命令，以及具体安全文本。
- 空状态、加载状态和权限拒绝 UX。
- API 聚合还是前端调用两个独立 API。
- 前端组件复用和验收案例。

输出目标：`10-operations-center.md`。

## TODO 4: v0.6.0 acceptance

Release blocking: Yes

需要在所有功能 Spec 完成后定义：

- 从 v0.5.2 生产备份副本升级的完整演练。
- 全新 Docker Compose 安装。
- medium 数据规模下的关键 API/页面性能阈值。
- Admin/User/Viewer 权限矩阵回归。
- Case 单条和批量状态机一致性。
- 部分成功批量分诊、原子合并、幂等重试和 merged source 路由。
- Playbook Pending/Running/终态、Cancel、Retry、Stage 和 Worker 崩溃恢复。
- Custom Variables 的 Secret masking、Reveal audit 和 Module/Playbook 读取。
- Worker Redis 故障、重复实例、优雅退出和心跳过期。
- 所有正式集成的 Healthy/Unhealthy/Disabled 行为。
- SLA、AI 质量评估和抑制规则端到端场景。
- 备份、恢复和回滚演练。
- 文档、release notes、已知限制和功能冻结条件。
- P0/P1 缺陷门槛和 RC 观察周期。

输出目标：`11-release-acceptance.md`。

## Suggested continuation prompt

在新电脑上可从下面的提示继续：

> 阅读 `docs/specs/v0.6.0/README.md` 和 `TODO-remaining-domains.md`。已确认 Spec 不要重新讨论。从 AI quality evaluation 开始，一次只问一个决策问题，每个问题给出推荐答案；确认完成后依次处理 suppression rules、Operations Center 和 release acceptance。
