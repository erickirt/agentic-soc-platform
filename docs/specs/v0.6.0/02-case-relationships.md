# Case Relationships

Status: Confirmed

## 1. Purpose

允许分析师在不迁移数据、不改变 Case 生命周期的前提下，显式记录 Case 之间的调查联系。工程师和 Agent 可以从任一 Case 查看直接关联；系统还可以根据共享 Artifact 提供简单候选，由人工确认后转为正式关系。

Case Relationship 是弱关联，不是 Merge、分组、同步或级联工作流。

## 2. Scope

### Included

- 三种固定关系：Related、Duplicate of、Parent of。
- Admin/User 人工创建、修改和删除关系。
- Viewer 和 Agent 只读。
- 双向查看和反向语义展示。
- Related Cases 详情 Tab。
- Case 列表默认隐藏的关系数量列。
- 基于共享 Artifact 的查询时候选。
- Agent 正式关系和候选查询 API。
- AuditLog。

### Excluded

- Case Merge 或 Unmerge。
- Alert、Comment、Enrichment、Knowledge、Playbook、AI Job 等业务数据迁移。
- 自动关闭、自动修改 Verdict、状态或 Assignee。
- 字段、Tags、Summary 或 AI report 同步。
- 级联关闭或父子任务编排。
- 自定义关系类型。
- 后台候选 Worker、候选持久化、评分模型或 LLM 相似度。
- 关系变更 Inbox 通知。

## 3. Permission matrix

| Action | Admin | User | Viewer | Agent |
| --- | --- | --- | --- | --- |
| View formal relationships | Yes | Yes | Yes | Yes |
| View Artifact suggestions | Yes | Yes | Yes | Yes, explicit query |
| Create/update/delete | Yes | Yes | No | No |
| Confirm suggestion as Related | Yes | Yes | No | No |

Closed Case 使用相同权限。维护关系不要求 Reopen。

## 4. Relationship semantics

### Related

- 无方向。
- API/UI 在两端均显示 Related。
- 存储时按 Case UUID 稳定排序 source/target，避免同一关系出现两个方向。

### Duplicate of

`source_case Duplicate of target_case`：

- source 是重复 Case。
- target 是唯一主 Case。
- 反向显示为 Has duplicate。
- 每个 source 最多一个 Duplicate of target。
- target 不能同时 Duplicate of 其他 Case。
- 已作为其他 Duplicate 主 Case 的 Case 不能再成为 Duplicate。
- 不允许链或环。
- 不自动修改 source Verdict、Status、closed_time 或其他字段。

### Parent of

`source_case Parent of target_case`：

- source 是父 Case。
- target 是子 Case。
- 反向显示为 Child of。
- 每个子 Case 最多一个直接父 Case。
- 一个父 Case 可以有多个子 Case。
- 不允许形成环。
- 不产生字段同步、级联关闭或其他父子副作用。

### Pair cardinality

- 同一个无序 Case 对最多一条正式关系。
- 可以通过 PATCH 修改关系类型、方向和 note。
- 不能创建 Case 到自身的关系。

## 5. Data model

`CaseRelationship`：

| Field | Notes |
| --- | --- |
| id | UUID primary key |
| source_case | FK Case, CASCADE |
| target_case | FK Case, CASCADE |
| relationship_type | Related / Duplicate of / Parent of |
| note | optional, max 500 characters |
| created_by | nullable FK User, SET_NULL |
| pair_key | sorted Case UUID pair, unique |
| created_at/updated_at | timestamps |

约束：

- source_case != target_case。
- pair_key unique。
- Parent of 的 target_case 条件唯一。
- Duplicate of 的 source_case 条件唯一。
- source_case + relationship_type、target_case + relationship_type 建索引。

Case 删除时级联删除关系，不阻止 Case 删除。AuditLog 保留删除事实。

## 6. Formal relationship API

一级资源：

```text
GET    /api/case-relationships/
POST   /api/case-relationships/
GET    /api/case-relationships/{id}/
PATCH  /api/case-relationships/{id}/
DELETE /api/case-relationships/{id}/
```

列表支持：

- `case=<uuid>`：返回该 Case 的入边和出边。
- `relationship_type=<value>`。
- Case readable ID/title、note 和 creator 搜索。
- created_at/updated_at/relationship_type ordering。
- 标准分页。

创建/修改输入：

```json
{
  "source_case_id": "...",
  "target_case_id": "...",
  "relationship_type": "Parent of",
  "note": "Same campaign, parent investigation"
}
```

输出包含 source_case 和 target_case 摘要：

- UUID/readable ID/title。
- status/severity/verdict。
- assignee ID/name。
- created_by 和 timestamps。

失败：

- 非写入角色返回 403。
- Case 不存在或字段非法返回 400。
- 自关联、已有同 Case 对、Parent 环/多父级、Duplicate 链/环/多主 Case 返回 400。
- 并发唯一约束冲突返回稳定 400，不泄露数据库异常。

Case list/detail 增加 `relationship_count`，入边和出边各计一次。

## 7. Artifact suggestions

Endpoint：

```text
GET /api/case-relationships/suggestions/?case=<uuid>
```

规则：

1. 用户或 Agent 显式请求时才执行，不随 Related Cases Tab 加载或关系变更自动执行。
2. 按最近关联顺序最多取当前 Case 的 20 个去重 Artifact 记录。
3. 查找共享至少一个相同 Artifact 记录的其他 Case。
4. 排除当前 Case 和已经存在正式关系的 Case。
5. 按共享 Artifact 去重数量降序。
6. 相同数量按 Case updated_at 降序。
7. 最多返回 10 个候选。
8. 每项返回共享数量和最多 3 个 Artifact 摘要（id/type/value）。
9. 数据库查询超时为 3 秒；超时返回 503，不继续占用数据库连接执行。
10. 不应用时间窗口、类型权重、文本相似度或 LLM 判断。

候选按请求动态计算，不持久化、不写 AuditLog、不需要 Worker。

候选不是真实调查关系。Admin/User 点击确认后只创建 Related；不能直接确认成 Duplicate of 或 Parent of。

## 8. Agent API

Capabilities：

- `case.relationships`
- `case.relationship_suggestions`

Endpoints：

```text
GET /api/agent/v1/cases/{case_id}/relationships/
GET /api/agent/v1/cases/{case_id}/relationship-suggestions/
```

`case.show?include_related=true` 默认包含最多 50 条直接正式 relationships。

Agent：

- 只读取当前 Case 的直接关系，不递归展开二级或完整关系图。
- 正式关系返回相对当前 Case 的 relation 语义和对端 Case 摘要。
- 独立 relationships endpoint 使用 created_at cursor 分页。
- suggestions 不默认注入 Case 上下文，需要 Agent 主动查询。
- 不提供创建、修改或删除接口。

## 9. Business isolation

Case Relationship 不参与：

- Case Status/Verdict/Assignee 更新。
- Alert correlation_uid 路由。
- Dashboard Case 统计。
- SLA target、时钟、状态或通知。
- AI Quality 样本选择。
- Playbook 或 CaseAnalysisJob eligibility。
- Assignee 工作量。

所有 Case 保持完整独立生命周期。关系变化也不更新 Case.updated_at。

## 10. Audit and notifications

- 创建、修改、删除 CaseRelationship 写 AuditLog。
- 两端 Case Audit timeline 写 linked/unlinked/deleted relation event。
- Audit actor 使用当前用户。
- 候选查询和候选展示不写 AuditLog。
- 不发送 Inbox、邮件、Webhook 或其他通知。

## 11. Frontend

### Case detail

新增 Related Cases Tab：

- 使用与其他关联 Tab 一致的全高度 DataTable 展示正式关系列表。
- 工具栏使用图标按钮添加关系和查找候选。
- 相对当前 Case 的关系语义。
- 对端 Case readable ID/title/status/severity/verdict。
- note、creator、created time。
- 点击打开对端 Case。
- Admin/User 可 Add/Edit/Delete。
- Viewer 无写入入口。

Add/Edit：

- 固定三种关系类型。
- 有方向关系明确选择方向。
- 通过 Case ID/title 搜索对端 Case。
- note 可选，最多 500 字。
- Edit 可以修改类型、方向和 note，不更换对端 Case。

Suggestions：

- 默认不查询；用户点击工具栏查找图标后打开弹窗并发起请求。
- 查询期间按钮不可重复触发。
- 候选在弹窗内使用紧凑表格展示，错误在弹窗内提示并支持 Retry。
- 展示共享 Artifact 数量。
- 展示最多 3 个 type/value，剩余显示 +N。
- Admin/User 可确认 Add as Related。
- 确认后保持弹窗打开、移除已处理候选并刷新正式关系表。
- Viewer 只读。

### Case list

- 增加 Related Cases count 列。
- 默认隐藏。
- 点击数量打开 Related Cases Tab。
- 不增加全局 relationship filter。

## 12. Upgrade boundary

- Migration 只创建 CaseRelationship 表和约束。
- 现有 Case 不回填正式关系。
- 候选可立即根据已有 Alert–Artifact 数据动态产生。
- 不修改任何旧 Case、Alert、Job、SLA 或 Evaluation 数据。

## 13. Acceptance criteria

1. Admin/User 可创建、修改、删除关系，Viewer/Agent 不可写。
2. Related 在两端均正确显示且同一 Case 对只有一条关系。
3. Duplicate of 唯一指向主 Case，不形成链或环且没有业务副作用。
4. Parent of 单父级、可多子级且不形成环。
5. Closed Case 可以维护关系。
6. note 可选且最多 500 字。
7. 删除 Case 级联删除关系，不阻止 Case 删除。
8. 关系不改变 Case 或任何关联业务对象。
9. Case list/detail relationship_count 正确，列表列默认隐藏。
10. Related Cases Tab 从任一端显示正确反向语义并可打开对端。
11. Artifact suggestions 仅手动触发，最多使用 20 个 Artifact，排除自身和正式关联并按共享数量返回 Top 10。
12. 每项 suggestion 返回数量和最多 3 个 Artifact 证据。
13. 确认 suggestion 只创建 Related。
14. Agent 默认只读取直接正式关系，suggestions 需主动查询。
15. 关系 CRUD 写 AuditLog，不发送通知。
16. 并发冲突不会产生重复 Case 对、多个父级或多个 Duplicate 主目标。

## 14. Known tradeoffs

- 共享 Artifact 必须是同一个数据库记录；同值但不同 name/role 的 Artifact 可能无法互相建议。
- 常见 Artifact 可能产生弱相关候选，因此必须人工确认。
- 候选查询是有界的低频辅助功能；超过 3 秒会终止并提示数据量过大。
- 不做递归图展示，跨多跳关系需要逐个打开 Case。
- 不支持自定义关系类型。
- Case 删除会删除当前关系边，历史只通过 AuditLog 追溯。
