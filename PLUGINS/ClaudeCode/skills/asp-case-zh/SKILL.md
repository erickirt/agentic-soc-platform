---
name: asp-case-zh
description: '管理 ASP 安全 case。适用于审查 case、列出 case、查看 case 讨论、检查 case 相关告警或 playbook run，或更新 case 工作流和 AI 分析字段。'
argument-hint: 'review case <case_id> | list cases [filters] | update case <case_id> <fields> | run playbook for case <case_id> <playbook_name>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.3.0
  mcp-server: asp
  category: cyber security
  tags: [ case-management, soc, triage, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Case

当用户要以 case 为中心开展 SOC 工作时，使用这个 skill。

## 适用场景

- 用户给出一个 case ID，希望查看、分诊或快速总结。
- 用户希望按状态、严重级别、置信度、verdict、correlation UID、标题或标签查找 case。
- 用户想查看 case 的讨论上下文。
- 用户想从 case 视角检查相关告警或 playbook run。
- 用户想更新 case 工作流字段或 AI 分析字段。
- 用户想把 enrichment 或结构化分析附加到 case。
- 用户想把外部 ticket 记录附加到 case。
- 用户想对 case 执行 playbook。

## 运行规则

- 如果请求已经隐含操作，不要先问用户想执行什么。
- 只补充收集缺失的必要输入。
- 当用户请求足够具体时优先使用一次 MCP 调用；但如果用户要真正的 case 审查，可以使用简短的多步流程。
- 除非为了澄清枚举值或缺失输入，不要把 MCP 字段定义原样回显给用户。
- 总结 case 数据时要服务于行动判断，而不是输出原始 schema。
- 如果更新请求有歧义，先问一个聚焦问题再写入。
- 更新后只确认实际变更的字段。
- 查询单个 case 时，使用 `list_cases(case_id=...)`，因为当前 MCP surface 没有单独的 `get_case` 工具。
- 保持 case 作为用户的主要视图。只有在能帮助回答 case 问题时，才拉取相关告警、讨论或 playbook run。
- 如果用户想把结构化分析保存回 case，使用 `asp-enrichment-zh` skill。

## 决策流程

1. 如果用户提供了具体 case ID，或说要“open”“show”“review”“summarize”某个 case，调用 `list_cases(case_id=<id>, limit=1)`。
2. 如果用户想看讨论历史或分析上下文，在取回 case 后调用 `get_case_discussions`。
3. 如果用户想看相关告警，上下文可以通过 case 的 `correlation_uid` 进行 pivot，并在有助于回答 case 问题时调用 `list_alerts`。
4. 如果用户想看 case 自动化状态，调用 `list_playbook_runs(source_id=case_id, type=[CASE])`。
5. 如果用户想在 case 上运行自动化，但没有提供 playbook 名称，仅在名称缺失时调用 `list_available_playbook_definitions`，然后调用 `execute_playbook(type=CASE, record_id=case_id, name=...)`。
6. 如果用户要把 enrichment 或结构化分析附加到 case，使用 `asp-enrichment-zh` skill。
7. 如果用户要把外部 ticket 附加到 case，先调用 `create_ticket`，再调用 `attach_ticket_to_case(case_id=<case_id>, ticket_rowid=<created_rowid>)`。
8. 如果用户要查找、浏览或对比 case，使用 `list_cases`。
9. 如果用户要修改 status、verdict、severity 或 AI 字段，使用 `update_case`。
10. 如果用户要更新 case 但没提供 case ID，询问 case ID。
11. 如果用户给出了多个过滤条件，只应用 ASP 直接支持的部分，并明确说明不支持的过滤条件。

## SOP

### 审查单个 Case

1. 调用 `list_cases(case_id=<id>, limit=1)`。
2. 如果结果为空，直接说明找不到该 case。
3. 解析第一条 JSON 记录。
4. 如果用户想看分析上下文，调用 `get_case_discussions(case_id)`。
5. 如果 case 中有有用的 `correlation_uid`，且用户需要相关告警上下文，则用它做 pivot 调用 `list_alerts(correlation_uid=...)`。
6. 如果用户想确认自动化是否运行或仍在等待，调用 `list_playbook_runs(source_id=case_id, type=[CASE])`。
7. 只展示与用户请求最相关的部分。
8. 只有在确实影响用户目标时，才强调缺失字段或可疑字段。

首选回复结构：

- `Case`：case ID、标题、严重级别、状态、verdict、confidence、priority、category。
- `Timeline`：创建、acknowledged、closed，以及存在时的 start/end。
- `Key Alerts`：只列最相关的告警，不默认列全。
- `Discussions`：仅在相关时给出关键分析或系统讨论点。
- `Playbook Runs`：仅在相关时给出当前或最近运行记录。
- `Analyst / AI Notes`：在相关时给出 comment、summary 和 AI 字段。

当用户问“发生了什么”或“帮我理解这个 case”时，先给一段简短分析性总结，再给结构化细节。

### 列出 Case

1. 提取支持的过滤字段：`case_id`、`status`、`severity`、`confidence`、`verdict`、`correlation_uid`、`title`、`tags`、`limit`。
2. 如果用户给出逗号分隔或自然语言列表，在调用 MCP 前先规范化。
3. 调用 `list_cases`。
4. 解析返回的 JSON 字符串。
5. 以紧凑对比视图呈现。
6. 如果结果很多，建议下一步最有价值的过滤条件，而不是直接倾倒大量结果。

首选回复结构：

| Case ID | Title | Severity | Status | Verdict | Confidence | Priority | Updated |
|---------|-------|----------|--------|---------|------------|----------|---------|

然后在需要时补一句简短解释，例如：

- “Most matching cases are still in progress.”
- “High-severity cases are concentrated in one category.”
- “No matching cases were found.”

### 在 Case 上运行 Playbook

1. 要求提供 `case_id`。
2. 如果用户没有指定 playbook definition 名称，调用 `list_available_playbook_definitions`，并给出最相关选项，而不是猜测。
3. 调用 `execute_playbook(type=CASE, record_id=case_id, name=<definition_name>, user_input=<optional>)`。
4. 确认已创建一条待执行的 playbook run 记录。
5. 如果用户还想继续追踪状态，调用 `list_playbook_runs(source_id=case_id, type=[CASE])`。

首选回复结构：

- `Case`：case ID
- `Playbook`：definition 名称
- `Run status`：创建时通常为 pending
- `User input`：仅在提供时展示
- `Next useful step`：可选，通常是查询 case 相关 run

### 把 Ticket 附加到 Case

1. 要求提供 `case_id`。
2. 收集用户要同步的外部 ticket 详情。
3. 调用 `create_ticket` 并保留返回的 ticket row ID。
4. 调用 `attach_ticket_to_case(case_id=<case_id>, ticket_rowid=<created_rowid>)`。
5. 确认 ticket 已创建并附加到 case。

首选回复结构：

- `Case`：case ID
- `Ticket`：创建出的 ticket row ID，必要时也可给出外部 ticket 标识
- `Attachment`：已附加到 case
- `Next useful step`：可选，通常是重新查看 case 或稍后更新同步 ticket

### 更新 Case

1. 要求提供 `case_id`。
2. 只提取用户明确要求修改的字段。
3. 在调用 MCP 前校验请求里的枚举值。
4. 仅携带变更字段调用 `update_case`。
5. 如果结果为 `None`，说明找不到该 case。
6. 用简短变更记录风格确认更新结果。
7. 如果用户可能还要核实结果，建议重新获取 case。

常见可更新字段：

- `severity`
- `status`
- `verdict`
- `severity_ai`
- `confidence_ai`
- `attack_stage_ai`
- `comment_ai`
- `summary_ai`

首选回复结构：

- `Updated case`：case ID 或返回的 row ID
- `Changed fields`：只列实际提交的字段
- `Next useful step`：可选，通常是 `list_cases(case_id=..., limit=1)` 以查看刷新后的记录

## 澄清规则

- 只有在缺失时才询问 `case_id`。
- 只有当请求值无法清晰映射到 ASP 枚举时，才要求用户澄清。
- 如果用户要求“close”“resolve”或“mark suspicious”，在意图明确时可以直接映射到对应 status 或 verdict。
- 如果用户要对 case 执行自动化但没给 playbook 名称，展示可用 definitions，而不是猜一个。
- 如果用户给出的是广义审查请求，比如“show recent important cases”，先从 `list_cases` 开始，不要强迫用户先选操作。

## 输出规则

- 保持简洁。
- 除非用户明确要求，否则不要输出原始 JSON。
- 优先使用面向分析师的措辞，而不是 schema 措辞。
- 表格保持精简；当匹配很多时，展示最有价值的子集并说明总量。
- 如果一次审查用了多个 MCP 调用，要把结果合并成一个连贯的 case 叙事，而不是逐个调用回显。
- 明确指出阻塞项：case 不存在、不支持的过滤条件、无效枚举值。

## 失败处理

- 如果 case 不存在，直接说明。
- 如果过滤无结果，直接说明并建议最可能有用的收敛方式。
- 如果 playbook definition 名称和现有 definitions 不匹配，直接说明并给出最接近的可选项。
- 如果更新目标不明确，只问一个聚焦问题，不要猜测。
