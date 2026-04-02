---
name: asp-artifact-zh
description: '按 IOC 查找 artifact、创建新 artifact、把 artifact 附加到告警，或为 artifact 保存 enrichment。'
argument-hint: 'review artifact <artifact_id> | list artifacts [filters] | create artifact <value> | attach artifact to alert <alert_id> | enrich artifact <artifact_id>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ artifact, pivot, enrichment, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Artifact

当用户要围绕 artifact 进行调查分析时，使用这个 skill。

## 适用场景

- 用户想按 value、type、role、owner 或 reputation 查找 artifact。
- 用户想创建新的 artifact 记录。
- 用户想把新创建的 artifact 附加到告警。
- 用户已经有 artifact row ID，想把现有 artifact 附加到告警。
- 用户想给 artifact 附加 enrichment 或结构化分析。

## 运行规则

- 把 artifact 视为平台里的最小 pivot 对象。
- 如果用户请求已经隐含操作，不要反问用户要哪种操作。
- 只收集缺失的必要输入。
- 查询和审查时使用 `list_artifacts`。
- 用户要新增 artifact 记录时，使用 `create_artifact`。
- 只有在已经拿到 artifact row ID 后，才使用 `attach_artifact_to_alert`。
- 如果用户想把分析结果保存到 artifact 本身，使用 `create_enrichment` 加 `attach_enrichment_to_target`。
- 如需完整的 enrichment 持久化流程，使用 `asp-enrichment-zh` skill。
- artifact 回复保持简短，并以调查为导向。

## 决策流程

1. 如果用户要查找或审查 artifact，调用 `list_artifacts`。
2. 如果用户要创建新 artifact，调用 `create_artifact`。
3. 如果用户要把 artifact 加到告警，视情况先调用 `create_artifact` 或先找到现有 artifact row ID，然后调用 `attach_artifact_to_alert`。
4. 如果用户要为 artifact 附加情报、分析笔记或结构化分析，使用 `asp-enrichment-zh` skill。
5. 如果用户正从 artifact 出发进行调查，把 artifact 作为 pivot，只在必要时建议下一个最有价值的跳转点。

## SOP

### 列出 Artifact

1. 从请求中提取最窄且最有用的过滤条件。
2. 调用 `list_artifacts`。
3. 解析返回的 JSON 字符串。
4. 以紧凑的 artifact 视图呈现；如果用户大概率下一步要附加或复用该 artifact，则显式展示 artifact row ID。

首选回复结构：

| Artifact ID | Value | Type | Role | Owner | Reputation | Summary |
|-------------|-------|------|------|-------|------------|---------|

然后在需要时补一句简短解释。

### 创建 Artifact

1. 收集最少但足够有用的 artifact 信息。
2. 调用 `create_artifact`。
3. 确认创建后的 artifact row ID。
4. 如果该 artifact 应该归属于某条告警，建议下一步附加到告警。

首选回复结构：

- `Artifact`：创建出的 artifact row ID
- `Value`：在有必要时给出主要 artifact 值
- `Next useful step`：可选，通常是附加到告警或继续 enrich

### 把 Artifact 附加到告警

1. 要求提供 `alert_id`。
2. 如果用户还没有 artifact row ID，则先为新 artifact 调用 `create_artifact`，或先取回已有 artifact。
3. 调用 `attach_artifact_to_alert(alert_id=<alert_id>, artifact_rowid=<artifact_rowid>)`。
4. 确认 artifact 已附加成功。

## 澄清规则

- 只有当用户要附加到告警却没提供时，才询问 `alert_id`。
- 只有当用户要 enrich 现有 artifact 却未提供时，才询问 `artifact_id`。
- 如果用户只想新增 artifact，但没有明确表示要附加到哪里，就只创建 artifact，不要擅自假设父对象。
- 如果用户想做 pivot 但没有指定具体工具路径，先从 artifact 审查开始，再建议下一跳。

## 输出规则

- 保持简洁。
- 除非用户明确要求，否则不要输出原始 JSON。
- 优先使用 pivot 语义，而不是存储语义。
- 当匹配的 artifact 很多时，展示最有价值的一小部分，并简要说明整体模式。

## 失败处理

- 如果没有匹配的 artifact，直接说明，并建议最有用的收敛方式。
- 如果目标告警不存在，直接说明。
- 如果目标 artifact 不存在，直接说明。
- 如果 enrichment 请求信息不完整，只问一个聚焦问题，不要猜测。
