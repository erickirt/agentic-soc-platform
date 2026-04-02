---
name: asp-knowledge-zh
description: '查找 case 或 alert 相关的内部知识，检查是否已有知识记录，或更新 ASP knowledge 记录。'
argument-hint: 'search knowledge [filters] | update knowledge <knowledge_id> <fields>'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ knowledge, memory, rag, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Knowledge

当用户要在 ASP 中检索或维护内部知识时，使用这个 skill。

## 适用场景

- 用户想按标题、正文、标签、action、source 或使用状态查找已有内部知识。
- 用户想确认某条知识是否还应继续启用或应被移除。
- 用户想更新知识记录的内容、标签或生命周期状态。
- 用户想在决定下一步 case、alert 或 hunting 动作前，先查看可复用的分析师知识。

## 运行规则

- 把它视为知识检索与维护工具，而不是通用聊天记忆。
- 优先使用最窄且最有用的过滤条件。
- 如果用户给的是短语、症状或部分表述，优先使用模糊 title/body 匹配。
- 如果用户按场景、技术或主题操作，优先使用 tags。
- 更新时，只修改用户明确要求变更的字段。
- 如果用户需要的是语义搜索而不是字段过滤，要明确说明当前 MCP surface 仍然是过滤导向。

## 决策流程

1. 如果用户要查找或浏览知识，使用最窄有用过滤条件调用 `list_knowledge`。
2. 如果用户要修改已知记录的内容、状态、source、action 或 tags，调用 `update_knowledge`。
3. 如果用户只是想知道某类知识是否已经存在，但只给了部分措辞，则先从模糊 `title` 和 `body` 过滤开始。
4. 如果用户要管理生命周期或启用状态，优先使用 `action` 和 `using`，而不是发明新的工作流。

## SOP

### 搜索 Knowledge

1. 提取支持的过滤条件：`action`、`source`、`using`、`title`、`body`、`tags`、`limit`。
2. 当用户给出部分文本时，使用模糊 title/body 过滤。
3. 当用户本质上是在按主题或场景查找时，使用 tags。
4. 调用 `list_knowledge`。
5. 解析返回的 JSON 字符串。
6. 输出一个小而有用的候选列表，而不是所有字段全量展开。

首选回复结构：

| Knowledge ID | Title | Source | Action | Using | Tags |
|--------------|-------|--------|--------|-------|------|

然后在需要时补一句简短解释。

### 更新 Knowledge

1. 要求提供 `knowledge_id`。
2. 只提取用户明确要求修改的字段：`title`、`body`、`using`、`action`、`source`、`tags`。
3. 仅带变更字段调用 `update_knowledge`。
4. 如果结果为 `None`，说明找不到该知识记录。
5. 只确认实际变更的字段。

首选回复结构：

- `Updated knowledge`：knowledge ID 或返回的 row ID
- `Changed fields`：只列本次请求实际提交的字段
- `Next useful step`：可选，通常是查询类似知识，或用更窄的搜索验证更新结果

## 澄清规则

- 只有在用户要更新特定记录但未提供时，才询问 `knowledge_id`。
- 只有当请求状态不能清晰映射到 `action` 或 `using` 时，才要求澄清生命周期语义。
- 如果用户说“disable”“archive”或“stop using”某条 knowledge，优先澄清他们是想设 `using=false`、修改生命周期 `action`，还是两者都要。

## 输出规则

- 保持简洁。
- 除非用户明确要求，否则不要输出完整 knowledge body。
- 优先使用可复用的分析师语义，而不是底层存储语义。
- 当匹配记录很多时，展示最有价值的子集，并简要说明整体模式。

## 失败处理

- 如果没有匹配的 knowledge 记录，直接说明，并建议最可能有用的收敛方式。
- 如果要更新的记录不存在，直接说明。
- 如果请求的生命周期变更含义不清，只问一个聚焦问题，不要猜测。
