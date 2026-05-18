---
name: asp-alert-en
description: 'Review ASP alerts for triage analysis.'
argument-hint: 'review alert <alert_id> | list alerts [filters]'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ alert-management, soc, triage, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Alert

Use this skill when the user needs to work on ASP alerts for SOC analysis.
An alert is secondary data in ASP. Each alert belongs to a case, and each alert can have one or more artifacts attached.

## When to Use

- The user gives an alert ID and wants a quick review, inspection, or summary.
- The user wants to find alerts by status, severity, confidence, or correlation UID.
- The user wants to attach enrichment to an alert after analysis.

## Operating Rules

- Keep the response focused on triage value rather than repeating schema fields.
- If the user is working on a specific alert, prefer `list_alerts(alert_id=<id>, limit=1)` because the current MCP surface does not expose a separate `get_alert` tool.
- Alerts are currently read-only. If the user wants to save structured analysis back onto the alert, use the `asp-enrichment-en` skill.

## Additional Information

- `row_id` is the UUID for each alert record and is used for data association.
- `alert_id` is the human-readable unique ID for each alert record.

## Decision Flow

1. If the user provides a specific alert ID or says "open", "show", "review", or "summarize" an alert, call `list_alerts(alert_id=<id>, limit=1)`.
2. If the user wants to browse or compare alerts, use `list_alerts` with supported filters.
3. If the user wants to attach analysis results, intelligence, or structured context to the alert, use the `asp-enrichment-en` skill.

## SOP

### Review One Alert

1. If the user wants to review, analyze, or inspect alert details, call `list_alerts(alert_id=<id>, limit=1, lazy_load=false)` to fetch the full related data.
2. If the user only needs the basic alert information, call `list_alerts(alert_id=<id>, limit=1)`.
3. If the result is empty, state that the alert was not found.
4. Parse the first JSON record.
5. Present only the most useful triage fields.

Preferred response structure:

- `Alert`: alert ID, title or name, severity, status, confidence, correlation UID.
- `Timeline`: created or updated time when present.
- `Key Context`: source, rule, category, owner, or other high-signal fields.
- `Assessment`: short triage judgment.

### List Alerts

1. Extract supported filters: `alert_id`, `status`, `severity`, `confidence`, `correlation_uid`, `limit`.
2. Normalize natural-language filters before calling MCP.
3. Call `list_alerts`.
4. Parse the returned JSON strings.
5. Present a compact comparison view.

Preferred response structure:

| Alert ID | Title | Severity | Status | Confidence | First Seen | Rule Name |
|----------|-------|----------|--------|------------|------------|-----------|

Then add one short explanation line when needed.

## Clarification Rules

- Ask for `alert_id` only when it is missing for alert-related actions.
- Ask for enum clarification only when the requested value does not map cleanly to ASP values.

## Output Rules

- Be concise.
- Do not output raw JSON unless the user explicitly asks for it.
- Prefer triage wording over schema wording.
- State blockers clearly: alert not found, unsupported filter, invalid enum value.

## Failure Handling

- If the alert does not exist, say so directly.
- If filters return no results, say so directly and suggest the most useful refinement.
