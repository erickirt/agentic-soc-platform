---
name: asp-enrichment-en
description: 'Save structured data as enrichment and attach it to a case, alert, or artifact.'
argument-hint: 'create enrichment <target_id> [fields]'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.2.0
  mcp-server: asp
  category: cyber security
  tags: [ enrichment, analysis, context, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Enrichment

Use this skill when analysis results need to be saved back into ASP as structured context and attached to the corresponding case, alert, or artifact.

## When to Use

- The user wants to save structured analysis, intelligence, or investigation conclusions.
- The user wants to attach context to a case, alert, or artifact.
- The user wants to persist SIEM findings, threat intel, asset context, or analyst conclusions.

## Operating Rules

- Treat enrichment as the platform's structured result layer, not as a generic comment field.
- When the goal is to persist analysis on a `case`, `alert`, or `artifact`, use this skill.
- Use `create_enrichment` to create the enrichment record and attach it to the target in one step.
- Keep the payload compact and actionable.
- Use the object-specific skill first when the user is still inspecting the object, and use this skill when saving the result.

## Decision Flow

1. If the user wants to save a new structured result on a target object, call `create_enrichment(target_id=..., ...)`.
2. If the user is still exploring the object rather than saving a result, use the corresponding object skill first.

## SOP

### Create Enrichment

1. Require `target_id` such as `case_000001`, `alert_000001`, or `artifact_000001`.
2. Convert the user's analysis into a compact structured enrichment payload.
3. Call `create_enrichment(target_id=<target_id>, name=..., type=..., ...)`.
4. Confirm the created enrichment row_id and that it is attached to the target.

Preferred response structure:

- `Target ID`: target ID
- `Enrichment`: created enrichment row_id

## Clarification Rules

- Ask for `target_id` only when it is missing.
- If the user only says "save this result", infer the most obvious target object from the current request when it is clear, and prefer Case.

## Output Rules

- Be concise.
- Do not output raw JSON unless the user explicitly asks for it.
- Prefer analyst-facing wording over storage wording.
- Clearly state what was saved, where it was attached, and why it is useful.

## Failure Handling

- If the target object does not exist, say so directly.
- If the enrichment payload is incomplete, ask one focused follow-up instead of guessing.
