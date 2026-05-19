---
name: asp-playbook-en
description: 'Operate ASP playbook definitions and playbook run records. Use when users want to list runnable definitions, execute playbooks against a case, or inspect run history.'
argument-hint: 'list playbook definitions | run playbook <name> for <case_id> | list playbook runs [filters]'
compatibility: connect to asp mcp server
metadata:
  author: Funnywolf
  version: 0.1.0
  mcp-server: asp
  category: cyber security
  tags: [ playbook, automation, soar, investigation ]
  documentation: https://asp.viperrtp.com/
---

# ASP Playbook

Use this skill when the user needs to work with playbook automation on ASP.

## When to Use

- The user wants to know which playbook definitions are currently available to run.
- The user wants to run a playbook against a case.
- The user wants to inspect playbook run records by target case or job status.
- The user wants to confirm whether a case has already been automated.

## Operating Rules

- Keep playbook definitions and playbook run records strictly separate in language and workflow.
- Use `list_playbook_definitions` only for runnable definitions.
- Use `list_playbook_runs` only for run records.
- Use `execute_playbook` only when the user has named a runnable definition and identified the target object.
- Do not invent a playbook definition name. If it is missing, list or suggest available definitions first.
- Treat `user_input` as optional natural-language guidance for that specific run, not as a generic chat prompt.

## Decision Flow

1. If the user wants to know what can run, call `list_playbook_definitions`.
2. If the user wants to confirm whether automation has run for a case, call `list_playbook_runs(case_id=<case_id>)`.
3. If the user wants to run automation and already provides the definition name plus target case, call `execute_playbook`.
4. If the user wants to run automation but does not know the definition name, call `list_playbook_definitions` first.
5. If the user wants the overall automation history, call `list_playbook_runs` with the narrowest useful filters.

## SOP

### List Runnable Playbook Definitions

1. Call `list_playbook_definitions`.
2. Parse the returned JSON.
3. Show only the definitions that are most relevant to the user's target object or goal.
4. Make it explicit that these are definitions, not run records.

### Run a Playbook

1. Require the target case ID and the playbook definition `name`.
2. If the definition name is missing or uncertain, call `list_playbook_definitions` first.
3. Pass `user_input` only when the user wants extra guidance for that run.
4. Call `execute_playbook(case_id=<case_id>, name=<definition_name>, user_input=<optional>)`.
5. Confirm that a pending playbook run record was created.

Preferred response structure:

- `Target Case`: case ID
- `Playbook Definition`: selected name
- `Run Status`: pending at creation time unless the platform reports otherwise
- `User Input`: only if provided
- `Next Useful Step`: usually to query related playbook runs

### Review Playbook Runs

1. Extract supported filters: `playbook_id`, `job_status`, `case_id`, and `limit`.
2. Use `case_id` when the user is asking from the perspective of one case.
3. Call `list_playbook_runs`.
4. Parse the returned JSON strings.
5. Present a short run-oriented view.

Preferred response structure:

| Run ID | Case ID | Job Status | Definition Name | Updated |
|--------|---------|------------|-----------------|---------|

Then add one short interpretation line when useful.

## Clarification Rules

- Ask for the target case ID only when it is missing for run requests.
- Ask for the playbook definition name only when it is missing or ambiguous.
- If the user names something that sounds like a run ID instead of a definition, clarify before executing.
- If the user asks to "check the run" without a run ID, prefer `list_playbook_runs` with object context instead of guessing a specific run.

## Output Rules

- Be concise.
- Do not blur the words definition, run, record, and target object.
- Do not dump all playbook definitions if only a shortlist is relevant.
- Prefer operational wording: what can run, what ran, what is pending, and what should be checked next.

## Failure Handling

- If no matching playbook definitions exist, say that directly and suggest the closest relevant options.
- If no run records exist for the target, say that directly.
- If execution prerequisites are missing, ask one focused clarification instead of guessing.
- If the user asks for something only run records can answer, do not answer from definitions alone.