# Dashboard Design

## Status

Approved for implementation planning on 2026-06-25.

## Goal

Create a new Dashboard page that presents the platform as a Cyber Command Center: a dark, high-impact security posture view suitable as a public-facing first impression, while still using real platform data only.

The dashboard should show valuable SOC state and security posture signals, not mock or fabricated telemetry. It should use the Ant Design family for the visual system, with Ant Design Charts for charts where practical.

## Non-goals

- Do not replace the current `/` default route to Cases.
- Do not create synthetic demo records or hard-coded metric values.
- Do not turn the dashboard into a table-heavy SOC queue.
- Do not add real-time streaming in the first version.

## Existing data sources

The first version uses existing backend models:

- `Case`: status, severity, priority, confidence, impact, verdict, category, assignee, timestamps, AI assessment fields, and linked alert/playbook counts.
- `Alert`: severity, confidence, impact, status, risk level, product category/vendor/name, MITRE tactic/technique, first/last seen time, artifacts, and linked case.
- `Artifact`: type, name, role, value, and linked alerts.
- `Enrichment`: type, provider, linked case/alert/artifact.
- `Playbook`: job status, name, user, linked case, timestamps.
- `Knowledge`: source, tags, linked case.
- `AuditLog`: recent create/update/delete activity.

## Navigation and routing

Add a new `/dashboard` frontend route and a Dashboard item in the main sidebar. The route is available to authenticated users.

Keep the current root behavior unchanged: `/` still redirects to `/cases`.

## Page shape

The page is presentation-first and should feel more like a security operations screen than an admin report. It uses the existing dark theme and sidebar, then adds a denser cyber visual layer inside the content area:

1. Hero strip with title, selected time window, last refreshed time, and manual refresh.
2. Core posture band with Active Risk Index, open critical cases, critical/high alerts, automation success rate, MTTD, MTTA, and MTTR.
3. Threat landscape charts: alert trend, severity distribution, product/category distribution, and MITRE tactic distribution.
4. Automation and intelligence panels: playbook status, enrichment coverage, knowledge extraction signal.
5. Risk focus area: top risk artifacts as visual cards and latest high-severity highlights as an event stream.

Avoid traditional tables on this page. Lists should be styled as timeline/event-stream cards, not `Table`.

## Time windows

The page supports three windows:

- 24h
- 7d
- 30d

Default window: 7d.

The user switches windows with an Ant Design `Segmented` control. Data refresh is manual through a `Refresh` action. There is no automatic polling in the first version.

## Backend API

Add a backend dashboard aggregation endpoint:

```text
GET /api/dashboard/overview/?window=24h|7d|30d
```

The endpoint should be authenticated and read-only. It should aggregate with Django ORM queries on existing tables. Use a dedicated `apps.dashboard` Django app because dashboard aggregation is a business feature, not generic metadata.

No database migration is expected because the dashboard does not add new models.

### Response shape

The response is grouped by frontend module:

```json
{
  "window": "7d",
  "generated_at": "2026-06-25T13:00:00Z",
  "summary": {
    "active_risk_index": 73,
    "open_cases": 12,
    "open_critical_cases": 3,
    "critical_high_alerts": 28,
    "running_playbooks": 2,
    "failed_playbooks": 1,
    "automation_success_rate": 82.5
  },
  "mean_times": {
    "mttd": {"seconds": 3600, "sample_count": 8},
    "mtta": {"seconds": 5400, "sample_count": 6},
    "mttr": {"seconds": 43200, "sample_count": 4}
  },
  "alert_trend": [],
  "severity_distribution": [],
  "case_status_mix": [],
  "product_category_distribution": [],
  "mitre_tactics": [],
  "automation": [],
  "coverage": {},
  "top_risk_artifacts": [],
  "recent_highlights": []
}
```

Arrays should contain simple `{label, value}` or `{time, label, value}` objects where possible, so the frontend stays display-focused.

## Metric definitions

### Active Risk Index

Active Risk Index is a normalized risk-pressure visualization derived from existing records. It is not an external security rating.

Use only records in the selected window and open operational state:

- Cases with status `New`, `In Progress`, or `On Hold`.
- Alerts with status `New` or `In Progress`.
- Playbooks with status `Running` or `Failed`.

Severity weights:

- Critical: 10
- High: 6
- Medium: 3
- Low: 1
- Informational/Info: 0.5
- Unknown/empty/Other: 0

Formula:

```text
raw_score =
  sum(open_case_severity_weight * 2)
  + sum(active_alert_severity_weight)
  + failed_playbook_count * 4
  + running_playbook_count * 1

active_risk_index = min(100, round(raw_score))
```

The UI tooltip must explain that this is a weighted risk-pressure index based on current platform records.

### MTTD

Mean Time To Detect.

Base records: cases created in the selected window.

For each case, use:

```text
case.created_at - first_alert_seen_time
```

`first_alert_seen_time` is the earliest non-empty `Alert.first_seen_time` for the case.

Include only non-negative durations where both timestamps exist. Return average seconds and sample count. If the sample count is zero, return `seconds: null` and show `N/A`.

### MTTA

Mean Time To Acknowledge.

Base records: cases acknowledged in the selected window.

For each case, use:

```text
case.acknowledged_time - case.created_at
```

Include only non-negative durations where both timestamps exist. Return average seconds and sample count. If the sample count is zero, return `seconds: null` and show `N/A`.

### MTTR

Mean Time To Resolve.

Base records: cases closed in the selected window.

For each case, use:

```text
case.closed_time - case.acknowledged_time
```

Include only non-negative durations where both timestamps exist. Return average seconds and sample count. If the sample count is zero, return `seconds: null` and show `N/A`.

## Visual components

Use Ant Design components for layout and controls:

- `Card`
- `Statistic`
- `Segmented`
- `Tooltip`
- `Badge`
- `Tag`
- `Progress`
- `Skeleton`
- `Alert`
- `Button`

Use Ant Design Charts for chart rendering:

- Gauge or circular progress for Active Risk Index.
- Area or Line chart for alert trend.
- Pie or Rose chart for severity distribution.
- Column chart for product category distribution.
- Column or compact heat-strip component for MITRE tactics.
- Donut or stacked status visualization for playbook automation status.

The page can include custom CSS for cyber presentation: subtle gradients, glow borders, grid backgrounds, and compact event cards. Keep it scoped to the dashboard page.

## Empty, loading, and error states

Loading state:

- Preserve the full dashboard layout.
- Use Skeleton cards and chart placeholders.

Empty state:

- Do not use plain default `Empty`.
- Use a custom cyber-style empty panel such as "No telemetry in this window" or "Signal quiet".
- Do not fabricate fallback data.

Error state:

- Keep the dashboard shell visible.
- Show a low-profile module-level error or corner notice.
- Keep the manual Refresh action available.
- Avoid large blocking error pages because the dashboard is presentation-oriented.

## Frontend data flow

Add a dashboard API helper that calls `/dashboard/overview/`.

`Dashboard.tsx` owns:

- selected window state,
- loading/error state,
- fetched dashboard payload,
- manual refresh,
- formatting seconds into readable durations,
- rendering module components.

Break visual modules into these small components so each component has a single display responsibility:

- `PostureMetricCard`
- `MeanTimeMetricCard`
- `ThreatTrendChart`
- `DistributionChart`
- `AutomationPanel`
- `RiskArtifactCard`
- `SecurityHighlightStream`

These components should receive plain data props and not fetch directly.

## Permissions

Dashboard is available to authenticated users. It does not require admin permission.

The endpoint should use the same authentication behavior as other platform APIs.

## Testing and validation

Backend validation:

- The dashboard endpoint returns HTTP 200 for authenticated users.
- `window=24h`, `window=7d`, and `window=30d` return the same response shape.
- Invalid `window` returns a clear 400 response.
- MTTD, MTTA, and MTTR ignore incomplete or negative durations and include sample counts.
- Empty datasets return zero counts, empty arrays, and `null` mean-time seconds rather than failing.

Frontend validation:

- Dashboard route renders for authenticated users.
- Time-window switching requests the matching backend window.
- Loading, empty, and error states render without breaking the layout.
- `N/A` is shown for MTTD/MTTA/MTTR when sample count is zero.
- Existing root route and Cases page behavior remain unchanged.

Manual visual validation:

- Dashboard fits the existing dark shell.
- The first screen feels promotional and high-impact.
- The page avoids table-heavy layout.
- Charts and KPI cards remain readable on common laptop widths.
