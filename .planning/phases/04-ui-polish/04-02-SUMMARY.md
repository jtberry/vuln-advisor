---
phase: 04-ui-polish
plan: "02"
subsystem: ui
tags: [jinja2, bootstrap, dashboard, empty-states, ux]

# Dependency graph
requires:
  - phase: 03-dashboard-charts
    provides: Dashboard route with threat intel, overdue SLA, and Chart.js doughnut sections

provides:
  - Getting-started card for fresh installs (no assets) instead of zero-filled KPI dashboard
  - Reordered dashboard sections: KPI cards -> Overdue SLA -> Severity chart + Asset Risk -> Threat Intel
  - All-clear green checkmark widgets for empty SLA and Threat Intel sections
  - Clickable table rows in SLA and Threat Intel tables navigating to asset detail
  - Corrected CVE ID links in Threat Intel table pointing to /cve/CVE-ID
  - Upgraded assets list empty state with CTA button and scanner import link
  - Upgraded asset detail no-vulns empty state with manual add and scanner import buttons

affects:
  - 04-03 (any further UI polish plans)
  - web/routes.py (getting_started context variable)
  - web/templates/dashboard.html
  - web/templates/assets_list.html
  - web/templates/asset_detail.html

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "getting_started flag pattern: total_assets == 0 in route context controls entire dashboard branch"
    - "All-clear widget: green checkmark (&#10003;) with positive confirmation text replaces blank/gray empty states"
    - "Clickable row with link stopPropagation: tr onclick for row navigation, a onclick=event.stopPropagation() for inline links"

key-files:
  created: []
  modified:
    - web/routes.py
    - web/templates/dashboard.html
    - web/templates/assets_list.html
    - web/templates/asset_detail.html

key-decisions:
  - "getting_started branch wraps entire dashboard body below header - KPI cards never show zeros on fresh install"
  - "CVE ID links in Threat Intel table go to /cve/CVE-ID, row click goes to /assets/ID - two distinct navigation targets"
  - "stopPropagation on inline links prevents row click handler firing when link is clicked directly"
  - "asset_detail no-vulns button focuses cve_ids_raw textarea via getElementById - no page navigation needed"

patterns-established:
  - "Empty state CTA pattern: fw-semibold label + descriptive text + primary action button + secondary text link"
  - "Dual-target clickable row: tr onclick=location.href + a onclick=event.stopPropagation() for inline link"

requirements-completed:
  - UIPL-02
  - UIPL-03

# Metrics
duration: 4min
completed: 2026-02-26
---

# Phase 4 Plan 02: Dashboard UX and Empty States Summary

**Getting-started card for fresh installs, reordered dashboard sections (SLA before charts), green all-clear widgets, clickable table rows, and actionable empty states on assets list and asset detail pages**

## Performance

- **Duration:** ~4 min
- **Started:** 2026-02-26T22:17:00Z
- **Completed:** 2026-02-26T22:20:45Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Added `getting_started` flag to dashboard route and wrapped all content in `{% if getting_started %}/{% else %}` branches so fresh installs see a welcoming card instead of a dashboard full of zeros
- Reordered dashboard from (KPI, Severity+AssetRisk, ThreatIntel, SLA) to (KPI, SLA, Severity+AssetRisk, ThreatIntel) so overdue work is immediately visible
- Replaced plain "no items" text with green checkmark all-clear messages in SLA and Threat Intel empty widgets
- Made SLA and Threat Intel table rows clickable (navigate to asset detail); corrected Threat Intel CVE ID links from /assets/ID to /cve/CVE-ID
- Upgraded assets list and asset detail empty states with direct CTA buttons and secondary scanner import options

## Task Commits

1. **Task 1: Add getting-started flag and restructure dashboard template** - `cd6b951` (feat)
2. **Task 2: Upgrade empty states on assets list and asset detail pages** - `2f9b1d7` (feat)

## Files Created/Modified

- `web/routes.py` - Added `"getting_started": total_assets == 0` to dashboard template context
- `web/templates/dashboard.html` - Page header renamed to "Risk Overview"; getting-started branch added; sections reordered; all-clear widgets; clickable rows; CVE links corrected
- `web/templates/assets_list.html` - Empty state upgraded from passive link text to primary CTA button + scanner import secondary link
- `web/templates/asset_detail.html` - No-vulns empty state upgraded from single hint to two action buttons (manual add focuses textarea, scanner import links to /ingest)

## Decisions Made

- `getting_started` flag wraps the entire dashboard body below the page header - KPI zeros must never appear on fresh install; this is a single-flag branch, not per-widget conditionals
- CVE ID links in Threat Intel table navigate to `/cve/CVE-ID` (detail view), while the full row click navigates to `/assets/ID` (asset context) - two distinct user intents served by two click targets
- `event.stopPropagation()` on inline `<a>` tags inside clickable `<tr>` elements prevents the row handler from firing when the user intends to follow the link directly

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - all hooks passed cleanly on retry (pip-audit modifies its cache on first run, passes on second).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Dashboard is now a usable daily landing page for both fresh installs and active users
- Empty states on assets list and asset detail guide users to their next action
- Chart.js and client-side pagination JS unchanged and fully functional
- All 122 tests pass with 100% coverage on core modules

---
*Phase: 04-ui-polish*
*Completed: 2026-02-26*
