---
phase: 03-dashboard-charts
plan: "03"
subsystem: ui
tags: [bootstrap, modal, htmx, jinja2, fetch-api, optimistic-ui]

requires:
  - phase: 02-data-layer
    provides: PATCH /api/v1/assets/{id}/vulnerabilities/{cve}/status endpoint with typed response

provides:
  - Bootstrap 5.3 status modal (status_modal.html) for single-vuln optimistic update and bulk status change
  - Clickable status badges on vuln rows (replace HTMX inline form)
  - Checkbox column and bulk action toolbar on asset detail page
  - Toast notification system for status change feedback

affects:
  - 04-ui-polish (modal and badge patterns established here should be consistent with future UI work)
  - 05-test-coverage (modal JS and badge rendering need route tests)

tech-stack:
  added: []
  patterns:
    - "Optimistic UI via JS: apply DOM change immediately, revert on API failure"
    - "Bootstrap modal reuse: single modal instance for both single and bulk operations, mode set via dataset"
    - "Dynamic Bootstrap Toast: create element in JS, inject into #toastContainer, auto-remove on hidden event"
    - "data-cve on <tr> for querySelector lookup by CVE ID in optimistic revert logic"

key-files:
  created:
    - web/templates/partials/status_modal.html
  modified:
    - web/templates/partials/vuln_row.html
    - web/templates/asset_detail.html

key-decisions:
  - "Single modal instance for both single and bulk modes: mode flag in modal dataset, populated before Bootstrap opens it"
  - "Bulk uses page reload (not optimistic DOM updates): N concurrent optimistic updates with revert logic is too complex to be safe; reload is simple and correct"
  - "No CSRF token in JSON fetch calls: CSRF protection in this app is form-POST specific; JSON PATCH to API uses session cookie auth"
  - "Status badge closed case uses inline style (not bg-dark): matches existing dark badge pattern in the codebase (#21262d)"

patterns-established:
  - "Optimistic UI pattern: save old class+text, apply new state, revert on error"
  - "Bootstrap modal dataset pattern: set data-* before calling .show() so show.bs.modal handler reads correct values"
  - "Toast pattern: dynamically create element, inject into fixed container, remove after hidden.bs.toast fires"

requirements-completed: [STAT-03, STAT-04]

duration: 4min
completed: "2026-02-26"
---

# Phase 03 Plan 03: Asset Detail Status Modal Summary

**Bootstrap 5.3 modal replaces HTMX inline status dropdown -- single-vuln optimistic UI + bulk checkbox status change via fetch PATCH**

## Performance

- **Duration:** 4 min
- **Started:** 2026-02-26T21:42:37Z
- **Completed:** 2026-02-26T21:46:37Z
- **Tasks:** 2
- **Files modified:** 3 (1 created, 2 updated)

## Accomplishments

- Replaced the HTMX inline status select+save form with a clickable colored status badge that opens a Bootstrap modal
- Implemented optimistic UI: badge updates immediately in the DOM on click-save, reverts with error toast if PATCH fails
- Added checkbox column to every vuln row with a select-all header and a bulk action toolbar that appears on first checkbox selection
- Bulk mode fires one PATCH per selected CVE via Promise.all, then reloads the page (simpler and safer than N optimistic updates)
- Toast notification system using dynamically created Bootstrap Toast elements injected into a fixed #toastContainer

## Task Commits

Each task was committed atomically:

1. **Task 1: Create status modal partial and toast helper** - `0d65b46` (feat)
2. **Task 2: Replace HTMX status dropdown with clickable badge, add checkboxes and bulk controls** - `3c949e5` (feat)

## Files Created/Modified

- `web/templates/partials/status_modal.html` - Bootstrap 5.3 modal with single/bulk mode, JS save handler, showToast helper, applyStatusBadge helper
- `web/templates/partials/vuln_row.html` - Replaced HTMX form with status-badge span; added checkbox first column; data-cve on tr
- `web/templates/asset_detail.html` - Added select-all header, bulk toolbar, modal include, toast container, checkbox management JS

## Decisions Made

- **Single modal instance for both modes:** The modal's `data-mode` dataset attribute toggles between `single` and `bulk`. The bulk button sets this before calling `.show()` so the `show.bs.modal` handler reads the right context. This avoids having two modals in the DOM.
- **Bulk uses page reload:** After Promise.all completes, the page reloads after a short toast delay. This avoids the complexity of N concurrent optimistic badge updates each needing their own revert path. Research in 03-RESEARCH.md confirmed this as the right trade-off.
- **No CSRF token in fetch calls:** The PATCH endpoint is a JSON API route that authenticates via session cookie. CSRF protection in this app uses `fastapi-csrf-protect` which only applies to form POST routes. JSON fetch calls are outside that scope.
- **`closed` badge uses inline style:** The existing codebase uses `style="background-color: #21262d; color: #8b949e"` for dark badges (asset tags, IP, environment). This is consistent with that convention rather than `bg-dark` which is lighter.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

The pre-commit hook uses stash/restore for unstaged files. When Task 1 committed only the new modal partial, the hook stashed the (already-written) vuln_row and asset_detail changes, then restored them. The system notification showed old content briefly but the on-disk files were correct. Task 2 verification confirmed the actual file state.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Status workflow is now complete end-to-end in the UI: ingest -> asset detail -> click badge -> modal -> save -> badge updates in place
- Phase 3 is complete (03-01, 03-02, 03-03 all done)
- Phase 4 (UI Polish) can begin; the modal and badge color patterns established here should be carried forward consistently

---
*Phase: 03-dashboard-charts*
*Completed: 2026-02-26*
