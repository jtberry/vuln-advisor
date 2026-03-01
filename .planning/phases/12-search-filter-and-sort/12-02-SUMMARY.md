---
phase: 12-search-filter-and-sort
plan: "02"
subsystem: ui
tags: [alpine.js, htmx, javascript, jinja2, testing]

# Dependency graph
requires:
  - phase: 12-01
    provides: assetTable Alpine component and assets_list.html wiring as reference pattern
  - phase: 11-foundation-alpine-setup
    provides: Alpine CSP build, components.js file, HTMX bridge foundation

provides:
  - vulnTable Alpine.data() component with search, severity/status filter, column sort, URL sync
  - HTMX coexistence via outer-card x-data pattern (vulnTable root outside tbody)
  - refreshRows() method called after HTMX swaps to re-read new DOM rows
  - data-row, data-cve, data-description, data-severity, data-cvss, data-status on vuln <tr>
  - Sortable headers for CVE, Priority, CVSS, Status with three-state sort indicators
  - Checkbox fix: getCheckboxes() filters hidden rows so Select All only hits visible rows
  - 8 integration tests for vuln table HTML structure (16 total Phase 12 tests)

affects:
  - Any phase that modifies asset_detail.html or vuln_row.html
  - Phase 13 (CSV export) if it adds columns to the vuln table
  - Any future server-side pagination that replaces client-side filtering

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Outer-card x-data pattern: Alpine root on card div, not tbody, so HTMX swaps happen inside Alpine scope without destroying component"
    - "refreshRows() bridge: HTMX afterSwap listener re-reads DOM into this.rows array after HTMX innerHTML swap"
    - "Ordinal map sort: _severityOrdinal and _statusOrdinal for semantic sort (P1=0 ... P4=3)"
    - "Vanilla JS coexistence: Alpine owns filter/sort, vanilla JS owns checkboxes; getCheckboxes() visibility filter is the bridge"
    - "CSP-safe handlers: @input/:value pattern instead of x-model; function(){} syntax, no arrow functions or template literals"

key-files:
  created: []
  modified:
    - web/static/js/components.js
    - web/templates/asset_detail.html
    - web/templates/partials/vuln_row.html
    - tests/test_phase12_search_filter.py

key-decisions:
  - "x-data='vulnTable' on outer card div (not tbody): required because HTMX hx-swap=innerHTML targets #vuln-table-body; if Alpine owned tbody, the swap would destroy the component"
  - "data-cve lowercased on <tr> for case-insensitive search; original casing preserved via data-cve-id on checkbox element for vanilla JS bulk actions"
  - "Default sort: severity descending (P1/Critical first) on page load; dir=desc with ordinal P1=0 means P1 sorts first in ascending-ordinal order with desc multiplier"
  - "URL sync omits sort/dir params when state matches default (severity desc) to keep URLs clean"
  - "Empty-state row uses data-empty-state (no data-row) so readRows() excludes it from this.rows array"
  - "cache.get.return_value = None in test fixture: prevents MagicMock being used as EnrichedCVE (which fails SQLAlchemy binding)"

patterns-established:
  - "Outer-card Alpine root pattern: whenever HTMX targets a tbody inside an Alpine component, x-data must be on an ancestor outside the HTMX target"
  - "refreshRows contract: any HTMX swap into a tbody inside a vulnTable must be followed by a refreshRows() call to re-sync the rows array"
  - "Ordinal map pattern for semantic sort: pre-compute rank maps in init(), reference in _applyVisibility() sort comparator"

requirements-completed: [SRCH-05, SRCH-06, SRCH-07, SRCH-08, SRCH-09]

# Metrics
duration: 35min
completed: 2026-02-28
---

# Phase 12 Plan 02: Search, Filter, and Sort -- Vuln Table Summary

**vulnTable Alpine.js component with search/filter/sort/URL-sync wired to asset detail page, with HTMX coexistence via outer-card x-data pattern and checkbox visibility fix**

## Performance

- **Duration:** 35 min
- **Started:** 2026-02-28T23:45:00Z
- **Completed:** 2026-02-28T23:20:00Z (approx)
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- vulnTable Alpine.data() component registered in components.js with full search (CVE ID + description), severity/status dropdowns, four-column sort (cve/severity/cvss/status with semantic ordinal maps), URL param persistence, and refreshRows() for HTMX coexistence
- asset_detail.html wired: x-data="vulnTable" on outer card (not tbody), search toolbar, sortable headers, empty-state row, vanilla JS checkbox fix
- vuln_row.html extended with data-row, data-cve, data-description, data-severity, data-cvss, data-status for Alpine readRows()
- 8 new integration tests (16 total for Phase 12); 207/207 full suite passing

## Task Commits

Each task was committed atomically:

1. **Task 1: Add vulnTable component to components.js and extend test scaffold** - `153a9cf` (feat)
2. **Task 2: Wire asset_detail.html and vuln_row.html** - `bc338f3` (feat)

## Files Created/Modified

- `web/static/js/components.js` - Added vulnTable Alpine.data() component (search, filter, sort, URL sync, readRows, refreshRows) and second htmx:afterSwap listener for vulnTable re-sync
- `web/templates/asset_detail.html` - Added x-data="vulnTable" on card div, search/filter toolbar, sortable headers, empty-state row, checkbox visibility fix
- `web/templates/partials/vuln_row.html` - Added data-row, data-cve (lowercased), data-description, data-severity, data-cvss, data-status attributes to <tr>
- `tests/test_phase12_search_filter.py` - Added asset_detail_page fixture and 8 vuln table structure tests

## Decisions Made

- **x-data on outer card, not tbody**: HTMX's hx-swap="innerHTML" replaces #vuln-table-body contents. If Alpine owned the tbody, the swap would destroy the Alpine component. The outer-card pattern keeps the component alive while HTMX operates inside its scope.
- **data-cve lowercased on <tr>**: Search matching works case-insensitively. The original casing is preserved in data-cve-id on the checkbox element (used by vanilla JS bulk actions), so there is no conflict.
- **Default sort: severity descending**: P1 (Critical) should appear first on page load. The ordinal map assigns P1=0, and with sortDir='desc', the comparator multiplies by -1, placing lower ordinal (more critical) rows first.
- **cache.get.return_value = None in test fixture**: Without this, MagicMock.get() returns a truthy MagicMock used as a cache hit. That mock propagates through enrichment and produces a MagicMock as cve_id in the SQL INSERT, which SQLAlchemy cannot bind. Setting return_value to None forces a cache miss and lets the real enrichment path run (returning None from fetch_nvd in tests, which is handled gracefully).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed wrong field name in test fixture API call**
- **Found during:** Task 1 (test scaffold)
- **Issue:** Test fixture posted `{"cve_ids": [...]}` but AssetVulnAssign model expects `{"ids": [...]}`. API returned 422.
- **Fix:** Changed to `json={"ids": ["CVE-2021-44228"]}`.
- **Files modified:** tests/test_phase12_search_filter.py
- **Verification:** API returned 200, fixture proceeded.
- **Committed in:** 153a9cf (Task 1 commit)

**2. [Rule 1 - Bug] Fixed MagicMock cache causing SQLAlchemy bind failure**
- **Found during:** Task 1 (test scaffold)
- **Issue:** conftest.py sets `app.state.cache = MagicMock()`. MagicMock.get() returns a truthy MagicMock treated as a cache hit. The MagicMock propagates through pipeline and becomes the cve_id parameter in the SQL INSERT. SQLAlchemy cannot bind MagicMock to a SQL parameter: `sqlite3.InterfaceError: Error binding parameter 1 - probably unsupported type`.
- **Fix:** Set `app.state.cache.get.return_value = None` in the fixture before API calls. This forces a cache miss, process_cves() calls fetch_nvd() (which returns None in test env), and the route handles None enrichment gracefully by skipping the CVE.
- **Files modified:** tests/test_phase12_search_filter.py
- **Verification:** Fixture completes without error; asset detail page renders with vuln table.
- **Committed in:** 153a9cf (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (2 Rule 1 bugs in test fixture)
**Impact on plan:** Both fixes required to get the test fixture working. No scope creep. Template implementation was exactly as planned.

## Issues Encountered

The vuln table test fixture had two related issues (wrong field name, mock cache binding failure) that were both found and fixed during Task 1. Neither affected the production code -- both were test infrastructure issues arising from the difference between the test's mock environment and the plan's assumptions.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 12 complete: both assetTable (Plan 01) and vulnTable (Plan 02) are wired and tested
- Phase 13 (CSV/report export) can proceed -- it may add columns to the vuln table; if so, vuln_row.html should be extended and readRows() may need updating if new columns need to be sortable
- The outer-card x-data pattern is established and should be documented as a project convention for any future table components that coexist with HTMX swaps

---
*Phase: 12-search-filter-and-sort*
*Completed: 2026-02-28*
