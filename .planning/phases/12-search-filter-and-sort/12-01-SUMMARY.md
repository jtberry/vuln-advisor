---
phase: 12-search-filter-and-sort
plan: "01"
subsystem: ui
tags: [alpine, javascript, csp, filtering, sorting, search, assets]

requires:
  - phase: 11-foundation-alpine-setup
    provides: Alpine.js CSP build, components.js skeleton, assetTable stub, HTMX bridge

provides:
  - Complete assetTable Alpine.data() component with search, criticality/environment filter, three-state sort, debounced URL sync
  - Fully wired assets_list.html template with toolbar, data-* row attributes, sortable headers, and no-results state
  - 8 smoke tests in test_phase12_search_filter.py verifying Alpine HTML structure

affects: [12-02-vulnerability-table, future-client-side-filter-patterns]

tech-stack:
  added: []
  patterns:
    - "Data-down / Events-up (DDEU): server renders full table as HTML; Alpine reads data-* attrs and drives visibility without server round-trips"
    - "Three-state sort cycle: asc -> desc -> reset to default (hostname A-Z)"
    - "CSP-safe input binding: :value + @input instead of x-model to comply with CSP no-eval policy"
    - "Semantic criticality sort: ordinal map { critical:0, high:1, medium:2, low:3 } for correct priority ordering"
    - "Debounced URL sync: 300ms setTimeout on search input; immediate sync on filter/sort changes"

key-files:
  created:
    - tests/test_phase12_search_filter.py
  modified:
    - web/static/js/components.js
    - web/templates/assets_list.html

key-decisions:
  - "EnvironmentEnum values are production/staging/development (not internet/internal/isolated which are ExposureEnum values) -- plan's dropdown options updated to match actual model"
  - "Default sort on page load is hostname A-Z (locked decision from STATE.md) -- URL params only written when deviating from default"
  - "data-name mirrors data-hostname (assets have no separate display-name field) -- documented in template comments"
  - "data-vuln-count hardcoded to 0 for now -- vuln count sort reserved for future Plan 02 integration"

patterns-established:
  - "Alpine component boundary: x-data on the outermost card div -- all x-* attrs inside are scoped to that component instance"
  - "data-row selector pattern: Alpine init() uses tbody.querySelectorAll('tr[data-row]') to find rows -- data-row is the stable selector, not row index or class"
  - "Lowercase in template: data-hostname/ip/name values lowercased via Jinja2 | lower filter to avoid repeated .toLowerCase() in JS on every keystroke"
  - "No-results row: x-show='matchCount === 0 && totalCount > 0' with style='display:none' fallback to prevent flash before Alpine mounts"

requirements-completed: [SRCH-01, SRCH-02, SRCH-03, SRCH-04, SRCH-09]

duration: 18min
completed: 2026-02-28
---

# Phase 12 Plan 01: Search Filter and Sort Summary

**Alpine assetTable component with text search, criticality/environment dropdowns, three-state hostname/criticality/environment sort, and URL-persisted filter state wired to assets_list.html**

## Performance

- **Duration:** 18 min
- **Started:** 2026-02-28T23:27:32Z
- **Completed:** 2026-02-28T23:45:16Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Complete `assetTable` Alpine.data() component replacing the Phase 11 skeleton: text search across hostname/IP/name, exact-match criticality and environment filters, three-state column sort with semantic criticality ordering, debounced 300ms URL sync via history.replaceState
- assets_list.html fully wired with search/filter toolbar (left: text input + result count, right: dropdowns + Clear filters), `data-*` attributes on all rows, sortable Hostname/Environment/Criticality headers with three-state arrow indicators, and no-results empty state
- 8 HTML structure smoke tests in test_phase12_search_filter.py -- all pass; full suite 199/199 passing with 100% coverage

## Task Commits

Each task was committed atomically:

1. **Task 1: Create test scaffold and complete assetTable component** - `ae65609` (feat)
2. **Task 2: Wire assets_list.html with Alpine toolbar and data attributes** - `2e40cfb` (feat)

## Files Created/Modified

- `tests/test_phase12_search_filter.py` - 8 smoke tests verifying Alpine HTML structure wiring on the assets list page
- `web/static/js/components.js` - Full assetTable Alpine.data() component replacing Phase 11 skeleton; HTMX bridge preserved
- `web/templates/assets_list.html` - Search/filter toolbar, data-* attrs on rows, sortable headers, no-results state

## Decisions Made

- **EnvironmentEnum mismatch:** The plan's test fixture and dropdown options used `internal` for environment, but the actual API model uses `EnvironmentEnum` (production/staging/development). The `internal` value belongs to `ExposureEnum`. Fixed the test fixture to use `production` and updated dropdown options to show Production/Staging/Development to match the model. This is a plan error caught at execution, not a code deviation.
- **URL sync for default sort:** Hostname A-Z is the default. The `updateUrl()` method skips writing `sort` and `dir` params when the state matches the default, keeping URLs clean. Hostname-desc is treated as non-default and is preserved in the URL.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixture used wrong environment enum value**
- **Found during:** Task 1 (test scaffold)
- **Issue:** Plan specified `"environment": "internal"` in the test fixture POST body, but `EnvironmentEnum` only accepts `production`/`staging`/`development`. The `internal` value belongs to `ExposureEnum`. API returned 422 Unprocessable Entity.
- **Fix:** Changed fixture to use `"environment": "production"` and updated the `test_assets_list_environment_attr` assertion to check for `data-environment="production"`. Updated dropdown options in the toolbar from internet/internal/isolated to production/staging/development.
- **Files modified:** tests/test_phase12_search_filter.py, web/templates/assets_list.html
- **Verification:** 422 resolved, test fixture passes, all 8 tests pass
- **Committed in:** ae65609 (Task 1) and 2e40cfb (Task 2)

**2. [Rule 3 - Blocking] API route path was /v1/assets not /api/v1/assets**
- **Found during:** Task 1 (test scaffold)
- **Issue:** Fixture called `POST /v1/assets` but the actual route is `POST /api/v1/assets`. Got 404 Not Found.
- **Fix:** Corrected the path in the fixture.
- **Files modified:** tests/test_phase12_search_filter.py
- **Verification:** 404 resolved, 201 Created returned
- **Committed in:** ae65609 (Task 1)

---

**Total deviations:** 2 auto-fixed (1 bug in plan's test data, 1 blocking wrong route path)
**Impact on plan:** Both were plan-data errors caught at execution. No architectural changes needed.

## Issues Encountered

None beyond the auto-fixed deviations above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 01 establishes the toolbar/data-attr/sort pattern that Plan 02 (vulnerability table) will replicate
- The `assetTable` component is fully functional and tested
- Key pattern for Plan 02: same DDEU approach, same three-state sort, same URL sync, same CSP constraints

---
*Phase: 12-search-filter-and-sort*
*Completed: 2026-02-28*
