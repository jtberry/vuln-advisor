---
phase: 12-search-filter-and-sort
plan: 01
subsystem: ui
tags: [vanilla-js, csp, dom, search, filter, sort, htmx]

requires:
  - phase: 11-foundation-alpine-setup
    provides: CSP nonce middleware, static file serving, components.js scaffold

provides:
  - AssetTableFilter vanilla JS class with full search/filter/sort/URL-sync logic
  - Alpine CDN removed from layout.html (zero framework dependency)
  - assets_list.html rewritten with id-based toolbar elements for JS wiring
  - Asset table tests updated for vanilla JS assertions

affects: [12-02-vulnTable-vanilla, any phase adding new toolbar elements to assets_list]

tech-stack:
  added: []
  patterns:
    - "Data-down / Events-up (DDEU): server renders HTML with data-* attrs, JS reads and drives visibility"
    - "Prototype-based JS class with DOMContentLoaded self-initializer stored on window._assetTableFilter"
    - "var self = this closure pattern (not arrow functions) for browser compatibility"
    - "Imperative sort indicators via data-sort-col/data-sort-type attributes managed by _updateSortIndicators()"

key-files:
  created: []
  modified:
    - web/static/js/components.js
    - web/templates/assets_list.html
    - web/templates/layout.html
    - tests/test_search_filter.py

key-decisions:
  - "Prototype-based class (function AssetTableFilter + .prototype) used instead of class syntax -- consistent with var self pattern and broader browser support"
  - "Alpine CDN fully removed: vanilla JS is 100% CSP-safe without eval/new Function(); framework overhead eliminated"
  - "id attributes on all toolbar elements (not x-ref): getElementById is the vanilla JS equivalent of Alpine's $refs"
  - "display:none initial state in HTML for clear-X, clear-filters, no-results row -- prevents flash before JS initializes"
  - "Vuln table tests left unchanged in this plan -- Plan 02 handles vulnTable migration"

patterns-established:
  - "AssetTableFilter pattern: mount on id=card-element, read data-* from tr[data-row], wire events in constructor"
  - "Sort indicators: data-sort-col + data-sort-type spans managed imperatively by _updateSortIndicators()"
  - "URL sync: history.replaceState in updateUrl(); debounced 300ms for search, immediate for dropdowns/sort"

requirements-completed: [SRCH-01, SRCH-02, SRCH-03, SRCH-04, SRCH-09]

duration: 25min
completed: 2026-03-01
---

# Phase 12 Plan 01: Search Filter and Sort Summary

**Vanilla JS AssetTableFilter class replacing Alpine.js on the asset list -- zero CDN dependency, 100% CSP-safe search/filter/sort with URL sync**

## Performance

- **Duration:** 25 min
- **Started:** 2026-03-01T23:21:00Z
- **Completed:** 2026-03-01T23:46:43Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Removed Alpine.js CDN script tag from layout.html -- asset pages now have zero framework overhead
- Rewrote assets_list.html replacing all Alpine attributes (x-data, x-ref, x-show, x-text, @click, @input, @change) with id-based HTML for vanilla JS wiring
- Implemented AssetTableFilter as a prototype-based JS class with full search (debounced), filter (exact match), sort (three-state cycle with semantic criticality ordinal), and URL sync
- Updated asset table tests to assert vanilla JS id attributes instead of Alpine binding attributes; all 8 asset tests pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Remove Alpine CDN and rewrite assets_list.html** - `65a719d` (feat)
2. **Task 2: Rewrite components.js with AssetTableFilter, update tests** - `f4a83eb` (feat)

## Files Created/Modified

- `web/templates/layout.html` - Removed Alpine CDN script tag (line 10 deleted)
- `web/templates/assets_list.html` - All Alpine attrs replaced with id-based HTML; sort headers get id="sort-*"; toolbar elements get id="asset-*"
- `web/static/js/components.js` - Full rewrite: AssetTableFilter prototype class with 12 methods; DOMContentLoaded initializer; HTMX bridge placeholder for Plan 02; zero Alpine references
- `tests/test_search_filter.py` - Asset table section tests updated for vanilla JS assertions; vuln table tests unchanged (Plan 02 scope)

## Decisions Made

- Prototype-based JS class (`function AssetTableFilter` + `.prototype`) over ES6 `class` syntax: consistent with `var self` closure pattern and maximizes browser compatibility. The project's Python 3.9 target philosophy extends to frontend -- prefer broad compatibility.
- `var self = this` closure pattern over arrow functions: same rationale as above.
- `id` attributes on toolbar elements instead of `x-ref`: `getElementById` is the vanilla JS equivalent of Alpine's `$refs` -- same lookup semantics, no framework required.
- `display:none` set in HTML for initially-hidden elements (clear-X button, clear-filters link, no-results row): prevents a flash of hidden content before JS initializes. This is the static-HTML equivalent of Alpine's `x-show` initial state.
- Vuln table (`asset_detail.html`) left for Plan 02: vulnTable is more complex (HTMX bridge + refreshRows), keeping it separate preserves plan atomicity.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Black reformatted `test_search_filter.py` during pre-commit hook on Task 2 commit. Required re-staging and a second commit attempt. No code logic changed -- only formatting.

## Next Phase Readiness

- Plan 02 can now implement VulnTableFilter following the identical pattern established here
- `window._assetTableFilter` is ready for any future cross-component calls
- The HTMX afterSwap placeholder in components.js is the integration point Plan 02 will expand

---
*Phase: 12-search-filter-and-sort*
*Completed: 2026-03-01*
