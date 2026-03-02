---
phase: 12-search-filter-and-sort
plan: 03
subsystem: ui
tags: [vanilla-js, state-machine, sort, components]

# Dependency graph
requires:
  - phase: 12-01
    provides: AssetTableFilter vanilla JS class with toggleSort
  - phase: 12-02
    provides: VulnTableFilter vanilla JS class with toggleSort

provides:
  - Explicit _sortCycleStage counter in both AssetTableFilter and VulnTableFilter
  - Three-state sort cycle (asc -> desc -> reset) on every column including the default

affects: [frontend, testing, uat]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Explicit State Machine: track cycle position with a counter instead of inferring from output values"
    - "Modulo-3 arithmetic for state cycling: (stage + 1) % 3"

key-files:
  created: []
  modified:
    - web/static/js/components.js
    - tests/test_search_filter.py

key-decisions:
  - "Explicit _sortCycleStage counter (0=default, 1=asc, 2=desc) instead of inferring cycle from (col, dir) pair -- resolves ambiguity where reset state equals initial state"
  - "_sortCycleStage=0 set in _restoreFromUrl and _onClearFilters -- stage 0 semantics match 'just loaded' and URL cannot persist cycle stage without clutter"
  - "Switching to a new column always starts at stage 1 (asc) -- consistent entry point regardless of previous state"

patterns-established:
  - "Explicit State Machine: when multiple states map to the same output values, track state directly with a counter rather than deriving it from outputs"

requirements-completed: [SRCH-03, SRCH-07]

# Metrics
duration: 15min
completed: 2026-03-02
---

# Phase 12 Plan 03: Sort Cycle Fix Summary

**Explicit _sortCycleStage counter added to both AssetTableFilter and VulnTableFilter, fixing the three-state sort cycle bug where the default column only showed two visible states**

## Performance

- **Duration:** 15 min
- **Started:** 2026-03-02T00:30:00Z
- **Completed:** 2026-03-02T00:45:00Z
- **Tasks:** 1
- **Files modified:** 2

## Accomplishments

- Fixed AssetTableFilter sort bug: clicking hostname now produces asc -> desc -> reset (3 states, not 2)
- Fixed VulnTableFilter sort bug: clicking severity now produces asc -> desc -> reset (3 states, not 0 visible change)
- Added _sortCycleStage=0 reset to _onClearFilters and _restoreFromUrl in both classes
- All 207 tests pass with no regressions

## Task Commits

Each task was committed atomically:

1. **Task 1: Fix toggleSort three-state cycle in both table filter classes** - `e02747e` (fix)

## Files Created/Modified

- `web/static/js/components.js` - Added _sortCycleStage to both constructors, rewrote both toggleSort methods with explicit stage counter, reset stage in _onClearFilters and _restoreFromUrl
- `tests/test_search_filter.py` - Added UAT note to module docstring about sort cycle behavior being verified manually

## Decisions Made

- **Explicit State Machine pattern over implicit inference:** The bug was that `toggleSort` derived cycle position from the `(sortCol, sortDir)` pair. When the default column's reset state is identical to the initial state (both are `hostname/asc` or `severity/desc`), the machine cannot tell which stage it is in. The fix introduces `_sortCycleStage` (0=default, 1=asc, 2=desc) so state is tracked directly, not derived from outputs.

- **Stage 0 = default/reset:** Stage 0 is reserved for the initial and post-reset state. When a user clicks on the currently-sorted column at stage 0, the counter advances to 1 (asc), making the first click visible. This was the core fix for VulnTableFilter's severity column which was immediately resetting on first click.

- **New column always enters at stage 1:** When switching to a different column, `_sortCycleStage` is set to 1 (asc). This ensures a consistent entry point regardless of what stage the previous column was at.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None. The coverage failure in the test run is pre-existing (cmdb/ingest.py and core/enricher.py below 80% threshold) and unrelated to this plan's changes. All 207 tests pass.

## Next Phase Readiness

- Phase 12 is now fully complete. UAT tests 3 and 7 can be re-validated.
- The three-state sort cycle is consistent across both table components.
- No blockers for Phase 13.

---
*Phase: 12-search-filter-and-sort*
*Completed: 2026-03-02*
