---
phase: 12-search-filter-and-sort
plan: "02"
subsystem: web/frontend
tags: [vanilla-js, search, filter, sort, htmx, vulnerability-table]
dependency_graph:
  requires: [12-01]
  provides: [VulnTableFilter class, vuln table search/filter/sort, HTMX swap resilience]
  affects: [web/templates/asset_detail.html, web/static/js/components.js]
tech_stack:
  added: []
  patterns: [prototype-based JS class, data-down/events-up, outer-card HTMX anchor]
key_files:
  created: []
  modified:
    - web/templates/asset_detail.html
    - web/static/js/components.js
    - tests/test_search_filter.py
    - tests/test_csp_alpine.py
decisions:
  - "VulnTableFilter anchors on outer card div (id=vuln-table-card), not tbody -- HTMX hx-swap=innerHTML targets tbody; outer-card pattern keeps component alive during HTMX swaps"
  - "Prototype-based class pattern (function VulnTableFilter + .prototype) -- consistent with AssetTableFilter and var self closure; broad browser compatibility"
  - "Default sort severity desc (P1 first); toggleSort three-state cycles back to severity/desc default"
  - "refreshRows() public method called by HTMX bridge after swap; re-scans live DOM and re-applies current filter/sort state"
  - "test_csp_alpine.py Alpine CDN tests updated to assert Alpine absent (removed in Plan 01) and components.js nonce present"
metrics:
  duration: "35min"
  completed: "2026-03-01"
  tasks_completed: 2
  files_modified: 4
requirements: [SRCH-05, SRCH-06, SRCH-07, SRCH-08, SRCH-09]
---

# Phase 12 Plan 02: VulnTableFilter Vanilla JS Class Summary

**One-liner:** VulnTableFilter vanilla JS class with search, severity/status filters, semantic sort, URL sync, and HTMX swap resilience replacing the previous Alpine.js vulnTable component.

## What Was Built

The vulnerability table on the asset detail page now has fully interactive filtering via a vanilla JS class (`VulnTableFilter`) following the same prototype-based pattern as `AssetTableFilter` from Plan 01.

### Key behaviors delivered

- **Text search:** Substring match on CVE ID and description (case-insensitive, debounced URL sync)
- **Severity filter:** Exact match dropdown (p1/p2/p3/p4) with semantic ordinal sort (P1=0, P2=1, P3=2, P4=3)
- **Status filter:** Exact match dropdown (open/in_review/remediated/deferred/closed) with semantic ordinal sort
- **Sort:** Three-state cycle (asc -> desc -> default=severity desc) on CVE ID, priority, CVSS, status columns
- **URL sync:** `history.replaceState()` mirrors state to query params; sharing URL reproduces filtered view; sort/dir omitted when state matches default (severity desc) to keep URLs clean
- **HTMX resilience:** `refreshRows()` called after `htmx:afterSwap` on `#vuln-table-body` re-scans live DOM so newly-added CVEs respect active filters
- **Checkbox coexistence:** Vanilla JS checkbox code already filters `cb.closest('tr').style.display !== 'none'`; VulnTableFilter does not own checkboxes

### Architecture: outer-card anchor pattern

The HTMX add-CVE form targets `#vuln-table-body` with `hx-swap="innerHTML"`. If VulnTableFilter owned the tbody, HTMX's DOM replacement would orphan the component's `this.rows` array (stale detached `<tr>` references). By anchoring the component on the outer card div (`id="vuln-table-card"`), the tbody swap happens inside the component's scope without destroying it. The `htmx:afterSwap` bridge then calls `refreshRows()` to re-read the updated DOM.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Rewrite asset_detail.html vuln card toolbar to vanilla HTML | b785b99 | web/templates/asset_detail.html |
| 2 | Add VulnTableFilter class, wire HTMX bridge, update tests | 7fd9141 | web/static/js/components.js, tests/test_search_filter.py, tests/test_csp_alpine.py |

## Verification Results

All plan verification checks passed:

- `python -m pytest tests/test_search_filter.py -x -q` -- 16 passed (both asset and vuln table tests)
- `python -m pytest tests/ -q` -- 207 passed, no regressions
- `grep -c 'function VulnTableFilter' web/static/js/components.js` -- 1
- `grep 'Alpine.data\|alpine:init\|_x_dataStack' web/static/js/components.js` -- 0 (zero functional Alpine code)
- `grep -c 'x-data\|x-ref\|x-show\|x-text' web/templates/asset_detail.html` -- 0
- `grep -c 'refreshRows' web/static/js/components.js` -- 7 (definition + bridge call + prototype methods)
- `grep 'cb.closest' web/templates/asset_detail.html` -- checkbox hidden-row filter confirmed

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed stale Alpine CDN assertions in test_csp_alpine.py**

- **Found during:** Task 2 (full test suite run)
- **Issue:** `test_alpine_cdn_in_layout` and `test_alpine_scripts_have_nonce` asserted `@alpinejs/csp` presence in HTML. Alpine was removed in Plan 01 (commit `65a719d`), so these tests were wrong -- the code is correct, the tests were outdated.
- **Fix:** Renamed `test_alpine_cdn_in_layout` to `test_no_alpine_cdn_in_layout` (now asserts Alpine is absent); renamed `test_alpine_scripts_have_nonce` to `test_components_js_has_nonce` (now checks `components.js` script tag has nonce); updated docstrings and file-level docstring to reflect vanilla JS architecture. Also updated `test_no_unsafe_eval_in_csp` docstring (removed Alpine reference).
- **Files modified:** tests/test_csp_alpine.py
- **Commit:** 7fd9141 (included in Task 2 commit)

## Self-Check: PASSED

All key files verified to exist. Both task commits verified in git log.
207 tests pass with no regressions. Zero Alpine functional code in components.js or asset_detail.html.
