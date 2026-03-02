---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: Searchable & Exportable
status: unknown
last_updated: "2026-03-02T00:32:52.142Z"
progress:
  total_phases: 12
  completed_phases: 11
  total_plans: 35
  completed_plans: 34
---

# VulnAdvisor - State

## Project Reference

See: .planning/PROJECT.md (updated 2026-02-27)

**Core value:** A solo security analyst can open VulnAdvisor each day, see what needs attention, triage new CVEs, understand which assets are most at risk, and export findings - all in one tool, with no paid subscriptions required.
**Current focus:** Phase 12 - Search, Filter, and Sort

## Current Position

Phase: 12 of 14 (Search, Filter, and Sort)
Plan: 3 of 3 completed
Status: Active
Last activity: 2026-03-02 - Phase 12 Plan 03 complete (three-state sort cycle bug fix via _sortCycleStage counter)

Progress: [##########] Plan 3/3 (Phase 12 COMPLETE)

## Performance Metrics

**Velocity:**
- Total plans completed: 2 (Phase 12)
- Average duration: 26min
- Total execution time: 53min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| - | - | - | - |

*Updated after each plan completion*
| Phase 11-foundation-alpine-setup P01 | 16 | 2 tasks | 6 files |
| Phase 11-foundation-alpine-setup P02 | 18min | 2 tasks | 8 files |
| Phase 12-search-filter-and-sort P01 | 18min | 2 tasks | 3 files |
| Phase 12-search-filter-and-sort P02 | 35min | 2 tasks | 4 files |
| Phase 12-search-filter-and-sort P01 | 25 | 2 tasks | 4 files |
| Phase 12-search-filter-and-sort P02 | 35min | 2 tasks | 4 files |
| Phase 12-search-filter-and-sort P03 | 15min | 1 tasks | 2 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- Hybrid JS framework: Alpine.js 3.15.8 via CDN (no build step); coexists with HTMX via strict DOM ownership split
- Clean v1.0 debt before new features: 8 audit items in Phase 11 before any interactive UI work
- Client-side filtering (no server pagination): document constraint at implementation point so it is not accidentally removed
- CSV export row cap: default 500 / max 2,000; validate against target environment before shipping
- PDF export deferred to v2: fpdf2 is pure Python but adds dependency; CSV covers all bulk-data needs for v1.1
- [Phase 11-foundation-alpine-setup]: Use Content-Security-Policy-Report-Only (not enforcing) -- report-only surfaces violations without breaking pages
- [Phase 11-foundation-alpine-setup]: csp_nonce_middleware registered last as @app.middleware so it becomes outermost wrapper (Starlette reverses order)
- [Phase 11-foundation-alpine-setup]: StaticFiles mount placed in asgi.py not api/main.py -- web layer concern preserving api/web separation
- [Phase 11-foundation-alpine-setup]: Route at /account/api-keys (not /api-keys) to group account pages under a common prefix for future middleware path targeting
- [Phase 11-foundation-alpine-setup]: get_settings() over os.environ.get() for NVD key: lru_cache allows test isolation via cache_clear()
- [Phase 12-search-filter-and-sort]: EnvironmentEnum = production/staging/development (not internal); ExposureEnum = internet/internal/isolated -- plan's filter dropdown options corrected at execution
- [Phase 12-search-filter-and-sort]: data-name mirrors data-hostname (no separate display-name field on assets); data-vuln-count hardcoded 0 for now
- [Phase 12-search-filter-and-sort]: URL sync omits sort/dir params when state matches default (hostname A-Z) to keep URLs clean
- [Phase 12-search-filter-and-sort P02]: x-data="vulnTable" on outer card div (not tbody) -- HTMX hx-swap=innerHTML targets tbody; outer-card pattern keeps Alpine alive during HTMX swaps
- [Phase 12-search-filter-and-sort P02]: Default sort severity desc (P1 first); ordinal P1=0, dir=-1 puts lower-ordinal rows first
- [Phase 12-search-filter-and-sort P02]: cache.get.return_value=None in test fixture to prevent MagicMock SQLAlchemy bind failure
- [Phase 12-search-filter-and-sort]: Alpine CDN fully removed in Plan 01 rewrite: vanilla JS AssetTableFilter is 100% CSP-safe without eval/new Function()
- [Phase 12-search-filter-and-sort]: Prototype-based class pattern used for AssetTableFilter (function + .prototype) -- consistent with var self closure pattern and broad browser compatibility
- [Phase 12-search-filter-and-sort]: VulnTableFilter anchors on id=vuln-table-card (outer card div) not tbody -- HTMX hx-swap=innerHTML targets tbody; outer-card pattern keeps component alive during HTMX swaps
- [Phase 12-search-filter-and-sort]: Alpine CDN fully removed (Plan 01); test_csp_alpine.py Alpine assertions updated to reflect vanilla JS architecture (no Alpine CDN, components.js nonce check)
- [Phase 12-search-filter-and-sort]: Explicit _sortCycleStage counter (0=default, 1=asc, 2=desc) instead of inferring cycle from (col, dir) pair -- resolves ambiguity where reset state equals initial state on default column

### Pending Todos

None yet.

### Blockers/Concerns

- API key last_used_at: deferred to v2; create a GitHub issue during Phase 13 so the "last used" display gap is tracked

## Session Continuity

Last session: 2026-03-02
Stopped at: Completed 12-03-PLAN.md -- three-state sort cycle bug fix in AssetTableFilter and VulnTableFilter (Phase 12 Plan 03, Phase 12 COMPLETE)
Resume file: None
