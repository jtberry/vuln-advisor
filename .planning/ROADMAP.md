# Roadmap: VulnAdvisor - Solo Analyst Milestone

## Overview

This milestone transforms VulnAdvisor from a functional walk-phase prototype into a reliable daily driver for a solo security analyst. The engine is solid. The gaps are on the experience side: auth UX that users can trust, a data layer that won't slow down under chart load, a dashboard that surfaces what matters, and UI polish that makes daily use feel natural. Each phase delivers a coherent capability that the next phase builds on.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Auth & Foundation** - Harden auth UX end-to-end and centralize config so every downstream feature has a stable, trustworthy base (completed 2026-02-26)
- [x] **Phase 2: Data Layer** - Fix N+1 queries and enable WAL mode, then wire up the PATCH endpoint and audit status workflow backend (completed 2026-02-26)
- [ ] **Phase 3: Dashboard & Charts** - Surface risk data visually and connect status workflow to the UI
- [ ] **Phase 4: UI Polish** - Make the tool feel complete and usable as a daily landing page
- [ ] **Phase 5: Test Coverage** - Formalize test coverage across all routes, stores, auth, and ingest
- [ ] **Phase 6: Containerization** - Dockerfile, docker-compose, and reverse proxy for deployment

## Phase Details

### Phase 1: Auth & Foundation
**Goal**: Auth UX is reliable and trustworthy; configuration is centralized so every subsequent phase builds on a stable base
**Depends on**: Nothing (first phase)
**Requirements**: AUTH-01, AUTH-02, AUTH-03, AUTH-04, AUTH-05, AUTH-06, AUTH-07, DEBT-01
**Success Criteria** (what must be TRUE):
  1. User can complete the full auth flow (setup -> login -> session -> logout -> expired session) without encountering broken states or confusing behavior
  2. Every authenticated page shows the logged-in username and a working logout button in the navigation
  3. When a session expires, the user is redirected to login with a `?next=` return URL and lands back on the original page after logging in
  4. All Jinja2 form routes have CSRF protection applied and no mutating action accepts a request without a valid token
  5. SECRET_KEY is a required setting that surfaces a clear error at startup when not configured; no random fallback in production
**Plans**: 8 total (01-01 through 01-08)

Plans:
- [x] 01-01-PLAN.md -- Centralized config and SECRET_KEY validation
- [x] 01-02-PLAN.md -- CSRF protection and logout flow
- [x] 01-03-PLAN.md -- Navigation and layout updates
- [x] 01-04-PLAN.md -- Registration and setup wizard
- [x] 01-05-PLAN.md -- Session expiry modal and per-user duration
- [x] 01-06-PLAN.md -- Settings pages, app_settings, auth audit
- [ ] 01-07-PLAN.md -- Gap closure: /dashboard redirect and /assets list page
- [ ] 01-08-PLAN.md -- Gap closure: session expiry modal detection fixes

### Phase 2: Data Layer
**Goal**: The data layer is query-efficient and write-safe; the status workflow backend is audited and the PATCH endpoint works correctly
**Depends on**: Phase 1
**Requirements**: DEBT-02, DEBT-03, STAT-01, STAT-02
**Success Criteria** (what must be TRUE):
  1. Dashboard API responds with a single aggregate query per request - no per-asset query loops visible in SQL logs
  2. SQLite WAL mode is enabled on all stores; concurrent reads during an ingest do not cause locking errors
  3. PATCH endpoint for asset and vulnerability status updates returns correct responses and persists state correctly
  4. Status workflow backend (open -> in review -> remediated -> closed/deferred) is confirmed working end-to-end via direct API calls
**Plans**: 2 total (02-01 through 02-02)

Plans:
- [ ] 02-01-PLAN.md -- WAL mode on all stores + N+1 aggregate query replacement
- [ ] 02-02-PLAN.md -- Status workflow rename, regression detection, typed PATCH response

### Phase 3: Dashboard & Charts
**Goal**: The dashboard is a functional risk summary page with charts, KEV/EPSS highlights, and inline status updates
**Depends on**: Phase 2
**Requirements**: DASH-01, DASH-02, DASH-03, DASH-04, STAT-03, STAT-04
**Success Criteria** (what must be TRUE):
  1. Dashboard shows a severity breakdown chart (P1/P2/P3/P4 doughnut using Chart.js) populated from live CMDB data
  2. Dashboard surfaces KEV entries affecting tracked assets and vulnerabilities with EPSS > 0.5 as distinct highlighted widgets
  3. Overdue SLA items are visually prominent on the dashboard (not buried in a count; shown as a list or badge with asset names)
  4. User can change a vulnerability status from the asset detail page without leaving the page, and the change persists on refresh
  5. Triage-to-remediation workflow is completable end-to-end in the UI: ingest -> view on dashboard -> open asset -> update status
**Plans**: 3 total (03-01 through 03-03)

Plans:
- [ ] 03-01-PLAN.md -- SLA defaults update, configurable SLA settings, CMDB overdue/threat intel queries
- [ ] 03-02-PLAN.md -- Dashboard chart, KEV stat card, threat intel section, overdue SLA list
- [x] 03-03-PLAN.md -- Asset detail status modal, optimistic UI, bulk status change

### Phase 4: UI Polish
**Goal**: Navigation, empty states, and overall layout are consistent and usable enough to make daily use feel natural
**Depends on**: Phase 3
**Requirements**: UIPL-01, UIPL-02, UIPL-03
**Success Criteria** (what must be TRUE):
  1. Navigation is consistent across all pages - same structure, active state indicators, and session display on every authenticated page
  2. Every major empty state (no assets loaded, no vulns ingested, no KEV matches) shows a clear next-action prompt rather than a blank or error
  3. A solo analyst can open the dashboard as their first action each day and immediately see what needs attention without navigating elsewhere
**Plans**: TBD

### Phase 5: Test Coverage
**Goal**: Routes, stores, auth flow, and ingest parsers have automated test coverage; regressions on critical safety features are caught before merge
**Depends on**: Phase 4
**Requirements**: DEBT-04
**Success Criteria** (what must be TRUE):
  1. Test suite covers the aggregate dashboard store methods added in Phase 2 with assertions on query correctness
  2. Auth redirect chain (login -> session -> expiry -> redirect -> return) is tested with an automated test that fails if the redirect loop regresses
  3. CSV formula injection is covered by a regression test that asserts sanitized output for cells starting with `=`, `+`, `-`, `@`
  4. All new API routes added this milestone have at least one happy-path and one auth-failure test
**Plans**: TBD

### Phase 6: Containerization
**Goal**: VulnAdvisor can be deployed as a containerized application with TLS and production-ready configuration
**Depends on**: Phase 5
**Requirements**: DEPL-01
**Success Criteria** (what must be TRUE):
  1. `docker-compose up` starts the application with all services configured
  2. Reverse proxy (Caddy) handles TLS termination
  3. Environment variables and SECRET_KEY are configured via docker-compose env
  4. Health check endpoint confirms application is running
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5 -> 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Auth & Foundation | 8/8 | Complete   | 2026-02-26 |
| 2. Data Layer | 2/2 | Complete   | 2026-02-26 |
| 3. Dashboard & Charts | 3/4 | In Progress|  |
| 4. UI Polish | 0/TBD | Not started | - |
| 5. Test Coverage | 0/TBD | Not started | - |
| 6. Containerization | 0/TBD | Not started | - |
