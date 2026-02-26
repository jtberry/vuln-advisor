# Requirements: VulnAdvisor Solo Analyst Milestone

**Defined:** 2026-02-26
**Core Value:** A solo security analyst can open VulnAdvisor daily, see what needs attention, triage CVEs, track asset risk, and update status - all in one tool with no paid subscriptions.

## v1 Requirements

Requirements for the Solo Analyst milestone. Each maps to roadmap phases.

### Auth & Security

- [x] **AUTH-01**: Auth flow is reviewed end-to-end (setup -> login -> session -> logout -> expired session redirect)
- [x] **AUTH-02**: User sees clear session state in navigation (username, logout button) on every authenticated page
- [x] **AUTH-03**: First-run setup wizard creates admin account with clear guidance and error handling
- [x] **AUTH-04**: Expired session redirects to login with return URL, then back to original page after login
- [x] **AUTH-05**: API endpoints are reviewed for proper authentication enforcement (no unprotected routes)
- [x] **AUTH-06**: CSRF protection is applied to all Jinja2 form routes
- [x] **AUTH-07**: SECRET_KEY is surfaced as a required production setting (not random fallback)

### Tech Debt & Foundation

- [x] **DEBT-01**: Centralized pydantic-settings config replaces scattered os.getenv() calls
- [x] **DEBT-02**: N+1 query in dashboard API is replaced with single aggregate query
- [x] **DEBT-03**: SQLite WAL mode enabled for concurrent read safety
- [ ] **DEBT-04**: Test suite expanded to cover stores, routes, auth, and ingest

### Status Workflow

- [x] **STAT-01**: Existing status workflow features are audited and tested end-to-end
- [x] **STAT-02**: PATCH endpoint for asset and vulnerability updates works correctly
- [x] **STAT-03**: User can change vulnerability status from asset detail page (Open -> In Review -> Remediated -> Closed/Deferred)
- [x] **STAT-04**: End-to-end triage-to-remediation workflow is connected and usable in UI

### Dashboard & Charts

- [ ] **DASH-01**: Severity breakdown chart shows open vulns by priority (P1/P2/P3/P4) using Chart.js
- [ ] **DASH-02**: KEV highlights widget surfaces newly added KEV entries affecting tracked assets
- [ ] **DASH-03**: High-EPSS highlights widget surfaces vulns with EPSS > 0.5 on tracked assets
- [ ] **DASH-04**: Overdue SLA items are visually prominent on dashboard (not just a count)

### UI Polish

- [ ] **UIPL-01**: Navigation is consistent and usable across all pages
- [ ] **UIPL-02**: Empty states guide user to next action (first asset load, first ingest, etc.)
- [ ] **UIPL-03**: Dashboard is a usable daily landing page for a solo analyst

### Deployment

- [ ] **DEPL-01**: Application runs via docker-compose with Dockerfile, reverse proxy (Caddy), and TLS

## v2 Requirements

Deferred to future milestones. Tracked but not in current roadmap.

### Export & Reporting

- **EXPT-01**: User can export vulnerability data as CSV from asset detail and global views
- **EXPT-02**: CSV export sanitizes formula injection (values starting with =, +, -, @)

### Activity & Trends

- **ACTV-01**: Recent activity feed shows new CVE ingests, status changes, KEV additions
- **ACTV-02**: Trend line chart shows open vuln count over time

### Team Features (Milestone 2)

- **TEAM-01**: Multi-user access with role-based permissions
- **TEAM-02**: Shared dashboard views
- **TEAM-03**: Vulnerability assignment to team members

### Platform Features (Milestone 3)

- **PLAT-01**: Multi-tenancy with org_id enforcement
- **PLAT-02**: Jira/ServiceNow integration
- **PLAT-03**: PostgreSQL migration

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| PDF report generation | Heavy dependency (WeasyPrint/ReportLab), CSV covers reporting needs |
| Real-time push notifications / WebSockets | Solo analyst doesn't need push; page refresh sufficient |
| Custom dashboard widgets / drag-and-drop | One user doesn't need personalization; fixed layout serves solo use |
| SPA frontend rewrite | Jinja templates carry solo milestone; reassess at team milestone |
| Scheduled/automated scans | Requires task queue + workers; manual ingest is correct for SQLite deployment |
| AI/LLM triage summaries | Rule-based triage reason is already a differentiator; LLM adds cost and non-determinism |
| Mobile-responsive rewrite | Bootstrap responsive breakpoints are sufficient; dedicated mobile effort not worth it |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| AUTH-01 | Phase 1 | Complete |
| AUTH-02 | Phase 1 | Complete |
| AUTH-03 | Phase 1 | Complete |
| AUTH-04 | Phase 1 | Complete |
| AUTH-05 | Phase 1 | Complete |
| AUTH-06 | Phase 1 | Complete |
| AUTH-07 | Phase 1 | Complete |
| DEBT-01 | Phase 1 | Complete |
| DEBT-02 | Phase 2 | Complete |
| DEBT-03 | Phase 2 | Complete |
| STAT-01 | Phase 2 | Complete |
| STAT-02 | Phase 2 | Complete |
| DASH-01 | Phase 3 | Pending |
| DASH-02 | Phase 3 | Pending |
| DASH-03 | Phase 3 | Pending |
| DASH-04 | Phase 3 | Pending |
| STAT-03 | Phase 3 | Complete |
| STAT-04 | Phase 3 | Complete |
| UIPL-01 | Phase 4 | Pending |
| UIPL-02 | Phase 4 | Pending |
| UIPL-03 | Phase 4 | Pending |
| DEBT-04 | Phase 5 | Pending |
| DEPL-01 | Phase 6 | Pending |

**Coverage:**
- v1 requirements: 23 total
- Mapped to phases: 23
- Unmapped: 0

---
*Requirements defined: 2026-02-26*
*Last updated: 2026-02-26 after roadmap creation*
