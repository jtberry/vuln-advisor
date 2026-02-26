# VulnAdvisor

## What This Is

An open-source CVE triage and risk management tool for vulnerability management teams. VulnAdvisor fetches data from free public sources (NVD, CISA KEV, EPSS, PoC-in-GitHub), delivers plain-language triage decisions, and tracks organizational risk through an asset inventory with vulnerability mapping. Accessible via CLI, REST API, or web UI.

## Core Value

A solo security analyst can open VulnAdvisor each day, see what needs attention, triage new CVEs, understand which assets are most at risk, and export findings - all in one tool, with no paid subscriptions required.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

- ✓ CLI single and bulk CVE triage with prioritized output - v0.1.0
- ✓ CWE-based compensating controls and Sigma rule links - v0.1.0
- ✓ SQLite TTL cache for API call deduplication - v0.1.0
- ✓ NVD API key support for higher rate limits - walk phase
- ✓ Exposure flag (internet/internal/isolated) adjusting triage priority - walk phase
- ✓ REST API layer (FastAPI) wrapping core triage engine - walk phase
- ✓ Asset CMDB with create, list, and vulnerability linking - walk phase
- ✓ Scanner ingest (Trivy, Grype, Nessus, CSV) - walk phase
- ✓ Authentication system (JWT, bcrypt, OAuth, API keys) - walk phase
- ✓ First-run setup wizard for initial admin account - walk phase
- ✓ Rate limiting on API endpoints - walk phase
- ✓ Basic web UI with server-rendered templates - walk phase
- ✓ Core pipeline extracted as pure function (process_cve) - walk phase

### Active

<!-- Current scope. Building toward these. -->

- [ ] Dashboard with risk summary (open vulns by severity, P1/P2/P3 counts, trends)
- [ ] Dashboard with asset health view (most exposed assets, critical assets with open vulns)
- [ ] Dashboard with recent activity (newly ingested CVEs, remediations, status changes)
- [ ] Dashboard with EPSS/KEV highlights (trending exploitation probability, new KEV entries)
- [ ] Interactive charts and visualizations (JS charting library in templates)
- [ ] CSV export of triage results and asset vulnerability data
- [ ] Auth UX overhaul (end-to-end flow: setup, login, session behavior, logged-in vs. not states)
- [ ] Polished web UI suitable for daily use (navigation, layout, usability)
- [ ] End-to-end triage-to-remediation workflow connected in UI
- [ ] PATCH endpoint for asset updates
- [ ] Centralized pydantic-settings config (replace scattered env reads)
- [ ] Expanded test suite (stores, routes, auth, ingest)

### Out of Scope

<!-- Explicit boundaries. Includes reasoning to prevent re-adding. -->

- Multi-user team features (shared dashboards, team roles) - deferred to Milestone 2
- Multi-tenancy / org_id enforcement - deferred to Milestone 3
- Jira/ServiceNow integrations - deferred to Milestone 3
- PostgreSQL migration - run-phase prep, not needed for solo analyst milestone
- Full async SQLAlchemy - run-phase optimization
- Task queue (ARQ) for background processing - run-phase
- SPA frontend rewrite (React/Vue) - reassess at team milestone; Jinja templates carry solo analyst
- Real-time notifications - not needed for solo use
- Mobile app - web-first

## Context

VulnAdvisor started as a CLI-only crawl-phase tool (v0.1.0) and has grown organically through the walk phase. Features were added as they made sense in the moment, but without a structured roadmap the project lacks clear release boundaries. This re-initialization establishes milestone-based planning to provide that clarity.

The codebase is healthy architecturally - clean layer separation, pure core pipeline, no cross-layer imports. The main gaps are on the product/experience side: the engine works well but the UI, dashboard, charts, and auth flow need significant work to make it a usable daily tool.

Three natural milestones have been identified:
1. **Solo Analyst** (current) - one person, full daily workflow
2. **Small Team** (future) - shared dashboard, multi-user auth
3. **Org Platform** (future) - multi-tenancy, integrations, RBAC

Tech debt will be addressed alongside new features, not as a separate phase.

Existing GitHub issues #14-#52 track prior walk-phase work. This roadmap supersedes the previous ad-hoc issue tracking for planning purposes.

## Constraints

- **Python version**: 3.9 minimum - no syntax or stdlib features requiring 3.10+
- **UI approach**: Jinja2 server-rendered templates through this milestone - no SPA/build step
- **Charts**: JavaScript library (Chart.js or similar) embedded in templates
- **Database**: SQLite for this milestone - keeps deployment simple for solo use
- **Auth stack**: bcrypt (direct, not passlib), python-jose, Authlib - already established
- **No paid dependencies**: All data sources must remain free (NVD, CISA KEV, EPSS, PoC-in-GitHub)

## Key Decisions

<!-- Decisions that constrain future work. Add throughout project lifecycle. -->

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Keep Jinja templates for solo milestone | No need for SPA complexity; reassess at team milestone | -- Pending |
| JS charting library for visualizations | Interactive charts (tooltips, zoom) needed; drops into templates easily | -- Pending |
| Interleave tech debt with features | Keeps momentum while building on solid ground; test as we build | -- Pending |
| Auth UX overhaul early in milestone | Every feature sits behind auth; broken flow blocks everything | -- Pending |
| Milestone-based releases | Organic feature addition lacked clear "done" boundaries | -- Pending |

---
*Last updated: 2026-02-26 after initialization*
