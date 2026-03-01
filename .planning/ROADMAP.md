# Roadmap: VulnAdvisor

## Milestones

- ✅ **v1.0 Solo Analyst** - Phases 01-10 (shipped 2026-02-27)
- 🚧 **v1.1 Searchable & Exportable** - Phases 11-14 (in progress)

## Phases

<details>
<summary>✅ v1.0 Solo Analyst (Phases 01-10) - SHIPPED 2026-02-27</summary>

29/29 requirements satisfied. CLI, REST API, web UI, asset CMDB, scanner ingest, full auth system, dashboard with Chart.js, Docker deployment, 176 tests, security audit, MkDocs docs.

</details>

### 🚧 v1.1 Searchable & Exportable (In Progress)

**Milestone Goal:** Make existing data explorable and extractable. Clean v1.0 debt, wire Alpine.js for interactivity, add search/filter/sort on asset and CVE tables, fix API key management page, and deliver CSV export.

- [x] **Phase 11: Foundation & Alpine Setup** - Clear v1.0 audit debt and wire Alpine.js globally (completed 2026-02-27)
- [x] **Phase 12: Search, Filter, and Sort** - Interactive search and filter on asset and vulnerability tables (completed 2026-03-01)
- [ ] **Phase 13: API Key Management** - Working web page to list, create, and revoke API keys
- [ ] **Phase 14: CSV Export** - Downloadable filtered asset and vulnerability data

## Phase Details

### Phase 11: Foundation & Alpine Setup
**Goal**: The codebase is audit-clean and Alpine.js is globally available so all v1.1 interactive features can be built on a solid, debt-free base
**Depends on**: Nothing (first v1.1 phase)
**Requirements**: DEBT-05, DEBT-06, DEBT-07, DEBT-08, DEBT-09, DEBT-11, DEBT-12, FRNT-01, FRNT-02, FRNT-03
**Success Criteria** (what must be TRUE):
  1. The /api-keys nav link navigates to a real page instead of a 404
  2. Alpine.js is loaded on every page with no console errors and no conflicts with existing HTMX interactions
  3. The NVD API key is read from centralized Settings; no bare os.environ.get() calls remain for it
  4. The CSP header uses nonce-based policy with no unsafe-inline in layout.html
  5. The reusable Alpine table component pattern is documented and tested in at least one template
**Plans**: 2 plans
- [ ] 11-01-PLAN.md -- CSP nonce middleware and Alpine.js global setup
- [ ] 11-02-PLAN.md -- Tech debt cleanup (DEBT-05, DEBT-06, DEBT-07, DEBT-08, DEBT-09, DEBT-12)

### Phase 12: Search, Filter, and Sort
**Goal**: A user can find any asset or vulnerability in seconds using text search, dropdowns, and column sort - without leaving the page or waiting for a full reload
**Depends on**: Phase 11
**Requirements**: SRCH-01, SRCH-02, SRCH-03, SRCH-04, SRCH-05, SRCH-06, SRCH-07, SRCH-08, SRCH-09
**Success Criteria** (what must be TRUE):
  1. User can type into a search box on the assets page and the table filters to matching rows by name, hostname, or IP instantly
  2. User can select criticality and environment dropdowns to filter the asset table, combining filters without a page reload
  3. User can click any column header on the asset table to sort ascending or descending
  4. User can search and filter the vulnerability table on an asset detail page by CVE ID, description, severity, and status
  5. Sharing the page URL with active filters reproduces the same filtered view in a new browser tab
**Plans**: 2 plans
- [ ] 12-01-PLAN.md -- Asset table search, filter, sort, and URL sync (SRCH-01 through SRCH-04, SRCH-09)
- [ ] 12-02-PLAN.md -- Vulnerability table search, filter, sort, HTMX resilience, and checkbox fix (SRCH-05 through SRCH-09)

### Phase 13: API Key Management
**Goal**: Users can manage their API keys from the web UI without using the REST API directly, and the dead nav link is permanently fixed
**Depends on**: Phase 11
**Requirements**: AKEY-01, AKEY-02, AKEY-03
**Success Criteria** (what must be TRUE):
  1. User can navigate to /account/api-keys and see a list of their existing API keys with name, key prefix, and creation date
  2. User can create a new API key, see the full key value exactly once in the UI, and is warned it will not be shown again
  3. User can revoke any API key from the list and it is immediately rejected by the API
**Plans**: TBD

### Phase 14: CSV Export
**Goal**: Users can download a CSV of the assets or vulnerabilities they are currently viewing, safe for immediate use in spreadsheets and audit tools
**Depends on**: Phase 12
**Requirements**: EXPT-01, EXPT-02, EXPT-03, EXPT-04
**Success Criteria** (what must be TRUE):
  1. User can click an export button on the assets page and download a CSV that matches the current filter state
  2. User can click an export button on an asset detail page and download a CSV of that asset's vulnerabilities
  3. Opening the exported CSV in Excel does not execute any formula injections from hostname, owner, or CVE description fields
  4. The export endpoint enforces a row cap and rate limit, returning a 429 after excessive requests rather than blocking the server
**Plans**: TBD

## Progress

**Execution Order:** Phases execute in numeric order: 11 → 12 → 13 → 14
Note: Phases 12 and 13 are independent of each other and can be implemented in parallel if desired.

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 11. Foundation & Alpine Setup | 2/2 | Complete    | 2026-02-27 | - |
| 12. Search, Filter, and Sort | 2/2 | Complete   | 2026-03-01 | - |
| 13. API Key Management | v1.1 | 0/? | Not started | - |
| 14. CSV Export | v1.1 | 0/? | Not started | - |
