# Codebase Structure

**Analysis Date:** 2026-02-25

## Directory Layout

```
vuln-advisor/
├── main.py                    # CLI entry point (argparse, orchestration)
├── asgi.py                    # ASGI assembly (joins api/ and web/)
├── core/                      # Pure engine (fetching, enrichment, formatting)
│   ├── __init__.py
│   ├── pipeline.py            # process_cve() + process_cves() (no side effects)
│   ├── fetcher.py             # All HTTP calls (NVD, CISA KEV, EPSS, PoC-GitHub)
│   ├── enricher.py            # CVSS parsing, CWE mapping, triage logic, EnrichedCVE
│   ├── formatter.py           # Terminal, JSON, CSV, HTML, Markdown output
│   └── models.py              # Dataclasses only (EnrichedCVE, CVSSDetails, etc.)
├── cache/                     # Shared SQLite cache (CLI + API)
│   ├── __init__.py
│   ├── store.py               # CVECache class (get/set/purge_expired with TTL)
│   └── vulnadvisor.db         # SQLite database (24h TTL)
├── cmdb/                      # Asset/vulnerability persistence
│   ├── __init__.py
│   ├── models.py              # Dataclasses (Asset, AssetVulnerability, RemediationRecord)
│   ├── store.py               # CMDBStore with SQLAlchemy Core (assets, vulns, audit trail)
│   ├── ingest.py              # Scanner parsers (Trivy, Grype, Nessus, CSV)
│   └── vulnadvisor_cmdb.db    # SQLite CMDB (created on first write)
├── api/                       # REST API layer (FastAPI)
│   ├── __init__.py
│   ├── main.py                # FastAPI app, lifespan, middleware, /health
│   ├── models.py              # Pydantic request/response contracts
│   ├── limiter.py             # slowapi rate limiter config
│   └── routes/
│       ├── __init__.py
│       └── v1/
│           ├── __init__.py
│           ├── cve.py         # GET /cve/{id}, POST /cve/bulk, GET /cve/summary
│           ├── assets.py      # CRUD /assets, POST /ingest, GET /dashboard
│           ├── auth.py        # POST /login, /logout, /api-keys, admin /users
│           └── dashboard.py   # GET /dashboard (risk metrics)
├── auth/                      # Authentication & identity
│   ├── __init__.py
│   ├── models.py              # User, ApiKey dataclasses
│   ├── tokens.py              # JWT encode/decode, bcrypt hash/verify, API key HMAC-SHA256
│   ├── store.py               # UserStore with SQLAlchemy Core
│   ├── oauth.py               # Authlib OAuth registry (GitHub, Google, OIDC)
│   ├── dependencies.py        # FastAPI Depends helpers (get_current_user, require_admin)
│   └── vulnadvisor_auth.db    # SQLite auth database
├── web/                       # Web UI (Jinja2 templates)
│   ├── __init__.py
│   ├── routes.py              # GET /, /cve, /assets, /login, /logout, /setup, /ingest
│   └── templates/
│       ├── layout.html        # Base template (nav, footer, Jinja2 globals)
│       ├── login.html         # Password + OAuth buttons
│       ├── setup.html         # First-run admin account creation
│       ├── cve.html           # Research page (single/bulk lookup forms)
│       ├── cve_card.html      # HTMX CVE result card
│       ├── cve_table.html     # Bulk results table rows
│       ├── dashboard.html     # Risk dashboard (auth required)
│       ├── assets.html        # Asset list/detail
│       ├── assets_form.html   # Create/edit asset form
│       ├── ingest.html        # Scanner file upload form
│       └── 404.html           # Error template
├── tests/                     # Test suite
│   ├── __init__.py
│   ├── test_enricher.py       # 80 unit tests for core/enricher.py (100% coverage)
│   └── test_pipeline.py       # Integration tests for process_cve()
├── docs/                      # Reference documentation
│   └── architecture.md        # Full architecture guide with patterns and principles
├── .github/                   # GitHub metadata
│   └── workflows/             # (CI/CD not configured yet)
├── requirements.txt           # Core dependencies (requests)
├── requirements-api.txt       # API additions (fastapi, sqlalchemy, authlib, etc.)
├── requirements-dev.txt       # Dev dependencies (pytest, pytest-cov, black, ruff, etc.)
├── pyproject.toml             # Black, Ruff, Pytest configuration
├── Makefile                   # Development tasks (check, test, run-api, etc.)
├── CLAUDE.md                  # Contributor guide (branch strategy, standards, etc.)
├── README.md                  # User documentation
└── .pre-commit-config.yaml    # Git hooks (black, isort, ruff, bandit, pip-audit)
```

## Directory Purposes

**`core/`:**
- Purpose: Pure business logic for CVE triage — zero dependencies on database, HTTP framework, or external state
- Contains: Fetch-cache-enrich pipeline, CVSS parsing, CWE mapping, triage priority rules, output formatting
- Key files: `pipeline.py` (entry point for both CLI and API), `enricher.py` (core decision logic), `models.py` (EnrichedCVE dataclass)
- Commit-to: Always (source code)

**`cache/`:**
- Purpose: Lightweight TTL-based cache to reduce redundant API calls
- Contains: CVECache class with parameterized SQLite queries, 24-hour default TTL
- Key files: `store.py` (cache interface), `vulnadvisor.db` (auto-created on first run)
- Commit-to: `store.py` and schema DDL only; database file is ephemeral

**`cmdb/`:**
- Purpose: Persistence and enrichment context for tracked assets and their vulnerabilities
- Contains: Asset/AssetVulnerability dataclasses, SQLAlchemy Core schema, scanner parsers (Trivy, Grype, Nessus, CSV), SLA deadline logic
- Key files: `models.py` (domain dataclasses), `store.py` (Repository pattern with CMDBStore), `ingest.py` (scanner parser dispatchers)
- Commit-to: Source code only; database is user-generated

**`api/`:**
- Purpose: REST API layer that exposes the core engine over HTTP with rate limiting, auth, and structured responses
- Contains: FastAPI app, route handlers, Pydantic validation models, slowapi rate limiter, middleware stack
- Key files: `main.py` (app entry point, lifespan, middleware), `routes/v1/cve.py` (CVE endpoints), `models.py` (Pydantic contracts)
- Commit-to: All source files

**`auth/`:**
- Purpose: Authentication, identity, and credential management (JWT, API keys, OAuth2)
- Contains: User and ApiKey dataclasses, JWT token generation/validation, bcrypt password hashing, Authlib OAuth registry, FastAPI dependency injection helpers
- Key files: `tokens.py` (JWT and API key logic), `store.py` (user persistence), `dependencies.py` (get_current_user, require_admin), `oauth.py` (OAuth configuration)
- Commit-to: All source files

**`web/`:**
- Purpose: Server-rendered HTML UI for browser clients
- Contains: Route handlers for Jinja2 template rendering, form submission handling, OAuth callback routes, HTMX fragments for partial updates
- Key files: `routes.py` (all HTTP route handlers), `templates/layout.html` (base template with nav/footer), `templates/cve.html` (research page)
- Commit-to: All source files

**`tests/`:**
- Purpose: Unit and integration test suite
- Contains: `test_enricher.py` (80 unit tests with 100% line coverage for core/enricher.py), `test_pipeline.py` (integration tests for process_cve)
- Coverage scope: `--cov=core.enricher` (future: expand to include routes and stores)
- Commit-to: All test files

**`docs/`:**
- Purpose: Architecture and design decision reference
- Contains: `architecture.md` (module map, patterns, principles, design decisions with teaching focus)
- Commit-to: Yes, this is part of the codebase

## Key File Locations

**Entry Points:**
- `main.py`: CLI entry point — run with `python main.py CVE-ID` or `python main.py --file cves.txt`
- `asgi.py`: ASGI app assembly — run with `uvicorn asgi:app --reload` (FastAPI + web router)
- `api/main.py`: FastAPI app instance (imported by asgi.py)

**Configuration:**
- `pyproject.toml`: Black line length, Ruff rules (B008 ignored for FastAPI Depends), Pytest coverage
- `.pre-commit-config.yaml`: Git hooks (black, isort, ruff, bandit, pip-audit)
- `Makefile`: Development commands (make check, make test, make run-api, etc.)
- `.env` / `.env.example`: Environment variables (NVD_API_KEY optional, DATABASE_URL for PostgreSQL migration)

**Core Logic:**
- `core/pipeline.py`: process_cve() and process_cves() — the heart of the fetch-cache-enrich pipeline
- `core/enricher.py`: _triage_priority() and enrich() — CVE enrichment and priority calculation
- `core/fetcher.py`: fetch_nvd(), fetch_epss(), fetch_poc(), fetch_kev() — all external HTTP calls
- `core/models.py`: EnrichedCVE, CVSSDetails, PoCInfo, RemediationStep — canonical data structures

**Testing:**
- `tests/test_enricher.py`: 80 unit tests for core/enricher.py (pure function tests with no mocks)
- `tests/test_pipeline.py`: Integration tests for process_cve() with cache and KEV set
- Run with: `make test` or `pytest tests/ --cov=core.enricher`

**Database Schemas:**
- `cache/store.py`: CVE cache schema (cve_id, data, cached_at) — single table, 24h TTL
- `cmdb/store.py`: Assets, AssetVulnerabilities, RemediationRecords tables — SQLAlchemy Core DDL
- `auth/store.py`: Users, ApiKeys tables — SQLAlchemy Core DDL

**API Routes:**
- `api/routes/v1/cve.py`: GET /cve/summary, POST /cve/bulk, GET /cve/{cve_id}
- `api/routes/v1/assets.py`: GET/POST /assets, GET /assets/{id}, POST .../vulnerabilities, PATCH .../status
- `api/routes/v1/auth.py`: POST /login, GET /me, GET /providers, CRUD /api-keys, admin /users
- `api/routes/v1/dashboard.py`: GET /dashboard (risk metrics)

**Web Routes:**
- `web/routes.py`: GET /, /cve, /assets, /login, /logout, /setup, /ingest (all browser-facing)
- `web/templates/layout.html`: Base Jinja2 template (nav, footer, try_get_current_user global)
- `web/templates/login.html`: Bootstrap dark form with password + OAuth buttons

## Naming Conventions

**Files:**
- `snake_case.py` for all Python modules (PEP 8)
- `route_handlers.py` in api/routes/v1/ (descriptive, lowercase)
- `data.html` for Jinja2 templates (lowercase, descriptive)
- `vulnadvisor.db` for SQLite files (lowercase, no caps)

**Directories:**
- Lowercase packages matching module names: `api/`, `core/`, `cache/`, `cmdb/`, `auth/`, `web/`, `tests/`, `docs/`
- Nested routes under `api/routes/v1/` for versioning

**Classes & Functions:**
- PascalCase for classes: `CVECache`, `EnrichedCVE`, `CMDBStore`, `UserStore`, `BulkRequest`
- snake_case for functions: `process_cve()`, `fetch_nvd()`, `enrich()`, `get_current_user()`
- `_leading_underscore` for private functions/module-level constants: `_triage_priority()`, `_session`, `_DDL`

**Variables:**
- snake_case for all variables: `cve_id`, `kev_set`, `cache_key`
- ALL_CAPS for module-level constants: `CVE_PATTERN`, `NVD_API`, `_DEFAULT_TTL`, `_SLA_DAYS`

**Database:**
- snake_case table names: `assets`, `asset_vulnerabilities`, `remediation_records`
- snake_case column names: `cve_id`, `created_at`, `effective_priority`

## Where to Add New Code

**New Core Logic (CVE processing):**
- Primary code: `core/enricher.py` (if pure triage logic) or `core/fetcher.py` (if new HTTP source)
- Models: Add dataclass to `core/models.py`
- Tests: Add unit tests to `tests/test_enricher.py`

**New API Route:**
- Implementation: Create `api/routes/v1/{resource}.py` (or extend existing file)
- Models: Add Pydantic request/response classes to `api/models.py`
- Register: Import in `api/main.py` and add `app.include_router(router, prefix="/api/v1")`
- Tests: Create `tests/test_routes_{resource}.py` with mock dependencies

**New Web Route:**
- Implementation: Add handler to `web/routes.py`
- Template: Create `web/templates/{page}.html` or `{fragment}.html` for HTMX
- Auth: Use `@_require_auth(request)` helper if protected; check `current_user = try_get_current_user(request)` in template
- Tests: Create `tests/test_web_{page}.py` with mocked stores

**New Asset/CMDB Feature:**
- Models: Add dataclass to `cmdb/models.py` (zero logic)
- Persistence: Add SQLAlchemy Table to `cmdb/store.py` (SQL, Repository pattern)
- Routes: Add endpoints to `api/routes/v1/assets.py` or `web/routes.py`
- Tests: Create `tests/test_cmdb_*.py`

**New Auth Method:**
- Logic: Implement in `auth/tokens.py` (token generation) or `auth/oauth.py` (provider config)
- Dependency: Add to `auth/dependencies.py::try_get_current_user()` priority list
- Routes: Add endpoint to `api/routes/v1/auth.py`
- Tests: Create `tests/test_auth_*.py`

**Shared Utilities:**
- Location: `core/` (if pure logic), `cache/` (if caching), `cmdb/` (if persistence)
- Pattern: Pure functions in core/; Repository pattern in cmdb/; simple interface for cache/

## Special Directories

**`.planning/codebase/`:**
- Purpose: Generated GSD codebase analysis documents (ARCHITECTURE.md, STRUCTURE.md, etc.)
- Generated: Yes (by /gsd:map-codebase)
- Committed: Yes (for reference across sessions)

**`.claude/worktrees/`:**
- Purpose: Isolated git worktrees for parallel subagent work (clone branches safely)
- Generated: Yes (by /gsd:execute-phase with isolation: worktree)
- Committed: No (excluded in .gitignore, auto-cleanup)

**`tests/`:**
- Purpose: Test suite with unit and integration tests
- Generated: No (manually written)
- Committed: Yes (all test files)

**`.pytest_cache/`:**
- Purpose: Pytest test result cache
- Generated: Yes (by pytest on first run)
- Committed: No (excluded in .gitignore)

**`venv/`:**
- Purpose: Python virtual environment (dependencies)
- Generated: Yes (by `python -m venv venv`)
- Committed: No (excluded in .gitignore)

**`__pycache__/`:**
- Purpose: Python bytecode cache
- Generated: Yes (by Python interpreter)
- Committed: No (excluded in .gitignore)

---

*Structure analysis: 2026-02-25*
