# Architecture

**Analysis Date:** 2026-02-25

## Pattern Overview

**Overall:** Layered Open-Core Architecture with Clean Boundaries

**Key Characteristics:**
- **Separation of Concerns:** Each module has a single responsibility; dependencies flow inward toward the core
- **Pure Functions:** Core pipeline contains no side effects, making it reusable across CLI and API contexts
- **Multi-Consumer Core:** Same business logic (`core/pipeline.py`, `core/enricher.py`) powers both CLI and REST API without duplication
- **Independent Vertical Layers:** `api/` and `web/` never import from each other; both import from `core/`, `cache/`, `cmdb/`, `auth/`

## Layers

**Core Engine (`core/`):**
- Purpose: Pure data fetching, enrichment, and formatting logic for CVE triage
- Location: `core/pipeline.py`, `core/fetcher.py`, `core/enricher.py`, `core/formatter.py`, `core/models.py`
- Contains: Fetch-cache-enrich pipeline, CVSS parsing, CWE mapping, triage decision logic, output formatting
- Depends on: Nothing (except Python stdlib and requests)
- Used by: `main.py` (CLI), `api/routes/v1/cve.py` (REST API), `web/routes.py` (Web UI)

**Cache Layer (`cache/`):**
- Purpose: SQLite-backed TTL cache shared by CLI and API to avoid redundant API calls
- Location: `cache/store.py`
- Contains: CVECache class with get/set/purge_expired methods; 24-hour default TTL
- Depends on: Nothing except stdlib
- Used by: `core/pipeline.py`, `api/main.py` (lifespan), CLI via `main.py`

**Asset/CMDB Layer (`cmdb/`):**
- Purpose: Persistence and enrichment context for tracked infrastructure assets and their vulnerabilities
- Location: `cmdb/models.py`, `cmdb/store.py`, `cmdb/ingest.py`
- Contains: Asset and AssetVulnerability dataclasses; SQLAlchemy Core schema; scanner parsers (Trivy, Grype, Nessus, CSV)
- Depends on: `core/models.py` (EnrichedCVE for triage logic)
- Used by: `api/routes/v1/assets.py`, `web/routes.py` (ingest and asset CRUD)

**Authentication Layer (`auth/`):**
- Purpose: JWT tokens, API keys, OAuth2, and user credential management
- Location: `auth/models.py`, `auth/tokens.py`, `auth/store.py`, `auth/oauth.py`, `auth/dependencies.py`
- Contains: User and ApiKey dataclasses; JWT encode/decode; bcrypt hashing; Authlib OAuth registry; FastAPI Depends helpers
- Depends on: Nothing from core/cache/cmdb/web (only stdlib + third-party)
- Used by: `api/main.py` (lifespan), `api/routes/v1/auth.py`, `web/routes.py`, all protected routes via Depends

**REST API Layer (`api/`):**
- Purpose: FastAPI HTTP server and route handlers for CVE triage, asset management, auth
- Location: `api/main.py`, `api/routes/v1/cve.py`, `api/routes/v1/assets.py`, `api/routes/v1/auth.py`, `api/routes/v1/dashboard.py`, `api/models.py`, `api/limiter.py`
- Contains: Route handlers, Pydantic request/response models, rate limiting config, middleware stack
- Depends on: `core/pipeline.py`, `core/models.py`, `cache/`, `cmdb/`, `auth/`
- Used by: HTTP clients; mounted in `asgi.py`

**Web UI Layer (`web/`):**
- Purpose: Server-rendered HTML templates and browser-facing routes (Jinja2)
- Location: `web/routes.py`, `web/templates/`
- Contains: Route handlers (GET/POST), Jinja2 template rendering, form handling, OAuth callback routes
- Depends on: `core/pipeline.py`, `core/models.py`, `cache/`, `cmdb/`, `auth/`
- Used by: Browsers; mounted in `asgi.py`

**CLI Layer (`main.py`):**
- Purpose: Command-line orchestrator for single and bulk CVE triage
- Location: `main.py`
- Contains: argparse, CVE deduplication, output format selection, progress reporting
- Depends on: `core/pipeline.py`, `cache/`, `core/models.py`, `core/formatter.py`
- Entry point: Direct execution (`python main.py CVE-2021-44228`)

**ASGI Entry Point (`asgi.py`):**
- Purpose: Assemble FastAPI app with web router without coupling them
- Location: `asgi.py`
- Contains: Single file that imports both `api.main:app` and `web.routes:router`, then includes router in app
- Depends on: `api/main.py`, `web/routes.py`
- Entry point: `uvicorn asgi:app` (for server deployment)

## Data Flow

**CLI Single CVE:**
1. User: `python main.py CVE-2021-44228`
2. `main.py`: Parse args, load KEV feed via `fetch_kev()`, validate CVE ID format
3. `core/pipeline.py` → `process_cve()`: Check cache, fetch NVD/EPSS/PoC, enrich with KEV context
4. `core/enricher.py` → `enrich()`: Combine raw data, parse CVSS, apply triage rules, return `EnrichedCVE`
5. `core/formatter.py` → `print_terminal()`: Render to colored terminal output
6. Output: Prioritized plain-language triage decision on terminal

**REST API Bulk Lookup:**
1. HTTP: `POST /api/v1/cve/bulk` with `{"ids": ["CVE-2021-44228", "CVE-2023-44487"]}`
2. `api/routes/v1/cve.py` → `post_cve_bulk()`: Validate, deduplicate, check length limit
3. Loop: Call `core/pipeline.py` → `process_cve()` for each ID (same as CLI flow)
4. `api/routes/v1/cve.py`: Build priority-bucketed summary, optionally include full results
5. Output: JSON with `{summary: {P1: [...], P2: [...]}, results: [...]}` or summary-only

**Web UI Asset Vulnerability Ingest:**
1. User: Upload Trivy JSON scan file via `/ingest` form
2. `web/routes.py` → ingest handler: Parse file via `cmdb.ingest.parse_trivy_json()`
3. `cmdb/ingest.py`: Extract CVE IDs and asset context
4. Loop: Call `core/pipeline.py` → `process_cve()` for each CVE (same core logic)
5. `cmdb/store.py`: Link enriched CVEs to asset, apply criticality modifier
6. Database: Insert AssetVulnerability records with base_priority + effective_priority
7. Output: Asset dashboard with vulnerability table

**State Management:**
- **App-level state:** Initialized in `api/main.py` lifespan: `app.state.cache`, `app.state.kev_set`, `app.state.cmdb`, `app.state.user_store`, `app.state.oauth`
- **Request-level state:** Available via `request.app.state` to all handlers (cache, KEV set, stores)
- **User session:** JWT cookie (web UI) or Authorization Bearer header (API clients) decoded in `auth/dependencies.py`

## Key Abstractions

**EnrichedCVE (Core Output):**
- Purpose: Canonical representation of a fully processed CVE ready for output or consumption
- Examples: `core/models.py::EnrichedCVE` (dataclass with id, cvss, cwe_id, triage_priority, remediation, etc.)
- Pattern: Data Transfer Object (DTO) — immutable structured container passed between layers

**CVECache (Caching):**
- Purpose: Simple TTL-based cache to avoid redundant API calls for the same CVE
- Examples: `cache/store.py::CVECache` with `get(cve_id)`, `set(cve_id, data)`, `purge_expired()`
- Pattern: Cache-Aside — check cache first, fetch on miss, store for next time

**CMDBStore (Persistence):**
- Purpose: Repository pattern for Asset and AssetVulnerability entities with SLA deadline calculation
- Examples: `cmdb/store.py::CMDBStore` with `create_asset()`, `list_asset_vulns()`, `update_vuln_status()`
- Pattern: Repository + Data Mapper — clean interface hides SQLAlchemy query details

**process_cve (Shared Pipeline):**
- Purpose: Pure function that both CLI and API call to avoid code duplication
- Examples: `core/pipeline.py::process_cve(cve_id, kev_set, cache, exposure, nvd_api_key) → Optional[EnrichedCVE]`
- Pattern: DRY (Don't Repeat Yourself) — single source of truth for fetch-cache-enrich logic

**Pydantic Request Models (Input Validation):**
- Purpose: Automatic validation and serialization of HTTP request bodies
- Examples: `api/models.py::BulkRequest` with field_validator that normalizes CVE IDs before pattern check
- Pattern: Boundary layer — user input is validated at the HTTP boundary before any business logic touches it

## Entry Points

**CLI Entry Point:**
- Location: `main.py:main()`
- Triggers: Direct execution (`python main.py CVE-ID...`) or programmatic call to `main()` function
- Responsibilities: Parse argparse, deduplicate CVE IDs, load KEV feed, call `process_cve()` for each ID, format and print results

**API Entry Point:**
- Location: `api/main.py:app` (FastAPI instance created at module load)
- Triggers: `uvicorn asgi:app --reload` or gunicorn/ASGI server
- Responsibilities: Lifespan startup/shutdown (initialize cache, KEV feed, stores), mount middleware (auth, CORS, rate limiting), register route handlers

**Web UI Routes:**
- Location: `web/routes.py` → mounted in `asgi.py` via `app.include_router()`
- Triggers: HTTP GET/POST to `/`, `/cve`, `/assets`, `/login`, etc.
- Responsibilities: Render Jinja2 templates, handle form submissions, redirect on auth failure, call core pipeline for CVE lookups

**OAuth Callback:**
- Location: `web/routes.py::GET /login/callback/{provider}`
- Triggers: OAuth provider redirects with auth code
- Responsibilities: Exchange code for user info via Authlib, create/update User in database, set JWT cookie, redirect to dashboard

## Error Handling

**Strategy:** Graceful degradation at source level; validation at boundaries; structured error responses

**Patterns:**

**Source-level failures are silent:**
- `core/fetcher.py` functions return `None` or empty dict on network errors, never raise
- `core/pipeline.py::process_cve()` returns `None` if NVD record not found
- Callers handle `None` gracefully; tool remains functional if one source is down

**Input validation at boundaries:**
- HTTP routes validate CVE ID format before calling pipeline: `if not re.match(CVE_PATTERN, cve_id): raise HTTPException(400)`
- Pydantic models auto-validate request bodies; FastAPI returns 422 on schema violation
- CLI validates file paths before reading: `Path(path).resolve().is_file()`

**Structured error responses:**
- REST API returns `ErrorDetail(code, message, detail)` as JSON for all errors
- Web UI redirects on auth failure with `?error=bad_credentials` query param (whitelist-mapped to safe message)
- CLI prints user-friendly messages: `[!] 'CVE-2021' doesn't look like a valid CVE ID...`

**Database transaction safety:**
- `cmdb/store.py` uses parameterized queries exclusively (no f-strings in SQL)
- `cache/store.py` uses bound parameters: `VALUES(?, ?, ?)`
- SQLAlchemy tables defined via `Table()` not ORM — zero risk of injection

## Cross-Cutting Concerns

**Logging:**
- Approach: Standard Python logging module (`logging.getLogger(__name__)`)
- Usage: `core/fetcher.py` logs network failures at WARNING level; `api/main.py` logs startup/shutdown; no logging in pure logic (`enricher.py`)
- Configuration: `api/main.py` sets up root logger on startup with ISO timestamp format

**Validation:**
- At HTTP boundary: Pydantic models for request bodies; regex patterns for path params; query param length limits
- In pipeline: `core/models.py::CVE_PATTERN` regex is canonical; imported everywhere validation is needed
- In database: SQL bound parameters prevent injection; enum constraints on status/priority fields

**Authentication:**
- Three-tier priority in `auth/dependencies.py::try_get_current_user()`:
  1. JWT cookie (web UI login flow)
  2. Authorization: Bearer header (API clients)
  3. X-API-Key header (CI/CD scripts)
- All converge on `User` object; FastAPI Depends helpers enforce auth on protected routes
- Sessions: `SessionMiddleware` from Starlette manages httpOnly cookie lifecycle

**Rate Limiting:**
- Tool: slowapi (Starlette rate limiter)
- Configuration: `api/limiter.py::Limiter(key_func=get_remote_address, storage_uri="memory://")`
- Applied: `@limiter.limit("30/minute")` decorator on individual routes
- Enforcement: SlowAPIMiddleware in `api/main.py` applies limits before handlers run

**Middleware Stack (outermost to innermost):**
1. TrustedHostMiddleware — rejects mismatched Host headers (HTTPS verification)
2. CORSMiddleware — adds CORS headers for allowed browser origins
3. SlowAPIMiddleware — rate limiting from per-route decorators
4. SessionMiddleware — httpOnly cookie management

---

*Architecture analysis: 2026-02-25*
