# VulnAdvisor -- Architecture Guide

This document explains every structural decision made in this codebase and why it was made that way. It is intended to be a learning reference as much as a technical reference.

---

## The Core Principle: Separation of Concerns

The entire architecture is built around one idea: **each piece of code should do one thing and only one thing.**

This is called the **Single Responsibility Principle** and it is one of the most important ideas in software design. When code has one job, it is:
- Easier to understand (you always know where to look)
- Easier to test (you can test each piece in isolation)
- Easier to change (a change in one place does not break another)

In VulnAdvisor this principle is applied at the module level.

---

## Module Map

```
main.py               CLI entry point -- argparse, orchestration
core/
  config.py           Centralized settings (pydantic-style dataclass, env vars)
  pipeline.py         Pure process_cve() + process_cves() -- shared by CLI and API
  fetcher.py          All HTTP calls -- one function per source, returns None on failure
  enricher.py         Pure logic -- raw data in, EnrichedCVE out
  formatter.py        Terminal + JSON + CSV/HTML/Markdown export -- no business logic
  models.py           Dataclasses only -- zero logic
cache/
  store.py            SQLite TTL cache -- shared by CLI and API
auth/
  models.py           User and ApiKey dataclasses
  store.py            UserStore -- SQLAlchemy Core, user/API key CRUD
  tokens.py           JWT encode/decode, bcrypt hashing, API key gen/hash (HMAC-SHA256)
  oauth.py            Authlib OAuth registry (GitHub, Google/OIDC)
  dependencies.py     FastAPI Depends helpers -- try_get_current_user, require_admin
cmdb/
  models.py           Asset, AssetVulnerability, RemediationRecord dataclasses
  store.py            CMDBStore -- SQLAlchemy Core, asset and vuln tracking
  ingest.py           Scanner parsers -- CSV, Trivy, Grype, Nessus
api/
  main.py             FastAPI app -- lifespan, middleware stack, exception handlers
  limiter.py          Shared slowapi rate limiter
  models.py           Pydantic v2 request/response models
  routes/v1/cve.py    CVE endpoints -- GET /cve/{id}, POST /cve/bulk, GET /cve/summary
  routes/v1/auth.py   Login, API key CRUD, OAuth flow, admin user management
  routes/v1/assets.py Asset CRUD, vulnerability ingest, status tracking
  routes/v1/dashboard.py  Dashboard summary endpoint
web/
  routes.py           All web routes -- login, logout, setup, OAuth, dashboard, assets
  templates/          Jinja2 templates -- Bootstrap dark theme
tests/
  test_enricher.py    Unit tests for core/enricher -- 80 tests, 100% line coverage
```

Dependencies flow inward: `web/` and `api/` import from `core/`, `auth/`, `cache/`, and `cmdb/`. The `core/` engine knows nothing about `api/` or `web/`. `api/` and `web/` never import from each other -- the top-level `asgi.py` mounts both as independent layers.

---

## main.py -- The CLI Orchestrator

**What it does:** Parses command-line arguments, loads the CISA KEV feed once, then calls `core/pipeline.py` for each CVE ID.

**Why it is thin:** `main.py` should be an entry point, not a logic engine. It wires the pieces together and delegates everything else. If you find business logic in `main.py`, that is a signal it belongs somewhere in `core/`.

**Pattern used:** This is called an **orchestrator** -- it coordinates other components without doing the work itself.

**Key decision:** The CISA KEV feed is loaded once before the loop, not once per CVE. This is a simple form of caching. Loading 1,000 CVEs should not download the KEV feed 1,000 times.

---

## core/config.py -- Centralized Configuration

**What it does:** Defines a `Settings` dataclass populated from environment variables. Every module that needs configuration imports `get_settings()` instead of calling `os.getenv()` directly.

**Why it exists:** Before `config.py`, settings were scattered across modules as inline `os.getenv()` calls. This made it impossible to see all configurable values in one place, and easy to introduce inconsistent defaults. Centralizing configuration is the **Single Source of Truth** principle.

**Key decisions:**
- `SECRET_KEY` is required in production (DEBUG=false). A missing key raises a hard `ValueError` at startup -- no silent fallbacks that would leave sessions insecure.
- In dev mode (DEBUG=true), a random key is generated with a console warning. This is acceptable because dev sessions don't need to persist across restarts.
- `get_settings()` is cached with `lru_cache` -- the settings object is created once and shared.

---

## core/pipeline.py -- The Shared Processing Core

**What it does:** Provides `process_cve()` and `process_cves()` -- pure functions that handle the fetch-cache-enrich sequence for one or many CVE IDs. Both the CLI and the API call these functions. Neither caller reimplements the logic.

**Why it exists:** Before `pipeline.py`, the CLI's main loop contained the fetch-and-enrich orchestration inline. This meant the API would have had to duplicate that logic. Extracting it into a pure function that any caller can use is the **Don't Repeat Yourself (DRY)** principle in action.

**Why it is pure:** No `print()` statements, no side effects. Callers decide what to do with results. This makes the function easy to test and easy to call from different contexts (terminal, HTTP handler, future scheduler).

**Key decision:** CVE ID validation (regex `CVE-\d{4}-\d{4,}`) lives here, not in the callers. One validation rule, one place to update it.

---

## core/models.py -- The Data Contracts

**What it does:** Defines the shape of data using Python dataclasses. No logic, no functions -- just structure.

**Why dataclasses:** Python dataclasses give you a clean way to define structured data without writing boilerplate. They are like a blueprint for what an object looks like.

**Why no logic here:** If `models.py` contained logic, you would have to understand models to understand the logic, and understand the logic to understand models. Keeping them separate means each file is fully understandable on its own.

**Key structures:**
- `CVSSDetails` -- the parsed CVSS score and plain-language attack surface
- `PoCInfo` -- public PoC status, count, and link
- `RemediationStep` -- a single action item (PATCH, WORKAROUND, or REFERENCE)
- `EnrichedCVE` -- the complete output object that all other modules pass around

**Pattern used:** This is called a **Data Transfer Object (DTO)** -- a plain container that carries data between layers of the application.

---

## core/fetcher.py -- The Data Layer

**What it does:** Makes all HTTP requests to external APIs. One function per data source. Returns `None` or an empty dict on failure -- never raises an exception.

**Why one function per source:** Each source has its own URL, its own response format, and its own failure modes. Keeping them separate means a problem with one source does not affect the others.

**Why failures are silent:** This is a triage tool. If EPSS is unavailable, the tool should still show CVSS and KEV data. Crashing the entire run because one source is down would make the tool unreliable. Each function returns a safe empty value on failure and the rest of the pipeline handles missing data gracefully.

**Key decision -- KEV caching:** The CISA KEV feed is a large JSON file (~200KB). The `_kev_cache` module-level variable means it is downloaded once per session regardless of how many CVEs are looked up. This is the simplest possible caching strategy.

**Pattern used:** This is called the **Repository Pattern** -- a layer that abstracts data fetching so the rest of the application does not need to know how or where data comes from.

---

## core/enricher.py -- The Logic Layer

**What it does:** Takes raw fetched data and combines it into a structured, plain-language `EnrichedCVE`. This is where all the intelligence lives.

**Why it is the most complex module:** Enrichment is inherently complex -- it involves parsing CVSS vectors, mapping CWE IDs to plain language, extracting CPE data, and applying multi-signal triage logic. That complexity is intentional and appropriate here. It would be worse if it were spread across multiple modules.

**Key components:**

`CWE_MAP` -- A dictionary mapping CWE IDs to plain-language names, descriptions, and fix guidance. This is a lookup table, not logic. Adding a new CWE is as simple as adding a new entry.

`_parse_cvss_vector()` -- CVSS vectors are compact strings like `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`. This function splits them into key-value pairs and translates each code into plain English using lookup dictionaries.

`_triage_priority()` -- The core decision engine. Combines CVSS score, KEV status, EPSS probability, and PoC availability into a single P1-P4 priority. This is rule-based, not machine learning -- rules are transparent, explainable, and auditable.

**The triage rules:**
```
P1 (fix in 24h)   CVSS >= 9.0 AND (actively exploited OR EPSS >= 50%)
P2 (fix in 7d)    CVSS >= 7.0 AND (exploited OR has PoC OR EPSS >= 30%)
P2 (fix in 7d)    CVSS >= 7.0 (high severity alone)
P3 (fix in 30d)   CVSS >= 4.0
P4 (next cycle)   everything else
```

**Pattern used:** This is called an **enrichment pipeline** -- raw data goes in, enriched structured data comes out.

---

## auth/ -- Authentication and Authorization

**What it does:** Provides the complete authentication layer: user accounts, password hashing, JWT sessions, API key management, and OAuth 2.0 (GitHub, Google/OIDC).

**Why it is a separate package (not in api/):** Auth logic is consumed by both `api/` (route-level Depends) and `web/` (template context, login forms). Putting it in `api/` would create a cross-layer import from `web/`. A standalone `auth/` package lets both layers import cleanly.

**Key modules:**

`tokens.py` -- JWT creation and verification using python-jose. Password hashing uses bcrypt directly (not passlib, which has compatibility issues with bcrypt 4.x). API key generation uses `secrets.token_urlsafe()` with HMAC-SHA256 hashing for storage. Cookies are set with httpOnly, samesite=lax, and configurable secure flag.

`store.py` -- UserStore backed by SQLAlchemy Core (not ORM). Parameterized queries throughout, no raw f-strings in SQL. App-level settings (OAuth toggles, registration toggle) stored in an `app_settings` table with whitelist validation on column names.

`dependencies.py` -- Three auth methods checked in order: cookie JWT, Bearer header JWT, API key hash. Each returns the user or falls through. `require_admin()` is a FastAPI Depends that raises 403 for non-admin users.

`oauth.py` -- Authlib OAuth registry with GitHub (static URLs) and Google/OIDC (discovery-based). Email verification is mandatory -- GitHub requires `primary=true AND verified=true`, Google requires `email_verified=true`. Unverified emails raise ValueError.

**Security decisions:**
- Timing-safe password verification: a pre-computed dummy hash is used when the username doesn't exist, preventing timing-based user enumeration.
- Session expiry uses a two-cookie pattern: httpOnly `access_token` (the JWT) and non-httpOnly `session_expires_at` (a Unix timestamp for JS to read). The expiry cookie has 2x the lifetime so JS can detect when the JWT has expired.
- API keys are capped at 10 per user. Revocation checks both key ID and user ID (IDOR protection).

---

## cmdb/ -- Asset and Vulnerability Tracking

**What it does:** Tracks organizational assets (servers, endpoints) and their vulnerability status. Ingests scan results from common formats.

**Key modules:**

`models.py` -- Dataclasses for Asset (hostname, IP, environment, exposure, criticality), AssetVulnerability (links a CVE to an asset with status tracking), and RemediationRecord.

`store.py` -- CMDBStore using SQLAlchemy Core. `apply_criticality_modifier()` adjusts triage priority based on asset criticality (a critical production server with a P2 vuln may become P1).

`ingest.py` -- Parses scanner output from CSV, Trivy JSON, Grype JSON, and Nessus XML into a common `IngestRecord` format that the store can process uniformly.

---

## api/ -- REST API Layer

**What it does:** Exposes the core engine and CMDB over HTTP. FastAPI with Pydantic v2 models for request/response validation.

**Key components:**

`main.py` -- App entry point with lifespan management (initializes cache, KEV feed, CMDB, auth store, OAuth on startup; tears down on shutdown). Middleware stack: TrustedHost, CORS, SlowAPI rate limiting, SessionMiddleware. All exception handlers return a uniform `ErrorResponse` envelope.

`routes/v1/cve.py` -- Three CVE endpoints wrapping `core/pipeline.py`. No auth required (public data).

`routes/v1/auth.py` -- Login (rate-limited at 10/minute), logout, user info, OAuth flow, API key CRUD, admin user management. Generic error messages prevent username enumeration.

`routes/v1/assets.py` -- Asset CRUD, vulnerability ingest from scanner formats, status workflow (open, in_review, remediated, closed, deferred).

`routes/v1/dashboard.py` -- Dashboard summary endpoint aggregating asset and vulnerability counts.

**Why /docs and /redoc require auth:** API documentation is only available to authenticated users. The built-in FastAPI docs are disabled and replaced with custom routes that require a valid JWT.

---

## web/ -- Server-Rendered Web UI

**What it does:** Bootstrap dark-themed web interface using Jinja2 templates. All routes in `web/routes.py`, all templates in `web/templates/`.

**Key features:**
- Login, registration, and first-run setup wizard with password complexity validation
- OAuth login buttons (GitHub, Google) when providers are configured
- Session expiry modal with JS polling detection and server-side expired-session flash
- Dashboard, asset management, CVE research pages
- CSRF protection on all form submissions (fastapi-csrf-protect double-submit cookie pattern)
- Admin settings: OAuth toggles, self-registration toggle, user management table

**Why server-rendered (not a SPA):** For a solo analyst tool, server-rendered pages are simpler, faster to build, and have zero JS framework overhead. If a team-facing SPA is needed later, the API layer already exists to support it.

---

## The Open-Core Path

The architecture was designed so that the same core engine powers both the CLI and the API without duplication.

```
Open source CLI (crawl phase -- complete):
  main.py -> pipeline -> fetcher -> enricher -> formatter -> terminal

REST API (walk phase -- active):
  HTTP request -> pipeline -> fetcher -> enricher -> to_json() -> API response

Web UI (walk phase -- active):
  Browser -> web/routes.py -> api/ endpoints -> pipeline -> template render
```

Both CLI and API call the same `process_cve()` from `core/pipeline.py` and the same `enrich()` from `core/enricher.py`. The API is not a separate reimplementation -- it is another consumer of the same core engine. The web UI calls the API endpoints and renders the results.

This design pattern is called **open-core** -- the core logic is free and open source, and the value-added layer (web UI, team features, integrations) is where a commercial product can be built on top.

---

## What Was Deliberately Left Out

**No AI/ML layer.** The triage logic is entirely rule-based. Rules are transparent, auditable, and free. An AI layer would require an API key, cost money, and produce results that are harder to explain. Rule-based is the right choice for an open-source security tool.

**No ORM (for now).** The SQLite stores use SQLAlchemy Core (table definitions and parameterized queries) rather than the ORM (mapped classes and sessions). At this scale the extra abstraction would add complexity without payoff. This may change when PostgreSQL migration happens.

---

## Testing Strategy

**What is tested:** `core/enricher.py` -- the module with the most business logic and the clearest pure-function interface (no I/O, no side effects). 80 tests, 100% line coverage.

**Why private functions are tested directly:** `_triage_priority()` is the most critical logic path in the codebase. Testing it through `enrich()` alone would make it hard to isolate boundary conditions. Python does not enforce private access, and testing internals directly is the right call when those internals are the core decision engine.

**Why no mocking:** All tested functions are pure -- they take plain Python dicts and return plain Python objects. No HTTP calls, no SQLite. Pure functions are the highest-ROI test targets because they need zero test infrastructure.

**Coverage scope:** `--cov=core.enricher` only. A global 80% threshold would fail immediately since `fetcher.py`, `pipeline.py`, and the API layer are not yet covered. Scoping to enricher is honest about what is actually tested. Expand scope as each tier gets tests added.

**Pattern used:** This is called **unit testing** -- testing the smallest independent unit of logic in isolation. The counterpart is integration testing, which tests multiple components working together.
