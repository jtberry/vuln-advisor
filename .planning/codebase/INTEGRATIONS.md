# External Integrations

**Analysis Date:** 2026-02-25

## APIs & External Services

**Vulnerability Data (all free, no auth required except optional NVD key):**

- **NVD (National Vulnerability Database)**
  - What: CVE record fetching (details, CVSS scores, CWE mappings)
  - Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
  - SDK/Client: `requests` library (sync HTTP)
  - Auth: Optional `NVD_API_KEY` environment variable
  - Rate limits: 5 req/30s unauthenticated, 50 req/30s with API key
  - Fallback: Returns None on failure; caller handles gracefully
  - Code: `core/fetcher.py:fetch_nvd()`

- **CISA KEV (Known Exploited Vulnerabilities)**
  - What: List of CVEs with known public exploits
  - Endpoint: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  - SDK/Client: `requests` library (sync HTTP)
  - Auth: None
  - Rate limits: No documented limit (publicly available JSON feed)
  - Fallback: Returns empty set on failure
  - Caching: Cached via `CVECache` with 24h TTL in API server; CLI fetches on every run
  - Code: `core/fetcher.py:fetch_kev()`

- **FIRST EPSS (Exploit Prediction Scoring System)**
  - What: Exploitation probability score (0-1.0) for CVEs
  - Endpoint: `https://api.first.org/data/v1/epss`
  - SDK/Client: `requests` library (sync HTTP)
  - Auth: None
  - Query params: `?cve={CVE_ID}`
  - Fallback: Returns `{"score": None, "percentile": None}` on failure
  - Code: `core/fetcher.py:fetch_epss()`

- **PoC-in-GitHub (nomi-sec/PoC-in-GitHub)**
  - What: Public proof-of-concept repositories for CVEs on GitHub
  - Endpoint: `https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json`
  - SDK/Client: `requests` library (sync HTTP)
  - Auth: None (public GitHub raw content)
  - Fallback: Returns `{"has_poc": False, "count": 0, "sources": []}` on 404 or network failure
  - Limits: Cap at 5 source links per CVE
  - Code: `core/fetcher.py:fetch_poc()`

## Data Storage

**Databases:**

- **CVE Cache (SQLite)**
  - Purpose: TTL-backed cache for enriched CVE results
  - Location: `cache/vulnadvisor.db` (local SQLite file)
  - Connection: `sqlite3` library via SQLAlchemy (SQLite-specific config in `cache/store.py`)
  - Client: `cache/store.py:CVECache` class
  - Schema: Single table `cve_cache` (cve_id TEXT PRIMARY KEY, data TEXT, cached_at REAL)
  - TTL: 24 hours (configurable, default 86400 seconds)
  - Purge: Expired entries removed via periodic task (API) or on-demand (CLI)
  - Shared by: CLI (`main.py`) and API server (walk phase)

- **CMDB Store (SQLite, PostgreSQL-ready)**
  - Purpose: Asset inventory and vulnerability tracking
  - Location: `cmdb/vulnadvisor_cmdb.db` (local SQLite file)
  - Connection: SQLAlchemy Core (database-agnostic)
  - Client: `cmdb/store.py:CMDBStore` class
  - Schema: Three tables:
    - `assets` - Asset inventory (hostname, IP, environment, exposure, criticality, owner, tags, OS, EOL, compliance)
    - `asset_vulnerabilities` - CVE-asset links with triage state (status, priority, deadline, owner, evidence, scanner source)
    - `remediation_records` - Immutable audit trail of status changes per vulnerability
  - Migration: Hand-rolled `ALTER TABLE` migrations in `_migrate_assets_table()` and `_migrate_vulns_table()` (planned Alembic migration in issue #46)
  - Reserved column: `org_id` for multi-tenancy enforcement (run phase; walk phase always NULL)
  - Query pattern: Repository (CMDBStore methods) + Data Mapper (_row_to_asset, _row_to_vuln)

- **Auth Store (SQLite, PostgreSQL-ready)**
  - Purpose: User accounts, OAuth linkage, API keys
  - Location: `auth/vulnadvisor_auth.db` (separate SQLite file)
  - Connection: SQLAlchemy Core (database-agnostic)
  - Client: `auth/store.py:UserStore` class
  - Schema: Two tables:
    - `users` - User accounts (username, hashed_password, role, oauth_provider, oauth_subject, user_preferences, created_at, is_active)
    - `api_keys` - API credentials (user_id, name, key_hash, key_prefix, created_at, last_used, is_active)
  - Unique constraints:
    - `users.username` - Unique; prevents duplicate accounts
    - `api_keys.key_hash` - Unique; O(1) lookups
    - `users(oauth_provider, oauth_subject)` - Enforced in code (SQLite UNIQUE treats NULLs as distinct; code check prevents duplicates)
  - First-run detection: `has_users()` method checks if any user records exist (walk phase uses this for setup redirect)

**File Storage:**
- None (local filesystem access is read-only for CVE ID lists via `_load_file()` in `main.py`)

**Caching:**
- In-memory: slowapi rate limiter uses memory-backed storage (not Redis, walk phase only)
- Disk: SQLite CVECache (24h TTL)
- No distributed cache (walk phase); migration to Redis planned for issue #48

## Authentication & Identity

**Auth Provider:**
- Custom local auth (username/password) + OAuth/OIDC
- Supported OAuth providers:
  - **GitHub** - via Authlib, static endpoints
    - Client ID/Secret: `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` env vars
    - Scope: `read:user user:email`
    - User info flow: GET /user → numeric ID; GET /user/emails → primary verified email
    - Email verification: Required (only primary=true AND verified=true accepted; error if missing)
    - Subject ID: GitHub numeric user ID (stable, never changes)

  - **Google** - via Authlib, OIDC discovery
    - Client ID/Secret: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` env vars
    - Server metadata: `https://accounts.google.com/.well-known/openid-configuration`
    - Scope: `openid email profile`
    - Email verification: Checked via `email_verified` claim in id_token (required=True)
    - Subject ID: `sub` claim from id_token

  - **Generic OIDC** - via Authlib, OIDC discovery (Okta, Azure AD, Keycloak, Authentik, etc.)
    - Client ID/Secret: `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` env vars
    - Server metadata: `OIDC_DISCOVERY_URL` env var (e.g., `https://keycloak.example.com/auth/realms/master/.well-known/openid-configuration`)
    - Display name: `OIDC_DISPLAY_NAME` env var (login button label)
    - Scope: `openid email profile`
    - Email verification: Checked via `email_verified` claim (required=True)
    - Subject ID: `sub` claim

- **Session Management:**
  - Starlette SessionMiddleware - Encrypts session state (state parameter for OAuth CSRF protection)
  - Secret key: `auth/tokens.py:_SECRET_KEY` (auto-generated or loaded from environment)

- **JWT Tokens (API):**
  - Library: python-jose with cryptography backend
  - Algorithm: HS256 (symmetric, using shared secret)
  - Stored in: HTTP-only cookies (set-cookie from login endpoint)
  - Expiration: TBD (currently stored in token, no refresh token pattern yet)

- **API Keys:**
  - Generation: Cryptographically random via `secrets` stdlib
  - Storage: HMAC-SHA256 hash of the key (not the raw key)
  - Display: First 12 characters (key_prefix) for user reference
  - Lookup: O(1) via UNIQUE key_hash index in api_keys table
  - Revocation: Mark is_active=0 (soft delete)
  - Audit: Timestamp on first creation and last_used

- **Password Hashing:**
  - Library: bcrypt (version 4.0.1+)
  - NOT passlib (passlib 1.7.4 + bcrypt 4.x incompatible: passlib adds test_password with >72 bytes, bcrypt 4.x rejects)
  - Use `bcrypt.hashpw()` and `bcrypt.checkpw()` directly

## Monitoring & Observability

**Error Tracking:**
- Not integrated yet. Reserved env var: `ANTHROPIC_API_KEY` (future AI-enhanced features)

**Logs:**
- Standard Python logging to stdout (CLI and API)
- Format: ISO8601 timestamp, level, logger name, message
- Config: `logging.basicConfig()` in `api/main.py` and `main.py`
- Log levels: INFO (default), WARNING (fetch failures), ERROR (unhandled exceptions)

**Metrics:**
- No metrics collection (walk phase); Prometheus integration planned for run phase

## CI/CD & Deployment

**Hosting:**
- Not specified (walk phase deployable anywhere Python 3.9+ runs)
- Recommended: Docker container (issue #17 planned)

**CI Pipeline:**
- GitHub Actions (inferred from branch strategy and PR workflow)
- Pre-commit hooks run locally (black, isort, ruff, bandit, pip-audit, semgrep)

**Deployment:**
- CLI: `python main.py [CVE-IDs...]`
- API: `uvicorn api.main:app --reload` (dev) or `uvicorn api.main:app` (prod, bind 0.0.0.0:8000)
- Lifespan: Modern FastAPI asynccontextmanager pattern (startup/shutdown hooks)

## Environment Configuration

**Required env vars (walk phase):**
- None - all external data sources are free and don't require authentication

**Optional env vars:**
- `NVD_API_KEY` - NVD rate limit upgrade (5→50 req/30s)
- `GITHUB_CLIENT_ID` - GitHub OAuth client ID (OAuth disabled if not set)
- `GITHUB_CLIENT_SECRET` - GitHub OAuth client secret (OAuth disabled if not set)
- `GOOGLE_CLIENT_ID` - Google OAuth client ID (OAuth disabled if not set)
- `GOOGLE_CLIENT_SECRET` - Google OAuth client secret (OAuth disabled if not set)
- `OIDC_CLIENT_ID` - Generic OIDC client ID (OAuth disabled if not set)
- `OIDC_CLIENT_SECRET` - Generic OIDC client secret (OAuth disabled if not set)
- `OIDC_DISCOVERY_URL` - Generic OIDC discovery endpoint (OAuth disabled if not set)
- `OIDC_DISPLAY_NAME` - Label for generic OIDC button (default: "SSO")

**Secrets location:**
- Loaded from `.env` file (python-dotenv) or environment at process startup
- Never committed to git (`.env` in `.gitignore`)
- Never logged or printed

**Database location:**
- `cache/vulnadvisor.db` - CVE cache (relative to module)
- `cmdb/vulnadvisor_cmdb.db` - Asset CMDB (relative to module)
- `auth/vulnadvisor_auth.db` - User auth (relative to module)
- Future: Environment variable `DATABASE_URL` for production connection strings (issue #43)

## Webhooks & Callbacks

**Incoming:**
- None (walk phase is request-response only)

**Outgoing:**
- None (walk phase does not trigger external actions)

---

*Integration audit: 2026-02-25*
