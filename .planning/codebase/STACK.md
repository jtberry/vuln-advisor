# Technology Stack

**Analysis Date:** 2026-02-25

## Languages

**Primary:**
- Python 3.9+ - All application code (core, API, CLI, web backend)

**Secondary:**
- HTML/Jinja2 - Web UI templates (server-rendered, no client-side framework)

## Runtime

**Environment:**
- Python 3.9 (minimum version enforced in pyproject.toml)

**Package Manager:**
- pip
- Lockfile: requirements.txt (core), requirements-dev.txt (development tools), requirements-api.txt (API server)

## Frameworks

**Core:**
- FastAPI 0.115.6 - REST API server (walk phase, async ASGI)
- Uvicorn 0.34.0 - ASGI server (standard choice for FastAPI)

**Data Persistence:**
- SQLAlchemy 2.0+ - Database abstraction layer using SQLAlchemy Core (not ORM)
- sqlite3 - Default database (SQLite 3)

**Authentication & Security:**
- Authlib 1.3.0 - OAuth/OIDC client (GitHub, Google, generic OIDC)
- python-jose[cryptography] 3.3.0 - JWT encode/decode (via jose library)
- bcrypt 4.0.1+ - Password hashing (direct library, NOT passlib due to v1.7.4 incompatibility with bcrypt 4.x)

**Web Framework:**
- Jinja2 3.1.0+ - Server-rendered HTML templates
- Starlette SessionMiddleware - Session management for OAuth state/CSRF protection

**Rate Limiting:**
- slowapi 0.1.9 - Per-route rate limiting (memory-backed key function)

**HTTP Requests:**
- requests 2.28.0+ - Synchronous HTTP client (for fetcher.py external API calls)
- httpx 0.27.0 - Async HTTP client (for OAuth provider requests)

**Utilities:**
- python-dotenv 1.0.0 - Environment variable loading (.env files)
- python-multipart 0.0.9 - FastAPI dependency for form data parsing
- itsdangerous 2.1.0 - Secure cookie/session signing (SessionMiddleware dependency)

## Testing & Development

**Testing:**
- pytest 7.4.0+ - Test runner
- pytest-cov 4.0.0+ - Coverage reporting (enforces 80%+ on core.enricher and core.pipeline)

**Code Quality:**
- black 24.0.0+ - Code formatter (line length 120, target Python 3.9)
- isort 5.13.0+ - Import organizer (black profile)
- ruff 0.8.0+ - Fast linter (pycodestyle, pyflakes, flake8-bugbear, pyupgrade, security via bandit rules)
- bandit 1.7.0+ - Security linter (skips assert warnings)
- semgrep 1.50.0+ - Static analysis (pattern-based vulnerability detection)
- pip-audit 2.7.0+ - Dependency vulnerability scanner

**Pre-commit Hooks:**
- pre-commit 3.5.0+ - Automated hook framework

## Key Dependencies

**Critical:**
- SQLAlchemy 2.0+ - Enables database portability (SQLite dev, PostgreSQL production target)
- Authlib 1.3.0+ - Multi-provider OAuth/OIDC authentication
- bcrypt 4.0.1+ - Password security (must be >=4.0.1 for compatibility with python-jose)
- python-jose[cryptography] 3.3.0+ - JWT tokens for API authentication

**Infrastructure:**
- fastapi 0.115.6 - REST API framework with automatic OpenAPI docs
- uvicorn[standard] 0.34.0 - ASGI server with lifespan management
- slowapi 0.1.9 - Rate limiting middleware

## Configuration

**Environment:**
- `.env` file (not checked in; see `.env.example`)
- Environment variables at process startup (module-level reads in fetcher.py and auth/oauth.py)

**Key configurations required:**
- `NVD_API_KEY` - Optional. Raises NVD rate limit from 5 req/30s to 50 req/30s. Free registration at https://nvd.nist.gov/developers/request-an-api-key
- `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` - Optional. GitHub OAuth provider
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` - Optional. Google OAuth provider
- `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_DISCOVERY_URL`, `OIDC_DISPLAY_NAME` - Optional. Generic OIDC provider (Okta, Azure AD, Keycloak, Authentik, etc.)

**Build:**
- `pyproject.toml` - Tool configuration (black, isort, ruff, bandit, pytest)
- `.pre-commit-config.yaml` - Pre-commit hook definitions

## Platform Requirements

**Development:**
- Python 3.9+ installed
- Virtual environment (venv)
- pip for dependency installation
- Git for version control

**Production:**
- Python 3.9+ runtime
- SQLite 3 (bundled with Python) for default deployment
- PostgreSQL 12+ (future migrations via #45; Schema migrations planned via Alembic #46)
- 512 MB+ RAM minimum (walk phase with FastAPI server)
- Network access to external APIs: NVD (nvd.nist.gov), CISA (cisa.gov), FIRST/EPSS (api.first.org), GitHub PoC (raw.githubusercontent.com)

## Database Deployment Target

**Current (Walk Phase):**
- SQLite (development and single-server deployments)

**Future (Run Phase):**
- PostgreSQL migration planned (issue #45)
- Alembic schema migration framework planned (issue #46)

---

*Stack analysis: 2026-02-25*
