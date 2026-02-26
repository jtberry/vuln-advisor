# Codebase Concerns

**Analysis Date:** 2026-02-25

## Tech Debt

### Synchronous Database Calls in Async Context

**Issue:** Database operations use synchronous SQLAlchemy/sqlite3 in FastAPI async route handlers. This blocks the event loop.

**Files:**
- `cmdb/store.py` — All query methods (create_asset, list_assets, update_vuln_status, etc.)
- `cache/store.py` — get(), set(), purge_expired() are sync operations
- `auth/store.py` — User and API key operations

**Impact:** Concurrent requests stall the event loop while waiting for I/O. Routes calling `cmdb.create_asset()` or `cache.get()` from async handlers block other requests from processing.

**Fix approach:**
1. Wrap sync DB calls in `asyncio.to_thread()` or use an executor (short-term, v0.2.x)
2. Migrate to async SQLAlchemy + asyncpg for PostgreSQL (long-term, v0.3.x) — tracked in GitHub issues #49, #50

**Tracking:** GitHub issue #49 (Wrap sync DB calls in thread executor)

---

### CVE ID Format Validation Inconsistency

**Issue:** CVE format validation happens at multiple layers with different regex patterns.

**Files:**
- `core/models.py` line 10 — canonical pattern: `r"^CVE-\d{4}-\d{4,}$"`
- `core/pipeline.py` line 16 — duplicate local pattern with same regex
- `api/models.py` line 29 — uses imported pattern from core
- `api/routes/v1/cve.py` line 72 — route-level validation with imported pattern
- `core/fetcher.py` line 103 — no validation; splits on "-" and assumes format

**Impact:** Inconsistent validation across layers. fetch_poc() crashes with IndexError if CVE ID is malformed. Routes validate input, but core functions assume format correctness.

**Fix approach:**
1. Add defensive validation in `core/fetcher.py` fetch_poc() — validate cve_id before indexing
2. Consider raising ValueError in core/fetcher functions on invalid format (requires API contract change)
3. Document that core/ assumes validated input from callers

---

### Data-Logic Separation: CWE_MAP in enricher.py

**Issue:** CWE_MAP is hardcoded enrichment data (25+ CWE entries) mixed with triage logic in `core/enricher.py`.

**Files:** `core/enricher.py` lines 17-267

**Impact:** Large dataclass clutters logic file. CWE definitions are not easily reusable (e.g., web UI wanting to display CWE descriptions). Updates to remediation guidance require editing logic code.

**Fix approach:** Move CWE_MAP to `core/cwe_definitions.py` (data file). Keep import in enricher.py for backwards compatibility.

**Tracking:** Documented in CLAUDE.md personal memory as pre-API-launch debt

---

### Missing CVE ID Length Validation

**Issue:** CVE pattern `r"^CVE-\d{4}-\d{4,}$"` allows unbounded sequence IDs (CVE-2099-99999999...).

**Files:** `core/models.py` line 10

**Impact:** Malformed but regex-valid IDs like CVE-2025-999999999999999999 could be created. Not a security issue but indicates lax validation.

**Fix approach:** Cap sequence to 5-7 digits: `r"^CVE-\d{4}-\d{4,7}$"` (modern CVEs max ~6 digits in 2026)

---

### Race Condition on First-Run Setup

**Issue:** POST /setup re-checks `has_users()` at DB level after checking in-memory flag, but two concurrent requests could both read empty user table before either commits.

**Files:** `api/main.py` line 233-234 (documented with [M1] marker)

**Impact:** Two users could both see setup=required and both try to create admin accounts. Mitigated by unique constraint on first admin but logged as a known race.

**Fix approach:** Use database-level transaction isolation (SERIALIZABLE) when checking and creating first user. Or add a setup_lock file.

**Status:** Known limitation, documented in code

---

## Security Considerations

### Email Verification in OAuth

**Status:** IMPLEMENTED CORRECTLY

**Files:** `auth/oauth.py` lines 121-180

**Summary:** Email verification is mandatory before accepting OAuth login (H1). GitHub requires verified email, Google/OIDC require email_verified=true. Unverified emails raise ValueError and trigger 401.

---

### Secret Key Validation

**Status:** IMPLEMENTED CORRECTLY

**Files:** `auth/tokens.py` lines 46-57

**Summary:** SECRET_KEY must be >= 32 characters or the app raises RuntimeError at startup. If unset, a random key is generated with a warning (sessions won't persist across restarts).

---

### Bcrypt Password Hashing

**Status:** IMPLEMENTED CORRECTLY

**Files:** `auth/tokens.py` lines 70-95

**Summary:** Direct bcrypt usage (not passlib) avoids version incompatibility. Passwords > 72 bytes silently truncated by bcrypt (known limitation), but Pydantic validates max_length=255 at API layer. Timing equalization dummy hash [C1] prevents username enumeration.

---

### Path Traversal in File Operations

**Status:** MITIGATED

**Files:** `main.py` lines 42-50

**Issue:** File reading in `load_cve_ids_from_file()` uses `Path.resolve()` and `is_file()` check, which prevents some traversal attacks but doesn't enforce a whitelist directory.

**Risk:** Low for CLI (user controls their own argument) but moderate for API if file paths ever become user-controllable.

**Mitigation:** Resolve path, check is_file(), fail on OSError. If API ever adds file upload destination control, add explicit directory whitelist.

---

### SQL Injection Prevention

**Status:** IMPLEMENTED CORRECTLY

**Files:**
- `cmdb/store.py` — All queries use bound parameters via SQLAlchemy Core
- `cache/store.py` — Parameterized queries with ? placeholders
- `auth/store.py` — Parameterized queries

**Summary:** No SQL constructed from user input. All queries use `.execute(query, (params,))` pattern.

---

### API Key Storage

**Status:** IMPLEMENTED CORRECTLY

**Files:** `auth/tokens.py` lines 133-160

**Summary:** API keys stored as HMAC-SHA256(SECRET_KEY, raw_key). Lookup is O(1). Raw key never stored. Generation uses secrets.token_hex(32) for 256 bits entropy.

---

## Performance Bottlenecks

### Large JSON Deserialization

**Issue:** Ingest routes read entire file (up to 1 MB) into memory before parsing.

**Files:** `api/routes/v1/assets.py` line 179

**Impact:** For bulk operations, parsing large JSON/CSV files is done sequentially in-memory. Extremely large files (1 MB) may cause latency spikes.

**Fix approach:** Stream parsing using json.JSONDecoder.raw_decode() or csv iterator (long-term optimization)

---

### No Connection Pooling Configuration

**Issue:** SQLAlchemy create_engine() uses default pool settings.

**Files:** `cmdb/store.py` line 187, `auth/store.py` line 100

**Impact:** Default pool size (5 connections) may be insufficient under load. No timeout or overflow handling configured.

**Fix approach:** Add pool_size, max_overflow, pool_pre_ping to create_engine() calls for production

---

### KEV Feed Caching TTL

**Issue:** CISA KEV feed is cached for 24 hours. During that window, new exploits won't be detected.

**Files:** `cache/store.py` line 22 (_DEFAULT_TTL = 60*60*24)

**Impact:** Known exploits added to CISA KEV after cache load won't be marked as is_kev=true until next cache expiry.

**Fix approach:** Reduce TTL for KEV (e.g., 6 hours) or implement manual cache invalidation endpoint

---

## Fragile Areas

### Nested JSON Extraction in NVD Response

**Files:** `core/enricher.py` lines 325-338 (_extract_cvss)

**Why fragile:** Assumes specific keys exist in metrics dict (cvssMetricV31, cvssMetricV30, cvssMetricV2). If NVD changes response structure, silent failures occur (details remain empty, no exception).

**Safe modification:**
```python
# Current pattern: dict.get("key") chains without validation
# Better: validate structure before accessing nested keys
if "cvssMetricV31" in metrics:
    entry = metrics["cvssMetricV31"][0]
    cvss_data = entry.get("cvssData", {})
    # ... use cvss_data
```

**Test coverage:** `tests/test_enricher.py` covers _extract_cvss but only with synthetic data. No real NVD response edge cases tested.

---

### CPE String Parsing

**Files:** `core/enricher.py` lines 361-378

**Why fragile:** CPE URI format `cpe:2.3:a:vendor:product:version:...` is split on colons without validation. If CPE format changes or contains unexpected structure, index errors or wrong data extraction occurs.

**Risk:** Low (controlled by NVD data), but brittle to schema changes.

**Safe modification:** Add CPE format validation (check parts length >= 5 before accessing parts[3:5])

---

### Cache Expiry Check on Every Get

**Files:** `cache/store.py` lines 40-52

**Why fragile:** Cache gets called per CVE lookup. Each get() computes `time.time() - cached_at > self.ttl` on every access. Not slow but wasteful for repeated lookups.

**Impact:** Negligible unless thousands of lookups hit cold cache entries simultaneously.

**Fix approach:** Return expired entries as None (current) or implement lazy expiry via separate purge_expired() cron (already implemented at line 62)

---

### Limiter State Not Persisted

**Files:** `api/limiter.py` line 15

**Issue:** `slowapi.Limiter(storage_uri="memory://")` stores rate limit state in-memory. In multi-worker deployments, rate limits are not shared across processes.

**Impact:** Each worker has its own 30-request bucket. With N workers, actual limit becomes 30*N requests per minute (bypass).

**Fix approach:** Switch to Redis-backed storage for distributed rate limiting. Tracked in GitHub issue #47 (Redis-backed rate limiting).

**Status:** Known limitation for single-process dev/test. Production requires fix.

---

## Test Coverage Gaps

### No Integration Tests for CMDB Routes

**Issue:** CMDB routes (POST /assets, PATCH /vulnerabilities/status) have no test coverage.

**Files:**
- `api/routes/v1/assets.py` — untested
- `cmdb/store.py` — repository methods untested
- `cmdb/ingest.py` — parser methods untested

**Risk:** Changes to asset creation flow or ingest parsing won't be caught before merge.

**Priority:** High — CMDB is core to walk phase

**Fix approach:** Add test_assets.py, test_cmdb_store.py, test_ingest.py with 80%+ coverage

**Tracking:** GitHub issue #44 (Expand test suite)

---

### No Auth Route Tests

**Issue:** Auth endpoints (/login, /me, /api-keys, /providers) have no test coverage.

**Files:**
- `api/routes/v1/auth.py` — untested
- `auth/store.py` — untested
- `auth/tokens.py` — JWT encode/decode untested

**Risk:** Auth regression (e.g., token expiry logic, password verify failures) won't be caught.

**Priority:** High — security-critical

**Fix approach:** Add test_auth_routes.py, test_auth_tokens.py with fixtures for users/tokens

**Tracking:** GitHub issue #44 (Expand test suite)

---

### No Web Route Tests

**Issue:** Web template routes have no test coverage.

**Files:** `web/routes.py` — all routes untested

**Risk:** Template rendering errors, form processing bugs won't be caught.

**Priority:** Medium — web UI is secondary to API

**Fix approach:** Add test_web_routes.py with client fixtures

---

### Limited Enricher Test Coverage

**Current:** 80% coverage on core/enricher.py and core/pipeline.py via `tests/test_enricher.py` and `tests/test_pipeline.py`

**Gaps:**
- No real NVD response fixtures (all data is synthetic)
- No edge cases for malformed CVSS vectors, missing weaknesses
- No exposure adjustment scenarios fully tested

**Impact:** Low risk (logic is well-tested on synthetic data) but real-world edge cases may be missed

---

## Dependencies at Risk

### python-jose with CryptographyBackend

**Risk:** `python-jose[cryptography]` requires cryptography >= 3.4. No minimum version specified in requirements.

**Impact:** Older installations may have crypto incompatibilities with JWT operations.

**Fix approach:** Explicitly pin: `python-jose[cryptography]>=3.3.0`

**Tracking:** requirements-api.txt currently has no pinned versions

---

### Bcrypt Version Lock

**Risk:** bcrypt 4.x+ changed internal API. passlib 1.7.4 + bcrypt 4.x known incompatible (wrap-bug detection creates >72 byte password).

**Current mitigation:** Direct bcrypt usage (not passlib) avoids issue. But if passlib is ever added back, requires `bcrypt<4.0` pin.

**Impact:** Accidental passlib addition could break password auth at runtime.

**Fix approach:** Pin bcrypt>=4.0.1 and document "do not use passlib"

---

### No Database Migration Tool

**Risk:** Schema updates are manual SQL in `cmdb/store.py` _migrate_* functions. As schema grows, hand-rolled migrations become error-prone.

**Impact:** Schema versioning is implicit. No rollback capability. Hard to test schema changes in CI.

**Fix approach:** Adopt Alembic for declarative migrations. Tracked in GitHub issue #46 (Alembic schema migrations).

**Tracking:** #46 (run-prep phase)

---

## Missing Critical Features

### No Configuration Management

**Issue:** All config is via environment variables (NVD_API_KEY, SECRET_KEY, DATABASE_URL, etc.). No centralized config validation.

**Files:** `auth/oauth.py` lines 44-84, `core/fetcher.py` line 22, scattered throughout

**Impact:** Missing env var = silent failure or wrong behavior. No schema validation of config values.

**Fix approach:** Create `core/config.py` using pydantic-settings for centralized config validation

**Tracking:** GitHub issue #43 (Central pydantic-settings config)

---

### No Async/Background Job Queue

**Issue:** All processing is synchronous request-response. Bulk ingest routes block the handler until all CVEs are enriched.

**Files:** `api/routes/v1/assets.py` line 248 (process_cves called synchronously)

**Impact:** Large bulk ingest (100+ CVEs) causes request timeout. No background task tracking.

**Fix approach:** Implement job queue (ARQ, Celery) for async CVE processing. Tracked in GitHub issue #52 (task queue).

**Tracking:** #52 (run phase, p3)

---

### No Input Sanitization for Display Fields

**Issue:** Asset fields like `hostname`, `owner`, `tags` are stored and displayed without HTML escaping in templates.

**Files:** `web/templates/` (presumed Jinja2)

**Risk:** Low (internal tool) but hostname could theoretically contain HTML if manually inserted into DB

**Fix approach:** Ensure Jinja2 autoescape=true on template environments. Audit all {{ }} expressions for unsafe content.

---

## Scaling Limits

### SQLite Single-Writer Concurrency

**Issue:** SQLite allows only one writer at a time. With concurrent requests, write-heavy operations serialize.

**Impact:** POST /assets and PATCH /vulnerabilities route latency increases linearly with concurrent users.

**Current capacity:** ~10 concurrent users before queueing on writes

**Scaling path:** Migrate to PostgreSQL (issue #45, run-prep phase). SQLAlchemy abstracts DB details; swapping DB_URL is a config change.

**Tracking:** #45 (Migrate to PostgreSQL)

---

### Memory-Backed Rate Limiter

**Issue:** slowapi with memory:// storage doesn't scale across workers.

**Current capacity:** Single-process dev mode. Production with N workers = N * limit effective rate.

**Scaling path:** Switch to Redis-backed rate limiting (issue #47)

**Tracking:** #47 (Redis-backed rate limiting)

---

### In-Memory KEV Set

**Issue:** CISA KEV feed (1000+ entries) loaded into memory on startup and kept in app.state for the lifetime.

**Impact:** Single-machine only. Distributed deployments need shared KEV cache.

**Current capacity:** ~5000 CVE IDs in-memory = ~500 KB. Negligible.

**Scaling path:** Keep CVE cache in Redis instead of SQLite (issue #48)

**Tracking:** #48 (Redis CVE cache)

---

## Architecture Debt

### Layer Boundary Violations (Future-Proof)

**Status:** Currently clean — no violations detected

**Potential risk:** As more features are added, web/ importing from api/ or api/ reaching into cmdb/ without going through a service layer.

**Prevention:** Pre-commit hook or linter rule to enforce layer imports (not yet implemented)

**Recommendation:** Add ruff rule or manual review gate for cross-layer imports before feature expansions

---

---

*Concerns audit: 2026-02-25*
