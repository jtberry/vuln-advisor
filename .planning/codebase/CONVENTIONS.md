# Coding Conventions

**Analysis Date:** 2026-02-25

## Naming Patterns

**Files:**
- Lowercase with underscores: `fetcher.py`, `enricher.py`, `pipeline.py`
- API route files: `cve.py`, `assets.py`, `auth.py` (one route per file)
- Test files: `test_enricher.py`, `test_pipeline.py` (match module under test)
- Private module-level helpers: prefixed with underscore: `_CVE_RE`, `_load_file()`, `_triage_priority()`

**Functions:**
- camelCase for public functions: `process_cve()`, `fetch_nvd()`, `enrich()`
- snake_case prefix with underscore for private helpers: `_triage_priority()`, `_extract_cvss()`, `_build_remediation()`
- Descriptive names that indicate purpose: `apply_criticality_modifier()`, `parse_trivy_json()`
- Verb-first pattern for actions: `fetch_*`, `process_*`, `parse_*`, `get_*`, `create_*`, `update_*`

**Variables:**
- snake_case: `cve_id`, `epss_score`, `has_poc`, `kev_set`
- Constants in UPPER_CASE: `NVD_API`, `CISA_KEV_URL`, `CVE_PATTERN`, `_DEFAULT_TTL`
- Private module-level constants prefixed with underscore: `_NVD_API_KEY`, `_session`, `_DEFAULT_DB`
- Dataclass fields use lowercase: `score`, `severity`, `vector`, `attack_vector`

**Types:**
- Dataclass names use PascalCase: `CVSSDetails`, `EnrichedCVE`, `PoCInfo`, `RemediationStep`
- Enum classes use PascalCase: `ExposureEnum`, `PriorityEnum`
- Generic type hints use built-in types: `dict[str, Any]`, `list[str]`, `set[str]`, `Optional[dict]`
- No `typing.List`, `typing.Dict`, `typing.Set` — use built-in generics (Python 3.9+)

**Class structure:**
- Logger instances named `logger` or `_log`: `logger = logging.getLogger(__name__)` or `_log = logging.getLogger(__name__)`
- Module-level logger uses qualified name: `logging.getLogger("vulnadvisor.fetcher")`
- Private class methods use underscore prefix in method name: `_delete()`, `_migrate_assets_table()`

## Code Style

**Formatting:**
- Tool: black (configured in `pyproject.toml`)
- Line length: 120 characters
- Target version: Python 3.9

**Linting:**
- Tool: ruff
- Rules enforced: E, F, B, UP, I, S, C4 (see `pyproject.toml` [tool.ruff.lint] select)
- Ignored rules:
  - S101: assert statements allowed in test and non-test code
  - S311: standard pseudo-random acceptable (not used for crypto)
  - B008: FastAPI `Depends()` in default args is canonical pattern, not a bug
- Per-file ignores: security rules (S) ignored in `tests/**` files
- Pre-commit hooks: black, isort, ruff, bandit, pip-audit

**Import Organization:**

1. **Order:** Standard library, third-party, local imports (enforced by isort)
   ```python
   import logging
   import os
   from datetime import datetime
   from typing import Optional

   import requests
   from fastapi import APIRouter

   from cache.store import CVECache
   from core.pipeline import process_cve
   ```

2. **Conditional imports:** Use TYPE_CHECKING for forward references to avoid circular dependencies
   ```python
   from typing import TYPE_CHECKING
   if TYPE_CHECKING:
       from auth.models import User
       from auth.store import UserStore
   ```

3. **Relative imports:** Not used. Always use absolute imports from package root: `from core.models import EnrichedCVE` (not `from ..models import`)

4. **Star imports:** Never used. Always explicit: `from api.models import CVE_PATTERN, BulkRequest`

5. **Import aliases:** Used when module name conflicts or for brevity:
   ```python
   from dataclasses import asdict
   from core.fetcher import fetch_nvd as fetch_nvd_api
   ```

## Error Handling

**Return None on external failure:**
- All HTTP fetchers return `Optional[dict]`, not raise: `fetch_nvd()`, `fetch_kev()`, `fetch_epss()`, `fetch_poc()`
- Exception caught at source, logged to module logger, returns None/empty gracefully:
  ```python
  except requests.RequestException as e:
      logger.warning("NVD fetch failed for %s: %s", cve_id, e)
      return None
  ```

**Raise only for programmer errors:**
- Format validation in pipeline: `process_cve()` raises `ValueError` for invalid CVE ID format
- Validation happens before any external calls (input validation at boundary)
- API layer converts exceptions to HTTP responses via FastAPI exception handlers

**Database operations:**
- SQLAlchemy IntegrityError caught in routes, converted to HTTP 400/409
- Cache operations fail silently (log warnings, continue)

**No silent failures in core:**
- Pure logic functions like `enrich()` raise if data structure is malformed (programming error, not data error)
- This keeps invalid state from propagating through the system

## Logging

**Framework:** Python standard library `logging` module

**Logger names:**
- Module level: `logging.getLogger("vulnadvisor.LAYER")` where LAYER is `fetcher`, `enricher`, `api`, `auth`, `web`
- Private variable: `_log = logging.getLogger(__name__)` only in `core/enricher.py`
- Public variable: `logger = logging.getLogger(...)` everywhere else

**Patterns:**
- External API failures: `logger.warning("Message", cve_id, exception)` — never raise
- Important state transitions: `logger.info(...)` — guard initialization, service startup
- Sensitive operations (auth, crypto, crypto validation): log action name only, no secrets
- Debug details: `logger.debug(...)` — only in critical paths if added later

**Example from `core/fetcher.py`:**
```python
except requests.RequestException as e:
    logger.warning("NVD fetch failed for %s: %s", cve_id, e)
    return None
```

## Comments

**When to comment:**
- Complex algorithms: comment the triage decision logic in `_triage_priority()`
- Non-obvious state transitions: comment why a field is computed fresh (e.g., "exposure is runtime context, not cached")
- Trade-offs and known limitations: "This is a known bcrypt limitation" — explains why code is written that way
- Block boundaries: separator comments using `# -----------` (40 chars) to group related functions

**JSDoc/TSDoc style:**
- Function docstrings are triple-quoted Python docstrings, not JSDoc
- Format: one-line summary, blank line, detailed description, Args/Raises section
  ```python
  def process_cve(
      cve_id: str,
      kev_set: set[str],
      cache: Optional[CVECache] = None,
      exposure: str = "internal",
      nvd_api_key: Optional[str] = None,
  ) -> Optional[EnrichedCVE]:
      """Fetch, cache, and enrich a single CVE. Returns None if the CVE is not found.

      Args:
          cve_id:      CVE identifier, e.g. "CVE-2021-44228".
          kev_set:     Set of CVE IDs from the CISA KEV catalog.
          cache:       Optional SQLite cache. Pass None to disable caching.
          exposure:    Asset exposure context: "internet", "internal", or "isolated".
          nvd_api_key: Optional NVD API key for higher rate limits.

      Raises ValueError if cve_id does not match the expected format.
      No print statements — all side effects belong to the caller.
      """
  ```

**Module docstrings:**
- One-line purpose at top of file, blank line, detailed explanation if needed:
  ```python
  """
  core/enricher.py — Takes raw fetched data and enriches it into a structured,
  plain-language EnrichedCVE ready for output.
  """
  ```

## Function Design

**Size guideline:** Functions should fit on one screen (~50 lines). Longer logic is extracted into smaller helpers.

**Parameters:**
- Type hints required on all parameters, including defaults
- Maximum 5-6 parameters; use dataclasses or dicts if more needed
- Required params first, then optional params with defaults

**Return values:**
- Always typed: `-> Optional[EnrichedCVE]`, `-> list[str]`, `-> dict[str, int]`
- Use `Optional[T]` not `T | None` (Python 3.9 compatibility)
- Return None on failure (not empty list/dict) for optional operations
- Consistent return type on all paths (no implicit None return)

**Pure functions preferred in core:**
- No print statements in `core/`, `cache/`, `cmdb/`
- No print in `api/` routes (use logging or response bodies)
- All side effects (I/O, printing) belong to orchestration layer (`main.py`, route handlers)
- Functions in `core/pipeline.py` document "No print statements — all side effects belong to the caller"

**Default arguments:**
- FastAPI `Depends()` allowed in route defaults (B008 rule ignored)
- Regular functions use None and create internally: `cache: Optional[CVECache] = None`
- No mutable defaults: never use `list[]` or `dict{}` as defaults

## Module Design

**Exports:**
- No `__all__` declarations; import what you need explicitly
- Barrel files (`__init__.py`) left empty or import only for convenience, never re-export everything

**Layering:**
- `core/` imports: only stdlib and requests
- `cache/` imports: core/ and stdlib
- `cmdb/` imports: stdlib, sqlalchemy, core/
- `api/` imports: stdlib, fastapi, sqlalchemy, core/, cache/, cmdb/, auth/
- `auth/` imports: stdlib, external auth libraries (bcrypt, jose, authlib)
- `web/` imports: stdlib, jinja2, fastapi (via starlette)
- Never sideways: `api/` and `web/` don't import each other

**Separation of concerns:**
- `core/models.py`: dataclasses only, zero logic
- `core/fetcher.py`: HTTP calls only, one function per data source
- `core/enricher.py`: pure triage and formatting logic
- `api/models.py`: Pydantic v2 models for HTTP contract (separate from core/models)
- `cache/store.py`: SQLite cache with parameterized queries only
- `cmdb/store.py`: Asset inventory via SQLAlchemy Core

---

*Convention analysis: 2026-02-25*
