# Testing Patterns

**Analysis Date:** 2026-02-25

## Test Framework

**Runner:**
- pytest (configured in `pyproject.toml`)
- Config file: `pyproject.toml` [tool.pytest.ini_options]
- Test paths: `tests/` directory

**Assertion Library:**
- pytest built-in assertions (`assert`, `pytest.raises`)
- No external assertion library (vanilla Python assert)

**Run Commands:**
```bash
pytest tests/                          # Run all tests
pytest tests/test_enricher.py          # Run single file
pytest -v                              # Verbose output with test names
pytest --cov=core.enricher --cov=core.pipeline --cov-report=term-missing  # Coverage report
pytest -x                              # Stop on first failure
pytest -k test_critical                # Run tests matching pattern
```

**Coverage Requirements:**
- Minimum: 80% on `core.enricher` and `core.pipeline`
- Enforced: `--cov-fail-under=80` in pytest config
- Report: term-missing (shows which lines uncovered)

## Test File Organization

**Location:**
- Co-located in `tests/` directory parallel to source
- Pattern: `tests/test_MODULE.py` matches `MODULE.py`
- Examples: `tests/test_enricher.py` (tests `core/enricher.py`), `tests/test_pipeline.py` (tests `core/pipeline.py`)

**Naming:**
- File: `test_*.py`
- Test classes: `TestFunctionName` (PascalCase, "Test" prefix)
- Test methods: `test_description_of_case` (snake_case, "test_" prefix)
- Inline helpers: `_helper_function` (underscore prefix)

**Structure:**
```
tests/
├── __init__.py                  # Empty
├── test_enricher.py             # Tests for core/enricher.py
│   ├── _cve_with_weaknesses()   # Inline data builder (no fixtures)
│   ├── _cpe_match()             # Inline data builder
│   └── TestTriagePriority       # Test class grouping
│       └── test_critical_score_kev_is_p1()
└── test_pipeline.py             # Tests for core/pipeline.py
    ├── _VALID_ID                # Module-level test data constant
    ├── _MINIMAL_CVE_RAW         # Minimal fixture data
    └── TestProcessCve           # Test class grouping
        └── test_invalid_format_raises_value_error()
```

## Test Structure

**Suite Organization:**
```python
"""Unit tests for core/enricher.py — pure logic, no I/O, no mocking needed.

All functions under test are pure (no HTTP calls, no SQLite). Tests call them
directly with inline data — no fixtures or mocking required.
"""

from core.enricher import enrich, _triage_priority
from core.models import CVSSDetails

# --- Inline data helpers — no conftest.py, no fixtures ---

def _cve_with_weaknesses(*cwe_values):
    """Build a minimal CVE dict with the given CWE value(s) in weaknesses."""
    return {"weaknesses": [{"description": [{"value": v} for v in cwe_values]}]}

# --- Test classes group related tests ---

class TestTriagePriority:
    """Tests for _triage_priority(cvss, is_kev, epss_score, has_poc, exposure)."""

    def test_critical_score_kev_is_p1(self):
        cvss = CVSSDetails(score=9.5)
        priority, _, _ = _triage_priority(cvss, is_kev=True, epss_score=None, has_poc=False)
        assert priority == "P1"
```

**Key patterns:**
- No `conftest.py` fixtures for pure logic tests
- Inline data builders with underscore prefix: `_cve_with_weaknesses()`
- Module-level test constants for shared test data: `_VALID_ID`, `_MINIMAL_CVE_RAW`
- Test classes group related tests by function or behavior
- Docstrings explain what is being tested and why (especially for complex triage logic)
- Known tech debt documented in test docstrings as learning notes

## Mocking

**Framework:** unittest.mock (stdlib)

**Patterns:**
```python
from unittest.mock import MagicMock, patch

# Context manager for single function
with patch("core.pipeline.fetch_nvd", return_value=None):
    result = process_cve("CVE-2021-44228", kev_set=set())

# Multiple patches (Python 3.10+ syntax with nested with)
with (
    patch("core.pipeline.fetch_nvd", return_value=_MINIMAL_CVE_RAW),
    patch("core.pipeline.fetch_epss", return_value=_EPSS_DATA),
    patch("core.pipeline.fetch_poc", return_value=_POC_DATA),
):
    result = process_cve(_VALID_ID, kev_set=set(), cache=None)

# Mock object with return values
cache = MagicMock()
cache.get.return_value = None  # cache miss
cache.set.assert_called_once()  # verify call was made

# Assert mock was not called
with patch("core.pipeline.fetch_nvd") as mock_fetch:
    result = process_cve(_VALID_ID, kev_set=set(), cache=cache_with_hit)
mock_fetch.assert_not_called()
```

**What to mock:**
- External HTTP calls: `fetch_nvd()`, `fetch_epss()`, `fetch_poc()`, `fetch_kev()`
- Database calls: cache.get(), cache.set()
- Clock/time: mocked when triage logic depends on dates
- Third-party services: OAuth, Stripe (not present in current tests)

**What NOT to mock:**
- Pure logic functions: call directly with test data
- Data builders: inline create test dicts, don't mock dataclass constructors
- Standard library functions like json.loads, regex matches
- Internal helpers in the same module (import and call directly)

**Mocking philosophy:**
- Test behavior, not implementation
- Mock only I/O and side effects
- Pure functions tested with real inputs/outputs, no mocks
- Mocking increases coupling to implementation; minimize it

## Fixtures and Factories

**Test Data:**
- No pytest fixtures (conftest.py)
- Inline data builders with underscore prefix in test file
- Module-level constants for shared test data

```python
# From tests/test_pipeline.py
_VALID_ID = "CVE-2021-44228"
_MINIMAL_CVE_RAW = {
    "id": _VALID_ID,
    "descriptions": [{"lang": "en", "value": "Test description."}],
    "metrics": {},
    "weaknesses": [],
    "configurations": [],
    "references": [],
}
_EPSS_DATA = {"score": 0.5, "percentile": 0.9}
_POC_DATA = {"has_poc": True, "count": 2, "sources": ["GitHub"]}

# From tests/test_enricher.py
def _cve_with_weaknesses(*cwe_values):
    return {"weaknesses": [{"description": [{"value": v} for v in cwe_values]}]}

def _cve_with_cpe(matches):
    return {"configurations": [{"nodes": [{"cpeMatch": matches}]}]}

def _cpe_match(criteria, vulnerable=True, **kwargs):
    return {"criteria": criteria, "vulnerable": vulnerable, **kwargs}
```

**Location:** Inline in test file at module level, before test classes

**Rationale:** Pure functions tests are simpler with direct data; conftest.py adds indirection

## Coverage

**Requirements:** 80% minimum (enforced via `--cov-fail-under=80`)

**Measured against:**
- `core.enricher`: all triage logic, CWE mappings, CVSS extraction
- `core.pipeline`: fetch-cache-enrich orchestration, deduplication, error handling

**View Coverage:**
```bash
pytest --cov=core.enricher --cov=core.pipeline --cov-report=term-missing
pytest --cov=core.enricher --cov=core.pipeline --cov-report=html  # generates htmlcov/index.html
```

**Coverage gaps (intentional):**
- `core.fetcher`: HTTP calls mocked in integration tests, unit tests not written (future work #44)
- `cache/store.py`: SQLite operations not unit tested (#44)
- `cmdb/store.py`: SQLAlchemy ORM operations not unit tested (#44)
- `api/routes/*.py`: Route handlers not unit tested (#44)
- `auth/`: Auth logic not unit tested (#44)
- `web/`: Template rendering not unit tested (templates tested via integration)

## Test Types

**Unit Tests (primary):**
- Scope: Single function or class
- Location: `tests/test_MODULE.py`
- Mocking: I/O and side effects mocked
- Database: None (pure logic only)
- Examples: `test_triage_priority()`, `test_process_cve_with_cache_hit()`

**Integration Tests:**
- Not yet implemented (issue #44)
- Would test routes + cache + enricher together
- Would use in-memory SQLite for speed

**E2E Tests:**
- Not yet implemented
- Future work: test full CLI flow with real NVD API calls (behind feature flag)

## Common Patterns

**Async Testing:**
Currently no async code in tests (all sync). When FastAPI tests are added:
```python
# Pattern for async route testing (future reference)
import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

def test_get_cve_summary():
    response = client.get("/cve/summary?ids=CVE-2021-44228")
    assert response.status_code == 200
```

**Error Testing:**
```python
# Test ValueError raised on invalid input
def test_invalid_format_raises_value_error(self):
    with pytest.raises(ValueError, match="Invalid CVE ID format"):
        process_cve("not-a-cve", kev_set=set())

# Test return None on external failure
def test_nvd_not_found_returns_none(self):
    with patch("core.pipeline.fetch_nvd", return_value=None):
        result = process_cve(_VALID_ID, kev_set=set())
    assert result is None
```

**Boundary Testing:**
```python
# Test score boundaries for triage priority
def test_critical_boundary_score_kev_is_p1(self):
    cvss = CVSSDetails(score=9.0)  # Boundary: score == 9.0
    priority, _, _ = _triage_priority(cvss, is_kev=True, epss_score=None, has_poc=False)
    assert priority == "P1"

def test_score_7_boundary_kev_is_p2(self):
    cvss = CVSSDetails(score=7.0)  # Boundary: score == 7.0
    priority, _, _ = _triage_priority(cvss, is_kev=True, epss_score=None, has_poc=False)
    assert priority == "P2"
```

**State Verification:**
```python
# Verify cache was called correctly
def test_cache_miss_calls_fetchers_and_stores(self):
    cache = MagicMock()
    cache.get.return_value = None

    with (
        patch("core.pipeline.fetch_nvd", return_value=_MINIMAL_CVE_RAW),
        patch("core.pipeline.fetch_epss", return_value=_EPSS_DATA),
        patch("core.pipeline.fetch_poc", return_value=_POC_DATA),
    ):
        result = process_cve(_VALID_ID, kev_set=set(), cache=cache)

    cache.set.assert_called_once()  # Verify set() was called
    assert result is not None
    assert result.id == _VALID_ID
```

**Private Function Testing:**
Testing private (underscore-prefixed) functions is intentional in this codebase:
```python
# From tests/test_enricher.py docstring:
# "Learning note: testing private (_underscore) functions directly is intentional
# here. _triage_priority is the most critical logic path and deserves targeted
# coverage independent of the full enrich() orchestrator."
```

This is a deliberate trade-off: private functions test the most critical logic in isolation, accepting coupling to implementation details.

## Pre-commit Hooks

**Automated checks before each commit:**
1. black — code formatting
2. isort — import ordering
3. ruff — linting (E, F, B, UP, I, S, C4 rules)
4. bandit — security scanning
5. pip-audit — dependency vulnerability scanning

**Install hooks:**
```bash
pre-commit install
```

**Run manually:**
```bash
pre-commit run --all-files
```

**Bypass (not recommended):**
```bash
git commit --no-verify  # Unsafe — breaks code quality guardrails
```

---

*Testing analysis: 2026-02-25*
