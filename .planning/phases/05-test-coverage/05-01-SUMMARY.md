---
phase: 05-test-coverage
plan: 01
subsystem: testing
tags: [pytest, csv-injection, cwe-1236, ingest, conftest, fixtures]

# Dependency graph
requires:
  - phase: 02-data-layer
    provides: cmdb/ingest.py parsers (parse_csv, parse_trivy_json, parse_grype_json, parse_nessus_csv)
  - phase: 01-auth-foundation
    provides: UserStore, CMDBStore, auth tokens -- needed by shared conftest.py fixtures
provides:
  - tests/conftest.py shared fixtures for all integration test plans
  - Unit test coverage for all four ingest parsers (csv, trivy, grype, nessus)
  - CSV formula injection regression tests (CWE-1236)
  - _sanitize_csv_cell() sanitizer in core/formatter.py
affects: 05-test-coverage plans 02 and beyond (use api_client / web_client fixtures from conftest.py)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Named shared-memory SQLite URIs for thread-safe in-memory test isolation
    - _patch_lifespan() pattern for replacing FastAPI lifespan with test doubles
    - TDD Red-Green cycle: injection tests written before sanitizer existed

key-files:
  created:
    - tests/conftest.py
    - tests/test_ingest.py
    - tests/test_csv_formula_injection.py
  modified:
    - core/formatter.py

key-decisions:
  - "Named SQLite URIs (file:name?mode=memory&cache=shared&uri=true) over plain :memory: -- TestClient uses thread pool; plain :memory: gives each thread a blank schema"
  - "Tab-prefix sanitization (OWASP recommended) over single-quote prefix -- universally handled across Excel, LibreOffice, and Google Sheets"
  - "Module-level _FORMULA_PREFIXES tuple -- referenced by both _sanitize_csv_cell() and tests without coupling to function internals"
  - "TDD contract for injection tests: 4 dangerous-prefix tests intentionally fail in Task 1 red phase, pass after Task 2 adds sanitizer"

patterns-established:
  - "conftest _patch_lifespan() pattern: replace app.router.lifespan_context with asynccontextmanager that wires test stores into app.state"
  - "scope='module' fixtures: one TestClient per test module for speed; cheaper than per-test client startup"
  - "follow_redirects=False for web_client: assert on redirect locations before they resolve"

requirements-completed: [DEBT-04]

# Metrics
duration: 6min
completed: 2026-02-26
---

# Phase 5 Plan 01: Test Foundation and CSV Injection Fix Summary

**Shared pytest fixtures (conftest.py), 24 ingest parser unit tests, and tab-prefix CSV injection sanitizer (CWE-1236) in core/formatter.py**

## Performance

- **Duration:** 6 min
- **Started:** 2026-02-26T00:27:03Z
- **Completed:** 2026-02-26T00:32:57Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Created tests/conftest.py with thread-safe named shared-memory SQLite fixtures (_make_test_stores, _patch_lifespan, api_client, web_client) that Plan 02 integration tests will use
- Created tests/test_ingest.py with 24 unit tests covering all four parsers (csv, trivy, grype, nessus) for valid input, invalid input, and edge cases -- all pass
- Created tests/test_csv_formula_injection.py with 6 regression tests for CWE-1236 formula injection using TDD: 4 dangerous-prefix tests drove the Task 2 implementation
- Fixed CSV injection vulnerability in core/formatter.py: added _sanitize_csv_cell() with tab-prefix sanitization applied to remediation_summary in to_csv()
- Full test suite: 152 tests passing, zero regressions

## Task Commits

Each task was committed atomically:

1. **Task 1: Create conftest.py, ingest tests, and CSV formula injection regression tests** - `22bd440` (test)
2. **Task 2: Implement _sanitize_csv_cell() in formatter.py** - `6be8335` (feat)

**Plan metadata:** (created below)

_Note: Task 1 is the TDD red phase -- 4 injection tests intentionally fail. Task 2 is the green phase -- all 6 pass after sanitizer is added._

## Files Created/Modified

- `tests/conftest.py` - Shared pytest fixtures: _make_test_stores, _patch_lifespan, api_client (scope=module), web_client (scope=module, follow_redirects=False)
- `tests/test_ingest.py` - 24 unit tests for parse_csv, parse_trivy_json, parse_grype_json, parse_nessus_csv covering valid input, invalid input, and edge cases
- `tests/test_csv_formula_injection.py` - 6 regression tests for CWE-1236: 4 dangerous-prefix tests (=, +, -, @) and 2 safe-value tests (unchanged text, empty remediation)
- `core/formatter.py` - Added _FORMULA_PREFIXES tuple, _sanitize_csv_cell() helper, applied sanitizer to remediation_summary in to_csv()

## Decisions Made

- Named shared-memory SQLite URIs instead of plain `:memory:`: TestClient runs handlers in a thread pool; each thread connection to `:memory:` gets a blank schema. Named URIs share one in-memory instance across all connections in the same process.
- Tab-prefix sanitization per OWASP CWE-1236 guidance: `\t` prefix forces text interpretation in Excel, LibreOffice, and Google Sheets. Single-quote prefix behavior varies by application.
- `_FORMULA_PREFIXES` as module-level constant: both `_sanitize_csv_cell()` and test files can reference it directly. Avoids magic strings scattered across the codebase.
- `scope="module"` for api_client and web_client fixtures: one client per test module. Cheaper than per-test startup; appropriate since tests within a module share a common state (same admin user, same stores).

## Deviations from Plan

None - plan executed exactly as written.

The one pre-commit correction was formatting (black, isort, ruff) and removal of an unused variable left from an intermediate draft of the Nessus test. This is normal hook behavior, not a deviation.

## Issues Encountered

- Pre-commit hooks (black, isort, ruff) reformatted the initial commit on first attempt. Corrected unused variable (F841) in test_ingest.py and re-staged. Commit succeeded on second attempt. No code logic changes.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- conftest.py fixtures are ready for Plan 02 API integration tests (api_client, web_client)
- All ingest parsers have unit test coverage -- regression baseline established
- CSV injection fix is in place -- remediation_summary column is safe for all four formula prefix characters
- No blockers for Plan 02

---
*Phase: 05-test-coverage*
*Completed: 2026-02-26*
