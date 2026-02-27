---
phase: 07-code-quality
plan: 02
subsystem: stores
tags: [deduplication, logging, semgrep, sqlite, cleanup]

requires:
  - phase: 07-code-quality
    provides: "Centralized now_iso() and set_wal_mode() in core/config.py"
provides:
  - "Clean cmdb/ and auth/ packages with no duplicated helpers"
  - "Consistent __name__ loggers across all store modules"
  - "Semgrep finding suppressed with safety explanation in auth/store.py"
affects: [07-03]

tech-stack:
  added: []
  patterns: [centralized utility imports from core/config, nosemgrep inline suppression for safe dynamic SQL]

key-files:
  created: []
  modified: [cmdb/store.py, cmdb/ingest.py, auth/store.py, auth/tokens.py, auth/oauth.py]

key-decisions:
  - "auth/store.py layer rule updated to allow core/ imports for shared utilities (now_iso, set_wal_mode)"
  - "nosemgrep suppression placed as standalone comment line above the conn.execute() call for readability"
  - "verify_password except block now logs warning with error message for fail-safe auth debugging"

patterns-established:
  - "All store modules import now_iso() and set_wal_mode() from core.config instead of defining local copies"
  - "Logger naming: logger = logging.getLogger(__name__) in all modules that log"

requirements-completed: [QUAL-01, QUAL-02, QUAL-03]

duration: 5min
completed: 2026-02-27
---

# Phase 7 Plan 02: Store Layer Cleanup Summary

**Deduplicated _now_iso() and _set_wal_mode() across cmdb/ and auth/, standardized all loggers to __name__, and suppressed semgrep finding with safety explanation**

## Performance

- **Duration:** 5 min
- **Started:** 2026-02-27T15:34:52Z
- **Completed:** 2026-02-27T15:39:23Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments
- Removed 5 duplicate helper definitions (_now_iso x3, _set_wal_mode x2) and replaced with imports from core.config
- Fixed inline `import logging` inside function body in cmdb/store.py -- moved to module level
- Standardized hardcoded logger names in auth/tokens.py ("vulnadvisor.auth") and auth/oauth.py ("vulnadvisor.auth.oauth") to __name__
- Added nosemgrep suppression with safety explanation on the dynamic SQL in auth/store.py update_app_settings
- Added error logging to verify_password's bare except block

## Task Commits

Each task was committed atomically:

1. **Task 1: Deduplicate helpers and clean cmdb/ package** - `845c1fe` (refactor)
2. **Task 2: Clean auth/ package -- loggers, deduplication, semgrep suppression** - `3c925b0` (refactor)

## Files Created/Modified
- `cmdb/store.py` - Replaced _now_iso()/_set_wal_mode() with core.config imports, added module-level logger, removed inline import
- `cmdb/ingest.py` - Replaced _now_iso() with core.config import, removed unused datetime imports
- `auth/store.py` - Replaced _now_iso()/_set_wal_mode() with core.config imports, added nosemgrep suppression, updated layer rule docstring
- `auth/tokens.py` - Changed logger from hardcoded "vulnadvisor.auth" to __name__, added warning log to verify_password except block
- `auth/oauth.py` - Changed logger from hardcoded "vulnadvisor.auth.oauth" to __name__

## Decisions Made
- Updated auth/store.py layer rule docstring to explicitly allow core/ imports for shared utilities -- this is consistent with auth/tokens.py and auth/oauth.py which already import from core/
- nosemgrep suppression uses a standalone comment line above the execute() call rather than trailing inline, because black reformatted the expression to multi-line
- verify_password logs at WARNING level (not ERROR) because auth failures are expected operational events, not system errors

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- All cmdb/ and auth/ modules are clean with consistent patterns
- Plan 03 can proceed with api/ and web/ layer cleanup on the same foundation

---
*Phase: 07-code-quality*
*Completed: 2026-02-27*
