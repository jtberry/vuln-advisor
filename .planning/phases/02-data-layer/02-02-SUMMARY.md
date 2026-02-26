---
phase: 02-data-layer
plan: 02
subsystem: cmdb
tags: [status-workflow, regression-detection, audit-trail, typed-api, migration]
dependency_graph:
  requires: [02-01]
  provides: [status-workflow, regression-detection, is_regression-column, typed-patch-response]
  affects: [cmdb/store.py, cmdb/models.py, api/models.py, api/routes/v1/assets.py]
tech_stack:
  added: []
  patterns: [ordinal-map, repository-pattern, typed-api-response, append-only-audit-trail]
key_files:
  created: []
  modified:
    - cmdb/models.py
    - cmdb/store.py
    - api/models.py
    - api/routes/v1/assets.py
decisions:
  - "[02-02]: _STATUS_ORDER ordinal map over full state machine library -- linear workflow with one exit lane (deferred) does not need a graph; index comparison is sufficient and has zero deps"
  - "[02-02]: Soft enforcement -- all transitions allowed, backwards transitions flagged not blocked -- analysts need to be able to re-open items; compliance requires the regression to be recorded, not prevented"
  - "[02-02]: from_status passed by caller not fetched inside transaction -- avoids a second DB round-trip; caller (route handler) already holds the current vuln record"
  - "[02-02]: update_vuln_status returns tuple (updated, is_regression) -- route handler needs both values; Python tuples are idiomatic for this; avoids wrapper dataclass"
metrics:
  duration: 4 min
  completed_date: "2026-02-26"
  tasks_completed: 2
  files_modified: 4
  commits: 2
requirements_satisfied: [STAT-01, STAT-02]
---

# Phase 2 Plan 02: Status Workflow Overhaul Summary

**One-liner:** Analyst-friendly status names (open/in_review/remediated) with ordinal-map regression detection, is_regression audit column, and typed Pydantic PATCH response replacing untyped dict.

## What Was Built

The status workflow was overhauled end-to-end:

1. **Status vocabulary renamed** - Developer jargon (pending, in_progress, verified) replaced with analyst-friendly names (open, in_review, remediated). closed and deferred retained as-is.

2. **Regression detection** - `_is_regression(from_status, to_status)` uses an ordinal map (`_STATUS_ORDER`) to classify transitions. Any backward movement is a regression. Transitions to `deferred` are never regressions (valid exit from any state). Transitions from any terminal state (closed, deferred) back to an active state are always regressions.

3. **Audit trail enriched** - `is_regression` column added to `remediation_records` table. Every status change row now records whether it was a regression. History is still append-only.

4. **Typed API response** - PATCH handler now returns `VulnStatusUpdateResponse` (Pydantic model) instead of an untyped dict. Response includes full `remediation_history` list and top-level `is_regression` flag for easy UI highlighting.

5. **DB migration** - `_migrate_remediation_table()` adds the `is_regression` column to existing DBs. `_migrate_status_values()` renames existing rows from old to new vocabulary. Both are idempotent (safe to re-run).

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | Status workflow, regression detection, migrations | 427239e | cmdb/store.py, cmdb/models.py |
| 2 | Typed response models and updated PATCH handler | d88fd48 | api/models.py, api/routes/v1/assets.py |

## Decisions Made

**Ordinal map over state machine library**
`_STATUS_ORDER = {"open": 0, "in_review": 1, "remediated": 2, "closed": 3}`. This is the simplest correct approach for a linear workflow. A state machine library (e.g. `transitions`) would add a dependency and a DSL for no benefit. Index comparison (`to_idx < from_idx`) is three lines.

**Soft enforcement - flag, don't block**
Any transition is accepted; backward transitions are recorded with `is_regression=True`. Analysts regularly re-open items due to failed patches or new evidence. Blocking the transition would cause workflow friction. Compliance requirement is met by recording the fact, not preventing it.

**Deferred as terminal exit, not ordinal rank**
`deferred` is excluded from `_STATUS_ORDER`. It is not a step in the remediation progression - it is an exit. Transitioning to deferred from any state (including remediated or closed) means "we accept this risk / it is not applicable." Re-activating a deferred item IS a regression (re-opening a terminal decision).

**`from_status` passed by caller**
Route handler already holds the current `vuln` record (fetched for the 404 check). Passing `from_status=vuln.status` avoids a second SELECT inside the transaction. Clean and efficient.

## Regression Logic Summary

| From | To | Regression? | Reason |
|------|----|-------------|--------|
| open | in_review | No | Forward |
| in_review | remediated | No | Forward |
| remediated | closed | No | Forward |
| open | deferred | No | deferred is never regression |
| in_review | deferred | No | deferred is never regression |
| remediated | in_review | Yes | Backward (index 2 -> 1) |
| closed | open | Yes | Terminal state re-opened |
| deferred | open | Yes | Terminal state re-opened |
| deferred | in_review | Yes | Terminal state re-opened |

## Deviations from Plan

None - plan executed exactly as written.

## Self-Check

Files created/modified:
- [x] cmdb/models.py - is_regression field, status default updated
- [x] cmdb/store.py - _STATUS_ORDER, _is_regression(), migrations, updated methods
- [x] api/models.py - VulnStatusEnum updated, RemediationHistoryRow, VulnStatusUpdateResponse
- [x] api/routes/v1/assets.py - typed PATCH handler, status="open" in assign_vulnerabilities

Commits:
- [x] 427239e - Task 1 (store + models)
- [x] d88fd48 - Task 2 (api models + route handler)

Tests: 97 passed, 0 failed. Coverage: 100%.

## Self-Check: PASSED
