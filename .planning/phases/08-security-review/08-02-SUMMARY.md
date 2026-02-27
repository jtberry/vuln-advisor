---
phase: 08-security-review
plan: 02
subsystem: infra
tags: [csp, security-headers, caddy, gitignore]

# Dependency graph
requires:
  - phase: 06-containerization
    provides: Caddyfile with existing HSTS/X-Frame-Options/X-Content-Type-Options/Referrer-Policy headers
provides:
  - Content-Security-Policy header in Caddyfile allowing cdn.jsdelivr.net and unpkg.com CDN origins
  - SECURITY.md at repo root with vulnerability reporting policy and security practices summary
  - Audited .gitignore verified clean for public release; .planning/ exposure documented for user decision
affects: [public-release, v1.0]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "CSP with unsafe-inline as documented trade-off for data island script pattern; nonce-based upgrade tracked as tech debt"
    - "SECURITY.md follows GitHub security advisory template conventions"

key-files:
  created:
    - SECURITY.md
  modified:
    - Caddyfile

key-decisions:
  - "unsafe-inline retained in script-src: required for tojson data island pattern in dashboard.html and session expiry script in layout.html; nonce-based CSP is the clean upgrade path and is tracked as tech debt"
  - "unpkg.com added to script-src alongside cdn.jsdelivr.net: htmx loads from unpkg.com, not jsdelivr"
  - ".planning/ is tracked in git and contains strategic planning artifacts; this is user's decision to make before public release -- not auto-added to .gitignore"

patterns-established:
  - "Security header comments in Caddyfile explain why unsafe-inline is present -- no silent suppressions"

requirements-completed: [SEC-01]

# Metrics
duration: 2min
completed: 2026-02-27
---

# Phase 08 Plan 02: Security Headers and Disclosure Policy Summary

**CSP header added to Caddyfile allowing cdn.jsdelivr.net/unpkg.com CDN origins; SECURITY.md created with responsible disclosure policy; .gitignore audited clean**

## Performance

- **Duration:** ~2 min
- **Started:** 2026-02-27T16:26:21Z
- **Completed:** 2026-02-27T16:28:06Z
- **Tasks:** 2
- **Files modified:** 2 modified, 1 created

## Accomplishments
- Added Content-Security-Policy header to Caddyfile; allows Bootstrap, Chart.js (cdn.jsdelivr.net) and htmx (unpkg.com) with documented unsafe-inline trade-off
- Created SECURITY.md with responsible disclosure instructions (GitHub private advisory), security practices summary, and out-of-scope definitions
- Audited .gitignore: all sensitive patterns already present (.env, *.db, venv/, __pycache__/, .claude/); no changes needed
- Confirmed no Claude session or memory files tracked in git (only CLAUDE.md which is intentional)
- Documented .planning/ tracked status for user decision before public release

## Task Commits

Each task was committed atomically:

1. **Task 1: Add CSP header to Caddyfile** - `5855027` (feat)
2. **Task 2: Create SECURITY.md and audit .gitignore** - `d35c02d` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified
- `Caddyfile` - Added Content-Security-Policy header with cdn.jsdelivr.net, unpkg.com, unsafe-inline trade-off documented in comments
- `SECURITY.md` - New public security policy file at repo root with reporting process and security practices

## Decisions Made

- **unsafe-inline in script-src:** The dashboard uses a data island pattern (server-side `{{ priority_counts | tojson }}` injected into a `<script>` block) and layout.html has an inline session expiry script. Both require `'unsafe-inline'`. This is a known, documented trade-off. The clean upgrade path is nonce-based CSP injection on every request, tracked as tech debt.
- **unpkg.com in script-src:** htmx is loaded from `https://unpkg.com/htmx.org@1.9.12` in layout.html, not from cdn.jsdelivr.net. Both CDN origins required in `script-src`.
- **.planning/ exposure left for user decision:** `.planning/` is currently tracked in git and contains full product strategy, roadmap, phase plans, and research. Per plan instructions, this was not auto-added to .gitignore. The user should decide before public release whether to remove it from git history or leave it as-is.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## .planning/ Exposure Note

**User decision required before public release:**

Running `git ls-files .planning/` confirms the `.planning/` directory is tracked. It contains:
- `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md` - project management artifacts
- Phase plan and summary files - full development roadmap and decisions

This directory is already excluded in `.gitignore` on developer workstations (preventing accidental new commits), but the files already committed remain in git history.

Options before public release:
1. Leave as-is (open source project, planning artifacts are public anyway)
2. Remove with `git filter-branch` or `git filter-repo` to clean history
3. Add to a new commit that removes it from tracking (`git rm -r --cached .planning/`)

## Next Phase Readiness

- Security header hardening complete; Caddyfile now has all 5 major headers
- SECURITY.md ready for GitHub to display in the Security tab
- Repo is clean of sensitive files and Claude working artifacts
- Ready for Plan 03: findings report and final review

---
*Phase: 08-security-review*
*Completed: 2026-02-27*
