# VulnAdvisor — Claude Code Project Guide

## Project Overview

VulnAdvisor is an open-source CVE triage and remediation guidance tool built for vulnerability management teams. It fetches data from free public sources (NVD, CISA KEV, EPSS, PoC-in-GitHub) and returns plain-language triage decisions with no API keys or paywalls required.

Build methodology: crawl / walk / run. Keep changes scoped to the current phase.

---

## Teaching Mode

This repo is being built as a learning project. When working in this codebase:

- **Always explain the why before the how.** Before writing or changing code, explain what pattern or principle is being applied and why it is the right choice here.
- **Name the concept.** If you use a pattern (e.g. separation of concerns, single responsibility, dependency injection), say what it is called so the user can look it up and learn more.
- **Explain trade-offs.** When there are multiple valid approaches, briefly explain what was chosen and what was ruled out and why.
- **Flag learning moments.** If the existing code has something worth noting — a good pattern, a potential improvement, or a common pitfall — point it out even if it is not the main task.
- **Teach on errors.** When something fails (a hook, a test, a runtime error), explain what the error means and why it happened, not just how to fix it.
- **KISS check.** If a proposed solution is getting complex, pause and ask whether there is a simpler approach before proceeding.

---

## Architecture

```
main.py               CLI entry point (argparse)
core/fetcher.py       All external HTTP calls — one function per source
core/enricher.py      Data processing, triage logic, CWE mapping
core/formatter.py     Terminal output and JSON rendering
core/models.py        Dataclasses only — no logic
docs/                 Architecture and project structure reference
```

Each module has a single responsibility. Do not reach across layers.
See `docs/architecture.md` for a full explanation of every design decision.

---

## Coding Standards

- **Python 3.9** — do not use syntax or stdlib features that require 3.10+
- **Formatter:** black (line length 120)
- **Linter:** ruff
- **Import order:** isort
- **Type hints required** on all function signatures
- Use built-in `list`, `dict`, `set` for type hints — not `typing.List`, `typing.Dict`, etc.
- No dynamic imports unless explicitly justified
- No hardcoded secrets, credentials, or API keys
- Use `print()` for user-facing output — this is a CLI tool, not a service

---

## Behavior Rules

- Explain WHY before HOW when proposing changes
- Prefer small, focused changes over large refactors
- Ask before making changes that touch more than one module
- All commits run pre-commit hooks (black, isort, ruff, bandit, pip-audit) — code must pass before committing
- The user writes their own commits unless they explicitly ask otherwise

---

## Safety

- Never hardcode secrets, tokens, or credentials
- Never disable authentication or security checks
- Never bypass pre-commit hooks with --no-verify
- All external data fetching must handle failures gracefully and never raise to the caller

---

## Current Phase: Crawl

The core CLI is complete. Planned crawl-phase additions:
- Bulk CVE input from a file or comma-separated list
- Prioritized summary output for large lists (P1s first, then P2s, etc.)

Walk phase (not yet started):
- Custom priority overrides per user
- Caching layer for repeated lookups and bulk processing
- Web UI

Do not build walk-phase features until crawl is complete and stable.
