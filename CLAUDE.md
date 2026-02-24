# VulnAdvisor — Contributor Guide

## Project Overview

VulnAdvisor is an open-source CVE triage and remediation guidance tool built for vulnerability management teams. It fetches data from free public sources (NVD, CISA KEV, EPSS, PoC-in-GitHub) and returns plain-language triage decisions with no API keys or paywalls required.

See `docs/architecture.md` for a full explanation of the design and every module's role.

---

## Architecture

```
main.py               CLI entry point (argparse)
core/                 Engine — fetching, enrichment, triage, formatting
  fetcher.py          All external HTTP calls — one function per source
  enricher.py         Data processing, triage logic, CWE mapping
  formatter.py        Terminal output and JSON rendering
  models.py           Dataclasses only — no logic
api/                  REST API layer — walk phase (FastAPI)
  main.py             App entry point
  routes/v1/cve.py    CVE lookup endpoints
cache/                SQLite cache layer — walk phase
  store.py            TTL-based cache for enriched CVE data
web/                  Web UI — walk phase (templates)
docs/                 Architecture and project structure reference
```

Each module has a single responsibility. `core/` knows nothing about `api/` or `web/`. Do not reach across layers.

---

## Branch Strategy

```
main        Always stable and tagged. Reflects the latest release.
develop     Active integration branch. All feature PRs target develop.
feature/*   Short-lived feature branches cut from develop.
```

- Cut feature branches from `develop`, not `main`
- PRs merge into `develop` for integration
- `develop` merges into `main` as a tagged release (v0.2.0, etc.)
- `main` is never force-pushed

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

## Dev Setup

```bash
git clone https://github.com/jtberry/vuln-advisor.git
cd vuln-advisor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
pre-commit install
```

All commits run pre-commit hooks automatically (black, isort, ruff, bandit, pip-audit). Code must pass all hooks before a commit is accepted.

---

## Safety Rules

- Never hardcode secrets, tokens, or credentials
- Never disable authentication or security checks
- Never bypass pre-commit hooks with --no-verify
- All external data fetching must handle failures gracefully and never raise to the caller

---

## Contributing

Please open an issue before starting work on a significant change. This keeps effort aligned and avoids duplicate work. See `docs/architecture.md` before making structural changes.
