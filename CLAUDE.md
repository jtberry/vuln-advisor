# VulnAdvisor — Contributor Guide

## Project Overview

VulnAdvisor is an open-source CVE triage and remediation guidance tool built for vulnerability management teams. It fetches data from free public sources (NVD, CISA KEV, EPSS, PoC-in-GitHub) and returns plain-language triage decisions with no API keys or paywalls required.

See `docs/architecture.md` for a full explanation of the design and every module's role.

---

## Architecture

```
main.py               CLI entry point (argparse)
core/                 Engine -- fetching, enrichment, triage, formatting
  config.py           Centralized settings (env vars, SECRET_KEY validation)
  pipeline.py         Pure process_cve() + process_cves() -- shared by CLI and API
  fetcher.py          All external HTTP calls -- one function per source
  enricher.py         Data processing, triage logic, CWE mapping
  formatter.py        Terminal + JSON + CSV/HTML/Markdown export
  models.py           Dataclasses only -- no logic
auth/                 Authentication layer -- consumed by api/ and web/
  models.py           User and ApiKey dataclasses
  store.py            UserStore -- SQLAlchemy Core, user/API key CRUD
  tokens.py           JWT, bcrypt hashing, API key gen (HMAC-SHA256)
  oauth.py            Authlib OAuth registry (GitHub, Google/OIDC)
  dependencies.py     FastAPI Depends -- try_get_current_user, require_admin
cmdb/                 Asset and vulnerability tracking
  models.py           Asset, AssetVulnerability, RemediationRecord
  store.py            CMDBStore -- SQLAlchemy Core, criticality modifiers
  ingest.py           Scanner parsers -- CSV, Trivy, Grype, Nessus
api/                  REST API layer (FastAPI)
  main.py             App entry point, middleware, exception handlers
  limiter.py          Shared slowapi rate limiter
  models.py           Pydantic v2 request/response models
  routes/v1/cve.py    CVE lookup endpoints
  routes/v1/auth.py   Login, API keys, OAuth, admin user management
  routes/v1/assets.py Asset CRUD, vulnerability ingest, status tracking
  routes/v1/dashboard.py  Dashboard summary endpoint
cache/                SQLite cache layer
  store.py            TTL-based cache for enriched CVE data
web/                  Web UI -- server-rendered Jinja2 templates
  routes.py           All web routes (login, setup, dashboard, assets, etc.)
  templates/          Bootstrap dark theme templates
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
- Use `print()` for CLI output; use logging for API/web server output

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

## Teaching Mode

When making changes, planning, or choosing between approaches:

- **Explain the why before the how.** Before writing or changing code, explain what pattern or principle is being applied and why it is the right choice.
- **Name the concept.** If a pattern is used (e.g. separation of concerns, dependency injection, strategy pattern), say what it is called.
- **Explain trade-offs.** When there are multiple valid approaches, briefly explain what was chosen, what was ruled out, and why.
- **Flag learning moments.** If existing code has something worth noting -- a good pattern, a potential improvement, or a common pitfall -- point it out.
- **Teach on errors.** When something fails, explain what the error means and why it happened, not just how to fix it.

This applies to all agents including GSD planners, executors, and verifiers. Plans should explain architectural decisions. Execution output should explain what changed and why.

---

## Quality Gates

After completing any GSD phase or significant code change, run these skills as quality gates before committing:

1. **Security review** (`/security-engineer`) -- run after planning phases that touch auth, API routes, user input handling, or data storage. Review the plan or diff for threats before proceeding.
2. **Code review** (`/code-review`) -- run after execution phases that produce code changes. Review the diff for correctness, style, and architectural violations.
3. **Frontend design** (`/frontend-design`) -- use when building or modifying UI components, templates, or pages. Do not skip this for web-facing work.

Do not commit until all applicable quality gates have passed. If a gate surfaces issues, fix them before moving on.

---

## Contributing

Please open an issue before starting work on a significant change. This keeps effort aligned and avoids duplicate work. See `docs/architecture.md` before making structural changes.
