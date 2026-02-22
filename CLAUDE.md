# VulnAdvisor — Contributor Guide

## Project Overview

VulnAdvisor is an open-source CVE triage and remediation guidance tool built for vulnerability management teams. It fetches data from free public sources (NVD, CISA KEV, EPSS, PoC-in-GitHub) and returns plain-language triage decisions with no API keys or paywalls required.

See `docs/architecture.md` for a full explanation of the design and every module's role.

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
