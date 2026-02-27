# VulnAdvisor

[![CI](https://github.com/jtberry/vuln-advisor/actions/workflows/ci.yml/badge.svg)](https://github.com/jtberry/vuln-advisor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

> Plain-language CVE triage and remediation guidance, built for security teams who need answers, not more data.

No API keys. No paywalls. All data from free, authoritative public sources.

---

## The Problem

Scanners produce hundreds of CVEs per cycle. Each comes with a CVSS score and a wall of technical text. Analysts spend hours researching manually, non-technical stakeholders can't understand the risk, and patches get missed because the signal is buried in noise.

Enterprise tools like Tenable and Qualys solve parts of this problem but cost tens of thousands of dollars a year. **VulnAdvisor fills that gap.**

---

## What It Does

Provide a CVE ID and get back a complete triage brief in seconds:

- **Triage priority** (P1-P4) with a clear time-to-fix recommendation based on real-world risk signals
- **Plain-language explanation** of what the vulnerability is, in terms anyone can understand
- **Exploitation status** showing whether it is actively being weaponized right now (CISA KEV)
- **Exploit probability** giving the statistical likelihood of exploitation in the next 30 days (EPSS)
- **Public PoC status** indicating whether working proof-of-concept exploits are publicly available
- **Remediation steps** covering what to patch and what version to upgrade to
- **Compensating controls** with CWE-specific actions to reduce risk while a patch is pending
- **Detection rule links** pointing directly to SigmaHQ community detection rules
- **Bulk triage** accepting a list of CVE IDs or a file, returning a prioritized summary table (P1 first)

---

## Data Sources

All sources are free and require no registration or API keys.

| Source | What it provides |
|--------|-----------------|
| [NVD (NIST)](https://nvd.nist.gov/) | CVE details, CVSS scores, affected products, patch versions |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited vulnerabilities catalog |
| [EPSS (FIRST.org)](https://www.first.org/epss/) | Exploit prediction probability score |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Public proof-of-concept exploit repositories |

---

## Quick Start

```bash
git clone https://github.com/jtberry/vuln-advisor.git
cd vuln-advisor
```

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

```bash
python main.py CVE-2021-44228
```

---

## Documentation

- **Getting started (local dev, Docker, production)** - [docs/getting-started.md](docs/getting-started.md)
- **CLI usage, flags, and troubleshooting** - [docs/CLI.md](docs/CLI.md)
- **REST API reference** - [api/README.md](api/README.md)
- **Architecture and design** - [docs/architecture.md](docs/architecture.md)

---

## Configuration

Copy `.env.example` to `.env` and configure. The CLI requires no configuration at all - environment variables are only needed for the web UI and API server.

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `SECRET_KEY` | Yes (production) | Auto-generated in debug | Signs sessions and API keys. Min 32 chars. |
| `DEBUG` | No | `false` | Enables auto-generated SECRET_KEY and verbose errors |
| `DOMAIN` | No | `localhost` | Caddy TLS cert target. Set to your real domain in production. |
| `DATABASE_URL` | No | SQLite (local files) | PostgreSQL URL when using `--profile with-postgres` |
| `SECURE_COOKIES` | No | `false` | Set `true` behind HTTPS to require TLS for auth cookies |
| `NVD_API_KEY` | No | None | Optional. Raises NVD rate limit from 5 to 50 req/30s |

**OAuth providers** (all optional - leave blank to disable):

| Provider | Variables |
|----------|-----------|
| GitHub | `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` |
| Google | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| OIDC (Okta, Azure AD, etc.) | `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_DISCOVERY_URL` |

See [.env.example](.env.example) for the full list with inline documentation.

---

## Roadmap

- [x] Bulk CVE processing from vulnerability scanner exports
- [x] REST API layer (FastAPI) wrapping the core engine
- [x] Exposure-aware triage (`--exposure internet/internal/isolated`)
- [x] Export formats (CSV, HTML, Markdown)
- [x] Web UI with Bootstrap dark theme (login, dashboard, asset management, CVE research)
- [x] Authentication (local accounts, OAuth with GitHub/Google, API keys, session management)
- [x] Asset tracking and vulnerability ingest (CSV, Trivy, Grype, Nessus)
- [x] Dashboard charts and risk visualization
- [x] Remediation status workflow UI (open -> in review -> remediated -> closed)
- [x] Containerization (Docker, docker-compose, reverse proxy)
- [ ] Jira / ServiceNow ticket creation
- [ ] Team workspaces and shared reporting

---

## Contributing

Pull requests are welcome. If you're adding a new data source, CWE mapping, or remediation template, please open an issue first to discuss the approach.

```bash
pip install -r requirements-dev.txt
pre-commit install
```

All commits run pre-commit hooks automatically: formatting (black, isort), linting (ruff), security scanning (bandit, pip-audit, semgrep).

To run the unit test suite locally:

```bash
make test
```

CI enforces 80% line coverage on `core/enricher.py`. All 6 CI checks (lint, security, semgrep, secret scan, import smoke test, unit tests) must pass before merging.

---

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) for reporting instructions.

---

## License

MIT. Free to use, modify, and distribute. See [LICENSE](LICENSE).
