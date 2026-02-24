# VulnAdvisor

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

- **CLI usage, flags, and troubleshooting** - [docs/CLI.md](docs/CLI.md)
- **REST API reference** - [api/README.md](api/README.md)
- **Architecture and design** - [docs/architecture.md](docs/architecture.md)

---

## Roadmap

- [x] Bulk CVE processing from vulnerability scanner exports
- [x] REST API layer (FastAPI) wrapping the core engine
- [x] Exposure-aware triage (`--exposure internet/internal/isolated`)
- [x] Export formats (CSV, HTML, Markdown)
- [ ] Web UI for team use
- [ ] Remediation tracking (open -> in progress -> resolved)
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

## License

MIT. Free to use, modify, and distribute. See [LICENSE](LICENSE).
