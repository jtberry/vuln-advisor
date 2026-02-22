# VulnAdvisor

> Plain-language CVE triage and remediation guidance, built for security teams who need answers, not more data.

No API keys. No paywalls. All data from free, authoritative public sources.

---

## Why This Exists

I work in vulnerability management. Every day, security teams face the same grind: a scanner dumps hundreds of CVEs, each one looking equally urgent, and the people who need to act on them either don't have the time to research them properly or don't have the background to know what the raw data actually means.

I got tired of spending 20 minutes per CVE doing the same manual steps: look it up on NVD, cross-reference CISA KEV, check EPSS, search GitHub for PoCs, piece together what it means, write it up in plain English for a stakeholder who just needs to know whether to drop everything or add it to the next sprint.

Enterprise VM tools solve this. But they cost tens of thousands of dollars a year. Smaller teams, MSPs, and anyone building out a VM practice from scratch are priced out entirely.

VulnAdvisor is my attempt to close that gap. Free, open source, no API keys, no accounts. Just paste in a CVE ID and get back a clear triage decision with the context you need to act on it.

It is also a portfolio project. I am building this in public to demonstrate what a production-quality security tool looks like from the ground up: clean architecture, automated code quality checks, real data sources, and a clear path from a CLI tool toward a SaaS product.

---

## The Problem

Vulnerability management teams are drowning in findings.

Scanners produce hundreds (sometimes thousands) of CVEs per cycle. Each one comes with a CVSS score, a wall of technical text, and a list of affected CPEs that means nothing to most of the people who need to act on it. The result is familiar to anyone who has worked in VM:

- Analysts spend hours researching each finding manually
- Non-technical stakeholders can't understand what the risk actually means
- Teams struggle to prioritize; everything looks urgent, so nothing gets fixed fast enough
- Patches get missed not because people don't care, but because the signal is buried in noise

Enterprise tools like Tenable, Qualys, and Rapid7 solve parts of this problem, but they cost tens of thousands of dollars a year and are out of reach for smaller security teams, MSPs, and organizations just building out their VM practice.

**VulnAdvisor fills that gap.**

---

## Who This Is For

- **Security analysts** who need to triage a backlog of CVEs quickly and accurately
- **VM engineers** who want plain-language remediation steps alongside the raw data
- **IT administrators** who are responsible for patching but don't have a security background
- **MSPs and consultants** who manage vulnerability programs for multiple clients
- **Small and mid-size security teams** that can't justify enterprise VM tool pricing
- **SOC teams** who need to quickly assess the real-world risk of a newly published CVE

If you've ever copied a CVE ID into Google and spent 20 minutes piecing together what it means and what to do, this tool is for you.

---

## What It Does

Provide a CVE ID and get back a complete triage brief in seconds:

- **Triage priority** (P1–P4) with a clear time-to-fix recommendation based on real-world risk signals
- **Plain-language explanation** of what the vulnerability is, in terms anyone can understand
- **Exploitation status** showing whether it is actively being weaponized right now (CISA KEV)
- **Exploit probability** giving the statistical likelihood of exploitation in the next 30 days (EPSS)
- **Public PoC status** indicating whether working proof-of-concept exploits are publicly available
- **Remediation steps** covering what to patch, what version to upgrade to, and any workarounds if patching isn't immediate

The output is designed to be useful to two audiences at once: technical enough for an analyst to act on, plain enough for a manager to understand.

---

## What Makes This Different

Most CVE lookup tools show you the same data that's already on NVD, just formatted differently. VulnAdvisor layers multiple risk signals together to give you a **triage decision**, not just information:

| Signal | Source | Why It Matters |
|--------|--------|----------------|
| CVSS Score | NVD / NIST | Baseline severity from the vulnerability itself |
| Active Exploitation | CISA KEV | Is this being used against real targets right now? |
| Exploit Probability | EPSS (FIRST.org) | Statistical likelihood of exploitation in the wild |
| Public PoC | PoC-in-GitHub | Are working exploits freely available to attackers? |

A CVE with a 7.5 CVSS score that is actively exploited, has a 60% EPSS score, and 30 public PoC repos is not a "fix within 30 days" problem. It's a "fix today" problem. VulnAdvisor makes that call automatically.

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

## Setup

### Prerequisites

- Python 3.9 or later
- `pip` (included with Python)

```bash
python3 --version
```

### Install

```bash
# Clone the repo
git clone https://github.com/jtberry/vuln-advisor.git
cd vuln-advisor

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux / macOS
venv\Scripts\activate.bat         # Windows (Command Prompt)
venv\Scripts\Activate.ps1         # Windows (PowerShell)

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Look up a single CVE

```bash
python main.py CVE-2021-44228
```

### Look up multiple CVEs at once

```bash
python main.py CVE-2021-44228 CVE-2023-44487 CVE-2024-1234
```

### Get structured JSON output

Useful for piping into other tools or scripts.

```bash
python main.py CVE-2021-44228 --json
```

### Save a report to file

```bash
python main.py CVE-2021-44228 > report.txt
python main.py CVE-2021-44228 --json > report.json
```

### Deactivate the virtual environment when done

```bash
deactivate
```

---

## Example Output

```
════════════════════════════════════════════════════════════════════════
  CVE-2021-44228  │  CVSS 10.0 CRITICAL  *** ACTIVELY EXPLOITED ***
════════════════════════════════════════════════════════════════════════

  TRIAGE PRIORITY
  ──────────────────────────────────────────────────────────────────
    P1 — Fix within 24 hours
    Critical CVSS score with active exploitation or high exploit probability.

  THREAT SNAPSHOT
  ──────────────────────────────────────────────────────────────────
    CVSS Score          10.0/10 (CRITICAL)
    Actively Exploited  YES — On CISA Known Exploited List
    Exploit Probability 94.4%  (higher than 99.9% of all CVEs)
    Public PoC          YES — 392 public repo(s) found

  WHAT IS IT?
  ──────────────────────────────────────────────────────────────────
    Type:  Improper Input Validation

    A flaw in Apache Log4j (a popular Java logging library) that lets an
    attacker run any command on your system by sending a specially crafted
    message that gets logged by the application.

  WHAT DO I DO?
  ──────────────────────────────────────────────────────────────────
    1. [PATCH     ]  Upgrade Apache Log4j to 2.17.1 or later
    2. [WORKAROUND]  Set LOG4J_FORMAT_MSG_NO_LOOKUPS=true if patching
                     is not immediately possible
```

---

## Triage Priority Levels

| Priority | Fix Within | Triggered When |
|----------|------------|----------------|
| **P1** | 24 hours | Critical CVSS + actively exploited or EPSS ≥ 50% |
| **P2** | 7 days | High CVSS + public PoC or EPSS ≥ 30% |
| **P3** | 30 days | Medium severity |
| **P4** | Next patch cycle | Low severity |

---

## Roadmap

- [ ] Bulk CVE processing from vulnerability scanner exports
- [ ] Web UI for team use
- [ ] Remediation tracking (open → in progress → resolved)
- [ ] Jira / ServiceNow ticket creation
- [ ] Team workspaces and shared reporting

---

## Contributing

Pull requests are welcome. If you're adding a new data source, CWE mapping, or remediation template, please open an issue first to discuss the approach.

For dev setup:

```bash
pip install -r requirements-dev.txt
pre-commit install
```

All commits run formatting (black, isort), linting (ruff), and security checks (bandit, pip-audit) automatically.

---

## License

MIT. Free to use, modify, and distribute. See [LICENSE](LICENSE).
