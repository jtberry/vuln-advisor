# VulnAdvisor

> Plain-language CVE triage and remediation guidance, built for security teams who need answers, not more data.

No API keys. No paywalls. All data from free, authoritative public sources.

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
- **Compensating controls** with CWE-specific actions to reduce risk while a patch is pending (WAF rules, monitoring, network restrictions, and more)
- **Detection rule links** pointing directly to SigmaHQ community detection rules for the CVE so your SOC can monitor while patching is in progress
- **Bulk triage** accepting a list of CVE IDs or a file from a scanner export, returning a prioritized summary table sorted P1 → P4 so the most urgent items are always at the top

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

When more than one CVE is provided, VulnAdvisor returns a prioritized summary table (P1 first) instead of individual reports.

```bash
python main.py CVE-2021-44228 CVE-2023-44487 CVE-2024-1234
```

### Bulk triage from a file

Pass a text file with one CVE ID per line. Lines starting with `#` and blank lines are ignored.

```bash
python main.py --file cves.txt
```

```
# cves.txt — scanner export
CVE-2021-44228
CVE-2023-44487
CVE-2024-21762
```

### Show full reports after the summary

```bash
python main.py --file cves.txt --full
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

## REST API

VulnAdvisor exposes a lightweight HTTP API built with FastAPI. Useful when you want to integrate triage results into your own tooling, dashboards, or the web UI.

### Install API dependencies

```bash
pip install -r requirements-api.txt
```

### Start the server

```bash
make run-api
# or directly:
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

Interactive docs are available at `http://localhost:8000/docs` once the server is running.

---

### Endpoints

#### Health check

```
GET /api/v1/health
```

```bash
curl http://localhost:8000/api/v1/health
```

```json
{"status": "ok", "version": "0.2.0"}
```

---

#### Single CVE lookup

```
GET /api/v1/cve/{cve_id}?exposure=internal
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `cve_id` | path | required | CVE ID, e.g. `CVE-2021-44228` |
| `exposure` | query | `internal` | Asset exposure context: `internet`, `internal`, or `isolated` |

```bash
curl "http://localhost:8000/api/v1/cve/CVE-2021-44228"
```

Returns the full enriched CVE record as JSON (same data as `--json` from the CLI).

---

#### Bulk lookup

```
POST /api/v1/cve/bulk?exposure=internal&full=false&priority_filter=P1
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `exposure` | query | `internal` | Asset exposure context |
| `full` | query | `false` | Include full CVE records alongside the summary |
| `priority_filter` | query | none | Restrict results to one priority bucket: `P1`, `P2`, `P3`, or `P4` |

Request body:

```json
{
  "ids": ["CVE-2021-44228", "CVE-2023-44487", "CVE-2024-21762"]
}
```

```bash
curl -X POST "http://localhost:8000/api/v1/cve/bulk" \
  -H "Content-Type: application/json" \
  -d '{"ids": ["CVE-2021-44228", "CVE-2023-44487"]}'
```

```json
{
  "meta": {
    "requested": 2,
    "returned": 2,
    "failed": 0,
    "exposure": "internal"
  },
  "summary": {
    "P1": [
      {
        "id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "cvss_severity": "CRITICAL",
        "is_kev": true,
        "has_poc": true,
        "cwe_name": "Improper Input Validation",
        "triage_priority": "P1",
        "triage_label": "Fix within 24 hours"
      }
    ],
    "P2": [...],
    "P3": [],
    "P4": []
  }
}
```

Max 50 CVE IDs per request. Duplicates and lowercase IDs are handled automatically.

---

#### Priority summary counts

```
GET /api/v1/cve/summary?ids=CVE-2021-44228,CVE-2023-44487&exposure=internal
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `ids` | query | required | Comma-separated CVE IDs |
| `exposure` | query | `internal` | Asset exposure context |

```bash
curl "http://localhost:8000/api/v1/cve/summary?ids=CVE-2021-44228,CVE-2023-44487"
```

```json
{
  "counts": {"P1": 1, "P2": 1, "P3": 0, "P4": 0},
  "total": 2,
  "exposure": "internal"
}
```

Useful for dashboard widgets that show a count per bucket without fetching full records.

---

### Rate limits

| Endpoint | Limit |
|----------|-------|
| `GET /cve/{cve_id}` | 30 requests / minute |
| `GET /cve/summary` | 30 requests / minute |
| `POST /cve/bulk` | 5 requests / minute |
| `GET /health` | unlimited |

Exceeding a limit returns `429 Too Many Requests`.

---

### Error format

All errors use the same envelope regardless of status code:

```json
{
  "error": {
    "code": "invalid_cve_id",
    "message": "Invalid CVE ID format.",
    "detail": "CVE-bad does not match CVE-YYYY-NNNNN."
  }
}
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

- [x] Bulk CVE processing from vulnerability scanner exports
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
