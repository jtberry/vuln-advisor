# VulnAdvisor

Plain-language CVE triage and remediation guidance for vulnerability management teams.

No API keys required. No paywalls. All data is pulled from free, authoritative public sources.

---

## What It Does

Paste in a CVE ID and get back:

- **Triage priority** (P1–P4) with a clear time-to-fix recommendation
- **Plain-language explanation** of what the vulnerability is and what an attacker could do
- **Exploitation status** — is it being actively exploited right now? (CISA KEV)
- **Exploit probability** — statistical likelihood it will be exploited (EPSS)
- **Public PoC status** — are there working proof-of-concept exploits on GitHub?
- **Remediation steps** — what to patch, what version to upgrade to, and any workarounds

---

## Data Sources

| Source | What it provides |
|--------|-----------------|
| [NVD (NIST)](https://nvd.nist.gov/) | CVE details, CVSS scores, affected products |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited vulnerabilities catalog |
| [EPSS (FIRST.org)](https://www.first.org/epss/) | Exploit prediction probability score |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Public proof-of-concept exploit repos |

All free. No registration needed.

---

## Setup

### 1. Prerequisites

- Python 3.9 or later
- `pip` (comes with Python)

Check your version:
```bash
python3 --version
```

### 2. Clone the repository

```bash
git clone https://github.com/yourusername/vuln-advisor.git
cd vuln-advisor
```

### 3. Create a virtual environment

This keeps the project dependencies isolated from your system Python.

```bash
# Create the virtual environment
python3 -m venv venv

# Activate it
# On Linux / macOS:
source venv/bin/activate

# On Windows (Command Prompt):
venv\Scripts\activate.bat

# On Windows (PowerShell):
venv\Scripts\Activate.ps1
```

You should see `(venv)` appear at the start of your terminal prompt.

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. (Optional) Environment file

No API keys are required for core functionality. If you want to set up future AI-enhanced features:

```bash
cp .env.example .env
# Edit .env and add any keys
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

### Get structured JSON output (for scripting or integrations)

```bash
python main.py CVE-2021-44228 --json
```

### Save output to a file

```bash
python main.py CVE-2021-44228 > report.txt
python main.py CVE-2021-44228 --json > report.json
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
    Exploit Probability 97.6%  (higher than 99.9% of all CVEs)
    Public PoC          YES — 200+ public repo(s) found
...
```

---

## Triage Priority Levels

| Priority | Time to Fix | When |
|----------|-------------|------|
| **P1** | Within 24 hours | Critical CVSS + actively exploited or high EPSS |
| **P2** | Within 7 days | High CVSS + public PoC or elevated EPSS |
| **P3** | Within 30 days | Medium severity |
| **P4** | Next patch cycle | Low severity |

---

## Deactivating the Virtual Environment

When you're done, deactivate the venv:

```bash
deactivate
```

---

## Roadmap

- [ ] Tanium Comply export import (CSV/JSON)
- [ ] Bulk CVE processing from scanner exports
- [ ] Web UI
- [ ] Jira / ServiceNow ticket creation
- [ ] Remediation tracking (open → in progress → resolved)
- [ ] Team workspaces

---

## Contributing

Pull requests welcome. Please open an issue first to discuss significant changes.

---

## License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE).
