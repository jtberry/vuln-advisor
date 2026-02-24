# CLI Reference

This document covers all CLI flags, usage examples, output format, and troubleshooting for VulnAdvisor's command-line interface.

---

## Installation

Requirements: Python 3.9 or later.

```bash
git clone https://github.com/jtberry/vuln-advisor.git
cd vuln-advisor
python3 -m venv venv
source venv/bin/activate          # Linux / macOS
venv\Scripts\activate.bat         # Windows (Command Prompt)
venv\Scripts\Activate.ps1         # Windows (PowerShell)
pip install -r requirements.txt
```

---

## All Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `CVE-XXXX-XXXX` | positional | - | One or more CVE IDs to look up |
| `--file FILE` | path | - | Text file with one CVE ID per line |
| `--full` | flag | off | Show full individual reports after the summary table |
| `--json` | flag | off | Output structured JSON instead of terminal-formatted text |
| `--format {csv,html,markdown}` | string | - | Export summary table in the specified format |
| `--exposure {internet,internal,isolated}` | string | `internal` | Asset exposure context - adjusts triage priority |
| `--no-cache` | flag | off | Bypass the local cache and fetch fresh data |
| `--no-color` | flag | off | Disable ANSI color codes in output |

---

## Usage Examples

### Single CVE

```bash
python main.py CVE-2021-44228
```

### Multiple CVEs

When more than one CVE ID is provided, VulnAdvisor returns a prioritized summary table (P1 first) instead of individual reports.

```bash
python main.py CVE-2021-44228 CVE-2023-44487 CVE-2024-1234
```

### Bulk from file

Pass a text file with one CVE ID per line. Lines starting with `#` and blank lines are ignored.

```bash
python main.py --file cves.txt
```

```
# cves.txt -- scanner export
CVE-2021-44228
CVE-2023-44487
CVE-2024-21762
```

### Show full reports after the summary

```bash
python main.py --file cves.txt --full
```

### Export formats

```bash
python main.py --file cves.txt --format csv > report.csv
python main.py --file cves.txt --format html > report.html
python main.py --file cves.txt --format markdown > report.md
```

### Exposure contexts

The `--exposure` flag adjusts triage priority based on where the affected asset lives. A vulnerability on an internet-facing host is higher urgency than the same CVE on an isolated lab system.

```bash
python main.py CVE-2021-44228 --exposure internet    # highest urgency
python main.py CVE-2021-44228 --exposure internal    # default
python main.py CVE-2021-44228 --exposure isolated    # lowest urgency
```

### NVD API key

NVD enforces a 5 request/min rate limit for unauthenticated requests. A free NVD API key raises this to 50 request/min and is recommended for bulk triage.

```bash
export NVD_API_KEY=your_key_here
python main.py --file cves.txt
```

Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

### JSON output

Useful for piping into other tools or scripts.

```bash
python main.py CVE-2021-44228 --json
python main.py CVE-2021-44228 --json > report.json
```

### Combined example

```bash
python main.py --file scanner-export.txt --exposure internet --format markdown > triage-report.md
```

---

## Output Format

Terminal output for a single CVE:

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
| **P1** | 24 hours | Critical CVSS + actively exploited or EPSS >= 50% |
| **P2** | 7 days | High CVSS + public PoC or EPSS >= 30% |
| **P3** | 30 days | Medium severity |
| **P4** | Next patch cycle | Low severity |

---

## Cache

VulnAdvisor caches enriched CVE data in a local SQLite database (`cache/vulnadvisor.db`) with a 24-hour TTL. Cached results are served instantly without hitting external APIs.

To bypass the cache and fetch fresh data:

```bash
python main.py CVE-2021-44228 --no-cache
```

To clear the cache entirely:

```bash
make clean
```

---

## Troubleshooting

**"No NVD record found" for a valid CVE**

NVD occasionally lags a few hours behind CVE publication. Wait and retry. Also confirm the CVE ID format is correct (`CVE-YYYY-NNNNN`).

**Rate limit errors on bulk triage**

You are hitting NVD's unauthenticated limit (5 req/min). Add an `NVD_API_KEY` environment variable to raise the limit to 50 req/min.

**Malformed CVE IDs in a file**

Lines that do not match `CVE-YYYY-NNNNN` are skipped with a warning. Use `#` to comment out lines you want to keep but not process yet.

**Stale data returned**

Use `--no-cache` to force a fresh fetch. The cache TTL is 24 hours by default.

**ANSI color codes appearing in CI logs**

Pass `--no-color` or set `NO_COLOR=1` in your environment.
