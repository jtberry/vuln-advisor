# VulnAdvisor

Plain-language CVE triage and remediation guidance, built for security teams who need answers, not more data.

No API keys. No paywalls. All data from free, authoritative public sources.

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

## Data Sources

All sources are free and require no registration or API keys.

| Source | What it provides |
|--------|-----------------|
| [NVD (NIST)](https://nvd.nist.gov/) | CVE details, CVSS scores, affected products, patch versions |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited vulnerabilities catalog |
| [EPSS (FIRST.org)](https://www.first.org/epss/) | Exploit prediction probability score |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Public proof-of-concept exploit repositories |

## Quick Start

```bash
git clone https://github.com/jtberry/vuln-advisor.git
cd vuln-advisor
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python main.py CVE-2021-44228
```

For full deployment options (local dev, Docker, production VPS), see the [Getting Started](getting-started.md) guide.

## License

MIT. Free to use, modify, and distribute.
