"""
fetcher.py — All external data fetching.
All sources are free and require no API keys.
"""

from typing import Any, Optional

import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
POC_GITHUB = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json"

_kev_cache: Optional[set[str]] = None


def fetch_nvd(cve_id: str) -> Optional[dict[str, Any]]:
    """Fetch raw CVE record from NVD."""
    try:
        resp = requests.get(NVD_API, params={"cveId": cve_id}, timeout=10)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        return vulns[0].get("cve") if vulns else None
    except requests.RequestException as e:
        print(f"  [!] NVD fetch failed for {cve_id}: {e}")
        return None


def fetch_kev() -> set[str]:
    """Fetch CISA Known Exploited Vulnerabilities catalog (cached for session)."""
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        resp = requests.get(CISA_KEV_URL, timeout=10)
        resp.raise_for_status()
        entries = resp.json().get("vulnerabilities", [])
        _kev_cache = {e["cveID"] for e in entries}
        return _kev_cache
    except requests.RequestException:
        print("  [!] Could not fetch CISA KEV feed — skipping exploit status check.")
        _kev_cache = set()
        return _kev_cache


def fetch_epss(cve_id: str) -> dict[str, Any]:
    """Fetch EPSS exploitation probability score from FIRST.org."""
    try:
        resp = requests.get(EPSS_API, params={"cve": cve_id}, timeout=10)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if data:
            return {
                "score": float(data[0].get("epss", 0)),
                "percentile": float(data[0].get("percentile", 0)),
            }
    except requests.RequestException:
        pass
    return {"score": None, "percentile": None}


def fetch_poc(cve_id: str) -> dict[str, Any]:
    """
    Check PoC-in-GitHub for public proof-of-concept repos.
    Repo: https://github.com/nomi-sec/PoC-in-GitHub
    """
    try:
        year = cve_id.split("-")[1]
        url = POC_GITHUB.format(year=year, cve_id=cve_id)
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404:
            return {"has_poc": False, "count": 0, "sources": []}
        resp.raise_for_status()
        entries = resp.json()
        sources = [e.get("html_url", "") for e in entries if e.get("html_url")]
        return {
            "has_poc": len(sources) > 0,
            "count": len(sources),
            "sources": sources[:5],  # cap at 5 links
        }
    except (requests.RequestException, IndexError, ValueError):
        return {"has_poc": False, "count": 0, "sources": []}
