"""
fetcher.py — All external data fetching.
All sources are free and require no API keys.
"""

import threading
from typing import Any, Optional

import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
POC_GITHUB = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json"

# Module-level session shared across all fetcher calls for connection pooling.
# max_redirects=3 replaces the requests default of 30 — these are known public APIs,
# 3 hops is generous and protects against open redirect / SSRF via redirect chains.
_session = requests.Session()
_session.max_redirects = 3

_kev_cache: Optional[set[str]] = None
_kev_lock = threading.Lock()


def fetch_nvd(cve_id: str, api_key: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Fetch raw CVE record from NVD.

    Args:
        cve_id:  CVE identifier, e.g. "CVE-2021-44228".
        api_key: Optional NVD API key (header: apiKey). Raises rate limit from
                 5 req/min (unauthenticated) to 50 req/min (authenticated).
                 Free registration at https://nvd.nist.gov/developers/request-an-api-key
    """
    try:
        headers = {"apiKey": api_key} if api_key else {}
        resp = _session.get(NVD_API, params={"cveId": cve_id}, headers=headers, timeout=10)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        return vulns[0].get("cve") if vulns else None
    except requests.RequestException as e:
        print(f"  [!] NVD fetch failed for {cve_id}: {e}")
        return None


def fetch_kev() -> set[str]:
    """Fetch CISA Known Exploited Vulnerabilities catalog (cached for session).

    Thread-safe via double-checked locking: check under lock, fetch outside lock
    (network I/O must not block other threads), write result under lock.
    """
    global _kev_cache
    with _kev_lock:
        if _kev_cache is not None:
            return _kev_cache
    try:
        resp = _session.get(CISA_KEV_URL, timeout=10)
        resp.raise_for_status()
        entries = resp.json().get("vulnerabilities", [])
        kev_set: set[str] = {e["cveID"] for e in entries}
    except requests.RequestException:
        print("  [!] Could not fetch CISA KEV feed — skipping exploit status check.")
        kev_set = set()
    with _kev_lock:
        _kev_cache = kev_set
    return kev_set


def fetch_epss(cve_id: str) -> dict[str, Any]:
    """Fetch EPSS exploitation probability score from FIRST.org."""
    try:
        resp = _session.get(EPSS_API, params={"cve": cve_id}, timeout=10)
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
        resp = _session.get(url, timeout=10)
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
