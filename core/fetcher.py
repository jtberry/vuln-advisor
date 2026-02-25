"""
fetcher.py -- All external data fetching.
All sources are free. NVD optionally accepts an API key for higher rate limits.
"""

import logging
import os
from typing import Any, Optional

import requests

logger = logging.getLogger("vulnadvisor.fetcher")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
POC_GITHUB = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json"

# NVD_API_KEY is optional. When set, NVD allows 50 req/30s instead of 5 req/30s.
# Read once at module load so the value is consistent for the process lifetime.
# Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
_NVD_API_KEY: Optional[str] = os.environ.get("NVD_API_KEY") or None

# Module-level session shared across all fetcher calls for connection pooling.
# max_redirects=3 replaces the requests default of 30 -- these are known public APIs,
# 3 hops is generous and protects against open redirect / SSRF via redirect chains.
_session = requests.Session()
_session.max_redirects = 3


def fetch_nvd(cve_id: str, api_key: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Fetch raw CVE record from NVD.

    Args:
        cve_id:  CVE identifier, e.g. "CVE-2021-44228".
        api_key: Optional NVD API key override. When not provided, the module
                 reads NVD_API_KEY from the environment automatically. Passing
                 a key raises the NVD rate limit from 5 req/30s (unauthenticated)
                 to 50 req/30s (authenticated).
                 Free registration at https://nvd.nist.gov/developers/request-an-api-key

    Gracefully falls back to unauthenticated calls if no key is available.
    """
    # Explicit caller argument takes precedence; fall back to the module-level env var.
    effective_key = api_key or _NVD_API_KEY
    try:
        params: dict[str, str] = {"cveId": cve_id}
        if effective_key:
            params["apiKey"] = effective_key
        resp = _session.get(NVD_API, params=params, timeout=10)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        return vulns[0].get("cve") if vulns else None
    except requests.RequestException as e:
        logger.warning("NVD fetch failed for %s: %s", cve_id, e)
        return None


def fetch_kev() -> set[str]:
    """Fetch CISA Known Exploited Vulnerabilities catalog and return the CVE ID set.

    Pure stateless function -- fetches from CISA on every call and returns
    the result directly. No module-level caching; that is the caller's concern.

    In the API server, api/main.py lifespan calls this via _load_kev() which
    wraps it with CVECache. This keeps core/ free of any cache or concurrency
    concerns -- no global state, no locks, no threading import needed.

    Returns an empty set on network failure so callers always get a valid set.
    """
    try:
        resp = _session.get(CISA_KEV_URL, timeout=10)
        resp.raise_for_status()
        entries = resp.json().get("vulnerabilities", [])
        return {e["cveID"] for e in entries}
    except requests.RequestException as e:
        logger.warning("Could not fetch CISA KEV feed: %s", e)
        return set()


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
    except requests.RequestException as e:
        logger.warning("EPSS fetch failed for %s: %s", cve_id, e)
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
