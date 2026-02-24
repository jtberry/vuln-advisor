"""
core/pipeline.py — Pure CVE fetch-cache-enrich pipeline.

No side effects. No print statements. Designed to be called by both
the CLI (via main.py) and the REST API (via api/routes/v1/cve.py).
"""

import re
from typing import Optional

from cache.store import CVECache
from core.enricher import enrich
from core.fetcher import fetch_epss, fetch_nvd, fetch_poc
from core.models import EnrichedCVE

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def process_cve(cve_id: str, kev_set: set[str], cache: Optional[CVECache] = None) -> Optional[EnrichedCVE]:
    """Fetch, cache, and enrich a single CVE. Returns None if the CVE is not found.

    Raises ValueError if cve_id does not match the expected format.
    No print statements — all side effects belong to the caller.
    """
    cve_id = cve_id.strip().upper()

    if not _CVE_RE.match(cve_id):
        raise ValueError(f"Invalid CVE ID format: {cve_id}")

    if cache is not None:
        cached = cache.get(cve_id)
        if cached is not None:
            return enrich(cached["cve_raw"], kev_set, cached["epss_data"], cached["poc_data"])

    cve_raw = fetch_nvd(cve_id)
    if cve_raw is None:
        return None

    epss_data = fetch_epss(cve_id)
    poc_data = fetch_poc(cve_id)

    if cache is not None:
        cache.set(cve_id, {"cve_raw": cve_raw, "epss_data": epss_data, "poc_data": poc_data})

    return enrich(cve_raw, kev_set, epss_data, poc_data)


def process_cves(cve_ids: list[str], kev_set: set[str], cache: Optional[CVECache] = None) -> list[EnrichedCVE]:
    """Process a list of CVE IDs and return all successfully enriched results.

    Deduplicates input (case-insensitive, preserving first-occurrence order).
    Silently skips any ID that raises ValueError or produces no NVD record.
    No print statements — all side effects belong to the caller.
    """
    seen: set[str] = set()
    deduped: list[str] = []
    for cve_id in cve_ids:
        normalized = cve_id.strip().upper()
        if normalized not in seen:
            seen.add(normalized)
            deduped.append(cve_id)

    results: list[EnrichedCVE] = []
    for cve_id in deduped:
        try:
            enriched = process_cve(cve_id, kev_set, cache)
        except ValueError:
            continue
        if enriched is not None:
            results.append(enriched)

    return results
