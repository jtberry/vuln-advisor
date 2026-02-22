"""
cache/store.py — SQLite-backed cache for CVE lookups.

Walk phase — avoids redundant API calls by storing enriched CVE data
locally with a configurable TTL (default 24 hours). Shared across
the CLI and API so both benefit from cached results.

Planned interface:
  get(cve_id)          -> EnrichedCVE | None
  set(cve_id, data)    -> None
  invalidate(cve_id)   -> None
  purge_expired()      -> int   (number of entries removed)
"""

# TODO: implement SQLite cache
