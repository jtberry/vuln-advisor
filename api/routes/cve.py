"""
api/routes/cve.py — CVE lookup endpoints.

Walk phase — wraps core.fetcher + core.enricher and returns
EnrichedCVE as JSON. Bulk endpoint accepts a list of IDs and
returns a prioritized summary.

Planned endpoints:
  GET  /cve/{cve_id}        — single CVE triage report
  POST /cve/bulk            — list of CVE IDs, returns priority summary
"""

# TODO: implement routes
