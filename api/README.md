# VulnAdvisor REST API

This document covers setup, all endpoints, the exposure parameter, rate limits, error format, and troubleshooting for the VulnAdvisor REST API.

---

## Setup

Install API dependencies:

```bash
pip install -r requirements-api.txt
```

Start the server:

```bash
make run-api
# or directly:
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

Interactive docs are available at `http://localhost:8000/docs` once the server is running.

---

## Endpoints

### Health check

```
GET /api/v1/health
```

```bash
curl http://localhost:8000/api/v1/health
```

```json
{"status": "ok", "version": "0.2.0"}
```

No rate limit on this endpoint.

---

### Single CVE lookup

```
GET /api/v1/cve/{cve_id}?exposure=internal
```

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `cve_id` | path | required | CVE ID, e.g. `CVE-2021-44228` |
| `exposure` | query | `internal` | Asset exposure context: `internet`, `internal`, or `isolated` |

```bash
curl "http://localhost:8000/api/v1/cve/CVE-2021-44228"
curl "http://localhost:8000/api/v1/cve/CVE-2021-44228?exposure=internet"
```

Returns the full enriched CVE record as JSON.

---

### Bulk lookup

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

### Priority summary counts

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

## Exposure Parameter

The `exposure` query parameter adjusts triage priority based on where the affected asset lives.

| Value | Meaning | Effect |
|-------|---------|--------|
| `internet` | Asset is publicly reachable | Priority may be raised one level |
| `internal` | Asset is on internal network (default) | No adjustment |
| `isolated` | Asset is air-gapped or lab-only | Priority may be lowered one level |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `GET /cve/{cve_id}` | 30 requests / minute |
| `GET /cve/summary` | 30 requests / minute |
| `POST /cve/bulk` | 5 requests / minute |
| `GET /health` | unlimited |

Exceeding a limit returns `429 Too Many Requests` with a `Retry-After` header.

---

## Error Format

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

## Troubleshooting

**ImportError: cannot import name 'SlowAPIMiddleware' from 'slowapi'**

The middleware lives in `slowapi.middleware`, not `slowapi`. Use:

```python
from slowapi.middleware import SlowAPIMiddleware
```

**TrustedHostMiddleware rejecting requests**

The default config allows `localhost` and `127.0.0.1`. If you are proxying through a hostname, add it to the allowed hosts list in `api/main.py`.

**429 with no Retry-After header**

This indicates an old version of slowapi. Update your dependencies: `pip install -r requirements-api.txt`.

**CORS errors from a browser**

The API does not enable CORS by default. If you are calling the API from a browser-based app, add `CORSMiddleware` to `api/main.py` with the appropriate origins.

**KEV feed failure at startup**

VulnAdvisor fetches the CISA KEV catalog at startup. If your network cannot reach CISA, you will see a warning in the logs. The API continues to run but KEV data will be unavailable until connectivity is restored.

**Cache not persisting across restarts**

The SQLite cache file (`cache/vulnadvisor.db`) is file-based and does persist across restarts. If you are seeing cache misses after restart, confirm the `cache/` directory was not deleted and that the process has write permission to it.
