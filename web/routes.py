"""
web/routes.py -- Jinja2 template routes for the VulnAdvisor web UI.

These routes serve server-rendered HTML. They share app.state with the API
routes (same CMDB store, cache, KEV set) but return HTML instead of JSON.

Route registration order matters. FastAPI resolves same-level paths in order:
  - GET /cve and POST /cve/lookup and POST /cve/bulk must be registered
    before GET /cve/{cve_id} or FastAPI captures "lookup"/"bulk" as path params.

Routes:
  GET  /                                              -- risk dashboard
  GET  /cve                                           -- CVE research page
  POST /cve/lookup                                    -- HTMX: single CVE card
  POST /cve/bulk                                      -- HTMX: bulk results table
  GET  /cve/{cve_id}                                  -- full CVE detail
  GET  /assets/{asset_id}                             -- asset detail
  POST /assets/{asset_id}/vulnerabilities/{cve}/status -- HTMX: row update
"""

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from api.models import CVE_PATTERN
from cmdb.store import CMDBStore
from core.pipeline import process_cve, process_cves

logger = logging.getLogger("vulnadvisor.web")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
router = APIRouter()

_NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
_STATUSES = ["pending", "in_progress", "verified", "closed", "deferred"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _deadline_info(deadline_iso: Optional[str]) -> dict:
    """Return display text and CSS class for a deadline ISO timestamp."""
    if not deadline_iso:
        return {"text": "—", "css": "text-muted"}
    now = datetime.now(timezone.utc)
    try:
        deadline = datetime.fromisoformat(deadline_iso)
    except ValueError:
        return {"text": "—", "css": "text-muted"}
    diff = deadline - now
    secs = diff.total_seconds()
    if secs < 0:
        return {"text": "OVERDUE", "css": "text-danger fw-bold"}
    hours = int(secs / 3600)
    if hours < 24:
        mins = int((secs % 3600) / 60)
        return {"text": f"{hours}h {mins}m", "css": "text-danger"}
    if diff.days <= 7:
        return {"text": f"{diff.days}d", "css": "text-warning"}
    return {"text": f"{diff.days}d", "css": "text-muted"}


def _cvss_row_css(metric: str, value: str) -> str:
    """Return a CSS class for a CVSS vector component value.

    Highlights the worst-case values (highest attack surface / highest impact)
    so analysts can scan the breakdown table at a glance.
    """
    worst: dict[str, set] = {
        "attack_vector": {"NETWORK"},
        "attack_complexity": {"LOW"},
        "privileges_required": {"NONE"},
        "user_interaction": {"NONE"},
        "scope": {"CHANGED"},
        "confidentiality": {"HIGH"},
        "integrity": {"HIGH"},
        "availability": {"HIGH"},
    }
    if value.upper() in worst.get(metric, set()):
        return "text-p1"
    return "text-muted"


# ---------------------------------------------------------------------------
# GET / -- risk dashboard
# ---------------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    cmdb: CMDBStore = request.app.state.cmdb
    assets = cmdb.list_assets()
    priority_counts = cmdb.get_all_priority_counts()

    asset_rows = []
    overdue_count = 0

    for asset in assets:
        counts = cmdb.get_priority_counts(asset.id)
        vulns = cmdb.get_asset_vulns(asset.id)

        nearest_deadline: Optional[str] = None
        for v in vulns:
            if v.status in ("closed", "deferred") or not v.deadline:
                continue
            info = _deadline_info(v.deadline)
            if info["text"] == "OVERDUE":
                overdue_count += 1
            if nearest_deadline is None or v.deadline < nearest_deadline:
                nearest_deadline = v.deadline

        asset_rows.append(
            {
                "asset": asset,
                "counts": counts,
                "nearest_deadline": _deadline_info(nearest_deadline),
            }
        )

    asset_rows.sort(key=lambda r: (-r["counts"]["P1"], -r["counts"]["P2"]))

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "asset_rows": asset_rows,
            "total_assets": len(assets),
            "priority_counts": priority_counts,
            "total_open": sum(priority_counts.values()),
            "overdue_count": overdue_count,
        },
    )


# ---------------------------------------------------------------------------
# GET /cve -- CVE research page (registered BEFORE /cve/{cve_id})
# ---------------------------------------------------------------------------


@router.get("/cve", response_class=HTMLResponse)
def cve_research(request: Request) -> HTMLResponse:
    """Render the CVE research page: single lookup + bulk triage."""
    return templates.TemplateResponse("cve_research.html", {"request": request})


# ---------------------------------------------------------------------------
# POST /cve/lookup -- HTMX: enrich one CVE, return a summary card fragment
# ---------------------------------------------------------------------------


@router.post("/cve/lookup", response_class=HTMLResponse)
async def cve_lookup_htmx(
    request: Request,
    cve_id: str = Form(...),
    exposure: str = Form(default="internal"),
) -> HTMLResponse:
    """Enrich a single CVE and return a card fragment for HTMX to swap in."""
    normalized = cve_id.strip().upper()

    if not re.match(CVE_PATTERN, normalized):
        return templates.TemplateResponse(
            "partials/cve_card.html",
            {
                "request": request,
                "enriched": None,
                "error": f"'{cve_id[:40]}' does not match CVE-YYYY-NNNNN format.",
                "exposure": exposure,
                "nvd_url": None,
            },
        )

    enriched = None
    try:
        enriched = process_cve(
            normalized,
            request.app.state.kev_set,
            request.app.state.cache,
            exposure=exposure,
        )
    except Exception:
        logger.debug("CVE lookup failed for %s", normalized, exc_info=True)

    return templates.TemplateResponse(
        "partials/cve_card.html",
        {
            "request": request,
            "enriched": enriched,
            "error": None if enriched else f"{normalized} was not found in NVD.",
            "exposure": exposure,
            "nvd_url": _NVD_URL.format(cve_id=normalized),
        },
    )


# ---------------------------------------------------------------------------
# POST /cve/bulk -- HTMX: enrich many CVEs, return a prioritised table
# ---------------------------------------------------------------------------


@router.post("/cve/bulk", response_class=HTMLResponse)
async def cve_bulk_htmx(
    request: Request,
    cve_ids_raw: str = Form(...),
    exposure: str = Form(default="internal"),
) -> HTMLResponse:
    """Enrich up to 50 CVEs and return a priority-sorted results table."""
    lines = [ln.strip().upper() for ln in cve_ids_raw.splitlines() if ln.strip()]
    valid_ids = [ln for ln in lines if re.match(CVE_PATTERN, ln)]
    invalid = [ln for ln in lines if not re.match(CVE_PATTERN, ln)]

    results = process_cves(
        valid_ids[:50],
        request.app.state.kev_set,
        request.app.state.cache,
        exposure=exposure,
    )

    _order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    results.sort(key=lambda e: _order.get(e.triage_priority, 9))

    return templates.TemplateResponse(
        "partials/bulk_results.html",
        {
            "request": request,
            "results": results,
            "invalid": invalid,
            "exposure": exposure,
            "requested": len(valid_ids),
        },
    )


# ---------------------------------------------------------------------------
# GET /cve/{cve_id} -- full CVE detail (registered LAST under /cve/*)
# ---------------------------------------------------------------------------


@router.get("/cve/{cve_id}", response_class=HTMLResponse)
def cve_detail(
    request: Request,
    cve_id: str,
    exposure: str = "internal",
) -> HTMLResponse:
    """Full CVE detail: enriched data, CVSS breakdown, remediation, CMDB assets."""
    normalized = cve_id.strip().upper()
    if not re.match(CVE_PATTERN, normalized):
        return HTMLResponse(
            "<div class='text-danger p-4'>Invalid CVE ID format.</div>",
            status_code=400,
        )

    enriched = None
    try:
        enriched = process_cve(
            normalized,
            request.app.state.kev_set,
            request.app.state.cache,
            exposure=exposure,
        )
    except Exception:
        logger.debug("CVE detail enrichment failed for %s", normalized, exc_info=True)

    # Which CMDB assets have this CVE? This is the key differentiator from NVD.
    cmdb: CMDBStore = request.app.state.cmdb
    affected_assets = []
    for asset in cmdb.list_assets():
        vuln = cmdb.get_vuln_by_asset_and_cve(asset.id, normalized)
        if vuln:
            affected_assets.append(
                {
                    "asset": asset,
                    "vuln": vuln,
                    "deadline_info": _deadline_info(vuln.deadline),
                }
            )

    return templates.TemplateResponse(
        "cve_detail.html",
        {
            "request": request,
            "cve_id": normalized,
            "enriched": enriched,
            "exposure": exposure,
            "affected_assets": affected_assets,
            "nvd_url": _NVD_URL.format(cve_id=normalized),
            "cvss_row_css": _cvss_row_css,
        },
    )


# ---------------------------------------------------------------------------
# GET /assets/{asset_id} -- asset detail
# ---------------------------------------------------------------------------


@router.get("/assets/{asset_id}", response_class=HTMLResponse)
def asset_detail(request: Request, asset_id: int) -> HTMLResponse:
    cmdb: CMDBStore = request.app.state.cmdb
    asset = cmdb.get_asset(asset_id)
    if asset is None:
        return HTMLResponse("<h1>Asset not found</h1>", status_code=404)

    kev_set = request.app.state.kev_set
    cache = request.app.state.cache
    vulns = cmdb.get_asset_vulns(asset_id)

    vuln_rows = []
    for vuln in vulns:
        enriched = None
        try:
            enriched = process_cve(vuln.cve_id, kev_set, cache, exposure=asset.exposure)
        except Exception:
            logger.debug("Enrichment failed for %s on asset %d", vuln.cve_id, asset_id, exc_info=True)
        vuln_rows.append(
            {
                "vuln": vuln,
                "enriched": enriched,
                "deadline_info": _deadline_info(vuln.deadline),
                "nvd_url": _NVD_URL.format(cve_id=vuln.cve_id),
            }
        )

    return templates.TemplateResponse(
        "asset_detail.html",
        {
            "request": request,
            "asset": asset,
            "vuln_rows": vuln_rows,
            "counts": cmdb.get_priority_counts(asset_id),
            "asset_id": asset_id,
            "statuses": _STATUSES,
        },
    )


# ---------------------------------------------------------------------------
# POST /assets/{asset_id}/vulnerabilities/{cve_id}/status -- HTMX row update
# ---------------------------------------------------------------------------


@router.post(
    "/assets/{asset_id}/vulnerabilities/{cve_id}/status",
    response_class=HTMLResponse,
)
async def update_vuln_status_htmx(
    request: Request,
    asset_id: int,
    cve_id: str,
    status: str = Form(...),
    owner: Optional[str] = Form(default=None),
    evidence: Optional[str] = Form(default=None),
) -> HTMLResponse:
    cmdb: CMDBStore = request.app.state.cmdb
    normalized = cve_id.upper()

    vuln = cmdb.get_vuln_by_asset_and_cve(asset_id, normalized)
    if vuln is not None:
        cmdb.update_vuln_status(
            vuln.id,
            status=status,
            owner=owner or None,
            evidence=evidence or None,
        )
        vuln = cmdb.get_vuln_by_asset_and_cve(asset_id, normalized)

    asset = cmdb.get_asset(asset_id)
    enriched = None
    if asset:
        try:
            enriched = process_cve(
                normalized,
                request.app.state.kev_set,
                request.app.state.cache,
                exposure=asset.exposure,
            )
        except Exception:
            logger.debug("Enrichment failed for %s on status update", normalized, exc_info=True)

    return templates.TemplateResponse(
        "partials/vuln_row.html",
        {
            "request": request,
            "vuln": vuln,
            "enriched": enriched,
            "deadline_info": _deadline_info(vuln.deadline if vuln else None),
            "nvd_url": _NVD_URL.format(cve_id=normalized),
            "asset_id": asset_id,
            "statuses": _STATUSES,
        },
    )
