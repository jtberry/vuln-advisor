"""
web/routes.py -- Jinja2 template routes for the VulnAdvisor web UI.

These routes serve server-rendered HTML. They share app.state with the API
routes (same CMDB store, cache, KEV set) but return HTML instead of JSON.

Route registration order matters. FastAPI resolves same-level paths in order:
  - GET /cve and POST /cve/lookup and POST /cve/bulk must be registered
    before GET /cve/{cve_id} or FastAPI captures "lookup"/"bulk" as path params.
  - GET /assets/new and POST /assets must be registered before GET /assets/{asset_id}
    or FastAPI captures "new" as a path parameter.

Routes:
  GET  /                                              -- risk dashboard
  GET  /cve                                           -- CVE research page
  POST /cve/lookup                                    -- HTMX: single CVE card
  POST /cve/bulk                                      -- HTMX: bulk results table
  GET  /cve/{cve_id}                                  -- full CVE detail
  GET  /assets/new                                    -- asset creation form
  POST /assets                                        -- handle creation, redirect to /assets/{id}
  GET  /assets/{asset_id}                             -- asset detail
  POST /assets/{asset_id}/vulnerabilities             -- HTMX: add CVEs, return updated tbody
  POST /assets/{asset_id}/vulnerabilities/{cve}/status -- HTMX: row update
  GET  /ingest                                        -- scanner file ingest form
  POST /ingest                                        -- HTMX: file upload, return result fragment
"""

import logging
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import IntegrityError

from api.models import CVE_PATTERN
from cmdb.ingest import parse_csv, parse_grype_json, parse_nessus_csv, parse_trivy_json
from cmdb.models import Asset, AssetVulnerability
from cmdb.store import CMDBStore, apply_criticality_modifier
from core.pipeline import process_cve, process_cves

logger = logging.getLogger("vulnadvisor.web")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
router = APIRouter()

_NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
_STATUSES = ["pending", "in_progress", "verified", "closed", "deferred"]
_MAX_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MB
_VALID_ENVIRONMENTS = {"production", "staging", "development"}
_VALID_EXPOSURES = {"internet", "internal", "isolated"}
_VALID_CRITICALITIES = {"critical", "high", "medium", "low"}
_VALID_SCANNERS = {"manual", "csv", "trivy", "grype", "nessus"}


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


def _eol_info(eol_date: Optional[str]) -> dict:
    """Return display text and CSS class for an OS end-of-life date string."""
    if not eol_date:
        return {"text": "—", "css": "text-muted", "badge": False}
    today = datetime.now(timezone.utc).date()
    try:
        d = date.fromisoformat(eol_date)
    except ValueError:
        return {"text": "—", "css": "text-muted", "badge": False}
    if d < today:
        return {"text": "EOL", "css": "text-danger fw-bold", "badge": True}
    days = (d - today).days
    if days <= 90:
        return {"text": f"EOL in {days}d", "css": "text-warning", "badge": False}
    return {"text": str(d), "css": "text-muted", "badge": False}


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
# GET /assets/new -- asset creation form (MUST precede /assets/{asset_id})
# ---------------------------------------------------------------------------


@router.get("/assets/new", response_class=HTMLResponse)
def asset_create_form(request: Request) -> HTMLResponse:
    """Render the asset registration form."""
    return templates.TemplateResponse(
        "assets_form.html",
        {"request": request, "error": None, "form_data": {}, "compliance_options": _COMPLIANCE_OPTIONS},
    )


# ---------------------------------------------------------------------------
# POST /assets -- handle creation, 303-redirect to /assets/{id} on success
# ---------------------------------------------------------------------------


_COMPLIANCE_OPTIONS = ["PCI-DSS", "HIPAA", "SOX", "FedRAMP", "GDPR", "ISO 27001", "CIS"]


@router.post("/assets", response_class=HTMLResponse)
async def asset_create(
    request: Request,
    hostname: Optional[str] = Form(default=None),
    ip: Optional[str] = Form(default=None),
    environment: str = Form(default="production"),
    exposure: str = Form(default="internal"),
    criticality: str = Form(default="medium"),
    owner: Optional[str] = Form(default=None),
    tags: Optional[str] = Form(default=None),
    os: Optional[str] = Form(default=None),
    eol_date: Optional[str] = Form(default=None),
    compliance: Optional[list[str]] = Form(default=None),  # noqa: B008
) -> HTMLResponse:
    """Handle asset creation form POST. Redirects to the new asset on success."""
    compliance_raw: list[str] = compliance or []
    form_data = {
        "hostname": hostname or "",
        "ip": ip or "",
        "environment": environment,
        "exposure": exposure,
        "criticality": criticality,
        "owner": owner or "",
        "tags": tags or "",
        "os": os or "",
        "eol_date": eol_date or "",
        "compliance": compliance_raw,
    }

    hostname_clean = (hostname or "").strip()
    if not hostname_clean:
        return templates.TemplateResponse(
            "assets_form.html",
            {
                "request": request,
                "error": "Hostname is required.",
                "form_data": form_data,
                "compliance_options": _COMPLIANCE_OPTIONS,
            },
        )
    if len(hostname_clean) > 255:
        return templates.TemplateResponse(
            "assets_form.html",
            {
                "request": request,
                "error": "Hostname must be 255 characters or fewer.",
                "form_data": form_data,
                "compliance_options": _COMPLIANCE_OPTIONS,
            },
        )

    if environment not in _VALID_ENVIRONMENTS:
        environment = "production"
    if exposure not in _VALID_EXPOSURES:
        exposure = "internal"
    if criticality not in _VALID_CRITICALITIES:
        criticality = "medium"

    tag_list = [t.strip() for t in (tags or "").split(",") if t.strip()]
    compliance_clean = [c for c in compliance_raw if c in _COMPLIANCE_OPTIONS]
    eol_clean = (eol_date or "").strip() or None
    os_clean = (os or "").strip()[:100] or None

    asset = Asset(
        hostname=hostname_clean,
        ip=(ip or "").strip() or None,
        environment=environment,
        exposure=exposure,
        criticality=criticality,
        owner=(owner or "").strip() or None,
        tags=tag_list,
        os=os_clean,
        eol_date=eol_clean,
        compliance=compliance_clean,
    )

    cmdb: CMDBStore = request.app.state.cmdb
    try:
        asset_id = cmdb.create_asset(asset)
    except Exception as exc:
        logger.debug("Asset creation failed: %s", exc, exc_info=True)
        return templates.TemplateResponse(
            "assets_form.html",
            {
                "request": request,
                "error": "Failed to create asset. The hostname may already be registered.",
                "form_data": form_data,
                "compliance_options": _COMPLIANCE_OPTIONS,
            },
        )

    return RedirectResponse(f"/assets/{asset_id}", status_code=303)


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
            "eol_info": _eol_info(asset.eol_date),
        },
    )


# ---------------------------------------------------------------------------
# POST /assets/{asset_id}/vulnerabilities -- HTMX: add CVEs, return updated tbody
# ---------------------------------------------------------------------------


@router.post("/assets/{asset_id}/vulnerabilities", response_class=HTMLResponse)
async def add_asset_vulns_htmx(
    request: Request,
    asset_id: int,
    cve_ids_raw: str = Form(...),
    scanner: str = Form(default="manual"),
    owner: Optional[str] = Form(default=None),
) -> HTMLResponse:
    """HTMX: enrich and assign CVEs to an asset, return all current tbody rows."""
    cmdb: CMDBStore = request.app.state.cmdb
    asset = cmdb.get_asset(asset_id)
    if asset is None:
        return HTMLResponse(
            "<tr><td colspan='8' class='text-danger p-3'>Asset not found.</td></tr>",
            status_code=404,
        )

    lines = [ln.strip().upper() for ln in cve_ids_raw.splitlines() if ln.strip()]
    # Deduplicate while preserving order
    seen: set[str] = set()
    valid_ids: list[str] = []
    for ln in lines:
        if re.match(CVE_PATTERN, ln) and ln not in seen:
            seen.add(ln)
            valid_ids.append(ln)

    if valid_ids:
        enriched_list = process_cves(
            valid_ids,
            request.app.state.kev_set,
            request.app.state.cache,
            exposure=asset.exposure,
        )
        scanner_clean = scanner if scanner in _VALID_SCANNERS else "manual"
        owner_clean = (owner or "").strip() or None
        for enriched in enriched_list:
            base_priority = enriched.triage_priority
            effective_priority = apply_criticality_modifier(base_priority, asset.criticality)
            vuln = AssetVulnerability(
                asset_id=asset_id,
                cve_id=enriched.id,
                base_priority=base_priority,
                effective_priority=effective_priority,
                scanner=scanner_clean,
                owner=owner_clean,
            )
            try:
                cmdb.create_asset_vuln(vuln)
            except IntegrityError:
                pass  # Already assigned -- skip silently

    # Re-fetch all vulns to return fresh, fully accurate tbody
    vulns = cmdb.get_asset_vulns(asset_id)
    vuln_rows = []
    for vuln in vulns:
        enriched = None
        try:
            enriched = process_cve(
                vuln.cve_id, request.app.state.kev_set, request.app.state.cache, exposure=asset.exposure
            )
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
        "partials/vuln_table_body.html",
        {
            "request": request,
            "vuln_rows": vuln_rows,
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


# ---------------------------------------------------------------------------
# GET /assets/{asset_id}/edit -- pre-populated edit form
# ---------------------------------------------------------------------------


@router.get("/assets/{asset_id}/edit", response_class=HTMLResponse)
def asset_edit_form(request: Request, asset_id: int) -> HTMLResponse:
    """Render the asset edit form, pre-populated with current values."""
    cmdb: CMDBStore = request.app.state.cmdb
    asset = cmdb.get_asset(asset_id)
    if asset is None:
        return HTMLResponse("<h1>Asset not found</h1>", status_code=404)
    form_data = {
        "hostname": asset.hostname,
        "ip": asset.ip or "",
        "environment": asset.environment,
        "exposure": asset.exposure,
        "criticality": asset.criticality,
        "owner": asset.owner or "",
        "tags": ", ".join(asset.tags),
        "os": asset.os or "",
        "eol_date": asset.eol_date or "",
        "compliance": asset.compliance,
    }
    return templates.TemplateResponse(
        "asset_edit.html",
        {
            "request": request,
            "asset": asset,
            "form_data": form_data,
            "error": None,
            "compliance_options": _COMPLIANCE_OPTIONS,
        },
    )


# ---------------------------------------------------------------------------
# POST /assets/{asset_id} -- handle asset update, 303-redirect to detail
# ---------------------------------------------------------------------------


@router.post("/assets/{asset_id}", response_class=HTMLResponse)
async def asset_update(
    request: Request,
    asset_id: int,
    hostname: Optional[str] = Form(default=None),
    ip: Optional[str] = Form(default=None),
    environment: str = Form(default="production"),
    exposure: str = Form(default="internal"),
    criticality: str = Form(default="medium"),
    owner: Optional[str] = Form(default=None),
    tags: Optional[str] = Form(default=None),
    os: Optional[str] = Form(default=None),
    eol_date: Optional[str] = Form(default=None),
    compliance: Optional[list[str]] = Form(default=None),  # noqa: B008
) -> HTMLResponse:
    """Handle asset edit form POST. Redirects to /assets/{id} on success."""
    compliance_raw: list[str] = compliance or []
    cmdb: CMDBStore = request.app.state.cmdb
    asset = cmdb.get_asset(asset_id)
    if asset is None:
        return HTMLResponse("<h1>Asset not found</h1>", status_code=404)

    form_data = {
        "hostname": hostname or "",
        "ip": ip or "",
        "environment": environment,
        "exposure": exposure,
        "criticality": criticality,
        "owner": owner or "",
        "tags": tags or "",
        "os": os or "",
        "eol_date": eol_date or "",
        "compliance": compliance_raw,
    }

    hostname_clean = (hostname or "").strip()
    if not hostname_clean:
        return templates.TemplateResponse(
            "asset_edit.html",
            {
                "request": request,
                "asset": asset,
                "form_data": form_data,
                "error": "Hostname is required.",
                "compliance_options": _COMPLIANCE_OPTIONS,
            },
        )
    if len(hostname_clean) > 255:
        return templates.TemplateResponse(
            "asset_edit.html",
            {
                "request": request,
                "asset": asset,
                "form_data": form_data,
                "error": "Hostname must be 255 characters or fewer.",
                "compliance_options": _COMPLIANCE_OPTIONS,
            },
        )

    if environment not in _VALID_ENVIRONMENTS:
        environment = "production"
    if exposure not in _VALID_EXPOSURES:
        exposure = "internal"
    if criticality not in _VALID_CRITICALITIES:
        criticality = "medium"

    tag_list = [t.strip() for t in (tags or "").split(",") if t.strip()]
    compliance_clean = [c for c in compliance_raw if c in _COMPLIANCE_OPTIONS]
    eol_clean = (eol_date or "").strip() or None
    os_clean = (os or "").strip()[:100] or None

    try:
        cmdb.update_asset(
            asset_id,
            hostname=hostname_clean,
            ip=(ip or "").strip() or None,
            environment=environment,
            exposure=exposure,
            criticality=criticality,
            owner=(owner or "").strip() or None,
            tags=tag_list,
            os=os_clean,
            eol_date=eol_clean,
            compliance=compliance_clean,
        )
    except Exception as exc:
        logger.debug("Asset update failed: %s", exc, exc_info=True)
        return templates.TemplateResponse(
            "asset_edit.html",
            {
                "request": request,
                "asset": asset,
                "form_data": form_data,
                "error": "Failed to update asset.",
                "compliance_options": _COMPLIANCE_OPTIONS,
            },
        )

    return RedirectResponse(f"/assets/{asset_id}", status_code=303)


# ---------------------------------------------------------------------------
# GET /ingest -- scanner file ingest form
# ---------------------------------------------------------------------------


@router.get("/ingest", response_class=HTMLResponse)
def ingest_form(request: Request) -> HTMLResponse:
    """Render the scanner file ingest form."""
    return templates.TemplateResponse("ingest.html", {"request": request})


# ---------------------------------------------------------------------------
# POST /ingest -- HTMX: file upload, return result fragment
# ---------------------------------------------------------------------------


@router.post("/ingest", response_class=HTMLResponse)
async def ingest_file_htmx(
    request: Request,
    file: UploadFile,
    default_exposure: str = Form(default="internal"),
    default_criticality: str = Form(default="medium"),
) -> HTMLResponse:
    """HTMX: ingest a scanner file and return a counts/errors result fragment."""
    if default_exposure not in _VALID_EXPOSURES:
        default_exposure = "internal"
    if default_criticality not in _VALID_CRITICALITIES:
        default_criticality = "medium"

    raw = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(raw) > _MAX_UPLOAD_BYTES:
        return templates.TemplateResponse(
            "partials/ingest_result.html",
            {
                "request": request,
                "errors": ["File must be 1 MB or smaller."],
                "assets_created": 0,
                "vulns_assigned": 0,
                "vulns_skipped": 0,
                "new_assets": [],
            },
        )

    content = raw.decode("utf-8", errors="replace")
    filename = (file.filename or "").lower()

    records = []
    if filename.endswith(".json"):
        trivy = parse_trivy_json(content)
        records = trivy if trivy else parse_grype_json(content)
    elif filename.endswith(".csv"):
        nessus = parse_nessus_csv(content)
        records = nessus if nessus else parse_csv(content)
    else:
        return templates.TemplateResponse(
            "partials/ingest_result.html",
            {
                "request": request,
                "errors": ["File must have a .csv or .json extension."],
                "assets_created": 0,
                "vulns_assigned": 0,
                "vulns_skipped": 0,
                "new_assets": [],
            },
        )

    cmdb: CMDBStore = request.app.state.cmdb
    kev_set = request.app.state.kev_set
    cache = request.app.state.cache

    assets_created = 0
    vulns_assigned = 0
    vulns_skipped = 0
    errors: list[str] = []
    new_assets: list[dict] = []

    # Group by hostname; validate CVE IDs before any DB work
    by_hostname: dict[str, list[str]] = {}
    for rec in records:
        if not re.match(CVE_PATTERN, rec.cve_id):
            errors.append(f"Skipped invalid CVE ID: {rec.cve_id[:50]}")
            continue
        by_hostname.setdefault(rec.hostname, []).append(rec.cve_id)

    scanner = "csv" if filename.endswith(".csv") else "trivy"

    for hostname, cve_ids in by_hostname.items():
        asset = cmdb.get_asset_by_hostname(hostname)
        if asset is None:
            new_asset_obj = Asset(
                hostname=hostname,
                environment="production",
                exposure=default_exposure,
                criticality=default_criticality,
            )
            new_asset_id = cmdb.create_asset(new_asset_obj)
            asset = cmdb.get_asset(new_asset_id)
            assets_created += 1
            new_assets.append({"id": asset.id, "hostname": asset.hostname})

        enriched_list = process_cves(cve_ids, kev_set, cache, exposure=asset.exposure)
        for enriched in enriched_list:
            base_priority = enriched.triage_priority
            effective_priority = apply_criticality_modifier(base_priority, asset.criticality)
            vuln = AssetVulnerability(
                asset_id=asset.id,
                cve_id=enriched.id,
                base_priority=base_priority,
                effective_priority=effective_priority,
                scanner=scanner,
            )
            try:
                cmdb.create_asset_vuln(vuln)
                vulns_assigned += 1
            except IntegrityError:
                vulns_skipped += 1

    return templates.TemplateResponse(
        "partials/ingest_result.html",
        {
            "request": request,
            "assets_created": assets_created,
            "vulns_assigned": vulns_assigned,
            "vulns_skipped": vulns_skipped,
            "errors": errors,
            "new_assets": new_assets,
        },
    )
