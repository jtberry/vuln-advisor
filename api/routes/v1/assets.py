"""
api/routes/v1/assets.py -- Asset CMDB routes for the VulnAdvisor REST API.

Routes (in registration order to avoid FastAPI path capture conflicts):
  POST   /assets                                    -- create asset
  GET    /assets                                    -- list all assets
  POST   /ingest                                    -- bulk file upload (CSV/JSON)
  GET    /assets/{asset_id}                         -- asset detail + CVE list
  POST   /assets/{asset_id}/vulnerabilities         -- attach CVE IDs to asset
  PATCH  /assets/{asset_id}/vulnerabilities/{cve_id}/status  -- update status

Criticality modifier:
  After process_cves() returns enriched CVEs, apply_criticality_modifier() is
  called per CVE to compute effective_priority. This stays in cmdb/ rather than
  core/ to keep the CVE engine asset-agnostic.

File uploads:
  /ingest accepts multipart/form-data. File size is capped at 1 MB.
  Format is detected from filename extension (.csv, .json). Supported scanner
  formats: generic CSV, Trivy JSON, Grype JSON, Nessus CSV.
"""

import re

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from sqlalchemy.exc import IntegrityError

from api.limiter import limiter
from api.models import (
    CVE_PATTERN,
    AssetCreate,
    AssetResponse,
    AssetSummaryRow,
    AssetVulnAssign,
    AssetVulnRow,
    AssetVulnStatusUpdate,
    ErrorDetail,
    IngestResponse,
)
from auth.dependencies import get_current_user
from cmdb.ingest import IngestRecord, parse_csv, parse_grype_json, parse_nessus_csv, parse_trivy_json
from cmdb.models import Asset, AssetVulnerability
from cmdb.store import CMDBStore, apply_criticality_modifier
from core.pipeline import process_cves

# All asset and ingest routes require authentication.
# Router-level dependency applies to every route registered on this router,
# so individual handlers don't each need to repeat Depends(get_current_user).
router = APIRouter(dependencies=[Depends(get_current_user)])

_MAX_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MB


# ---------------------------------------------------------------------------
# POST /assets -- create a new asset
# ---------------------------------------------------------------------------


@limiter.limit("30/minute")
@router.post("/assets", response_model=AssetResponse, status_code=201)
def create_asset(
    request: Request,
    body: AssetCreate,
) -> AssetResponse:
    """Register a new asset in the CMDB.

    The asset's exposure and criticality become the default context for all
    CVE triage requests linked to this asset.
    """
    cmdb: CMDBStore = request.app.state.cmdb
    asset = Asset(
        hostname=body.hostname,
        ip=body.ip,
        environment=body.environment.value,
        exposure=body.exposure.value,
        criticality=body.criticality.value,
        owner=body.owner,
        tags=body.tags,
        os=body.os,
        eol_date=body.eol_date,
        compliance=body.compliance,
    )
    asset_id = cmdb.create_asset(asset)
    created = cmdb.get_asset(asset_id)
    # New asset has no vulnerabilities yet
    return AssetResponse(
        id=created.id,
        hostname=created.hostname,
        ip=created.ip,
        environment=created.environment,
        exposure=created.exposure,
        criticality=created.criticality,
        owner=created.owner,
        tags=created.tags,
        created_at=created.created_at,
        vuln_counts={"P1": 0, "P2": 0, "P3": 0, "P4": 0},
        vulnerabilities=[],
        os=created.os,
        eol_date=created.eol_date,
        compliance=created.compliance,
    )


# ---------------------------------------------------------------------------
# GET /assets -- list all assets with priority summary counts
# ---------------------------------------------------------------------------


@limiter.limit("60/minute")
@router.get("/assets", response_model=list[AssetSummaryRow])
def list_assets(request: Request) -> list[AssetSummaryRow]:
    """Return all registered assets with open vulnerability counts per priority."""
    cmdb: CMDBStore = request.app.state.cmdb
    assets = cmdb.list_assets()
    rows = []
    for asset in assets:
        counts = cmdb.get_priority_counts(asset.id)
        rows.append(
            AssetSummaryRow(
                id=asset.id,
                hostname=asset.hostname,
                environment=asset.environment,
                exposure=asset.exposure,
                criticality=asset.criticality,
                owner=asset.owner,
                vuln_counts=counts,
            )
        )
    return rows


# ---------------------------------------------------------------------------
# POST /ingest -- bulk file upload (must be before /assets/{asset_id})
# ---------------------------------------------------------------------------


@limiter.limit("5/minute")
@router.post("/ingest", response_model=IngestResponse)
async def ingest_file(
    request: Request,
    file: UploadFile,
    default_exposure: str = "internal",
    default_criticality: str = "medium",
) -> IngestResponse:
    """Ingest a scanner output file mapping hostnames to CVE IDs.

    Supported formats (detected by filename extension):
      .csv  -- Generic hostname,cve_id CSV or Nessus CSV export
      .json -- Trivy or Grype JSON output

    Assets are auto-created if the hostname is not already registered.
    Duplicate (asset, CVE) pairs are silently skipped.

    Query params:
      default_exposure    -- exposure to use when auto-creating new assets
      default_criticality -- criticality to use when auto-creating new assets
    """
    # Validate defaults against allowed values
    _valid_exposure = {"internet", "internal", "isolated"}
    _valid_criticality = {"critical", "high", "medium", "low"}
    if default_exposure not in _valid_exposure:
        raise HTTPException(
            status_code=400,
            detail=ErrorDetail(
                code="invalid_param",
                message=f"default_exposure must be one of: {', '.join(sorted(_valid_exposure))}",
            ).model_dump(),
        )
    if default_criticality not in _valid_criticality:
        raise HTTPException(
            status_code=400,
            detail=ErrorDetail(
                code="invalid_param",
                message=f"default_criticality must be one of: {', '.join(sorted(_valid_criticality))}",
            ).model_dump(),
        )

    # Size guard -- read up to 1 MB + 1 byte; reject if over limit
    raw = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=ErrorDetail(
                code="file_too_large",
                message="Upload must be 1 MB or smaller.",
            ).model_dump(),
        )

    content = raw.decode("utf-8", errors="replace")
    filename = (file.filename or "").lower()

    # Detect format and parse
    records: list[IngestRecord] = []
    if filename.endswith(".json"):
        # Try Trivy first (has ArtifactName key), then Grype
        trivy = parse_trivy_json(content)
        if trivy:
            records = trivy
        else:
            records = parse_grype_json(content)
    elif filename.endswith(".csv"):
        # Try Nessus first (has Host + CVE columns), then generic CSV
        nessus = parse_nessus_csv(content)
        if nessus:
            records = nessus
        else:
            records = parse_csv(content)
    else:
        raise HTTPException(
            status_code=415,
            detail=ErrorDetail(
                code="unsupported_format",
                message="File must have a .csv or .json extension.",
            ).model_dump(),
        )

    cmdb: CMDBStore = request.app.state.cmdb
    kev_set: set = request.app.state.kev_set
    cache = request.app.state.cache

    assets_created = 0
    vulns_assigned = 0
    vulns_skipped = 0
    errors: list[str] = []

    # Group records by hostname to batch process_cves() calls per asset
    by_hostname: dict[str, list[str]] = {}
    for rec in records:
        if not re.match(CVE_PATTERN, rec.cve_id):
            errors.append(f"Skipped invalid CVE ID: {rec.cve_id[:50]}")
            continue
        by_hostname.setdefault(rec.hostname, []).append(rec.cve_id)

    for hostname, cve_ids in by_hostname.items():
        # Look up or auto-create the asset
        asset = cmdb.get_asset_by_hostname(hostname)
        if asset is None:
            new_asset = Asset(
                hostname=hostname,
                environment="production",
                exposure=default_exposure,
                criticality=default_criticality,
            )
            asset_id = cmdb.create_asset(new_asset)
            asset = cmdb.get_asset(asset_id)
            assets_created += 1

        # Enrich CVEs using the asset's exposure context
        enriched_list = process_cves(cve_ids, kev_set, cache, exposure=asset.exposure)

        # Store each enriched CVE as an AssetVulnerability
        scanner = "csv" if filename.endswith(".csv") else "trivy"
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

    return IngestResponse(
        assets_created=assets_created,
        vulns_assigned=vulns_assigned,
        vulns_skipped=vulns_skipped,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# GET /assets/{asset_id} -- asset detail with vulnerability list
# ---------------------------------------------------------------------------


@limiter.limit("60/minute")
@router.get("/assets/{asset_id}", response_model=AssetResponse)
def get_asset(request: Request, asset_id: int) -> AssetResponse:
    """Return full asset detail including all linked CVE records."""
    cmdb: CMDBStore = request.app.state.cmdb
    asset = cmdb.get_asset(asset_id)
    if asset is None:
        raise HTTPException(
            status_code=404,
            detail=ErrorDetail(
                code="asset_not_found",
                message=f"Asset {asset_id} not found.",
            ).model_dump(),
        )
    vulns = cmdb.get_asset_vulns(asset_id)
    counts = cmdb.get_priority_counts(asset_id)
    vuln_rows = [
        AssetVulnRow(
            vuln_id=v.id,
            cve_id=v.cve_id,
            status=v.status,
            base_priority=v.base_priority,
            effective_priority=v.effective_priority,
            discovered_at=v.discovered_at,
            deadline=v.deadline,
            owner=v.owner,
            scanner=v.scanner,
        )
        for v in vulns
    ]
    return AssetResponse(
        id=asset.id,
        hostname=asset.hostname,
        ip=asset.ip,
        environment=asset.environment,
        exposure=asset.exposure,
        criticality=asset.criticality,
        owner=asset.owner,
        tags=asset.tags,
        created_at=asset.created_at,
        vuln_counts=counts,
        vulnerabilities=vuln_rows,
        os=asset.os,
        eol_date=asset.eol_date,
        compliance=asset.compliance,
    )


# ---------------------------------------------------------------------------
# POST /assets/{asset_id}/vulnerabilities -- attach CVEs to an asset
# ---------------------------------------------------------------------------


@limiter.limit("10/minute")
@router.post("/assets/{asset_id}/vulnerabilities", response_model=list[AssetVulnRow])
def assign_vulnerabilities(
    request: Request,
    asset_id: int,
    body: AssetVulnAssign,
) -> list[AssetVulnRow]:
    """Enrich a list of CVE IDs and link them to the given asset.

    Uses the asset's exposure and criticality as triage context:
      1. process_cves() is called with the asset's exposure value.
      2. apply_criticality_modifier() upgrades priority for critical assets.
      3. Each result is stored as an AssetVulnerability with SLA deadline.

    Duplicate (asset, CVE) pairs are silently skipped -- already-assigned
    CVEs are not re-processed or overwritten.

    Returns the list of newly stored vulnerability rows.
    """
    cmdb: CMDBStore = request.app.state.cmdb
    asset = cmdb.get_asset(asset_id)
    if asset is None:
        raise HTTPException(
            status_code=404,
            detail=ErrorDetail(
                code="asset_not_found",
                message=f"Asset {asset_id} not found.",
            ).model_dump(),
        )

    enriched_list = process_cves(
        body.ids,
        request.app.state.kev_set,
        request.app.state.cache,
        exposure=asset.exposure,
    )

    stored: list[AssetVulnRow] = []
    for enriched in enriched_list:
        base_priority = enriched.triage_priority
        effective_priority = apply_criticality_modifier(base_priority, asset.criticality)
        vuln = AssetVulnerability(
            asset_id=asset_id,
            cve_id=enriched.id,
            base_priority=base_priority,
            effective_priority=effective_priority,
            scanner=body.scanner,
            owner=body.owner,
        )
        try:
            vuln_id = cmdb.create_asset_vuln(vuln)
        except IntegrityError:
            # Already assigned -- skip silently
            continue
        stored.append(
            AssetVulnRow(
                vuln_id=vuln_id,
                cve_id=enriched.id,
                status="pending",
                base_priority=base_priority,
                effective_priority=effective_priority,
                discovered_at=vuln.discovered_at or "",
                deadline=None,  # set by store; fetch from DB for accurate value
                owner=body.owner,
                scanner=body.scanner,
            )
        )

    return stored


# ---------------------------------------------------------------------------
# PATCH /assets/{asset_id}/vulnerabilities/{cve_id}/status -- update status
# ---------------------------------------------------------------------------


@limiter.limit("30/minute")
@router.patch("/assets/{asset_id}/vulnerabilities/{cve_id}/status")
def update_vuln_status(
    request: Request,
    asset_id: int,
    cve_id: str,
    body: AssetVulnStatusUpdate,
) -> dict:
    """Update the remediation status of an asset vulnerability.

    Valid transitions: pending -> in_progress -> verified -> closed | deferred
    Each status change writes an immutable RemediationRecord audit entry.

    Returns the updated vulnerability record.
    """
    normalized_cve = cve_id.upper()
    if not re.match(CVE_PATTERN, normalized_cve):
        raise HTTPException(
            status_code=400,
            detail=ErrorDetail(
                code="invalid_cve_id",
                message=f"{cve_id[:50]} does not match CVE-YYYY-NNNNN.",
            ).model_dump(),
        )

    cmdb: CMDBStore = request.app.state.cmdb

    vuln = cmdb.get_vuln_by_asset_and_cve(asset_id, normalized_cve)
    if vuln is None:
        raise HTTPException(
            status_code=404,
            detail=ErrorDetail(
                code="vuln_not_found",
                message=f"{normalized_cve} is not linked to asset {asset_id}.",
            ).model_dump(),
        )

    cmdb.update_vuln_status(
        vuln.id,
        status=body.status.value,
        owner=body.owner,
        evidence=body.evidence,
    )

    # Re-fetch to return the updated record
    updated = cmdb.get_vuln_by_asset_and_cve(asset_id, normalized_cve)
    return {
        "vuln_id": updated.id,
        "cve_id": updated.cve_id,
        "status": updated.status,
        "effective_priority": updated.effective_priority,
        "deadline": updated.deadline,
        "owner": updated.owner,
        "evidence": updated.evidence,
    }
