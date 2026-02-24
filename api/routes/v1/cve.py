"""
api/routes/v1/cve.py -- CVE triage route handlers for the VulnAdvisor REST API.

Route registration order matters here. FastAPI resolves routes in the order
they are added to the router. The literal paths /cve/summary and /cve/bulk
must be registered before /cve/{cve_id} or FastAPI will match the strings
"summary" and "bulk" as CVE ID path parameters, returning 400s instead of
routing to the correct handlers.

Rate limits are applied via slowapi. The @limiter.limit() decorator must sit
ABOVE @router.get/post so that slowapi can attach the limit string to the
function object before FastAPI wraps it.
"""

import re
from dataclasses import asdict
from typing import Annotated, Optional

from fastapi import APIRouter, HTTPException, Query, Request

from api.limiter import limiter
from api.models import (
    CVE_PATTERN,
    BulkMeta,
    BulkRequest,
    BulkResponse,
    CVESummaryRow,
    ErrorDetail,
    ExposureEnum,
    PriorityEnum,
    SummaryCountResponse,
)
from core.pipeline import process_cve

router = APIRouter()


# ---------------------------------------------------------------------------
# Route 1: GET /cve/summary -- registered FIRST to avoid /{cve_id} capture
# ---------------------------------------------------------------------------


@limiter.limit("30/minute")
@router.get("/cve/summary", response_model=SummaryCountResponse)
def get_cve_summary(
    request: Request,
    ids: Annotated[str, Query(max_length=2000)],
    exposure: ExposureEnum = ExposureEnum.internal,
) -> SummaryCountResponse:
    """Return priority bucket counts for a comma-separated list of CVE IDs.

    Useful for dashboard widgets: returns {"P1": N, "P2": N, ...} rather than
    full enriched records. Max 50 IDs per request.

    Query params:
        ids      -- comma-separated CVE IDs (required)
        exposure -- internet | internal | isolated (default: internal)
    """
    # Parse, strip, uppercase, and deduplicate
    raw_ids = [part.strip().upper() for part in ids.split(",") if part.strip()]
    seen: set[str] = set()
    deduped: list[str] = []
    for cve_id in raw_ids:
        if cve_id not in seen:
            seen.add(cve_id)
            deduped.append(cve_id)

    # Validate each ID against the CVE pattern before touching any external
    # system. Input validation at the boundary -- never pass unvalidated user
    # data into URLs or downstream functions.
    for cve_id in deduped:
        if not re.match(CVE_PATTERN, cve_id):
            raise HTTPException(
                status_code=400,
                detail=ErrorDetail(
                    code="invalid_cve_id",
                    message="Invalid CVE ID format.",
                    detail=f"{cve_id[:50]} does not match CVE-YYYY-NNNNN.",
                ).model_dump(),
            )

    # Enforce the 50-ID cap after deduplication
    if len(deduped) > 50:
        raise HTTPException(
            status_code=422,
            detail=ErrorDetail(
                code="bulk_limit_exceeded",
                message="Request exceeds the maximum of 50 CVE IDs.",
                detail=f"Received {len(deduped)} unique IDs after deduplication.",
            ).model_dump(),
        )

    # Fetch and enrich each CVE; skip any that are not found or raise
    results = []
    for cve_id in deduped:
        try:
            enriched = process_cve(cve_id, request.app.state.kev_set, request.app.state.cache)
        except ValueError:
            continue
        if enriched is not None:
            results.append(enriched)

    # Bucket counts by triage priority
    counts: dict[str, int] = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for enriched in results:
        priority = enriched.triage_priority
        if priority in counts:
            counts[priority] += 1

    return SummaryCountResponse(counts=counts, total=len(results), exposure=exposure)


# ---------------------------------------------------------------------------
# Route 2: POST /cve/bulk -- registered SECOND to avoid /{cve_id} capture
# ---------------------------------------------------------------------------


@limiter.limit("5/minute")
@router.post("/cve/bulk", response_model=BulkResponse)
def post_cve_bulk(
    request: Request,
    body: BulkRequest,
    exposure: ExposureEnum = ExposureEnum.internal,
    full: bool = False,
    priority_filter: Optional[PriorityEnum] = None,
) -> BulkResponse:
    """Look up and enrich a batch of CVE IDs in a single request.

    body.ids is already validated (CVE_PATTERN) and deduplicated by Pydantic
    before this handler runs -- the BulkRequest field_validator and per-item
    annotation handle that. No re-validation is needed here.

    Query params:
        exposure        -- internet | internal | isolated (default: internal)
        full            -- include full EnrichedCVE JSON alongside summary rows
        priority_filter -- restrict summary and results to one priority bucket
    """
    failed = 0
    results = []

    for cve_id in body.ids:
        try:
            enriched = process_cve(cve_id, request.app.state.kev_set, request.app.state.cache)
        except ValueError:
            failed += 1
            continue
        if enriched is None:
            failed += 1
            continue
        results.append(enriched)

    # Apply optional priority filter -- narrows both summary and full results
    if priority_filter is not None:
        results = [r for r in results if r.triage_priority == priority_filter.value]

    # Build priority-bucketed summary rows
    summary: dict[str, list[CVESummaryRow]] = {"P1": [], "P2": [], "P3": [], "P4": []}
    for enriched in results:
        priority = enriched.triage_priority
        if priority in summary:
            summary[priority].append(CVESummaryRow.from_enriched(enriched))

    # Full records only when the caller explicitly requests them
    full_results: Optional[list[dict]] = [asdict(r) for r in results] if full else None

    return BulkResponse(
        meta=BulkMeta(
            requested=len(body.ids),
            returned=len(results),
            failed=failed,
            exposure=exposure,
        ),
        summary=summary,
        results=full_results,
    )


# ---------------------------------------------------------------------------
# Route 3: GET /cve/{cve_id} -- registered LAST so literals above win first
# ---------------------------------------------------------------------------


@limiter.limit("30/minute")
@router.get("/cve/{cve_id}")
def get_cve(
    request: Request,
    cve_id: str,
    exposure: ExposureEnum = ExposureEnum.internal,
) -> dict:
    """Fetch and enrich a single CVE by ID.

    Returns the full EnrichedCVE payload as JSON. The exposure param is
    accepted for API contract stability but does not yet modify triage
    priority -- that adjustment is a planned walk-phase feature. Accepting
    the param now means callers will not need to change their request shape
    when it lands.

    Path param:
        cve_id   -- e.g. CVE-2021-44228 (case-insensitive, normalized internally)
    Query params:
        exposure -- internet | internal | isolated (default: internal)
    """
    normalized = cve_id.upper()

    # Validate format before hitting the pipeline -- never pass unvalidated
    # user input into the URL substitution inside process_cve / fetch_nvd.
    if not re.match(CVE_PATTERN, normalized):
        raise HTTPException(
            status_code=400,
            detail=ErrorDetail(
                code="invalid_cve_id",
                message="Invalid CVE ID format.",
                detail=f"{cve_id[:50]} does not match CVE-YYYY-NNNNN.",
            ).model_dump(),
        )

    # process_cve raises ValueError for format problems that slip past the
    # regex above (defensive). Convert to 400 so the caller gets a clear
    # error rather than an unhandled 500.
    try:
        result = process_cve(normalized, request.app.state.kev_set, request.app.state.cache)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=ErrorDetail(
                code="invalid_cve_id",
                message=str(exc),
            ).model_dump(),
        ) from exc

    if result is None:
        raise HTTPException(
            status_code=404,
            detail=ErrorDetail(
                code="cve_not_found",
                message=f"{normalized} was not found in NVD.",
            ).model_dump(),
        )

    # asdict() converts the EnrichedCVE dataclass (and all nested dataclasses)
    # to a plain dict that FastAPI's JSON serializer handles natively.
    return asdict(result)
