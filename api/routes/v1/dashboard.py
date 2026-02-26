"""
api/routes/v1/dashboard.py -- Aggregated metrics endpoint for the VulnAdvisor CMDB.

Returns a single payload suitable for driving dashboard widgets:
  - Total asset and open vulnerability counts
  - Priority distribution across all assets
  - Top assets ranked by P1 count

This is a read-only aggregate route -- no mutations here.
"""

from fastapi import APIRouter, Depends, Request

from api.limiter import limiter
from api.models import DashboardResponse
from auth.dependencies import get_current_user
from cmdb.store import CMDBStore

# Auth policy:
# - GET /api/v1/dashboard: requires auth -- aggregated CMDB metrics are internal data
# Router-level dependency enforces auth; the single handler does not repeat it.
router = APIRouter(dependencies=[Depends(get_current_user)])


@limiter.limit("60/minute")
@router.get("/dashboard", response_model=DashboardResponse)
def get_dashboard(request: Request) -> DashboardResponse:
    """Return aggregated risk metrics across all registered assets.

    Response:
      total_assets       -- number of registered assets
      total_open_vulns   -- sum of open (non-closed, non-deferred) vulnerabilities
      priority_counts    -- {"P1": N, "P2": N, "P3": N, "P4": N}
      top_assets_by_p1   -- up to 10 assets with the highest P1 count, descending
    """
    cmdb: CMDBStore = request.app.state.cmdb

    assets = cmdb.list_assets()
    priority_counts = cmdb.get_all_priority_counts()
    total_open_vulns = sum(priority_counts.values())

    # Single aggregate query replaces per-asset loop (N+1 -> 2 queries total)
    all_counts = cmdb.get_all_asset_priority_counts()
    zero = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}

    asset_p1: list[dict] = []
    for asset in assets:
        counts = all_counts.get(asset.id, zero)
        asset_p1.append(
            {
                "asset_id": asset.id,
                "hostname": asset.hostname,
                "criticality": asset.criticality,
                "p1_count": counts.get("P1", 0),
                "total_open": sum(counts.values()),
            }
        )

    top_assets = sorted(asset_p1, key=lambda x: x["p1_count"], reverse=True)[:10]

    return DashboardResponse(
        total_assets=len(assets),
        total_open_vulns=total_open_vulns,
        priority_counts=priority_counts,
        top_assets_by_p1=top_assets,
    )
