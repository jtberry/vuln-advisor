"""
API request and response models for VulnAdvisor REST endpoints.

These Pydantic v2 models define the HTTP transport contract for the API layer.
They are intentionally separate from the dataclasses in core/models.py, which
own the internal domain representation. Route handlers map between the two.

Separation of concerns: core/ models = domain truth; api/ models = API contract.
"""

from enum import Enum
from typing import Annotated, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.models import EnrichedCVE

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"

# Annotated type that applies the CVE pattern to every element in a list.
# Pydantic v2 validates each item against the constraint when used as list[_CveId].
_CveId = Annotated[str, Field(pattern=CVE_PATTERN)]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ExposureEnum(str, Enum):
    internet = "internet"
    internal = "internal"
    isolated = "isolated"


class PriorityEnum(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class BulkRequest(BaseModel):
    """Request body for POST /api/v1/cve/bulk.

    The field_validator normalizes entries (uppercase, deduplicate) before
    Pydantic applies the per-item CVE_PATTERN check, so callers may submit
    lowercase ids or duplicates without receiving a validation error.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    ids: list[_CveId] = Field(
        min_length=1,
        max_length=50,
        description="List of CVE IDs to look up. Min 1, max 50 per request.",
    )

    @field_validator("ids", mode="before")
    @classmethod
    def normalize_ids(cls, values: list) -> list[str]:
        """Uppercase and deduplicate CVE IDs while preserving original order.

        Runs before Pydantic's per-item pattern validation (mode='before') so
        the regex fires against the normalized form, not raw user input.
        """
        seen: set[str] = set()
        result: list[str] = []
        for v in values:
            normalized = str(v).upper()
            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)
        return result


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class CVESummaryRow(BaseModel):
    """Lightweight summary of a single CVE -- one row in the priority table.

    Excludes full remediation detail. Used in BulkResponse.summary.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    cvss_score: Optional[float]
    cvss_severity: str
    is_kev: bool
    has_poc: bool
    cwe_name: str
    triage_priority: str
    triage_label: str

    @classmethod
    def from_enriched(cls, cve: EnrichedCVE) -> "CVESummaryRow":
        """Build a CVESummaryRow from a core EnrichedCVE instance.

        This is the Factory Method pattern -- the mapping lives here, colocated
        with the output model, rather than scattered across route handlers.
        """
        return cls(
            id=cve.id,
            cvss_score=cve.cvss.score,
            cvss_severity=cve.cvss.severity,
            is_kev=cve.is_kev,
            has_poc=cve.poc.has_poc,
            cwe_name=cve.cwe_name,
            triage_priority=cve.triage_priority,
            triage_label=cve.triage_label,
        )


class BulkMeta(BaseModel):
    """Metadata envelope for a bulk CVE response."""

    model_config = ConfigDict(frozen=True)

    requested: int
    returned: int
    failed: int
    exposure: ExposureEnum


class BulkResponse(BaseModel):
    """Response body for POST /api/v1/cve/bulk.

    summary -- priority-bucketed rows (always present).
    results -- full EnrichedCVE JSON only when the caller passes ?full=true.
    """

    model_config = ConfigDict(frozen=True)

    meta: BulkMeta
    summary: dict[str, list[CVESummaryRow]]
    results: Optional[list[dict]] = None


class SummaryCountResponse(BaseModel):
    """Response for GET /api/v1/cve/summary.

    Returns a count of CVEs per priority bucket for the requested exposure
    context, useful for dashboard widgets without fetching full detail.
    """

    model_config = ConfigDict(frozen=True)

    counts: dict[str, int]
    total: int
    exposure: ExposureEnum


class ErrorDetail(BaseModel):
    """Machine-readable error payload."""

    model_config = ConfigDict(frozen=True)

    code: str
    message: str
    detail: Optional[str] = None


class ErrorResponse(BaseModel):
    """Top-level error envelope returned on 4xx/5xx responses."""

    model_config = ConfigDict(frozen=True)

    error: ErrorDetail


class HealthResponse(BaseModel):
    """Response for GET /api/v1/health."""

    model_config = ConfigDict(frozen=True)

    status: str = "ok"
    version: str


# ---------------------------------------------------------------------------
# CMDB -- enums
# ---------------------------------------------------------------------------


class CriticalityEnum(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class EnvironmentEnum(str, Enum):
    production = "production"
    staging = "staging"
    development = "development"


class VulnStatusEnum(str, Enum):
    pending = "pending"
    in_progress = "in_progress"
    verified = "verified"
    closed = "closed"
    deferred = "deferred"


# ---------------------------------------------------------------------------
# CMDB -- asset request/response models
# ---------------------------------------------------------------------------


class AssetCreate(BaseModel):
    """Request body for POST /api/v1/assets."""

    model_config = ConfigDict(str_strip_whitespace=True)

    hostname: str = Field(min_length=1, max_length=255)
    ip: Optional[str] = Field(default=None, max_length=45)
    environment: EnvironmentEnum = EnvironmentEnum.production
    exposure: ExposureEnum = ExposureEnum.internal
    criticality: CriticalityEnum = CriticalityEnum.medium
    owner: Optional[str] = Field(default=None, max_length=255)
    tags: list[str] = Field(default_factory=list, max_length=20)
    os: Optional[str] = Field(default=None, max_length=100)
    eol_date: Optional[str] = Field(default=None)
    compliance: list[str] = Field(default_factory=list)


class AssetVulnRow(BaseModel):
    """Single vulnerability record in an asset detail response."""

    model_config = ConfigDict(frozen=True)

    vuln_id: int
    cve_id: str
    status: str
    base_priority: str
    effective_priority: str
    discovered_at: str
    deadline: Optional[str]
    owner: Optional[str]
    scanner: str


class AssetResponse(BaseModel):
    """Full asset detail response including linked vulnerability records."""

    model_config = ConfigDict(frozen=True)

    id: int
    hostname: str
    ip: Optional[str]
    environment: str
    exposure: str
    criticality: str
    owner: Optional[str]
    tags: list[str]
    created_at: str
    vuln_counts: dict[str, int]
    vulnerabilities: list[AssetVulnRow] = Field(default_factory=list)
    os: Optional[str] = None
    eol_date: Optional[str] = None
    compliance: list[str] = Field(default_factory=list)


class AssetSummaryRow(BaseModel):
    """One row in the GET /assets list -- no vulnerability detail."""

    model_config = ConfigDict(frozen=True)

    id: int
    hostname: str
    environment: str
    exposure: str
    criticality: str
    owner: Optional[str]
    vuln_counts: dict[str, int]


# ---------------------------------------------------------------------------
# CMDB -- vulnerability assignment and status update
# ---------------------------------------------------------------------------


class AssetVulnAssign(BaseModel):
    """Request body for POST /api/v1/assets/{asset_id}/vulnerabilities."""

    model_config = ConfigDict(str_strip_whitespace=True)

    ids: list[_CveId] = Field(
        min_length=1,
        max_length=50,
        description="CVE IDs to link to this asset. Min 1, max 50 per request.",
    )
    scanner: str = Field(default="manual", max_length=30)
    owner: Optional[str] = Field(default=None, max_length=255)

    @field_validator("ids", mode="before")
    @classmethod
    def normalize_ids(cls, values: list) -> list[str]:
        """Uppercase and deduplicate CVE IDs before pattern validation."""
        seen: set[str] = set()
        result: list[str] = []
        for v in values:
            normalized = str(v).upper()
            if normalized not in seen:
                seen.add(normalized)
                result.append(normalized)
        return result


class AssetVulnStatusUpdate(BaseModel):
    """Request body for PATCH .../vulnerabilities/{cve_id}/status."""

    model_config = ConfigDict(str_strip_whitespace=True)

    status: VulnStatusEnum
    owner: Optional[str] = Field(default=None, max_length=255)
    evidence: Optional[str] = Field(default=None, max_length=1000)


# ---------------------------------------------------------------------------
# CMDB -- ingest and dashboard
# ---------------------------------------------------------------------------


class IngestResponse(BaseModel):
    """Response for POST /api/v1/ingest."""

    model_config = ConfigDict(frozen=True)

    assets_created: int
    vulns_assigned: int
    vulns_skipped: int
    errors: list[str] = Field(default_factory=list)


class DashboardResponse(BaseModel):
    """Response for GET /api/v1/dashboard."""

    model_config = ConfigDict(frozen=True)

    total_assets: int
    total_open_vulns: int
    priority_counts: dict[str, int]
    top_assets_by_p1: list[dict]
