"""
cmdb/models.py -- Domain dataclasses for the VulnAdvisor CMDB.

These are pure data containers with zero logic. All business logic (criticality
modifiers, SLA deadlines, status transitions) lives in cmdb/store.py.

Separation of concerns: these dataclasses are the CMDB's domain truth, just as
core/models.py is the CVE engine's domain truth. Neither layer imports the other.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Asset:
    """A tracked infrastructure asset.

    exposure feeds directly into CVE triage: it is a property of the asset,
    not a per-request flag. criticality triggers a priority upgrade when
    set to "critical" (see cmdb/store.apply_criticality_modifier).

    id is None before the record is written to the database.
    """

    hostname: str
    environment: str  # "production" | "staging" | "development"
    exposure: str  # "internet" | "internal" | "isolated"
    criticality: str  # "critical" | "high" | "medium" | "low"
    id: Optional[int] = None
    ip: Optional[str] = None
    owner: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    created_at: str = ""  # ISO 8601, set by store on insert


@dataclass
class AssetVulnerability:
    """A CVE linked to an asset with enrichment context and remediation state.

    base_priority   -- triage_priority from core/enricher, before any modifier
    effective_priority -- final priority after criticality modifier is applied

    Both values are stored so auditors can see the raw enricher output alongside
    the asset-adjusted priority that drives remediation SLA.

    id is None before the record is written to the database.
    """

    asset_id: int
    cve_id: str
    status: str = "pending"  # "pending" | "in_progress" | "verified" | "closed" | "deferred"
    base_priority: str = ""
    effective_priority: str = ""
    discovered_at: str = ""  # ISO 8601
    deadline: Optional[str] = None  # ISO 8601, auto-set from SLA on insert
    owner: Optional[str] = None
    evidence: Optional[str] = None  # ticket URL or verification note
    scanner: str = "manual"  # "manual" | "trivy" | "grype" | "nessus" | "csv"
    id: Optional[int] = None


@dataclass
class RemediationRecord:
    """Immutable audit entry written whenever an AssetVulnerability status changes.

    Builds an append-only audit trail for compliance and SLA reporting.
    Records are never updated or deleted -- only inserted.

    id is None before the record is written to the database.
    """

    asset_vuln_id: int
    status: str  # the new status after the change
    updated_at: str  # ISO 8601
    owner: Optional[str] = None
    evidence: Optional[str] = None
    id: Optional[int] = None
