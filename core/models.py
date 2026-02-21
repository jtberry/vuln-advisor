from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CVSSDetails:
    score: Optional[float] = None
    severity: str = "Unknown"
    vector: Optional[str] = None
    attack_vector: str = ""
    attack_complexity: str = ""
    privileges_required: str = ""
    user_interaction: str = ""
    scope: str = ""
    confidentiality: str = ""
    integrity: str = ""
    availability: str = ""


@dataclass
class PoCInfo:
    has_poc: bool = False
    count: int = 0
    sources: list[str] = field(default_factory=list)


@dataclass
class RemediationStep:
    action: str  # PATCH | WORKAROUND | REFERENCE
    description: str


@dataclass
class Reference:
    url: str
    tags: list[str] = field(default_factory=list)
    name: str = ""


@dataclass
class EnrichedCVE:
    id: str
    description: str
    cvss: CVSSDetails
    cwe_id: Optional[str]
    cwe_name: str
    cwe_plain: str
    is_kev: bool
    epss_score: Optional[float]
    epss_percentile: Optional[float]
    poc: PoCInfo
    triage_priority: str  # P1 / P2 / P3 / P4
    triage_label: str
    triage_reason: str
    affected_products: list[str]
    patch_versions: list[str]
    remediation: list[RemediationStep]
    references: list[Reference]
