from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Domain constants
# ---------------------------------------------------------------------------

# Canonical CVE ID format. A domain rule -- not an API contract.
# All layers (api/, web/, CLI) that need to validate CVE IDs import from here.
CVE_PATTERN = r"^CVE-\d{4}-\d{4,}$"


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
    priority: str = "RECOMMENDED"


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
    compensating_controls: list[str]  # general controls if patching is not immediate
    sigma_link: Optional[str]  # Sigma rule search URL for detection rules
    references: list[Reference]
