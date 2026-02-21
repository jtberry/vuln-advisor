"""
enricher.py — Takes raw fetched data and enriches it into a structured,
plain-language EnrichedCVE ready for output.
"""

from typing import Any, Dict, List, Optional, Set
from .models import CVSSDetails, EnrichedCVE, PoCInfo, Reference, RemediationStep

# ---------------------------------------------------------------------------
# CWE — plain-language name, description, and generic remediation
# ---------------------------------------------------------------------------

CWE_MAP: Dict[str, Dict[str, str]] = {
    "CWE-20":  {"name": "Improper Input Validation",
                "plain": "The software doesn't properly check data it receives, allowing attackers to send malicious input.",
                "fix": "Validate and sanitize all input before processing."},
    "CWE-22":  {"name": "Path Traversal",
                "plain": "An attacker can trick the software into accessing files outside its intended directory.",
                "fix": "Restrict file access to expected directories. Never construct file paths from user input."},
    "CWE-78":  {"name": "OS Command Injection",
                "plain": "An attacker can make the software run operating system commands of their choosing.",
                "fix": "Avoid passing user input to shell commands. Use safe API alternatives."},
    "CWE-79":  {"name": "Cross-Site Scripting (XSS)",
                "plain": "An attacker can inject malicious scripts into web pages viewed by other users, potentially stealing sessions or data.",
                "fix": "Encode all output to the browser. Implement a Content Security Policy (CSP)."},
    "CWE-89":  {"name": "SQL Injection",
                "plain": "An attacker can manipulate database queries to read, change, or delete data.",
                "fix": "Use parameterized queries or prepared statements. Never build SQL from user input."},
    "CWE-94":  {"name": "Code Injection",
                "plain": "An attacker can inject code that gets executed by the application.",
                "fix": "Never eval or execute user-supplied content as code."},
    "CWE-125": {"name": "Out-of-bounds Read",
                "plain": "The software reads memory outside what it allocated, potentially leaking sensitive data.",
                "fix": "Apply vendor patch. Bounds-check all buffer accesses."},
    "CWE-190": {"name": "Integer Overflow",
                "plain": "A math overflow causes unexpected behavior that attackers can exploit.",
                "fix": "Apply vendor patch. Validate numeric input ranges."},
    "CWE-200": {"name": "Information Exposure",
                "plain": "Sensitive information is exposed to people who shouldn't have access to it.",
                "fix": "Review and restrict what information is returned in errors or responses."},
    "CWE-287": {"name": "Improper Authentication",
                "plain": "The system doesn't properly verify who someone is, allowing unauthorized access.",
                "fix": "Apply vendor patch. Enforce multi-factor authentication where possible."},
    "CWE-295": {"name": "Improper Certificate Validation",
                "plain": "The software doesn't verify SSL/TLS certificates properly, enabling man-in-the-middle attacks.",
                "fix": "Apply vendor patch. Ensure certificate validation is not disabled in configuration."},
    "CWE-306": {"name": "Missing Authentication",
                "plain": "Critical functions can be accessed without any login or credentials.",
                "fix": "Apply vendor patch. Audit exposed endpoints for authentication requirements."},
    "CWE-326": {"name": "Inadequate Encryption Strength",
                "plain": "The encryption used is weak enough that attackers can break it.",
                "fix": "Upgrade to AES-256 or equivalent. Disable weak cipher suites."},
    "CWE-327": {"name": "Broken Cryptographic Algorithm",
                "plain": "The software uses outdated or broken cryptography that attackers can defeat.",
                "fix": "Replace deprecated algorithms (MD5, SHA-1, DES) with modern equivalents."},
    "CWE-352": {"name": "Cross-Site Request Forgery (CSRF)",
                "plain": "An attacker can trick a logged-in user into unknowingly performing actions.",
                "fix": "Implement CSRF tokens. Use SameSite cookie attribute."},
    "CWE-400": {"name": "Uncontrolled Resource Consumption",
                "plain": "An attacker can exhaust system memory or CPU, causing a denial of service.",
                "fix": "Apply vendor patch. Implement rate limiting and resource quotas."},
    "CWE-416": {"name": "Use After Free",
                "plain": "The software uses memory after releasing it, which attackers can exploit to run code.",
                "fix": "Apply vendor patch. No user-side workaround available for this class."},
    "CWE-434": {"name": "Unrestricted File Upload",
                "plain": "An attacker can upload malicious files (e.g., scripts) that the server may execute.",
                "fix": "Validate file types server-side. Store uploads outside the web root."},
    "CWE-476": {"name": "NULL Pointer Dereference",
                "plain": "The application crashes when it tries to use an uninitialized memory reference.",
                "fix": "Apply vendor patch."},
    "CWE-502": {"name": "Deserialization of Untrusted Data",
                "plain": "Malicious data can be used to execute code when the application processes (deserializes) it.",
                "fix": "Apply vendor patch. Do not deserialize data from untrusted sources."},
    "CWE-611": {"name": "XML External Entity (XXE)",
                "plain": "XML processing can be exploited to read local files or make internal network requests.",
                "fix": "Disable external entity processing in your XML parser."},
    "CWE-732": {"name": "Incorrect Permission Assignment",
                "plain": "Files or resources have overly permissive access controls.",
                "fix": "Audit and tighten file/resource permissions. Apply least privilege."},
    "CWE-787": {"name": "Out-of-bounds Write",
                "plain": "The software writes data outside its allocated memory, potentially allowing code execution.",
                "fix": "Apply vendor patch."},
    "CWE-798": {"name": "Hard-coded Credentials",
                "plain": "The application has embedded usernames or passwords that attackers can extract.",
                "fix": "Remove hard-coded credentials. Rotate any exposed secrets immediately."},
    "CWE-918": {"name": "Server-Side Request Forgery (SSRF)",
                "plain": "An attacker can make the server send requests to internal systems or external services.",
                "fix": "Validate and allowlist URLs the server is permitted to contact."},
}

# ---------------------------------------------------------------------------
# CVSS vector plain-language maps
# ---------------------------------------------------------------------------

_AV = {
    "N": "Anyone on the internet can attempt this remotely",
    "A": "Attacker must be on the same local network",
    "L": "Attacker needs local/shell access to the system",
    "P": "Attacker needs physical access to the device",
}
_AC = {
    "L": "No special conditions needed — straightforward to exploit",
    "H": "Specific conditions must be met — harder to exploit",
}
_PR = {
    "N": "No account or login required",
    "L": "Basic user account required",
    "H": "Admin or privileged account required",
}
_UI = {
    "N": "No user action needed",
    "R": "A user must take an action (e.g., open a file, click a link)",
}
_SCOPE = {
    "C": "Impact can spread beyond the vulnerable component",
    "U": "Impact is contained to the vulnerable component",
}
_IMPACT = {
    "H": "HIGH",
    "L": "LOW",
    "N": "NONE",
}


def _parse_cvss_vector(vector: str, details: CVSSDetails) -> None:
    """Parse a CVSS v3 vector string and populate plain-language fields."""
    try:
        parts = dict(p.split(":") for p in vector.split("/") if ":" in p)
        details.attack_vector        = _AV.get(parts.get("AV", ""), "")
        details.attack_complexity    = _AC.get(parts.get("AC", ""), "")
        details.privileges_required  = _PR.get(parts.get("PR", ""), "")
        details.user_interaction     = _UI.get(parts.get("UI", ""), "")
        details.scope                = _SCOPE.get(parts.get("S", ""), "")
        details.confidentiality      = _IMPACT.get(parts.get("C", ""), "")
        details.integrity            = _IMPACT.get(parts.get("I", ""), "")
        details.availability         = _IMPACT.get(parts.get("A", ""), "")
    except Exception:
        pass


def _extract_cvss(cve: Dict) -> CVSSDetails:
    details = CVSSDetails()
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            entry = metrics[key][0]
            cvss_data = entry.get("cvssData", {})
            details.score    = cvss_data.get("baseScore")
            details.severity = (cvss_data.get("baseSeverity")
                                or entry.get("baseSeverity", "Unknown")).upper()
            details.vector   = cvss_data.get("vectorString")
            if details.vector:
                _parse_cvss_vector(details.vector, details)
            break
    return details


def _extract_cwe(cve: Dict):
    """Return the first CWE ID found, or None."""
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val != "CWE-noinfo" and val != "CWE-Other":
                return val
    return None


def _extract_affected_and_patches(cve: Dict):
    """Return (affected_products list, patch_versions list) from CPE data."""
    affected = []
    patches  = []

    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor  = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                    label = f"{vendor} {product}" + (f" {version}" if version else "")
                    if label not in affected:
                        affected.append(label)

                fix_ver = match.get("versionEndExcluding") or match.get("versionEndIncluding")
                if fix_ver:
                    qualifier = "or later" if match.get("versionEndExcluding") else "(inclusive)"
                    patch_label = f"{parts[4].replace('_', ' ').title()} {fix_ver} {qualifier}"
                    if patch_label not in patches:
                        patches.append(patch_label)

    return affected[:10], patches[:5]


def _build_remediation(cwe_id: Optional[str], patch_versions: List[str],
                       references: List[Reference]) -> List[RemediationStep]:
    steps: List[RemediationStep] = []

    if patch_versions:
        steps.append(RemediationStep(
            action="PATCH",
            description="Upgrade to the following fixed version(s): " + ", ".join(patch_versions),
        ))
    else:
        steps.append(RemediationStep(
            action="PATCH",
            description="Apply the vendor-supplied patch. Check vendor advisories in the references below.",
        ))

    if cwe_id and cwe_id in CWE_MAP:
        steps.append(RemediationStep(
            action="WORKAROUND",
            description=CWE_MAP[cwe_id]["fix"],
        ))

    advisory_urls = [r.url for r in references if any(
        t in ("Patch", "Vendor Advisory", "Mitigation") for t in r.tags
    )]
    if advisory_urls:
        steps.append(RemediationStep(
            action="REFERENCE",
            description="Vendor advisory: " + advisory_urls[0],
        ))

    return steps


def _triage_priority(cvss: CVSSDetails, is_kev: bool,
                     epss_score: Optional[float], has_poc: bool):
    score = cvss.score or 0.0

    if score >= 9.0 and (is_kev or (epss_score or 0) >= 0.5):
        return "P1", "Fix within 24 hours", \
               "Critical CVSS score with active exploitation or high exploit probability."

    if score >= 7.0 and (is_kev or has_poc or (epss_score or 0) >= 0.3):
        return "P2", "Fix within 7 days", \
               "High severity with public exploit or elevated exploitation probability."

    if score >= 7.0:
        return "P2", "Fix within 7 days", \
               "High CVSS severity."

    if score >= 4.0:
        return "P3", "Fix within 30 days", \
               "Medium severity — schedule for next patch cycle."

    return "P4", "Fix at next scheduled patch cycle", \
           "Low severity — address as part of routine patching."


def enrich(cve_raw: Dict, kev_set: Set[str],
           epss_data: Dict, poc_data: Dict) -> EnrichedCVE:
    """Combine all fetched data into a structured, plain-language EnrichedCVE."""

    cve_id = cve_raw.get("id", "Unknown")

    descriptions = cve_raw.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available."
    )

    cvss = _extract_cvss(cve_raw)
    cwe_id = _extract_cwe(cve_raw)
    cwe_info = CWE_MAP.get(cwe_id, {}) if cwe_id else {}

    is_kev = cve_id in kev_set
    epss_score      = epss_data.get("score")
    epss_percentile = epss_data.get("percentile")

    poc = PoCInfo(
        has_poc=poc_data.get("has_poc", False),
        count=poc_data.get("count", 0),
        sources=poc_data.get("sources", []),
    )

    affected, patches = _extract_affected_and_patches(cve_raw)

    references = [
        Reference(url=r.get("url", ""), tags=r.get("tags", []), name=r.get("source", ""))
        for r in cve_raw.get("references", [])
    ]

    remediation = _build_remediation(cwe_id, patches, references)
    priority, label, reason = _triage_priority(cvss, is_kev, epss_score, poc.has_poc)

    return EnrichedCVE(
        id=cve_id,
        description=description,
        cvss=cvss,
        cwe_id=cwe_id,
        cwe_name=cwe_info.get("name", "Unknown Vulnerability Type"),
        cwe_plain=cwe_info.get("plain", ""),
        is_kev=is_kev,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        poc=poc,
        triage_priority=priority,
        triage_label=label,
        triage_reason=reason,
        affected_products=affected,
        patch_versions=patches,
        remediation=remediation,
        references=references,
    )
