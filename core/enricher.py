"""
enricher.py — Takes raw fetched data and enriches it into a structured,
plain-language EnrichedCVE ready for output.
"""

import logging
from typing import Optional

from .models import CVSSDetails, EnrichedCVE, PoCInfo, Reference, RemediationStep

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CWE — plain-language name, description, and generic remediation
# ---------------------------------------------------------------------------

CWE_MAP: dict[str, dict] = {
    "CWE-20": {
        "name": "Improper Input Validation",
        "plain": "The software doesn't properly check data it receives, allowing attackers to send malicious input.",
        "fix": "Validate and sanitize all input before processing.",
        "controls": [
            "Deploy a WAF with rules targeting malformed or unexpected input patterns.",
            "Enable application-level logging of input validation failures to detect probing.",
            "Rate-limit endpoints that accept external input to slow automated attack attempts.",
        ],
    },
    "CWE-22": {
        "name": "Path Traversal",
        "plain": "An attacker can trick the software into accessing files outside its intended directory.",
        "fix": "Restrict file access to expected directories. Never construct file paths from user input.",
        "controls": [
            "Enable WAF rules targeting path traversal patterns (../, %2e%2e, encoded variants).",
            "Monitor filesystem access logs for requests containing directory traversal sequences.",
            "Run the application process in a chroot jail or container to limit filesystem access.",
        ],
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "plain": "An attacker can make the software run operating system commands of their choosing.",
        "fix": "Avoid passing user input to shell commands. Use safe API alternatives.",
        "controls": [
            "Monitor for unexpected child process spawning from the application process (EDR alert).",
            "Restrict outbound network connections from the affected service to limit attacker callback.",
            "Enable application allow-listing to block execution of unauthorized binaries.",
        ],
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "plain": "An attacker can inject malicious scripts into web pages viewed by other users,"
        " potentially stealing sessions or data.",
        "fix": "Encode all output to the browser. Implement a Content Security Policy (CSP).",
        "controls": [
            "Enable Content Security Policy (CSP) headers to restrict what scripts can execute.",
            "Deploy a WAF with XSS detection rules as an additional layer.",
            "Monitor web server logs for script injection patterns in request parameters.",
        ],
    },
    "CWE-89": {
        "name": "SQL Injection",
        "plain": "An attacker can manipulate database queries to read, change, or delete data.",
        "fix": "Use parameterized queries or prepared statements. Never build SQL from user input.",
        "controls": [
            "Enable database activity monitoring (DAM) to detect unusual query patterns.",
            "Deploy a WAF with SQL injection signatures to block common attack payloads.",
            "Restrict the database account used by the application to the minimum required permissions.",
        ],
    },
    "CWE-94": {
        "name": "Code Injection",
        "plain": "An attacker can inject code that gets executed by the application.",
        "fix": "Never eval or execute user-supplied content as code.",
        "controls": [
            "Monitor for unexpected process execution originating from the application.",
            "Apply application allow-listing to prevent execution of unauthorized code.",
            "Restrict write access to directories the application can execute from.",
        ],
    },
    "CWE-125": {
        "name": "Out-of-bounds Read",
        "plain": "The software reads memory outside what it allocated, potentially leaking sensitive data.",
        "fix": "Apply vendor patch. Bounds-check all buffer accesses.",
        "controls": [
            "Verify memory protection features are enabled on the host (ASLR, DEP/NX).",
            "Monitor for repeated application crashes or core dumps which may indicate exploitation.",
            "Consider running the affected service in an isolated process or sandbox.",
        ],
    },
    "CWE-190": {
        "name": "Integer Overflow",
        "plain": "A math overflow causes unexpected behavior that attackers can exploit.",
        "fix": "Apply vendor patch. Validate numeric input ranges.",
        "controls": [
            "Verify memory protection features are enabled on the host (ASLR, DEP/NX).",
            "Monitor for application crashes or unexpected behavior following numeric input.",
        ],
    },
    "CWE-200": {
        "name": "Information Exposure",
        "plain": "Sensitive information is exposed to people who shouldn't have access to it.",
        "fix": "Review and restrict what information is returned in errors or responses.",
        "controls": [
            "Audit API and error responses immediately for sensitive data leakage.",
            "Monitor access logs for unusual enumeration patterns or high-volume data requests.",
            "Enable rate limiting on affected endpoints to slow data harvesting attempts.",
        ],
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "plain": "The system doesn't properly verify who someone is, allowing unauthorized access.",
        "fix": "Apply vendor patch. Enforce multi-factor authentication where possible.",
        "controls": [
            "Enable MFA on all accounts that can access the affected system.",
            "Monitor authentication logs for unusual patterns, repeated failures, or off-hours access.",
            "Implement account lockout policies to slow brute-force attempts.",
        ],
    },
    "CWE-295": {
        "name": "Improper Certificate Validation",
        "plain": "The software doesn't verify SSL/TLS certificates properly, enabling man-in-the-middle attacks.",
        "fix": "Apply vendor patch. Ensure certificate validation is not disabled in configuration.",
        "controls": [
            "Audit configuration to confirm certificate validation is not explicitly disabled.",
            "Monitor network traffic for unexpected or self-signed certificates on sensitive connections.",
            "Restrict outbound TLS connections from the affected service to known-good endpoints.",
        ],
    },
    "CWE-306": {
        "name": "Missing Authentication",
        "plain": "Critical functions can be accessed without any login or credentials.",
        "fix": "Apply vendor patch. Audit exposed endpoints for authentication requirements.",
        "controls": [
            "Restrict network access to the affected endpoint via firewall rules immediately.",
            "Place the service behind an authenticated reverse proxy as a temporary control.",
            "Monitor access logs for unauthorized requests to the unprotected endpoint.",
        ],
    },
    "CWE-326": {
        "name": "Inadequate Encryption Strength",
        "plain": "The encryption used is weak enough that attackers can break it.",
        "fix": "Upgrade to AES-256 or equivalent. Disable weak cipher suites.",
        "controls": [
            "Disable weak cipher suites in server/service configuration immediately (RC4, DES, 3DES).",
            "Scan TLS configuration with testssl.sh or sslyze to confirm weak ciphers are removed.",
            "Monitor for negotiation of weak ciphers in network traffic logs.",
        ],
    },
    "CWE-327": {
        "name": "Broken Cryptographic Algorithm",
        "plain": "The software uses outdated or broken cryptography that attackers can defeat.",
        "fix": "Replace deprecated algorithms (MD5, SHA-1, DES) with modern equivalents.",
        "controls": [
            "Audit configuration to identify and disable deprecated algorithm usage (MD5, SHA-1, DES).",
            "Monitor network traffic for use of deprecated algorithms in TLS negotiation.",
            "Scan with testssl.sh or sslyze to confirm deprecated algorithms are disabled.",
        ],
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "plain": "An attacker can trick a logged-in user into unknowingly performing actions.",
        "fix": "Implement CSRF tokens. Use SameSite cookie attribute.",
        "controls": [
            "Verify SameSite cookie attributes are set to Strict or Lax on session cookies.",
            "Monitor access logs for unexpected cross-origin requests to state-changing endpoints.",
            "Enable referrer-based request validation as a temporary layer while patching.",
        ],
    },
    "CWE-400": {
        "name": "Uncontrolled Resource Consumption",
        "plain": "An attacker can exhaust system memory or CPU, causing a denial of service.",
        "fix": "Apply vendor patch. Implement rate limiting and resource quotas.",
        "controls": [
            "Enable rate limiting and connection throttling on affected endpoints immediately.",
            "Monitor CPU, memory, and connection metrics for spikes indicating an attack.",
            "Configure auto-scaling or load shedding if the infrastructure supports it.",
        ],
    },
    "CWE-416": {
        "name": "Use After Free",
        "plain": "The software uses memory after releasing it, which attackers can exploit to run code.",
        "fix": "Apply vendor patch. No user-side workaround available for this class.",
        "controls": [
            "Verify memory protection features are enabled on the host (ASLR, DEP/NX, stack canaries).",
            "Monitor for application crashes or core dumps which may indicate exploitation attempts.",
            "Consider running the affected service in an isolated process or container.",
        ],
    },
    "CWE-434": {
        "name": "Unrestricted File Upload",
        "plain": "An attacker can upload malicious files (e.g., scripts) that the server may execute.",
        "fix": "Validate file types server-side. Store uploads outside the web root.",
        "controls": [
            "Confirm upload directories are outside the web root and have no execute permissions.",
            "Monitor upload directories for newly created files with executable extensions.",
            "Scan uploaded files with antivirus or content inspection before allowing access.",
        ],
    },
    "CWE-476": {
        "name": "NULL Pointer Dereference",
        "plain": "The application crashes when it tries to use an uninitialized memory reference.",
        "fix": "Apply vendor patch.",
        "controls": [
            "Monitor for repeated application crashes or restarts which may indicate exploitation.",
            "Enable process crash alerting and automatic restart to maintain availability.",
        ],
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "plain": "Malicious data can be used to execute code when the application processes (deserializes) it.",
        "fix": "Apply vendor patch. Do not deserialize data from untrusted sources.",
        "controls": [
            "Monitor for unexpected child process spawning from application servers (key IOC for this class).",
            "Restrict outbound network connections from the affected service to limit attacker callback.",
            "Enable logging of all deserialization operations to detect malformed payload attempts.",
        ],
    },
    "CWE-611": {
        "name": "XML External Entity (XXE)",
        "plain": "XML processing can be exploited to read local files or make internal network requests.",
        "fix": "Disable external entity processing in your XML parser.",
        "controls": [
            "Audit XML parser configuration to confirm external entity processing is disabled.",
            "Monitor for unexpected outbound HTTP or DNS requests from the application.",
            "Deploy WAF rules targeting XXE attack patterns in XML request bodies.",
        ],
    },
    "CWE-732": {
        "name": "Incorrect Permission Assignment",
        "plain": "Files or resources have overly permissive access controls.",
        "fix": "Audit and tighten file/resource permissions. Apply least privilege.",
        "controls": [
            "Audit file and resource permissions immediately and remove unnecessary access.",
            "Enable file integrity monitoring (FIM) on sensitive paths to detect unauthorized changes.",
            "Monitor access logs for unusual access patterns to sensitive files or directories.",
        ],
    },
    "CWE-787": {
        "name": "Out-of-bounds Write",
        "plain": "The software writes data outside its allocated memory, potentially allowing code execution.",
        "fix": "Apply vendor patch.",
        "controls": [
            "Verify memory protection features are enabled on the host (ASLR, DEP/NX).",
            "Monitor for application crashes which may indicate active exploitation attempts.",
            "Consider running the affected service in an isolated process or container.",
        ],
    },
    "CWE-798": {
        "name": "Hard-coded Credentials",
        "plain": "The application has embedded usernames or passwords that attackers can extract.",
        "fix": "Remove hard-coded credentials. Rotate any exposed secrets immediately.",
        "controls": [
            "Rotate the exposed credentials immediately — assume they are already compromised.",
            "Monitor authentication logs for use of the exposed credentials from unexpected sources.",
            "Audit access logs for any activity using the affected account since the vulnerability was introduced.",
        ],
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "plain": "An attacker can make the server send requests to internal systems or external services.",
        "fix": "Validate and allowlist URLs the server is permitted to contact.",
        "controls": [
            "Implement egress filtering to block outbound requests to internal IP ranges (RFC1918).",
            "Monitor outbound network traffic from the application for unexpected internal requests.",
            "Deploy WAF rules targeting SSRF patterns in request parameters.",
        ],
    },
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
        details.attack_vector = _AV.get(parts.get("AV", ""), "")
        details.attack_complexity = _AC.get(parts.get("AC", ""), "")
        details.privileges_required = _PR.get(parts.get("PR", ""), "")
        details.user_interaction = _UI.get(parts.get("UI", ""), "")
        details.scope = _SCOPE.get(parts.get("S", ""), "")
        details.confidentiality = _IMPACT.get(parts.get("C", ""), "")
        details.integrity = _IMPACT.get(parts.get("I", ""), "")
        details.availability = _IMPACT.get(parts.get("A", ""), "")
    except (
        ValueError,
        KeyError,
        IndexError,
        TypeError,
        AttributeError,
    ) as e:
        logger.warning("CVSS vector parse failed: vector=%r error=%s", vector, e)


def _extract_cvss(cve: dict) -> CVSSDetails:
    details = CVSSDetails()
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            entry = metrics[key][0]
            cvss_data = entry.get("cvssData", {})
            details.score = cvss_data.get("baseScore")
            details.severity = (cvss_data.get("baseSeverity") or entry.get("baseSeverity", "Unknown")).upper()
            details.vector = cvss_data.get("vectorString")
            if details.vector:
                _parse_cvss_vector(details.vector, details)
            break
    return details


def _extract_cwe(cve: dict):
    """Return the first CWE ID found, or None."""
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val != "CWE-noinfo" and val != "CWE-Other":
                return val
    return None


def _extract_affected_and_patches(cve: dict):
    """Return (affected_products list, patch_versions list) from CPE data."""
    affected = []
    patches = []

    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""

                    # Build a version-range label when range bounds are present.
                    start_ver = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                    end_ver = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                    if start_ver and end_ver:
                        range_label = f"{vendor} {product} {start_ver} through {end_ver}"
                    elif end_ver:
                        range_label = f"{vendor} {product} (up to {end_ver})"
                    elif start_ver:
                        range_label = f"{vendor} {product} (from {start_ver})"
                    else:
                        range_label = f"{vendor} {product}" + (f" {version}" if version else "")

                    if range_label not in affected:
                        affected.append(range_label)

                fix_ver = match.get("versionEndExcluding") or match.get("versionEndIncluding")
                if fix_ver:
                    qualifier = "or later" if match.get("versionEndExcluding") else "(inclusive)"
                    patch_label = f"{parts[4].replace('_', ' ').title()} {fix_ver} {qualifier}"
                    if patch_label not in patches:
                        patches.append(patch_label)

    return affected[:10], patches


def _build_remediation(
    cwe_id: Optional[str], patch_versions: list[str], references: list[Reference]
) -> list[RemediationStep]:
    steps: list[RemediationStep] = []

    if patch_versions:
        steps.append(
            RemediationStep(
                action="PATCH",
                description="Upgrade to the following fixed version(s): " + ", ".join(patch_versions),
                priority="CRITICAL",
            )
        )
    else:
        steps.append(
            RemediationStep(
                action="PATCH",
                description="Apply the vendor-supplied patch. Check vendor advisories in the references below.",
                priority="CRITICAL",
            )
        )

    if cwe_id and cwe_id in CWE_MAP:
        steps.append(
            RemediationStep(
                action="WORKAROUND",
                description=CWE_MAP[cwe_id]["fix"],
                priority="RECOMMENDED",
            )
        )

    advisory_urls = [r.url for r in references if any(t in ("Patch", "Vendor Advisory", "Mitigation") for t in r.tags)]
    if advisory_urls:
        steps.append(
            RemediationStep(
                action="REFERENCE",
                description="Vendor advisory: " + advisory_urls[0],
                priority="OPTIONAL",
            )
        )

    return steps


def _triage_priority(
    cvss: CVSSDetails,
    is_kev: bool,
    epss_score: Optional[float],
    has_poc: bool,
    exposure: str = "internal",
) -> tuple:
    score = cvss.score or 0.0

    if score >= 9.0 and (is_kev or (epss_score or 0) >= 0.5):
        priority = "P1"
        label = "Fix within 24 hours"
        reason = "Critical CVSS score with active exploitation or high exploit probability."
    elif score >= 7.0 and (is_kev or has_poc or (epss_score or 0) >= 0.3):
        priority = "P2"
        label = "Fix within 7 days"
        reason = "High severity with public exploit or elevated exploitation probability."
    elif score >= 7.0:
        priority = "P2"
        label = "Fix within 7 days"
        reason = "High CVSS severity."
    elif score >= 4.0:
        priority = "P3"
        label = "Fix within 30 days"
        reason = "Medium severity - schedule for next patch cycle."
    else:
        priority = "P4"
        label = "Fix at next scheduled patch cycle"
        reason = "Low severity - address as part of routine patching."

    # Exposure adjustment: lower priority for assets with reduced attack surface.
    # Never downgrade a KEV-confirmed exploit regardless of exposure.
    if exposure == "isolated" and not is_kev:
        _priority_map = {"P1": "P2", "P2": "P3", "P3": "P4", "P4": "P4"}
        priority = _priority_map.get(priority, priority)
    elif exposure == "internet" and priority in ("P2", "P3"):
        # Internet-facing assets get one level higher urgency for exploitable vulns
        if has_poc or (epss_score is not None and epss_score >= 0.2):
            _upgrade_map = {"P2": "P1", "P3": "P2"}
            priority = _upgrade_map.get(priority, priority)

    return priority, label, reason


def _build_compensating_controls(cwe_id: Optional[str]) -> list[str]:
    """Return general compensating controls for the given CWE, or empty list."""
    if not cwe_id or cwe_id not in CWE_MAP:
        return []
    return CWE_MAP[cwe_id].get("controls", [])


def _build_sigma_link(cve_id: str) -> Optional[str]:
    """Return a SigmaHQ GitHub code-search URL for the CVE."""
    if not cve_id or not cve_id.startswith("CVE-"):
        return None
    return f"https://github.com/SigmaHQ/sigma/search?q={cve_id}&type=code"


def enrich(
    cve_raw: dict, kev_set: set[str], epss_data: dict, poc_data: dict, exposure: str = "internal"
) -> EnrichedCVE:
    """Combine all fetched data into a structured, plain-language EnrichedCVE."""

    cve_id = cve_raw.get("id", "Unknown")

    descriptions = cve_raw.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available.")

    cvss = _extract_cvss(cve_raw)
    cwe_id = _extract_cwe(cve_raw)
    cwe_info = CWE_MAP.get(cwe_id, {}) if cwe_id else {}

    is_kev = cve_id in kev_set
    epss_score = epss_data.get("score")
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
    priority, label, reason = _triage_priority(cvss, is_kev, epss_score, poc.has_poc, exposure)
    compensating_controls = _build_compensating_controls(cwe_id)
    sigma_link = _build_sigma_link(cve_id)

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
        compensating_controls=compensating_controls,
        sigma_link=sigma_link,
        references=references,
    )
