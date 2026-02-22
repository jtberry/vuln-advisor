"""
formatter.py — Renders EnrichedCVE to terminal output or JSON.
"""

import json
from dataclasses import asdict

from .models import EnrichedCVE

W = 68  # output width

PRIORITY_COLORS = {
    "P1": "\033[91m",
    "P2": "\033[93m",
    "P3": "\033[94m",
    "P4": "\033[92m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[90m"


def _bar(char="═") -> str:
    """Return a full-width horizontal rule."""
    return char * W


def _section(title: str) -> str:
    """Return a bold section header with an underline rule."""
    return f"\n  {BOLD}{title}{RESET}\n  {'─' * (W - 2)}"


def _wrap(text: str, indent: int = 4, width: int = W) -> str:
    """Word-wrap text to the output width with a leading indent."""
    words = text.split()
    lines = []
    line = " " * indent
    for word in words:
        if len(line) + len(word) + 1 > width:
            lines.append(line)
            line = " " * indent + word
        else:
            line += ("" if line.strip() == "" else " ") + word
    if line.strip():
        lines.append(line)
    return "\n".join(lines)


def print_terminal(cve: EnrichedCVE) -> None:
    p_color = PRIORITY_COLORS.get(cve.triage_priority, "")

    # ── Header ───────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{_bar()}{RESET}")
    kev_tag = f"  {BOLD}\033[91m*** ACTIVELY EXPLOITED ***{RESET}" if cve.is_kev else ""
    print(f"  {BOLD}{cve.id}{RESET}  │  CVSS {cve.cvss.score} {cve.cvss.severity}{kev_tag}")
    print(f"{BOLD}{_bar()}{RESET}")

    # ── Triage Priority ──────────────────────────────────────────────────────
    print(_section("TRIAGE PRIORITY"))
    print(f"    {p_color}{BOLD}{cve.triage_priority} — {cve.triage_label}{RESET}")
    print(f"    {cve.triage_reason}")

    # ── Threat Snapshot ──────────────────────────────────────────────────────
    print(_section("THREAT SNAPSHOT"))
    score_str = f"{cve.cvss.score}/10" if cve.cvss.score else "N/A"
    print(f"    CVSS Score          {score_str} ({cve.cvss.severity})")
    kev_val = f"\033[91m{BOLD}YES — On CISA Known Exploited List{RESET}" if cve.is_kev else "No"
    print(f"    Actively Exploited  {kev_val}")
    if cve.epss_score is not None:
        pct = round(cve.epss_score * 100, 1)
        tile = round(cve.epss_percentile * 100, 1) if cve.epss_percentile else 0
        print(f"    Exploit Probability {pct}%  (higher than {tile}% of all CVEs)")
    if cve.poc.has_poc:
        print(f"    Public PoC          \033[91m{BOLD}YES — {cve.poc.count} public repo(s){RESET}")
        if cve.poc.link:
            print(f"                        {DIM}{cve.poc.link}{RESET}")
    else:
        print("    Public PoC          None found")

    # ── What Is It ───────────────────────────────────────────────────────────
    print(_section("WHAT IS IT?"))
    if cve.cwe_plain:
        print(f"    Type:  {cve.cwe_name}\n")
        print(_wrap(cve.cwe_plain))
    print()
    print(_wrap(cve.description))

    # ── Attack Surface ───────────────────────────────────────────────────────
    print(_section("HOW CAN IT BE ATTACKED?"))
    for label, val in [
        ("Who can attack", cve.cvss.attack_vector),
        ("Complexity", cve.cvss.attack_complexity),
        ("Login required", cve.cvss.privileges_required),
        ("User action needed", cve.cvss.user_interaction),
        ("Blast radius", cve.cvss.scope),
    ]:
        if val:
            print(f"    {label:<22}  {val}")

    # ── Impact ───────────────────────────────────────────────────────────────
    print(_section("WHAT COULD AN ATTACKER DO?"))
    for label, val in [
        ("Data confidentiality", cve.cvss.confidentiality),
        ("Data integrity", cve.cvss.integrity),
        ("Availability / uptime", cve.cvss.availability),
    ]:
        if val and val != "NONE":
            print(f"    {label:<26} {val} impact")

    # ── Affected Products ─────────────────────────────────────────────────────
    if cve.affected_products:
        print(_section("AFFECTED PRODUCTS"))
        for product in cve.affected_products[:6]:
            print(f"    • {product}")

    # ── Remediation ───────────────────────────────────────────────────────────
    print(_section("WHAT DO I DO?"))
    for i, step in enumerate(cve.remediation, 1):
        tag = f"[{step.action:<10}]"
        print(f"\n    {i}. {BOLD}{tag}{RESET}")
        print(_wrap(step.description, indent=8))

    # ── References ────────────────────────────────────────────────────────────
    patch_refs = [r for r in cve.references if any(t in ("Patch", "Vendor Advisory", "Mitigation") for t in r.tags)]
    if patch_refs:
        print(_section("PATCH / ADVISORY REFERENCES"))
        for ref in patch_refs[:5]:
            print(f"    • {ref.url}")
    elif cve.references:
        print(_section("REFERENCES"))
        for ref in cve.references[:5]:
            print(f"    • {ref.url}")

    print(f"\n{_bar()}\n")


def to_json(cve: EnrichedCVE) -> str:
    return json.dumps(asdict(cve), indent=2)
