"""
formatter.py — Renders EnrichedCVE to terminal output or JSON.
"""

import json
from dataclasses import asdict

from .models import EnrichedCVE

W = 68  # output width

PRIORITY_COLORS = {
    "P1": "\033[91m",  # red
    "P2": "\033[93m",  # yellow
    "P3": "\033[94m",  # blue
    "P4": "\033[92m",  # green
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _bar(char="═") -> str:
    return char * W


def _section(title: str) -> str:
    return f"\n  {BOLD}{title}{RESET}\n  {'─' * (W - 2)}"


def _wrap(text: str, indent: int = 4, width: int = W) -> str:
    """Simple word-wrap at `width` chars with leading indent."""
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

    # ── Header ──────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{_bar()}{RESET}")
    kev_tag = f"  {BOLD}\033[91m*** ACTIVELY EXPLOITED ***{RESET}" if cve.is_kev else ""
    print(f"  {BOLD}{cve.id}{RESET}  │  CVSS {cve.cvss.score} {cve.cvss.severity}{kev_tag}")
    print(f"{BOLD}{_bar()}{RESET}")

    # ── Triage Priority ─────────────────────────────────────────────────────
    print(_section("TRIAGE PRIORITY"))
    print(f"    {p_color}{BOLD}{cve.triage_priority} — {cve.triage_label}{RESET}")
    print(f"    {cve.triage_reason}")

    # ── Threat Snapshot ─────────────────────────────────────────────────────
    print(_section("THREAT SNAPSHOT"))
    score_str = f"{cve.cvss.score}/10" if cve.cvss.score else "N/A"
    print(f"    CVSS Score     {score_str} ({cve.cvss.severity})")

    kev_val = f"\033[91m{BOLD}YES — On CISA Known Exploited List{RESET}" if cve.is_kev else "No"
    print(f"    Actively Exploited  {kev_val}")

    if cve.epss_score is not None:
        pct = round(cve.epss_score * 100, 1)
        tile = round(cve.epss_percentile * 100, 1) if cve.epss_percentile else 0
        print(f"    Exploit Probability  {pct}%  (higher than {tile}% of all CVEs)")

    poc_val = f"\033[91m{BOLD}YES — {cve.poc.count} public repo(s) found{RESET}" if cve.poc.has_poc else "None found"
    print(f"    Public PoC     {poc_val}")

    # ── What Is It ──────────────────────────────────────────────────────────
    print(_section("WHAT IS IT?"))
    if cve.cwe_plain:
        print(f"    Type:  {cve.cwe_name}")
        print()
        print(_wrap(cve.cwe_plain))
    print()
    print(_wrap(cve.description))

    # ── How Can It Be Attacked ───────────────────────────────────────────────
    print(_section("HOW CAN IT BE ATTACKED?"))
    cvss = cve.cvss
    for label, val in [
        ("Who can attack", cvss.attack_vector),
        ("Complexity", cvss.attack_complexity),
        ("Login required", cvss.privileges_required),
        ("User action needed", cvss.user_interaction),
        ("Blast radius", cvss.scope),
    ]:
        if val:
            print(f"    {label:<22}  {val}")

    # ── Impact ──────────────────────────────────────────────────────────────
    print(_section("WHAT COULD AN ATTACKER DO?"))
    for label, val in [
        ("Data confidentiality", cvss.confidentiality),
        ("Data integrity", cvss.integrity),
        ("Availability / uptime", cvss.availability),
    ]:
        if val and val != "NONE":
            print(f"    {label:<26} {val} impact")

    # ── Affected Products ────────────────────────────────────────────────────
    if cve.affected_products:
        print(_section("AFFECTED PRODUCTS"))
        for product in cve.affected_products[:6]:
            print(f"    • {product}")

    # ── What To Do ──────────────────────────────────────────────────────────
    print(_section("WHAT DO I DO?"))
    for i, step in enumerate(cve.remediation, 1):
        tag = f"[{step.action:<10}]"
        print(f"\n    {i}. {BOLD}{tag}{RESET}")
        print(_wrap(step.description, indent=8))

    # ── PoC Sources ─────────────────────────────────────────────────────────
    if cve.poc.sources:
        print(_section("PUBLIC PROOF-OF-CONCEPT REPOS"))
        print("    These are real exploit demos — patch before attackers use them.\n")
        for src in cve.poc.sources:
            print(f"    • {src}")

    # ── References ──────────────────────────────────────────────────────────
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
    """Return a JSON-serializable dict — ready for future API use."""
    d = asdict(cve)
    return json.dumps(d, indent=2)
