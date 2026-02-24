"""
formatter.py — Renders EnrichedCVE to terminal output or JSON.
"""

import csv
import html
import io
import json
import os
import re
import sys
from dataclasses import asdict
from datetime import date
from typing import Optional

from .models import EnrichedCVE

W = 68  # output width

# ---------------------------------------------------------------------------
# ANSI color control
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from a string."""
    return _ANSI_RE.sub("", text)


def _use_color() -> bool:
    """Return True if stdout is a TTY and color has not been disabled.

    Respects NO_COLOR env var (https://no-color.org) and checks sys.stdout.isatty().
    Can be overridden by calling disable_color() / enable_color().
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_color_enabled: Optional[bool] = None  # None = auto-detect


def disable_color() -> None:
    """Force-disable color output (called when --no-color flag is set)."""
    global _color_enabled
    _color_enabled = False


def enable_color() -> None:
    """Force-enable color output (called when --color=always is set)."""
    global _color_enabled
    _color_enabled = True


def _color_active() -> bool:
    """Check if color is currently active."""
    if _color_enabled is not None:
        return _color_enabled
    return _use_color()


# ---------------------------------------------------------------------------
# ANSI code helpers — return empty string when color is off
# ---------------------------------------------------------------------------

PRIORITY_COLORS = {
    "P1": "\033[91m",  # red
    "P2": "\033[93m",  # yellow
    "P3": "\033[94m",  # blue
    "P4": "\033[92m",  # green
}


def _reset() -> str:
    return "\033[0m" if _color_active() else ""


def _bold() -> str:
    return "\033[1m" if _color_active() else ""


def _dim() -> str:
    return "\033[2m" if _color_active() else ""


def _red() -> str:
    return "\033[91m" if _color_active() else ""


def _p_color(priority: str) -> str:
    return PRIORITY_COLORS.get(priority, "") if _color_active() else ""


# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------


def _bar(char: str = "═") -> str:
    return char * W


def _section(title: str) -> str:
    bold = _bold()
    reset = _reset()
    return f"\n  {bold}{title}{reset}\n  {'─' * (W - 2)}"


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


# ---------------------------------------------------------------------------
# Terminal renderer
# ---------------------------------------------------------------------------


def print_terminal(cve: EnrichedCVE) -> None:
    bold = _bold()
    reset = _reset()
    red = _red()
    p_color = _p_color(cve.triage_priority)

    # -- Header ---------------------------------------------------------------
    print(f"\n{bold}{_bar()}{reset}")
    kev_tag = f"  {bold}{red}*** ACTIVELY EXPLOITED ***{reset}" if cve.is_kev else ""
    print(f"  {bold}{cve.id}{reset}  │  CVSS {cve.cvss.score} {cve.cvss.severity}{kev_tag}")
    print(f"{bold}{_bar()}{reset}")

    # -- Triage Priority ------------------------------------------------------
    print(_section("TRIAGE PRIORITY"))
    print(f"    {p_color}{bold}{cve.triage_priority} — {cve.triage_label}{reset}")
    print(f"    {cve.triage_reason}")

    # -- Threat Snapshot ------------------------------------------------------
    print(_section("THREAT SNAPSHOT"))
    score_str = f"{cve.cvss.score}/10" if cve.cvss.score else "N/A"
    print(f"    CVSS Score     {score_str} ({cve.cvss.severity})")

    kev_val = f"{red}{bold}YES — On CISA Known Exploited List{reset}" if cve.is_kev else "No"
    print(f"    Actively Exploited  {kev_val}")

    if cve.epss_score is not None:
        pct = round(cve.epss_score * 100, 1)
        tile = round(cve.epss_percentile * 100, 1) if cve.epss_percentile else 0
        print(f"    Exploit Probability  {pct}%  (higher than {tile}% of all CVEs)")

    poc_val = f"{red}{bold}YES — {cve.poc.count} public repo(s) found{reset}" if cve.poc.has_poc else "None found"
    print(f"    Public PoC     {poc_val}")

    # -- What Is It -----------------------------------------------------------
    print(_section("WHAT IS IT?"))
    if cve.cwe_plain:
        print(f"    Type:  {cve.cwe_name}")
        print()
        print(_wrap(cve.cwe_plain))
    print()
    print(_wrap(cve.description))

    # -- How Can It Be Attacked -----------------------------------------------
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

    # -- Impact ---------------------------------------------------------------
    print(_section("WHAT COULD AN ATTACKER DO?"))
    for label, val in [
        ("Data confidentiality", cvss.confidentiality),
        ("Data integrity", cvss.integrity),
        ("Availability / uptime", cvss.availability),
    ]:
        if val and val != "NONE":
            print(f"    {label:<26} {val} impact")

    # -- Affected Products ----------------------------------------------------
    if cve.affected_products:
        print(_section("AFFECTED PRODUCTS"))
        for product in cve.affected_products[:6]:
            print(f"    • {product}")

    # -- What To Do -----------------------------------------------------------
    print(_section("WHAT DO I DO?"))
    for i, step in enumerate(cve.remediation, 1):
        tag = f"[{step.action:<10}]"
        print(f"\n    {i}. {bold}{tag}{reset}")
        print(_wrap(step.description, indent=8))

    # -- Compensating Controls ------------------------------------------------
    if cve.compensating_controls:
        print(_section("IF PATCHING IS NOT IMMEDIATE"))
        print("    Reduce risk with these controls while you work toward a fix.\n")
        for control in cve.compensating_controls:
            print(_wrap(f"• {control}", indent=4))
        if cve.sigma_link:
            dim = _dim()
            print(f"\n    {dim}Detection rules (Sigma): {cve.sigma_link}{reset}")

    # -- PoC Sources ----------------------------------------------------------
    if cve.poc.sources:
        print(_section("PUBLIC PROOF-OF-CONCEPT REPOS"))
        print("    These are real exploit demos — patch before attackers use them.\n")
        for src in cve.poc.sources:
            print(f"    • {src}")

    # -- References -----------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Summary table renderer
# ---------------------------------------------------------------------------


def print_summary(cves: list[EnrichedCVE]) -> None:
    """Print a prioritized summary table for a list of CVEs — P1 first, P4 last."""
    PRIORITY_ORDER = ["P1", "P2", "P3", "P4"]
    PRIORITY_LABELS = {
        "P1": "Fix within 24 hours",
        "P2": "Fix within 7 days",
        "P3": "Fix within 30 days",
        "P4": "Next patch cycle",
    }

    bold = _bold()
    reset = _reset()
    red = _red()

    by_priority: dict[str, list[EnrichedCVE]] = {p: [] for p in PRIORITY_ORDER}
    for cve in cves:
        by_priority.setdefault(cve.triage_priority, []).append(cve)

    print(f"\n{bold}{_bar()}{reset}")
    print(f"  {bold}PRIORITY SUMMARY — {len(cves)} CVEs analysed{reset}")
    print(f"{bold}{_bar()}{reset}")

    for priority in PRIORITY_ORDER:
        group = by_priority.get(priority, [])
        if not group:
            continue

        p_color = _p_color(priority)
        label = PRIORITY_LABELS.get(priority, "")
        header = f"{priority} — {label}"
        count = f"({len(group)})"
        print(f"\n  {p_color}{bold}{header:<46}{count}{reset}")
        print(f"  {'─' * (W - 2)}")

        for cve in group:
            score = f"{cve.cvss.score:.1f}" if cve.cvss.score else " N/A"
            severity = cve.cvss.severity[:8]
            kev_tag = f"{bold}{red}KEV{reset}" if cve.is_kev else "   "
            poc_tag = f"{bold}{red}PoC{reset}" if cve.poc.has_poc else "   "
            cwe = cve.cwe_name[:30] if cve.cwe_name else "Unknown"
            print(f"  {cve.id:<18} {score:>4}  {severity:<9} {kev_tag}  {poc_tag}  {cwe}")

    print(f"\n{_bar()}\n")


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------


def to_json(cve: EnrichedCVE) -> str:
    """Return a JSON-serializable dict — ready for future API use."""
    d = asdict(cve)
    return json.dumps(d, indent=2)


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------


def to_csv(results: list) -> str:
    """Render a list of EnrichedCVE as CSV.

    Columns: id, triage_priority, triage_label, cvss_score, cvss_severity,
             is_kev, epss_score, has_poc, poc_count, cwe_id, cwe_name,
             affected_products_count, remediation_summary
    """
    headers = [
        "id",
        "triage_priority",
        "triage_label",
        "cvss_score",
        "cvss_severity",
        "is_kev",
        "epss_score",
        "has_poc",
        "poc_count",
        "cwe_id",
        "cwe_name",
        "affected_products_count",
        "remediation_summary",
    ]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(headers)

    for r in results:
        # Build remediation summary: prefer first PATCH step, else first of any type.
        remediation_summary = ""
        patch_steps = [s for s in r.remediation if s.action.upper() == "PATCH"]
        if patch_steps:
            remediation_summary = patch_steps[0].description
        elif r.remediation:
            remediation_summary = r.remediation[0].description
        remediation_summary = remediation_summary[:120]

        writer.writerow(
            [
                r.id,
                r.triage_priority,
                r.triage_label,
                r.cvss.score if r.cvss.score is not None else "",
                r.cvss.severity,
                r.is_kev,
                r.epss_score if r.epss_score is not None else "",
                r.poc.has_poc,
                r.poc.count,
                r.cwe_id or "",
                r.cwe_name,
                len(r.affected_products),
                remediation_summary,
            ]
        )

    return buf.getvalue()


# ---------------------------------------------------------------------------
# HTML export
# ---------------------------------------------------------------------------

_PRIORITY_HTML_COLORS = {
    "P1": "#dc2626",
    "P2": "#ea580c",
    "P3": "#ca8a04",
    "P4": "#16a34a",
}

_HTML_STYLE = """
    body { font-family: Arial, sans-serif; margin: 32px; background: #f9fafb; color: #111827; }
    h1 { font-size: 1.5rem; margin-bottom: 4px; }
    p.subtitle { color: #6b7280; margin-top: 0; margin-bottom: 24px; font-size: 0.9rem; }
    table { border-collapse: collapse; width: 100%; background: #ffffff; }
    th { background: #1f2937; color: #f9fafb; text-align: left; padding: 10px 12px; font-size: 0.85rem; }
    td { padding: 9px 12px; font-size: 0.85rem; border-bottom: 1px solid #e5e7eb; vertical-align: middle; }
    tr:nth-child(even) td { background: #f3f4f6; }
    tr:hover td { background: #eff6ff; }
    .badge {
        display: inline-block; padding: 2px 10px; border-radius: 12px;
        color: #ffffff; font-weight: bold; font-size: 0.8rem;
    }
    .check { color: #16a34a; font-weight: bold; }
    .dash  { color: #9ca3af; }
"""


def to_html(results: list) -> str:
    """Render a list of EnrichedCVE as a self-contained HTML report.

    Suitable for saving as .html and opening in a browser, or attaching to email.
    No external CSS or JS dependencies -- all styles are inline.
    """
    today = date.today().isoformat()
    rows_html = []

    for r in results:
        badge_color = _PRIORITY_HTML_COLORS.get(r.triage_priority, "#6b7280")
        badge = f'<span class="badge" style="background:{badge_color}">' f"{html.escape(r.triage_priority)}</span>"
        cve_id = html.escape(r.id)
        score = f"{r.cvss.score:.1f}" if r.cvss.score is not None else "N/A"
        kev = '<span class="check">&#10003;</span>' if r.is_kev else '<span class="dash">-</span>'
        poc = '<span class="check">&#10003;</span>' if r.poc.has_poc else '<span class="dash">-</span>'
        epss = f"{round(r.epss_score * 100, 1)}%" if r.epss_score is not None else "-"
        cwe_name = html.escape(r.cwe_name) if r.cwe_name else "-"
        triage_label = html.escape(r.triage_label)

        rows_html.append(
            f"    <tr>"
            f"<td>{badge}</td>"
            f"<td>{cve_id}</td>"
            f"<td>{score}</td>"
            f"<td>{kev}</td>"
            f"<td>{poc}</td>"
            f"<td>{epss}</td>"
            f"<td>{cwe_name}</td>"
            f"<td>{triage_label}</td>"
            f"</tr>"
        )

    rows = "\n".join(rows_html)

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '  <meta charset="UTF-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "  <title>VulnAdvisor &mdash; CVE Triage Report</title>\n"
        f"  <style>{_HTML_STYLE}  </style>\n"
        "</head>\n"
        "<body>\n"
        "  <h1>VulnAdvisor &mdash; CVE Triage Report</h1>\n"
        f'  <p class="subtitle">Generated {today} &nbsp;&bull;&nbsp; {len(results)} CVE(s)</p>\n'
        "  <table>\n"
        "    <thead>\n"
        "      <tr>\n"
        "        <th>Priority</th><th>CVE ID</th><th>CVSS</th>"
        "<th>KEV</th><th>PoC</th><th>EPSS</th><th>CWE</th><th>Triage Label</th>\n"
        "      </tr>\n"
        "    </thead>\n"
        "    <tbody>\n"
        f"{rows}\n"
        "    </tbody>\n"
        "  </table>\n"
        "</body>\n"
        "</html>\n"
    )


# ---------------------------------------------------------------------------
# Markdown export
# ---------------------------------------------------------------------------


def to_markdown(results: list) -> str:
    """Render a list of EnrichedCVE as a Markdown summary table.

    Suitable for Slack, GitHub issues, and documentation.
    """
    header = "| Priority | CVE ID | CVSS | KEV | PoC | EPSS | Triage Label |"
    separator = "|----------|--------|------|-----|-----|------|--------------|"
    lines = [header, separator]

    for r in results:
        score = f"{r.cvss.score:.1f}" if r.cvss.score is not None else "N/A"
        kev = "Yes" if r.is_kev else "No"
        poc = "Yes" if r.poc.has_poc else "No"
        epss = f"{round(r.epss_score * 100, 1)}%" if r.epss_score is not None else "-"
        # Escape pipe characters in any free-text field to avoid breaking table layout.
        triage_label = r.triage_label.replace("|", "\\|")
        cve_id = r.id.replace("|", "\\|")
        lines.append(f"| {r.triage_priority} | {cve_id} | {score} | {kev} | {poc} | {epss} | {triage_label} |")

    return "\n".join(lines) + "\n"
