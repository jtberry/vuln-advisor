#!/usr/bin/env python3
"""
VulnAdvisor — Open-source CVE triage and remediation guidance.
No API keys required. All data sources are free and public.

Usage:
  python main.py CVE-2021-44228
  python main.py CVE-2021-44228 CVE-2023-44487
  python main.py CVE-2021-44228 --json
"""

import argparse

from core.enricher import enrich
from core.fetcher import fetch_epss, fetch_kev, fetch_nvd, fetch_poc
from core.formatter import print_terminal, to_json


def process(cve_id: str, kev_set, output_json: bool) -> bool:
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        print(f"  [!] '{cve_id}' doesn't look like a valid CVE ID. Expected format: CVE-YYYY-NNNNN")
        return False

    print(f"  Fetching {cve_id}...", end=" ", flush=True)

    cve_raw = fetch_nvd(cve_id)
    if not cve_raw:
        print(f"\n  [!] No NVD record found for {cve_id}. Check the ID and try again.\n")
        return False

    epss_data = fetch_epss(cve_id)
    poc_data = fetch_poc(cve_id)
    print("done.")

    enriched = enrich(cve_raw, kev_set, epss_data, poc_data)

    if output_json:
        print(to_json(enriched))
    else:
        print_terminal(enriched)

    return True


def main():
    parser = argparse.ArgumentParser(
        prog="vuln-advisor",
        description="Plain-language CVE triage and remediation guidance.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py CVE-2021-44228
  python main.py CVE-2021-44228 CVE-2023-44487 CVE-2024-1234
  python main.py CVE-2021-44228 --json
        """,
    )
    parser.add_argument(
        "cves",
        nargs="+",
        metavar="CVE-ID",
        help="One or more CVE IDs to look up",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured JSON instead of terminal display",
    )
    args = parser.parse_args()

    print("\nVulnAdvisor — CVE Triage Tool")
    print("─" * 40)
    print("Loading CISA Known Exploited Vulnerabilities feed...", end=" ", flush=True)
    kev_set = fetch_kev()
    print(f"{len(kev_set)} entries loaded.\n")

    success = 0
    for cve_id in args.cves:
        if process(cve_id, kev_set, args.json):
            success += 1

    if len(args.cves) > 1:
        print(f"\nProcessed {success}/{len(args.cves)} CVEs successfully.")


if __name__ == "__main__":
    main()
