#!/usr/bin/env python3
"""
VulnAdvisor — Open-source CVE triage and remediation guidance.
No API keys required. All data sources are free and public.

Usage:
  python main.py CVE-2021-44228
  python main.py CVE-2021-44228 CVE-2023-44487
  python main.py --file cves.txt
  python main.py --file cves.txt --full
  python main.py CVE-2021-44228 --json
  python main.py CVE-2021-44228 --no-cache
"""

import argparse
import re
from pathlib import Path
from typing import Optional

from cache.store import CVECache
from core.fetcher import fetch_kev
from core.formatter import print_summary, print_terminal, to_json
from core.models import EnrichedCVE
from core.pipeline import process_cve


def _load_file(path: str) -> list[str]:
    """Read CVE IDs from a file — one per line, # comments and blank lines ignored."""
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as e:
        print(f"  [!] Could not read file '{path}': {e}")
        return []
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def fetch_and_enrich(cve_id: str, kev_set: set[str], cache: Optional[CVECache] = None) -> Optional[EnrichedCVE]:
    """Fetch and enrich a single CVE. Returns None on failure.

    Delegates all pipeline logic to core.pipeline.process_cve. This function
    exists solely to add CLI progress output around the pure pipeline call.
    """
    cve_id = cve_id.strip().upper()

    if cache is not None and cache.get(cve_id) is not None:
        print(f"  {cve_id} (cached)")
        return process_cve(cve_id, kev_set, cache)

    if not _CVE_RE.match(cve_id):
        print(f"  [!] '{cve_id}' doesn't look like a valid CVE ID. Expected format: CVE-YYYY-NNNNN")
        return None

    print(f"  Fetching {cve_id}...", end=" ", flush=True)

    result = process_cve(cve_id, kev_set, cache)

    if result is None:
        print(f"\n  [!] No NVD record found for {cve_id}. Check the ID and try again.")
        return None

    print("done.")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vuln-advisor",
        description="Plain-language CVE triage and remediation guidance.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py CVE-2021-44228
  python main.py CVE-2021-44228 CVE-2023-44487 CVE-2024-1234
  python main.py --file cves.txt
  python main.py --file cves.txt --full
  python main.py CVE-2021-44228 --json
        """,
    )
    parser.add_argument(
        "cves",
        nargs="*",
        metavar="CVE-ID",
        help="One or more CVE IDs to look up",
    )
    parser.add_argument(
        "--file",
        metavar="PATH",
        help="Path to a text file with one CVE ID per line (# comments supported)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Print the full report for every CVE after the priority summary",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured JSON instead of terminal display",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Skip the local cache and force fresh API lookups",
    )
    args = parser.parse_args()

    # Collect and deduplicate CVE IDs from args and/or file
    all_ids: list[str] = list(args.cves)
    if args.file:
        all_ids.extend(_load_file(args.file))
    seen: set[str] = set()
    cve_ids = [x for x in all_ids if not (x.upper() in seen or seen.add(x.upper()))]  # type: ignore[func-returns-value]

    if not cve_ids:
        parser.print_help()
        return

    print("\nVulnAdvisor — CVE Triage Tool")
    print("─" * 40)
    print("Loading CISA Known Exploited Vulnerabilities feed...", end=" ", flush=True)
    kev_set = fetch_kev()
    print(f"{len(kev_set)} entries loaded.\n")

    cache = None if args.no_cache else CVECache()

    results: list[EnrichedCVE] = []
    for cve_id in cve_ids:
        enriched = fetch_and_enrich(cve_id, kev_set, cache)
        if enriched:
            results.append(enriched)

    if not results:
        return

    if args.json:
        if len(results) == 1:
            print(to_json(results[0]))
        else:
            import json

            print(json.dumps([json.loads(to_json(r)) for r in results], indent=2))
        return

    if len(results) == 1:
        print_terminal(results[0])
    else:
        print_summary(results)
        if args.full:
            for enriched in results:
                print_terminal(enriched)
        else:
            print("\n  Run with --full to see the complete report for each CVE.\n")

    if len(cve_ids) > len(results):
        failed = len(cve_ids) - len(results)
        print(f"  [!] {failed} CVE(s) could not be retrieved.\n")


if __name__ == "__main__":
    main()
