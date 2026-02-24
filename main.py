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
  python main.py CVE-2021-44228 --format csv
  python main.py CVE-2021-44228 --exposure internet
  python main.py CVE-2021-44228 --no-cache
  python main.py CVE-2021-44228 --no-color

Environment variables:
  NVD_API_KEY   Optional NVD API key. Raises rate limit from 5 req/min to 50 req/min.
                Free registration at https://nvd.nist.gov/developers/request-an-api-key
"""

import argparse
import os
import re
from pathlib import Path
from typing import Optional

from cache.store import CVECache
from core.fetcher import fetch_kev
from core.formatter import disable_color, print_summary, print_terminal, to_csv, to_html, to_json, to_markdown
from core.models import EnrichedCVE
from core.pipeline import process_cve


def _load_file(path: str) -> list[str]:
    """Read CVE IDs from a file — one per line, # comments and blank lines ignored.

    Resolves symlinks and verifies the path is a regular file before reading.
    This prevents accidental reads from FIFOs, devices, or traversal into
    unexpected locations when the function is called programmatically.
    """
    file_path = Path(path).resolve()
    if not file_path.is_file():
        print(f"  [!] '{path}' is not a readable file.")
        return []
    try:
        lines = file_path.read_text().splitlines()
    except OSError as e:
        print(f"  [!] Could not read file '{path}': {e}")
        return []
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def fetch_and_enrich(
    cve_id: str,
    kev_set: set[str],
    cache: Optional[CVECache] = None,
    exposure: str = "internal",
    nvd_api_key: Optional[str] = None,
) -> Optional[EnrichedCVE]:
    """Fetch and enrich a single CVE. Returns None on failure.

    Delegates all pipeline logic to core.pipeline.process_cve. This function
    exists solely to add CLI progress output around the pure pipeline call.
    """
    cve_id = cve_id.strip().upper()

    if cache is not None and cache.get(cve_id) is not None:
        print(f"  {cve_id} (cached)")
        return process_cve(cve_id, kev_set, cache, exposure=exposure, nvd_api_key=nvd_api_key)

    if not _CVE_RE.match(cve_id):
        print(f"  [!] '{cve_id}' doesn't look like a valid CVE ID. Expected format: CVE-YYYY-NNNNN")
        return None

    print(f"  Fetching {cve_id}...", end=" ", flush=True)

    result = process_cve(cve_id, kev_set, cache, exposure=exposure, nvd_api_key=nvd_api_key)

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
  python main.py CVE-2021-44228 --format csv > report.csv
  python main.py CVE-2021-44228 --format html > report.html
  python main.py CVE-2021-44228 --exposure internet
  NVD_API_KEY=your-key python main.py --file cves.txt
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
        "--exposure",
        choices=["internet", "internal", "isolated"],
        default="internal",
        metavar="CONTEXT",
        help="Asset exposure context: internet, internal, or isolated (default: internal). "
        "Adjusts triage priority based on attack surface.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Print the full report for every CVE after the priority summary",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured JSON (shorthand for --format json)",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json", "csv", "html", "markdown"],
        default=None,
        metavar="FORMAT",
        help="Output format: terminal (default), json, csv, html, or markdown",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Skip the local cache and force fresh API lookups",
    )
    args = parser.parse_args()

    # Apply color preference before any output
    if args.no_color:
        disable_color()

    # Resolve output format — --json is a backward-compatible alias for --format json
    output_format = args.format or ("json" if args.json else "terminal")

    # Read NVD API key from environment
    nvd_api_key: Optional[str] = os.environ.get("NVD_API_KEY") or None

    # Collect CVE IDs from args and/or file, with deduplication reporting
    all_ids: list[str] = list(args.cves)
    file_ids: list[str] = []
    if args.file:
        file_ids = _load_file(args.file)
        all_ids.extend(file_ids)

    seen: set[str] = set()
    cve_ids: list[str] = []
    for x in all_ids:
        if x.upper() not in seen:
            seen.add(x.upper())
            cve_ids.append(x)

    if not cve_ids:
        parser.print_help()
        return

    # Report deduplication when loading from file
    if args.file and len(all_ids) != len(cve_ids):
        dupes = len(all_ids) - len(cve_ids)
        print(f"  Loaded {len(all_ids)} IDs, {dupes} duplicate(s) removed, {len(cve_ids)} unique.\n")

    print("\nVulnAdvisor — CVE Triage Tool")
    print("─" * 40)
    if nvd_api_key:
        print("NVD API key loaded (50 req/min).")
    print("Loading CISA Known Exploited Vulnerabilities feed...", end=" ", flush=True)
    kev_set = fetch_kev()
    print(f"{len(kev_set)} entries loaded.\n")

    cache = None if args.no_cache else CVECache()

    results: list[EnrichedCVE] = []
    for cve_id in cve_ids:
        enriched = fetch_and_enrich(cve_id, kev_set, cache, exposure=args.exposure, nvd_api_key=nvd_api_key)
        if enriched:
            results.append(enriched)

    if not results:
        return

    # Output
    if output_format == "json":
        import json

        if len(results) == 1:
            print(to_json(results[0]))
        else:
            print(json.dumps([json.loads(to_json(r)) for r in results], indent=2))

    elif output_format == "csv":
        print(to_csv(results))

    elif output_format == "html":
        print(to_html(results))

    elif output_format == "markdown":
        print(to_markdown(results))

    else:
        # terminal (default)
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
