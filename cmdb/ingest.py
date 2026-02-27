"""
cmdb/ingest.py -- Scanner output parsers for bulk CVE-to-asset ingestion.

All parsers normalize scanner-specific output to a common IngestRecord
dataclass. No external dependencies beyond stdlib.

Supported formats:
  - Generic CSV  (hostname,cve_id columns)
  - Trivy JSON   (trivy image --format json)
  - Grype JSON   (grype --output json)
  - Nessus CSV   (Nessus Essentials plugin export)

Pipeline:
  scanner output -> parse_*() -> list[IngestRecord]
  -> caller: asset lookup/create -> process_cves() -> CMDBStore.create_asset_vuln()

CVE ID format validation is NOT done here -- that responsibility belongs to
the route handler which validates against CVE_PATTERN before any storage call.
"""

import csv
import io
import json
from dataclasses import dataclass, field

from core.config import now_iso


@dataclass
class IngestRecord:
    """Normalized scanner record -- common output from all parse_*() functions.

    All parsers reduce their native schema to this common representation
    before the record is fed into the asset/vulnerability store. The raw
    field preserves the original scanner record for audit purposes.
    """

    hostname: str
    cve_id: str
    discovered_at: str  # ISO 8601
    scanner: str  # "csv" | "trivy" | "grype" | "nessus"
    raw: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Generic CSV parser
# ---------------------------------------------------------------------------


def parse_csv(content: str) -> list[IngestRecord]:
    """Parse a generic CSV of hostname,cve_id rows.

    Expected header: hostname,cve_id
    Extra columns are ignored. Rows with missing or empty values are skipped.
    """
    records: list[IngestRecord] = []
    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        hostname = (row.get("hostname") or "").strip()
        cve_id = (row.get("cve_id") or "").strip().upper()
        if not hostname or not cve_id:
            continue
        records.append(
            IngestRecord(
                hostname=hostname,
                cve_id=cve_id,
                discovered_at=now_iso(),
                scanner="csv",
                raw=dict(row),
            )
        )
    return records


# ---------------------------------------------------------------------------
# Trivy JSON parser
# ---------------------------------------------------------------------------


def parse_trivy_json(content: str) -> list[IngestRecord]:
    """Parse output from `trivy image --format json`.

    Trivy schema (simplified):
    {
      "ArtifactName": "my-image:latest",
      "Results": [
        {
          "Target": "my-image (ubuntu 22.04)",
          "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2021-44228", ...}
          ]
        }
      ]
    }

    The hostname is taken from ArtifactName (the scanned image or target).
    Returns an empty list if the content is not valid JSON or lacks the
    expected structure -- never raises to the caller.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []

    hostname = str(data.get("ArtifactName") or "unknown")
    records: list[IngestRecord] = []

    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            cve_id = (vuln.get("VulnerabilityID") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            records.append(
                IngestRecord(
                    hostname=hostname,
                    cve_id=cve_id,
                    discovered_at=now_iso(),
                    scanner="trivy",
                    raw=vuln,
                )
            )

    return records


# ---------------------------------------------------------------------------
# Grype JSON parser
# ---------------------------------------------------------------------------


def parse_grype_json(content: str) -> list[IngestRecord]:
    """Parse output from `grype --output json`.

    Grype schema (simplified):
    {
      "source": {"target": {"userInput": "nginx:latest"}},
      "matches": [
        {
          "vulnerability": {"id": "CVE-2021-44228", ...},
          "artifact": {"name": "log4j", ...}
        }
      ]
    }

    Returns an empty list if the content is not valid JSON or lacks the
    expected structure -- never raises to the caller.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return []

    # Extract hostname from source.target.userInput; fall back gracefully
    hostname = str((data.get("source") or {}).get("target", {}).get("userInput") or "unknown")

    records: list[IngestRecord] = []
    for match in data.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        cve_id = (vuln.get("id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        records.append(
            IngestRecord(
                hostname=hostname,
                cve_id=cve_id,
                discovered_at=now_iso(),
                scanner="grype",
                raw=match,
            )
        )

    return records


# ---------------------------------------------------------------------------
# Nessus CSV parser
# ---------------------------------------------------------------------------


def parse_nessus_csv(content: str) -> list[IngestRecord]:
    """Parse a Nessus Essentials CSV plugin export.

    Expected columns (Nessus default export):
      Plugin ID, CVE, CVSS v2.0 Base Score, Risk, Host, Protocol, Port,
      Name, Synopsis, Description, Solution, See Also, Plugin Output

    Only rows with a non-empty 'CVE' column produce IngestRecords.
    A single Nessus row may contain multiple CVE IDs (comma- or semicolon-
    separated), so one row can expand to multiple IngestRecords.
    """
    records: list[IngestRecord] = []
    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        hostname = (row.get("Host") or "").strip()
        cve_cell = (row.get("CVE") or "").strip()
        if not hostname or not cve_cell:
            continue
        # Normalize separators and split
        cve_ids = [c.strip().upper() for c in cve_cell.replace(";", ",").split(",") if c.strip()]
        for cve_id in cve_ids:
            if not cve_id.startswith("CVE-"):
                continue
            records.append(
                IngestRecord(
                    hostname=hostname,
                    cve_id=cve_id,
                    discovered_at=now_iso(),
                    scanner="nessus",
                    raw=dict(row),
                )
            )

    return records
