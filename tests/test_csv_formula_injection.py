"""
tests/test_csv_formula_injection.py -- Regression tests for CSV formula injection (CWE-1236).

Security background: Spreadsheet applications (Excel, LibreOffice, Google Sheets)
interpret cells that start with =, +, -, or @ as formulas. If user-supplied text
(e.g. CVE descriptions or remediation notes from external sources) is written
directly to a CSV without sanitization, a malicious actor who controls that text
could embed a formula like =CMD|'/C calc' that executes when a user opens the CSV.

This is CWE-1236 (Improper Neutralization of Formula Elements in a CSV File),
also called "CSV injection" or "formula injection".

Mitigation: Tab-prefix sanitization. Cells starting with a dangerous character
are prefixed with \t. Spreadsheet applications interpret the cell as text when
it starts with whitespace, neutralizing the formula.

TDD contract: These 4 dangerous-prefix tests WILL FAIL until Task 2 adds
_sanitize_csv_cell() to core/formatter.py. That is intentional -- the tests
drive the implementation.

Learning note: Writing tests first (Red-Green-Refactor) proves the tests
actually detect the vulnerability before the fix is applied. A test that
always passes doesn't prove anything.
"""

import csv
import io
from typing import Optional

from core.formatter import to_csv
from core.models import CVSSDetails, EnrichedCVE, PoCInfo, RemediationStep

# ---------------------------------------------------------------------------
# Test data helper
# ---------------------------------------------------------------------------


def _make_enriched_cve(remediation_desc: Optional[str]) -> EnrichedCVE:
    """Build a minimal EnrichedCVE with one RemediationStep for testing.

    The remediation_desc is what ends up in the remediation_summary CSV column,
    making it the injection surface we are testing.

    Args:
        remediation_desc: The description text for the single PATCH step,
                          or None to test the empty-remediation case.
    """
    remediation = []
    if remediation_desc is not None:
        remediation = [RemediationStep(action="PATCH", description=remediation_desc)]

    return EnrichedCVE(
        id="CVE-2021-99999",
        description="Test vulnerability for formula injection testing.",
        cvss=CVSSDetails(score=9.8, severity="CRITICAL"),
        cwe_id="CWE-1236",
        cwe_name="CSV Formula Injection",
        cwe_plain="Improper neutralization of formula elements in CSV.",
        is_kev=False,
        epss_score=None,
        epss_percentile=None,
        poc=PoCInfo(),
        triage_priority="P1",
        triage_label="Patch immediately",
        triage_reason="CVSS 9.8",
        affected_products=[],
        patch_versions=[],
        remediation=remediation,
        compensating_controls=[],
        sigma_link=None,
        references=[],
    )


def _get_remediation_cell(remediation_desc: Optional[str]) -> str:
    """Call to_csv() and extract the remediation_summary cell value."""
    cve = _make_enriched_cve(remediation_desc)
    csv_output = to_csv([cve])
    reader = csv.reader(io.StringIO(csv_output))
    rows = list(reader)
    # rows[0] = header row, rows[1] = data row
    assert len(rows) == 2, f"Expected header + 1 data row, got {len(rows)} rows"
    # remediation_summary is the last column (index -1)
    return rows[1][-1]


# ---------------------------------------------------------------------------
# Tests for dangerous-prefix sanitization
# ---------------------------------------------------------------------------


def test_formula_prefix_equals_sanitized():
    """Cell starting with '=' must not start with '=' after to_csv()."""
    cell = _get_remediation_cell("=CMD|'/C calc'")
    assert not cell.startswith("="), f"CSV injection: remediation_summary cell starts with '=' -- got: {cell!r}"


def test_formula_prefix_plus_sanitized():
    """Cell starting with '+' must not start with '+' after to_csv()."""
    cell = _get_remediation_cell("+1+1")
    assert not cell.startswith("+"), f"CSV injection: remediation_summary cell starts with '+' -- got: {cell!r}"


def test_formula_prefix_minus_sanitized():
    """Cell starting with '-' must not start with '-' after to_csv()."""
    cell = _get_remediation_cell("-1+1")
    assert not cell.startswith("-"), f"CSV injection: remediation_summary cell starts with '-' -- got: {cell!r}"


def test_formula_prefix_at_sanitized():
    """Cell starting with '@' must not start with '@' after to_csv()."""
    cell = _get_remediation_cell("@SUM(A1)")
    assert not cell.startswith("@"), f"CSV injection: remediation_summary cell starts with '@' -- got: {cell!r}"


# ---------------------------------------------------------------------------
# Tests for safe values -- no false-positive sanitization
# ---------------------------------------------------------------------------


def test_safe_text_unchanged():
    """Safe text that does not start with a formula prefix is not modified."""
    cell = _get_remediation_cell("Update to version 2.0")
    assert cell == "Update to version 2.0", f"Safe text was incorrectly modified. Got: {cell!r}"


def test_empty_remediation_unchanged():
    """Empty remediation list produces an empty string cell, not a tab."""
    cell = _get_remediation_cell(None)
    assert cell == "", f"Empty remediation should produce empty string cell. Got: {cell!r}"
