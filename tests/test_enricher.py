"""Unit tests for core/enricher.py — pure logic, no I/O, no mocking needed.

All functions under test are pure (no HTTP calls, no SQLite). Tests call them
directly with inline data — no fixtures or mocking required.

Learning note: testing private (_underscore) functions directly is intentional
here. _triage_priority is the most critical logic path and deserves targeted
coverage independent of the full enrich() orchestrator.
"""

from core.enricher import (
    _build_compensating_controls,
    _build_remediation,
    _build_sigma_link,
    _extract_affected_and_patches,
    _extract_cvss,
    _extract_cwe,
    _parse_cvss_vector,
    _triage_priority,
    enrich,
)
from core.models import CVSSDetails, Reference

# ---------------------------------------------------------------------------
# Inline data helpers — no conftest.py, no fixtures, no shared state
# ---------------------------------------------------------------------------


def _cve_with_weaknesses(*cwe_values):
    """Build a minimal CVE dict with the given CWE value(s) in weaknesses."""
    return {"weaknesses": [{"description": [{"value": v} for v in cwe_values]}]}


def _cve_with_cpe(matches):
    """Wrap CPE matches in the nested configurations structure NVD uses."""
    return {"configurations": [{"nodes": [{"cpeMatch": matches}]}]}


def _cpe_match(criteria, vulnerable=True, **kwargs):
    """Build a single cpeMatch entry."""
    return {"criteria": criteria, "vulnerable": vulnerable, **kwargs}


# ---------------------------------------------------------------------------
# TestTriagePriority
# ---------------------------------------------------------------------------


class TestTriagePriority:
    """
    Tests for _triage_priority(cvss, is_kev, epss_score, has_poc, exposure).

    Known tech debt (plan note): exposure adjustments only update *priority*,
    not *label* or *reason*. A P3 upgraded to P2 via internet exposure still
    carries the "Fix within 30 days" P3 label. Tests document actual behaviour,
    not ideal behaviour. A future refactor should keep label/reason in sync.
    """

    # --- Baseline (exposure="internal") ---

    def test_critical_score_kev_is_p1(self):
        cvss = CVSSDetails(score=9.5)
        priority, _, _ = _triage_priority(cvss, is_kev=True, epss_score=None, has_poc=False)
        assert priority == "P1"

    def test_critical_score_high_epss_is_p1(self):
        # epss >= 0.5 satisfies the P1 exploit-indicator condition
        cvss = CVSSDetails(score=9.5)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=0.6, has_poc=False)
        assert priority == "P1"

    def test_critical_score_no_exploit_is_p2(self):
        # score >= 9.0 but no KEV and epss below 0.5 → first branch misses → score >= 7.0 → P2
        cvss = CVSSDetails(score=9.5)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=0.49, has_poc=False)
        assert priority == "P2"

    def test_critical_boundary_score_kev_is_p1(self):
        # boundary: score == 9.0 qualifies for P1
        cvss = CVSSDetails(score=9.0)
        priority, _, _ = _triage_priority(cvss, is_kev=True, epss_score=None, has_poc=False)
        assert priority == "P1"

    def test_high_score_kev_is_p2(self):
        cvss = CVSSDetails(score=8.0)
        priority, _, _ = _triage_priority(cvss, is_kev=True, epss_score=None, has_poc=False)
        assert priority == "P2"

    def test_high_score_poc_is_p2(self):
        cvss = CVSSDetails(score=8.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=True)
        assert priority == "P2"

    def test_high_score_epss_boundary_is_p2(self):
        # boundary: epss == 0.3 satisfies the P2 exploit-indicator check
        cvss = CVSSDetails(score=8.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=0.3, has_poc=False)
        assert priority == "P2"

    def test_high_score_no_exploit_is_p2(self):
        # score >= 7.0 always yields at least P2 even with no exploit indicators
        cvss = CVSSDetails(score=8.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=0.0, has_poc=False)
        assert priority == "P2"

    def test_score_7_boundary_kev_is_p2(self):
        # boundary: score == 7.0 qualifies for the high-severity branches
        cvss = CVSSDetails(score=7.0)
        priority, _, _ = _triage_priority(cvss, is_kev=True, epss_score=None, has_poc=False)
        assert priority == "P2"

    def test_medium_score_no_exploit_is_p3(self):
        cvss = CVSSDetails(score=5.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=False)
        assert priority == "P3"

    def test_score_4_boundary_is_p3(self):
        # boundary: score == 4.0 still qualifies for P3
        cvss = CVSSDetails(score=4.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=False)
        assert priority == "P3"

    def test_score_below_4_is_p4(self):
        cvss = CVSSDetails(score=3.9)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=False)
        assert priority == "P4"

    def test_zero_score_is_p4(self):
        cvss = CVSSDetails(score=0.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=False)
        assert priority == "P4"

    def test_none_score_is_p4(self):
        # cvss.score is None → `cvss.score or 0.0` = 0.0 → P4
        cvss = CVSSDetails(score=None)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=False)
        assert priority == "P4"

    # --- exposure="isolated" ---

    def test_isolated_kev_never_downgraded(self):
        # KEV is always protected from exposure downgrade
        cvss = CVSSDetails(score=9.5)
        priority, _, _ = _triage_priority(cvss, is_kev=True, epss_score=None, has_poc=False, exposure="isolated")
        assert priority == "P1"

    def test_isolated_non_kev_p1_downgraded_to_p2(self):
        # Base P1 (high EPSS), isolated, not KEV → P2
        cvss = CVSSDetails(score=9.5)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=0.6, has_poc=False, exposure="isolated")
        assert priority == "P2"

    def test_isolated_p2_downgraded_to_p3(self):
        cvss = CVSSDetails(score=8.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=False, exposure="isolated")
        assert priority == "P3"

    def test_isolated_p3_downgraded_to_p4(self):
        cvss = CVSSDetails(score=5.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=False, exposure="isolated")
        assert priority == "P4"

    def test_isolated_p4_stays_p4(self):
        cvss = CVSSDetails(score=3.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=False, exposure="isolated")
        assert priority == "P4"

    # --- exposure="internet" ---

    def test_internet_p2_poc_upgraded_to_p1(self):
        cvss = CVSSDetails(score=8.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=True, exposure="internet")
        assert priority == "P1"

    def test_internet_p3_epss_boundary_upgraded_to_p2(self):
        # boundary: epss == 0.2 satisfies the internet upgrade condition
        cvss = CVSSDetails(score=5.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=0.2, has_poc=False, exposure="internet")
        assert priority == "P2"

    def test_internet_p3_epss_below_boundary_no_upgrade(self):
        cvss = CVSSDetails(score=5.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=0.19, has_poc=False, exposure="internet")
        assert priority == "P3"

    def test_internet_no_exploit_no_upgrade(self):
        # Internet exposure only upgrades when has_poc or epss >= 0.2
        cvss = CVSSDetails(score=8.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=False, exposure="internet")
        assert priority == "P2"

    # --- epss_score=None edge cases ---

    def test_none_epss_coerced_to_zero_no_p1(self):
        # (None or 0) >= 0.5 evaluates False — None does not trigger P1
        cvss = CVSSDetails(score=9.5)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=False)
        assert priority == "P2"

    def test_none_epss_coerced_to_zero_no_p2_exploit_branch(self):
        # (None or 0) >= 0.3 evaluates False — None does not trigger exploit-indicator P2
        # Priority is still P2 because score >= 7.0 catches it via the plain severity branch
        cvss = CVSSDetails(score=8.0)
        priority, _, _ = _triage_priority(cvss, is_kev=False, epss_score=None, has_poc=False)
        assert priority == "P2"


# ---------------------------------------------------------------------------
# TestExtractCwe
# ---------------------------------------------------------------------------


class TestExtractCwe:
    def test_valid_cwe_returned(self):
        assert _extract_cwe(_cve_with_weaknesses("CWE-79")) == "CWE-79"

    def test_cwe_noinfo_filtered(self):
        assert _extract_cwe(_cve_with_weaknesses("CWE-noinfo")) is None

    def test_cwe_other_filtered(self):
        assert _extract_cwe(_cve_with_weaknesses("CWE-Other")) is None

    def test_multiple_cwes_first_valid_returned(self):
        # noinfo comes first but is filtered; CWE-79 is the first valid entry
        cve = {"weaknesses": [{"description": [{"value": "CWE-noinfo"}, {"value": "CWE-79"}]}]}
        assert _extract_cwe(cve) == "CWE-79"

    def test_no_weaknesses_key_returns_none(self):
        assert _extract_cwe({}) is None

    def test_empty_weaknesses_returns_none(self):
        assert _extract_cwe({"weaknesses": []}) is None


# ---------------------------------------------------------------------------
# TestExtractCvss
# ---------------------------------------------------------------------------


class TestExtractCvss:
    def test_v31_preferred_over_v30(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                "cvssMetricV30": [{"cvssData": {"baseScore": 7.0, "baseSeverity": "HIGH"}}],
            }
        }
        result = _extract_cvss(cve)
        assert result.score == 9.8
        assert result.severity == "CRITICAL"

    def test_v30_fallback_when_no_v31(self):
        cve = {"metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}}
        result = _extract_cvss(cve)
        assert result.score == 7.5

    def test_v2_fallback_when_no_v31_or_v30(self):
        # In NVD format, V2 entries carry baseSeverity at the entry level, not inside cvssData
        cve = {"metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]}}
        result = _extract_cvss(cve)
        assert result.score == 5.0

    def test_no_metrics_returns_empty_details(self):
        result = _extract_cvss({})
        assert result.score is None

    def test_vector_populates_plain_language_fields(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": 10.0,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        }
                    }
                ]
            }
        }
        result = _extract_cvss(cve)
        assert result.attack_vector == "Anyone on the internet can attempt this remotely"
        assert result.attack_complexity != ""


# ---------------------------------------------------------------------------
# TestParseCvssVector
# ---------------------------------------------------------------------------


class TestParseCvssVector:
    VALID_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

    def test_valid_vector_populates_all_fields(self):
        details = CVSSDetails()
        _parse_cvss_vector(self.VALID_VECTOR, details)
        assert details.attack_vector == "Anyone on the internet can attempt this remotely"
        assert details.attack_complexity == "No special conditions needed — straightforward to exploit"
        assert details.privileges_required == "No account or login required"
        assert details.user_interaction == "No user action needed"
        assert details.scope == "Impact can spread beyond the vulnerable component"
        assert details.confidentiality == "HIGH"
        assert details.integrity == "HIGH"
        assert details.availability == "HIGH"

    def test_av_network_mapped(self):
        details = CVSSDetails()
        _parse_cvss_vector("CVSS:3.1/AV:N/AC:L", details)
        assert details.attack_vector == "Anyone on the internet can attempt this remotely"

    def test_ac_low_mapped(self):
        details = CVSSDetails()
        _parse_cvss_vector("CVSS:3.1/AV:N/AC:L", details)
        assert "No special conditions needed" in details.attack_complexity

    def test_unknown_av_code_returns_empty_string(self):
        # Unknown codes fall back to dict.get() default of "" — no exception
        details = CVSSDetails()
        _parse_cvss_vector("CVSS:3.1/AV:Z/AC:L", details)
        assert details.attack_vector == ""

    def test_none_vector_does_not_raise(self):
        # TypeError/AttributeError from None.split() is caught by the broad except clause
        details = CVSSDetails()
        _parse_cvss_vector(None, details)  # type: ignore[arg-type]
        assert details.attack_vector == ""


# ---------------------------------------------------------------------------
# TestBuildCompensatingControls
# ---------------------------------------------------------------------------


class TestBuildCompensatingControls:
    def test_known_cwe_returns_controls(self):
        controls = _build_compensating_controls("CWE-79")
        assert len(controls) == 3
        assert all(isinstance(c, str) for c in controls)

    def test_unknown_cwe_returns_empty(self):
        assert _build_compensating_controls("CWE-9999") == []

    def test_none_returns_empty(self):
        assert _build_compensating_controls(None) == []

    def test_empty_string_returns_empty(self):
        assert _build_compensating_controls("") == []


# ---------------------------------------------------------------------------
# TestBuildSigmaLink
# ---------------------------------------------------------------------------


class TestBuildSigmaLink:
    def test_valid_cve_returns_url_with_id(self):
        url = _build_sigma_link("CVE-2021-44228")
        assert url is not None
        assert "CVE-2021-44228" in url

    def test_none_returns_none(self):
        assert _build_sigma_link(None) is None  # type: ignore[arg-type]

    def test_empty_string_returns_none(self):
        assert _build_sigma_link("") is None

    def test_non_cve_id_returns_none(self):
        assert _build_sigma_link("GHSA-1234") is None


# ---------------------------------------------------------------------------
# TestBuildRemediation
# ---------------------------------------------------------------------------


class TestBuildRemediation:
    def test_with_patch_versions_description_starts_upgrade_to(self):
        steps = _build_remediation("CWE-79", ["2.0.1 or later"], [])
        assert steps[0].action == "PATCH"
        assert steps[0].description.startswith("Upgrade to")

    def test_without_patch_versions_description_starts_apply_vendor(self):
        steps = _build_remediation("CWE-79", [], [])
        assert steps[0].action == "PATCH"
        assert steps[0].description.startswith("Apply the vendor-supplied patch")

    def test_patch_step_is_always_critical(self):
        steps = _build_remediation(None, [], [])
        assert steps[0].priority == "CRITICAL"

    def test_known_cwe_adds_workaround_step(self):
        steps = _build_remediation("CWE-79", [], [])
        assert "WORKAROUND" in [s.action for s in steps]

    def test_unknown_cwe_no_workaround_step(self):
        steps = _build_remediation("CWE-9999", [], [])
        assert "WORKAROUND" not in [s.action for s in steps]

    def test_patch_tag_adds_reference_step(self):
        refs = [Reference(url="https://example.com/patch", tags=["Patch"])]
        steps = _build_remediation(None, [], refs)
        assert "REFERENCE" in [s.action for s in steps]

    def test_vendor_advisory_tag_adds_reference_step(self):
        refs = [Reference(url="https://example.com/advisory", tags=["Vendor Advisory"])]
        steps = _build_remediation(None, [], refs)
        assert "REFERENCE" in [s.action for s in steps]

    def test_mitigation_tag_adds_reference_step(self):
        refs = [Reference(url="https://example.com/mit", tags=["Mitigation"])]
        steps = _build_remediation(None, [], refs)
        assert "REFERENCE" in [s.action for s in steps]

    def test_unrelated_tag_no_reference_step(self):
        refs = [Reference(url="https://example.com/news", tags=["Third Party Advisory"])]
        steps = _build_remediation(None, [], refs)
        assert "REFERENCE" not in [s.action for s in steps]

    def test_empty_references_no_reference_step(self):
        steps = _build_remediation(None, [], [])
        assert "REFERENCE" not in [s.action for s in steps]

    def test_reference_step_priority_is_optional(self):
        refs = [Reference(url="https://example.com/patch", tags=["Patch"])]
        steps = _build_remediation(None, [], refs)
        ref_steps = [s for s in steps if s.action == "REFERENCE"]
        assert ref_steps[0].priority == "OPTIONAL"


# ---------------------------------------------------------------------------
# TestExtractAffectedAndPatches
# ---------------------------------------------------------------------------


class TestExtractAffectedAndPatches:
    def test_start_and_end_version_range(self):
        cve = _cve_with_cpe(
            [
                _cpe_match(
                    "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                    versionStartIncluding="1.0",
                    versionEndIncluding="2.0",
                )
            ]
        )
        affected, _ = _extract_affected_and_patches(cve)
        assert "Vendor Product 1.0 through 2.0" in affected

    def test_end_only_version_range(self):
        cve = _cve_with_cpe([_cpe_match("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", versionEndExcluding="2.0")])
        affected, _ = _extract_affected_and_patches(cve)
        assert "Vendor Product (up to 2.0)" in affected

    def test_start_only_version_range(self):
        cve = _cve_with_cpe([_cpe_match("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", versionStartIncluding="1.0")])
        affected, _ = _extract_affected_and_patches(cve)
        assert "Vendor Product (from 1.0)" in affected

    def test_specific_version_no_bounds(self):
        cve = _cve_with_cpe([_cpe_match("cpe:2.3:a:vendor:product:1.5:*:*:*:*:*:*:*")])
        affected, _ = _extract_affected_and_patches(cve)
        assert "Vendor Product 1.5" in affected

    def test_wildcard_version_no_trailing_space(self):
        cve = _cve_with_cpe([_cpe_match("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")])
        affected, _ = _extract_affected_and_patches(cve)
        assert affected == ["Vendor Product"]

    def test_underscore_in_cpe_replaced_and_titled(self):
        cve = _cve_with_cpe([_cpe_match("cpe:2.3:a:vendor:apache_httpd:2.4.50:*:*:*:*:*:*:*")])
        affected, _ = _extract_affected_and_patches(cve)
        assert any("Apache Httpd" in a for a in affected)

    def test_non_vulnerable_entry_skipped(self):
        cve = _cve_with_cpe([_cpe_match("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", vulnerable=False)])
        affected, _ = _extract_affected_and_patches(cve)
        assert affected == []

    def test_version_end_excluding_patch_label_ends_or_later(self):
        cve = _cve_with_cpe([_cpe_match("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", versionEndExcluding="2.0.1")])
        _, patches = _extract_affected_and_patches(cve)
        assert any(p.endswith("or later") for p in patches)

    def test_version_end_including_patch_label_contains_inclusive(self):
        cve = _cve_with_cpe([_cpe_match("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", versionEndIncluding="2.0.1")])
        _, patches = _extract_affected_and_patches(cve)
        assert any("(inclusive)" in p for p in patches)

    def test_products_capped_at_10(self):
        # 11 unique products → slice to 10
        matches = [_cpe_match(f"cpe:2.3:a:vendor:product{i}:1.0:*:*:*:*:*:*:*") for i in range(11)]
        cve = _cve_with_cpe(matches)
        affected, _ = _extract_affected_and_patches(cve)
        assert len(affected) == 10

    def test_duplicate_range_labels_deduplicated(self):
        match = _cpe_match(
            "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
            versionStartIncluding="1.0",
            versionEndIncluding="2.0",
        )
        cve = _cve_with_cpe([match, match])
        affected, _ = _extract_affected_and_patches(cve)
        assert affected.count("Vendor Product 1.0 through 2.0") == 1


# ---------------------------------------------------------------------------
# TestEnrich
# ---------------------------------------------------------------------------

# Realistic CVE dict used across multiple enrich() tests.
_FULL_CVE = {
    "id": "CVE-2021-44228",
    "descriptions": [
        {"lang": "en", "value": "A critical RCE vulnerability in Log4j."},
        {"lang": "es", "value": "Una vulnerabilidad critica en Log4j."},
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseScore": 10.0,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                }
            }
        ]
    },
    "weaknesses": [{"description": [{"value": "CWE-502"}]}],
    "configurations": [],
    "references": [],
}


class TestEnrich:
    def test_full_cve_correct_triage_and_fields(self):
        result = enrich(
            _FULL_CVE,
            kev_set={"CVE-2021-44228"},
            epss_data={"score": 0.97, "percentile": 0.99},
            poc_data={"has_poc": True, "count": 5, "sources": ["GitHub"]},
            exposure="internal",
        )
        assert result.id == "CVE-2021-44228"
        assert result.triage_priority == "P1"
        assert result.is_kev is True
        assert result.epss_score == 0.97
        assert result.poc.has_poc is True

    def test_english_description_selected(self):
        result = enrich(_FULL_CVE, kev_set=set(), epss_data={}, poc_data={})
        assert result.description == "A critical RCE vulnerability in Log4j."

    def test_cve_in_kev_set_is_kev_true(self):
        result = enrich(_FULL_CVE, kev_set={"CVE-2021-44228"}, epss_data={}, poc_data={})
        assert result.is_kev is True

    def test_cve_not_in_kev_set_is_kev_false(self):
        result = enrich(_FULL_CVE, kev_set=set(), epss_data={}, poc_data={})
        assert result.is_kev is False

    def test_epss_data_score_and_percentile_populated(self):
        result = enrich(_FULL_CVE, kev_set=set(), epss_data={"score": 0.5, "percentile": 0.8}, poc_data={})
        assert result.epss_score == 0.5
        assert result.epss_percentile == 0.8

    def test_empty_epss_data_yields_none(self):
        result = enrich(_FULL_CVE, kev_set=set(), epss_data={}, poc_data={})
        assert result.epss_score is None
        assert result.epss_percentile is None

    def test_poc_data_has_poc_and_count(self):
        result = enrich(_FULL_CVE, kev_set=set(), epss_data={}, poc_data={"has_poc": True, "count": 2})
        assert result.poc.has_poc is True
        assert result.poc.count == 2

    def test_known_cwe_populates_name_and_plain(self):
        # CWE-502 is in CWE_MAP — should resolve to a non-default name/plain
        result = enrich(_FULL_CVE, kev_set=set(), epss_data={}, poc_data={})
        assert result.cwe_id == "CWE-502"
        assert result.cwe_name != "Unknown Vulnerability Type"
        assert result.cwe_plain != ""

    def test_missing_id_defaults_to_unknown(self):
        cve = dict(_FULL_CVE)
        del cve["id"]
        result = enrich(cve, kev_set=set(), epss_data={}, poc_data={})
        assert result.id == "Unknown"
