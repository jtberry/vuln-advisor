"""Unit tests for web/routes.py dashboard route -- threat intel and overdue data assembly.

Covers:
- KEV highlights: dashboard surfaces CVEs where enriched.is_kev is True
- EPSS highlights: dashboard surfaces CVEs where enriched.epss_score > 0.5
- Overdue data: dashboard passes overdue and approaching items from get_overdue_vulns()
- KEV count stat card: count of KEV-flagged items passed to template
- Empty state: dashboard handles no open vulns gracefully

All tests are xfail-marked because the production code changes (threat intel
assembly, get_overdue_vulns() integration) are implemented in 03-02.
"""

from typing import Optional
from unittest.mock import MagicMock, patch

from core.models import CVSSDetails, EnrichedCVE, PoCInfo

# ---------------------------------------------------------------------------
# Shared test data helpers
# ---------------------------------------------------------------------------


def _make_enriched_cve(
    cve_id: str = "CVE-2021-44228",
    is_kev: bool = False,
    epss_score: float = 0.0,
) -> EnrichedCVE:
    """Build a minimal EnrichedCVE for use in dashboard tests."""
    return EnrichedCVE(
        id=cve_id,
        description="Test vulnerability.",
        cvss=CVSSDetails(score=7.5, severity="HIGH"),
        cwe_id="CWE-79",
        cwe_name="XSS",
        cwe_plain="Cross-Site Scripting",
        is_kev=is_kev,
        epss_score=epss_score,
        epss_percentile=0.9 if epss_score > 0 else None,
        poc=PoCInfo(),
        triage_priority="P2",
        triage_label="High",
        triage_reason="CVSS >= 7.0",
        affected_products=[],
        patch_versions=[],
        remediation=[],
        compensating_controls=[],
        sigma_link=None,
        references=[],
    )


def _make_mock_cmdb(
    open_vuln_cve_ids: Optional[list] = None,
    overdue_result: Optional[dict] = None,
) -> MagicMock:
    """Build a mock CMDBStore with configurable return values.

    Defaults to empty state (no assets, no vulns).
    """
    cmdb = MagicMock()
    cmdb.list_assets.return_value = []
    cmdb.get_all_priority_counts.return_value = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    cmdb.get_open_vuln_cve_ids.return_value = open_vuln_cve_ids or []
    cmdb.get_overdue_vulns.return_value = overdue_result or {"overdue": [], "approaching": []}
    return cmdb


def _make_mock_request(cmdb: Optional[MagicMock] = None) -> MagicMock:
    """Build a mock Starlette Request with app.state pre-configured.

    cookies and headers are configured as real dicts so that .get() calls
    with defaults behave correctly (returning None / "" rather than MagicMock
    objects that would cause downstream code -- e.g. HMAC hashing -- to fail).
    """
    request = MagicMock()
    request.app.state.cmdb = cmdb or _make_mock_cmdb()
    request.app.state.kev_set = set()
    request.app.state.cache = None
    user_store = MagicMock()
    user_store.get_sla_config.return_value = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}
    request.app.state.user_store = user_store
    request.session = {}
    # Use real dicts so .get(key, default) returns the default for missing keys
    request.cookies = {}
    request.headers = {}
    request.url.path = "/"
    return request


# ---------------------------------------------------------------------------
# TestDashboardThreatIntel
# ---------------------------------------------------------------------------


class TestDashboardThreatIntel:
    def test_kev_highlights(self) -> None:
        """Dashboard must surface CVEs where enriched.is_kev is True in threat_intel_items.

        When get_open_vuln_cve_ids() returns an item and process_cve enriches
        it as is_kev=True, the template context must include it in threat_intel_items.
        """
        open_vuln = {
            "asset_id": 1,
            "hostname": "web-01",
            "cve_id": "CVE-2021-44228",
            "effective_priority": "P1",
            "exposure": "internet",
        }
        kev_enriched = _make_enriched_cve("CVE-2021-44228", is_kev=True, epss_score=0.8)
        cmdb = _make_mock_cmdb(open_vuln_cve_ids=[open_vuln])
        request = _make_mock_request(cmdb=cmdb)

        captured_context: dict = {}

        def fake_template_response(template_name: str, context: dict) -> MagicMock:
            captured_context.update(context)
            return MagicMock()

        with (
            patch("web.routes._require_auth", return_value=None),
            patch("web.routes.process_cve", return_value=kev_enriched),
            patch("web.routes.templates.TemplateResponse", side_effect=fake_template_response),
        ):
            from web.routes import dashboard

            dashboard(request)

        threat_items = captured_context.get("threat_intel_items", [])
        assert len(threat_items) > 0, "Expected at least one threat intel item"
        kev_items = [item for item in threat_items if item.get("is_kev") is True]
        assert len(kev_items) > 0, "Expected at least one KEV-flagged item in threat_intel_items"

    def test_epss_highlights(self) -> None:
        """Dashboard must surface CVEs where enriched.epss_score > 0.5 in threat_intel_items."""
        open_vuln = {
            "asset_id": 1,
            "hostname": "web-01",
            "cve_id": "CVE-2022-12345",
            "effective_priority": "P2",
            "exposure": "internet",
        }
        high_epss = _make_enriched_cve("CVE-2022-12345", is_kev=False, epss_score=0.75)
        cmdb = _make_mock_cmdb(open_vuln_cve_ids=[open_vuln])
        request = _make_mock_request(cmdb=cmdb)

        captured_context: dict = {}

        def fake_template_response(template_name: str, context: dict) -> MagicMock:
            captured_context.update(context)
            return MagicMock()

        with (
            patch("web.routes._require_auth", return_value=None),
            patch("web.routes.process_cve", return_value=high_epss),
            patch("web.routes.templates.TemplateResponse", side_effect=fake_template_response),
        ):
            from web.routes import dashboard

            dashboard(request)

        threat_items = captured_context.get("threat_intel_items", [])
        high_epss_items = [item for item in threat_items if item.get("epss_score", 0) > 0.5]
        assert len(high_epss_items) > 0, "Expected high-EPSS CVE in threat_intel_items"

    def test_low_epss_excluded(self) -> None:
        """CVEs with epss_score <= 0.5 and is_kev=False must NOT appear in threat_intel_items."""
        open_vuln = {
            "asset_id": 1,
            "hostname": "web-01",
            "cve_id": "CVE-2022-99999",
            "effective_priority": "P3",
            "exposure": "internal",
        }
        low_epss = _make_enriched_cve("CVE-2022-99999", is_kev=False, epss_score=0.3)
        cmdb = _make_mock_cmdb(open_vuln_cve_ids=[open_vuln])
        request = _make_mock_request(cmdb=cmdb)

        captured_context: dict = {}

        def fake_template_response(template_name: str, context: dict) -> MagicMock:
            captured_context.update(context)
            return MagicMock()

        with (
            patch("web.routes._require_auth", return_value=None),
            patch("web.routes.process_cve", return_value=low_epss),
            patch("web.routes.templates.TemplateResponse", side_effect=fake_template_response),
        ):
            from web.routes import dashboard

            dashboard(request)

        threat_items = captured_context.get("threat_intel_items", [])
        matching = [item for item in threat_items if item.get("cve_id") == "CVE-2022-99999"]
        assert len(matching) == 0, "Low-EPSS non-KEV CVE should not appear in threat_intel_items"

    def test_enrichment_failure_skipped(self) -> None:
        """When process_cve raises an Exception, the dashboard must still render.

        The failed CVE is silently dropped -- threat_intel_items is empty or missing
        only the failed entry. The route must not propagate the exception.
        """
        open_vuln = {
            "asset_id": 1,
            "hostname": "web-01",
            "cve_id": "CVE-2021-00001",
            "effective_priority": "P1",
            "exposure": "internet",
        }
        cmdb = _make_mock_cmdb(open_vuln_cve_ids=[open_vuln])
        request = _make_mock_request(cmdb=cmdb)

        captured_context: dict = {}

        def fake_template_response(template_name: str, context: dict) -> MagicMock:
            captured_context.update(context)
            return MagicMock()

        with (
            patch("web.routes._require_auth", return_value=None),
            patch("web.routes.process_cve", side_effect=Exception("NVD timeout")),
            patch("web.routes.templates.TemplateResponse", side_effect=fake_template_response),
        ):
            from web.routes import dashboard

            # Must not raise -- failures are absorbed per CLAUDE.md safety rules
            dashboard(request)

        # Dashboard renders; failed CVE not in threat_intel_items
        threat_items = captured_context.get("threat_intel_items", [])
        failed = [item for item in threat_items if item.get("cve_id") == "CVE-2021-00001"]
        assert len(failed) == 0, "Failed enrichment CVE must be excluded from threat_intel_items"


# ---------------------------------------------------------------------------
# TestDashboardOverdue
# ---------------------------------------------------------------------------


class TestDashboardOverdue:
    def test_overdue_data_passed_to_template(self) -> None:
        """Dashboard must pass overdue_data from get_overdue_vulns() to the template context."""
        overdue_item = {
            "cve_id": "CVE-2021-00001",
            "asset_id": 1,
            "hostname": "web-01",
            "days_overdue": 30,
            "effective_priority": "P1",
        }
        cmdb = _make_mock_cmdb(overdue_result={"overdue": [overdue_item], "approaching": []})
        request = _make_mock_request(cmdb=cmdb)

        captured_context: dict = {}

        def fake_template_response(template_name: str, context: dict) -> MagicMock:
            captured_context.update(context)
            return MagicMock()

        with (
            patch("web.routes._require_auth", return_value=None),
            patch("web.routes.templates.TemplateResponse", side_effect=fake_template_response),
        ):
            from web.routes import dashboard

            dashboard(request)

        overdue_data = captured_context.get("overdue_data")
        assert overdue_data is not None, "Expected overdue_data in template context"
        assert "overdue" in overdue_data
        assert len(overdue_data["overdue"]) == 1
        assert overdue_data["overdue"][0]["cve_id"] == "CVE-2021-00001"

    def test_kev_count_matches_kev_items(self) -> None:
        """Template context kev_count must equal the number of KEV-flagged threat intel items."""
        open_vulns = [
            {
                "asset_id": 1,
                "hostname": "web-01",
                "cve_id": f"CVE-2021-0000{i}",
                "effective_priority": "P1",
                "exposure": "internet",
            }
            for i in range(1, 4)
        ]
        # All 3 are KEV
        kev_enriched = [_make_enriched_cve(f"CVE-2021-0000{i}", is_kev=True, epss_score=0.9) for i in range(1, 4)]
        cmdb = _make_mock_cmdb(open_vuln_cve_ids=open_vulns)
        request = _make_mock_request(cmdb=cmdb)

        captured_context: dict = {}

        def fake_template_response(template_name: str, context: dict) -> MagicMock:
            captured_context.update(context)
            return MagicMock()

        call_count = [0]

        def fake_process_cve(cve_id, *args, **kwargs):
            idx = call_count[0]
            call_count[0] += 1
            return kev_enriched[idx] if idx < len(kev_enriched) else None

        with (
            patch("web.routes._require_auth", return_value=None),
            patch("web.routes.process_cve", side_effect=fake_process_cve),
            patch("web.routes.templates.TemplateResponse", side_effect=fake_template_response),
        ):
            from web.routes import dashboard

            dashboard(request)

        kev_count = captured_context.get("kev_count", -1)
        assert kev_count == 3, f"Expected kev_count=3, got {kev_count}"


# ---------------------------------------------------------------------------
# TestDashboardEmptyState
# ---------------------------------------------------------------------------


class TestDashboardEmptyState:
    def test_no_assets_returns_empty_dashboard(self) -> None:
        """Dashboard with no assets must render without error.

        All new template context fields (threat_intel_items, overdue_data,
        kev_count) must be present and empty/zero -- not missing or raising
        KeyError in templates.
        """
        cmdb = _make_mock_cmdb(open_vuln_cve_ids=[], overdue_result={"overdue": [], "approaching": []})
        request = _make_mock_request(cmdb=cmdb)

        captured_context: dict = {}

        def fake_template_response(template_name: str, context: dict) -> MagicMock:
            captured_context.update(context)
            return MagicMock()

        with (
            patch("web.routes._require_auth", return_value=None),
            patch("web.routes.process_cve", return_value=None),
            patch("web.routes.templates.TemplateResponse", side_effect=fake_template_response),
        ):
            from web.routes import dashboard

            # Must not raise
            dashboard(request)

        # All new context fields must be present with empty/zero values
        assert "threat_intel_items" in captured_context, "threat_intel_items must be in context"
        assert captured_context["threat_intel_items"] == [], "Empty state: threat_intel_items must be []"

        assert "overdue_data" in captured_context, "overdue_data must be in context"
        assert captured_context["overdue_data"]["overdue"] == [], "Empty state: overdue list must be []"

        assert "kev_count" in captured_context, "kev_count must be in context"
        assert captured_context["kev_count"] == 0, "Empty state: kev_count must be 0"
