"""
tests/test_search_filter.py -- Integration tests for search, filter, and sort.

Covers both vanilla JS components in components.js:

AssetTableFilter wiring on assets_list.html:
  - data-* attributes on <tr> rows (hostname, ip, name, criticality, environment)
  - id="asset-table-card" on the card wrapper div (JS mount point)
  - Search input with id="asset-search-input" (components.js wires addEventListener)
  - Criticality and environment filter dropdowns with id-based wiring
  - Sortable column headers with id="sort-*" attributes
  - Result count span with id="asset-count-label" (JS sets textContent)

VulnTableFilter wiring on asset_detail.html:
  - data-* attributes on vuln <tr> rows (cve, description, severity, cvss, status)
  - id="vuln-table-card" on the outer card div (JS mount point)
  - Search input with id="vuln-search-input"
  - Severity and status filter dropdowns with id-based wiring
  - Sortable column headers with id="sort-cve/severity/cvss/status" attributes

These tests verify server-rendered HTML structure only (no headless browser).
JavaScript behavior is tested manually via the browser. ID attribute presence
is a sufficient proxy for correct vanilla JS wiring.

Three-state sort cycle behavior (asc -> desc -> default reset on every column,
including the default column) is verified via UAT, not integration tests.
The fix uses an explicit _sortCycleStage counter in both AssetTableFilter and
VulnTableFilter to make the three states distinguishable regardless of which
column is the default.

Fixture design: module-scoped for performance. One asset is created via the
API before the test module runs, then the page is fetched once and reused
across all structure tests.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# Minimal NVD payload, mirroring _MINIMAL_CVE_RAW in tests/test_pipeline.py.
# enrich() needs only these keys to produce an EnrichedCVE.
_MINIMAL_CVE_RAW = {
    "id": "CVE-2021-44228",
    "descriptions": [{"lang": "en", "value": "Test description."}],
    "metrics": {},
    "weaknesses": [],
    "configurations": [],
    "references": [],
}
_EPSS_DATA = {"score": 0.5, "percentile": 0.9}
_POC_DATA = {"has_poc": True, "count": 2, "sources": ["GitHub"]}

# ---------------------------------------------------------------------------
# Module-scoped fixture: create one asset and fetch /assets page
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def assets_page(web_client: tuple[TestClient, str]) -> tuple[str, int]:
    """Create an asset via the API and return (html_body, asset_id).

    Uses web_client (TestClient + token). The TestClient is shared with
    web_client so the in-memory DB state is shared across the module.

    Auth strategy:
      - API routes (POST /v1/assets): Authorization: Bearer {token} header
      - Web routes (GET /assets): access_token cookie

    The web_client fixture uses follow_redirects=False so we must follow
    the /login redirect manually by setting the cookie.
    """
    client, token = web_client

    # Create an asset via the REST API with Bearer auth.
    # Note: EnvironmentEnum accepts production/staging/development (not internal);
    # exposure accepts internet/internal/isolated.
    resp = client.post(
        "/api/v1/assets",
        json={
            "hostname": "test-web-01.lab.local",
            "ip": "10.0.0.1",
            "environment": "production",
            "exposure": "internal",
            "criticality": "high",
        },
        headers={"Authorization": "Bearer " + token},
    )
    assert resp.status_code == 201, f"Asset creation failed: {resp.status_code} {resp.text[:200]}"
    asset_id = resp.json()["id"]

    # Fetch /assets with cookie-based auth (web routes use cookie, not header)
    client.cookies.set("access_token", token)
    page_resp = client.get("/assets", follow_redirects=True)
    assert page_resp.status_code == 200, f"GET /assets failed: {page_resp.status_code} {page_resp.text[:200]}"

    return page_resp.text, asset_id


# ---------------------------------------------------------------------------
# Tests: data-* attributes on <tr> rows
# ---------------------------------------------------------------------------


def test_assets_list_row_data_attrs(assets_page: tuple[str, int]) -> None:
    """Rows have data-row marker and data-hostname, data-ip, data-name attributes."""
    html, _asset_id = assets_page
    assert "data-row" in html, "<tr data-row> attribute not found -- AssetTableFilter reads tr[data-row] selectors"
    assert "data-hostname=" in html, "data-hostname attribute missing from <tr>"
    assert "data-ip=" in html, "data-ip attribute missing from <tr>"
    assert "data-name=" in html, "data-name attribute missing from <tr>"


def test_assets_list_criticality_attr(assets_page: tuple[str, int]) -> None:
    """Rows have data-criticality matching the asset's criticality value."""
    html, _asset_id = assets_page
    assert 'data-criticality="high"' in html, (
        "data-criticality attribute not found or does not match 'high'. "
        "AssetTableFilter._onCritChange() filters on this attribute."
    )


def test_assets_list_environment_attr(assets_page: tuple[str, int]) -> None:
    """Rows have data-environment matching the asset's environment value."""
    html, _asset_id = assets_page
    assert 'data-environment="production"' in html, (
        "data-environment attribute not found or does not match 'production'. "
        "AssetTableFilter._onEnvChange() filters on this attribute."
    )


# ---------------------------------------------------------------------------
# Tests: vanilla JS wiring on the wrapper and headers
# ---------------------------------------------------------------------------


def test_vanilla_wrapper_assets(assets_page: tuple[str, int]) -> None:
    """The outer card div has id=\"asset-table-card\" as the JS mount point."""
    html, _asset_id = assets_page
    assert 'id="asset-table-card"' in html, (
        'id="asset-table-card" not found on the card wrapper. '
        "AssetTableFilter constructor looks up this element via getElementById."
    )


def test_assets_list_sort_headers(assets_page: tuple[str, int]) -> None:
    """Column headers have id attributes for per-column sort wiring."""
    html, _asset_id = assets_page
    for sort_id in ("sort-hostname", "sort-environment", "sort-criticality"):
        assert 'id="' + sort_id + '"' in html, (
            f'id="{sort_id}" not found in HTML. '
            f"Sortable headers need id attributes for components.js addEventListener wiring."
        )


# ---------------------------------------------------------------------------
# Tests: toolbar elements (search input, dropdowns, result count)
# ---------------------------------------------------------------------------


def test_assets_search_input(assets_page: tuple[str, int]) -> None:
    """Search input with id=\"asset-search-input\" exists in toolbar."""
    html, _asset_id = assets_page
    assert 'id="asset-search-input"' in html, (
        'id="asset-search-input" not found on search input. '
        "AssetTableFilter wires input listener via getElementById('asset-search-input')."
    )


def test_assets_filter_dropdowns(assets_page: tuple[str, int]) -> None:
    """Criticality and environment select dropdowns exist with id attributes."""
    html, _asset_id = assets_page
    assert (
        'id="asset-crit-select"' in html
    ), 'id="asset-crit-select" not found. Criticality dropdown needs this id for components.js wiring.'
    assert (
        'id="asset-env-select"' in html
    ), 'id="asset-env-select" not found. Environment dropdown needs this id for components.js wiring.'


def test_assets_result_count(assets_page: tuple[str, int]) -> None:
    """Result count span with id=\"asset-count-label\" exists in toolbar."""
    html, _asset_id = assets_page
    assert 'id="asset-count-label"' in html, (
        'id="asset-count-label" not found in HTML. '
        "AssetTableFilter._updateUiState() sets textContent on this element."
    )


# ---------------------------------------------------------------------------
# Fixture: asset detail page with a vulnerability linked
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def asset_detail_page(web_client: tuple[TestClient, str]) -> tuple[str, int]:
    """Create an asset, link a vulnerability, and return (html_body, asset_id).

    Auth strategy:
      - API routes use Authorization: Bearer {token}
      - Web routes use access_token cookie

    CVE-2021-44228 (Log4Shell) is used because it is commonly cached/known;
    the test only needs the HTML structure, not enriched data.
    """
    client, token = web_client

    # No cache stubbing needed: app.state.cache is a real in-memory CVECache
    # (see tests/conftest.py), so an unseeded lookup is a genuine miss and
    # process_cves() falls through to the patched fetchers below. This used to
    # be `app.state.cache.get.return_value = None`, a workaround for the
    # MagicMock cache that reported every lookup as a hit.

    # Create a new asset (separate from the one in assets_page to avoid state bleed)
    resp = client.post(
        "/api/v1/assets",
        json={
            "hostname": "detail-test-01.lab.local",
            "ip": "10.0.1.1",
            "environment": "production",
            "exposure": "internet",
            "criticality": "critical",
        },
        headers={"Authorization": "Bearer " + token},
    )
    assert resp.status_code == 201, f"Asset creation failed: {resp.status_code} {resp.text[:200]}"
    asset_id = resp.json()["id"]

    # Link a vulnerability via the API.
    # Field name is "ids" (not "cve_ids") per AssetVulnAssign model in api/models.py.
    #
    # The fetchers MUST be patched. Unpatched, process_cves() makes a live call
    # to the NVD API; wherever NVD is unreachable, rate-limited (5 req/30s
    # unauthenticated), or slow, fetch_nvd() returns None, the route skips the
    # CVE, no vuln row is created, and asset_detail.html's `{% if vuln_rows %}`
    # block never renders -- so every structural assertion below fails. Patching
    # here follows the same pattern as tests/test_pipeline.py and makes these
    # tests hermetic.
    with (
        patch("core.pipeline.fetch_nvd", return_value=_MINIMAL_CVE_RAW),
        patch("core.pipeline.fetch_epss", return_value=_EPSS_DATA),
        patch("core.pipeline.fetch_poc", return_value=_POC_DATA),
    ):
        vuln_resp = client.post(
            f"/api/v1/assets/{asset_id}/vulnerabilities",
            json={"ids": ["CVE-2021-44228"]},
            headers={"Authorization": "Bearer " + token},
        )
    assert vuln_resp.status_code in (
        200,
        201,
    ), f"Vulnerability link failed: {vuln_resp.status_code} {vuln_resp.text[:200]}"

    # Fetch the asset detail page with cookie auth
    client.cookies.set("access_token", token)
    page_resp = client.get(f"/assets/{asset_id}", follow_redirects=True)
    assert (
        page_resp.status_code == 200
    ), f"GET /assets/{asset_id} failed: {page_resp.status_code} {page_resp.text[:200]}"

    return page_resp.text, asset_id


# ---------------------------------------------------------------------------
# Tests: data-* attributes on vuln <tr> rows
# ---------------------------------------------------------------------------


def test_vuln_row_data_attrs(asset_detail_page: tuple[str, int]) -> None:
    """Vuln rows have data-row, data-cve, and data-description attributes."""
    html, _asset_id = asset_detail_page
    assert "data-row" in html, "<tr data-row> marker not found -- vulnTable.readRows() uses tr[data-row] selector"
    assert "data-cve=" in html, "data-cve attribute missing from vuln <tr>"
    assert "data-description=" in html, "data-description attribute missing from vuln <tr>"


def test_vuln_row_severity_attr(asset_detail_page: tuple[str, int]) -> None:
    """Vuln rows have data-severity attribute with the effective_priority value (lowercased)."""
    html, _asset_id = asset_detail_page
    assert "data-severity=" in html, (
        "data-severity attribute missing from vuln <tr>. "
        "vulnTable._severityOrdinal maps this value for semantic sort."
    )


def test_vuln_row_status_attr(asset_detail_page: tuple[str, int]) -> None:
    """Vuln rows have data-status attribute with the vuln status value."""
    html, _asset_id = asset_detail_page
    assert "data-status=" in html, (
        "data-status attribute missing from vuln <tr>. " "vulnTable setStatus() filters on this attribute."
    )


def test_vuln_row_cvss_attr(asset_detail_page: tuple[str, int]) -> None:
    """Vuln rows have data-cvss attribute for numeric CVSS sort."""
    html, _asset_id = asset_detail_page
    assert "data-cvss=" in html, (
        "data-cvss attribute missing from vuln <tr>. " "vulnTable sort by CVSS uses parseFloat on this attribute."
    )


def test_vuln_table_sort_headers(asset_detail_page: tuple[str, int]) -> None:
    """Vuln table has per-column sort headers wired with vanilla JS id attributes."""
    html, _asset_id = asset_detail_page
    for sort_id in ("sort-cve", "sort-severity", "sort-cvss", "sort-status"):
        assert 'id="' + sort_id + '"' in html, (
            f'id="{sort_id}" not found in HTML. '
            f"Sortable headers need id attributes for VulnTableFilter addEventListener wiring."
        )


def test_vanilla_wrapper_vulns(asset_detail_page: tuple[str, int]) -> None:
    """The outer vulnerability card div has id=\"vuln-table-card\" as the JS mount point."""
    html, _asset_id = asset_detail_page
    assert 'id="vuln-table-card"' in html, (
        'id="vuln-table-card" not found on the vulnerability card wrapper. '
        "VulnTableFilter constructor looks up this element via getElementById."
    )


def test_vuln_search_input(asset_detail_page: tuple[str, int]) -> None:
    """Search input with id=\"vuln-search-input\" exists in the vuln card."""
    html, _asset_id = asset_detail_page
    assert 'id="vuln-search-input"' in html, (
        'id="vuln-search-input" not found on vuln search input. '
        "VulnTableFilter wires input listener via getElementById('vuln-search-input')."
    )


def test_vuln_filter_dropdowns(asset_detail_page: tuple[str, int]) -> None:
    """Severity and status select dropdowns exist with id attributes for vanilla JS wiring."""
    html, _asset_id = asset_detail_page
    assert (
        'id="vuln-severity-select"' in html
    ), 'id="vuln-severity-select" not found. Severity dropdown needs this id for VulnTableFilter wiring.'
    assert (
        'id="vuln-status-select"' in html
    ), 'id="vuln-status-select" not found. Status dropdown needs this id for VulnTableFilter wiring.'
