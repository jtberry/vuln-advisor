"""
tests/test_phase12_search_filter.py -- Integration tests for Phase 12 Plan 01.

Covers the Alpine.js assetTable component wiring on assets_list.html:
  - data-* attributes on <tr> rows (hostname, ip, name, criticality, environment)
  - x-data="assetTable" on the card wrapper div
  - Search input with :value and @input handlers
  - Criticality and environment filter dropdowns with @change handlers
  - Sortable column headers with @click="toggleSort" references
  - Result count span with x-text containing matchCount

These tests verify server-rendered HTML structure only (no headless browser).
JavaScript behavior is tested manually via the browser. Alpine attribute
presence is a sufficient proxy for correct wiring.

Fixture design: module-scoped for performance. One asset is created via the
API before the test module runs, then the /assets page is fetched once and
reused across all structure tests.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app

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
    assert "data-row" in html, "<tr data-row> attribute not found -- Alpine init() reads tr[data-row] selectors"
    assert "data-hostname=" in html, "data-hostname attribute missing from <tr>"
    assert "data-ip=" in html, "data-ip attribute missing from <tr>"
    assert "data-name=" in html, "data-name attribute missing from <tr>"


def test_assets_list_criticality_attr(assets_page: tuple[str, int]) -> None:
    """Rows have data-criticality matching the asset's criticality value."""
    html, _asset_id = assets_page
    assert 'data-criticality="high"' in html, (
        "data-criticality attribute not found or does not match 'high'. "
        "Alpine setCriticality() filters on this attribute."
    )


def test_assets_list_environment_attr(assets_page: tuple[str, int]) -> None:
    """Rows have data-environment matching the asset's environment value."""
    html, _asset_id = assets_page
    assert 'data-environment="production"' in html, (
        "data-environment attribute not found or does not match 'production'. "
        "Alpine setEnvironment() filters on this attribute."
    )


# ---------------------------------------------------------------------------
# Tests: Alpine wiring on the wrapper and headers
# ---------------------------------------------------------------------------


def test_alpine_xdata_wrapper_assets(assets_page: tuple[str, int]) -> None:
    """The outer card div has x-data=\"assetTable\" to mount the Alpine component."""
    html, _asset_id = assets_page
    assert 'x-data="assetTable"' in html, (
        'x-data="assetTable" not found on the card wrapper. '
        "Alpine will not initialize the component without this attribute."
    )


def test_assets_list_sort_headers(assets_page: tuple[str, int]) -> None:
    """Column headers for hostname, criticality, environment have @click=\"toggleSort\" references."""
    html, _asset_id = assets_page
    # All three sortable headers must be present
    toggle_count = html.count("toggleSort")
    assert toggle_count >= 3, (
        f"Expected at least 3 toggleSort references (hostname, criticality, environment), found {toggle_count}. "
        "Sortable headers need @click=\"toggleSort('col')\" attributes."
    )


# ---------------------------------------------------------------------------
# Tests: toolbar elements (search input, dropdowns, result count)
# ---------------------------------------------------------------------------


def test_assets_search_input(assets_page: tuple[str, int]) -> None:
    """Search input with :value=\"search\" and @input=\"setSearch\" exists in toolbar."""
    html, _asset_id = assets_page
    assert ':value="search"' in html or ':value="search"' in html, (
        ':value="search" binding not found on search input. '
        "Alpine uses :value + @input instead of x-model to comply with CSP."
    )
    assert (
        '@input="setSearch"' in html or "@input='setSearch'" in html
    ), '@input="setSearch" handler not found on search input.'


def test_assets_filter_dropdowns(assets_page: tuple[str, int]) -> None:
    """Criticality and environment select dropdowns exist with @change handlers."""
    html, _asset_id = assets_page
    assert (
        "setCriticality" in html
    ), 'setCriticality handler not found. Criticality dropdown needs @change="setCriticality".'
    assert (
        "setEnvironment" in html
    ), 'setEnvironment handler not found. Environment dropdown needs @change="setEnvironment".'


def test_assets_result_count(assets_page: tuple[str, int]) -> None:
    """Result count span with x-text containing matchCount exists in toolbar."""
    html, _asset_id = assets_page
    assert "matchCount" in html, (
        "matchCount not found in HTML. " "The result count span needs x-text bound to a matchCount expression."
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

    # Configure the mock cache to return None (cache miss) so process_cves()
    # falls through to the real fetch path. Without this, MagicMock.get() returns
    # a truthy MagicMock which is treated as a cache hit, and the returned mock
    # object's attributes fail SQLAlchemy's type binding.
    # Note: fetch_nvd() will also return None in tests (no real HTTP), so we get
    # a None EnrichedCVE -- the route handles this gracefully by skipping that CVE.
    # We only need the HTML structure (data-* attrs), not real enrichment data.
    app.state.cache.get.return_value = None

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
    """Vuln table has sortable headers for CVE, Priority, CVSS, Status with toggleSort references."""
    html, _asset_id = asset_detail_page
    toggle_count = html.count("toggleSort")
    assert toggle_count >= 4, (
        f"Expected at least 4 toggleSort references (cve, severity, cvss, status), found {toggle_count}. "
        "Sortable headers need @click=\"toggleSort('col')\" attributes."
    )


def test_alpine_xdata_wrapper_vulns(asset_detail_page: tuple[str, int]) -> None:
    """The outer vulnerability card div has x-data=\"vulnTable\" to mount the Alpine component."""
    html, _asset_id = asset_detail_page
    assert 'x-data="vulnTable"' in html, (
        'x-data="vulnTable" not found on the vulnerability card wrapper. '
        "Alpine will not initialize the component without this attribute."
    )


def test_vuln_search_input(asset_detail_page: tuple[str, int]) -> None:
    """Search input with :value=\"search\" and @input=\"setSearch\" exists in the vuln card."""
    html, _asset_id = asset_detail_page
    assert ':value="search"' in html, (
        ':value="search" binding not found on vuln search input. '
        "Alpine uses :value + @input instead of x-model to comply with CSP."
    )
    assert (
        '@input="setSearch"' in html or "@input='setSearch'" in html
    ), '@input="setSearch" handler not found on vuln search input.'


def test_vuln_filter_dropdowns(asset_detail_page: tuple[str, int]) -> None:
    """Severity and status select dropdowns exist with @change handlers."""
    html, _asset_id = asset_detail_page
    assert "setSeverity" in html, 'setSeverity handler not found. Severity dropdown needs @change="setSeverity".'
    assert "setStatus" in html, 'setStatus handler not found. Status dropdown needs @change="setStatus".'
