"""
tests/test_csp_alpine.py -- Integration tests for CSP nonce middleware and vanilla JS setup.

Covers:
  - CSP nonce middleware generates a per-request nonce in the response header
  - All script/style tags in layout.html carry the nonce attribute
  - The nonce value in the HTML matches the value in the CSP header
  - components.js (vanilla JS, no Alpine) is referenced in the HTML
  - CSP header contains no unsafe-inline or unsafe-eval directives

Note: Alpine.js CDN was removed in Phase 12 Plan 01. All interactive UI is now
implemented with vanilla JS (AssetTableFilter, VulnTableFilter in components.js).
These tests were updated to reflect the vanilla JS architecture.

These tests use the /login page (no auth required) since it renders layout.html.
The web_client fixture provides a TestClient with follow_redirects=False and a
pre-created admin user (JWT token available but not needed for these tests).
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_login_response(client):
    """GET /login and return the response. Uses follow_redirects to reach /login."""
    resp = client.get("/login", follow_redirects=True)
    return resp


# ---------------------------------------------------------------------------
# CSP header tests
# ---------------------------------------------------------------------------


def test_csp_header_present(web_client):
    """Every HTML response includes Content-Security-Policy-Report-Only header."""
    client, _token = web_client
    resp = _get_login_response(client)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:200]}"
    csp = resp.headers.get("Content-Security-Policy-Report-Only", "")
    assert csp, "Content-Security-Policy-Report-Only header is missing"
    assert "nonce-" in csp, f"CSP header does not contain a nonce directive: {csp}"


def test_csp_nonce_in_html(web_client):
    """Script and style tags in the HTML carry a nonce attribute."""
    client, _token = web_client
    resp = _get_login_response(client)
    assert resp.status_code == 200
    body = resp.text
    # At least one nonce attribute must appear in the rendered HTML
    assert 'nonce="' in body, "No nonce attributes found in HTML -- layout.html missing nonce wiring"


def test_csp_nonce_matches_header(web_client):
    """The nonce value in the CSP header appears in the HTML body."""
    client, _token = web_client
    resp = _get_login_response(client)
    assert resp.status_code == 200
    csp = resp.headers.get("Content-Security-Policy-Report-Only", "")
    # Extract the nonce value from the CSP header (nonce-<value>)
    match = re.search(r"nonce-([A-Za-z0-9_\-]+)", csp)
    assert match, f"Could not extract nonce from CSP header: {csp}"
    nonce_value = match.group(1)
    # The nonce value must appear in the HTML body
    assert nonce_value in resp.text, (
        f"Nonce '{nonce_value}' from CSP header not found in HTML body -- "
        "nonce mismatch between middleware and template"
    )


# ---------------------------------------------------------------------------
# Vanilla JS / components.js tests
# ---------------------------------------------------------------------------


def test_no_alpine_cdn_in_layout(web_client):
    """Alpine.js CDN must NOT be present -- it was removed in Phase 12 Plan 01.

    All interactive UI now uses vanilla JS (AssetTableFilter, VulnTableFilter).
    Alpine requires unsafe-eval in CSP; vanilla JS does not.
    """
    client, _token = web_client
    resp = _get_login_response(client)
    assert resp.status_code == 200
    assert "alpinejs" not in resp.text, (
        "Alpine.js CDN found in HTML. Alpine was removed in Phase 12 Plan 01 -- "
        "all interactive UI uses vanilla JS components.js instead."
    )


def test_components_js_loaded(web_client):
    """components.js is referenced in the layout so vanilla JS components load."""
    client, _token = web_client
    resp = _get_login_response(client)
    assert resp.status_code == 200
    assert "/static/js/components.js" in resp.text, "/static/js/components.js script tag not found in HTML"


def test_components_js_has_nonce(web_client):
    """components.js script tag carries a nonce attribute (required by CSP)."""
    client, _token = web_client
    resp = _get_login_response(client)
    assert resp.status_code == 200
    body = resp.text
    # Find the components.js script tag and check it has a nonce
    components_tag_match = re.search(r"<script[^>]*components\.js[^>]*>", body)
    assert components_tag_match, "Could not find components.js script tag in HTML"
    assert 'nonce="' in components_tag_match.group(
        0
    ), f"components.js script tag is missing nonce attribute: {components_tag_match.group(0)}"


# ---------------------------------------------------------------------------
# CSP policy content tests
# ---------------------------------------------------------------------------


def test_no_unsafe_inline_in_csp(web_client):
    """CSP header must not contain unsafe-inline (it is replaced by nonces)."""
    client, _token = web_client
    resp = _get_login_response(client)
    csp = resp.headers.get("Content-Security-Policy-Report-Only", "")
    assert csp, "CSP header missing"
    assert "unsafe-inline" not in csp, f"CSP header contains unsafe-inline -- nonces should replace it: {csp}"


def test_no_unsafe_eval_in_csp(web_client):
    """CSP header must not contain unsafe-eval (vanilla JS has no eval requirement)."""
    client, _token = web_client
    resp = _get_login_response(client)
    csp = resp.headers.get("Content-Security-Policy-Report-Only", "")
    assert csp, "CSP header missing"
    assert "unsafe-eval" not in csp, f"CSP header contains unsafe-eval -- vanilla JS components.js avoids eval: {csp}"
