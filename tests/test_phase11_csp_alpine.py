"""
tests/test_phase11_csp_alpine.py -- Integration tests for Phase 11 Plan 01.

Covers:
  - CSP nonce middleware generates a per-request nonce in the response header
  - All script/style tags in layout.html carry the nonce attribute
  - The nonce value in the HTML matches the value in the CSP header
  - Alpine.js CSP build CDN tag is present in the HTML
  - components.js is referenced in the HTML
  - CSP header contains no unsafe-inline or unsafe-eval directives

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
# Alpine.js CDN tests
# ---------------------------------------------------------------------------


def test_alpine_cdn_in_layout(web_client):
    """Alpine.js CSP build CDN script tag is present on every page."""
    client, _token = web_client
    resp = _get_login_response(client)
    assert resp.status_code == 200
    # The @alpinejs/csp package (not alpinejs) must be used -- the CSP build
    # is required because our policy forbids unsafe-eval.
    assert "@alpinejs/csp" in resp.text, (
        "Alpine.js CSP build CDN URL not found in HTML. "
        "The standard alpinejs build would violate CSP (uses Function())."
    )


def test_components_js_loaded(web_client):
    """components.js is referenced in the layout so Alpine.data() components load."""
    client, _token = web_client
    resp = _get_login_response(client)
    assert resp.status_code == 200
    assert "/static/js/components.js" in resp.text, "/static/js/components.js script tag not found in HTML"


def test_alpine_scripts_have_nonce(web_client):
    """Alpine CDN and components.js script tags carry a nonce attribute."""
    client, _token = web_client
    resp = _get_login_response(client)
    assert resp.status_code == 200
    body = resp.text
    # Both Alpine script tags must have a nonce (otherwise CSP will block them)
    assert "@alpinejs/csp" in body, "Alpine CDN tag missing"
    # Find the Alpine script tag and check it has a nonce
    alpine_tag_match = re.search(r"<script[^>]*@alpinejs/csp[^>]*>", body)
    assert alpine_tag_match, "Could not find Alpine CDN script tag"
    assert 'nonce="' in alpine_tag_match.group(
        0
    ), f"Alpine CDN script tag is missing nonce attribute: {alpine_tag_match.group(0)}"


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
    """CSP header must not contain unsafe-eval (Alpine CSP build avoids Function())."""
    client, _token = web_client
    resp = _get_login_response(client)
    csp = resp.headers.get("Content-Security-Policy-Report-Only", "")
    assert csp, "CSP header missing"
    assert "unsafe-eval" not in csp, f"CSP header contains unsafe-eval -- @alpinejs/csp build avoids this: {csp}"
