"""
tests/test_debt_cleanup.py -- Integration tests for v1.0 audit debt items.

Covers DEBT-05, DEBT-06, DEBT-07:
  DEBT-05: /account/api-keys route exists and requires auth
  DEBT-06: update_vuln_status_htmx accepts from_status form field
  DEBT-07: NVD_API_KEY is read from Settings, not os.environ directly
"""

from __future__ import annotations

import inspect
import subprocess

from core.config import Settings

# ---------------------------------------------------------------------------
# DEBT-05: /account/api-keys route
# ---------------------------------------------------------------------------


def test_api_keys_page_requires_auth(web_client):
    """GET /account/api-keys without auth redirects to /login (302)."""
    client, _token = web_client
    resp = client.get("/account/api-keys")
    assert resp.status_code == 302, f"Expected 302, got {resp.status_code}"
    assert "/login" in resp.headers.get(
        "location", ""
    ), f"Expected redirect to /login, got: {resp.headers.get('location')}"


def test_api_keys_page_authenticated(web_client):
    """GET /account/api-keys with a valid auth cookie returns 200 with 'Coming soon'."""
    client, token = web_client
    client.cookies.set("access_token", token)
    try:
        resp = client.get("/account/api-keys")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert "Coming soon" in resp.text, "Expected 'Coming soon' in page body"
    finally:
        client.cookies.delete("access_token")


def test_api_keys_nav_link_updated(web_client):
    """Authenticated page body contains href='/account/api-keys' (not '/api-keys')."""
    client, token = web_client
    client.cookies.set("access_token", token)
    try:
        resp = client.get("/account/api-keys")
        assert resp.status_code == 200
        assert 'href="/account/api-keys"' in resp.text, "Nav link should point to /account/api-keys"
        assert 'href="/api-keys"' not in resp.text, "Old /api-keys nav link should be removed"
    finally:
        client.cookies.delete("access_token")


# ---------------------------------------------------------------------------
# DEBT-06: from_status parameter on update_vuln_status_htmx
# ---------------------------------------------------------------------------


def test_from_status_accepted():
    """update_vuln_status_htmx function signature includes from_status parameter."""
    from web.routes import update_vuln_status_htmx

    sig = inspect.signature(update_vuln_status_htmx)
    assert "from_status" in sig.parameters, "update_vuln_status_htmx must accept from_status as an optional form field"
    param = sig.parameters["from_status"]
    # Verify it is optional (has a default, not required)
    assert param.default is not inspect.Parameter.empty, "from_status must be optional (have a default value)"


# ---------------------------------------------------------------------------
# DEBT-07: NVD_API_KEY centralized in Settings
# ---------------------------------------------------------------------------


def test_nvd_api_key_in_settings():
    """Settings class has nvd_api_key field with an empty string default."""
    settings = Settings(debug=True, secret_key="x" * 32)
    assert hasattr(settings, "nvd_api_key"), "Settings must have nvd_api_key field"
    assert settings.nvd_api_key == "", f"Default nvd_api_key should be empty string, got: {settings.nvd_api_key!r}"


def test_nvd_api_key_not_in_environ():
    """core/fetcher.py must not read NVD_API_KEY directly from os.environ."""
    import core.fetcher as fetcher_module

    source = inspect.getsource(fetcher_module)
    assert 'os.environ.get("NVD_API_KEY")' not in source, (
        "fetcher.py must not read NVD_API_KEY from os.environ directly. " "Use get_settings().nvd_api_key instead."
    )
    assert "get_settings" in source, "fetcher.py must use get_settings() to read the NVD API key"


# ---------------------------------------------------------------------------
# DEBT-08: make smoke exits zero and includes auth + web imports
# ---------------------------------------------------------------------------


def test_smoke_target_exits_zero():
    """make smoke completes without errors (exit code 0)."""
    result = subprocess.run(
        ["make", "smoke"],
        capture_output=True,
        text=True,
        cwd="/mnt/c/Users/Jason/scripts/new_project",
    )
    assert result.returncode == 0, (
        f"make smoke failed with exit code {result.returncode}.\n"
        f"stdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )
    assert "All imports OK" in result.stdout, f"Expected 'All imports OK' in smoke output.\nstdout: {result.stdout}"
