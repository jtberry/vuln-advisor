"""
tests/test_auth_redirect.py -- Integration tests for the auth redirect chain.

These tests exercise _require_auth() end-to-end through the real ASGI stack
using the web_client fixture (follow_redirects=False). We assert on redirect
Location headers directly -- following the redirect would hide them.

Coverage:
  - Unauthenticated requests -> 302 /login?next={path}
  - Expired session (session_expires_at cookie present) -> 302 /login?next=&expired=1
  - Expired session cleanup -- stale cookie deleted in redirect response
  - Authenticated requests pass through (200, no redirect)
  - Dashboard 301 permanent redirect (special case, not auth)
  - Security: next= param is always a relative path (open-redirect prevention)

Why integration tests over unit tests:
  _require_auth is a safety-critical path. Mocking the function would confirm
  the mock works, not the real code. Running through ASGI catches regressions
  where the redirect logic is accidentally removed or the cookie name changes.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient


class TestAuthRedirectChain:
    """Test all three branches of _require_auth: never logged in, expired session, authenticated."""

    def test_unauthenticated_redirects_to_login(self, web_client: tuple[TestClient, str]) -> None:
        """GET /assets with no cookies must redirect 302 to /login?next=/assets."""
        client, _token = web_client
        resp = client.get("/assets")
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith("/login")
        assert "next=/assets" in location

    def test_unauthenticated_includes_next_param(self, web_client: tuple[TestClient, str]) -> None:
        """GET /ingest unauthenticated -- Location must contain next=/ingest for correct post-login return."""
        client, _token = web_client
        resp = client.get("/ingest")
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "next=/ingest" in location

    def test_expired_session_redirects_with_expired_flag(self, web_client: tuple[TestClient, str]) -> None:
        """GET /assets with only session_expires_at cookie (no access_token) must include expired=1.

        _require_auth detects the expired state by the presence of the companion
        session_expires_at cookie. The cookie value itself is irrelevant -- only
        its presence triggers the expired branch.
        """
        client, _token = web_client
        resp = client.get("/assets", cookies={"session_expires_at": "12345"})
        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "next=/assets" in location
        assert "expired=1" in location

    def test_expired_session_deletes_stale_cookie(self, web_client: tuple[TestClient, str]) -> None:
        """Expired session redirect must also delete the stale session_expires_at cookie.

        Leaving the stale cookie would cause every subsequent unauthenticated
        request to appear as an 'expired session' rather than 'never logged in',
        misleading the user with the wrong error message.
        """
        client, _token = web_client
        resp = client.get("/assets", cookies={"session_expires_at": "12345"})
        assert resp.status_code == 302
        # Check that Set-Cookie header deletes session_expires_at
        # FastAPI/Starlette sets max-age=0 to delete cookies
        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not set_cookie_headers:
            # httpx response headers -- iterate all set-cookie values
            set_cookie_headers = [v for k, v in resp.headers.items() if k.lower() == "set-cookie"]
        cookie_deleted = any(
            "session_expires_at" in h and ("max-age=0" in h.lower() or "expires=" in h.lower())
            for h in set_cookie_headers
        )
        assert cookie_deleted, f"session_expires_at cookie was not deleted. Set-Cookie headers: {set_cookie_headers}"

    def test_authenticated_no_redirect(self, web_client: tuple[TestClient, str]) -> None:
        """GET /assets with valid access_token cookie must return 200, not 302."""
        client, token = web_client
        resp = client.get("/assets", cookies={"access_token": token})
        assert resp.status_code == 200

    def test_dashboard_redirects_to_root(self, web_client: tuple[TestClient, str]) -> None:
        """GET /dashboard (authenticated) must 301-redirect to /.

        /dashboard is a permanent redirect for bookmark/nav compatibility, not
        an auth redirect. The 301 means browsers should update stored links to /.
        """
        client, token = web_client
        resp = client.get("/dashboard", cookies={"access_token": token})
        assert resp.status_code == 301
        assert resp.headers["location"] == "/"


class TestSafeNextValidation:
    """Verify the next= redirect parameter cannot be used for open redirect attacks."""

    def test_next_param_is_path_only(self, web_client: tuple[TestClient, str]) -> None:
        """GET /assets unauthenticated -- next= value must be a relative path only.

        An open redirect would allow an attacker to craft:
          /login?next=https://attacker.com
        and redirect victims off-site after login. _require_auth only emits
        the request path (never the full URL), so this must always start with '/'.
        """
        client, _token = web_client
        resp = client.get("/assets")
        assert resp.status_code == 302
        location = resp.headers["location"]
        parsed = urlparse(location)
        next_values = parse_qs(parsed.query).get("next", [])
        assert len(next_values) == 1, f"Expected exactly one 'next' param, got: {next_values}"
        next_path = next_values[0]
        assert next_path.startswith("/"), f"next= must be a relative path, got: {next_path!r}"
        assert not next_path.startswith("//"), f"next= must not be protocol-relative, got: {next_path!r}"
