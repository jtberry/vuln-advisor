"""
tests/test_api_routes.py -- Integration tests for API asset and auth routes.

These tests exercise the full stack: FastAPI routing -> auth dependency injection
-> CMDBStore/UserStore operations -> response model serialization. Unit testing
individual route functions would miss middleware, dependency injection, and
response model validation -- integration tests are the right tool here.

Coverage:
  - Auth failures: 401 on GET/POST /assets, GET /me, GET /assets/{id} without token
  - Asset happy path: POST 201, GET list 200, GET detail 200, GET 404
  - Auth route happy path: POST /login valid 200, POST /login invalid 401, GET /me 200
  - Public endpoint: GET /providers returns 200 without auth

Fixtures used (from conftest.py):
  - api_client: (client, token, uid) -- TestClient with admin JWT, follow_redirects=True
    The fixture creates an admin user with username="testadmin", password="testpass123".
"""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestApiAuthFailure:
    """Unauthenticated requests to protected API routes must return 401."""

    def test_get_assets_unauthenticated(self, api_client: tuple[TestClient, str, int]) -> None:
        """GET /api/v1/assets without Authorization header must return 401."""
        client, _token, _uid = api_client
        resp = client.get("/api/v1/assets")
        assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"

    def test_post_assets_unauthenticated(self, api_client: tuple[TestClient, str, int]) -> None:
        """POST /api/v1/assets with valid JSON body but no auth header must return 401."""
        client, _token, _uid = api_client
        resp = client.post("/api/v1/assets", json={"hostname": "no-auth-host"})
        assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"

    def test_get_me_unauthenticated(self, api_client: tuple[TestClient, str, int]) -> None:
        """GET /api/v1/auth/me without Authorization header must return 401."""
        client, _token, _uid = api_client
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"

    def test_get_asset_detail_unauthenticated(self, api_client: tuple[TestClient, str, int]) -> None:
        """GET /api/v1/assets/1 without Authorization header must return 401."""
        client, _token, _uid = api_client
        resp = client.get("/api/v1/assets/1")
        assert resp.status_code in (401, 403), f"Expected 401/403, got {resp.status_code}"


class TestApiAssetRoutes:
    """Happy-path integration tests for asset CRUD routes."""

    def test_create_asset(self, api_client: tuple[TestClient, str, int]) -> None:
        """POST /api/v1/assets with valid auth and body must return 201 with asset id and hostname."""
        client, token, _uid = api_client
        headers = {"Authorization": f"Bearer {token}"}
        body = {"hostname": "test-web-01", "exposure": "internet", "criticality": "high"}
        resp = client.post("/api/v1/assets", json=body, headers=headers)
        assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert "id" in data, "Response must include 'id'"
        assert data["hostname"] == "test-web-01"

    def test_list_assets(self, api_client: tuple[TestClient, str, int]) -> None:
        """GET /api/v1/assets with valid auth must return 200 with a list."""
        client, token, _uid = api_client
        headers = {"Authorization": f"Bearer {token}"}
        resp = client.get("/api/v1/assets", headers=headers)
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert isinstance(data, list), "Response must be a list"

    def test_get_asset_detail(self, api_client: tuple[TestClient, str, int]) -> None:
        """POST to create an asset, then GET /api/v1/assets/{id} must return the asset with empty vulns."""
        client, token, _uid = api_client
        headers = {"Authorization": f"Bearer {token}"}

        # Create a fresh asset for this test to have a known id
        create_resp = client.post(
            "/api/v1/assets",
            json={"hostname": "detail-test-host", "exposure": "internal", "criticality": "medium"},
            headers=headers,
        )
        assert create_resp.status_code == 201
        asset_id = create_resp.json()["id"]

        # Fetch the detail view
        resp = client.get(f"/api/v1/assets/{asset_id}", headers=headers)
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["hostname"] == "detail-test-host"
        assert isinstance(data.get("vulnerabilities"), list), "vulnerabilities must be a list"
        assert data["vulnerabilities"] == [], "Freshly created asset must have empty vulnerabilities"

    def test_get_asset_not_found(self, api_client: tuple[TestClient, str, int]) -> None:
        """GET /api/v1/assets/99999 with valid auth must return 404 for a non-existent asset."""
        client, token, _uid = api_client
        headers = {"Authorization": f"Bearer {token}"}
        resp = client.get("/api/v1/assets/99999", headers=headers)
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"


class TestApiAuthRoutes:
    """Happy-path and failure tests for auth routes."""

    def test_login_valid_credentials(self, api_client: tuple[TestClient, str, int]) -> None:
        """POST /api/v1/auth/login with correct credentials must return 200 with access_token and username."""
        client, _token, _uid = api_client
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "testadmin", "password": "testpass123"},
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert "access_token" in data, "Response must include 'access_token'"
        assert data["username"] == "testadmin"

    def test_login_invalid_credentials(self, api_client: tuple[TestClient, str, int]) -> None:
        """POST /api/v1/auth/login with wrong password must return 401 with bad_credentials error code."""
        client, _token, _uid = api_client
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "testadmin", "password": "wrongpassword"},
        )
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data.get("error", {}).get("code") == "bad_credentials"

    def test_me_authenticated(self, api_client: tuple[TestClient, str, int]) -> None:
        """GET /api/v1/auth/me with valid Bearer token must return 200 with username and role."""
        client, token, _uid = api_client
        headers = {"Authorization": f"Bearer {token}"}
        resp = client.get("/api/v1/auth/me", headers=headers)
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert data["username"] == "testadmin"
        assert data["role"] == "admin"

    def test_providers_public(self, api_client: tuple[TestClient, str, int]) -> None:
        """GET /api/v1/auth/providers with no auth must return 200 -- intentionally public endpoint."""
        client, _token, _uid = api_client
        resp = client.get("/api/v1/auth/providers")
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert isinstance(data, list), "providers response must be a list"
