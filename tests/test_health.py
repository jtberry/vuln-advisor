"""
tests/test_health.py -- Integration tests for GET /api/v1/health.

Covers:
  - 200 response with status, version, and components fields (DEPL-01)
  - components.database key present and reports 'ok' (DEPL-01)
  - No authentication required (DEPL-01)
"""

from __future__ import annotations


def test_health_returns_200_with_components(api_client):
    """Health endpoint returns 200 with status, version, and components."""
    client, token, _ = api_client
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "components" in data
    assert data["components"]["app"] == "ok"
    assert data["components"]["database"] == "ok"


def test_health_response_includes_database_component(api_client):
    """Health response components dict includes database status."""
    client, _, _ = api_client
    data = client.get("/api/v1/health").json()
    assert "database" in data["components"]
    assert data["components"]["database"] in ("ok", "error")


def test_health_no_auth_required(api_client):
    """Health endpoint is accessible without any authentication headers."""
    client, _, _ = api_client
    # Explicitly make request with no auth headers
    resp = client.get("/api/v1/health", headers={})
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
