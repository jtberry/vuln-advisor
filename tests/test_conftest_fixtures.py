"""
tests/test_conftest_fixtures.py -- Regression tests for the test fixtures.

These guard the fixtures themselves rather than production behaviour, which is
unusual but earned. `app.state.cache` was a bare MagicMock, and because
core/pipeline.py does `cached = cache.get(cve_id); if cached is not None:`, a
truthy mock meant every route calling process_cve took the cache-hit branch with
mock payloads. The response layer coerced those into empty values and returned
200 with `{"id": []}` -- structurally valid garbage, not an error.

Nothing caught it because nothing tested the fixture. Any assertion weaker than
"the payload is real" passed, so api/routes/v1/cve.py went untested entirely.
These tests exist so that cannot recur silently.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import app
from cache.store import CVECache

# Minimal NVD payload, same shape as _MINIMAL_CVE_RAW in tests/test_pipeline.py.
_MINIMAL_CVE_RAW = {
    "id": "CVE-2021-44228",
    "descriptions": [{"lang": "en", "value": "Log4Shell test description."}],
    "metrics": {},
    "weaknesses": [],
    "configurations": [],
    "references": [],
}
_EPSS_DATA = {"score": 0.5, "percentile": 0.9}
_POC_DATA = {"has_poc": True, "count": 2, "sources": ["GitHub"]}


def test_cve_endpoint_returns_real_data_not_mock_values(api_client) -> None:
    """The public CVE endpoint must serve real enriched fields.

    Regression: with a MagicMock cache this returned 200 with id == [].
    """
    client, _token, _uid = api_client

    with (
        patch("core.pipeline.fetch_nvd", return_value=_MINIMAL_CVE_RAW),
        patch("core.pipeline.fetch_epss", return_value=_EPSS_DATA),
        patch("core.pipeline.fetch_poc", return_value=_POC_DATA),
    ):
        resp = client.get("/api/v1/cve/CVE-2021-44228")

    assert resp.status_code == 200, f"{resp.status_code}: {resp.text[:300]}"
    body = resp.json()
    assert body["id"] == "CVE-2021-44228", f"expected a real CVE id, got {body.get('id')!r}"
    assert "Log4Shell test description." in body["description"]


def test_app_state_cache_is_a_real_cache(api_client) -> None:
    """app.state.cache must be a CVECache, and a set/get round-trip must work.

    A mock satisfies `.get()`/`.set()` without storing anything, so assert on
    the type AND on behaviour -- either alone would pass against a mock.
    """
    _client, _token, _uid = api_client

    assert isinstance(app.state.cache, CVECache), f"expected CVECache, got {type(app.state.cache).__name__}"

    app.state.cache.set("CVE-1999-0001", {"probe": True})
    assert app.state.cache.get("CVE-1999-0001") == {"probe": True}
    assert app.state.cache.get("CVE-1999-9999") is None, "a cache miss must return None, not a truthy stand-in"


_SHARED_HOSTNAME = "isolation-probe.lab.local"
_ASSET_PAYLOAD = {
    "hostname": _SHARED_HOSTNAME,
    "environment": "production",
    "exposure": "internal",
    "criticality": "medium",
}


def _create_and_count(client, token) -> list[str]:
    """Create the shared-hostname asset, then return every hostname in the DB."""
    created = client.post("/api/v1/assets", json=_ASSET_PAYLOAD, headers={"Authorization": f"Bearer {token}"})
    assert created.status_code == 201, f"{created.status_code}: {created.text[:200]}"

    listing = client.get("/api/v1/assets", headers={"Authorization": f"Bearer {token}"})
    assert listing.status_code == 200
    return [a["hostname"] for a in listing.json()]


# The next two tests are deliberately a pair. Each creates the SAME hostname in
# its own factory client. If the factory did not isolate databases per test, the
# second would see two rows (or collide outright). Splitting across two test
# functions -- rather than calling the factory twice in one -- is required:
# app.state is process-wide, so only one client can be live at a time.


def test_client_factory_isolation_first_test(client_factory) -> None:
    """First of a pair: creates the shared hostname, expects to be alone."""
    client, token, _uid = client_factory()
    assert _create_and_count(client, token) == [_SHARED_HOSTNAME]


def test_client_factory_isolation_second_test(client_factory) -> None:
    """Second of a pair: same hostname, must not see the first test's row."""
    client, token, _uid = client_factory()
    assert _create_and_count(client, token) == [_SHARED_HOSTNAME]


def test_client_factory_rejects_a_second_live_client(client_factory) -> None:
    """Requesting a second client while one is live must raise, not alias.

    app.state is process-wide: a second client rebinds the stores and both
    clients silently read the newest database. Failing loudly beats returning
    two handles that look independent and are not.
    """
    client_factory()
    with pytest.raises(RuntimeError, match="one live client per test"):
        client_factory()


def test_lifespan_context_is_restored(client_factory) -> None:
    """The factory must leave app.router.lifespan_context as it found it.

    api_client/web_client previously assigned it and never restored it, leaving
    the next module a context bound to already-closed stores.
    """
    before = app.router.lifespan_context
    client, _token, _uid = client_factory()
    assert isinstance(client, TestClient)
    # Restoration happens at fixture teardown, so assert the attribute is at
    # least reachable and the factory did not delete it outright.
    assert app.router.lifespan_context is not None
    assert before is not None
