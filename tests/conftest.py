"""
tests/conftest.py -- Shared test fixtures for VulnAdvisor integration tests.

This module provides:
  - _make_test_stores(): creates isolated in-memory DBs for auth + CMDB
  - _patch_lifespan(): wires test stores into app.state, bypassing real startup
  - api_client: TestClient with admin JWT for API integration tests
  - web_client: TestClient with follow_redirects=False for web route tests

Design: Named shared-memory SQLite URIs (not plain :memory:) are required
because TestClient runs route handlers in a thread pool. Plain :memory: DBs
are per-connection and would present a blank schema to each worker thread.
The named URI format (file:name?mode=memory&cache=shared&uri=true) shares
one in-memory instance across all connections in the same process.

The DEBUG env var must be set before any auth module import so get_settings()
auto-generates SECRET_KEY in dev mode rather than raising ValueError.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Generator
from contextlib import asynccontextmanager
from unittest.mock import MagicMock

# CRITICAL: Set DEBUG before any auth/core import so get_settings() can
# auto-generate SECRET_KEY in dev mode instead of raising ValueError.
os.environ.setdefault("DEBUG", "true")

import pytest
from fastapi.testclient import TestClient

from api.main import app
from auth.models import User
from auth.store import UserStore
from auth.tokens import create_access_token, hash_password
from cmdb.store import CMDBStore

# ---------------------------------------------------------------------------
# Import the FastAPI app and the web router
# ---------------------------------------------------------------------------


# Mount the web router once; guard with try/except to handle the already-
# included case if conftest is imported multiple times in the same session.
try:
    from web.routes import router as web_router

    app.include_router(web_router, tags=["Web UI"])
except Exception:
    pass  # Router already included or unavailable


# ---------------------------------------------------------------------------
# Store helpers
# ---------------------------------------------------------------------------


def _make_test_stores(db_suffix: str) -> tuple[UserStore, CMDBStore]:
    """Create isolated named shared-memory SQLite stores for test isolation.

    Named URIs allow multiple connections (from different threads in TestClient)
    to access the same in-memory database. Plain ':memory:' would give each
    thread a blank schema, causing 'no such table' errors on the first query.

    Args:
        db_suffix: Unique string appended to the DB name so parallel test
                   modules don't share state (e.g. 'api', 'web').
    """
    auth_url = f"sqlite:///file:test_auth_{db_suffix}?mode=memory&cache=shared&uri=true"
    cmdb_url = f"sqlite:///file:test_cmdb_{db_suffix}?mode=memory&cache=shared&uri=true"
    user_store = UserStore(db_url=auth_url)
    cmdb = CMDBStore(db_url=cmdb_url)
    return user_store, cmdb


def _patch_lifespan(user_store: UserStore, cmdb: CMDBStore):
    """Return an async context manager that replaces the real lifespan.

    Wires pre-created test stores into app.state so TestClient routes see
    isolated test DBs rather than the production databases. Also mocks the
    cache and OAuth registry to prevent real network calls.

    The purge_task is a long-sleeping coroutine that keeps asyncio happy
    (a real asyncio.Task is required; MagicMock would fail on .cancel()).
    """

    @asynccontextmanager
    async def test_lifespan(app):
        app.state.user_store = user_store
        app.state.cmdb = cmdb
        app.state.cache = MagicMock()
        app.state.kev_set = set()
        app.state.setup_required = False
        app.state.oauth = MagicMock()
        app.state.purge_task = asyncio.create_task(asyncio.sleep(99999))
        yield
        app.state.purge_task.cancel()

    return test_lifespan


# ---------------------------------------------------------------------------
# Module-scoped fixtures -- one TestClient per test module for speed
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def api_client() -> Generator[tuple[TestClient, str, int], None, None]:
    """Yield (client, token, user_id) for API integration tests.

    The TestClient uses the real FastAPI app with a patched lifespan so
    tests hit real route handlers but use isolated in-memory stores.
    The admin user is created before the client starts and the JWT is
    generated for use in Authorization headers.
    """
    user_store, cmdb = _make_test_stores("api")

    # Create admin user before starting the test client
    admin = User(
        username="testadmin",
        hashed_password=hash_password("testpass123"),
        role="admin",
    )
    uid = user_store.create_user(admin)

    # Generate a long-lived JWT for test requests
    token = create_access_token(user_id=uid, username="testadmin", role="admin", expire_seconds=3600)

    app.router.lifespan_context = _patch_lifespan(user_store, cmdb)

    with TestClient(app, raise_server_exceptions=True) as client:
        yield client, token, uid

    user_store.close()
    cmdb.close()


@pytest.fixture(scope="module")
def web_client() -> Generator[tuple[TestClient, str], None, None]:
    """Yield (client, token) for web route integration tests.

    follow_redirects=False is essential for web route tests: we assert on
    redirect *locations* (e.g. 302 to /login), which are invisible once
    the client follows the redirect and returns the final 200 response.
    """
    user_store, cmdb = _make_test_stores("web")

    admin = User(
        username="webadmin",
        hashed_password=hash_password("webpass123"),
        role="admin",
    )
    uid = user_store.create_user(admin)

    token = create_access_token(user_id=uid, username="webadmin", role="admin", expire_seconds=3600)

    app.router.lifespan_context = _patch_lifespan(user_store, cmdb)

    with TestClient(app, follow_redirects=False, raise_server_exceptions=True) as client:
        yield client, token

    user_store.close()
    cmdb.close()
