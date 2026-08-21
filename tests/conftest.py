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
from typing import Callable
from unittest.mock import MagicMock
from uuid import uuid4

# CRITICAL: Set DEBUG before any auth/core import so get_settings() can
# auto-generate SECRET_KEY in dev mode instead of raising ValueError.
os.environ.setdefault("DEBUG", "true")

import pytest
from fastapi.testclient import TestClient

from api.main import app
from auth.models import User
from auth.store import UserStore
from auth.tokens import create_access_token, hash_password
from cache.store import CVECache
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
        # A real cache, NOT a MagicMock.
        #
        # core/pipeline.py does `cached = cache.get(cve_id); if cached is not
        # None:` -- a bare MagicMock returns a truthy mock from .get() and
        # supports __getitem__, so every route calling process_cve took the
        # cache-hit branch with mock payloads. The response layer then coerced
        # those mocks into empty values and returned 200 with garbage
        # (`GET /api/v1/cve/CVE-2021-44228` -> 200 with `"id": []`), rather
        # than failing loudly. That is why api/routes/v1/cve.py had no tests:
        # any assertion stronger than `status_code == 200` was impossible.
        #
        # ":memory:" is per-connection, which is fine here -- CVECache holds a
        # single sqlite3 connection with check_same_thread=False, so the
        # TestClient thread pool shares one instance. (Contrast the named
        # shared-memory URIs the SQLAlchemy stores need, explained above.)
        cache = CVECache(db_path=":memory:", ttl=3600)

        app.state.user_store = user_store
        app.state.cmdb = cmdb
        app.state.cache = cache
        app.state.kev_set = set()
        app.state.setup_required = False
        # oauth stays mocked on purpose -- it prevents real network calls to
        # the provider during tests. Unlike the cache, nothing reads through it.
        app.state.oauth = MagicMock()
        app.state.purge_task = asyncio.create_task(asyncio.sleep(99999))
        yield
        app.state.purge_task.cancel()
        cache.close()

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

    # Capture and restore: app is a module-level singleton, so leaving a patched
    # lifespan behind hands the next test module a context bound to stores this
    # fixture already closed.
    original_lifespan = app.router.lifespan_context
    app.router.lifespan_context = _patch_lifespan(user_store, cmdb)

    with TestClient(app, base_url="http://localhost", raise_server_exceptions=True) as client:
        yield client, token, uid

    app.router.lifespan_context = original_lifespan
    user_store.close()
    cmdb.close()


@pytest.fixture(scope="module")
def web_client() -> Generator[tuple[TestClient, str], None, None]:
    """Yield (client, token) for web route integration tests.

    follow_redirects=False is essential for web route tests: we assert on
    redirect *locations* (e.g. 302 to /login), which are invisible once
    the client follows the redirect and returns the final 200 response.

    base_url="http://localhost" is required because TrustedHostMiddleware
    in api/main.py allows only localhost and 127.0.0.1. The default TestClient
    base URL is http://testserver, which is rejected with 400 Invalid host header.
    """
    user_store, cmdb = _make_test_stores("web")

    admin = User(
        username="webadmin",
        hashed_password=hash_password("webpass123"),
        role="admin",
    )
    uid = user_store.create_user(admin)

    token = create_access_token(user_id=uid, username="webadmin", role="admin", expire_seconds=3600)

    original_lifespan = app.router.lifespan_context
    app.router.lifespan_context = _patch_lifespan(user_store, cmdb)

    with TestClient(app, base_url="http://localhost", follow_redirects=False, raise_server_exceptions=True) as client:
        yield client, token

    app.router.lifespan_context = original_lifespan
    user_store.close()
    cmdb.close()


# ---------------------------------------------------------------------------
# Function-scoped factory -- for tests that create or mutate data
# ---------------------------------------------------------------------------


@pytest.fixture
def client_factory() -> Generator[Callable[..., tuple[TestClient, str, int]], None, None]:
    """Yield a factory producing isolated TestClients, one database each.

    Use this for any test that creates or mutates data. The module-scoped
    api_client/web_client fixtures share a single database across every test in
    a file, so tests observe each other's writes and become order-dependent.
    That is why test_api_routes.py asserts `isinstance(data, list)` rather than
    an exact count -- the shared state makes a stronger assertion impossible.

    Each call gets a uuid4 database suffix, so two *tests* can create the same
    hostname without colliding.

    ONE LIVE CLIENT PER TEST. `app` is a module-level singleton and the lifespan
    writes the stores onto `app.state`, which is shared process-wide. Starting a
    second client rebinds app.state.cmdb / app.state.user_store, and the first
    client silently starts reading the second one's database -- two simultaneous
    clients are aliases, not isolated peers. A second call while one is live
    raises rather than quietly returning something wrong.

    Args accepted by the returned factory:
        db_suffix:        override the generated suffix (default: uuid4 hex)
        follow_redirects: False to assert on redirect Locations (default True)
        username / role:  the seeded user (default an admin)
    """
    created: list = []
    original_lifespan = app.router.lifespan_context

    def _make(
        db_suffix: str = "",
        follow_redirects: bool = True,
        username: str = "factoryadmin",
        role: str = "admin",
    ) -> tuple[TestClient, str, int]:
        if created:
            raise RuntimeError(
                "client_factory supports one live client per test. app.state is "
                "process-wide, so a second client rebinds the stores and both "
                "clients end up reading the newest database. Split the test in two -- "
                "each test function gets its own factory instance."
            )

        suffix = db_suffix or uuid4().hex
        user_store, cmdb = _make_test_stores(suffix)

        user = User(username=username, hashed_password=hash_password("factorypass123"), role=role)
        uid = user_store.create_user(user)
        token = create_access_token(user_id=uid, username=username, role=role, expire_seconds=3600)

        app.router.lifespan_context = _patch_lifespan(user_store, cmdb)
        # Entered manually rather than via `with` so the client stays open for
        # the body of the test; teardown below closes it.
        ctx = TestClient(
            app,
            base_url="http://localhost",
            follow_redirects=follow_redirects,
            raise_server_exceptions=True,
        )
        client = ctx.__enter__()
        created.append((ctx, user_store, cmdb))
        return client, token, uid

    yield _make

    for ctx, user_store, cmdb in reversed(created):
        ctx.__exit__(None, None, None)
        user_store.close()
        cmdb.close()
    app.router.lifespan_context = original_lifespan
