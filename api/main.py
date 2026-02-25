"""
api/main.py -- FastAPI application entry point for VulnAdvisor.

Walk phase -- exposes the core engine over HTTP so the web UI and external
tools can consume triage results without running the CLI.

Install deps:  pip install -r requirements-api.txt
Run with:      make run-api
               uvicorn asgi:app --reload

Middleware stack (outermost to innermost):
  1. TrustedHostMiddleware -- rejects requests with unexpected Host headers
  2. CORSMiddleware        -- adds CORS headers for allowed browser origins
  3. SlowAPIMiddleware     -- enforces per-route rate limits from api.limiter

Lifespan handles startup (KEV feed load, cache init, purge task) and
shutdown (cancel purge task, close DB connection) symmetrically.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import JSONResponse, RedirectResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.sessions import SessionMiddleware

from api.limiter import limiter
from api.models import ErrorDetail, ErrorResponse, HealthResponse
from api.routes.v1.assets import router as assets_router
from api.routes.v1.auth import router as auth_router
from api.routes.v1.cve import router as cve_router
from api.routes.v1.dashboard import router as dashboard_router
from auth.dependencies import get_current_user
from auth.models import User
from auth.oauth import oauth as oauth_client
from auth.store import UserStore
from auth.tokens import _SECRET_KEY
from cache.store import CVECache
from cmdb.store import CMDBStore
from core.fetcher import fetch_kev

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("vulnadvisor.api")

# ---------------------------------------------------------------------------
# Background purge task
# ---------------------------------------------------------------------------


async def _purge_loop(app: FastAPI) -> None:
    """Purge expired cache entries every 6 hours.

    Runs as a background asyncio task started in lifespan startup. The
    while-True loop is intentional: asyncio.sleep yields to the event loop so
    other coroutines run freely between iterations. CancelledError from
    task.cancel() during shutdown propagates out of asyncio.sleep and unwinds
    the coroutine cleanly.
    """
    while True:
        await asyncio.sleep(6 * 60 * 60)
        app.state.cache.purge_expired()


# ---------------------------------------------------------------------------
# Lifespan -- modern startup / shutdown pattern (replaces @app.on_event)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage application-level resources across the full server lifetime.

    Pattern: asynccontextmanager lifespan. Everything before yield runs on
    startup; everything after yield runs on shutdown. This is the FastAPI-
    recommended replacement for the deprecated @app.on_event decorator and
    guarantees symmetric teardown even if startup raises an exception mid-way.

    Startup order matters:
      1. KEV feed first -- cheap synchronous HTTP call, data ready before any
         request arrives.
      2. Cache second -- depends on nothing, but must exist before the purge
         task references app.state.cache.
      3. Purge task last -- references app.state.cache, so cache must exist.
    """
    # Startup
    logger.info("VulnAdvisor API starting up")
    kev_data = fetch_kev()
    app.state.kev_set = kev_data
    if kev_data:
        logger.info("KEV feed loaded (%d entries)", len(kev_data))
    else:
        logger.warning("KEV feed unavailable -- exploit status checks will be skipped")
    app.state.cache = CVECache()
    logger.info("Cache initialized")
    app.state.cmdb = CMDBStore()
    logger.info("CMDB initialized")
    # Auth store and OAuth registry
    app.state.user_store = UserStore()
    app.state.setup_required = not app.state.user_store.has_users()
    app.state.oauth = oauth_client
    logger.info(
        "Auth initialized (setup_required=%s)",
        app.state.setup_required,
    )
    app.state.purge_task = asyncio.create_task(_purge_loop(app))

    yield

    # Shutdown
    app.state.purge_task.cancel()
    app.state.cache.close()
    app.state.cmdb.close()
    app.state.user_store.close()
    logger.info("VulnAdvisor API shutdown complete")


# ---------------------------------------------------------------------------
# App instantiation
# ---------------------------------------------------------------------------

app = FastAPI(
    title="VulnAdvisor API",
    description="CVE triage and remediation guidance. Data from NVD, CISA KEV, EPSS, and PoC-in-GitHub.",
    version="0.2.0",
    lifespan=lifespan,
    # Disable built-in /docs and /redoc so we can add auth protection.
    # Auth-protected equivalents are registered below.
    docs_url=None,
    redoc_url=None,
)

# ---------------------------------------------------------------------------
# Middleware stack
#
# Starlette (FastAPI's foundation) wraps middleware in reverse registration
# order at the ASGI level, but add_middleware() calls are applied outermost-
# first from the caller's perspective. Register in the order you want the
# request to encounter them: TrustedHost -> CORS -> SlowAPI.
# ---------------------------------------------------------------------------

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.localhost"],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://localhost:3000", "http://127.0.0.1"],
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
    max_age=3600,
)

app.add_middleware(SlowAPIMiddleware)

# SessionMiddleware is required by authlib to store the OAuth state value
# between the authorization redirect and the callback. This is the standard
# CSRF protection mechanism for OAuth 2.0 authorization code flow -- the state
# is set in the session before redirecting to the provider, then verified in
# the callback. Without session middleware, authlib cannot store state and
# the OAuth flow fails.
app.add_middleware(SessionMiddleware, secret_key=_SECRET_KEY)

# Attach the shared limiter to app.state so SlowAPIMiddleware can locate it.
# SlowAPI looks for app.state.limiter by convention.
app.state.limiter = limiter

# ---------------------------------------------------------------------------
# Setup redirect middleware
#
# If no users have been created yet, redirect every request to /setup so the
# first admin account can be created before any other page is accessible.
# Exempt /setup itself, /static/, and /api/v1/health to avoid redirect loops.
# ---------------------------------------------------------------------------


@app.middleware("http")
async def setup_redirect(request: Request, call_next):
    """Redirect all requests to /setup when no users exist (first-run state).

    The setup_required flag is set in lifespan and cleared by POST /setup
    once the first admin is created. It is an in-memory flag, not re-checked
    on every request to avoid a DB call on every hit. POST /setup re-checks
    at the DB level to guard against the race condition where two concurrent
    requests both pass the flag check before either creates a user [M1].
    """
    path = request.url.path
    if getattr(request.app.state, "setup_required", False):
        exempt = ("/setup", "/api/v1/health")
        if path not in exempt and not path.startswith(("/static/",)):
            return RedirectResponse("/setup", status_code=302)
    return await call_next(request)


# ---------------------------------------------------------------------------
# Request logging middleware
#
# Pattern: Interceptor / Chain of Responsibility. Every request passes through
# this coroutine before reaching any route handler. We capture wall-clock time
# before and after call_next so we can report latency on every response.
#
# @app.middleware("http") is separate from add_middleware() -- it wraps all
# routes at the ASGI level and receives the raw Request/Response objects.
# ---------------------------------------------------------------------------


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    ms = (time.perf_counter() - start) * 1000
    logger.info(
        "%s %s %d %.1fms %s",
        request.method,
        request.url.path,
        response.status_code,
        ms,
        request.client.host if request.client else "unknown",
    )
    return response


# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------

app.include_router(auth_router, prefix="/api/v1", tags=["Auth"])
app.include_router(cve_router, prefix="/api/v1", tags=["CVE Triage"])
app.include_router(assets_router, prefix="/api/v1", tags=["Assets"])
app.include_router(dashboard_router, prefix="/api/v1", tags=["Dashboard"])
# Web UI router is mounted by asgi.py, not here.
# api/ and web/ are independent layers -- only the top-level asgi.py imports both.


# ---------------------------------------------------------------------------
# Auth-protected API documentation
#
# /docs and /redoc are disabled on the FastAPI() constructor (docs_url=None,
# redoc_url=None) and replaced here with custom routes that require a valid
# JWT cookie or Bearer token. This prevents unauthenticated users from
# browsing the full API schema.
# ---------------------------------------------------------------------------


@app.get("/docs", include_in_schema=False)
async def docs(user: User = Depends(get_current_user)):
    """Swagger UI -- requires authentication."""
    return get_swagger_ui_html(openapi_url="/openapi.json", title="VulnAdvisor API")


@app.get("/redoc", include_in_schema=False)
async def redoc(user: User = Depends(get_current_user)):
    """ReDoc UI -- requires authentication."""
    return get_redoc_html(openapi_url="/openapi.json", title="VulnAdvisor API")


# ---------------------------------------------------------------------------
# Exception handlers
#
# All handlers return the same ErrorResponse envelope so API clients can parse
# errors uniformly without inspecting status codes to choose a schema.
# ---------------------------------------------------------------------------


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Return 429 with a structured error when a rate limit is exceeded.

    Retry-After tells clients exactly how many seconds to wait before retrying.
    slowapi stores this on the exception as exc.retry_after (int seconds).
    """
    retry_after = int(getattr(exc, "retry_after", 60))
    response = JSONResponse(
        status_code=429,
        content=ErrorResponse(
            error=ErrorDetail(
                code="rate_limited",
                message="Too many requests.",
                detail=str(exc),
            )
        ).model_dump(),
    )
    response.headers["Retry-After"] = str(retry_after)
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Return 422 with structured error when request body or query params fail validation."""
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            error=ErrorDetail(
                code="validation_error",
                message="Request validation failed.",
                detail=str(exc.errors()),
            )
        ).model_dump(),
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Return a structured error for all FastAPI/Starlette HTTP exceptions.

    Route handlers raise HTTPException with detail=ErrorDetail(...).model_dump()
    (a dict). When detail is already a structured dict, use it directly as the
    error field rather than stringifying it -- str(dict) produces a Python repr,
    not JSON.
    """
    if isinstance(exc.detail, dict):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail},
        )
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=ErrorDetail(
                code=f"http_{exc.status_code}",
                message=str(exc.detail),
            )
        ).model_dump(),
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for unexpected server errors.

    Security note: the raw exception is written to stderr only, never to the
    response body. Exposing internal stack traces to clients can leak
    implementation details and aid attackers. The client receives only a
    generic message.
    """
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error=ErrorDetail(
                code="internal_error",
                message="An unexpected error occurred.",
            )
        ).model_dump(),
    )


# ---------------------------------------------------------------------------
# Health endpoint
#
# Defined directly in main.py (not in a router) so it is always reachable
# regardless of router registration state. No rate limit applied -- health
# checks from load balancers and monitoring systems must not be throttled.
# ---------------------------------------------------------------------------


@app.get("/api/v1/health", include_in_schema=True, tags=["Health"])
async def health() -> HealthResponse:
    """Return API liveness and current version."""
    return HealthResponse(version="0.2.0")
