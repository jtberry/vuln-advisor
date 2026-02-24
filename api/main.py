"""
api/main.py -- FastAPI application entry point for VulnAdvisor.

Walk phase -- exposes the core engine over HTTP so the web UI and external
tools can consume triage results without running the CLI.

Install deps:  pip install -r requirements-api.txt
Run with:      make run-api
               uvicorn api.main:app --reload

Middleware stack (outermost to innermost):
  1. TrustedHostMiddleware -- rejects requests with unexpected Host headers
  2. CORSMiddleware        -- adds CORS headers for allowed browser origins
  3. SlowAPIMiddleware     -- enforces per-route rate limits from api.limiter

Lifespan handles startup (KEV feed load, cache init, purge task) and
shutdown (cancel purge task, close DB connection) symmetrically.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from api.limiter import limiter
from api.models import ErrorDetail, ErrorResponse, HealthResponse
from api.routes.v1.cve import router as cve_router
from cache.store import CVECache
from core.fetcher import fetch_kev

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
    app.state.kev_set = fetch_kev()
    app.state.cache = CVECache()
    app.state.purge_task = asyncio.create_task(_purge_loop(app))

    yield

    # Shutdown
    app.state.purge_task.cancel()
    app.state.cache.close()


# ---------------------------------------------------------------------------
# App instantiation
# ---------------------------------------------------------------------------

app = FastAPI(
    title="VulnAdvisor API",
    description="CVE triage and remediation guidance. Data from NVD, CISA KEV, EPSS, and PoC-in-GitHub.",
    version="0.2.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
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
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    max_age=3600,
)

app.add_middleware(SlowAPIMiddleware)

# Attach the shared limiter to app.state so SlowAPIMiddleware can locate it.
# SlowAPI looks for app.state.limiter by convention.
app.state.limiter = limiter

# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------

app.include_router(cve_router, prefix="/api/v1", tags=["CVE Triage"])

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
    """Return a structured error for all FastAPI/Starlette HTTP exceptions."""
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
    print(str(exc), file=sys.stderr)
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
