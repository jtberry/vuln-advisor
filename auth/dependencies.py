"""
auth/dependencies.py -- FastAPI Depends() helpers for authentication.

Three auth methods are checked in priority order:
  1. JWT cookie ("access_token") -- set by the web UI login flow.
  2. Authorization: Bearer <token> header -- API clients using JWTs.
  3. X-API-Key header -- CI/CD and scripts using long-lived API keys.

All three methods converge on a User object after successful verification.

try_get_current_user() is the soft variant (returns None on failure).
get_current_user() wraps it and raises HTTP 401 if unauthenticated.
require_admin() wraps get_current_user() and raises HTTP 403 if not admin.

Layer rule: no imports from web/, core/, cmdb/, or cache/.
  auth/dependencies.py may import from fastapi (for Depends/HTTPException/Request)
  because this module is part of the FastAPI dependency injection system.
"""

from __future__ import annotations

from fastapi import HTTPException, Request

from auth.models import User
from auth.tokens import decode_access_token, hash_api_key


def try_get_current_user(request: Request) -> User | None:
    """Attempt to authenticate the request via cookie, Bearer, or API key.

    Returns the authenticated User on success, None on any failure.
    Never raises -- callers that need a hard 401 should use get_current_user().

    Auth method priority:
      1. JWT cookie -- set by the web UI login (httpOnly, samesite=lax).
      2. Authorization: Bearer header -- for API clients using JWTs.
      3. X-API-Key header -- for CI/CD and scripts.
    """
    user_store = request.app.state.user_store

    # 1. Cookie (web UI)
    token: str | None = request.cookies.get("access_token")

    # 2. Authorization: Bearer header (API clients)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

    # Validate JWT (from cookie or Bearer header)
    if token:
        payload = decode_access_token(token)
        if payload:
            user = user_store.get_by_id(payload["user_id"])
            if user and user.is_active:
                return user

    # 3. X-API-Key header (CI/CD, scripts)
    raw_key = request.headers.get("X-API-Key", "")
    if raw_key:
        key_hash = hash_api_key(raw_key)
        key = user_store.get_api_key_by_hash(key_hash)
        if key and key.is_active:
            user = user_store.get_by_id(key.user_id)
            if user and user.is_active:
                user_store.update_api_key_last_used(key.id)
                return user

    return None


def get_current_user(request: Request) -> User:
    """Require authentication. Raises HTTP 401 if the request is not authenticated.

    Use as a FastAPI dependency:
        @router.get("/protected")
        async def route(user: User = Depends(get_current_user)): ...
    """
    user = try_get_current_user(request)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail={"code": "unauthorized", "message": "Authentication required."},
        )
    return user


def require_admin(request: Request) -> User:
    """Require admin role. Raises HTTP 401 if unauthenticated, HTTP 403 if not admin.

    Use as a FastAPI dependency:
        @router.post("/admin-only")
        async def route(user: User = Depends(require_admin)): ...
    """
    user = get_current_user(request)
    if user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail={"code": "forbidden", "message": "Admin access required."},
        )
    return user
