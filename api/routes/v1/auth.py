"""
api/routes/v1/auth.py -- Authentication and user management REST endpoints.

Routes:
  POST /api/v1/auth/login              -- password login; sets JWT cookie
  POST /api/v1/auth/logout             -- clears cookie; 200
  GET  /api/v1/auth/me                 -- current user info (requires auth)
  GET  /api/v1/auth/providers          -- list enabled OAuth providers (public)
  POST /api/v1/auth/api-keys           -- create API key (requires auth)
  GET  /api/v1/auth/api-keys           -- list user's API keys (requires auth)
  DELETE /api/v1/auth/api-keys/{id}   -- revoke key (requires auth, ownership checked)
  POST /api/v1/auth/users              -- create user (admin only)
  GET  /api/v1/auth/users              -- list all users (admin only)
  PATCH /api/v1/auth/users/{id}        -- update role/is_active (admin only)

Security:
  [H2] POST /login is rate-limited to 10 requests/minute per IP.
  [C1] authenticate_user() provides timing equalization -- use it, never inline.
  [M4] PATCH /users/{id} blocks self-deactivation and last-admin-deactivation.
  [M5] Cache-Control: no-store on login responses.
  IDOR guard: DELETE /api-keys/{id} passes user_id to store; the store checks ownership.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from api.limiter import limiter
from api.models import (
    ApiKeyCreate,
    ApiKeyCreatedResponse,
    ApiKeyResponse,
    LoginRequest,
    LoginResponse,
    MeResponse,
    OAuthProviderInfo,
    UserCreate,
    UserPatch,
    UserResponse,
)
from auth.dependencies import get_current_user, require_admin
from auth.models import ApiKey, User
from auth.oauth import get_enabled_providers
from auth.store import UserStore
from auth.tokens import (
    authenticate_user,
    create_access_token,
    generate_api_key,
    hash_api_key,
    hash_password,
    set_auth_cookie,
)

# Auth policy:
# - POST   /api/v1/auth/login:           public -- login endpoint must be unauthenticated
# - POST   /api/v1/auth/logout:          public -- clearing a cookie needs no prior auth
# - GET    /api/v1/auth/providers:       public -- login page calls this to render OAuth buttons
# - GET    /api/v1/auth/me:              requires auth (get_current_user)
# - POST   /api/v1/auth/api-keys:        requires auth (get_current_user)
# - GET    /api/v1/auth/api-keys:        requires auth (get_current_user)
# - DELETE /api/v1/auth/api-keys/{id}:   requires auth + ownership check in store
# - POST   /api/v1/auth/users:           requires admin (require_admin)
# - GET    /api/v1/auth/users:           requires admin (require_admin)
# - PATCH  /api/v1/auth/users/{id}:      requires admin (require_admin)
router = APIRouter()


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------


@limiter.limit("10/minute")  # [H2] brute-force mitigation -- must be ABOVE @router to preserve FastAPI introspection
@router.post("/auth/login", response_model=LoginResponse)
def login(request: Request, body: LoginRequest) -> JSONResponse:
    """Authenticate with username and password; set JWT cookie.

    Uses authenticate_user() which includes timing equalization [C1]. Do NOT
    inline get_by_username() + verify_password() -- that re-introduces the
    timing attack.

    Returns the same generic error for wrong username and wrong password
    ("bad_credentials") to avoid leaking username existence information.
    """
    user_store: UserStore = request.app.state.user_store
    user = authenticate_user(user_store, body.username, body.password)
    if user is None:
        resp = JSONResponse(
            status_code=401,
            content={"error": {"code": "bad_credentials", "message": "Invalid username or password."}},
        )
        resp.headers["Cache-Control"] = "no-store"  # [M5]
        return resp

    token = create_access_token(user.id, user.username, user.role)
    resp = JSONResponse(
        status_code=200,
        content=LoginResponse(
            access_token=token,
            token_type="bearer",  # noqa: S106 # nosec B106 -- OAuth token type, not a password
            expires_in=8 * 3600,
            username=user.username,
            role=user.role,
        ).model_dump(),
    )
    set_auth_cookie(resp, token)
    resp.headers["Cache-Control"] = "no-store"  # [M5]
    return resp


@router.post("/auth/logout")
async def logout() -> JSONResponse:
    """Clear the JWT cookie and end the session."""
    resp = JSONResponse(content={"message": "Logged out."})
    resp.delete_cookie("access_token")
    return resp


@router.get("/auth/providers", response_model=list[OAuthProviderInfo])
async def list_providers() -> list[OAuthProviderInfo]:
    """Return the list of configured OAuth providers.

    Public endpoint -- the login page calls this to decide which provider
    buttons to render. Returns an empty list if no OAuth env vars are set.
    """
    return [OAuthProviderInfo(**p) for p in get_enabled_providers()]


# ---------------------------------------------------------------------------
# Authenticated endpoints
# ---------------------------------------------------------------------------


@router.get("/auth/me", response_model=MeResponse)
async def me(current_user: User = Depends(get_current_user)) -> MeResponse:
    """Return identity information for the currently authenticated user."""
    return MeResponse(
        user_id=current_user.id,
        username=current_user.username,
        role=current_user.role,
        oauth_provider=current_user.oauth_provider,
    )


# ---------------------------------------------------------------------------
# API key management (authenticated)
# ---------------------------------------------------------------------------


@router.post("/auth/api-keys", response_model=ApiKeyCreatedResponse, status_code=201)
async def create_api_key(
    request: Request,
    body: ApiKeyCreate,
    current_user: User = Depends(get_current_user),
) -> ApiKeyCreatedResponse:
    """Generate a new API key. The raw key is shown ONCE and never stored.

    [H3] Enforces a cap of 10 active keys per user. This prevents abuse
    (e.g. a compromised account creating unlimited keys) and makes it
    practical to audit keys during incident response.
    """
    user_store: UserStore = request.app.state.user_store

    existing = user_store.get_api_keys(current_user.id)
    if len(existing) >= 10:  # [H3]
        raise HTTPException(
            status_code=400,
            detail={
                "code": "key_limit_reached",
                "message": "Maximum of 10 API keys per user. Revoke an existing key first.",
            },
        )

    raw_key = generate_api_key()
    key_hash = hash_api_key(raw_key)
    key_prefix = raw_key[:12]

    api_key = ApiKey(
        user_id=current_user.id,
        name=body.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
    )
    key_id = user_store.create_api_key(api_key)

    return ApiKeyCreatedResponse(
        id=key_id,
        name=body.name,
        key_prefix=key_prefix,
        created_at="",  # store sets this; fetch fresh record for accurate value
        last_used=None,
        key=raw_key,
    )


@router.get("/auth/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(
    request: Request,
    current_user: User = Depends(get_current_user),
) -> list[ApiKeyResponse]:
    """List all active API keys for the current user. Raw key values are never returned."""
    user_store: UserStore = request.app.state.user_store
    keys = user_store.get_api_keys(current_user.id)
    return [
        ApiKeyResponse(
            id=k.id,
            name=k.name,
            key_prefix=k.key_prefix,
            created_at=k.created_at or "",
            last_used=k.last_used,
        )
        for k in keys
    ]


@router.delete("/auth/api-keys/{key_id}", status_code=204)
async def revoke_api_key(
    request: Request,
    key_id: int,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Revoke an API key. Ownership is verified server-side [IDOR guard].

    Passes both key_id and current_user.id to the store. The store's WHERE
    clause requires both to match, so an analyst cannot revoke another user's
    key even if they know its ID.
    """
    user_store: UserStore = request.app.state.user_store
    revoked = user_store.revoke_api_key(key_id, current_user.id)
    if not revoked:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": "API key not found."},
        )
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------


@router.post("/auth/users", response_model=UserResponse, status_code=201)
async def create_user(
    request: Request,
    body: UserCreate,
    current_user: User = Depends(require_admin),
) -> UserResponse:
    """Create a new user account. Admin only.

    Admins pre-create accounts before users log in. For OAuth users, set
    username to the user's provider email. For local users, a password is
    required.
    """
    from sqlalchemy.exc import IntegrityError

    user_store: UserStore = request.app.state.user_store

    hashed_pw: str | None = None
    if body.password:
        hashed_pw = hash_password(body.password)

    new_user = User(
        username=body.username,
        role=body.role,
        hashed_password=hashed_pw,
    )
    try:
        user_id = user_store.create_user(new_user)
    except IntegrityError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "conflict", "message": "A user with that username already exists."},
        ) from exc

    created = user_store.get_by_id(user_id)
    return _user_to_response(created)


@router.get("/auth/users", response_model=list[UserResponse])
async def list_users(
    request: Request,
    current_user: User = Depends(require_admin),
) -> list[UserResponse]:
    """List all user accounts. Admin only."""
    user_store: UserStore = request.app.state.user_store
    users = user_store.list_users()
    return [_user_to_response(u) for u in users]


@router.patch("/auth/users/{user_id}", response_model=UserResponse)
async def update_user(
    request: Request,
    user_id: int,
    body: UserPatch,
    current_user: User = Depends(require_admin),
) -> UserResponse:
    """Update a user's role or active status. Admin only.

    [M4] Prevents:
      - Self-deactivation (admin accidentally locking themselves out).
      - Deactivating the last active admin (no recovery path without DB access).
    """
    user_store: UserStore = request.app.state.user_store

    target = user_store.get_by_id(user_id)
    if target is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "not_found", "message": "User not found."},
        )

    updates: dict = {}
    if body.role is not None:
        updates["role"] = body.role
    if body.is_active is not None:
        # [M4] Block self-deactivation
        if not body.is_active and target.id == current_user.id:
            raise HTTPException(
                status_code=400,
                detail={"code": "self_deactivation", "message": "You cannot deactivate your own account."},
            )
        # [M4] Block deactivating the last admin
        if not body.is_active and target.role == "admin":
            if user_store.count_active_admins() <= 1:
                raise HTTPException(
                    status_code=400,
                    detail={"code": "last_admin", "message": "Cannot deactivate the last active admin account."},
                )
        updates["is_active"] = body.is_active

    if not updates:
        raise HTTPException(
            status_code=400,
            detail={"code": "no_changes", "message": "No fields to update."},
        )

    user_store.update_user(user_id, **updates)
    updated = user_store.get_by_id(user_id)
    return _user_to_response(updated)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user_to_response(user: User | None) -> UserResponse:
    if user is None:
        raise HTTPException(
            status_code=500,
            detail={"code": "internal_error", "message": "User not found after write."},
        )
    return UserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        oauth_provider=user.oauth_provider,
        is_active=user.is_active,
        created_at=user.created_at or "",
    )
