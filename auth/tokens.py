"""
auth/tokens.py -- JWT, password hashing, and API key utilities.

Security design decisions:
  JWT: python-jose with HS256. Tokens are signed with SECRET_KEY and carry
       user_id, username, role, and expiry. Verification returns None on any
       failure -- route layer turns that into a 401.

  Passwords: passlib bcrypt via CryptContext. Bcrypt is the right choice for
       low-entropy secrets (passwords) because its cost factor makes brute-force
       expensive. The _DUMMY_HASH constant enables timing equalization in
       authenticate_user() so response time does not reveal whether a username
       exists [C1].

  API keys: secrets.token_hex(32) gives 256 bits of entropy -- brute-force is
       computationally infeasible. We store HMAC-SHA256(SECRET_KEY, raw_key) so
       lookup is O(1). bcrypt's intentional slowness is unnecessary here.

  SECRET_KEY: sourced from core.config.get_settings(). The Settings class
       validates the key at startup: dev mode (DEBUG=true) auto-generates a
       random key with a warning; production mode refuses to start without one.
       Short keys (<32 chars) are rejected with ValueError [M6].

Layer rule: no imports from api/, web/, cmdb/, or cache/. Import from core/
is allowed -- core/ is the kernel and has no reverse dependencies.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import bcrypt
from jose import JWTError, jwt

from core.config import get_settings

if TYPE_CHECKING:
    from auth.models import User
    from auth.store import UserStore

logger = logging.getLogger("vulnadvisor.auth")

# ---------------------------------------------------------------------------
# Config -- read once at module load via the lru_cache singleton [M6]
# ---------------------------------------------------------------------------

_settings = get_settings()

_ALGORITHM = "HS256"

# ---------------------------------------------------------------------------
# Password hashing (bcrypt -- direct usage, no passlib wrapper)
#
# Using bcrypt directly rather than passlib[bcrypt] because passlib's internal
# wrap-bug detection creates a password longer than 72 bytes, which bcrypt 4.x
# rejects with an explicit error. Direct bcrypt usage is simpler, has no
# compatibility shim, and is actively maintained.
# ---------------------------------------------------------------------------


def hash_password(plain: str) -> str:
    """Return a bcrypt hash of the given plaintext password.

    Passwords longer than 72 bytes are silently truncated by bcrypt (this is
    a known bcrypt limitation). We enforce a max_length=255 at the API layer
    (Pydantic field), which keeps inputs well below the truncation threshold.
    """
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if the plaintext password matches the bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# Timing equalization dummy hash [C1].
# Computed once at module load so the first login attempt is not measurably
# slower than subsequent ones. Always call verify_password() even when the
# username does not exist -- bcrypt's constant work factor equalizes timing
# and prevents username enumeration via response-time differences.
_DUMMY_HASH: str = hash_password("vulnadvisor_timing_dummy")


# ---------------------------------------------------------------------------
# JWT encode / decode
# ---------------------------------------------------------------------------


def create_access_token(user_id: int, username: str, role: str, expire_seconds: int = 0) -> str:
    """Encode a signed JWT with user identity and configurable expiry.

    Args:
        user_id:        Numeric user ID stored in the DB.
        username:       Username stored as the JWT subject claim.
        role:           User role ("admin" or "user").
        expire_seconds: Session duration in seconds. If 0 (default), uses
                        the value from Settings.token_expire_seconds. Pass
                        the user's stored preference here to honour per-user
                        session duration (1h/4h/8h).
    """
    duration = expire_seconds if expire_seconds > 0 else _settings.token_expire_seconds
    expire = datetime.now(timezone.utc) + timedelta(seconds=duration)
    payload = {
        "sub": username,
        "user_id": user_id,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, _settings.secret_key, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    """Decode and verify a JWT. Returns the payload dict or None on any failure.

    Returning None (rather than raising) keeps the caller simple: any invalid
    token is treated as unauthenticated. Route handlers turn None into 401.
    """
    try:
        payload = jwt.decode(token, _settings.secret_key, algorithms=[_ALGORITHM])
        if "user_id" not in payload or "role" not in payload:
            return None
        return payload
    except JWTError:
        return None


# ---------------------------------------------------------------------------
# User authentication (constant-time) [C1]
# ---------------------------------------------------------------------------


def authenticate_user(store: UserStore, username: str, password: str) -> User | None:
    """Authenticate a local username/password login with timing equalization.

    Always runs bcrypt whether or not the user exists. This prevents an attacker
    from enumerating valid usernames by measuring response time differences:
    - Unknown username: bcrypt runs against _DUMMY_HASH (same cost as real check)
    - Wrong password: bcrypt runs against the real hash (same cost)

    Returns the User on success, None on any failure.
    """
    user = store.get_by_username(username)
    if user is None or user.hashed_password is None:
        # Equalize timing -- do NOT return early before running bcrypt [C1]
        verify_password(password, _DUMMY_HASH)
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    return user


# ---------------------------------------------------------------------------
# API key generation and hashing
# ---------------------------------------------------------------------------


def generate_api_key() -> str:
    """Generate a new API key in the format: va_<64 hex chars>.

    secrets.token_hex(32) produces 32 random bytes as 64 hex characters,
    giving 256 bits of entropy. Brute-force is computationally infeasible.
    """
    return f"va_{secrets.token_hex(32)}"


def hash_api_key(raw_key: str) -> str:
    """Return HMAC-SHA256(SECRET_KEY, raw_key) as a hex string.

    Using SECRET_KEY as the HMAC key means an attacker who obtains the DB
    cannot reverse-engineer keys without also knowing SECRET_KEY. The hash
    is deterministic, enabling O(1) lookup by hash rather than scanning all
    active keys.
    """
    return hmac.new(
        _settings.secret_key.encode(),
        raw_key.encode(),
        hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------------
# Cookie helper
# ---------------------------------------------------------------------------


def set_auth_cookie(response, token: str, expire_seconds: int = 0) -> None:
    """Write the JWT access token as an httpOnly cookie on the response.

    httponly=True: JS cannot read the cookie (XSS mitigation).
    samesite="lax": cookie sent on same-site navigations and GET cross-site
        links, but not on cross-site POST -- CSRF mitigation for most cases.
    secure: only sent over HTTPS when SECURE_COOKIES=true (set in production).
    max_age: matches the JWT expiry so both expire together.

    Args:
        response:       FastAPI/Starlette response object.
        token:          Encoded JWT string.
        expire_seconds: Cookie max_age in seconds. If 0 (default), uses
                        Settings.token_expire_seconds. Pass the same value
                        used in create_access_token() to keep cookie and
                        token expiry in sync.
    """
    duration = expire_seconds if expire_seconds > 0 else _settings.token_expire_seconds
    response.set_cookie(
        "access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=_settings.secure_cookies,
        max_age=duration,
    )
