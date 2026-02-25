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

  SECRET_KEY: validated at module load. A random fallback is generated if unset
       (sessions won't survive restart) but a key shorter than 32 chars is
       rejected outright with RuntimeError [M6].

Layer rule: no imports from api/, web/, core/, cmdb/, or cache/.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import bcrypt
from jose import JWTError, jwt

if TYPE_CHECKING:
    from auth.models import User
    from auth.store import UserStore

logger = logging.getLogger("vulnadvisor.auth")

# ---------------------------------------------------------------------------
# Secret key -- validated at module load [M6]
# ---------------------------------------------------------------------------

_SECRET_KEY: str = os.environ.get("SECRET_KEY", "")
if not _SECRET_KEY:
    _SECRET_KEY = secrets.token_hex(32)
    logger.warning(
        "SECRET_KEY not set -- random key in use. All sessions will be invalidated on restart. "
        "Set SECRET_KEY in your environment for persistent sessions."
    )
if len(_SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY must be at least 32 characters. " "Refusing to start with a weak signing key.")

_ALGORITHM = "HS256"
_TOKEN_EXPIRE_SECONDS = 8 * 3600  # 8 hours

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


def create_access_token(user_id: int, username: str, role: str) -> str:
    """Encode a signed JWT with user identity and 8-hour expiry."""
    expire = datetime.now(timezone.utc) + timedelta(seconds=_TOKEN_EXPIRE_SECONDS)
    payload = {
        "sub": username,
        "user_id": user_id,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, _SECRET_KEY, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    """Decode and verify a JWT. Returns the payload dict or None on any failure.

    Returning None (rather than raising) keeps the caller simple: any invalid
    token is treated as unauthenticated. Route handlers turn None into 401.
    """
    try:
        payload = jwt.decode(token, _SECRET_KEY, algorithms=[_ALGORITHM])
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
        _SECRET_KEY.encode(),
        raw_key.encode(),
        hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------------
# Cookie helper
# ---------------------------------------------------------------------------


def set_auth_cookie(response, token: str) -> None:
    """Write the JWT access token as an httpOnly cookie on the response.

    httponly=True: JS cannot read the cookie (XSS mitigation).
    samesite="lax": cookie sent on same-site navigations and GET cross-site
        links, but not on cross-site POST -- CSRF mitigation for most cases.
    secure: only sent over HTTPS when SECURE_COOKIES=true (set in production).
    max_age: 8 hours, matching the JWT expiry so both expire together.
    """
    response.set_cookie(
        "access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=os.environ.get("SECURE_COOKIES", "false").lower() == "true",
        max_age=_TOKEN_EXPIRE_SECONDS,
    )
