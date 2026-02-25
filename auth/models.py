"""
auth/models.py -- Domain dataclasses for authentication entities.

Pattern: Data class (pure data container, zero logic). Mirrors the approach
in core/models.py and cmdb/models.py -- dataclasses own domain shape; stores
and routes do the work.

Layer rule: no imports from api/, web/, core/, cmdb/, or cache/.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class User:
    """Represents an authenticated identity in VulnAdvisor.

    username doubles as the email address for OAuth users -- the pre-created
    record uses the provider email as username so the OAuth callback can match
    by get_by_username(email) before the oauth_subject is linked.

    hashed_password is None for OAuth-only users (they have no local password).
    oauth_provider / oauth_subject are None until the user logs in via OAuth for
    the first time, at which point link_oauth() fills them in.

    user_preferences is a JSON blob reserved for Phase 3 dashboard customization.
    """

    username: str
    role: str  # "admin", "analyst", "viewer"
    id: int | None = None
    hashed_password: str | None = None  # None = OAuth-only user
    oauth_provider: str | None = None  # "github", "google", "oidc"
    oauth_subject: str | None = None  # provider's stable user ID
    user_preferences: str | None = None  # JSON blob (Phase 3 dashboard config)
    created_at: str | None = None
    is_active: bool = True


@dataclass
class ApiKey:
    """A long-lived credential for non-browser API clients (CI/CD, scripts).

    Security design:
    - key_hash is HMAC-SHA256(SECRET_KEY, raw_key). Deterministic hash lets the
      store do an O(1) lookup without bcrypt's intentional slowness.  Long random
      keys (256-bit entropy) make brute-force attacks infeasible -- the strength
      requirement bcrypt satisfies for low-entropy passwords is unnecessary here.
    - key_prefix (first 12 chars of the raw key) is stored for display purposes
      only. Users can identify which key is which without exposing the full value.
    - The raw key is never persisted. It is returned ONCE at creation and then
      unrecoverable. Users must rotate if lost.
    """

    user_id: int
    name: str
    key_hash: str  # HMAC-SHA256 of the raw key
    key_prefix: str  # first 12 chars of raw key, display only
    id: int | None = None
    created_at: str | None = None
    last_used: str | None = None
    is_active: bool = True
