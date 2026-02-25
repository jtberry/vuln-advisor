"""
auth/store.py -- SQLAlchemy Core persistence layer for auth entities.

Pattern: Repository + Data Mapper (same as cmdb/store.py).
UserStore is the repository; _row_to_user / _row_to_api_key are the mappers.
Route and dependency code never touches SQL directly.

Security:
  All queries use bound parameters. No f-strings in SQL.

  UNIQUE(oauth_provider, oauth_subject) is enforced in code rather than SQL
  because SQLite treats two NULL values as distinct in UNIQUE constraints,
  which would allow duplicate unlinked records. The code-level check in
  link_oauth() handles this correctly.

DB path: auth/vulnadvisor_auth.db (sibling to cmdb/vulnadvisor_cmdb.db).

Layer rule: no imports from api/, web/, core/, cmdb/, or cache/.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import Column, Integer, MetaData, String, Table, Text, create_engine, text
from sqlalchemy.engine import Engine

from auth.models import ApiKey, User

_DEFAULT_DB_URL = f"sqlite:///{Path(__file__).parent / 'vulnadvisor_auth.db'}"

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_metadata = MetaData()

_users = Table(
    "users",
    _metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(255), nullable=False, unique=True),
    Column("hashed_password", Text),  # NULL for OAuth-only users
    Column("role", String(30), nullable=False, server_default="analyst"),
    Column("oauth_provider", String(30)),  # "github", "google", "oidc"
    Column("oauth_subject", Text),  # provider's stable user ID
    Column("user_preferences", Text),  # JSON blob (Phase 3)
    Column("created_at", String(32), nullable=False),
    Column("is_active", Integer, nullable=False, server_default="1"),
    # Note: UNIQUE(oauth_provider, oauth_subject) enforced in code, not SQL.
    # SQLite treats two NULLs as distinct in UNIQUE constraints, which would
    # allow duplicate unlinked records for users who haven't yet done OAuth.
)

_api_keys = Table(
    "api_keys",
    _metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, nullable=False),
    Column("name", String(100), nullable=False),
    Column("key_hash", String(64), nullable=False, unique=True),  # HMAC-SHA256 hex
    Column("key_prefix", String(12), nullable=False),  # first 12 chars, display only
    Column("created_at", String(32), nullable=False),
    Column("last_used", String(32)),
    Column("is_active", Integer, nullable=False, server_default="1"),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------


class UserStore:
    """Repository for User and ApiKey entities.

    Usage:
        store = UserStore()
        store.create_user(User(username="admin", role="admin", hashed_password=hash_password("secret")))
        user = store.get_by_username("admin")
        store.close()
    """

    def __init__(self, db_url: str = _DEFAULT_DB_URL) -> None:
        connect_args: dict = {}
        if db_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        self.engine: Engine = create_engine(db_url, connect_args=connect_args)
        _metadata.create_all(self.engine)

    # ------------------------------------------------------------------
    # User queries
    # ------------------------------------------------------------------

    def has_users(self) -> bool:
        """Return True if at least one user record exists.

        Used by the setup redirect middleware and POST /setup to detect
        first-run state. Must be cheap -- uses COUNT(*) with early exit.
        """
        with self.engine.connect() as conn:
            result = conn.execute(text("SELECT COUNT(*) FROM users")).scalar()
        return (result or 0) > 0

    def create_user(self, user: User) -> int:
        """Insert a new user and return its assigned database ID.

        Raises sqlalchemy.exc.IntegrityError if the username already exists.
        Callers (e.g. POST /setup) should catch IntegrityError as a signal
        that a concurrent request already created the record [M1].
        """
        with self.engine.connect() as conn:
            result = conn.execute(
                _users.insert().values(
                    username=user.username,
                    hashed_password=user.hashed_password,
                    role=user.role,
                    oauth_provider=user.oauth_provider,
                    oauth_subject=user.oauth_subject,
                    user_preferences=user.user_preferences,
                    created_at=_now_iso(),
                    is_active=1 if user.is_active else 0,
                )
            )
            conn.commit()
            return result.inserted_primary_key[0]

    def get_by_username(self, username: str) -> User | None:
        """Look up a user by exact username (case-sensitive). Returns None if not found."""
        with self.engine.connect() as conn:
            row = conn.execute(_users.select().where(_users.c.username == username)).fetchone()
        return _row_to_user(row) if row is not None else None

    def get_by_id(self, user_id: int) -> User | None:
        """Look up a user by primary key. Returns None if not found."""
        with self.engine.connect() as conn:
            row = conn.execute(_users.select().where(_users.c.id == user_id)).fetchone()
        return _row_to_user(row) if row is not None else None

    def get_by_oauth(self, provider: str, subject: str) -> User | None:
        """Look up a user by (oauth_provider, oauth_subject) pair.

        Returns None if no linked record exists. The OAuth callback uses this
        after the first successful login links an identity; subsequent logins
        find the user instantly via this method.
        """
        with self.engine.connect() as conn:
            row = conn.execute(
                _users.select().where((_users.c.oauth_provider == provider) & (_users.c.oauth_subject == subject))
            ).fetchone()
        return _row_to_user(row) if row is not None else None

    def link_oauth(self, user_id: int, provider: str, subject: str) -> None:
        """Associate an OAuth identity with an existing user record.

        Called on first OAuth login when a pre-created user (matched by email)
        has not yet been linked to a provider. Subsequent logins use get_by_oauth().
        """
        with self.engine.connect() as conn:
            conn.execute(
                _users.update().where(_users.c.id == user_id).values(oauth_provider=provider, oauth_subject=subject)
            )
            conn.commit()

    def list_users(self) -> list[User]:
        """Return all users ordered by username. Admin-only operation."""
        with self.engine.connect() as conn:
            rows = conn.execute(_users.select().order_by(_users.c.username)).fetchall()
        return [_row_to_user(r) for r in rows]

    def update_user(self, user_id: int, **fields) -> bool:
        """Update mutable fields on an existing user.

        Accepted fields: role, is_active, user_preferences, hashed_password.
        is_active must be passed as bool; this method converts to int for SQLite.

        Returns True if a row was updated, False if user_id was not found.
        """
        if "is_active" in fields:
            fields["is_active"] = 1 if fields["is_active"] else 0
        with self.engine.connect() as conn:
            result = conn.execute(_users.update().where(_users.c.id == user_id).values(**fields))
            conn.commit()
        return result.rowcount > 0

    def count_active_admins(self) -> int:
        """Return the number of active admin users.

        Used by PATCH /users/{id} to prevent deactivating the last admin [M4].
        """
        with self.engine.connect() as conn:
            result = conn.execute(text("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1")).scalar()
        return result or 0

    # ------------------------------------------------------------------
    # API key queries
    # ------------------------------------------------------------------

    def get_api_keys(self, user_id: int) -> list[ApiKey]:
        """Return all active API keys for a user (newest first)."""
        with self.engine.connect() as conn:
            rows = conn.execute(
                _api_keys.select()
                .where((_api_keys.c.user_id == user_id) & (_api_keys.c.is_active == 1))
                .order_by(_api_keys.c.created_at.desc())
            ).fetchall()
        return [_row_to_api_key(r) for r in rows]

    def create_api_key(self, api_key: ApiKey) -> int:
        """Insert a new API key record and return its ID."""
        with self.engine.connect() as conn:
            result = conn.execute(
                _api_keys.insert().values(
                    user_id=api_key.user_id,
                    name=api_key.name,
                    key_hash=api_key.key_hash,
                    key_prefix=api_key.key_prefix,
                    created_at=_now_iso(),
                    is_active=1,
                )
            )
            conn.commit()
            return result.inserted_primary_key[0]

    def get_api_key_by_hash(self, key_hash: str) -> ApiKey | None:
        """Look up an active API key by its HMAC hash. O(1) via UNIQUE index."""
        with self.engine.connect() as conn:
            row = conn.execute(
                _api_keys.select().where((_api_keys.c.key_hash == key_hash) & (_api_keys.c.is_active == 1))
            ).fetchone()
        return _row_to_api_key(row) if row is not None else None

    def update_api_key_last_used(self, key_id: int) -> None:
        """Stamp last_used on a key after each successful API authentication."""
        with self.engine.connect() as conn:
            conn.execute(_api_keys.update().where(_api_keys.c.id == key_id).values(last_used=_now_iso()))
            conn.commit()

    def revoke_api_key(self, key_id: int, user_id: int) -> bool:
        """Deactivate a key. user_id is checked to prevent IDOR attacks.

        An analyst cannot revoke another user's key even if they know the key
        ID. Both conditions must match for the update to succeed.

        Returns True if a key was revoked, False if not found or wrong owner.
        """
        with self.engine.connect() as conn:
            result = conn.execute(
                _api_keys.update()
                .where((_api_keys.c.id == key_id) & (_api_keys.c.user_id == user_id))
                .values(is_active=0)
            )
            conn.commit()
        return result.rowcount > 0

    def close(self) -> None:
        self.engine.dispose()


# ---------------------------------------------------------------------------
# Row mappers (Data Mapper pattern)
# ---------------------------------------------------------------------------


def _row_to_user(row) -> User:
    return User(
        id=row.id,
        username=row.username,
        hashed_password=row.hashed_password,
        role=row.role,
        oauth_provider=row.oauth_provider,
        oauth_subject=row.oauth_subject,
        user_preferences=row.user_preferences,
        created_at=row.created_at,
        is_active=bool(row.is_active),
    )


def _row_to_api_key(row) -> ApiKey:
    return ApiKey(
        id=row.id,
        user_id=row.user_id,
        name=row.name,
        key_hash=row.key_hash,
        key_prefix=row.key_prefix,
        created_at=row.created_at,
        last_used=row.last_used,
        is_active=bool(row.is_active),
    )
