"""
core/config.py -- Centralized application configuration via pydantic-settings.

All environment variable reads for VulnAdvisor happen here. No module should
call os.getenv() or os.environ.get() directly -- import get_settings() instead.

Design patterns used:
  Singleton via lru_cache: get_settings() instantiates Settings once at first
      call and returns the cached instance on every subsequent call. This is
      the official FastAPI dependency injection pattern for config.

  BaseSettings (pydantic-settings): Reads values from environment variables
      and an optional .env file automatically. Field names map to env var names
      (e.g. secret_key -> SECRET_KEY). Type coercion and validation are built in.

  @model_validator(mode="after"): Runs cross-field validation after all fields
      are resolved from environment. Used to implement the DEBUG-conditional
      SECRET_KEY logic per user decision: dev mode generates a key with warning,
      production mode refuses to start without one.

Security notes:
  [M6] SECRET_KEY shorter than 32 chars is rejected outright. HMAC-SHA256 and
       JWT signing both rely on key entropy -- a short key weakens both.

  [M7] In production mode (DEBUG not set or false), a missing SECRET_KEY is a
       hard startup failure. This prevents accidentally running with a random
       key in production (where session persistence is required).

Layer rule: core/ is the kernel. This module may not import from api/, web/,
auth/, cmdb/, or cache/.
"""

import logging
import secrets
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger("vulnadvisor.config")


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file.

    All fields have defaults so Settings() can be instantiated in test
    environments without a real .env file. The model_validator enforces
    production-safety rules at startup.

    Environment variable name mapping: field names are uppercased automatically.
    E.g. `secret_key` reads from SECRET_KEY, `debug` reads from DEBUG.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Core
    # ------------------------------------------------------------------

    debug: bool = False
    # Empty string is the sentinel for "not configured". The model_validator
    # below either generates a dev key or raises, so callers never see "".
    secret_key: str = ""

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    secure_cookies: bool = False
    # Default 1 hour -- aligned with user decision (most secure default).
    # Individual users can override this preference; it is stored per-user
    # in the DB and passed to create_access_token() at issue time.
    token_expire_seconds: int = 3600

    # ------------------------------------------------------------------
    # OAuth providers (optional -- empty string means provider is disabled)
    # ------------------------------------------------------------------

    github_client_id: str = ""
    github_client_secret: str = ""
    google_client_id: str = ""
    google_client_secret: str = ""

    # Generic OIDC (Okta, Azure AD, Keycloak, Authentik, etc.)
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_discovery_url: str = ""
    oidc_display_name: str = "SSO"

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    login_rate_limit: str = "10/minute"

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    self_registration_enabled: bool = True

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def validate_secret_key(self) -> "Settings":
        """Enforce SECRET_KEY policy per user decision [M7].

        Dev mode (DEBUG=true): auto-generate a random key with a warning.
            Sessions will not survive restart -- acceptable for local dev.

        Production mode (DEBUG=false or not set): refuse to start if
            SECRET_KEY is missing. A missing key in production means sessions
            would be invalidated on every restart, which breaks auth silently.

        Both modes: reject keys shorter than 32 characters. Short keys have
            insufficient entropy for HMAC-SHA256 and JWT signing [M6].
        """
        if not self.secret_key:
            if self.debug:
                self.secret_key = secrets.token_hex(32)
                logger.warning(
                    "WARNING: Using auto-generated SECRET_KEY. " "Sessions will not persist across restarts."
                )
            else:
                raise ValueError(
                    "SECRET_KEY is required in production mode. "
                    "Set SECRET_KEY in your environment or .env file. "
                    "To run in development mode, set DEBUG=true."
                )
        if len(self.secret_key) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters.")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the application Settings singleton.

    Uses lru_cache so Settings() is instantiated exactly once -- at first call.
    This is the official FastAPI pattern for config (see FastAPI docs /advanced/settings/).
    All modules should call get_settings() rather than constructing Settings() directly.

    In tests: call get_settings.cache_clear() between test cases if you need
    to inject different environment variables.
    """
    return Settings()
