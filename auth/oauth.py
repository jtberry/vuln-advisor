"""
auth/oauth.py -- Authlib OAuth/OIDC provider configuration.

Reads environment variables at module load to decide which providers are
active. Only providers with both client ID and secret configured get
registered -- the login template renders buttons dynamically based on
get_enabled_providers().

Security notes:
  [H1] Email verification is mandatory. get_oauth_user_info() raises ValueError
       if the provider does not confirm the email is verified. An unverified
       email from GitHub could belong to an attacker who added a victim's
       address without confirming it.

  OAuth state parameter (CSRF protection) is handled by authlib automatically
  via Starlette SessionMiddleware. The session stores the state between the
  authorization redirect and the callback -- never trust state from query params
  alone.

Supported providers:
  github -- Authorization code flow; static endpoints.
  google -- Authorization code flow; OIDC discovery.
  oidc   -- Generic OIDC discovery (Okta, Azure AD, Keycloak, Authentik, etc.)

Layer rule: no imports from api/, web/, core/, cmdb/, or cache/.
"""

from __future__ import annotations

import logging
import os

from authlib.integrations.starlette_client import OAuth

logger = logging.getLogger("vulnadvisor.auth.oauth")

# ---------------------------------------------------------------------------
# Authlib OAuth registry
# ---------------------------------------------------------------------------

oauth = OAuth()

# GitHub -- static endpoints (no OIDC discovery document)
_GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
_GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
if _GITHUB_CLIENT_ID and _GITHUB_CLIENT_SECRET:
    oauth.register(
        name="github",
        client_id=_GITHUB_CLIENT_ID,
        client_secret=_GITHUB_CLIENT_SECRET,
        access_token_url="https://github.com/login/oauth/access_token",  # noqa: S106 -- URL, not a password
        authorize_url="https://github.com/login/oauth/authorize",
        api_base_url="https://api.github.com/",
        client_kwargs={"scope": "read:user user:email"},
    )
    logger.info("GitHub OAuth provider registered")

# Google -- OIDC discovery
_GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
_GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
if _GOOGLE_CLIENT_ID and _GOOGLE_CLIENT_SECRET:
    oauth.register(
        name="google",
        client_id=_GOOGLE_CLIENT_ID,
        client_secret=_GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
    logger.info("Google OAuth provider registered")

# Generic OIDC -- Okta, Azure AD, Keycloak, Authentik, etc.
_OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
_OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
_OIDC_DISCOVERY_URL = os.environ.get("OIDC_DISCOVERY_URL", "")
_OIDC_DISPLAY_NAME = os.environ.get("OIDC_DISPLAY_NAME", "SSO")
if _OIDC_CLIENT_ID and _OIDC_CLIENT_SECRET and _OIDC_DISCOVERY_URL:
    oauth.register(
        name="oidc",
        client_id=_OIDC_CLIENT_ID,
        client_secret=_OIDC_CLIENT_SECRET,
        server_metadata_url=_OIDC_DISCOVERY_URL,
        client_kwargs={"scope": "openid email profile"},
    )
    logger.info("Generic OIDC provider registered (display name: %s)", _OIDC_DISPLAY_NAME)


# ---------------------------------------------------------------------------
# Provider metadata
# ---------------------------------------------------------------------------


def get_enabled_providers() -> list[dict]:
    """Return metadata for every configured OAuth provider.

    Used by GET /api/v1/auth/providers and the login template to render
    provider buttons dynamically. Only providers with both env vars set are
    included.

    Returns list of {"name": str, "label": str} dicts.
    """
    providers: list[dict] = []
    if _GITHUB_CLIENT_ID and _GITHUB_CLIENT_SECRET:
        providers.append({"name": "github", "label": "GitHub"})
    if _GOOGLE_CLIENT_ID and _GOOGLE_CLIENT_SECRET:
        providers.append({"name": "google", "label": "Google"})
    if _OIDC_CLIENT_ID and _OIDC_CLIENT_SECRET and _OIDC_DISCOVERY_URL:
        providers.append({"name": "oidc", "label": _OIDC_DISPLAY_NAME})
    return providers


# ---------------------------------------------------------------------------
# Email / subject extraction -- provider-specific normalization [H1]
# ---------------------------------------------------------------------------


async def get_oauth_user_info(client, provider: str, token: dict) -> tuple[str, str]:
    """Extract (email, subject_id) from a provider token response.

    Normalizes the provider-specific response formats into a common interface.

    [H1] SECURITY: Email verification is checked before returning. An unverified
    email could be a victim's address added by an attacker. If the provider does
    not confirm verification, or returns no primary verified email, raises
    ValueError -- the caller must treat this as an authentication failure and
    redirect to /login?error=oauth_failed.

    Args:
        client:   The authlib OAuth client for this provider.
        provider: "github", "google", or "oidc".
        token:    The token dict returned by authlib after code exchange.

    Returns:
        (email, subject_id) -- both are stable identifiers for this user.

    Raises:
        ValueError: If a verified email cannot be confirmed.
    """
    if provider == "github":
        return await _get_github_user_info(client, token)
    elif provider in ("google", "oidc"):
        return _get_oidc_user_info(token, provider)
    else:
        raise ValueError(f"Unknown OAuth provider: {provider!r}")


async def _get_github_user_info(client, token: dict) -> tuple[str, str]:
    """Extract (email, subject_id) from a GitHub token.

    GitHub does not include the email in the access token. Two API calls are
    required:
      1. GET /user -- to get the numeric user ID (stable subject).
      2. GET /user/emails -- to find the primary verified email.

    [H1] Only the email where both primary=true AND verified=true is accepted.
    If no such entry exists, raises ValueError.
    """
    # Fetch the user profile for the numeric ID
    resp = await client.get("user", token=token)
    resp.raise_for_status()
    profile = resp.json()
    subject_id = str(profile["id"])

    # Fetch emails and find primary verified one
    emails_resp = await client.get("user/emails", token=token)
    emails_resp.raise_for_status()
    emails = emails_resp.json()

    email: str | None = None
    for entry in emails:
        if entry.get("primary") and entry.get("verified"):
            email = entry["email"]
            break

    if not email:
        raise ValueError(
            "GitHub OAuth: no primary verified email found. "
            "The user must verify their email address on GitHub before logging in."
        )

    return email, subject_id


def _get_oidc_user_info(token: dict, provider: str) -> tuple[str, str]:
    """Extract (email, subject_id) from a Google/OIDC id_token.

    Both Google and generic OIDC providers return an id_token whose claims
    include email, email_verified, and sub (subject ID).

    [H1] The email claim is only accepted when email_verified is True.
    Some OIDC providers omit email_verified entirely -- we treat that as
    unverified and raise ValueError.
    """
    userinfo = token.get("userinfo")
    if not userinfo:
        raise ValueError(f"{provider} OAuth: no userinfo in token response")

    if not userinfo.get("email_verified", False):
        raise ValueError(
            f"{provider} OAuth: email is not verified. "
            "The provider must confirm email ownership before login is allowed."
        )

    email = userinfo.get("email")
    subject_id = userinfo.get("sub")

    if not email or not subject_id:
        raise ValueError(f"{provider} OAuth: missing email or sub claim in userinfo")

    return email, subject_id
