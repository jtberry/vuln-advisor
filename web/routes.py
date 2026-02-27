"""
web/routes.py -- Jinja2 template routes for the VulnAdvisor web UI.

These routes serve server-rendered HTML. They share app.state with the API
routes (same CMDB store, cache, KEV set) but return HTML instead of JSON.

Route registration order matters. FastAPI resolves same-level paths in order:
  - GET /cve and POST /cve/lookup and POST /cve/bulk must be registered
    before GET /cve/{cve_id} or FastAPI captures "lookup"/"bulk" as path params.
  - GET /assets/new, POST /assets, and GET /assets must be registered before
    GET /assets/{asset_id} or FastAPI captures "new"/bare-path as path params.
  - GET /login/oauth/{provider} and GET /login/callback/{provider} must be
    registered before GET /login or FastAPI may misroute them.

Routes:
  GET  /                                              -- risk dashboard (auth required)
  GET  /dashboard                                     -- 301 redirect to / (bookmarks / nav compat)
  GET  /cve                                           -- CVE research page
  POST /cve/lookup                                    -- HTMX: single CVE card
  POST /cve/bulk                                      -- HTMX: bulk results table
  GET  /cve/{cve_id}                                  -- full CVE detail
  GET  /assets/new                                    -- asset creation form (auth required)
  POST /assets                                        -- handle creation, redirect to /assets/{id}
  GET  /assets                                        -- asset list (auth required)
  GET  /assets/{asset_id}                             -- asset detail (auth required)
  POST /assets/{asset_id}/vulnerabilities             -- HTMX: add CVEs, return updated tbody
  POST /assets/{asset_id}/vulnerabilities/{cve}/status -- HTMX: row update
  GET  /ingest                                        -- scanner file ingest form (auth required)
  POST /ingest                                        -- HTMX: file upload, return result fragment
  GET  /login/oauth/{provider}                        -- OAuth redirect to provider
  GET  /login/callback/{provider}                     -- OAuth callback handler
  GET  /login                                         -- login form
  POST /login                                         -- handle password login
  GET  /logout                                         -- clear cookie, redirect /login (GET; see Plan 02 trade-off)
  GET  /setup                                         -- first-run wizard
  POST /setup                                         -- create first admin
  GET  /register                                      -- registration form
  POST /register                                      -- create user account (role="user")
  GET  /settings                                      -- user settings (session duration, password change)
  POST /settings                                      -- save user settings
  GET  /admin/settings                                -- admin settings (OAuth, registration, user management)
  POST /admin/settings                                -- save admin settings
"""

import json
import logging
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter, Depends, Form, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi_csrf_protect import CsrfProtect
from fastapi_csrf_protect.exceptions import CsrfProtectError  # noqa: F401 -- re-exported for api/main.py handler
from sqlalchemy.exc import IntegrityError

from auth.dependencies import try_get_current_user
from auth.oauth import get_enabled_providers, get_oauth_user_info
from auth.store import UserStore
from auth.tokens import authenticate_user, create_access_token, get_session_duration, hash_password, set_auth_cookie
from cmdb.ingest import parse_csv, parse_grype_json, parse_nessus_csv, parse_trivy_json
from cmdb.models import Asset, AssetVulnerability
from cmdb.store import CMDBStore, apply_criticality_modifier
from core.models import CVE_PATTERN
from core.pipeline import process_cve, process_cves

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Password validation
# ---------------------------------------------------------------------------


def _validate_password(password: str) -> str:
    """Return an error message if the password fails complexity rules, empty string if valid.

    Rules (all must pass):
      - At least 12 characters
      - At least one uppercase letter
      - At least one number
      - At least one special character

    Shared by both the setup wizard and the registration flow so the rules
    stay consistent in one place (single responsibility).
    """
    if len(password) < 12:
        return "Password must be at least 12 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>/?\\|`~]', password):
        return "Password must contain at least one special character."
    return ""


templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
# Expose try_get_current_user as a Jinja2 global so layout.html can call it
# without requiring every route handler to manually include current_user in the
# template context. The function receives the request object from the template
# context (always present) and returns the User or None.
templates.env.globals["try_get_current_user"] = try_get_current_user
# Expose get_enabled_providers as a Jinja2 global so layout.html (and the
# session-expiry modal partial it includes) can render OAuth buttons without
# requiring every route handler to pass providers in the context dict.
# get_enabled_providers() reads only from Settings (no request context needed).
templates.env.globals["get_enabled_providers"] = get_enabled_providers
router = APIRouter()

# ---------------------------------------------------------------------------
# CSRF protection
#
# fastapi-csrf-protect uses the Double Submit Cookie pattern:
#   1. GET route generates two tokens: a signed cookie token and a plain form token.
#   2. The plain token is embedded as a hidden input in the form.
#   3. POST route calls validate_csrf() which checks that the cookie and form token match.
#
# An attacker can forge a POST but cannot read or set the site's cookies
# (same-origin cookie policy), so they cannot forge a matching token pair.
#
# The import inside get_csrf_config() is intentional -- it avoids a circular import
# and ensures settings are loaded lazily at first use, not at module import time.
# (See Pitfall 2 in RESEARCH.md)
# ---------------------------------------------------------------------------


@CsrfProtect.load_config
def get_csrf_config() -> list[tuple[str, str]]:
    """Configure fastapi-csrf-protect from centralized settings.

    token_location="body" tells the library to read the CSRF token from the
    form POST body (the hidden input named "csrf_token") rather than from an
    X-CSRF-Token HTTP header. HTML forms cannot set custom headers, so header
    mode only works for AJAX/JS clients. Our forms are server-rendered HTML.

    token_key="csrf_token" matches the name="" attribute on our hidden inputs.
    """
    from core.config import get_settings

    return [
        ("secret_key", get_settings().secret_key),
        ("token_location", "body"),
        ("token_key", "csrf_token"),
    ]


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

# Whitelist mapping for ?error= query params on /login [M3].
# The raw query param is NEVER passed to templates -- only the message from
# this dict is. Prevents reflected XSS via crafted error query strings.
_ERROR_MESSAGES: dict[str, str] = {
    "bad_credentials": "Invalid username or password.",
    "not_provisioned": "Your account has not been provisioned. Contact an admin.",
    "account_disabled": "Your account has been disabled. Contact an admin.",
    "oauth_failed": "OAuth authentication failed. Please try again.",
    "setup_complete": "Setup already complete. Please log in.",
}


def _safe_next(next_url: Optional[str]) -> str:
    """Validate a post-login redirect target. Only accept relative paths. [C2]

    Prevents open redirect attacks where an attacker crafts a URL like:
      /login?next=https://attacker.com  or  /login?next=//attacker.com

    Both would redirect off-site after login. We only allow paths that:
    - Start with "/" (relative, server-local)
    - Do NOT start with "//" (protocol-relative URL, redirects off-site)
    """
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return "/"


def _get_flash(request: Request) -> str:
    """Pop flash message from session if present."""
    return request.session.pop("flash", "")


def _require_auth(request: Request) -> Optional[RedirectResponse]:
    """Check if the current request is authenticated.

    Returns a RedirectResponse to /login if not authenticated, None if OK.
    Call at the top of protected route handlers:
        if redirect := _require_auth(request):
            return redirect

    Distinguishes two unauthenticated states:
      - Session expired: session_expires_at cookie is still present (the
        access_token expired but the longer-lived companion cookie hasn't).
        Redirects to /login?expired=1 with an expiry-specific flash message
        and cleans up the stale session_expires_at cookie.
      - Never logged in: no session_expires_at cookie at all.
        Redirects to /login with the standard "please log in" message.
    """
    user = try_get_current_user(request)
    if user is None:
        path = request.url.path
        has_expired_session = request.cookies.get("session_expires_at") is not None
        if has_expired_session:
            request.session["flash"] = "Your session has expired. Please log in again."
            resp = RedirectResponse(f"/login?next={path}&expired=1", status_code=302)
            resp.delete_cookie("session_expires_at")
            return resp
        else:
            request.session["flash"] = "Please log in to access this page."
            return RedirectResponse(f"/login?next={path}", status_code=302)
    return None


_NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
_STATUSES = ["pending", "in_progress", "verified", "closed", "deferred"]
_MAX_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MB
_VALID_ENVIRONMENTS = {"production", "staging", "development"}
_VALID_EXPOSURES = {"internet", "internal", "isolated"}
_VALID_CRITICALITIES = {"critical", "high", "medium", "low"}
_VALID_SCANNERS = {"manual", "csv", "trivy", "grype", "nessus"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _deadline_info(deadline_iso: Optional[str]) -> dict:
    """Return display text and CSS class for a deadline ISO timestamp."""
    if not deadline_iso:
        return {"text": "—", "css": "text-muted"}
    now = datetime.now(timezone.utc)
    try:
        deadline = datetime.fromisoformat(deadline_iso)
    except ValueError:
        return {"text": "—", "css": "text-muted"}
    diff = deadline - now
    secs = diff.total_seconds()
    if secs < 0:
        return {"text": "OVERDUE", "css": "text-danger fw-bold"}
    hours = int(secs / 3600)
    if hours < 24:
        mins = int((secs % 3600) / 60)
        return {"text": f"{hours}h {mins}m", "css": "text-danger"}
    if diff.days <= 7:
        return {"text": f"{diff.days}d", "css": "text-warning"}
    return {"text": f"{diff.days}d", "css": "text-muted"}


def _eol_info(eol_date: Optional[str]) -> dict:
    """Return display text and CSS class for an OS end-of-life date string."""
    if not eol_date:
        return {"text": "—", "css": "text-muted", "badge": False}
    today = datetime.now(timezone.utc).date()
    try:
        d = date.fromisoformat(eol_date)
    except ValueError:
        return {"text": "—", "css": "text-muted", "badge": False}
    if d < today:
        return {"text": "EOL", "css": "text-danger fw-bold", "badge": True}
    days = (d - today).days
    if days <= 90:
        return {"text": f"EOL in {days}d", "css": "text-warning", "badge": False}
    return {"text": str(d), "css": "text-muted", "badge": False}


def _cvss_row_css(metric: str, value: str) -> str:
    """Return a CSS class for a CVSS vector component value.

    Highlights the worst-case values (highest attack surface / highest impact)
    so analysts can scan the breakdown table at a glance.
    """
    worst: dict[str, set] = {
        "attack_vector": {"NETWORK"},
        "attack_complexity": {"LOW"},
        "privileges_required": {"NONE"},
        "user_interaction": {"NONE"},
        "scope": {"CHANGED"},
        "confidentiality": {"HIGH"},
        "integrity": {"HIGH"},
        "availability": {"HIGH"},
    }
    if value.upper() in worst.get(metric, set()):
        return "text-p1"
    return "text-muted"


# ---------------------------------------------------------------------------
# GET / -- risk dashboard
# ---------------------------------------------------------------------------


_PAGE_SIZE = 25


def _build_threat_intel(request: Request) -> list[dict]:
    """Build the threat intelligence item list for the dashboard.

    Fetches open vulnerability CVE IDs from the CMDB, enriches each through
    the pipeline (wrapping failures so a single bad CVE cannot break the page),
    and returns only items that are KEV-listed or have an EPSS score > 0.5.

    KEV items are sorted first; within each group items are sorted by EPSS
    score descending so the highest-risk items surface at the top of the table.

    Pattern: "fail-safe enrichment" -- external data failures are absorbed per
    CLAUDE.md safety rules (external calls return None or empty, never raise).
    """
    cmdb: CMDBStore = request.app.state.cmdb
    kev_set: set = request.app.state.kev_set
    cache = request.app.state.cache

    open_vulns = cmdb.get_open_vuln_cve_ids()
    if len(open_vulns) > 50:
        logger.info("Dashboard threat intel: enriching %d CVEs", len(open_vulns))

    items: list[dict] = []
    for vuln in open_vulns:
        cve_id = vuln["cve_id"]
        try:
            enriched = process_cve(cve_id, kev_set, cache, exposure=vuln.get("exposure", "internal"))
        except Exception:
            logger.warning("Dashboard threat intel: failed to enrich %s, skipping", cve_id)
            continue

        if enriched is None:
            continue

        epss_score: Optional[float] = enriched.epss_score
        is_kev: bool = bool(enriched.is_kev)

        # Filter: only KEV entries or high-EPSS (> 0.5) items surface here
        if not is_kev and (epss_score is None or epss_score <= 0.5):
            continue

        items.append(
            {
                "cve_id": cve_id,
                "asset_id": vuln["asset_id"],
                "hostname": vuln["hostname"],
                "is_kev": is_kev,
                "epss_score": epss_score,
                "effective_priority": vuln["effective_priority"],
            }
        )

    # KEV items first, then descending EPSS score
    items.sort(key=lambda x: (0 if x["is_kev"] else 1, -(x["epss_score"] or 0.0)))
    return items


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, page: int = 1) -> HTMLResponse:
    if redirect := _require_auth(request):
        return redirect
    cmdb: CMDBStore = request.app.state.cmdb
    assets = cmdb.list_assets()
    priority_counts = cmdb.get_all_priority_counts()

    # Resolve per-asset vuln counts in a single query (eliminates N+1 from the old loop)
    all_asset_counts = cmdb.get_all_asset_priority_counts()

    asset_rows = []
    for asset in assets:
        # .get() safe default: assets with zero open vulns are omitted from the bulk count map
        counts = all_asset_counts.get(asset.id, {"P1": 0, "P2": 0, "P3": 0, "P4": 0})

        # Nearest open deadline per asset (still a per-asset query, but this is a display-only
        # detail not covered by the bulk count query and only used for the risk table column)
        vulns = cmdb.get_asset_vulns(asset.id)
        nearest_deadline: Optional[str] = None
        for v in vulns:
            if v.status in ("closed", "deferred") or not v.deadline:
                continue
            if nearest_deadline is None or v.deadline < nearest_deadline:
                nearest_deadline = v.deadline

        asset_rows.append(
            {
                "asset": asset,
                "counts": counts,
                "nearest_deadline": _deadline_info(nearest_deadline),
            }
        )

    asset_rows.sort(key=lambda r: (-r["counts"]["P1"], -r["counts"]["P2"]))

    total_assets = len(asset_rows)
    total_pages = max(1, (total_assets + _PAGE_SIZE - 1) // _PAGE_SIZE)
    page = max(1, min(page, total_pages))
    start = (page - 1) * _PAGE_SIZE
    page_rows = asset_rows[start : start + _PAGE_SIZE]

    # --- New dashboard datasets ---
    threat_intel_items = _build_threat_intel(request)
    kev_count = sum(1 for item in threat_intel_items if item["is_kev"])

    user_store = request.app.state.user_store
    sla_config = user_store.get_sla_config()
    overdue_data = cmdb.get_overdue_vulns(sla_days=sla_config)
    overdue_count = len(overdue_data["overdue"])

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "asset_rows": page_rows,
            "total_assets": total_assets,
            "priority_counts": priority_counts,
            "total_open": sum(priority_counts.values()),
            "overdue_count": overdue_count,
            "page": page,
            "total_pages": total_pages,
            "page_size": _PAGE_SIZE,
            "flash_message": _get_flash(request),
            "threat_intel_items": threat_intel_items,
            "overdue_data": overdue_data,
            "kev_count": kev_count,
            "getting_started": total_assets == 0,
        },
    )


# ---------------------------------------------------------------------------
# GET /dashboard -- permanent redirect to / for bookmarks and typed URLs
# ---------------------------------------------------------------------------


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_redirect(request: Request) -> RedirectResponse:
    """Redirect /dashboard to / permanently.

    /dashboard has never been its own page -- the real dashboard lives at /.
    A 301 (permanent) redirect is appropriate here so browsers and bookmarks
    update their stored URL to /, minimising future round-trips.
    """
    return RedirectResponse("/", status_code=301)


# ---------------------------------------------------------------------------
# GET /cve -- CVE research page (registered BEFORE /cve/{cve_id})
# ---------------------------------------------------------------------------


@router.get("/cve", response_class=HTMLResponse)
def cve_research(request: Request) -> HTMLResponse:
    """Render the CVE research page: single lookup + bulk triage."""
    return templates.TemplateResponse("cve_research.html", {"request": request, "flash_message": _get_flash(request)})


# ---------------------------------------------------------------------------
# POST /cve/lookup -- HTMX: enrich one CVE, return a summary card fragment
# ---------------------------------------------------------------------------


@router.post("/cve/lookup", response_class=HTMLResponse)
async def cve_lookup_htmx(
    request: Request,
    cve_id: str = Form(...),
    exposure: str = Form(default="internal"),
) -> HTMLResponse:
    """Enrich a single CVE and return a card fragment for HTMX to swap in."""
    normalized = cve_id.strip().upper()

    if not re.match(CVE_PATTERN, normalized):
        return templates.TemplateResponse(
            "partials/cve_card.html",
            {
                "request": request,
                "enriched": None,
                "error": f"'{cve_id[:40]}' does not match CVE-YYYY-NNNNN format.",
                "exposure": exposure,
                "nvd_url": None,
            },
        )

    enriched = None
    try:
        enriched = process_cve(
            normalized,
            request.app.state.kev_set,
            request.app.state.cache,
            exposure=exposure,
        )
    except Exception:
        logger.debug("CVE lookup failed for %s", normalized, exc_info=True)

    return templates.TemplateResponse(
        "partials/cve_card.html",
        {
            "request": request,
            "enriched": enriched,
            "error": None if enriched else f"{normalized} was not found in NVD.",
            "exposure": exposure,
            "nvd_url": _NVD_URL.format(cve_id=normalized),
        },
    )


# ---------------------------------------------------------------------------
# POST /cve/bulk -- HTMX: enrich many CVEs, return a prioritised table
# ---------------------------------------------------------------------------


@router.post("/cve/bulk", response_class=HTMLResponse)
async def cve_bulk_htmx(
    request: Request,
    cve_ids_raw: str = Form(...),
    exposure: str = Form(default="internal"),
) -> HTMLResponse:
    """Enrich up to 50 CVEs and return a priority-sorted results table."""
    lines = [ln.strip().upper() for ln in cve_ids_raw.splitlines() if ln.strip()]
    valid_ids = [ln for ln in lines if re.match(CVE_PATTERN, ln)]
    invalid = [ln for ln in lines if not re.match(CVE_PATTERN, ln)]

    results = process_cves(
        valid_ids[:50],
        request.app.state.kev_set,
        request.app.state.cache,
        exposure=exposure,
    )

    _order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    results.sort(key=lambda e: _order.get(e.triage_priority, 9))

    return templates.TemplateResponse(
        "partials/bulk_results.html",
        {
            "request": request,
            "results": results,
            "invalid": invalid,
            "exposure": exposure,
            "requested": len(valid_ids),
        },
    )


# ---------------------------------------------------------------------------
# GET /cve/{cve_id} -- full CVE detail (registered LAST under /cve/*)
# ---------------------------------------------------------------------------


@router.get("/cve/{cve_id}", response_class=HTMLResponse)
def cve_detail(
    request: Request,
    cve_id: str,
    exposure: str = "internal",
) -> HTMLResponse:
    """Full CVE detail: enriched data, CVSS breakdown, remediation, CMDB assets."""
    normalized = cve_id.strip().upper()
    if not re.match(CVE_PATTERN, normalized):
        return HTMLResponse(
            "<div class='text-danger p-4'>Invalid CVE ID format.</div>",
            status_code=400,
        )

    enriched = None
    try:
        enriched = process_cve(
            normalized,
            request.app.state.kev_set,
            request.app.state.cache,
            exposure=exposure,
        )
    except Exception:
        logger.debug("CVE detail enrichment failed for %s", normalized, exc_info=True)

    # Which CMDB assets have this CVE? This is the key differentiator from NVD.
    cmdb: CMDBStore = request.app.state.cmdb
    affected_assets = []
    for asset in cmdb.list_assets():
        vuln = cmdb.get_vuln_by_asset_and_cve(asset.id, normalized)
        if vuln:
            affected_assets.append(
                {
                    "asset": asset,
                    "vuln": vuln,
                    "deadline_info": _deadline_info(vuln.deadline),
                }
            )

    return templates.TemplateResponse(
        "cve_detail.html",
        {
            "request": request,
            "cve_id": normalized,
            "enriched": enriched,
            "exposure": exposure,
            "affected_assets": affected_assets,
            "nvd_url": _NVD_URL.format(cve_id=normalized),
            "cvss_row_css": _cvss_row_css,
            "flash_message": _get_flash(request),
        },
    )


# ---------------------------------------------------------------------------
# GET /assets/new -- asset creation form (MUST precede /assets/{asset_id})
# ---------------------------------------------------------------------------


@router.get("/assets/new", response_class=HTMLResponse)
def asset_create_form(request: Request) -> HTMLResponse:
    """Render the asset registration form."""
    if redirect := _require_auth(request):
        return redirect
    return templates.TemplateResponse(
        "assets_form.html",
        {
            "request": request,
            "error": None,
            "form_data": {},
            "compliance_options": _COMPLIANCE_OPTIONS,
            "flash_message": _get_flash(request),
        },
    )


# ---------------------------------------------------------------------------
# POST /assets -- handle creation, 303-redirect to /assets/{id} on success
# ---------------------------------------------------------------------------


_COMPLIANCE_OPTIONS = ["PCI-DSS", "HIPAA", "SOX", "FedRAMP", "GDPR", "ISO 27001", "CIS"]


@router.post("/assets", response_class=HTMLResponse)
async def asset_create(
    request: Request,
    hostname: Optional[str] = Form(default=None),
    ip: Optional[str] = Form(default=None),
    environment: str = Form(default="production"),
    exposure: str = Form(default="internal"),
    criticality: str = Form(default="medium"),
    owner: Optional[str] = Form(default=None),
    tags: Optional[str] = Form(default=None),
    os: Optional[str] = Form(default=None),
    eol_date: Optional[str] = Form(default=None),
    compliance: Optional[list[str]] = Form(default=None),  # noqa: B008
) -> HTMLResponse:
    """Handle asset creation form POST. Redirects to the new asset on success."""
    compliance_raw: list[str] = compliance or []
    form_data = {
        "hostname": hostname or "",
        "ip": ip or "",
        "environment": environment,
        "exposure": exposure,
        "criticality": criticality,
        "owner": owner or "",
        "tags": tags or "",
        "os": os or "",
        "eol_date": eol_date or "",
        "compliance": compliance_raw,
    }

    hostname_clean = (hostname or "").strip()
    if not hostname_clean:
        return templates.TemplateResponse(
            "assets_form.html",
            {
                "request": request,
                "error": "Hostname is required.",
                "form_data": form_data,
                "compliance_options": _COMPLIANCE_OPTIONS,
            },
        )
    if len(hostname_clean) > 255:
        return templates.TemplateResponse(
            "assets_form.html",
            {
                "request": request,
                "error": "Hostname must be 255 characters or fewer.",
                "form_data": form_data,
                "compliance_options": _COMPLIANCE_OPTIONS,
            },
        )

    if environment not in _VALID_ENVIRONMENTS:
        environment = "production"
    if exposure not in _VALID_EXPOSURES:
        exposure = "internal"
    if criticality not in _VALID_CRITICALITIES:
        criticality = "medium"

    tag_list = [t.strip() for t in (tags or "").split(",") if t.strip()]
    compliance_clean = [c for c in compliance_raw if c in _COMPLIANCE_OPTIONS]
    eol_clean = (eol_date or "").strip() or None
    os_clean = (os or "").strip()[:100] or None

    asset = Asset(
        hostname=hostname_clean,
        ip=(ip or "").strip() or None,
        environment=environment,
        exposure=exposure,
        criticality=criticality,
        owner=(owner or "").strip() or None,
        tags=tag_list,
        os=os_clean,
        eol_date=eol_clean,
        compliance=compliance_clean,
    )

    cmdb: CMDBStore = request.app.state.cmdb
    try:
        asset_id = cmdb.create_asset(asset)
    except Exception as exc:
        logger.debug("Asset creation failed: %s", exc, exc_info=True)
        return templates.TemplateResponse(
            "assets_form.html",
            {
                "request": request,
                "error": "Failed to create asset. The hostname may already be registered.",
                "form_data": form_data,
                "compliance_options": _COMPLIANCE_OPTIONS,
            },
        )

    return RedirectResponse(f"/assets/{asset_id}", status_code=303)


# ---------------------------------------------------------------------------
# GET /assets -- asset list (MUST precede /assets/{asset_id})
# ---------------------------------------------------------------------------


@router.get("/assets", response_class=HTMLResponse)
def asset_list(request: Request) -> HTMLResponse:
    """Render a table of all registered assets.

    Registered before GET /assets/{asset_id} so the bare /assets path is not
    captured as a path parameter named asset_id.
    """
    if redirect := _require_auth(request):
        return redirect
    cmdb: CMDBStore = request.app.state.cmdb
    assets = cmdb.list_assets()
    return templates.TemplateResponse(
        "assets_list.html",
        {
            "request": request,
            "assets": assets,
            "flash_message": _get_flash(request),
        },
    )


# ---------------------------------------------------------------------------
# GET /assets/{asset_id} -- asset detail
# ---------------------------------------------------------------------------


@router.get("/assets/{asset_id}", response_class=HTMLResponse)
def asset_detail(request: Request, asset_id: int) -> HTMLResponse:
    if redirect := _require_auth(request):
        return redirect
    cmdb: CMDBStore = request.app.state.cmdb
    asset = cmdb.get_asset(asset_id)
    if asset is None:
        return HTMLResponse("<h1>Asset not found</h1>", status_code=404)

    kev_set = request.app.state.kev_set
    cache = request.app.state.cache
    vulns = cmdb.get_asset_vulns(asset_id)

    vuln_rows = []
    for vuln in vulns:
        enriched = None
        try:
            enriched = process_cve(vuln.cve_id, kev_set, cache, exposure=asset.exposure)
        except Exception:
            logger.debug("Enrichment failed for %s on asset %d", vuln.cve_id, asset_id, exc_info=True)
        vuln_rows.append(
            {
                "vuln": vuln,
                "enriched": enriched,
                "deadline_info": _deadline_info(vuln.deadline),
                "nvd_url": _NVD_URL.format(cve_id=vuln.cve_id),
            }
        )

    return templates.TemplateResponse(
        "asset_detail.html",
        {
            "request": request,
            "asset": asset,
            "vuln_rows": vuln_rows,
            "counts": cmdb.get_priority_counts(asset_id),
            "asset_id": asset_id,
            "statuses": _STATUSES,
            "eol_info": _eol_info(asset.eol_date),
            "flash_message": _get_flash(request),
        },
    )


# ---------------------------------------------------------------------------
# POST /assets/{asset_id}/vulnerabilities -- HTMX: add CVEs, return updated tbody
# ---------------------------------------------------------------------------


@router.post("/assets/{asset_id}/vulnerabilities", response_class=HTMLResponse)
async def add_asset_vulns_htmx(
    request: Request,
    asset_id: int,
    cve_ids_raw: str = Form(...),
    scanner: str = Form(default="manual"),
    owner: Optional[str] = Form(default=None),
) -> HTMLResponse:
    """HTMX: enrich and assign CVEs to an asset, return all current tbody rows."""
    cmdb: CMDBStore = request.app.state.cmdb
    asset = cmdb.get_asset(asset_id)
    if asset is None:
        return HTMLResponse(
            "<tr><td colspan='8' class='text-danger p-3'>Asset not found.</td></tr>",
            status_code=404,
        )

    lines = [ln.strip().upper() for ln in cve_ids_raw.splitlines() if ln.strip()]
    # Deduplicate while preserving order
    seen: set[str] = set()
    valid_ids: list[str] = []
    for ln in lines:
        if re.match(CVE_PATTERN, ln) and ln not in seen:
            seen.add(ln)
            valid_ids.append(ln)

    if valid_ids:
        enriched_list = process_cves(
            valid_ids,
            request.app.state.kev_set,
            request.app.state.cache,
            exposure=asset.exposure,
        )
        scanner_clean = scanner if scanner in _VALID_SCANNERS else "manual"
        owner_clean = (owner or "").strip() or None
        for enriched in enriched_list:
            base_priority = enriched.triage_priority
            effective_priority = apply_criticality_modifier(base_priority, asset.criticality)
            vuln = AssetVulnerability(
                asset_id=asset_id,
                cve_id=enriched.id,
                base_priority=base_priority,
                effective_priority=effective_priority,
                scanner=scanner_clean,
                owner=owner_clean,
            )
            try:
                cmdb.create_asset_vuln(vuln)
            except IntegrityError:
                pass  # Already assigned -- skip silently

    # Re-fetch all vulns to return fresh, fully accurate tbody
    vulns = cmdb.get_asset_vulns(asset_id)
    vuln_rows = []
    for vuln in vulns:
        enriched = None
        try:
            enriched = process_cve(
                vuln.cve_id, request.app.state.kev_set, request.app.state.cache, exposure=asset.exposure
            )
        except Exception:
            logger.debug("Enrichment failed for %s on asset %d", vuln.cve_id, asset_id, exc_info=True)
        vuln_rows.append(
            {
                "vuln": vuln,
                "enriched": enriched,
                "deadline_info": _deadline_info(vuln.deadline),
                "nvd_url": _NVD_URL.format(cve_id=vuln.cve_id),
            }
        )

    return templates.TemplateResponse(
        "partials/vuln_table_body.html",
        {
            "request": request,
            "vuln_rows": vuln_rows,
            "asset_id": asset_id,
            "statuses": _STATUSES,
        },
    )


# ---------------------------------------------------------------------------
# POST /assets/{asset_id}/vulnerabilities/{cve_id}/status -- HTMX row update
# ---------------------------------------------------------------------------


@router.post(
    "/assets/{asset_id}/vulnerabilities/{cve_id}/status",
    response_class=HTMLResponse,
)
async def update_vuln_status_htmx(
    request: Request,
    asset_id: int,
    cve_id: str,
    status: str = Form(...),
    owner: Optional[str] = Form(default=None),
    evidence: Optional[str] = Form(default=None),
) -> HTMLResponse:
    cmdb: CMDBStore = request.app.state.cmdb
    normalized = cve_id.upper()

    vuln = cmdb.get_vuln_by_asset_and_cve(asset_id, normalized)
    if vuln is not None:
        cmdb.update_vuln_status(
            vuln.id,
            status=status,
            owner=owner or None,
            evidence=evidence or None,
        )
        vuln = cmdb.get_vuln_by_asset_and_cve(asset_id, normalized)

    asset = cmdb.get_asset(asset_id)
    enriched = None
    if asset:
        try:
            enriched = process_cve(
                normalized,
                request.app.state.kev_set,
                request.app.state.cache,
                exposure=asset.exposure,
            )
        except Exception:
            logger.debug("Enrichment failed for %s on status update", normalized, exc_info=True)

    return templates.TemplateResponse(
        "partials/vuln_row.html",
        {
            "request": request,
            "vuln": vuln,
            "enriched": enriched,
            "deadline_info": _deadline_info(vuln.deadline if vuln else None),
            "nvd_url": _NVD_URL.format(cve_id=normalized),
            "asset_id": asset_id,
            "statuses": _STATUSES,
        },
    )


# ---------------------------------------------------------------------------
# GET /assets/{asset_id}/edit -- pre-populated edit form
# ---------------------------------------------------------------------------


@router.get("/assets/{asset_id}/edit", response_class=HTMLResponse)
def asset_edit_form(request: Request, asset_id: int) -> HTMLResponse:
    """Render the asset edit form, pre-populated with current values."""
    if redirect := _require_auth(request):
        return redirect
    cmdb: CMDBStore = request.app.state.cmdb
    asset = cmdb.get_asset(asset_id)
    if asset is None:
        return HTMLResponse("<h1>Asset not found</h1>", status_code=404)
    form_data = {
        "hostname": asset.hostname,
        "ip": asset.ip or "",
        "environment": asset.environment,
        "exposure": asset.exposure,
        "criticality": asset.criticality,
        "owner": asset.owner or "",
        "tags": ", ".join(asset.tags),
        "os": asset.os or "",
        "eol_date": asset.eol_date or "",
        "compliance": asset.compliance,
    }
    return templates.TemplateResponse(
        "asset_edit.html",
        {
            "request": request,
            "asset": asset,
            "form_data": form_data,
            "error": None,
            "compliance_options": _COMPLIANCE_OPTIONS,
            "flash_message": _get_flash(request),
        },
    )


# ---------------------------------------------------------------------------
# POST /assets/{asset_id} -- handle asset update, 303-redirect to detail
# ---------------------------------------------------------------------------


@router.post("/assets/{asset_id}", response_class=HTMLResponse)
async def asset_update(
    request: Request,
    asset_id: int,
    hostname: Optional[str] = Form(default=None),
    ip: Optional[str] = Form(default=None),
    environment: str = Form(default="production"),
    exposure: str = Form(default="internal"),
    criticality: str = Form(default="medium"),
    owner: Optional[str] = Form(default=None),
    tags: Optional[str] = Form(default=None),
    os: Optional[str] = Form(default=None),
    eol_date: Optional[str] = Form(default=None),
    compliance: Optional[list[str]] = Form(default=None),  # noqa: B008
) -> HTMLResponse:
    """Handle asset edit form POST. Redirects to /assets/{id} on success."""
    compliance_raw: list[str] = compliance or []
    cmdb: CMDBStore = request.app.state.cmdb
    asset = cmdb.get_asset(asset_id)
    if asset is None:
        return HTMLResponse("<h1>Asset not found</h1>", status_code=404)

    form_data = {
        "hostname": hostname or "",
        "ip": ip or "",
        "environment": environment,
        "exposure": exposure,
        "criticality": criticality,
        "owner": owner or "",
        "tags": tags or "",
        "os": os or "",
        "eol_date": eol_date or "",
        "compliance": compliance_raw,
    }

    hostname_clean = (hostname or "").strip()
    if not hostname_clean:
        return templates.TemplateResponse(
            "asset_edit.html",
            {
                "request": request,
                "asset": asset,
                "form_data": form_data,
                "error": "Hostname is required.",
                "compliance_options": _COMPLIANCE_OPTIONS,
            },
        )
    if len(hostname_clean) > 255:
        return templates.TemplateResponse(
            "asset_edit.html",
            {
                "request": request,
                "asset": asset,
                "form_data": form_data,
                "error": "Hostname must be 255 characters or fewer.",
                "compliance_options": _COMPLIANCE_OPTIONS,
            },
        )

    if environment not in _VALID_ENVIRONMENTS:
        environment = "production"
    if exposure not in _VALID_EXPOSURES:
        exposure = "internal"
    if criticality not in _VALID_CRITICALITIES:
        criticality = "medium"

    tag_list = [t.strip() for t in (tags or "").split(",") if t.strip()]
    compliance_clean = [c for c in compliance_raw if c in _COMPLIANCE_OPTIONS]
    eol_clean = (eol_date or "").strip() or None
    os_clean = (os or "").strip()[:100] or None

    try:
        cmdb.update_asset(
            asset_id,
            hostname=hostname_clean,
            ip=(ip or "").strip() or None,
            environment=environment,
            exposure=exposure,
            criticality=criticality,
            owner=(owner or "").strip() or None,
            tags=tag_list,
            os=os_clean,
            eol_date=eol_clean,
            compliance=compliance_clean,
        )
    except Exception as exc:
        logger.debug("Asset update failed: %s", exc, exc_info=True)
        return templates.TemplateResponse(
            "asset_edit.html",
            {
                "request": request,
                "asset": asset,
                "form_data": form_data,
                "error": "Failed to update asset.",
                "compliance_options": _COMPLIANCE_OPTIONS,
            },
        )

    return RedirectResponse(f"/assets/{asset_id}", status_code=303)


# ---------------------------------------------------------------------------
# GET /ingest -- scanner file ingest form
# ---------------------------------------------------------------------------


@router.get("/ingest", response_class=HTMLResponse)
def ingest_form(request: Request) -> HTMLResponse:
    """Render the scanner file ingest form."""
    if redirect := _require_auth(request):
        return redirect
    return templates.TemplateResponse("ingest.html", {"request": request, "flash_message": _get_flash(request)})


# ---------------------------------------------------------------------------
# POST /ingest -- HTMX: file upload, return result fragment
# ---------------------------------------------------------------------------


@router.post("/ingest", response_class=HTMLResponse)
async def ingest_file_htmx(
    request: Request,
    file: UploadFile,
    default_exposure: str = Form(default="internal"),
    default_criticality: str = Form(default="medium"),
) -> HTMLResponse:
    """HTMX: ingest a scanner file and return a counts/errors result fragment."""
    if default_exposure not in _VALID_EXPOSURES:
        default_exposure = "internal"
    if default_criticality not in _VALID_CRITICALITIES:
        default_criticality = "medium"

    raw = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(raw) > _MAX_UPLOAD_BYTES:
        return templates.TemplateResponse(
            "partials/ingest_result.html",
            {
                "request": request,
                "errors": ["File must be 1 MB or smaller."],
                "assets_created": 0,
                "vulns_assigned": 0,
                "vulns_skipped": 0,
                "new_assets": [],
            },
        )

    content = raw.decode("utf-8", errors="replace")
    filename = (file.filename or "").lower()

    records = []
    if filename.endswith(".json"):
        trivy = parse_trivy_json(content)
        records = trivy if trivy else parse_grype_json(content)
    elif filename.endswith(".csv"):
        nessus = parse_nessus_csv(content)
        records = nessus if nessus else parse_csv(content)
    else:
        return templates.TemplateResponse(
            "partials/ingest_result.html",
            {
                "request": request,
                "errors": ["File must have a .csv or .json extension."],
                "assets_created": 0,
                "vulns_assigned": 0,
                "vulns_skipped": 0,
                "new_assets": [],
            },
        )

    cmdb: CMDBStore = request.app.state.cmdb
    kev_set = request.app.state.kev_set
    cache = request.app.state.cache

    assets_created = 0
    vulns_assigned = 0
    vulns_skipped = 0
    errors: list[str] = []
    new_assets: list[dict] = []

    # Group by hostname; validate CVE IDs before any DB work
    by_hostname: dict[str, list[str]] = {}
    for rec in records:
        if not re.match(CVE_PATTERN, rec.cve_id):
            errors.append(f"Skipped invalid CVE ID: {rec.cve_id[:50]}")
            continue
        by_hostname.setdefault(rec.hostname, []).append(rec.cve_id)

    scanner = "csv" if filename.endswith(".csv") else "trivy"

    for hostname, cve_ids in by_hostname.items():
        asset = cmdb.get_asset_by_hostname(hostname)
        if asset is None:
            new_asset_obj = Asset(
                hostname=hostname,
                environment="production",
                exposure=default_exposure,
                criticality=default_criticality,
            )
            new_asset_id = cmdb.create_asset(new_asset_obj)
            asset = cmdb.get_asset(new_asset_id)
            assets_created += 1
            new_assets.append({"id": asset.id, "hostname": asset.hostname})

        enriched_list = process_cves(cve_ids, kev_set, cache, exposure=asset.exposure)
        for enriched in enriched_list:
            base_priority = enriched.triage_priority
            effective_priority = apply_criticality_modifier(base_priority, asset.criticality)
            vuln = AssetVulnerability(
                asset_id=asset.id,
                cve_id=enriched.id,
                base_priority=base_priority,
                effective_priority=effective_priority,
                scanner=scanner,
            )
            try:
                cmdb.create_asset_vuln(vuln)
                vulns_assigned += 1
            except IntegrityError:
                vulns_skipped += 1

    return templates.TemplateResponse(
        "partials/ingest_result.html",
        {
            "request": request,
            "assets_created": assets_created,
            "vulns_assigned": vulns_assigned,
            "vulns_skipped": vulns_skipped,
            "errors": errors,
            "new_assets": new_assets,
        },
    )


# ---------------------------------------------------------------------------
# Auth routes -- login, logout, setup, OAuth
# ---------------------------------------------------------------------------

# Route registration order: /login/oauth/{provider} and /login/callback/{provider}
# must come before GET /login so FastAPI doesn't treat "oauth" as a path param
# of some hypothetical /login/{something} route. We define all /login sub-paths
# first, then the base /login routes.


@router.get("/login/oauth/{provider}", response_class=HTMLResponse)
async def oauth_redirect(request: Request, provider: str) -> RedirectResponse:
    """Redirect the browser to the OAuth provider's authorization page.

    Validates the provider name against the enabled provider list before
    redirecting. This prevents an attacker from crafting a redirect to an
    arbitrary URL via a spoofed provider name.
    """
    enabled = {p["name"] for p in get_enabled_providers()}
    if provider not in enabled:
        return RedirectResponse("/login?error=oauth_failed", status_code=302)

    oauth_registry = request.app.state.oauth
    client = oauth_registry.create_client(provider)
    redirect_uri = str(request.url_for("oauth_callback", provider=provider))
    return await client.authorize_redirect(request, redirect_uri)


@router.get("/login/callback/{provider}", response_class=HTMLResponse, name="oauth_callback")
async def oauth_callback(request: Request, provider: str) -> RedirectResponse:
    """Handle the OAuth provider callback and issue a JWT cookie.

    Flow:
      1. Exchange authorization code for token (authlib handles CSRF via session state).
      2. Extract (email, subject_id) from the token -- raises ValueError if unverified [H1].
      3. Look up by (provider, subject_id) -- fast path for returning users.
      4. If not found, look up by username (email) -- first login, link OAuth identity.
      5. Reject unknown emails (not_provisioned) and inactive accounts.
      6. Issue JWT, set cookie, redirect to ?next or /.
    """
    enabled = {p["name"] for p in get_enabled_providers()}
    if provider not in enabled:
        return RedirectResponse("/login?error=oauth_failed", status_code=302)

    oauth_registry = request.app.state.oauth
    user_store: UserStore = request.app.state.user_store
    client = oauth_registry.create_client(provider)

    # Step 1: Exchange code for token
    try:
        token = await client.authorize_access_token(request)
    except OAuthError:
        logger.exception("OAuth token exchange failed for provider %r", provider)
        return RedirectResponse("/login?error=oauth_failed", status_code=302)

    # Step 2: Extract verified email and stable subject ID [H1]
    try:
        email, oauth_subject = await get_oauth_user_info(client, provider, token)
    except ValueError:
        logger.warning("OAuth login rejected: unverified or missing email from %r", provider)
        return RedirectResponse("/login?error=oauth_failed", status_code=302)

    # Step 3: Fast path -- returning user already linked
    user = user_store.get_by_oauth(provider, oauth_subject)

    # Step 4: First login -- match by pre-created username (email), link identity
    if user is None:
        user = user_store.get_by_username(email)
        if user is not None and user.oauth_subject is None:
            # Pre-created account, not yet linked. Link now.
            user_store.link_oauth(user.id, provider, oauth_subject)
            user = user_store.get_by_id(user.id)  # refresh after link
        elif user is None:
            # No pre-created account for this email.
            return RedirectResponse("/login?error=not_provisioned", status_code=302)

    # Step 5: Check account is active
    if not user.is_active:
        return RedirectResponse("/login?error=account_disabled", status_code=302)

    # Step 6: Issue JWT, set cookie, redirect
    user_store.update_last_login(user.id)  # stamp last_login on successful OAuth auth
    duration = get_session_duration(user.user_preferences)
    token_str = create_access_token(user.id, user.username, user.role, expire_seconds=duration)
    next_url = _safe_next(request.query_params.get("next"))  # [C2]
    resp = RedirectResponse(next_url, status_code=302)
    set_auth_cookie(resp, token_str, expire_seconds=duration)
    resp.headers["Cache-Control"] = "no-store"  # [M5]
    return resp


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, response: Response, csrf_protect: CsrfProtect = Depends()) -> HTMLResponse:
    """Render the login page with username/password form and OAuth buttons."""
    # Redirect already-authenticated users to /
    if try_get_current_user(request) is not None:
        return RedirectResponse("/", status_code=302)

    # Map ?error= query param through whitelist [M3]
    error_msg = _ERROR_MESSAGES.get(request.query_params.get("error", ""), None)
    # Pop any flash set by the CSRF error handler (e.g. tampered token on a previous submit)
    flash_message = request.session.pop("flash", None)
    providers = get_enabled_providers()
    csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
    resp = templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error_msg": error_msg,
            "flash_message": flash_message,
            "providers": providers,
            "csrf_token": csrf_token,
            "registration_enabled": _is_registration_enabled(request),
        },
    )
    csrf_protect.set_csrf_cookie(signed_token, resp)
    return resp


@router.post("/login", response_class=HTMLResponse)
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_protect: CsrfProtect = Depends(),
) -> RedirectResponse:
    """Handle username/password login form submission."""
    await csrf_protect.validate_csrf(request)
    user_store: UserStore = request.app.state.user_store
    user = authenticate_user(user_store, username, password)  # [C1] timing equalization
    if user is None:
        return RedirectResponse("/login?error=bad_credentials", status_code=302)

    user_store.update_last_login(user.id)  # stamp last_login on successful auth
    duration = get_session_duration(user.user_preferences)
    token = create_access_token(user.id, user.username, user.role, expire_seconds=duration)
    next_url = _safe_next(request.query_params.get("next"))  # [C2]
    resp = RedirectResponse(next_url, status_code=302)
    set_auth_cookie(resp, token, expire_seconds=duration)
    resp.headers["Cache-Control"] = "no-store"  # [M5]
    return resp


@router.get("/logout")
def logout(request: Request) -> RedirectResponse:
    """Clear the JWT cookie and redirect to the login page.

    Uses GET (not POST) to avoid the need for a CSRF token in every page's template
    context. Security trade-off: GET /logout can be triggered by a malicious link
    (e.g. <img src='/logout'>), but clearing the session cookie exposes no sensitive
    data -- the user simply re-authenticates. Acceptable for a solo-analyst tool.
    See Plan 02 RESEARCH.md Pitfall 1 for the full trade-off analysis.
    """
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("access_token")
    return resp


@router.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request, response: Response, csrf_protect: CsrfProtect = Depends()) -> HTMLResponse:
    """Render the first-run setup wizard.

    Redirects to /login after the first admin account has been created (per
    user decision in CONTEXT.md: silently redirect to /login, not 404).
    """
    if not getattr(request.app.state, "setup_required", True):
        return RedirectResponse("/login", status_code=302)
    flash_message = request.session.pop("flash", None)
    csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
    resp = templates.TemplateResponse(
        "setup.html",
        {
            "request": request,
            "flash_message": flash_message,
            "csrf_token": csrf_token,
        },
    )
    csrf_protect.set_csrf_cookie(signed_token, resp)
    return resp


@router.post("/setup", response_class=HTMLResponse)
async def setup_post(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_protect: CsrfProtect = Depends(),
) -> RedirectResponse:
    """Create the first admin account.

    [M1] Race condition guard: re-checks has_users() inside the handler even
    though the middleware already checked setup_required. Two concurrent requests
    could both pass the middleware check before either creates a user. The DB-
    level check and IntegrityError catch ensure only one wins.

    Auto-login: on success, a JWT is issued and the auth cookie is set so the
    admin arrives at the dashboard without a separate login step.
    """
    await csrf_protect.validate_csrf(request)

    user_store: UserStore = request.app.state.user_store

    # Re-check at DB level [M1]
    if user_store.has_users():
        return RedirectResponse("/login?error=setup_complete", status_code=302)

    def _setup_error(msg: str) -> HTMLResponse:
        """Re-render setup form with error message and a fresh CSRF token.

        Error re-renders must include a new CSRF token so the next submission
        passes validation. Without this, the form's hidden csrf_token input
        would be empty and every retry would fail CSRF checks.
        """
        csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
        err_resp = templates.TemplateResponse(
            "setup.html",
            {"request": request, "error_msg": msg, "csrf_token": csrf_token},
        )
        csrf_protect.set_csrf_cookie(signed_token, err_resp)
        return err_resp

    if not username.strip():
        return _setup_error("Username is required.")
    if password != confirm_password:
        return _setup_error("Passwords do not match.")
    pw_error = _validate_password(password)
    if pw_error:
        return _setup_error(pw_error)

    from auth.models import User as AuthUser

    new_admin = AuthUser(
        username=username.strip(),
        role="admin",
        hashed_password=hash_password(password),
    )
    try:
        new_user_id: int = user_store.create_user(new_admin)
        request.app.state.setup_required = False
    except IntegrityError:
        # Race condition: another request created an admin first [M1]
        return RedirectResponse("/login?error=setup_complete", status_code=302)

    # Auto-login: issue JWT and set auth cookie so admin lands on the dashboard
    # without needing to re-enter credentials. Pattern: create token -> set cookie
    # -> return redirect (cookie attaches to RedirectResponse, not the final page).
    token = create_access_token(new_user_id, new_admin.username, new_admin.role)
    resp = RedirectResponse("/", status_code=302)
    set_auth_cookie(resp, token)
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------------------
# Registration helpers
# ---------------------------------------------------------------------------

_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]+$")


def _is_registration_enabled(request: Request) -> bool:
    """Return True if self-registration is currently enabled.

    DB app_settings is the runtime source of truth. The env var
    SELF_REGISTRATION_ENABLED in core/config.py is the initial default;
    once the admin has toggled the setting in the UI the DB value overrides it.

    Accepts request so it can reach app.state.user_store without making
    UserStore a module-level global. Option A from the plan: explicit is
    better than implicit.
    """
    user_store: UserStore = request.app.state.user_store
    app_settings = user_store.get_app_settings()
    return bool(app_settings.get("self_registration_enabled", True))


# ---------------------------------------------------------------------------
# GET /register -- registration form
# ---------------------------------------------------------------------------


@router.get("/register", response_class=HTMLResponse)
def register_form(request: Request, response: Response, csrf_protect: CsrfProtect = Depends()) -> HTMLResponse:
    """Render the user registration page.

    If self-registration is disabled, redirects to /login with a flash message
    rather than returning a 404 or 403. This avoids leaking whether the feature
    exists while still giving a useful explanation to legitimate users.
    """
    if not _is_registration_enabled(request):
        request.session["flash"] = "Registration is currently disabled."
        return RedirectResponse("/login", status_code=302)
    # Redirect already-authenticated users away from the registration page
    if try_get_current_user(request) is not None:
        return RedirectResponse("/", status_code=302)
    flash_message = request.session.pop("flash", None)
    csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
    resp = templates.TemplateResponse(
        "register.html",
        {
            "request": request,
            "flash_message": flash_message,
            "csrf_token": csrf_token,
            "username": "",
        },
    )
    csrf_protect.set_csrf_cookie(signed_token, resp)
    return resp


# ---------------------------------------------------------------------------
# POST /register -- create user account
# ---------------------------------------------------------------------------


@router.post("/register", response_class=HTMLResponse)
async def register_post(
    request: Request,
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_protect: CsrfProtect = Depends(),
) -> HTMLResponse:
    """Handle the registration form submission.

    Security decisions:
      - Registration always creates role="user" -- admins are only created via /setup
        or by an existing admin. This prevents privilege escalation through registration.
      - Username is validated against a strict allowlist regex (3-30 chars,
        alphanumeric + underscores) to prevent injection and confusable usernames.
      - Self-registration toggle is re-checked here (defense in depth -- a crafted
        direct POST must not bypass the GET-level check).
      - Passwords must pass the shared _validate_password() complexity rules.
    """
    await csrf_protect.validate_csrf(request)

    # Defense in depth: re-check toggle on POST as well [C5]
    if not _is_registration_enabled(request):
        request.session["flash"] = "Registration is currently disabled."
        return RedirectResponse("/login", status_code=302)

    user_store: UserStore = request.app.state.user_store

    def _register_error(msg: str, prefill_username: str = "") -> HTMLResponse:
        """Re-render register form with error message and a fresh CSRF token."""
        csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
        err_resp = templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error_msg": msg,
                "csrf_token": csrf_token,
                "username": prefill_username,
            },
        )
        csrf_protect.set_csrf_cookie(signed_token, err_resp)
        return err_resp

    # Validate username: 3-30 chars, alphanumeric + underscores only
    username_clean = username.strip()
    if not username_clean:
        return _register_error("Username is required.")
    if len(username_clean) < 3 or len(username_clean) > 30:
        return _register_error("Username must be between 3 and 30 characters.", username_clean)
    if not _USERNAME_PATTERN.match(username_clean):
        return _register_error("Username may only contain letters, numbers, and underscores.", username_clean)

    # Validate passwords
    if password != confirm_password:
        return _register_error("Passwords do not match.", username_clean)
    pw_error = _validate_password(password)
    if pw_error:
        return _register_error(pw_error, username_clean)

    # Check for duplicate username
    if user_store.get_by_username(username_clean) is not None:
        return _register_error("That username is already taken.", username_clean)

    from auth.models import User as AuthUser

    new_user = AuthUser(
        username=username_clean,
        role="user",  # registration never grants admin -- only /setup does
        hashed_password=hash_password(password),
    )
    try:
        new_user_id: int = user_store.create_user(new_user)
    except IntegrityError:
        # Concurrent duplicate -- same username registered at the same time
        return _register_error("That username is already taken.", username_clean)

    # Auto-login: issue JWT and redirect to dashboard
    token = create_access_token(new_user_id, new_user.username, new_user.role)
    resp = RedirectResponse("/", status_code=302)
    set_auth_cookie(resp, token)
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------------------------------------------------------------------------
# Settings routes
# ---------------------------------------------------------------------------

# Valid session duration values (seconds). Whitelist prevents arbitrary values.
_VALID_SESSION_DURATIONS = {3600, 14400, 28800}


def _require_admin_redirect(request: Request) -> Optional[tuple]:
    """Check if the current user is authenticated AND is an admin.

    Returns (None, user) if access is allowed, or (RedirectResponse, None) if
    not. Combines the auth check and the role check into one call.
    """
    user = try_get_current_user(request)
    if user is None:
        request.session["flash"] = "Please log in to access this page."
        path = request.url.path
        return RedirectResponse(f"/login?next={path}", status_code=302), None
    if user.role != "admin":
        request.session["flash"] = "Admin access required."
        return RedirectResponse("/", status_code=302), None
    return None, user


@router.get("/settings", response_class=HTMLResponse)
def settings_form(request: Request, response: Response, csrf_protect: CsrfProtect = Depends()) -> HTMLResponse:
    """Render the user settings page: session duration picker and password change."""
    if redirect := _require_auth(request):
        return redirect
    user = try_get_current_user(request)
    # Extract current session duration from user_preferences JSON blob
    current_duration = 3600
    if user.user_preferences:
        try:
            prefs = json.loads(user.user_preferences)
            current_duration = int(prefs.get("session_duration_seconds", 3600))
        except (ValueError, TypeError):
            current_duration = 3600

    flash_message = request.session.pop("flash", None)
    csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
    resp = templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "user": user,
            "current_duration": current_duration,
            "csrf_token": csrf_token,
            "flash_message": flash_message,
        },
    )
    csrf_protect.set_csrf_cookie(signed_token, resp)
    return resp


@router.post("/settings", response_class=HTMLResponse)
async def settings_post(
    request: Request,
    response: Response,
    action: str = Form(...),
    csrf_protect: CsrfProtect = Depends(),
) -> HTMLResponse:
    """Handle user settings form submissions.

    Two actions are handled via the `action` hidden field:
      - "session_duration": update session duration preference
      - "change_password": validate and update password hash

    Both redirect back to /settings on success (POST/Redirect/GET pattern).
    """
    await csrf_protect.validate_csrf(request)

    if redirect := _require_auth(request):
        return redirect

    user = try_get_current_user(request)
    user_store: UserStore = request.app.state.user_store

    form_data = await request.form()

    def _settings_error(msg: str, current_duration: int = 3600) -> HTMLResponse:
        csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
        err_resp = templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "user": user,
                "current_duration": current_duration,
                "csrf_token": csrf_token,
                "error_msg": msg,
                "flash_message": None,
            },
        )
        csrf_protect.set_csrf_cookie(signed_token, err_resp)
        return err_resp

    if action == "session_duration":
        raw_duration = form_data.get("session_duration", "")
        try:
            duration_int = int(raw_duration)
        except (ValueError, TypeError):
            return _settings_error("Invalid session duration.")
        if duration_int not in _VALID_SESSION_DURATIONS:
            return _settings_error("Session duration must be 1, 4, or 8 hours.")

        # Merge into existing user_preferences JSON blob
        prefs: dict = {}
        if user.user_preferences:
            try:
                prefs = json.loads(user.user_preferences)
            except (ValueError, TypeError):
                prefs = {}
        prefs["session_duration_seconds"] = duration_int
        user_store.update_user(user.id, user_preferences=json.dumps(prefs))
        request.session["flash"] = "Session duration updated."
        return RedirectResponse("/settings", status_code=303)

    elif action == "change_password":
        current_password = form_data.get("current_password", "")
        new_password = form_data.get("new_password", "")
        confirm_password = form_data.get("confirm_password", "")

        # Current duration for re-render if error
        current_duration = 3600
        if user.user_preferences:
            try:
                prefs = json.loads(user.user_preferences)
                current_duration = int(prefs.get("session_duration_seconds", 3600))
            except (ValueError, TypeError):
                current_duration = 3600

        if not user.hashed_password:
            return _settings_error("Password change is not available for OAuth-only accounts.", current_duration)

        from auth.tokens import verify_password

        if not verify_password(current_password, user.hashed_password):
            return _settings_error("Current password is incorrect.", current_duration)
        if new_password != confirm_password:
            return _settings_error("New passwords do not match.", current_duration)
        pw_error = _validate_password(new_password)
        if pw_error:
            return _settings_error(pw_error, current_duration)

        user_store.update_user(user.id, hashed_password=hash_password(new_password))
        request.session["flash"] = "Password changed successfully."
        return RedirectResponse("/settings", status_code=303)

    else:
        return _settings_error("Unknown action.")


@router.get("/admin/settings", response_class=HTMLResponse)
def admin_settings_form(request: Request, response: Response, csrf_protect: CsrfProtect = Depends()) -> HTMLResponse:
    """Render the admin settings page: OAuth toggles, registration toggle, user management."""
    redirect, current_user = _require_admin_redirect(request)
    if redirect:
        return redirect

    user_store: UserStore = request.app.state.user_store
    app_settings = user_store.get_app_settings()
    all_users = user_store.list_users()
    enabled_providers = get_enabled_providers()  # env-var level (what's configured)

    flash_message = request.session.pop("flash", None)
    csrf_token, signed_token = csrf_protect.generate_csrf_tokens()
    resp = templates.TemplateResponse(
        "admin_settings.html",
        {
            "request": request,
            "current_user": current_user,
            "app_settings": app_settings,
            "users": all_users,
            "enabled_providers": enabled_providers,
            "csrf_token": csrf_token,
            "flash_message": flash_message,
        },
    )
    csrf_protect.set_csrf_cookie(signed_token, resp)
    return resp


@router.post("/admin/settings", response_class=HTMLResponse)
async def admin_settings_post(
    request: Request,
    response: Response,
    action: str = Form(...),
    csrf_protect: CsrfProtect = Depends(),
) -> HTMLResponse:
    """Handle admin settings form submissions.

    Actions (dispatched via hidden `action` field):
      - "toggle_settings": update self_registration/OAuth toggles
      - "delete_user": delete a user by user_id
      - "toggle_admin": promote/demote a user to/from admin role

    Each action redirects back to /admin/settings on success.
    """
    await csrf_protect.validate_csrf(request)

    redirect, current_user = _require_admin_redirect(request)
    if redirect:
        return redirect

    user_store: UserStore = request.app.state.user_store
    form_data = await request.form()

    if action == "toggle_settings":
        updates = {
            "self_registration_enabled": form_data.get("self_registration_enabled") == "1",
            "github_oauth_enabled": form_data.get("github_oauth_enabled") == "1",
            "google_oauth_enabled": form_data.get("google_oauth_enabled") == "1",
        }
        user_store.update_app_settings(**updates)
        request.session["flash"] = "Settings updated."
        return RedirectResponse("/admin/settings", status_code=303)

    elif action == "delete_user":
        raw_id = form_data.get("user_id", "")
        try:
            target_id = int(raw_id)
        except (ValueError, TypeError):
            request.session["flash"] = "Invalid user ID."
            return RedirectResponse("/admin/settings", status_code=303)

        if target_id == current_user.id:
            request.session["flash"] = "You cannot delete your own account."
            return RedirectResponse("/admin/settings", status_code=303)

        target = user_store.get_by_id(target_id)
        if target is None:
            request.session["flash"] = "User not found."
            return RedirectResponse("/admin/settings", status_code=303)

        # Prevent deleting the last admin
        if target.role == "admin" and user_store.count_active_admins() <= 1:
            request.session["flash"] = "Cannot delete the last active admin account."
            return RedirectResponse("/admin/settings", status_code=303)

        user_store.delete_user(target_id)
        request.session["flash"] = f"User '{target.username}' deleted."
        return RedirectResponse("/admin/settings", status_code=303)

    elif action == "toggle_admin":
        raw_id = form_data.get("user_id", "")
        try:
            target_id = int(raw_id)
        except (ValueError, TypeError):
            request.session["flash"] = "Invalid user ID."
            return RedirectResponse("/admin/settings", status_code=303)

        if target_id == current_user.id:
            request.session["flash"] = "You cannot change your own admin status."
            return RedirectResponse("/admin/settings", status_code=303)

        target = user_store.get_by_id(target_id)
        if target is None:
            request.session["flash"] = "User not found."
            return RedirectResponse("/admin/settings", status_code=303)

        # Prevent removing admin from last admin
        new_role = "user" if target.role == "admin" else "admin"
        if new_role == "user" and user_store.count_active_admins() <= 1:
            request.session["flash"] = "Cannot remove admin status from the last active admin."
            return RedirectResponse("/admin/settings", status_code=303)

        user_store.update_user(target_id, role=new_role)
        request.session["flash"] = f"User '{target.username}' role set to '{new_role}'."
        return RedirectResponse("/admin/settings", status_code=303)

    else:
        request.session["flash"] = "Unknown action."
        return RedirectResponse("/admin/settings", status_code=303)
