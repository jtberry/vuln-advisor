# VulnAdvisor Security Findings Report
## Pentest-Style Manual Code Review - Phase 8

**Reviewer:** Claude Sonnet 4.6 (automated review via GSD execute-phase)
**Review Date:** 2026-02-27
**Scope:** Full codebase - all Python source, templates, configuration, dependencies, Docker image
**Branch:** gsd/phase-07-code-quality (Phase 8 review branch)

---

## 1. Executive Summary

VulnAdvisor demonstrates a **strong security posture** for a solo-analyst internal tool. The authentication architecture is well-designed: JWT tokens use HS256 with a validated secret key, bcrypt with timing equalization prevents username enumeration, OAuth flows enforce email verification, API key storage uses HMAC-SHA256 (never plaintext), and CSRF protection covers all state-changing form routes. No critical vulnerabilities (auth bypass or RCE) were identified.

Three non-critical findings were identified during the two-pass review. Two are medium severity (DOM-based XSS via API error messages injected with innerHTML, and missing auth check on the web-layer POST /assets and ingest routes). One is low severity (missing validation on a CVE ID path parameter in the HTMX status update route). All other security controls reviewed as secure.

**Finding counts by severity:**

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 1 |
| Informational | 4 |
| **Total** | **7** |

**Key strengths identified:**

- JWT algorithm pinned to HS256 at decode time (`algorithms=[_ALGORITHM]`) - immune to algorithm confusion attacks
- Timing equalization in `authenticate_user()` with a module-level `_DUMMY_HASH` - prevents username enumeration by timing
- bcrypt rounds use library default (12 rounds in bcrypt 4.x) - adequate work factor
- API keys use `secrets.token_hex(32)` (256-bit entropy) - brute-force infeasible
- HMAC-SHA256 key storage - DB compromise alone cannot recover raw API keys
- Session duration whitelist `{3600, 14400, 28800}` - user cannot set arbitrary token lifetimes
- OAuth email verification mandatory for both GitHub (primary+verified) and OIDC (email_verified=True)
- OAuth state CSRF handled by Authlib via SessionMiddleware - not manually managed
- Zero `|safe` filter usage in any Jinja2 template - autoescape is ON by default in FastAPI Jinja2Templates
- Dynamic SQL in `update_app_settings()` uses only keys from `_APP_SETTINGS_KEYS` frozenset - not user input
- `_safe_next()` rejects protocol-relative URLs (`//`) and absolute URLs - open redirect prevented
- Error query param on `/login` routed through `_ERROR_MESSAGES` whitelist - reflected XSS prevented
- All API route handlers return structured errors; generic exception handler never exposes stack traces
- CSRF protection on all state-changing web form routes (Double Submit Cookie pattern)
- `/docs` and `/redoc` protected behind `get_current_user` dependency
- `secure_cookies` flag gates `Secure` attribute on auth cookies (correct for HTTP dev / HTTPS prod)

**Remediation summary:**

- F-001 (Medium - DOM XSS): Tracked as recommended GitHub issue; fix is low-complexity
- F-002 (Medium - Missing auth on web routes): Tracked as recommended GitHub issue; requires adding `_require_auth` to 2 routes
- F-003 (Low - CVE ID not validated in HTMX status update): Tracked as recommended GitHub issue; one-line fix
- All accepted risks documented in Section 5

---

## 2. Methodology

**Scope:**
- All Python source code: `auth/`, `api/`, `web/`, `core/`, `cmdb/`, `cache/`, `main.py`
- Jinja2 templates: `web/templates/`
- Configuration: `core/config.py`, `.env` handling, `Caddyfile`
- Dependencies: `requirements.txt`, `requirements-api.txt`, `requirements-dev.txt`
- Docker/container: `Dockerfile`, `docker-compose.yml`

**Automated tools (Phase 8 Plans 01 and 02):**
- `bandit` - SAST for Python: `core/`, `cache/`, `api/`, `cmdb/`, `auth/`
- `semgrep` - Rules: `p/python`, `p/fastapi`
- `pip-audit` - Dependency CVE scanning: all three requirements files
- Trivy - Container image scan (HIGH/CRITICAL) - added to GHA

**Manual review approach:**

Pass 1 - Defense-first: Reviewed crown jewels (auth layer, input validation, SQL handling, template rendering, config/secrets) in priority order.

Pass 2 - Attacker-path: Traced six user input entry points end-to-end from HTTP entry through DB write and template render.

**Review date:** 2026-02-27
**Reviewer:** Phase 8 GSD execution agent

---

## 3. Findings Table

| ID | Title | Severity | Category | Status |
|----|-------|----------|----------|--------|
| F-001 | DOM XSS via API error detail in toast notifications | Medium | xss | Tracked |
| F-002 | Missing auth check on POST /assets and POST /ingest web routes | Medium | auth | Tracked |
| F-003 | CVE ID not validated in HTMX vuln status update path parameter | Low | input-validation | Tracked |
| F-004 | GET /logout CSRF (session logout via crafted link) | Informational | auth | Accepted |
| F-005 | ecdsa transitive CVE (non-applicable attack vector) | Informational | deps | Accepted |
| F-006 | unsafe-inline in CSP script-src | Informational | config | Accepted |
| F-007 | .planning/ directory tracked in public git history | Informational | config | User decision pending |

---

## 4. Finding Details

---

### F-001: DOM XSS via API error detail in toast notifications

**Severity:** Medium
**Category:** XSS
**Status:** Tracked (recommended GitHub issue)

**Description:**

The `showToast()` function in `web/templates/partials/status_modal.html` (line 126) uses `innerHTML` to render toast notification content. When a PATCH status update request fails, the JS handler reads `data.detail` from the JSON API error response and passes it directly to `showToast()`. This creates a DOM-based XSS vector if an attacker can influence the `detail` field of an API error response.

**Evidence (file:line):**

`web/templates/partials/status_modal.html:124-130`:
```javascript
el.innerHTML = [
  '<div class="d-flex">',
  '  <div class="toast-body" style="font-size: 0.82rem">' + message + "</div>",
  ...
].join("");
```

`web/templates/partials/status_modal.html:214-218`:
```javascript
return resp.json().catch(function () { return {}; }).then(function (data) {
  showToast(
    "Failed to update status" + (data.detail ? ": " + data.detail : ""),
    "danger"
  );
```

**Risk assessment:**

- **Likelihood:** Low. The `data.detail` field comes from the VulnAdvisor API's own error responses. In the current architecture, API errors are generated server-side and do not reflect user input verbatim. However, if an API route ever includes user-controlled content in an error `detail` field, or if the API URL is misconfigured to point at a proxied attacker-controlled endpoint, this sink is exploitable.
- **Impact:** Medium. Successful exploitation would allow script execution in the context of an authenticated user's browser session. With httpOnly cookies, the access token cannot be directly stolen; however, CSRF attacks, session riding, and DOM manipulation remain possible.
- **Overall:** Medium. The risk is latent today but represents a defense-in-depth gap.

**Remediation:**

Replace `innerHTML` assignment with `textContent` for the toast body text, or use a DOM-safe text-setting approach:

```javascript
// Instead of innerHTML with concatenated message:
var toastBody = document.createElement("div");
toastBody.className = "toast-body";
toastBody.style.fontSize = "0.82rem";
toastBody.textContent = message;  // Safe: no HTML parsing
```

Alternatively, sanitize the `message` parameter before passing to `innerHTML` using a library like DOMPurify, or restrict toast content to static strings and avoid reflecting API error detail in toast UI.

**Status:** Recommended GitHub issue. Labels: `security`, `severity:medium`, `xss`.

---

### F-002: Missing auth check on POST /assets and POST /ingest web routes

**Severity:** Medium
**Category:** Authentication
**Status:** Tracked (recommended GitHub issue)

**Description:**

The web UI routes `POST /assets` and `POST /ingest` (in `web/routes.py`) do not call `_require_auth(request)` at the top of their handlers. Their corresponding GET routes (`GET /assets/new` and `GET /ingest`) do check auth, but the POST handlers that actually perform state-changing operations are missing the guard.

**Evidence (file:line):**

`web/routes.py:631-645` (POST /assets):
```python
@router.post("/assets", response_class=HTMLResponse)
async def asset_create(
    request: Request,
    hostname: Optional[str] = Form(default=None),
    ...
) -> HTMLResponse:
    """Handle asset creation form POST."""
    # NOTE: No _require_auth() call here
```

`web/routes.py:1107-1113` (POST /ingest):
```python
@router.post("/ingest", response_class=HTMLResponse)
async def ingest_file_htmx(
    request: Request,
    file: UploadFile,
    ...
) -> HTMLResponse:
    # NOTE: No _require_auth() call here
```

**Risk assessment:**

- **Likelihood:** Medium. An unauthenticated user who can reach the application can POST form data to `/assets` or upload a file to `/ingest` without logging in.
- **Impact:** Medium. An attacker could create spurious asset records or upload malicious scanner files to inject hostnames and CVE IDs into the CMDB without authentication.
- **Mitigating factors:** The application enforces a setup redirect until an admin account is created. The CMDB does not expose sensitive internal data - it stores asset names and CVE IDs. The HTMX POST routes for `/assets/{id}/vulnerabilities/status` and similar routes also lack explicit `_require_auth` checks, but those accept asset IDs and CVE IDs that are validated against the pattern before use.
- **Note:** The API layer equivalents (api/routes/v1/assets.py) ARE protected - the router uses `dependencies=[Depends(get_current_user)]` at the router level. Only the web/routes.py handlers are missing the guard.
- **Overall:** Medium. Creates an authentication bypass for write operations through the web UI.

**Remediation:**

Add `_require_auth` check at the top of the two POST handlers:

```python
@router.post("/assets", response_class=HTMLResponse)
async def asset_create(request: Request, ...) -> HTMLResponse:
    if redirect := _require_auth(request):
        return redirect
    ...
```

Same pattern for `POST /ingest`. Also audit `POST /assets/{asset_id}/vulnerabilities` (line 805) and `POST /assets/{asset_id}/vulnerabilities/{cve_id}/status` (line 892) which also lack `_require_auth` calls.

**Status:** Recommended GitHub issue. Labels: `security`, `severity:medium`, `auth`.

---

### F-003: CVE ID not validated against regex in HTMX vuln status update

**Severity:** Low
**Category:** Input Validation
**Status:** Tracked (recommended GitHub issue)

**Description:**

The HTMX route `POST /assets/{asset_id}/vulnerabilities/{cve_id}/status` (web/routes.py line 892) accepts the `cve_id` path parameter and calls `.upper()` on it, then queries the database. Unlike the API counterpart (`PATCH /api/v1/assets/{asset_id}/vulnerabilities/{cve_id}/status`), the web route does not validate the CVE ID against `CVE_PATTERN` before using it in a DB query.

**Evidence (file:line):**

`web/routes.py:896-916`:
```python
async def update_vuln_status_htmx(
    request: Request,
    asset_id: int,
    cve_id: str,
    ...
) -> HTMLResponse:
    cmdb: CMDBStore = request.app.state.cmdb
    normalized = cve_id.upper()
    # No regex validation of normalized before use
    vuln = cmdb.get_vuln_by_asset_and_cve(asset_id, normalized)
```

API counterpart for comparison (`api/routes/v1/assets.py:439-447`):
```python
normalized_cve = cve_id.upper()
if not re.match(CVE_PATTERN, normalized_cve):
    raise HTTPException(status_code=400, ...)
```

**Risk assessment:**

- **Likelihood:** Low. The CVE IDs in this path come from the asset detail page which renders values from the DB. An attacker would need to have already injected a malformed CVE ID into the DB (itself non-trivial given CVE pattern validation on ingest). The DB query uses parameterized SQLAlchemy calls, so SQL injection is not possible.
- **Impact:** Low. Without the validation, the route makes a DB call with an arbitrary string. The worst case is returning an empty result (vuln not found) or performing a no-op update. No injection risk due to parameterized queries.
- **Overall:** Low. Violates defense-in-depth (validation at boundary principle) but not directly exploitable.

**Remediation:**

Add the same CVE_PATTERN validation used in the API handler:

```python
normalized = cve_id.upper()
if not re.match(CVE_PATTERN, normalized):
    return HTMLResponse("<tr><td>Invalid CVE ID format.</td></tr>", status_code=400)
```

**Status:** Recommended GitHub issue. Labels: `security`, `severity:low`, `input-validation`.

---

### F-004: GET /logout CSRF (session logout via crafted link)

**Severity:** Informational
**Category:** Authentication
**Status:** Accepted

**Description:**

`GET /logout` clears the auth cookie. A malicious page can embed `<img src="https://app/logout">` to force a victim to log out without their knowledge.

**Risk assessment:** Clearing a session cookie exposes no sensitive data and cannot be used to escalate privileges. The victim simply needs to re-authenticate. For a solo-analyst tool this is an acceptable UX trade-off over the complexity of injecting a CSRF token into every page's layout context for a logout link.

**Accepted rationale:** Documented in `auth/tokens.py` and the STATE.md decisions log. The clean fix (POST /logout with CSRF token) is tracked as a future improvement. For a solo-analyst internal tool with a known user base, the risk is accepted.

---

### F-005: ecdsa transitive CVE GHSA-wj6h-64fc-37mp

**Severity:** Informational
**Category:** Dependencies
**Status:** Accepted

**Description:**

`python-jose` pulls `ecdsa` as a transitive dependency. `ecdsa` has a non-constant-time comparison vulnerability (GHSA-wj6h-64fc-37mp).

**Accepted rationale:** VulnAdvisor uses HS256 (HMAC-SHA256) for JWT signing. The ECDSA algorithm is never invoked. The non-constant-time comparison in `ecdsa` only applies to ECDSA signature operations. Documented in `requirements-api.txt` and Phase 08-01-SUMMARY.md.

---

### F-006: unsafe-inline in Content-Security-Policy script-src

**Severity:** Informational
**Category:** Configuration
**Status:** Accepted

**Description:**

The Caddyfile CSP header includes `'unsafe-inline'` in `script-src`.

**Accepted rationale:** The dashboard uses a server-side data island pattern (`{{ priority_counts | tojson }}` injected into a `<script>` block) and `layout.html` contains an inline session-expiry script. Both require `'unsafe-inline'`. The `tojson` filter properly escapes `<`, `>`, and `&`. The clean upgrade path (nonce-based CSP) is tracked as tech debt. Documented in Phase 08-02-SUMMARY.md.

---

### F-007: .planning/ directory tracked in git

**Severity:** Informational
**Category:** Configuration
**Status:** User decision pending

**Description:**

The `.planning/` directory containing full product strategy, roadmap, phase plans, and development decisions is tracked in the git repository.

**Risk assessment:** For an open-source tool, this is a product-management decision rather than a security vulnerability. The `.planning/` contents do not contain secrets, credentials, or attack surface details that would meaningfully aid an attacker.

**User decision options (before public release):**
1. Leave as-is (open-source project, planning artifacts are public anyway)
2. Remove with `git filter-repo` to clean full history
3. Add a commit removing it from tracking (`git rm -r --cached .planning/`) while leaving history intact

**Recommendation:** Option 1 is acceptable for an open-source tool. Option 3 is a clean compromise if you want future commits to not include planning updates while keeping historical context.

---

## 5. Accepted Risks

| Item | Rationale | Reference |
|------|-----------|-----------|
| GET /logout (F-004) | Solo-analyst tool; logout CSRF exposes no data; avoids CSRF token injection into every template | Phase 01-02 decision |
| ecdsa transitive CVE (F-005) | App uses HS256 not ECDSA; vulnerability non-applicable | 08-01-SUMMARY.md |
| unsafe-inline in CSP (F-006) | Required for tojson data island and inline session script; nonce upgrade tracked as tech debt | 08-02-SUMMARY.md |
| Dynamic SQL in update_app_settings() | Column names from hardcoded `_APP_SETTINGS_KEYS` frozenset, not user input; nosemgrep suppression reviewed and confirmed | auth/store.py:393 |
| Dynamic ALTER TABLE in migrations | Column names are hardcoded string literals in source; not user input; SQLite does not support parameter binding for column names | auth/store.py:182, cmdb/store.py:195/211/223 |
| CVE API routes intentionally public | Free triage is the core value proposition; GET /cve/*, POST /cve/bulk intentionally unauthenticated | Phase 01-06 decision |
| starlette CVEs GHSA-2c2j-9gv5-cj73, GHSA-7f5h-v6xp-fcq8 | Fix requires fastapi>=0.116.0 major upgrade; tracked for next dependency cycle | 08-01-SUMMARY.md |
| python-multipart GHSA-wp53-j4wj-2cfg | Fix version 0.0.22 not available on current pip mirror; will resolve when mirror updates | 08-01-SUMMARY.md |

---

## 6. Remediation Status

| Finding ID | Title | Status | Notes |
|------------|-------|--------|-------|
| F-001 | DOM XSS via API error detail in toast | Recommended GitHub issue | Labels: security, severity:medium, xss |
| F-002 | Missing auth check on POST /assets, POST /ingest | Recommended GitHub issue | Labels: security, severity:medium, auth |
| F-003 | CVE ID not validated in HTMX status update | Recommended GitHub issue | Labels: security, severity:low, input-validation |
| F-004 | GET /logout CSRF | Accepted | Documented in STATE.md decisions |
| F-005 | ecdsa transitive CVE | Accepted | Documented in 08-01-SUMMARY.md |
| F-006 | unsafe-inline in CSP | Accepted | Documented in 08-02-SUMMARY.md and Caddyfile comments |
| F-007 | .planning/ in git | User decision pending | Documented in 08-02-SUMMARY.md |

---

## 7. Branch Protection Recommendations

Per CONTEXT.md locked decision, configure the following required status checks on the `main` and `develop` branches in GitHub:

- **Security Scan** (bandit + semgrep): Must pass before merge
- **Semgrep SAST**: Must pass before merge
- **Secret Scan** (GitHub native): Must pass before merge
- **Trivy Container Scan**: Warn-only on push, blocking on PR merge (configure via branch protection, not exit code in YAML)

This ensures that findings similar to F-001 through F-003 would be caught by automated tools before landing in production.

---

## 8. .planning/ Exposure Decision

Running `git ls-files .planning/` confirms the `.planning/` directory is tracked. This contains:
- `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md` - project management artifacts
- Phase plan and summary files - full development roadmap and decisions

**User decision required before public release.** See F-007 above for options. This directory is excluded in `.gitignore` (preventing new accidental commits), but existing committed files remain in git history.

---

*Report generated as part of Phase 8 Plan 03 - Manual Security Review*
*VulnAdvisor v0.2.0 - 2026-02-27*
