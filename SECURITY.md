# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x     | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in VulnAdvisor, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.** Instead, use one of the following channels:

- **GitHub private vulnerability reporting:** Use the [Security Advisories](https://github.com/jtberry/vuln-advisor/security/advisories/new) page to submit a report privately. GitHub will notify the maintainers and the report remains confidential until a fix is released.
- **Email:** If you prefer to report via email, contact the project maintainer directly via GitHub profile contact information.

Please include:
- A clear description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested mitigation or fix if known

**Response timeline:** The maintainer will acknowledge the report within 7 days and aim to provide a fix or mitigation plan within 30 days for critical issues.

## Security Practices

VulnAdvisor uses the following security controls:

- **Passwords:** bcrypt hashing with cost factor 12; no plain-text passwords stored
- **Sessions:** HTTP-only JWT access tokens; session expiry enforced client- and server-side
- **CSRF protection:** `fastapi-csrf-protect` on all state-changing form submissions
- **Content-Security-Policy:** CSP header restricts script and style sources to known CDN origins
- **HSTS:** Strict-Transport-Security enforced via Caddy reverse proxy
- **Other security headers:** X-Content-Type-Options, X-Frame-Options, Referrer-Policy set by Caddy
- **SAST:** Bandit static analysis runs on every commit via pre-commit hooks
- **Dependency scanning:** pip-audit runs on every commit via pre-commit hooks
- **API key authentication:** HMAC-SHA256 hashed API keys; raw key shown only once at creation
- **Rate limiting:** Login endpoint rate-limited via slowapi to mitigate brute-force attacks
- **Input validation:** Pydantic v2 models validate all API request payloads
- **SQL injection:** Parameterized queries throughout all SQLAlchemy Core stores; no raw f-string SQL

## Out of Scope

The following are not considered vulnerabilities in VulnAdvisor:

- **Admin-level access issues:** VulnAdvisor is a self-hosted, single-team tool. An admin with direct database or server access can perform privileged operations by design. Security issues that require existing admin credentials are out of scope.
- **CVE data accuracy:** VulnAdvisor aggregates data from public sources (NVD, CISA KEV, EPSS, PoC-in-GitHub). Inaccuracies in the upstream data are not a VulnAdvisor vulnerability.
- **Denial-of-service via resource exhaustion on self-hosted instances:** Resource limits are the responsibility of the infrastructure operator.

## Security Changelog

Significant security improvements are noted in the [CHANGELOG](CHANGELOG.md) (if present) or in release notes.
