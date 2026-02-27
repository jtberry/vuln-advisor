# Getting Started

Deploy VulnAdvisor from a clean clone. Three configurations covered:

- [Prerequisites](#prerequisites)
- [Local Dev (Python + venv)](#local-dev-python--venv)
- [Docker (SQLite)](#docker-sqlite)
- [Production (VPS + TLS)](#production-vps--tls)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Tool | Version | Required for |
|------|---------|-------------|
| git | any | all |
| Python | 3.9+ | Local Dev only |
| Docker | any | Docker deployments |
| Docker Compose | v2 (`docker compose`) | Docker deployments |
| make | any | optional, but referenced in this guide |

---

## Local Dev (Python + venv)

For local development and CLI usage without Docker.

```bash
git clone https://github.com/jtberry/vuln-advisor.git
cd vuln-advisor
```

```bash
make venv
source venv/bin/activate
```

```bash
make install
pip install -r requirements-api.txt
```

```bash
cp .env.example .env
# Edit .env: set DEBUG=true (auto-generates SECRET_KEY for local dev)
```

```bash
make dev
```

Navigate to http://localhost:8000. First visit redirects to the setup wizard to create your admin account.

For CLI-only usage (no API server required), see [docs/CLI.md](CLI.md).

---

## Docker (SQLite)

Runs the full stack (app + Caddy reverse proxy) with SQLite storage.

```bash
git clone https://github.com/jtberry/vuln-advisor.git
cd vuln-advisor
```

```bash
make setup
```

```bash
make docker-up
```

Navigate to https://localhost. The browser will warn about a self-signed certificate -- this is expected and safe to proceed for local use.

First visit redirects to the setup wizard to create your admin account.

---

## Production (VPS + TLS)

Deploy to a self-hosted VPS (DigitalOcean, Linode, Hetzner, etc.). Caddy auto-provisions a Let's Encrypt TLS certificate on the first request.

**1. Provision a VPS and point your domain's DNS A record at the server IP.**

**2. Open ports 80 and 443 in the firewall.**

**3. Clone and configure:**

```bash
git clone https://github.com/jtberry/vuln-advisor.git
cd vuln-advisor
make setup
```

**4. Edit `.env` for production:**

```
# Your public hostname -- Caddy uses this for TLS cert provisioning
DOMAIN=vuln.example.com

# Required in production
DEBUG=false
SECURE_COOKIES=true
```

**5. Start:**

```bash
make docker-up
```

Caddy provisions the TLS certificate automatically on the first HTTPS request to your domain. No additional configuration required.

Navigate to https://vuln.example.com. First visit redirects to the setup wizard.

> **PostgreSQL support** is planned for a future release. The current deployment uses SQLite, which is appropriate for solo-analyst use. See GitHub issues #45 and #46 for migration tracking.

---

## Troubleshooting

### `docker-compose: command not found`

Compose v1 used `docker-compose` (hyphen). This project uses Compose v2 syntax: `docker compose` (space, no hyphen). Install Docker Desktop or Docker Engine with the Compose plugin.

### Browser warns about certificate on `https://localhost`

This is expected. When `DOMAIN=localhost`, Caddy uses an internally-generated self-signed certificate (`tls internal`). Click through the warning -- it is safe for local use. For a trusted cert, use a real domain (see the Production section).

### `make setup` fails with `.env already exists`

`make setup` exits early if `.env` exists to avoid overwriting a generated `SECRET_KEY`. To reset from scratch:

```bash
rm .env
make setup
```

### Windows users

Use WSL2 or Docker Desktop for Windows. Native Windows paths and line endings can cause issues with the Makefile and shell scripts.

---

## Further Reading

- [CLI usage and flags](CLI.md)
- [REST API reference](api-reference.md)
- [Architecture and design](architecture.md)
