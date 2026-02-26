PYTHON := python
VENV   := venv
BIN    := $(VENV)/bin

.DEFAULT_GOAL := help

# ── Help ─────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Setup ─────────────────────────────────────────────────────────────────────

.PHONY: venv install install-dev install-api

venv: ## Create virtual environment
	python3 -m venv $(VENV)
	@echo "  Activate with: source $(VENV)/bin/activate"


	pip install -r requirements.txt

install-dev: ## Install all deps and set up pre-commit hooks
	pip install -r requirements.txt -r requirements-dev.txt
	pre-commit install

install-api: ## Install API dependencies (walk phase)
	pip install -r requirements-api.txt

# ── Code quality ──────────────────────────────────────────────────────────────

.PHONY: lint format security check smoke test

lint: ## Check formatting and linting without auto-fixing
	black --check .
	isort --check-only .
	ruff check .

format: ## Auto-fix formatting (black + isort)
	black .
	isort .

security: ## Run security checks (bandit + pip-audit + semgrep)
	bandit -r core/ cache/ api/ cmdb/ -q
	pip-audit -r requirements.txt
	semgrep scan --config "p/python" --config "p/fastapi" --error --quiet .

smoke: ## Verify all modules import cleanly
	$(PYTHON) -c "from core.enricher import enrich; \
	              from core.formatter import print_terminal, print_summary; \
	              from core.fetcher import fetch_nvd; \
	              from cache.store import CVECache; \
	              from cmdb.store import CMDBStore; \
	              from cmdb.ingest import parse_csv, parse_trivy_json; \
	              print('  All imports OK')"

check: lint security smoke ## Run all quality checks (lint + security + smoke)

test: ## Run unit tests with coverage report
	pytest

# ── Run ───────────────────────────────────────────────────────────────────────

.PHONY: run run-file run-api

run: ## Triage a single CVE  (usage: make run CVE=CVE-2021-44228)
	$(PYTHON) main.py $(CVE)

run-file: ## Triage CVEs from a file  (usage: make run-file FILE=cves.txt)
	$(PYTHON) main.py --file $(FILE)

run-api: ## Start the API server  (walk phase)
	uvicorn asgi:app --reload --host 0.0.0.0 --port 8000

# ── Clean ─────────────────────────────────────────────────────────────────────

.PHONY: clean kill-api

kill-api: ## Kill any running API server on port 8000
	@pid=$$(lsof -ti :8000 2>/dev/null || ss -tlnp 2>/dev/null | grep ':8000 ' | sed -n 's/.*pid=\([0-9]*\).*/\1/p'); \
	if [ -n "$$pid" ]; then \
		kill $$pid && echo "  Killed PID $$pid on port 8000"; \
	else \
		echo "  No process found on port 8000"; \
	fi

clean: ## Remove build artifacts, cache files, and compiled bytecode
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -f cache/*.db
