# EnumGrid: Industrial-Level Network Enumeration Platform
# One entry point for setup, running, and the full test suite.
#
#   make setup   # one-time: venv + python deps + npm install
#   make dev     # run backend (:8011) + frontend (:5173) together
#   make test    # lint + CLI + backend + evaluation + frontend (the full gate)
#   make lint    # ruff only
#   make clean   # remove caches / build output
#
# (Override ports:  BACKEND_PORT=9000 FRONTEND_PORT=3000 make dev)

PY      := .venv/bin/python
PIP     := .venv/bin/pip

.DEFAULT_GOAL := help
.PHONY: help setup dev backend frontend test test-cli test-backend test-eval test-frontend lint clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup: ## One-time setup: create venv, install python + node deps
	@test -d .venv || python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r backend/requirements.txt -r requirements-dev.txt
	cd frontend && npm install
	@echo "✓ setup complete. Run 'make dev'"

dev: ## Run backend + frontend together (Ctrl-C stops both)
	@bash scripts/dev.sh

backend: ## Run only the FastAPI backend (:8011)
	cd backend && ../$(PY) -m uvicorn app:app --host 127.0.0.1 --port $(or $(BACKEND_PORT),8011)

frontend: ## Run only the Vite frontend (:5173)
	cd frontend && npm run dev

# `make test` mirrors the coverage gates CI enforces, so a change that would fail
# CI fails here first instead of after a push. Each suite runs the same coverage-
# gated command its CI job runs: the CLI and every backend module are held at 100%
# line coverage, the frontend lib at 100% (statements/functions/lines). The
# security, build and SBOM jobs (bandit, pip-audit, npm audit, vite build, syft)
# stay CI-only; run `make lint` for ruff.
test: lint test-cli test-backend test-eval test-frontend ## Run lint + every coverage-gated suite (the full gate)
	@echo "✓ all checks passed"

test-cli: ## CLI engine suite at CI's 100% coverage gate (tests/ -> purple_recon.py)
	$(PY) -m pytest tests --cov=purple_recon --cov-report=term-missing --cov-fail-under=100

test-backend: ## Backend suite at CI's 100% coverage gate (backend/tests/ -> every module)
	cd backend && ../$(PY) -m pytest -q tests \
		--cov=adscan --cov=app --cov=audit --cov=campaign --cov=cloudscan --cov=copilot \
		--cov=credscan --cov=cve --cov=discovery --cov=fingerprint --cov=history --cov=jobs \
		--cov=mdns --cov=models --cov=nbns --cov=notify --cov=obs --cov=osfp --cov=osv \
		--cov=passive --cov=provenance --cov=report --cov=scanner --cov=schedule --cov=security \
		--cov=snmp --cov=ssdp --cov=smbscan --cov=threatintel --cov=vulndb --cov=webscan \
		--cov-report=term-missing --cov-fail-under=100

test-eval: ## Evaluation suite + offline CVE accuracy gate (precision & recall == 1.0)
	$(PY) -m pytest evaluation -q
	$(PY) evaluation/cve_precision.py --min-precision 1.0 --min-recall 1.0

test-frontend: ## Frontend unit tests at CI's coverage gate (src/lib at 100%)
	cd frontend && npm run coverage

lint: ## Static analysis (ruff)
	$(PY) -m ruff check .

clean: ## Remove caches and build output
	rm -rf .pytest_cache .ruff_cache __pycache__ backend/__pycache__ \
		frontend/dist frontend/.vite
	find . -name '__pycache__' -type d -not -path './.venv/*' -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "✓ cleaned"
