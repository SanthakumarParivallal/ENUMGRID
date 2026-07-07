# EnumGrid — Industrial-Level Network Enumeration Platform
# One entry point for setup, running, and the full test suite.
#
#   make setup   # one-time: venv + python deps + npm install
#   make dev     # run backend (:8011) + frontend (:5173) together
#   make test    # CLI + backend + frontend tests + lint
#   make lint    # ruff only
#   make clean   # remove caches / build output
#
# (Override ports:  BACKEND_PORT=9000 FRONTEND_PORT=3000 make dev)

PY      := .venv/bin/python
PIP     := .venv/bin/pip

.DEFAULT_GOAL := help
.PHONY: help setup dev backend frontend test test-cli test-backend test-frontend lint clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

setup: ## One-time setup: create venv, install python + node deps
	@test -d .venv || python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r backend/requirements.txt -r requirements-dev.txt
	cd frontend && npm install
	@echo "✓ setup complete — run 'make dev'"

dev: ## Run backend + frontend together (Ctrl-C stops both)
	@bash scripts/dev.sh

backend: ## Run only the FastAPI backend (:8011)
	cd backend && ../$(PY) -m uvicorn app:app --host 127.0.0.1 --port $(or $(BACKEND_PORT),8011)

frontend: ## Run only the Vite frontend (:5173)
	cd frontend && npm run dev

test: lint test-cli test-backend test-frontend ## Run lint + all test suites
	@echo "✓ all checks passed"

test-cli: ## CLI engine test suite
	$(PY) -m pytest -q

test-backend: ## Backend (scope guard + NSE parsing) test suite
	cd backend && ../$(PY) -m pytest tests/test_scanner.py tests/test_security.py -q

test-frontend: ## Frontend unit tests (Vitest)
	cd frontend && npm test

lint: ## Static analysis (ruff)
	$(PY) -m ruff check .

clean: ## Remove caches and build output
	rm -rf .pytest_cache .ruff_cache __pycache__ backend/__pycache__ \
		frontend/dist frontend/.vite
	find . -name '__pycache__' -type d -not -path './.venv/*' -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "✓ cleaned"
