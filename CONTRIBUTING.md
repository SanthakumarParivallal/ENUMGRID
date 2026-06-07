# Contributing to ENUMGRID

Thanks for your interest in **ENUMGRID: the Enumeration Platform**! Contributions
— bug reports, fixes, tests, docs — are welcome.

## Ground rules

- **Authorized use only.** Never include scan output from systems you don't own
  or aren't authorized to test. Use the bundled docker testbed for examples.
- Keep results **real, never simulated**. The tool must never present fabricated
  data as a live result.
- Every change ships with tests and must pass the full gate (below).

## Dev setup

```bash
git clone https://github.com/SanthakumarParivallal/ENUMGRID.git
cd ENUMGRID
./start.sh --no-sudo          # venv + deps + both servers (no password)
# or: make setup && make dev
```

Backend lives in `backend/` (FastAPI + python-nmap), the CLI is the single-file
`purple_recon.py`, and the cockpit UI is in `frontend/` (React + Vite + Tailwind).

## The quality gate (must be green before a PR)

```bash
# Python: lint, security, tests
.venv/bin/ruff check backend purple_recon.py
.venv/bin/bandit -r purple_recon.py backend/ -c pyproject.toml
.venv/bin/pip-audit -r backend/requirements.txt -r requirements-dev.txt
.venv/bin/python -m pytest backend test_purple_recon.py evaluation

# Frontend: tests + build + audit
cd frontend && npm test && npm run build && npm audit
```

CI (`.github/workflows/ci.yml`) runs the same gate on every push.

## Style

- Python: `ruff` (lint + import order); type hints; docstrings on public funcs.
- JS/React: keep components small; mirror backend models in `frontend/src/lib/schema.js`.
- Accepted `bandit`/`ruff` exceptions get an inline `# nosec <ID>` / `# noqa: <CODE>`
  with a one-line justification — never a blanket ignore.

## Regenerating the README screenshot

`docs/dashboard.png` is a **real** scan of the maintainer's LAN, captured with a
no-dependency Chrome DevTools script (never simulated data):

```bash
./start.sh                       # in one terminal
node scripts/screenshot.mjs      # in another → writes docs/dashboard.png
```

## Pull requests

1. Branch from `main`.
2. Add/adjust tests; keep the gate green.
3. Update `CHANGELOG.md` and relevant docs.
4. Open the PR with a clear description of the change and its motivation.
