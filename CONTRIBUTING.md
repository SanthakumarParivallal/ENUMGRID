# Contributing to ENUMGRID

Bug reports, fixes, tests and docs are all welcome.

## Ground rules

- **Authorized use only.** Never include scan output from systems you don't own
  or aren't authorized to test. Use the bundled docker testbed for examples.
- Keep results real. The tool must never present fabricated data as a live result.
- Every change ships with tests and must pass the full gate (below).

## Dev setup

```bash
git clone https://github.com/SanthakumarParivallal/ENUMGRID.git
cd ENUMGRID
./start.sh --no-sudo          # venv + deps + both servers (no password)
# or: make setup && make dev
```

The backend lives in `backend/` (FastAPI + python-nmap), the CLI is the single-file
`purple_recon.py`, and the cockpit UI is in `frontend/` (React + Vite + Tailwind).

## The quality gate (must be green before a PR)

```bash
make test        # lint + CLI + backend + evaluation + frontend: the whole gate
```

Or the individual steps, if you want to see each one:

```bash
# Python: lint, security, tests
.venv/bin/python -m ruff check .
.venv/bin/python -m bandit -r purple_recon.py backend/ -c pyproject.toml
.venv/bin/python -m pip_audit -r backend/requirements.txt -r requirements-dev.txt -r requirements.lock
.venv/bin/python -m pytest tests backend evaluation

# Frontend: lint, tests + coverage gate, build, audit
cd frontend && npm run lint && npm test && npm run build && npm audit
```

Invoke the tools as `python -m <tool>` rather than `.venv/bin/<tool>`. The console
scripts embed an absolute interpreter path at install time, so they break if the
checkout is ever moved or renamed, while `python -m` always resolves.

CI (`.github/workflows/ci.yml`) runs the same gate on every push, across six jobs:
lint, security, CLI (Python 3.10 to 3.14), backend, frontend, and a CycloneDX SBOM.

## Style

- Python: `ruff` (lint + import order); type hints; docstrings on public funcs.
- JS/React: keep components small; mirror backend models in `frontend/src/lib/schema.js`.
- Accepted `bandit` and `ruff` exceptions get an inline `# nosec <ID>` or
  `# noqa: <CODE>` with a one-line justification. Blanket ignores are not accepted.

## Regenerating the README screenshot

`docs/dashboard.png` is a real scan of the maintainer's LAN, captured with a
no-dependency Chrome DevTools script:

```bash
./start.sh                       # in one terminal
node scripts/screenshot.mjs      # in another → writes docs/dashboard.png
```

## Commit identity

This repository has a single maintainer, and `.mailmap` maps every historical
spelling of that identity onto one canonical author. Before your first commit, set
the name and address you want attributed:

```bash
git config user.name  "Your Name"
git config user.email "you@example.com"
```

Two things are worth knowing if you care how the repository is attributed:

- `.mailmap` is what `git shortlog -sne`, `git log` and `git blame` honour. When an
  address changes, add a line there instead of rewriting history.
- GitHub's repository Contributors panel does not read `.mailmap`. It counts
  commit-author addresses and `Co-Authored-By:` trailers directly from the objects, so
  an extra address or trailer shows up there as an extra contributor. Only rewriting
  the history changes that panel, and doing so changes every commit id and needs a
  force-push. See the 1.0.0 entry in [`CHANGELOG.md`](CHANGELOG.md).

## Pull requests

1. Branch from `main`.
2. Add or adjust tests; keep the gate green.
3. Update `CHANGELOG.md` and the relevant docs.
4. Open the PR with a clear description of the change and its motivation.
