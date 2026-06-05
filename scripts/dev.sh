#!/usr/bin/env bash
#
# dev.sh — start the WHOLE platform with one command.
#
# Runs the FastAPI backend (the *real* scanner) on :8011 and the Vite frontend
# on :5173 together, and tears both down cleanly on Ctrl-C. This exists because
# running the frontend alone makes the dashboard fall back to the offline mock
# engine (fake 10.0.0.x devices, amber "DEMO STREAM" badge) — which looks broken.
# One command, both servers, no footgun.
#
# Usage:   ./scripts/dev.sh        (or: make dev)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BACKEND_PORT="${BACKEND_PORT:-8011}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
PYTHON="$ROOT/.venv/bin/python"

# --- preflight: fail with a helpful message, not a stack trace -------------- #
if [[ ! -x "$PYTHON" ]]; then
  echo "✖ No virtualenv at .venv — run 'make setup' first." >&2
  exit 1
fi
if [[ ! -d "$ROOT/frontend/node_modules" ]]; then
  echo "✖ frontend/node_modules missing — run 'make setup' (or 'cd frontend && npm install')." >&2
  exit 1
fi

pids=()
cleanup() {
  echo ""
  echo "▸ shutting down…"
  for pid in "${pids[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# --- backend (real scanner) ------------------------------------------------- #
echo "▸ backend  → http://127.0.0.1:${BACKEND_PORT}  (FastAPI / nmap)"
(
  cd "$ROOT/backend"
  exec "$PYTHON" -m uvicorn app:app --host 127.0.0.1 --port "$BACKEND_PORT"
) &
pids+=("$!")

# --- frontend (cockpit UI) -------------------------------------------------- #
echo "▸ frontend → http://localhost:${FRONTEND_PORT}  (Vite / React)"
(
  cd "$ROOT/frontend"
  exec npm run dev -- --port "$FRONTEND_PORT"
) &
pids+=("$!")

echo ""
echo "✓ Both servers up. Open  http://localhost:${FRONTEND_PORT}"
echo "  The target auto-fills to your network — just click Start Scan."
echo "  Look for the green 'LIVE STREAM' badge (amber = backend not reachable)."
echo "  Press Ctrl-C to stop both."
echo ""

# Wait for either child to exit; cleanup() handles the rest.
wait -n 2>/dev/null || wait
