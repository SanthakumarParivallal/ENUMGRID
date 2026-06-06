#!/usr/bin/env bash
#
# start.sh — ONE command to run EnumGrid. Nothing else required.
#
#   ./start.sh                 fast, no password. Discovers devices with a
#                              specific OS family (macOS/Android/Windows/router).
#   ./start.sh --accurate-os   asks for your password ONCE so nmap can do real
#                              OS/version fingerprinting (-O) on per-host scans.
#   ./start.sh --help          show all options.
#
# It does everything for you: checks prerequisites (and offers to install nmap),
# creates the Python virtualenv, installs backend + frontend dependencies, frees
# the ports if something is stuck, starts BOTH servers, waits until they're
# healthy, and opens your browser. Press Ctrl-C once to stop everything cleanly.
#
# Authorized use only — scan networks you own or are explicitly permitted to test.
# (The backend strictly refuses loopback, multicast, broadcast and, by default,
#  public/internet targets.)

set -euo pipefail

# --------------------------------------------------------------------------- #
# Pretty output
# --------------------------------------------------------------------------- #
if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'
  YEL=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; GRN=""; YEL=""; CYN=""; RST=""
fi
say()  { printf '%s▸%s %s\n' "$CYN" "$RST" "$*"; }
ok()   { printf '%s✓%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '%s!%s %s\n' "$YEL" "$RST" "$*"; }
die()  { printf '%s✖ %s%s\n' "$RED" "$*" "$RST" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# Config / args
# --------------------------------------------------------------------------- #
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

BACKEND_PORT="${BACKEND_PORT:-8011}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
PYTHON="$ROOT/.venv/bin/python"
ACCURATE_OS=0
OPEN_BROWSER=1

usage() {
  cat <<EOF
${BOLD}EnumGrid — ultra-advanced network enumeration${RST}

Usage: ./start.sh [options]

Options:
  --accurate-os, -o   Run the scanner privileged (sudo) so nmap can do real
                      OS + version detection (-O) on per-host scans. Asks for
                      your password once. Without this you still get a specific
                      OS family (macOS/Android/Windows/router) — just not the
                      exact build number.
  --no-open           Don't open the browser automatically.
  --port-back N       Backend port (default ${BACKEND_PORT}).
  --port-front N      Frontend port (default ${FRONTEND_PORT}).
  -h, --help          Show this help.

Examples:
  ./start.sh                 # quick start, no password
  ./start.sh --accurate-os   # exact OS/versions (asks for sudo password)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --accurate-os|-o|--privileged|--os) ACCURATE_OS=1; shift ;;
    --no-open)        OPEN_BROWSER=0; shift ;;
    --port-back)      BACKEND_PORT="${2:?}"; shift 2 ;;
    --port-front)     FRONTEND_PORT="${2:?}"; shift 2 ;;
    -h|--help)        usage; exit 0 ;;
    *) die "Unknown option: $1  (try ./start.sh --help)" ;;
  esac
done

OSNAME="$(uname -s)"

# Tiny sleep that degrades gracefully if `sleep` lacks fractional support.
nap() { sleep "$1" 2>/dev/null || true; }

# Animated ASCII boot banner (reveals line-by-line, like the app's splash).
boot_banner() {
  [[ -t 1 ]] || { printf '\n%sEnumGrid · network enumeration cockpit%s\n\n' "$BOLD" "$RST"; return; }
  clear 2>/dev/null || true
  local lines=(
    "${GRN}  ▟█▙  ${RST}${BOLD}ENUM${RST}${YEL}GRID${RST}"
    "${GRN} ▟███▙ ${RST}${DIM}network enumeration cockpit${RST}"
    "${GRN}▜█████▛${RST}${DIM}ICMP · ARP · NDP · mDNS · NBNS · nmap${RST}"
  )
  printf '\n'
  local l
  for l in "${lines[@]}"; do printf '   %b\n' "$l"; nap 0.10; done
  printf '\n   '
  local msg="booting scan engine "
  local i
  for (( i=0; i<${#msg}; i++ )); do printf '%s%s%s' "$CYN" "${msg:$i:1}" "$RST"; nap 0.012; done
  local f
  for f in '⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏'; do printf '%s%s%s\b' "$GRN" "$f" "$RST"; nap 0.045; done
  printf ' \n\n'
}
boot_banner

# --------------------------------------------------------------------------- #
# 0) Load .env (optional) — picks up secrets like ENUMGRID_NVD_API_KEY and
#    exports them so the backend (and sudo -E backend) inherit them. We parse
#    KEY=VALUE lines ourselves rather than `source` the file, so a stray command
#    in .env can never execute.
# --------------------------------------------------------------------------- #
load_dotenv() {
  local f="$ROOT/.env" n=0 key val
  if [[ ! -f "$f" ]]; then
    [[ -f "$ROOT/.env.example" ]] && printf '   %s(tip: cp .env.example .env and add ENUMGRID_NVD_API_KEY for faster CVE lookups)%s\n' "$DIM" "$RST"
    return 0
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[2]}"
      val="${BASH_REMATCH[3]}"
      val="${val#\"}"; val="${val%\"}"   # strip surrounding double quotes
      val="${val#\'}"; val="${val%\'}"   # strip surrounding single quotes
      [[ -z "$val" ]] && continue        # skip empty placeholders
      export "$key=$val"
      n=$((n + 1))
    fi
  done < "$f"
  ok ".env loaded ($n setting$([[ $n -ne 1 ]] && echo s))"
  [[ -n "${ENUMGRID_NVD_API_KEY:-}" ]] && ok "NVD API key detected — faster, higher-rate CVE lookups"
}
load_dotenv

# --------------------------------------------------------------------------- #
# 1) Prerequisites
# --------------------------------------------------------------------------- #
say "Checking prerequisites…"

command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.10+ first."

# --- nmap (the scan engine) ------------------------------------------------- #
if ! command -v nmap >/dev/null 2>&1; then
  warn "nmap is not installed — it's the core scan engine."
  if [[ "$OSNAME" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
    read -r -p "Install nmap now with Homebrew? [Y/n] " ans
    if [[ "${ans:-Y}" =~ ^[Nn] ]]; then
      die "nmap is required. Install it (brew install nmap) and re-run."
    fi
    brew install nmap || die "nmap install failed."
  elif command -v apt-get >/dev/null 2>&1; then
    read -r -p "Install nmap now with apt (needs sudo)? [Y/n] " ans
    if [[ "${ans:-Y}" =~ ^[Nn] ]]; then
      die "nmap is required. Install it (sudo apt-get install nmap) and re-run."
    fi
    sudo apt-get update && sudo apt-get install -y nmap || die "nmap install failed."
  else
    die "Please install nmap (https://nmap.org/download) and re-run."
  fi
fi
ok "nmap $(nmap --version | head -1 | awk '{print $3}')"

# --- node / npm (the UI build tool) ----------------------------------------- #
command -v node >/dev/null 2>&1 || die "Node.js not found. Install Node 18+ (https://nodejs.org) and re-run."
command -v npm  >/dev/null 2>&1 || die "npm not found. Install Node.js (bundles npm) and re-run."
ok "node $(node --version)"

# --------------------------------------------------------------------------- #
# 2) Python virtualenv + backend dependencies (idempotent)
# --------------------------------------------------------------------------- #
if [[ ! -x "$PYTHON" ]]; then
  say "Creating Python virtualenv (.venv)…"
  python3 -m venv .venv || die "Could not create virtualenv."
fi

# Install/refresh deps only when something is actually missing — keeps restarts fast.
if ! "$PYTHON" -c "import fastapi, uvicorn, nmap, reportlab, pydantic, paramiko" >/dev/null 2>&1; then
  say "Installing backend dependencies (first run only)…"
  "$PYTHON" -m pip install --upgrade pip >/dev/null
  "$PYTHON" -m pip install -r backend/requirements.txt >/dev/null || die "pip install failed."
fi
ok "Python environment ready"

# --------------------------------------------------------------------------- #
# 3) Frontend dependencies (idempotent)
# --------------------------------------------------------------------------- #
if [[ ! -d "$ROOT/frontend/node_modules" ]]; then
  say "Installing frontend dependencies (first run only)…"
  ( cd "$ROOT/frontend" && npm install --silent ) || die "npm install failed."
fi
ok "Frontend ready"

# --------------------------------------------------------------------------- #
# 4) Free the ports if something is stuck on them
# --------------------------------------------------------------------------- #
free_port() {
  local port="$1" pids
  if command -v lsof >/dev/null 2>&1; then
    pids="$(lsof -ti tcp:"$port" 2>/dev/null || true)"
    if [[ -n "$pids" ]]; then
      warn "Port $port busy — freeing it (pids: $(echo "$pids" | tr '\n' ' '))"
      # shellcheck disable=SC2086
      kill $pids 2>/dev/null || true
      sleep 1
      pids="$(lsof -ti tcp:"$port" 2>/dev/null || true)"
      # shellcheck disable=SC2086
      [[ -n "$pids" ]] && kill -9 $pids 2>/dev/null || true
    fi
  fi
}
free_port "$BACKEND_PORT"
free_port "$FRONTEND_PORT"

# --------------------------------------------------------------------------- #
# 5) Privileged mode (accurate OS) — cache sudo creds up front
# --------------------------------------------------------------------------- #
SUDO=()
if [[ "$ACCURATE_OS" == "1" ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    say "Accurate OS detection requested — caching sudo credentials (one prompt)…"
    sudo -v || die "sudo authentication failed."
    # Keep the sudo timestamp fresh while we run.
    ( while true; do sudo -n true 2>/dev/null || exit; sleep 50; done ) &
    SUDO_KEEPALIVE=$!
    SUDO=(sudo -E)
  fi
  ok "nmap will run privileged — real OS (-O) + version detection on per-host scans"
else
  say "Fast mode: specific OS family without a password."
  printf '   %s(tip: ./start.sh --accurate-os  → exact OS build numbers via sudo)%s\n' "$DIM" "$RST"
fi

# --------------------------------------------------------------------------- #
# 6) Launch both servers
# --------------------------------------------------------------------------- #
PIDS=()
cleanup() {
  printf '\n'
  say "Shutting down…"
  for pid in "${PIDS[@]+"${PIDS[@]}"}"; do kill "$pid" 2>/dev/null || true; done
  [[ -n "${SUDO_KEEPALIVE:-}" ]] && kill "$SUDO_KEEPALIVE" 2>/dev/null || true
  # If we ran the backend as root, hand the history DB back to you.
  if [[ "$ACCURATE_OS" == "1" && -f "$ROOT/backend/enumgrid_history.db" ]]; then
    sudo chown "$(id -u):$(id -g)" "$ROOT"/backend/enumgrid_history.db* 2>/dev/null || true
  fi
  wait 2>/dev/null || true
  ok "Stopped. Bye!"
}
trap cleanup INT TERM EXIT

say "Starting backend  → http://127.0.0.1:${BACKEND_PORT}  ${DIM}(FastAPI + nmap)${RST}"
(
  cd "$ROOT/backend"
  exec "${SUDO[@]+"${SUDO[@]}"}" "$PYTHON" -m uvicorn app:app --host 127.0.0.1 --port "$BACKEND_PORT" \
    >"$ROOT/.backend.log" 2>&1
) &
PIDS+=("$!")

# Wait for the backend to report healthy (up to ~30s), with a live spinner.
printf '%s▸%s Waiting for the scan engine to come up ' "$CYN" "$RST"
healthy=0
spin='|/-\'
for n in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${BACKEND_PORT}/api/health" >/dev/null 2>&1; then
    healthy=1; break
  fi
  if [[ -t 1 ]]; then
    c="${spin:$(( n % 4 )):1}"
    printf '%s%s%s\b' "$GRN" "$c" "$RST"
  fi
  sleep 0.5
done
printf ' \n'
if [[ "$healthy" != "1" ]]; then
  warn "Backend didn't answer in time — last log lines:"
  tail -n 20 "$ROOT/.backend.log" 2>/dev/null || true
  die "Backend failed to start. See $ROOT/.backend.log"
fi
priv="$(curl -fsS "http://127.0.0.1:${BACKEND_PORT}/api/health" 2>/dev/null || true)"
if echo "$priv" | grep -q '"privileged": *true'; then
  ok "Scan engine healthy — privileged (real nmap -O available)"
else
  ok "Scan engine healthy"
fi

say "Starting frontend → http://localhost:${FRONTEND_PORT}  ${DIM}(Vite + React)${RST}"
(
  cd "$ROOT/frontend"
  exec npm run dev -- --port "$FRONTEND_PORT" --strictPort >"$ROOT/.frontend.log" 2>&1
) &
PIDS+=("$!")

# Wait for the UI dev server.
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${FRONTEND_PORT}" >/dev/null 2>&1; then break; fi
  sleep 0.5
done

URL="http://localhost:${FRONTEND_PORT}"
printf '\n%s════════════════════════════════════════════════════%s\n' "$GRN" "$RST"
ok "${BOLD}EnumGrid is running.${RST}"
printf '   Open:  %s%s%s\n' "$BOLD" "$URL" "$RST"
printf '   The target auto-fills to your network — just click %sStart Scan%s.\n' "$BOLD" "$RST"
printf '   Look for the green %sLIVE STREAM%s badge. Press %sCtrl-C%s to stop.\n' "$GRN" "$RST" "$BOLD" "$RST"
printf '%s════════════════════════════════════════════════════%s\n\n' "$GRN" "$RST"

if [[ "$OPEN_BROWSER" == "1" ]]; then
  if [[ "$OSNAME" == "Darwin" ]]; then open "$URL" 2>/dev/null || true
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" 2>/dev/null || true
  fi
fi

# Wait until either server exits; the trap cleans up the rest.
wait -n 2>/dev/null || wait
