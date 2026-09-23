#!/usr/bin/env bash
#
# start.sh: ONE command to run EnumGrid. Nothing else required.
#
#   ./start.sh                 starts everything. No password, ever. Root-only
#                              scan techniques auto-adapt, and if you want the
#                              real ones you raise them from inside the app (the
#                              privilege pill in the command bar → Elevate),
#                              which asks for your sudo password there and holds
#                              it in the backend's memory for that session only.
#   ./start.sh --accurate-os   opt in to the OLD behaviour: prompt in the
#                              terminal at launch and run the backend under sudo
#                              for the whole run.
#   ./start.sh --help          show all options.
#
# It does everything for you: checks prerequisites (and offers to install nmap),
# creates the Python virtualenv, installs backend + frontend dependencies, frees
# the ports if something is stuck, starts BOTH servers, waits until they're
# healthy, and opens your browser. Press Ctrl-C once to stop everything cleanly.
#
# Authorized use only. Scan networks you own or are explicitly permitted to test.
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
# The boot banner shades a 3-D wordmark across a six-stop ramp, which needs the
# 256-colour palette. On a 16-colour terminal it still draws in bold face and dim
# side, so this only decides how much depth we get, never whether it renders.
if [[ -t 1 ]] && [[ "$(tput colors 2>/dev/null || echo 0)" -ge 256 ]]; then C256=1; else C256=0; fi
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
# Unprivileged by default: no password prompt at launch. Root-only techniques
# auto-adapt (SYN→connect, UDP→connect, -O skipped) so every profile still runs,
# and full fidelity is one click away in the app: the privilege pill elevates
# this session in place, no restart. `--accurate-os` opts back into running the
# whole backend under sudo from the start.
ACCURATE_OS=0
OPEN_BROWSER=1
TLS=0

usage() {
  cat <<EOF
${BOLD}EnumGrid: ultra-advanced network enumeration${RST}

Usage: ./start.sh [options]

Options:
  (unprivileged is the DEFAULT: no password prompt. Every scan profile runs;
   root-only techniques auto-adapt. For real -sS/-sU/-O, click the privilege
   pill in the app's command bar and Elevate: it takes your sudo password in
   the UI, keeps it in backend memory for that session only, and needs no
   restart. Nothing is written to disk and nothing is logged.)
  --accurate-os       Prompt for your password in the terminal at launch and run
                      the backend under sudo for the whole session, instead of
                      elevating from the app. Same scan fidelity either way.
  --no-sudo           Explicitly unprivileged (this is already the default).
  --tls               Serve the backend over HTTPS with a self-signed cert
                      (auto-generated). The UI proxy uses it transparently.
  --no-open           Don't open the browser automatically.
  --port-back N       Backend port (default ${BACKEND_PORT}).
  --port-front N      Frontend port (default ${FRONTEND_PORT}).
  -h, --help          Show this help.

Examples:
  ./start.sh                 # no password; elevate from inside the app if needed
  ./start.sh --accurate-os   # prompt at launch and run the backend under sudo
  ./start.sh --tls           # encrypt the backend (HTTPS)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --accurate-os|-o|--privileged|--os) ACCURATE_OS=1; shift ;;
    --no-sudo|--unprivileged) ACCURATE_OS=0; shift ;;
    --tls)            TLS=1; shift ;;
    --no-open)        OPEN_BROWSER=0; shift ;;
    --port-back)      BACKEND_PORT="${2:?}"; shift 2 ;;
    --port-front)     FRONTEND_PORT="${2:?}"; shift 2 ;;
    -h|--help)        usage; exit 0 ;;
    *) die "Unknown option: $1  (try ./start.sh --help)" ;;
  esac
done

# Backend scheme + (optional) TLS cert/uvicorn flags, resolved below.
BACKEND_SCHEME="http"
SSL_ARGS=()

OSNAME="$(uname -s)"

# Tiny sleep that degrades gracefully if `sleep` lacks fractional support.
nap() { sleep "$1" 2>/dev/null || true; }

# --------------------------------------------------------------------------- #
# Animated 3-D boot banner
# --------------------------------------------------------------------------- #
# The wordmark is drawn in two materials: `█` is the lit FACE of each letter and
# the box-drawing glyphs (`╔ ═ ╝ ║`) are the extruded SIDE falling away from it.
# Painting those two from different points on one colour ramp is the whole 3-D
# trick, and because the split is by glyph rather than by position, a highlight
# can travel down the rows by re-painting colour alone, never re-flowing the art.
#
# ENUM and GRID are kept as separate columns rather than one string so each half
# can carry its own ramp: steel and amber, the same two-tone wordmark the app
# header shows. Splitting a row by character index instead would break under a
# non-UTF-8 locale, where bash slices bytes and would cut a glyph in half.
_WM_L=(
'███████╗███╗   ██╗██╗   ██╗███╗   ███╗'
'██╔════╝████╗  ██║██║   ██║████╗ ████║'
'█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║'
'██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║'
'███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║'
'╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝'
)
_WM_R=(
' ██████╗ ██████╗ ██╗██████╗ '
'██╔════╝ ██╔══██╗██║██╔══██╗'
'██║  ███╗██████╔╝██║██║  ██║'
'██║   ██║██╔══██╗██║██║  ██║'
'╚██████╔╝██║  ██║██║██████╔╝'
' ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ '
)
_WM_W=66   # printed width of the two halves together

# Face/side pairs per row, darkening downwards so the light reads as overhead.
# The amber ramp is the app's own brand sweep (#FFD166 → #FFB300 → #FF8F3F) at
# its nearest 256-colour stops. Terminals below 256 colours fall back to
# bold/dim, which still separates face from side. The depth survives, the hue
# doesn't.
_wm_palette() {
  _FACE_L=(255 253 251 249 247 245); _SIDE_L=(238 238 237 237 236 236)
  _FACE_R=(222 221 220 214 208 202); _SIDE_R=(94  94  94  58  58  58)
  _LIT_L=$'\033[38;5;231m'; _LIT_R=$'\033[38;5;230m'
  _REF_L=$'\033[38;5;235m'; _REF_R=$'\033[38;5;236m'
}

# Wrap every `█` in the face colour `$2` and leave the rest in the side colour
# `$3`. One pass of parameter expansion, no per-character loop, so it is fast
# and safe on a byte-oriented locale.
_wm_paint() { local s="$1"; printf '%s%s%s' "$3" "${s//█/${RST}${2}█${3}}" "$RST"; }

# `lit` is the row the power-on highlight is crossing (-1 for none).
_wm_row() {
  local i="$1" lit="$2" fl fr sl sr
  if [[ "$C256" == "1" ]]; then
    fl=$'\033[38;5;'"${_FACE_L[$i]}"'m'; sl=$'\033[38;5;'"${_SIDE_L[$i]}"'m'
    fr=$'\033[38;5;'"${_FACE_R[$i]}"'m'; sr=$'\033[38;5;'"${_SIDE_R[$i]}"'m'
    [[ "$i" == "$lit" ]] && { fl="$_LIT_L"; fr="$_LIT_R"; }
  else
    fl=$'\033[1;37m'; sl="$DIM"; fr=$'\033[1;33m'; sr="$DIM"
    [[ "$i" == "$lit" ]] && { fl=$'\033[1;37m'; fr=$'\033[1;37m'; }
  fi
  printf '  '
  _wm_paint "${_WM_L[$i]}" "$fl" "$sl"
  _wm_paint "${_WM_R[$i]}" "$fr" "$sr"
  printf '\n'
}

_wm_frame() { local lit="$1" i; for (( i=0; i<6; i++ )); do _wm_row "$i" "$lit"; done; }

# The wordmark's own base row, flipped top-for-bottom and printed nearly black:
# the letters pick up a reflection, which is what sells them as standing ON
# something rather than floating. The base row only ever contains `╚ ═ ╝`, so
# swapping the two corners is a complete mirror and needs no placeholder pass.
_wm_reflection() {
  local l="${_WM_L[5]}" r="${_WM_R[5]}"
  l="${l//╚/╔}"; l="${l//╝/╗}"
  r="${r//╚/╔}"; r="${r//╝/╗}"
  printf '  '
  if [[ "$C256" == "1" ]]; then
    printf '%s%s%s%s%s\n' "$_REF_L" "$l" "$_REF_R" "$r" "$RST"
  else
    printf '%s%s%s%s\n' "$DIM" "$l" "$r" "$RST"
  fi
}

boot_banner() {
  # Not a terminal, or one too narrow to hold the 66-column wordmark: say the
  # same thing on one line rather than wrap the art into nonsense.
  local cols; cols="$(tput cols 2>/dev/null || echo 80)"
  if [[ ! -t 1 || "$cols" -lt $(( _WM_W + 4 )) ]]; then
    printf '\n%sENUMGRID%s %s· network enumeration cockpit%s\n\n' "$BOLD" "$RST" "$DIM" "$RST"
    return
  fi
  clear 2>/dev/null || true
  _wm_palette
  printf '\033[?25l'                        # hide the cursor for the animation

  # 1) Build: rows drop in top to bottom, each lit as it lands, then settling
  #    into the ramp, so the letters appear to extrude towards you.
  local i
  for (( i=0; i<6; i++ )); do
    _wm_row "$i" "$i"
    nap 0.05
    printf '\033[1A'; _wm_row "$i" -1
  done

  # 2) Two passes of a highlight sweeping down the faces: the power-on.
  local pass
  for pass in 1 2; do
    for (( i=0; i<6; i++ )); do
      printf '\033[6A'; _wm_frame "$i"
      nap 0.03
    done
  done
  printf '\033[6A'; _wm_frame -1
  _wm_reflection

  # 3) The radar sweep: a rule that draws itself out under the wordmark behind a
  #    bright head, which parks at the end as the engine comes up.
  local x
  printf '  '
  for (( x=0; x<_WM_W; x++ )); do
    if [[ "$C256" == "1" ]]; then
      printf '\033[38;5;35m━\033[38;5;48m▶\b'
    else
      printf '%s━%s' "$GRN" "$RST"
    fi
    nap 0.004
  done
  printf '%s\n' "$RST"
  printf '\033[?25h'                        # cursor back

  printf '  %snetwork enumeration cockpit%s   %sICMP · ARP · NDP · mDNS · NBNS · nmap%s\n\n' \
    "$DIM" "$RST" "$DIM" "$RST"
}
boot_banner

# --------------------------------------------------------------------------- #
# 0) Load .env (optional): picks up secrets like ENUMGRID_NVD_API_KEY and
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
  [[ -n "${ENUMGRID_NVD_API_KEY:-}" ]] && ok "NVD API key detected: faster, higher-rate CVE lookups"
}
load_dotenv

# --------------------------------------------------------------------------- #
# 1) Prerequisites
# --------------------------------------------------------------------------- #
say "Checking prerequisites…"

command -v python3 >/dev/null 2>&1 || die "python3 not found. Install Python 3.10+ first."

# --- nmap (the scan engine) ------------------------------------------------- #
if ! command -v nmap >/dev/null 2>&1; then
  warn "nmap is not installed; it's the core scan engine."
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

# Install/refresh deps only when something is actually missing, which keeps restarts fast.
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
      warn "Port $port busy, freeing it (pids: $(echo "$pids" | tr '\n' ' '))"
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
# 4b) TLS: self-signed cert for the backend (optional, --tls)
# --------------------------------------------------------------------------- #
if [[ "$TLS" == "1" ]]; then
  if ! command -v openssl >/dev/null 2>&1; then
    die "--tls needs openssl (not found). Install it or run without --tls."
  fi
  CERT_DIR="$ROOT/.certs"
  mkdir -p "$CERT_DIR"
  if [[ ! -f "$CERT_DIR/cert.pem" || ! -f "$CERT_DIR/key.pem" ]]; then
    say "Generating a self-signed TLS certificate (.certs/)…"
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
      -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
      -subj "/CN=localhost" >/dev/null 2>&1 || die "cert generation failed."
  fi
  SSL_ARGS=(--ssl-keyfile "$CERT_DIR/key.pem" --ssl-certfile "$CERT_DIR/cert.pem")
  BACKEND_SCHEME="https"
  export VITE_API_HTTPS=1   # tell the Vite proxy to use https + accept self-signed
  ok "TLS enabled: backend served over HTTPS (self-signed; the UI proxy trusts it)"
fi

# --------------------------------------------------------------------------- #
# 5) Privileged mode (accurate OS): ON BY DEFAULT, cache sudo creds up front.
#    We try sudo for full-fidelity scans (real -O / SYN / UDP). If sudo isn't
#    available or the user declines, we DON'T refuse to start. We fall back to
#    unprivileged mode (every scan still runs, root-only types auto-adapt).
# --------------------------------------------------------------------------- #
SUDO=()
if [[ "$ACCURATE_OS" == "1" ]]; then
  if [[ "$(id -u)" -eq 0 ]]; then
    ok "Running as root: full nmap power (real OS -O, SYN, UDP)."
  else
    say "Enabling full-fidelity scans, caching sudo credentials (one password prompt)…"
    if sudo -v 2>/dev/null; then
      # Keep the sudo timestamp fresh while we run so nmap stays elevated.
      ( while true; do sudo -n true 2>/dev/null || exit; sleep 50; done ) &
      SUDO_KEEPALIVE=$!
      SUDO=(sudo -E)
      ok "nmap will run privileged: real OS (-O) + SYN/UDP + version detection."
    else
      ACCURATE_OS=0
      warn "sudo unavailable/declined, starting unprivileged instead (still fully functional)."
      printf '   %s(root-only scans auto-adapt: SYN→connect, UDP→connect, OS detect skipped; never errors.)%s\n' "$DIM" "$RST"
    fi
  fi
else
  say "Unprivileged mode: no password needed. Every scan profile still runs."
  printf '   %s(root-only scans auto-adapt: SYN→connect, UDP→connect, OS detect skipped; never errors.)%s\n' "$DIM" "$RST"
  printf '   %sWant real -sS/-sU/-O? Click the privilege pill in the app and Elevate. It takes%s\n' "$DIM" "$RST"
  printf '   %syour sudo password there, keeps it in memory for the session, and needs no restart.%s\n' "$DIM" "$RST"
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

say "Starting backend  → ${BACKEND_SCHEME}://127.0.0.1:${BACKEND_PORT}  ${DIM}(FastAPI + nmap)${RST}"
(
  cd "$ROOT/backend"
  exec "${SUDO[@]+"${SUDO[@]}"}" "$PYTHON" -m uvicorn app:app --host 127.0.0.1 --port "$BACKEND_PORT" \
    "${SSL_ARGS[@]+"${SSL_ARGS[@]}"}" \
    >"$ROOT/.backend.log" 2>&1
) &
PIDS+=("$!")

# Wait for the backend to report healthy (up to ~30s), with a live spinner.
printf '%s▸%s Waiting for the scan engine to come up ' "$CYN" "$RST"
healthy=0
spin='|/-\'
for n in $(seq 1 60); do
  if curl -fksS "${BACKEND_SCHEME}://127.0.0.1:${BACKEND_PORT}/api/health" >/dev/null 2>&1; then
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
  warn "Backend didn't answer in time. Last log lines:"
  tail -n 20 "$ROOT/.backend.log" 2>/dev/null || true
  die "Backend failed to start. See $ROOT/.backend.log"
fi
priv="$(curl -fksS "${BACKEND_SCHEME}://127.0.0.1:${BACKEND_PORT}/api/health" 2>/dev/null || true)"
if echo "$priv" | grep -q '"capability": *"root"'; then
  ok "Scan engine healthy: root (full nmap: real -O / SYN / UDP)"
elif echo "$priv" | grep -q '"capability": *"sudo"'; then
  ok "Scan engine healthy: passwordless sudo (scans auto-elevate: real -O / SYN / UDP)"
elif echo "$priv" | grep -q '"privileged": *true'; then
  ok "Scan engine healthy: privileged (real nmap -O available)"
else
  ok "Scan engine healthy: unprivileged (root-only scans auto-adapt; no scan errors)"
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
printf '   The target auto-fills to your network. Just click %sStart Scan%s.\n' "$BOLD" "$RST"
printf '   Look for the green %sLIVE STREAM%s badge. Press %sCtrl-C%s to stop.\n' "$GRN" "$RST" "$BOLD" "$RST"
printf '%s════════════════════════════════════════════════════%s\n\n' "$GRN" "$RST"

if [[ "$OPEN_BROWSER" == "1" ]]; then
  if [[ "$OSNAME" == "Darwin" ]]; then open "$URL" 2>/dev/null || true
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL" 2>/dev/null || true
  fi
fi

# Wait until either server exits; the trap cleans up the rest.
wait -n 2>/dev/null || wait
