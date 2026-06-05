# PurpleRecon — Industrial-Level Network Enumeration Platform

A two-tiered, **purple-team** network enumeration tool: it thinks like an
offensive scanner but acts like a defensive asset mapper. Discover every live
device on a network you're authorized to assess, then deep-dive any host with
nmap on demand. Author: **santhakumarParivallal** (Master's security project).

It ships in two forms that share one engine:

| | What | Where |
|---|---|---|
| **CLI cockpit** | Single-file `rich` terminal dashboard — fast sweep → nmap deep-dive, JSON/HTML/CSV export, config-drift `--diff` | `purple_recon.py` |
| **Web cockpit** | FastAPI (SSE) backend + React/Tailwind dashboard — live device list, per-device nmap on demand | `backend/`, `frontend/` |

> ⚠️ **Authorized use only.** Scan only systems/networks you own or have
> explicit, written permission to test. The tool **hard-refuses** loopback,
> multicast, broadcast, link-local and reserved space to prevent self-DoS, and
> refuses public/internet-routable targets by default.

---

## Quickstart

```bash
make setup     # one-time: venv + python deps + npm install
make dev       # start backend (:8011) + frontend (:5173) together
```

Open <http://localhost:5173> — the target **auto-fills to your network**, so just
click **Start Scan**. A green **LIVE STREAM** badge means the real backend is
connected; amber **DEMO STREAM** means only the frontend is running (offline mock
data). `make dev` runs both, so you always get live data.

### Or just the CLI

```bash
# Fast device inventory (like Angry IP): IP / MAC / vendor / hostname
./.venv/bin/python purple_recon.py 192.168.0.0/24 --discover

# Two-tiered deep scan of one host, with HTML + CSV reports
./.venv/bin/python purple_recon.py 192.168.0.10 --top-ports 1000 --html --csv
```

---

## How it works

```
Phase 1  Horizontal sweep   ICMP + TCP + ARP   find live hosts (confidence-graded)
Phase 2  Vertical deep-dive nmap -sV (+ NSE)   service / version / vuln detection
```

- **Multi-method discovery** — ICMP echo (slow-Wi-Fi tolerant), TCP connect
  probes, and the OS **ARP cache** catch devices that ignore ping. A
  **proxy-ARP guard** stops a router that answers for the whole subnet from
  faking 254 "hosts".
- **Honest liveness** — a completed handshake / echo is `strong`; a bare TCP
  `RST` is `weak` and suppressed by default (firewalls forge those).
- **Vendor naming** — MAC → IEEE OUI lookup (39k+ entries via `--download-oui`);
  randomized "private Wi-Fi" MACs are detected and labelled, not guessed.

See [`docs`-level detail in the code](purple_recon.py) and
[`backend/README.md`](backend/README.md) for the API + security model.

---

## Security model

The CLI's `ScopeValidator` is the single source of truth, and the **web backend
reuses it** (`backend/security.py`) so both interfaces enforce the same policy.
Web-only knobs (env vars): `PURPLERECON_ALLOW_PUBLIC`, `PURPLERECON_MAX_SCANS`,
`PURPLERECON_MAX_HOSTS`, `PURPLERECON_API_TOKEN` — see `backend/README.md`.

**Accuracy & limitations (honest):** network discovery is probabilistic. No
scanner finds 100% of devices every run — MAC-randomized phones, ICMP-silent IoT
and cold ARP caches all hide hosts. PurpleRecon uses three independent methods to
minimize blind spots and *labels what it cannot resolve* rather than inventing it.

---

## Testing

```bash
make test      # ruff lint + CLI pytest + backend pytest + frontend Vitest
```

| Suite | Count | Scope |
|---|---|---|
| `test_purple_recon.py` | 69 | guardrails, discovery policy, ARP/OUI, reports, export, renderers |
| `backend/test_*.py` | 52 | scope enforcement, token gate, NSE/CVSS parsing, OS detection |
| `frontend/src/**/*.test.js` | 10 | schema coercion / null-safety, derived counters |

CI (`.github/workflows/ci.yml`) runs lint + all three suites on every push
across Python 3.10–3.13.

---

## Layout

```
purple_recon.py        # the single-file CLI engine (shared primitives)
test_purple_recon.py   # CLI test suite
backend/               # FastAPI SSE service (reuses the CLI engine)
frontend/              # Vite + React + Tailwind cockpit
scripts/dev.sh         # runs both servers together (make dev)
Makefile               # setup / dev / test / lint / clean
```
