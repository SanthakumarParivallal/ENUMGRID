# PurpleRecon — Industrial-Level Network Enumeration Platform

A two-tiered, **purple-team** network enumeration tool: it thinks like an
offensive scanner but acts like a defensive asset mapper. Discover every live
device on a network you're authorized to assess, then deep-dive any host with
nmap on demand. Author: **santhakumarParivallal** (Master's security project).

It ships in two forms that share one engine:

| | What | Where |
|---|---|---|
| **CLI cockpit** | Single-file `rich` terminal dashboard — fast sweep → nmap deep-dive, JSON/HTML/CSV export, config-drift `--diff` | `purple_recon.py` |
| **Web cockpit** | FastAPI (SSE) backend + React/Tailwind dashboard — live device list, device-type fingerprinting, per-device **or whole-network** nmap, SQLite history + drift, one-click **PDF report** | `backend/`, `frontend/` |

It's the trio you actually want in one place: **Angry IP / Fing** (instant device
inventory with vendor + MAC + device type), **Zenmap / nmap** (real service,
version and port detection on demand), and **network monitoring** (scan history +
"what changed since last time"), with a one-click PDF you can hand in.

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

Open <http://localhost:5173>. The target **auto-fills to your network** — or just
press **Start Scan with the field empty** and it auto-detects and sweeps your whole
`/24`. Then:

1. **Start Scan** → instant device list (IP · vendor · MAC · device type) in ~20s.
2. **Scan All** → runs nmap service/version detection on every device at once
   (or expand one row → **Nmap Scan** for just that host). Open ports, services
   and versions fill in live.
3. Toggle **Deep** first to add NSE vuln scripts + CVE/CVSS findings.
4. **Report** → downloads a one-click **PDF** of exactly what's on screen.

A green **LIVE STREAM** badge means the real backend is connected; amber
**DEMO STREAM** means only the frontend is running (offline mock data). `make dev`
runs both, so you always get live data.

> **OS detection:** nmap's authoritative OS fingerprint (`-O`) needs raw sockets,
> so run the backend with `sudo` to enable it. Unprivileged (the default), the
> tool infers OS from service banners/CPEs where possible and otherwise shows a
> **device-type** label (Router / Phone / Printer / Camera / …) derived from the
> vendor + open ports — a real, explainable signal, never a hallucinated OS.

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
- **Device-type fingerprinting** — vendor + open ports + services + hostname →
  a coarse type (Router / Phone / Printer / Camera / Media-TV / NAS / IoT /
  Computer). Evidence-driven and explainable; shows nothing when unsure.
- **Service / version detection** — Phase 2 runs real `nmap -sV`; ports, service
  names and product versions stream into each device's expandable detail table.
- **History + drift** — every completed scan is saved to SQLite; the **"What
  Changed"** panel and `/api/history/diff` surface new/gone devices and
  opened/closed ports vs the previous scan of the same target.
- **PDF report** — `POST /api/report/pdf` renders the live snapshot (summary +
  inventory + per-host ports/vulns) into a self-contained PDF (one-click in the UI).

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
| `backend/test_*.py` | 83 | scope enforcement, token gate, NSE/CVSS parsing, OS detection, device fingerprinting, SQLite history + drift, PDF report |
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
