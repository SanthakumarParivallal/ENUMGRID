# EnumGrid — Industrial-Level Network Enumeration Platform

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

## Quickstart — one command

```bash
./start.sh
```

That's it. The launcher checks your prerequisites (and offers to install nmap),
creates the Python virtualenv, installs **all** backend + frontend dependencies,
frees the ports if something is stuck, starts **both** servers, waits until
they're healthy, and **opens your browser**. Press **Ctrl-C** once to stop
everything cleanly. First run does the setup; later runs start in seconds.

```bash
./start.sh --accurate-os   # asks for your password once → real nmap -O
                           # OS + version detection on per-host scans
./start.sh --help          # all options (ports, no-browser, …)
```

<details><summary>Other ways to run (make / Docker / manual)</summary>

```bash
make setup && make dev     # equivalent: venv + deps, then both servers
# Container (Linux; LAN scanning needs the host network):
ENUMGRID_API_TOKEN=changeme docker compose up --build
```
</details>

Open <http://localhost:5173>. The target **auto-fills to your network** — or just
press **Start Scan with the field empty** and it auto-detects and sweeps your whole
`/24`. Then:

1. **Start Scan** → instant device list (IP · vendor · MAC · device type) in ~20s.
2. **Scan All** → runs nmap service/version detection on every device at once
   (or expand one row → **Nmap Scan** for just that host). Open ports, services
   and versions fill in live.
3. Toggle **Deep** first to add NSE vuln scripts + CVE/CVSS findings.
4. **Report** → downloads a one-click **PDF** of exactly what's on screen.
5. **Monitor** → auto-re-scans on an interval and alerts you when the network
   changes (new/gone devices, opened/closed ports). Switch **Matrix ⇄ Topology**
   for the map view.

A green **LIVE STREAM** badge means the real backend is connected. Results are
**always real**: if the backend is unreachable the dashboard shows a clear error
(it never silently fakes a scan). The simulated **DEMO STREAM** engine runs only
when you explicitly opt in with `VITE_USE_MOCK=true`. `./start.sh` runs both
servers, so you always get live data.

> **OS detection (specific, not a vague lump):** even **unprivileged**, EnumGrid
> fuses **four real signals** — ping-reply **TTL** (Linux/macOS/Unix · Windows ·
> network/IoT), the **OUI vendor**, the **hostname**, and the **mDNS `model=`**
> a device announces about itself — into a *specific* label: `macOS (Apple)`,
> `iPadOS (Apple)`, `Android`, `Windows`, `Router firmware (Linux)`,
> `Embedded / RTOS`, `Smart TV OS`, … (On a real `/24` this resolves **12 of 14**
> hosts to a specific OS instead of the generic family.) Run
> `./start.sh --accurate-os` (or the backend with `sudo`) to add nmap's
> authoritative `-O` fingerprint with the exact build on top. The OS is never
> fabricated: when no signal supports a claim it stays "Unknown".

### Or just the CLI

```bash
# Fast device inventory (like Angry IP): IP / MAC / vendor / hostname
./.venv/bin/python purple_recon.py 192.168.0.0/24 --discover

# Two-tiered deep scan of one host, with HTML + CSV reports
./.venv/bin/python purple_recon.py 192.168.0.10 --top-ports 1000 --html --csv
```

**Install it as a command** (`pyproject.toml`, single-file module):

```bash
pip install -e .                 # or: pip install -e ".[nmap,web]"
enumgrid 192.168.0.0/24 --discover
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
> 📊 **Measured:** on a real `/24`, EnumGrid found **11/12 live hosts (recall 1.00)** vs unprivileged `nmap -sn`'s **3 (recall 0.27)** — faster, zero false positives. See [`docs/EVALUATION.md`](docs/EVALUATION.md).

- **Device-type fingerprinting** — vendor + open ports + services + hostname →
  a coarse type (Router / Phone / Printer / Camera / Media-TV / NAS / IoT /
  Computer). Evidence-driven and explainable; shows nothing when unsure.
- **mDNS / Bonjour resolution** (web) — browses the network for advertised
  services (printers, Apple gear, Chromecasts, Sonos, HomeKit) to fill real
  device **names** and confident types for hosts that have no reverse-DNS record
  — the Fing/Angry-IP "what is this device" experience. Best-effort, never faked.
- **OS family (unprivileged)** — ping-reply **TTL** → OS family (Linux/macOS/Unix
  · Windows · network/IoT); `sudo` adds nmap `-O`. Honest: ambiguous → Unknown.
- **IPv6-aware** — `ScopeValidator` is dual-stack (accepts IPv6 targets, refuses
  `::1`/multicast/link-local/oversized); the **NDP neighbour cache** correlates
  each device's IPv6 address to its IPv4 entry by MAC (a "v6" badge in the grid);
  per-host nmap uses `-6` for IPv6 targets.
- **Topology map** (web) — a Zenmap-style radial view: the gateway as the hub,
  devices on rings coloured by type, click a node to nmap it. Toggle Matrix ⇄ Topology.
- **Continuous monitor mode** (web) — one toggle auto-re-scans on an interval
  (30s / 2m / 5m / 15m) and raises a dismissible banner **+ desktop notification**
  the moment a device appears/disappears or a port opens/closes. Network watch,
  not just a one-shot scan.
- **Service / version detection** — Phase 2 runs real `nmap -sV`; ports, service
  names and product versions stream into each device's expandable detail table.
- **11 Zenmap-style scan profiles** — pick per scan from the toolbar dropdown:
  *Quick · Default · Intense · **Recon** (rich safe enum: titles, certs, host
  keys, SMB/DNS) · Aggressive (`-A` +OS) · **Stealth SYN** (`-sS -T2`, low-noise)
  · Vulnerability (CVE+CVSS) · **Safe scripts** · All 65 535 ports ·
  **Comprehensive** (`-A -p-` + default & vuln — the works) · UDP*. Plus optional
  custom **NSE scripts** and a **port range** — all validated server-side so no
  argument can ever be injected (intrusive `brute`/`exploit`/`dos`/`malware`
  categories are refused by default).
- **Privilege auto-adaptation — every profile just runs.** SYN/UDP/OS-detect
  normally need root and *hard-fail* unprivileged. EnumGrid detects (without ever
  prompting) whether it can scan as **root**, via passwordless **sudo**
  (auto-elevated per scan), or **unprivileged** — and in the last case rewrites
  root-only flags to safe equivalents (SYN/UDP→connect, drop `-O`, `-A`→`-sV -sC`)
  so the scan completes with real results and an honest note. No more "requires
  root privileges. QUITTING!". Run `./start.sh --accurate-os` for full fidelity.
- **Automatic CVE intelligence (live, comprehensive, future-proof).** When
  version detection identifies a service, EnumGrid correlates it to CVEs from
  **three layered sources** so real-world coverage isn't limited to a hardcoded
  list:
  1. **Live NVD API** — queried by the exact **CPE** nmap emits, so *any*
     fingerprinted service is matched against the full, authoritative US-government
     CVE corpus, and **newly-published CVEs appear automatically** (no code
     change). Results are cached in a local SQLite DB, so repeat scans are instant
     and it keeps working **offline** once a service has been seen.
  2. **NSE `vulners`** — a second in-scan CVE source with CVSS scores.
  3. **Curated offline reference** (`backend/vulndb.py`) — the best-known cases as
     a last-resort fallback.
  Every finding is a **clickable link to its NVD page** and tagged with its
  **confidence** (`confirmed` = NSE actively tested · `version` = version/CPE
  match — verify). Set `ENUMGRID_NVD_API_KEY` to raise the NVD rate limit;
  `ENUMGRID_NVD_DISABLE=1` turns live lookups off. (Verified live: an OpenSSH
  `7.2p2` CPE returned 12 current CVEs in ~2.6 s, then instant from cache.)
- **Risk prioritization (KEV + EPSS).** Findings are enriched with **CISA KEV**
  (confirmed exploited-in-the-wild — a red `⚠ KEV` badge) and **FIRST EPSS**
  (exploit-probability %), then **risk-ranked** so "which of 40 CVEs matters
  first?" is answered for you: actively-exploited → high EPSS → high CVSS.
  (Live: 1612 KEV CVEs loaded in 0.3 s; Log4Shell/Heartbleed scored ~94 %.)
- **Credentialed scanning (authenticated truth).** `POST /api/host/credscan`
  logs in over **SSH** and reads the *exact* distro (`/etc/os-release`), kernel
  and installed-package inventory — eliminating version-banner false positives.
  Host-key-verified by default (`ENUMGRID_SSH_AUTOADD=1` to trust new keys);
  credentials are used in memory only, never logged.
- **SNMP device naming** — switches/APs/printers with no DNS/mDNS are named from
  SNMP `sysName`/`sysDescr` (default community), filling more of the grid.
- **Outbound alerting** — on scan-complete / drift, push to a **webhook**, **Slack**
  (`ENUMGRID_SLACK_WEBHOOK`) or **syslog** (`ENUMGRID_SYSLOG`) — KEV hits are
  called out. **Audit trail**: every scan/refusal/credscan is appended to a JSONL
  log (`/api/audit`) for accountability.
- **Filtered-state confirmation** — ports left ambiguous (`filtered`) by the first
  pass are automatically re-probed with a *different* technique (patient TCP
  connect, or SYN from a DNS source port when root) to resolve false "filtered".
- **NetBIOS (NBNS) names** — resolves hostnames for Windows PCs, printers, NAS and
  IoT with no reverse-DNS record, on top of reverse-DNS + mDNS.
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
Web-only knobs (env vars): `ENUMGRID_ALLOW_PUBLIC`, `ENUMGRID_MAX_SCANS`,
`ENUMGRID_MAX_HOSTS`, `ENUMGRID_API_TOKEN` — see `backend/README.md`.

**Accuracy & limitations (honest):** network discovery is probabilistic. No
scanner finds 100% of devices every run — MAC-randomized phones, ICMP-silent IoT
and cold ARP caches all hide hosts. EnumGrid uses three independent methods to
minimize blind spots and *labels what it cannot resolve* rather than inventing it.

---

## Testing

```bash
make test      # ruff lint + CLI pytest + backend pytest + frontend Vitest
```

| Suite | Count | Scope |
|---|---|---|
| `test_purple_recon.py` | 84 | guardrails (incl. IPv6 scope), NDP/ARP/OUI parsing, discovery policy, reports, export, renderers, **fuzzing** |
| `backend/test_*.py` | 312 | scope/**RBAC**, **11 scan profiles** + injection safety, **privilege auto-adaptation** (root/sudo/unprivileged downgrade), **live NVD + offline CVE DB + OSV backport-aware**, **KEV+EPSS prioritization**, **credentialed SSH + package parsers**, **web-DAST audit**, **SNMP BER codec**, **AWS/LDAP parsers**, **job-queue**, **outbound alerting + audit**, NSE/CVSS, **multi-signal OS fingerprinting**, device + mDNS + **NBNS**, history + drift, PDF, **FastAPI integration**, **hypothesis fuzzing** |
| `frontend/src/**/*.test.js` | 19 | schema coercion / null-safety + scan-state transients, CVE link + confidence + **KEV/EPSS risk-rank**, derived counters |
| `evaluation/test_benchmark.py` | 7 | benchmark metric math (precision/recall/Jaccard) |

**422 tests, all green.** Static analysis is clean: **ruff** 0 findings, **bandit**
SAST 0 high/medium, **pip-audit** 0 known CVEs, **npm audit** 0 (vite 8 / vitest 4).
CI (`.github/workflows/ci.yml`)
runs **5 jobs** — lint (ruff), **security** (bandit + pip-audit + npm audit), CLI
(Python 3.10–3.13 matrix), backend, and frontend — with coverage gates on every push.

### Project docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — design + rationale
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — assets, trust boundaries, controls
- [`docs/EVALUATION.md`](docs/EVALUATION.md) — measured accuracy vs `nmap -sn`
- [`CHANGELOG.md`](CHANGELOG.md)

---

## Layout

```
purple_recon.py        # the single-file CLI engine (shared primitives)
test_purple_recon.py   # CLI test suite
pyproject.toml         # pip-installable: `enumgrid` console command
backend/               # FastAPI SSE service (reuses the CLI engine)
  ├─ scanner.py        #   two-tiered nmap pipeline (+ nmap -6) + NSE/CVSS parsing
  ├─ discovery.py      #   fast device discovery (ICMP/ARP/NDP/mDNS/TTL, no nmap)
  ├─ fingerprint.py    #   device-type heuristics  ·  mdns.py  Bonjour names
  ├─ osfp.py           #   specific OS from TTL + vendor + hostname + mDNS model
  ├─ security.py       #   ScopeValidator reuse (dual-stack) + auth + concurrency cap
  ├─ history.py        #   SQLite scan history + drift  ·  report.py  PDF
frontend/              # Vite + React + Tailwind cockpit
evaluation/            # benchmark harness + docker testbed (vs nmap)
docs/                  # ARCHITECTURE · THREAT_MODEL · EVALUATION
Dockerfile             # backend + CLI image (nmap baked in)
docker-compose.yml     # one-command deployment  ·  requirements.lock  pinned env
start.sh               # ⭐ ONE command: setup + run both servers + open browser
scripts/dev.sh         # runs both servers together (make dev)
Makefile               # setup / dev / test / lint / clean
```
