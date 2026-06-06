# Changelog

All notable changes to EnumGrid. Format based on
[Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] — 2026-06-06

First public release (**v1**): the Angry-IP + Zenmap + monitoring trio in one
tool — CLI and web sharing one engine — with one-command launch, specific OS
identity, automatic CVE intelligence, measured accuracy and a security self-audit.

### Launch & UX
- **`./start.sh` — one command runs everything.** Checks prerequisites (offers to
  install nmap), creates the venv, installs backend + frontend deps, frees stuck
  ports, starts both servers, waits for health, opens the browser. `--accurate-os`
  runs privileged (one sudo prompt) for real `nmap -O`; cleans up on Ctrl-C.
- **Boot animation** — an on-brand startup splash in the dashboard and an animated
  banner + spinner in `start.sh`.

### Discovery & enumeration
- Two-tier engine: fast horizontal sweep → on-demand `nmap -sV` deep-dive.
- Multi-method, confidence-graded discovery: ICMP + TCP + **ARP** + **NDP (IPv6)**
  + **mDNS/Bonjour** + **NBNS (NetBIOS names)**. Proxy-ARP guard; RST suppression.
- MAC → IEEE OUI vendor (39k+), randomized-MAC detection, device-type fingerprint.
- **Specific OS identity** — `osfp.refine_os` fuses TTL + vendor + hostname + type;
  mDNS `model=`/`osxvers=` resolve the exact Apple product (iPhone/iPad/MacBook/
  Mac/Apple Watch/HomePod) and macOS version. `sudo`/`--accurate-os` adds nmap `-O`.
- **11 Zenmap-style scan profiles** (Quick · Default · Intense · Recon · Aggressive
  · Stealth SYN · Vulnerability · Safe · All-ports · Comprehensive · UDP), plus
  validated custom NSE scripts + port ranges — injection-safe by construction.
- **Filtered-state confirmation** — ports left `filtered` are re-probed with a
  different technique (patient TCP connect, or SYN from a DNS source port as root).
- **IPv6-aware**: dual-stack `ScopeValidator`, NDP correlation by MAC, nmap `-6`.

### Vulnerability intelligence (live, comprehensive, future-proof)
- **Live NVD API enrichment** (`backend/cve.py`) — every fingerprinted service is
  matched **by CPE** against the authoritative US-government NVD feed, so coverage
  isn't a hardcoded list and **newly-published CVEs appear automatically**.
  Results are cached in a local SQLite DB (grows over time, instant on repeat
  scans, works offline once seen); rate-limit-aware with a per-scan budget and an
  optional `ENUMGRID_NVD_API_KEY`. Verified live: OpenSSH `7.2p2` → 12 CVEs in ~2.6s.
- **NSE `vulners`** runs automatically on every on-demand host scan (second
  in-scan CVE source), plus a **curated offline reference** (`backend/vulndb.py`)
  as a last-resort fallback. All three sources are merged + deduped.
- **Clickable NVD links** on every finding (dashboard + PDF).
- **Risk prioritization (CISA KEV + FIRST EPSS)** (`backend/threatintel.py`) —
  findings are tagged with exploited-in-the-wild status + exploit probability and
  **risk-ranked** (KEV → EPSS → CVSS), so the few that matter surface first.
- **False-positive transparency** — each finding is tagged `confirmed` (an NSE
  script actively tested the host) or `version` (version/CPE match — "verify");
  non-finding output is filtered, and duplicates merge keeping the best confidence.
- **Credentialed scanning** (`backend/credscan.py`, `POST /api/host/credscan`) —
  authenticated SSH read of exact distro/kernel/package inventory (host-key
  verified by default; credentials never logged).

### Operations
- **SNMP device naming** (`backend/snmp.py`) — names switches/APs/printers with
  no DNS/mDNS from SNMP sysName/sysDescr.
- **Outbound alerting** (`backend/notify.py`) — webhook / Slack / syslog on
  scan-complete (KEV hits highlighted).
- **Audit trail** (`backend/audit.py`, `GET /api/audit`) — append-only JSONL of
  every scan, refusal and credentialed check.
- **`.env` auto-loading** in `start.sh` for secrets like `ENUMGRID_NVD_API_KEY`.

### Web cockpit
- FastAPI SSE backend + React/Tailwind dashboard; live device grid.
- Per-device **and** whole-network ("Scan All") nmap; start-with-no-target auto-sweep.
- **Rich filters** — quick chips (Web/SSH/DB/Open Ports/Vulnerable/Critical/Has
  Name), Device-type + OS-family dropdowns, search, and one-click Clear.
- **SQLite history + drift** ("What Changed"); **continuous Monitor mode** with
  auto-re-scan + drift alert + desktop notification.
- **Zenmap-style topology map** (Matrix ⇄ Topology toggle).
- **One-click PDF report** (reportlab) with clickable CVE links; CLI HTML/CSV/JSON
  export + `--diff`.

### Security
- `ScopeValidator` reused by CLI **and** web (loopback/multicast/broadcast/
  link-local/reserved/oversized refused, IPv4 + IPv6); anti-injection target regex.
- Public-target refusal by default, concurrency cap, optional API token.
- CI security gate: **bandit** (SAST) + **pip-audit** + **npm audit**.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

### Quality & reproducibility
- **361 tests** (CLI 84 · backend 253 · evaluation 7 · frontend 17): unit,
  **FastAPI TestClient integration**, **hypothesis fuzzing**. ruff 0,
  **bandit 0 high/medium**, pip-audit 0 CVEs.
- **Measured evaluation** vs `nmap -sn` ([`docs/EVALUATION.md`](docs/EVALUATION.md)):
  recall 1.00 vs 0.27 unprivileged, faster, zero false positives. Reproducible
  docker testbed + benchmark harness.
- `pip install`-able (`enumgrid` console command); `Dockerfile` + `docker-compose`
  (nmap baked in); pinned `requirements.lock` + `package-lock.json`.
- CI: lint · security · CLI matrix · backend · frontend.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

[1.0.0]: https://example.com/enumgrid/releases/tag/v1.0.0
