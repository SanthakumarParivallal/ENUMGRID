# Changelog

All notable changes to **ENUMGRID: the Enumeration Platform**. Format based on
[Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] — 2026-06-06

First public release (**v1**): the Angry-IP + Zenmap + monitoring trio in one
tool — CLI and web sharing one engine — with one-command launch, specific OS
identity, automatic CVE intelligence, measured accuracy and a security self-audit.

### Launch & UX
- **`./start.sh` — one command runs everything.** Checks prerequisites (offers to
  install nmap), creates the venv, installs backend + frontend deps, frees stuck
  ports, starts both servers, waits for health, opens the browser. **Privileged by
  default** (one password prompt → real `nmap -O` / SYN / UDP); falls back to
  unprivileged automatically if sudo is declined/unavailable (never blocks the
  start). `--no-sudo` opts out. Cleans up on Ctrl-C.
- **Boot animation** — an on-brand startup splash in the dashboard and an animated
  banner + spinner in `start.sh`.
- **One-click full scan** — pressing *Start Scan* now runs discovery **and**
  automatically port/service/OS-scans every up host (no second click).
- **Survives reloads** — scan results persist to `sessionStorage`, so a refresh
  (or a dev-server reload) restores the grid instead of wiping it to "standby".
- **Advanced progress bar** — segmented Ping-Sweep/Nmap-Enum phase tags that
  illuminate, a gradient fill with moving shimmer + pulsing leading edge, and a
  live recolouring percentage.

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
- **Privilege auto-adaptation — every profile runs without root, no errors.**
  Root-only scan types (`-sS` SYN, `-sU` UDP, `-O` OS detect) used to hard-fail
  unprivileged (`requires root privileges. QUITTING!`). The engine now detects —
  once, without ever prompting — whether it can scan as **root**, via passwordless
  **sudo** (`-n`, auto-elevated per scan, XML parsed), or **unprivileged**; in the
  last case it rewrites root-only flags to safe equivalents (SYN/UDP → connect,
  `-O`/`--source-port` dropped, `-A` → `-sV -sC`) and records an honest
  `scan_note` on the host. `GET /api/health` + `/api/profiles` expose
  `capability` + `can_raw`; the dashboard shows the tier and any adaptation.
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

### Accuracy & access
- **Backport-aware vulnerability matching** (`backend/osv.py`) — credentialed
  package lists are checked against OSV.dev's distro feeds (Ubuntu/Debian/Alpine),
  so a fix backported by the distro is *not* flagged. Verified live: 62
  distro-accurate findings for an old Ubuntu openssl.
- **Web-posture audit / DAST-lite** (`backend/webscan.py`, `GET /api/host/webscan`)
  — safe passive check of security headers, insecure cookies, and the TLS cert.
- **RBAC** (`security.py`) — admin (scan) vs viewer (read-only) tokens; open in
  localhost dev. **TLS**: `./start.sh --tls` serves the backend over HTTPS.

### Reach & scale
- **Cloud (AWS) discovery** (`backend/cloudscan.py`, `GET /api/cloud/aws`) — EC2
  + world-open security groups + public S3, via boto3 (optional) + your AWS
  credential chain. Read-only.
- **Active Directory enumeration** (`backend/adscan.py`, `POST /api/ad/enum`) —
  computers + users over LDAP via ldap3 (optional). Read-only; creds never logged.
- **Job queue** (`backend/jobs.py`, `/api/jobs/*`) — submit a scan, poll for the
  result; a bounded worker pool drains a persistent SQLite queue (survives
  restarts). Scales vertically; the queue is swappable for Redis (horizontal).
- **SSO** documented via authenticating reverse proxy (Caddy + oauth2-proxy) on
  top of the built-in RBAC. Responsive UI fixes (no more clipped target field /
  overlapping inputs on small screens).

### Operations
- **SNMP device naming** (`backend/snmp.py`) — names switches/APs/printers with
  no DNS/mDNS from SNMP sysName/sysDescr.
- **Outbound alerting** (`backend/notify.py`) — webhook / Slack / syslog on
  scan-complete (KEV hits highlighted).
- **Audit trail** (`backend/audit.py`, `GET /api/audit`) — append-only JSONL of
  every scan, refusal and credentialed check.
- **`.env` auto-loading** in `start.sh` for secrets like `ENUMGRID_NVD_API_KEY`.

### Web cockpit
- **Honest per-host scan status** — the grid badge now distinguishes **Ready**
  (discovered, not yet scanned) · **Queued** (genuinely waiting in a *Scan All*
  batch) · **Scanning** · **Done** · **No ports** (scanned, none open) · **Failed**.
  Previously every un-scanned host showed a misleading "Queued", making a single
  per-host scan look like it ran against the whole network. Scanning one host now
  affects only that host.
- **Per-host scan shows the real command** (the selected profile's nmap args for
  that one IP), not a hardcoded `-sV`.
- **NVD API key — set it from the dashboard.** A one-click panel in the nmap bar
  shows the current CVE rate limit, lets you paste a free key (applied instantly,
  in memory), links to where to get one, and shows the exact `.env` line to make
  it permanent (`GET/POST /api/settings/nvd[-key]`).
- **Real, never fake** — if the backend is unreachable the dashboard now fails
  with a clear error banner (and surfaces the backend's own refusal reasons)
  instead of silently substituting simulated data. The demo engine runs only with
  an explicit `VITE_USE_MOCK=true`.
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
- **Zero dependency CVEs** — backend (`pip-audit`) and frontend (`npm audit`,
  incl. dev tooling on vite 8 / vitest 4) both report 0 vulnerabilities.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

### Robustness fixes
- **SQLite handles no longer leak** — every cache/history/jobs connection now
  commits *and* closes (sqlite3's own context manager only commits).
- **Monitor mode never interrupts an in-flight port scan**; the session log is
  capped so a long monitor run can't grow state without bound.

### Quality & reproducibility
- **422 tests** (CLI 84 · backend 312 · evaluation 7 · frontend 19): unit,
  **FastAPI TestClient integration**, **hypothesis fuzzing**. ruff 0,
  **bandit 0 high/medium**, pip-audit 0 CVEs, npm audit 0.
- **Measured evaluation** vs `nmap -sn` ([`docs/EVALUATION.md`](docs/EVALUATION.md)):
  recall 1.00 vs 0.27 unprivileged, faster, zero false positives. Reproducible
  docker testbed + benchmark harness.
- `pip install`-able (`enumgrid` console command); `Dockerfile` + `docker-compose`
  (nmap baked in); pinned `requirements.lock` + `package-lock.json`.
- CI: lint · security · CLI matrix · backend · frontend.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

[1.0.0]: https://example.com/enumgrid/releases/tag/v1.0.0
