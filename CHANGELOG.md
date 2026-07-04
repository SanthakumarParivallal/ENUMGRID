# Changelog

All notable changes to **ENUMGRID: the Enumeration Platform**. Format based on
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added — discovery
- **SSDP / UPnP discovery** (`backend/ssdp.py`) — a new unprivileged name source
  that fills the hostname/model gap for devices that don't answer mDNS or NBNS
  (home routers, smart TVs, media renderers, consoles, many IoT). Sends the
  standard `M-SEARCH` multicast, then fetches each responder's UPnP device
  description for its `friendlyName` / `manufacturer` / `modelName` / device type.
  SSRF-guarded (only fetches a `LOCATION` whose host matches the responder; http/s
  only) and XXE-safe (targeted regex scrape, no XML parser). Verified live: a
  previously-nameless gateway now resolves to "Sagemcom F3896LG".
- **Discover-mode port preview** (`backend/discovery.py`) — discovery now runs a
  fast, parallel, unprivileged TCP connect-scan of the common service ports, so
  the live grid shows open ports immediately (no nmap, no root). These ports also
  feed the device-type classifier (port signatures are its strongest hint), so
  DEVICE/OS sharpens for free. The full `-sV`/CVE pass stays on-demand per host.
- **Adaptive port scanning** (`backend/scanner.py`) — the default service scan now
  covers the **top 1000** ports with `-sV` (up from 200), and then sweeps **all
  65 535** ports on *only* the hosts that already showed at least one open port
  (`scan_single_host(adaptive=…)`, `_merge_scan_results`; `?adaptive=1`). Thorough
  where it pays, fast where it doesn't (firewalled/dead hosts cost just the quick
  pass) — and never a fabricated port.

### Added — web cockpit
- **Runtime privilege elevation from the dashboard** — a new **Privilege** control
  in the command bar lets the operator raise the backend from *unprivileged* to
  real raw-socket scans (`-sS` SYN / `-sU` UDP / `-O` OS detection) by entering a
  sudo password — **no restart, nothing to configure at start-up**. New backend
  endpoints (`GET /api/privilege`, `POST /api/privilege/elevate`,
  `POST /api/privilege/drop`) validate the password against `sudo` and hold it
  **only in process memory** for the session (never written to disk, never logged,
  never returned); `scan_capability()` then reports `sudo` and every scan runs
  under `sudo -S`. "Drop" (or a restart) forgets it. Gated to the local operator
  (open-mode guard) or an admin token when RBAC is on. Honest by design: a wrong
  password fails with a clear message and never fakes elevation.
- **Complete command-center redesign** — the cockpit was rebuilt around a
  professional app shell: a fixed left **sidebar** (brand · scan pipeline · drift ·
  sessions · engine status), a frosted-glass **command bar**, a SOC-style **KPI
  strip** (Hosts · Ports · Services · Vulnerabilities · Critical), a **collapsible
  "Nmap scan options"** drawer (profile/command/NSE picker tucked away by default),
  and a consolidated **Settings** menu (theme · density · API token · NVD key).
  Fully responsive (sidebar collapses to a drawer on mobile) and theme-aware.
- **Light theme** — a "paper" light theme alongside the dark cockpit, toggled from
  the toolbar and persisted. Implemented with CSS variables (`index.css`) so a
  single `<html data-theme>` swap repaints the whole UI; opacity modifiers keep
  working via Tailwind's `<alpha-value>`. Signal accents are shared across themes.
- **Density toggle** — Cozy ⇄ Compact row spacing (matrix header, host rows, port
  rows), toggled from the toolbar and persisted.
- **Resizable matrix columns** — drag the Hostname / Vendor / Device·OS / MAC
  column edges to resize; double-click a grip to reset. Widths persist; header and
  rows always share one grid template, so they stay aligned.
- **Sticky per-host detail toolbar** — a host's IP + Re-scan controls stay pinned
  below the matrix header while scrolling a long ports/vulns list.
- View preferences (theme · density · column widths) persist in `localStorage`
  (`frontend/src/lib/preferences.js`) and apply before first paint (no theme flash).
- **Bigger NSE script menu** — the one-click "add NSE" chips are now a curated,
  categorized set (HTTP · TLS · SSH · SMB/Windows · Naming/Services · CVE — ~30
  scripts), all server-validated and non-intrusive, with a one-click "clear".
- **Topology map scales to any host count** — the radial view now sizes its SVG
  canvas to the data and distributes nodes across circumference-proportional rings,
  so a large `/24` no longer collapses or overlaps (verified 11→150 hosts, every
  node in-bounds with arc-gap > node diameter).
- **Honest "no open ports" diagnostic** — when most fully-scanned hosts expose no
  ports, the grid explains the likely *real* cause (host firewalls / Wi-Fi client
  isolation — visible via ARP at L2, unreachable over TCP at L3) instead of leaving
  it ambiguous. It never invents ports.

### Changed
- **NVD API key now persists across restarts** (`backend/cve.py`) — a key entered
  in the dashboard is saved to a local, owner-only (`0600`), git-ignored file and
  loaded on startup (`ENUMGRID_NVD_API_KEY` still takes precedence), so it no longer
  has to be re-entered after every restart. The key is still never logged.

### Fixed — classification accuracy (anti-hallucination)
- **Device type mislabelled from the Wi-Fi-chip vendor** (`backend/fingerprint.py`)
  — `guess_device_type` ranked the OUI vendor above the hostname, so a Windows
  "DESKTOP-…"/"W11N-…" machine whose wireless module is made by an IoT-adjacent
  vendor (e.g. AzureWave) was tagged "IoT / Embedded". Priority is now
  ports > services > **hostname > vendor** — a device's self-assigned name beats
  its sub-component's OUI. Verified: `DESKTOP-…`/`W11N-…` → Computer / Windows.
- **Fabricated mobile OS for randomized MACs** (`backend/osfp.py`) — a private
  ("locally-administered") MAC no longer asserts "Android / iOS"; it reports only
  the honest TTL family (Linux/macOS/Unix · Windows · or nothing), since a private
  MAC is just as likely a laptop. Windows "DESKTOP-…" hostnames resolve to Windows.

### Fixed
- **PDF report could crash / inject markup** (`backend/report.py`) — service/version
  banners, hostnames, vuln output and the target string (device-/attacker-controlled)
  were passed raw into reportlab's `Paragraph`, which parses a mini-XML markup; a
  single `<`, `>` or `&` (e.g. `Apache/2.4 (Ubuntu) & mod_ssl`) broke generation.
  All dynamic values are now escaped; CVE links use a quoted, scheme-checked URL.
- **TLS certificate audit never fired** (`backend/webscan.py`) — under
  `verify_mode = CERT_NONE`, `ssl.getpeercert()` returns `{}`, so the expired /
  self-signed checks silently never ran. The cert is now read in DER form and
  parsed with `cryptography`. Verified live against `expired.badssl.com` /
  `self-signed.badssl.com`.
- **Auth tokens compared in non-constant time** (`backend/security.py`) — admin /
  viewer token checks now use `hmac.compare_digest` (timing-safe).
- **CI security gate (bandit B406)** (`backend/report.py`) — importing
  `xml.sax.saxutils` (used only for output *escaping*, not parsing) tripped
  bandit's XML blacklist and failed the security job. Replaced with inline
  escapers so no blacklisted module is imported; bandit is clean again.
- **AWS security-group audit ignored IPv6** (`backend/cloudscan.py`) — ingress open
  to `::/0` is now flagged like `0.0.0.0/0`.
- **Discover-mode ports vs. "scanned"** (frontend) — now that discovery shows
  preview ports, the auto-scan / "Scan All" / status logic keys off the real
  `scanned` flag instead of `ports.length`, so hosts still get the full `-sV`/CVE
  pass even when a preview port is already shown.
- **Layout overlap in the matrix** — the expanded host-detail header no longer
  collides with its Re-scan button; `truncate`d grid cells (hostname/vendor/MAC,
  port service/version) now carry `min-w-0` so long values ellipsize instead of
  expanding their column; the vuln-finding badge row wraps.

### Security (audit)
*Findings from a full white-box source audit (OWASP-aligned manual review +
Bandit/pip-audit/npm-audit). No critical/RCE issues; the items below were fixed.*
- **Unauthenticated LAN exposure of the zero-config API (High)** — with no token,
  open mode granted admin to *every* caller; combined with the `0.0.0.0` Docker
  `--network host` bind this exposed the scanner to the LAN. Open mode is now
  **fail-closed to local clients**: a middleware refuses any `/api/*` request from
  a non-loopback peer when no token is set (`app.py:_local_only_in_open_mode`,
  `security.open_mode`/`client_is_local`).
- **DNS-rebinding / drive-by scanning (Medium)** — the same middleware validates
  the `Host` header is local in open mode, so a rebound origin can't drive the
  local scanner (`security.host_header_local`).
- **Inventory disclosure via history endpoints (Medium)** — `/api/history` and
  `/api/history/diff` are now RBAC-gated (viewer/admin) like `/api/audit`, instead
  of serving the device/port inventory unauthenticated.
- **PDF endpoint memory exhaustion (Low)** — `build_pdf` caps the host list
  (`MAX_REPORT_HOSTS`) before rendering.
- Hardening guidance added (prefer `Authorization` header over `?token=`; TLS +
  token before remote exposure; data-at-rest permissions) — see
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) (T15–T18) and `SECURITY.md`.

### Configuration
- New env vars: `ENUMGRID_DISCOVER_PORTS`, `ENUMGRID_PORT_TIMEOUT`,
  `ENUMGRID_MDNS_SECS`, `ENUMGRID_SSDP_SECS`, `ENUMGRID_NVD_KEY_FILE`
  (see `backend/README.md`). The default `NMAP_TOP_PORTS` is now `1000` (was `200`).

### Quality
- **446 tests** (CLI 84 · backend 336 · evaluation 7 · frontend 19) — new suites
  `test_discovery.py`, `test_ssdp.py`; new regressions for report-escaping, SG-IPv6,
  NVD-key persistence, device-type priority (hostname > vendor), honest
  randomized-MAC OS, and the **open-mode locality guard + history RBAC** security
  fixes. ruff 0; bandit 0; pip-audit 0; npm audit 0.

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

[Unreleased]: https://example.com/enumgrid/compare/v1.0.0...HEAD
[1.0.0]: https://example.com/enumgrid/releases/tag/v1.0.0
