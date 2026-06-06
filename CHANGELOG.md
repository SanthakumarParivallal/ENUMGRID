# Changelog

All notable changes to EnumGrid. Format based on
[Keep a Changelog](https://keepachangelog.com/); this project uses
[Semantic Versioning](https://semver.org/).

## [1.2.0] — 2026-06-06

Depth release: precise device/OS identity, automatic CVE intelligence, smarter
scanning, and a more capable dashboard.

### Added
- **Automatic version → CVE → hyperlink.** Every on-demand host scan now runs the
  version→CVE `vulners` lookup automatically (no need to pick a profile), and
  every finding is a **clickable link to its NVD page** (`Vuln.url`). Verified
  live: a router's `dnsmasq 2.87` + `lighttpd 1.4.63` auto-surfaced
  CVE-2023-50387/-28450 and CVE-2022-41556/-22707 with CVSS + NVD links.
- **Offline CVE reference** (`backend/vulndb.py`) — a curated, hand-checked
  version→CVE table (vsftpd 2.3.4, OpenSSH < 7.7, Apache 2.4.49/.50, ProFTPD
  1.3.5, Exim 4.87–4.91, dnsmasq < 2.90, …) so well-known vulnerable builds are
  flagged even without internet; the live `vulners` scan remains authoritative.
- **Specific Apple device + OS.** mDNS `model=`/`osxvers=` resolve the exact
  product line (iPhone / iPad / MacBook Pro / Mac / Apple Watch / HomePod) and
  macOS version (e.g. `osxvers=23` → "macOS 14 (Sonoma)").
- **Filtered-state confirmation.** Ports left `filtered` by the first pass are
  re-probed with a *different* technique (patient TCP connect, or SYN from a DNS
  source port when privileged) to resolve them — fewer false "filtered" verdicts.
- **NetBIOS (NBNS) name resolution** (`backend/nbns.py`) — fills hostnames for
  Windows PCs/printers/NAS/IoT that have no reverse-DNS (Angry IP / Fing style).
- **Boot animation** — an on-brand startup splash in the dashboard, plus an
  animated banner + spinner in `start.sh`.
- **Enhanced dashboard filters** — new quick filters (Open Ports, Vulnerable
  (CVE), Critical, Has Name) plus **Device-type** and **OS-family** dropdowns and
  a one-click "Clear (n)".

### Quality
- **303 tests** (was 263). ruff 0, bandit 0 high/medium, pip-audit 0 CVEs.

## [1.1.0] — 2026-06-06

Usability + accuracy release: one-command launch, specific OS labels, and more
scan options — driven by real user feedback.

### Added
- **`./start.sh` — one command to run everything.** Checks prerequisites (offers
  to install nmap), creates the venv, installs backend + frontend deps, frees
  stuck ports, starts both servers, waits for health, and opens the browser.
  `--accurate-os` runs the scanner privileged (one sudo prompt) for real
  `nmap -O`; cleans up (incl. DB ownership) on Ctrl-C.
- **Specific OS detection (no more "Linux / macOS / Unix" lump).** `osfp.refine_os`
  fuses TTL + OUI vendor + hostname + device type into a precise label
  (`macOS (Apple)`, `iPadOS (Apple)`, `Android`, `Windows`,
  `Router firmware (Linux)`, `Embedded / RTOS`, `Smart TV OS`, …). mDNS now reads
  the device-announced **`model=`** TXT for an authoritative Apple OS class.
  Measured: **12 / 14** hosts on a real `/24` resolve to a specific OS (was 0).
- **4 new scan profiles → 11 total:** **Recon** (rich safe enumeration),
  **Stealth SYN** (`-sS -T2`), **Safe scripts**, **Comprehensive** (`-A -p-` +
  default & vuln). All injection-safe.

### Fixed
- `start.sh` empty-array expansion under `set -u` on macOS bash 3.2.
- More IoT SoC vendors (AltoBeam, Ai-Thinker, Tuya, …) now classify as embedded.

### Quality
- **263 tests** (was 228). Static analysis fully clean: ruff 0, **bandit 0
  high/medium** (silenced a false-positive B104 on test data), pip-audit 0 CVEs.

## [1.0.0] — 2026-06-06

First complete release: the Angry-IP + Zenmap + monitoring trio in one tool,
CLI and web, sharing one engine — with measured accuracy and a security self-audit.

### Discovery & enumeration
- Two-tier engine: fast horizontal sweep → on-demand `nmap -sV` deep-dive.
- Multi-method, confidence-graded discovery: ICMP + TCP + **ARP** + **NDP (IPv6)**
  + **mDNS/Bonjour** + ping-**TTL** OS family. Proxy-ARP guard; RST suppression.
- MAC → IEEE OUI vendor (39k+), randomized-MAC detection.
- **Device-type fingerprinting** (Router/Phone/Printer/Camera/Media-TV/NAS/IoT).
- **Unprivileged OS family** via reply TTL (sudo adds nmap `-O`).
- **IPv6-aware**: dual-stack `ScopeValidator`, NDP correlation by MAC, nmap `-6`.
- NSE vuln scripts + CVE/CVSS scoring (opt-in "Deep").

### Web cockpit
- FastAPI SSE backend + React/Tailwind dashboard; live device grid.
- Per-device **and** whole-network ("Scan All") nmap; start-with-no-target auto-sweep.
- **SQLite history + drift** ("What Changed"); **continuous Monitor mode** with
  auto-re-scan + drift alert + desktop notification.
- **Zenmap-style topology map** (Matrix ⇄ Topology toggle).
- **One-click PDF report** (reportlab); CLI HTML/CSV/JSON export + `--diff`.

### Security
- `ScopeValidator` reused by CLI **and** web (loopback/multicast/broadcast/
  link-local/reserved/oversized refused, IPv4 + IPv6); anti-injection target regex.
- Public-target refusal by default, concurrency cap, optional API token.
- CI security gate: **bandit** (SAST) + **pip-audit** + **npm audit**; the two real
  bandit findings fixed (HTTPS-checked OUI download, parameterized SQL).
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

### Quality & reproducibility
- ~230 tests: unit, **FastAPI TestClient integration**, **hypothesis fuzzing** of
  every parser; coverage gates (CLI ≥50%, backend ≥60%).
- **Measured evaluation** vs `nmap -sn` ([`docs/EVALUATION.md`](docs/EVALUATION.md)):
  recall 1.00 vs 0.27 unprivileged, faster, zero false positives. Reproducible
  docker testbed + benchmark harness.
- `pip install`-able (`enumgrid` console command); `Dockerfile` + `docker-compose`
  (nmap baked in); pinned `requirements.lock` + `package-lock.json`.
- 4-job CI (lint · security · CLI matrix · backend · frontend); ruff-clean.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

[1.0.0]: https://example.com/enumgrid/releases/tag/v1.0.0
