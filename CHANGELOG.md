# Changelog

All notable changes to EnumGrid. Format based on
[Keep a Changelog](https://keepachangelog.com/); this project uses
[Semantic Versioning](https://semver.org/).

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
