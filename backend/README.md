# ENUMGRID — Backend (FastAPI + Nmap)

Runs the **Two-Tiered Scan Pipeline** and streams `ScanState` snapshots to the
dashboard over Server-Sent Events (SSE):

```
Phase 1  Ping Sweep        nmap -sn      host discovery          progress  0 → 40
Phase 2  Nmap Enumeration  nmap -sV      service/version detect  progress 40 → 100
```

## Requirements

- The **nmap** binary (`brew install nmap` / `apt install nmap`).
- Python 3.10+ and the project venv at `../.venv`.

## Install

```bash
cd backend
../.venv/bin/python -m pip install -r requirements.txt
```

## Run

```bash
cd backend
../.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8011 --reload
```

Then start the frontend (`cd ../frontend && npm run dev`). The Vite dev proxy
forwards `/api/*` to this server, so the dashboard talks to it same-origin.

## Endpoints

| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/api/health` | `{ status, nmap, privileged, max_concurrent_scans, allow_public }` |
| GET | `/api/network` | best-effort `{ primary_ip, suggested_target }` (dashboard auto-fill / empty-target Start) |
| GET | `/api/scan/stream?target=<t>&id=<id>&mode=<discover\|full>&deep=<0\|1>` | SSE stream of `ScanState` frames |
| GET | `/api/host/scan?ip=<ip>&deep=<0\|1>` | nmap one host, returns its `Host` (per-row "Nmap Scan" + "Scan All") |
| POST | `/api/report/pdf` | body = a `ScanState` snapshot → `application/pdf` download |
| GET | `/api/history?target=<t>&limit=<n>` | recent scan summaries (timeline) |
| GET | `/api/history/diff?target=<t>` | drift vs the previous scan: new/gone devices + opened/closed ports |

`mode=discover` (default) is the fast device inventory (MAC + vendor + hostname +
**device-type** fingerprint + **mDNS/Bonjour** names, no nmap). `mode=full` runs
the two-tiered nmap pipeline. `deep=1` adds an NSE **vuln-script** pass (`nmap --script vuln,vulners`),
populating each port's `vulns[]` with real findings (CVE id, CVSS, severity). It's
much slower, so it's opt-in.

Each completed scan is persisted to SQLite (`ENUMGRID_DB`, default beside the
backend) so `/api/history*` and the dashboard's **"What Changed"** panel can show
drift over time. The PDF report is **stateless** — it renders exactly the snapshot
you POST, so the document always matches the screen.

Quick check (streams live frames to your terminal — use *your own* subnet):

```bash
curl -N "http://127.0.0.1:8011/api/scan/stream?target=192.168.0.0/24"                  # fast discover
curl -N "http://127.0.0.1:8011/api/scan/stream?target=192.168.0.10&mode=full&deep=1"   # + vuln scripts
```

## Security model (enforced)

The web API runs the **same `ScopeValidator` as the CLI** (`backend/security.py`
reuses `purple_recon.ScopeValidator`), so every request is vetted before a single
packet is sent. Refused (returns an `Error` frame / `400` carrying a `message`):

- loopback `127.0.0.0/8`, multicast, broadcast, link-local, reserved space;
- anything with injectable characters (anti nmap-flag-injection);
- scopes larger than the host cap;
- **public / internet-routable** targets — unless you opt in (below).

| Env var | Default | Effect |
| ------- | ------- | ------ |
| `ENUMGRID_ALLOW_PUBLIC` | `0` | set `1` to permit public targets (authorized use only) |
| `ENUMGRID_AUTO_SUDO` | `1` | when not root, auto-elevate scans via passwordless `sudo` if available (`-n`, never prompts); set `0` to always run unprivileged |
| `ENUMGRID_MAX_SCANS` | `4` | cap on concurrent scans (excess → `429` / "server busy") |
| `ENUMGRID_MAX_HOSTS` | `4096` | per-request host cap |
| `ENUMGRID_DISCOVER_PORTS` | `1` | discover mode: connect-scan the common ports so the grid shows open ports (and sharper device types) with no nmap/root; set `0` to skip |
| `ENUMGRID_PORT_TIMEOUT` | `0.5` | per-port connect timeout (seconds) for the discover-mode port probe |
| `ENUMGRID_MDNS_SECS` | `6.0` | how long to listen for mDNS/Bonjour announcements (longer = more device names resolved) |
| `ENUMGRID_SSDP_SECS` | `2.5` | how long to wait for SSDP/UPnP replies (resolves names + models for routers, smart TVs, media players, IoT) |
| `ENUMGRID_API_TOKEN` | _(unset)_ | when set, require `?token=` or `Authorization: Bearer …` |
| `ENUMGRID_NVD_API_KEY` | _(unset)_ | NVD API key — raises the live-CVE rate limit (5→50 req/30s) |
| `ENUMGRID_NVD_DISABLE` | `0` | set `1` to disable live NVD lookups (cache + offline still used) |
| `ENUMGRID_CVE_TTL_DAYS` | `30` | freshness window for the local CVE cache |
| `ENUMGRID_NVD_BUDGET` | `20` | max seconds of live NVD lookups per host scan |

Auth is **off by default** (the server binds to localhost), so the local dev flow
needs no configuration. Set a token before exposing the API beyond localhost.

### CVE intelligence

Service versions are matched to CVEs from three layered sources — **live NVD API**
(by CPE, authoritative + always current, locally cached), in-scan **NSE `vulners`**,
and a **curated offline reference**. Findings carry CVSS, an NVD link, and a
`confirmed`/`version` confidence tag. `GET /api/health` reports `cve.cached_services`
(the local cache size, which grows as you scan). No API key is required, but
`ENUMGRID_NVD_API_KEY` is recommended for heavy use.

### More attack surface, scale & deployment

- **Authenticated (credentialed) scan** — `POST /api/host/credscan` (SSH) reads
  exact distro/kernel/packages; the package list is checked against **OSV.dev**
  for **backport-aware** CVEs (a distro-patched version is not flagged).
- **Web audit** — `GET /api/host/webscan` (security headers / cookies / TLS cert).
- **SNMP** — switches/APs/printers named from sysName/sysDescr during discovery.
- **Cloud** — `GET /api/cloud/aws` (EC2 + world-open SGs + public S3) via `boto3`
  + your AWS credential chain. **AD** — `POST /api/ad/enum` (computers/users over
  LDAP) via `ldap3`. Both optional deps; both read-only; credentials never logged.
- **Job queue (scale)** — `POST /api/jobs/submit` queues a scan; poll
  `GET /api/jobs/{id}`. A bounded worker pool drains it; jobs persist across
  restarts. The SQLite queue is swappable for Redis to scale horizontally.

### Access control, TLS & SSO

- **RBAC** — set `ENUMGRID_ADMIN_TOKEN` (launch scans) and optionally
  `ENUMGRID_VIEWER_TOKEN` (read-only). With none set, localhost access is open.
  Pass `?token=` or `Authorization: Bearer …`.
- **TLS** — `./start.sh --tls` serves the API over HTTPS (self-signed). For
  production use a real cert via a reverse proxy.
- **SSO (OIDC/SAML)** — front EnumGrid with an authenticating reverse proxy and
  bind it to your IdP. Example (Caddy + oauth2-proxy):

  ```
  # Caddy: terminate TLS, require SSO, then proxy to EnumGrid
  enumgrid.example.com {
      forward_auth oauth2-proxy:4180 {
          uri /oauth2/auth
          copy_headers X-Auth-Request-Email X-Auth-Request-User
      }
      reverse_proxy 127.0.0.1:5173    # the UI (which proxies /api to :8011)
  }
  ```
  oauth2-proxy handles the OIDC/SAML dance with Google/Okta/Entra/etc.; EnumGrid's
  own token RBAC then layers per-action authorization on top.

## Notes

- **Privilege auto-adaptation — every scan runs, no matter how you start it.**
  Some nmap scan types need raw sockets (root): `-sS` (SYN), `-sU` (UDP), `-O` (OS
  detection). Run unprivileged they *hard-fail* (`requires root privileges.
  QUITTING!`). The backend resolves this automatically, detecting once (without
  ever prompting for a password) how much privilege it can get:
  - **root** — running as root (e.g. `./start.sh --accurate-os`): full nmap.
  - **sudo** — not root but passwordless `sudo nmap` works (`-n`, NOPASSWD or a
    cached credential): each scan is transparently elevated and its XML parsed.
  - **unprivileged** — neither: root-only flags are *rewritten* to unprivileged
    equivalents (`-sS`/`-sU` → `-sT` connect, `-O`/`--source-port` dropped, `-A`
    → `-sV -sC`). The scan completes with real results and an honest `scan_note`
    on the host (e.g. *"UDP scan needs root — ran TCP connect instead"*).

  `GET /api/health` and `/api/profiles` report `capability` (`root`/`sudo`/
  `unprivileged`) and `can_raw`. Net effect: picking Stealth/UDP/Aggressive in the
  dashboard never errors. For full fidelity (real SYN/UDP/OS), run
  `./start.sh --accurate-os` or arrange passwordless `sudo` for nmap.
- **Unprivileged still derives a *specific* OS** by fusing TTL + OUI vendor +
  hostname + mDNS `model=` (no `sudo` needed).
- **Scan profiles** (`GET /api/profiles`): 11 Zenmap-style presets —
  `quick · default · intense · recon · aggressive · stealth · vuln · safe ·
  fullports · comprehensive · udp`. A request only sends a profile *name* plus an
  optional validated port spec and NSE script list; the nmap args are
  server-defined constants, so no user input is ever spliced into the command
  line. Intrusive `brute`/`exploit`/`dos`/`malware` scripts are refused.
- **Tunables** (env vars): `NMAP_DISCOVERY_ARGS`, `NMAP_SERVICE_ARGS`,
  `NMAP_TOP_PORTS`.
- **Target safety.** `target` is strictly allowlisted (IPv4 / CIDR / range /
  hostname) so it can't inject extra flags into the nmap command line.

> ⚠️ **Authorization.** Only scan hosts and networks you own or are explicitly
> authorized to test. Unauthorized scanning may be illegal where you live.
