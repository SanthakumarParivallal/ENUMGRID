# ENUMGRID backend (FastAPI + Nmap)

Runs the two-tiered scan pipeline and streams `ScanState` snapshots to the dashboard
over Server-Sent Events (SSE):

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
| GET | `/api/health` | `{ status, nmap, privileged, capability, can_raw, can_elevate, max_concurrent_scans, allow_public, cve }` |
| GET | `/api/network` | best-effort `{ primary_ip, suggested_target }` (dashboard auto-fill / empty-target Start) |
| GET | `/api/privilege` | `{ capability, can_raw, is_root, elevated, sudo_available, can_elevate }`: the scan-privilege tier for the dashboard's Elevate control |
| POST | `/api/privilege/elevate` | body `{ password }` validates `sudo` and elevates this session to real `-sS`, `-sU` and `-O`. The password is held in memory only, and the endpoint is admin-gated and local-only |
| POST | `/api/privilege/drop` | forgets any runtime-elevated credential (`sudo -k`), returning to unprivileged |
| GET | `/api/scan/stream?target=<t>&id=<id>&mode=<discover\|full>&deep=<0\|1>` | SSE stream of `ScanState` frames |
| GET | `/api/host/scan?ip=<ip>&deep=<0\|1>&adaptive=<0\|1>` | nmap one host, returns its `Host` (per-row "Nmap Scan" + "Scan All"). `adaptive=1` (default profile only): after the top-1000 `-sV` scan, if an open port is found, sweep all 65535 on that host |
| POST | `/api/report/pdf` | body is a `ScanState` snapshot; returns an `application/pdf` download |
| GET | `/api/history?target=<t>&limit=<n>` | recent scan summaries (timeline) |
| GET | `/api/history/diff?target=<t>` | drift against the previous scan: new and gone devices, opened and closed ports |

`mode=discover` (the default) is the fast device inventory: MAC, vendor, hostname,
device-type fingerprint, mDNS/Bonjour and SSDP/UPnP names, and a quick common-port
preview, with no nmap. `mode=full` runs the two-tiered nmap pipeline. `deep=1` adds
an NSE vuln-script pass (`nmap --script vuln,vulners`), populating each port's
`vulns[]` with real findings (CVE id, CVSS, severity). It is much slower, so it is
opt-in.

Each completed scan is persisted to SQLite (`ENUMGRID_DB`, default beside the
backend) so `/api/history*` and the dashboard's "What Changed" panel can show drift
over time. The PDF report is stateless: it renders exactly the snapshot you POST, so
the document always matches the screen.

Quick check, which streams live frames to your terminal. Use your own subnet:

```bash
curl -N "http://127.0.0.1:8011/api/scan/stream?target=192.168.0.0/24"                  # fast discover
curl -N "http://127.0.0.1:8011/api/scan/stream?target=192.168.0.10&mode=full&deep=1"   # + vuln scripts
```

## Security model (enforced)

The web API runs the same `ScopeValidator` as the CLI (`backend/security.py` reuses
`purple_recon.ScopeValidator`), so every request is vetted before a single packet is
sent. The following are refused, returning an `Error` frame or a `400` carrying a
`message`:

- loopback `127.0.0.0/8`, multicast, broadcast, link-local (incl. cloud-metadata
  `169.254.169.254`), reserved space; hostnames are rejected (IP/CIDR only);
- anything with injectable characters, which blocks nmap flag injection;
- scopes larger than the host cap;
- public and internet-routable targets, unless you opt in (below).

**Access control and exposure.** RBAC uses `ENUMGRID_ADMIN_TOKEN` for launching scans
and credentialed checks, and an optional `ENUMGRID_VIEWER_TOKEN` for read-only access
to health, history and audit. With no token configured the API is fail-closed to
local clients: a middleware refuses any `/api/*` call from a non-loopback peer or
with a non-local `Host` header, which blocks DNS-rebinding, so binding to `0.0.0.0`
(Docker `--network host`) cannot expose the scanner to the LAN without a token. The
scan history (`/api/history*`) is RBAC-gated like `/api/audit`. Prefer the
`Authorization: Bearer …` header over `?token=`, because query strings leak into
logs.

| Env var | Default | Effect |
| ------- | ------- | ------ |
| `ENUMGRID_ALLOW_PUBLIC` | `0` | set `1` to permit public targets (authorized use only) |
| `ENUMGRID_AUTO_SUDO` | `1` | when not root, auto-elevate scans via passwordless `sudo` if available (`-n`, never prompts); set `0` to always run unprivileged |
| `ENUMGRID_MAX_SCANS` | `4` | cap on concurrent scans; excess requests get `429` "server busy" |
| `ENUMGRID_MAX_HOSTS` | `4096` | per-request host cap |
| `ENUMGRID_DISCOVER_PORTS` | `1` | discover mode: connect-scan the common ports so the grid shows open ports, and sharper device types, with no nmap and no root. Set `0` to skip |
| `ENUMGRID_PORT_TIMEOUT` | `0.5` | per-port connect timeout (seconds) for the discover-mode port probe |
| `ENUMGRID_MDNS_SECS` | `6.0` | how long to listen for mDNS/Bonjour announcements; longer resolves more device names |
| `ENUMGRID_SSDP_SECS` | `2.5` | how long to wait for SSDP/UPnP replies (resolves names + models for routers, smart TVs, media players, IoT) |
| `ENUMGRID_ADMIN_TOKEN` | _(unset)_ | admin token, required for scans and credentialed checks when set (prefer the `Authorization: Bearer …` header) |
| `ENUMGRID_VIEWER_TOKEN` | _(unset)_ | read-only token (health / history / audit) |
| `ENUMGRID_API_TOKEN` | _(unset)_ | legacy alias for the admin token (`?token=` or `Authorization: Bearer …`) |
| `ENUMGRID_NVD_API_KEY` | _(unset)_ | NVD API key, which raises the live-CVE rate limit from 5 to 50 requests per 30s. Takes precedence over a key entered in the dashboard |
| `ENUMGRID_NVD_KEY_FILE` | `backend/.enumgrid_nvd_key` | where a dashboard-entered NVD key is persisted (owner-only `0600`, git-ignored, never logged) so it survives restarts |
| `NMAP_TOP_PORTS` | `1000` | port breadth for the default/vuln profiles; the adaptive pass then sweeps all 65535 on hosts with an open port |
| `ENUMGRID_NVD_DISABLE` | `0` | set `1` to disable live NVD lookups (cache + offline still used) |
| `ENUMGRID_CVE_TTL_DAYS` | `30` | freshness window for the local CVE cache |
| `ENUMGRID_NVD_BUDGET` | `20` | max seconds of live NVD lookups per host scan |

Auth is off by default, because the server binds to localhost, so the local dev flow
needs no configuration. Set a token before exposing the API beyond localhost.

### CVE intelligence

Service versions are matched to CVEs from three layered sources: the live NVD API (by
CPE, authoritative, always current and locally cached), the in-scan NSE `vulners`
script, and a curated offline reference. Findings carry CVSS, an NVD link, and a
`confirmed` or `version` confidence tag. `GET /api/health` reports `cve.cached_services`
(the local cache size, which grows as you scan). No API key is required, but
`ENUMGRID_NVD_API_KEY` is recommended for heavy use.

### More attack surface, scale and deployment

- **Authenticated (credentialed) scan.** `POST /api/host/credscan` reads the exact
  distro, kernel and packages over SSH, and the package list is checked against
  OSV.dev for backport-aware CVEs, so a distro-patched version is not flagged.
- **Web audit.** `GET /api/host/webscan` covers security headers, cookies and the TLS
  cert.
- **SNMP.** Switches, APs and printers are named from sysName and sysDescr during
  discovery.
- **Cloud.** `GET /api/cloud/aws` covers EC2, world-open SGs and public S3 via
  `boto3` and your AWS credential chain. For AD, `POST /api/ad/enum` enumerates
  computers and users over LDAP via `ldap3`. Both are optional dependencies, both are
  read-only, and credentials are never logged.
- **Job queue (scale).** `POST /api/jobs/submit` queues a scan and `GET /api/jobs/{id}`
  polls it. A bounded worker pool drains the queue and jobs persist across restarts.
  The SQLite queue is swappable for Redis to scale horizontally.

### Access control, TLS and SSO

- **RBAC.** Set `ENUMGRID_ADMIN_TOKEN` to launch scans, and optionally
  `ENUMGRID_VIEWER_TOKEN` for read-only access. With none set, localhost access is
  open. Pass `?token=` or `Authorization: Bearer …`.
- **TLS.** `./start.sh --tls` serves the API over HTTPS with a self-signed cert. For
  production, use a real cert behind a reverse proxy.
- **SSO (OIDC/SAML).** Front EnumGrid with an authenticating reverse proxy bound to
  your IdP. For example, with Caddy and oauth2-proxy:

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
  oauth2-proxy handles the OIDC or SAML exchange with Google, Okta, Entra and the
  like, and EnumGrid's own token RBAC then layers per-action authorization on top.

## Notes

- **Privilege auto-adaptation, so every scan runs however you start it.** Some nmap
  scan types need raw sockets, meaning root: `-sS` (SYN), `-sU` (UDP) and `-O` (OS
  detection). Run unprivileged, they hard-fail with `requires root privileges.
  QUITTING!`. The backend resolves this automatically, detecting once, without ever
  prompting for a password, how much privilege it can get:
  - **root.** Running as root, for example via `./start.sh --accurate-os`, gives full
    nmap.
  - **sudo.** Not root, but passwordless `sudo nmap` works (`-n`, NOPASSWD or a
    cached credential), so each scan is transparently elevated and its XML parsed.
  - **unprivileged.** Neither, so root-only flags are rewritten to unprivileged
    equivalents: `-sS` and `-sU` become `-sT` connect, `-O` and `--source-port` are
    dropped, and `-A` becomes `-sV -sC`. The scan completes with real results and an
    honest `scan_note` on the host, such as "UDP scan needs root, so TCP connect
    ran instead".

  `GET /api/health` and `/api/profiles` report `capability` (`root`/`sudo`/
  `unprivileged`) and `can_raw`. The net effect is that picking Stealth, UDP or
  Aggressive in the dashboard never errors. For full fidelity with real SYN, UDP and
  OS scans, run `./start.sh --accurate-os` or arrange passwordless `sudo` for nmap.
- **Runtime elevation (no restart).** When unprivileged, the operator can raise the
  session to real raw-socket scans by posting a `sudo` password to
  `POST /api/privilege/elevate` (the dashboard's **Privilege** control). It's
  validated with `sudo -k -S nmap --version`; on success `scan_capability()`
  becomes `sudo` and `_sudo_scan()` runs every scan under `sudo -S`, feeding the
  password on stdin, so it works even where `sudo -n` would not. The password is held
  only in `scanner._SUDO_PASSWORD`, in process memory, and is never written to disk,
  logged, or returned in a response. `POST /api/privilege/drop`, and process exit,
  forget it. Both endpoints are `admin_ok`-gated and, in open mode, reachable only by
  the local operator, and the elevation attempt is audited without the secret.
  Disable the whole mechanism with `ENUMGRID_AUTO_SUDO=0`.
- **Unprivileged still derives a specific OS**, by fusing TTL, the OUI vendor, the
  hostname and the mDNS `model=` record. No `sudo` needed.
- **Scan profiles** (`GET /api/profiles`): 11 Zenmap-style presets, being
  `quick · default · intense · recon · aggressive · stealth · vuln · safe ·
  fullports · comprehensive · udp`. A request sends only a profile name plus an
  optional validated port spec and NSE script list. The nmap args are server-defined
  constants, so no user input is ever spliced into the command line. Intrusive
  `brute`, `exploit`, `dos` and `malware` scripts are refused.
- **Tunables** (env vars): `NMAP_DISCOVERY_ARGS`, `NMAP_SERVICE_ARGS`,
  `NMAP_TOP_PORTS`.
- **Target safety.** `target` passes a strict character allowlist so it cannot inject
  extra flags into the nmap command line, and `ScopeValidator` then requires it to
  parse as an IPv4 or IPv6 address, CIDR or range. Hostnames are refused
  (`ScopeValidator(resolve_names=False)`): vetting and the scan resolve
  separately, so a name that resolved to a permitted address at vet time could
  resolve to loopback or a public host by the time nmap looked it up, which is
  DNS rebinding through the scope policy. The CLI, where the operator types the
  target locally and no such window exists, does accept hostnames.

> **Authorization.** Only scan hosts and networks you own or are explicitly
> authorized to test. Unauthorized scanning may be illegal where you live.
