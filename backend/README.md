# Enumeration Platform — Backend (FastAPI + Nmap)

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
| GET | `/api/network` | best-effort `{ primary_ip, suggested_target }` (dashboard auto-fill) |
| GET | `/api/scan/stream?target=<t>&id=<id>&mode=<discover\|full>&deep=<0\|1>` | SSE stream of `ScanState` frames |
| GET | `/api/host/scan?ip=<ip>&deep=<0\|1>` | deep-scan one host, returns its `Host` (per-row action) |

`mode=discover` (default) is the fast device inventory (MAC + vendor + hostname,
no nmap). `mode=full` runs the two-tiered nmap pipeline. `deep=1` adds an NSE
**vuln-script** pass (`nmap --script vuln,vulners`), populating each port's
`vulns[]` with real findings (CVE id, CVSS, severity). It's much slower, so it's
opt-in.

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
| `PURPLERECON_ALLOW_PUBLIC` | `0` | set `1` to permit public targets (authorized use only) |
| `PURPLERECON_MAX_SCANS` | `4` | cap on concurrent scans (excess → `429` / "server busy") |
| `PURPLERECON_MAX_HOSTS` | `4096` | per-request host cap |
| `PURPLERECON_API_TOKEN` | _(unset)_ | when set, require `?token=` or `Authorization: Bearer …` |

Auth is **off by default** (the server binds to localhost), so the local dev flow
needs no configuration. Set a token before exposing the API beyond localhost.

## Notes

- **Run as root for richer data.** Unprivileged scans use TCP connect discovery
  and connect service scans (no `sudo` needed). Running with `sudo` enables OS
  detection (`-O`) and raw-packet host discovery.
- **Tunables** (env vars): `NMAP_DISCOVERY_ARGS`, `NMAP_SERVICE_ARGS`,
  `NMAP_TOP_PORTS`.
- **Target safety.** `target` is strictly allowlisted (IPv4 / CIDR / range /
  hostname) so it can't inject extra flags into the nmap command line.

> ⚠️ **Authorization.** Only scan hosts and networks you own or are explicitly
> authorized to test. Unauthorized scanning may be illegal where you live.
