# EnumGrid — Threat Model

A security tool must be able to account for its own posture. This document states
what EnumGrid protects, the trust boundaries it sits across, the threats that
follow, and the controls that mitigate them. It is deliberately concise and is
kept in sync with the code (`backend/security.py`, `purple_recon.ScopeValidator`,
the test suites, and the CI security jobs).

## 1. Assets

| Asset | Why it matters |
|---|---|
| The host running EnumGrid | Must never be turned against itself (self-DoS) |
| The target network's confidentiality | Scan results reveal hosts, services, vulns |
| Scan reports / history DB | Operator data (devices, open ports, CVEs) — sensitive |
| The operator's authorization scope | Scanning out of scope can be illegal |

## 2. Trust boundaries

```
   Operator ──► CLI (purple_recon.py) ──► subprocess: ping/arp/ndp/nmap ──► Network
                                     └──► filesystem: JSON/HTML/CSV/PDF reports

   Browser ──HTTP──► Vite proxy ──► FastAPI (backend/app.py) ──► subprocess: nmap ──► Network
                                                            └──► SQLite history DB
```

The two boundaries that matter most:
- **HTTP → backend** — anything that can reach `:8011` can request a scan.
- **app → subprocess** — user-influenced values (the scan *target*) flow toward a
  command line (`nmap`), so argument injection is the key risk.

## 3. Adversaries & assumptions

- **Assumed trusted:** the operator running the tool, and `localhost`. The backend
  **binds to `127.0.0.1`** by default.
- **Assumed hostile:** the scan *target* and any value derived from the network
  (banners, ARP/NDP/mDNS replies), and — if the port is ever exposed — any client
  that can reach the API.
- **Out of scope:** a fully compromised host (root on the box already), and the
  security of `nmap`/the OS themselves.

## 4. Threats → controls (STRIDE-flavoured)

| # | Threat | Control | Where |
|---|---|---|---|
| T1 | **Self-DoS** — scanning loopback / multicast / broadcast / a `/8` | `ScopeValidator` hard-refuses loopback/multicast/broadcast/link-local/reserved (IPv4 **and** IPv6) and caps host count; the **web API reuses the same validator** | `ScopeValidator`, `backend/security.py:vet_target` |
| T2 | **nmap argument injection** — a target like `-oG /etc/x` or `--script=evil` | Strict allowlist regex (must start alnum/`:`, no whitespace) **+** `ScopeValidator`; nmap is invoked with list-form args, never a shell | `scanner._TARGET_RE`, `vet_target` |
| T3 | **Command injection via subprocess** | Every `ping`/`arp`/`ndp`/`nmap` call uses **list-form args** (`subprocess.run([...])`), never `shell=True`; inputs are validated first | `purple_recon.py`, `backend/osfp.py` |
| T4 | **Scanning out of scope / public space** | Public/internet-routable targets are **refused by default**; opt-in via `ENUMGRID_ALLOW_PUBLIC=1`. CLI requires confirmation for public/large scopes | `vet_target`, `confirm_scope` |
| T5 | **Scan-as-a-service abuse / resource exhaustion** | Per-process **concurrency cap** (`ENUMGRID_MAX_SCANS`, default 4 → excess gets `429`); host cap per request | `backend/security.scan_slot` |
| T6 | **Unauthorized API access (if exposed)** | Optional **bearer token** (`ENUMGRID_API_TOKEN`); localhost-only bind by default; CORS limited to the dev origin + GET/POST | `backend/security.token_ok`, `app.py` CORS |
| T7 | **SSRF via OUI download** | The IEEE OUI URL is a constant and **HTTPS-scheme-checked** before `urlopen` | `download_oui_registry` |
| T8 | **Report tampering / info leak at rest** | Reports + history are **operator-local**, `.gitignore`d; JSON/HTML/CSV written atomically with **mode 0600** | `write_report`, `.gitignore` |
| T9 | **Malicious banner / ARP / NDP / mDNS / SSDP data crashing the parser** | Parsers are defensive and **fuzz-tested** (hypothesis); the UI's schema layer coerces every field and never throws | parser tests, `frontend/src/lib/schema.js` |
| T10 | **Supply-chain (vulnerable deps)** | CI runs **`bandit`** (SAST), **`pip-audit`**, and **`npm audit --omit=dev`** on every push; shipped deps are 0-vuln | `.github/workflows/ci.yml` |
| T11 | **SSRF via SSDP `LOCATION`** — a rogue device advertises a UPnP description URL pointing at some *other* internal host | The description is fetched **only when its host matches the device that answered** and the scheme is http/https; the XML is scraped with targeted regexes (no XML parser → no XXE/entity expansion) | `backend/ssdp.py:_location_is_safe`, `discover_ssdp` |
| T12 | **Report injection / DoS** — a device service banner (or hostname / vuln output) containing `<`, `>`, `&` breaks or injects into the PDF | Every device-/client-supplied value is **escaped** before reaching reportlab's `Paragraph`; CVE links use a quoted, scheme-checked URL | `backend/report.py:_esc` |
| T13 | **Auth-token recovery via timing** | Admin / viewer token comparison uses **`hmac.compare_digest`** (constant-time) | `backend/security.py:role_for` |
| T14 | **Hostile TLS certificate during web audit** | The web audit connects with `CERT_NONE` (it *inspects*, doesn't trust-gate), reads the cert in **DER form** and parses it with `cryptography` — a malformed cert yields no findings, never a crash | `backend/webscan.py:_peercert_dict` |
| T15 | **LAN exposure of the zero-config API** — binding to `0.0.0.0` (Docker `--network host`) with no token would let any LAN host drive the scanner (open mode grants admin to all) | The zero-config "open" mode is **fail-closed to local clients only**: a middleware refuses any `/api/*` call from a non-loopback peer when no token is set, so exposure requires an explicit `ENUMGRID_ADMIN_TOKEN` | `app.py:_local_only_in_open_mode`, `security.client_is_local`, `security.open_mode` |
| T16 | **DNS-rebinding / drive-by scanning** — a malicious web page resolves its domain to `127.0.0.1` and issues `GET /api/scan/stream?...` to make the local browser drive the scanner | In open mode the middleware also validates the **`Host` header** is local (a rebind sends `Host: evil.com`); state-changing JSON `POST`s are additionally CORS-preflight-gated to the dev origin | `app.py:_local_only_in_open_mode`, `security.host_header_local` |
| T17 | **Inventory disclosure via history endpoints** — `/api/history*` returned the device/port inventory without auth even when tokens were configured | Both endpoints are now **RBAC-gated** (viewer/admin) like `/api/audit`; open when no tokens are set | `app.py:history_list/history_diff`, `security.token_ok` |
| T18 | **Memory exhaustion via the PDF endpoint** — an oversized POST body to `/api/report/pdf` could blow up reportlab | The host list is **capped** (`MAX_REPORT_HOSTS`, well above the scan host cap) before rendering | `backend/report.py:build_pdf` |
| T19 | **Sudo-password handling for runtime elevation** — `POST /api/privilege/elevate` accepts a sudo password to enable raw-socket scans without a restart; a mishandled secret could leak | The password is **admin-gated / local-only** (open-mode guard), validated via `sudo -k -S` (forced re-auth), then held **only in process memory** (`scanner._SUDO_PASSWORD`) — never persisted, logged, or echoed in a response; the audit records only that an attempt happened, never the secret. `POST /api/privilege/drop`, `ENUMGRID_AUTO_SUDO=0`, and process exit all clear it | `backend/scanner.py:elevate_sudo`, `app.py:privilege_elevate` |

## 5. Residual risk & guidance

- **TTL-based OS detection** is a *heuristic family* (not authoritative); run with
  `sudo` for nmap `-O` — either at start-up (`./start.sh --accurate-os`) or on
  demand via the dashboard's **Privilege → Elevate** control. The tool never
  presents a fabricated OS.
- **Runtime elevation on a shared host:** the sudo password primed via
  **Elevate** lives only in the backend process memory for the session. On a
  multi-user machine, click **Drop** (or restart the backend) when finished, or
  disable elevation entirely with `ENUMGRID_AUTO_SUDO=0` and start elevated
  instead. See T19.
- **mDNS / SSDP / NBNS / SNMP** name resolution is best-effort (depends on what
  each device chooses to advertise); a blank name is reported as blank, never guessed.
- **Dev-tooling advisories** (vitest/vite/esbuild) affect only the local dev
  server, never the shipped build (`vite build` output contains none of them); CI
  gates on **shipped** deps via `npm audit --omit=dev`.
- **Before exposing the API beyond localhost**: set `ENUMGRID_API_TOKEN`, keep
  `ENUMGRID_ALLOW_PUBLIC` unset, and front it with TLS. Without a token the API is
  fail-closed to local clients (T15/T16), so remote access is opt-in by design.
- **Prefer the `Authorization: Bearer …` header over `?token=`** when a token is
  configured: query strings can be written to access logs / proxy logs / browser
  history. The `?token=` form remains for convenience but the header is the
  recommended channel, especially over a shared or proxied deployment.
- **Credentialed inputs** (`/api/host/credscan` SSH, `/api/ad/enum` LDAP) are
  **admin-gated** and used in memory only (never logged/stored); a client-supplied
  `key_filename` / `dc_host` is trusted *because the caller is already admin* —
  these endpoints are for assets you administer, with your own credentials.
- **Local data at rest** (history DB, CVE/KEV/EPSS caches, audit log) is
  operator data; on a shared host, restrict the working directory's permissions
  (the NVD key file is already written `0600`).

## 6. Authorization (legal)

EnumGrid is for assets you **own or are explicitly authorized to test**.
Unauthorized scanning may be illegal. The guardrails reduce *accidental* harm;
they are not a substitute for authorization.
