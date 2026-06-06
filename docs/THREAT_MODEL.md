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
| T9 | **Malicious banner / ARP / NDP / mDNS data crashing the parser** | Parsers are defensive and **fuzz-tested** (hypothesis); the UI's schema layer coerces every field and never throws | parser tests, `frontend/src/lib/schema.js` |
| T10 | **Supply-chain (vulnerable deps)** | CI runs **`bandit`** (SAST), **`pip-audit`**, and **`npm audit --omit=dev`** on every push; shipped deps are 0-vuln | `.github/workflows/ci.yml` |

## 5. Residual risk & guidance

- **TTL-based OS detection** is a *heuristic family* (not authoritative); run with
  `sudo` for nmap `-O`. The tool never presents a fabricated OS.
- **mDNS** is best-effort (depends on what devices advertise).
- **Dev-tooling advisories** (vitest/vite/esbuild) affect only the local dev
  server, never the shipped build (`vite build` output contains none of them); CI
  gates on **shipped** deps via `npm audit --omit=dev`.
- **Before exposing the API beyond localhost**: set `ENUMGRID_API_TOKEN`, keep
  `ENUMGRID_ALLOW_PUBLIC` unset, and front it with TLS.

## 6. Authorization (legal)

EnumGrid is for assets you **own or are explicitly authorized to test**.
Unauthorized scanning may be illegal. The guardrails reduce *accidental* harm;
they are not a substitute for authorization.
