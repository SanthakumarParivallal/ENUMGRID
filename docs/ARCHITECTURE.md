# ENUMGRID — Architecture

How the system is built and **why** it's built that way. The design goal is a
tool that thinks like an offensive scanner but behaves like a defensive asset
mapper: fast, honest, unprivileged-friendly, and safe to point at a real network.

![ENUMGRID architecture diagram](architecture.svg)

## 1. One engine, two front-ends

```
                     ┌───────────────────────────────┐
   purple_recon.py ──┤ ScopeValidator · DiscoveryEngine · OUI/ARP/NDP/MAC ·
   (CLI cockpit)     │ diff_reports · report builders   (the shared engine)
                     └───────────────────────────────┘
                                  ▲ imported by
        backend/ (FastAPI) ───────┘   discovery.py · security.py · history.py
        frontend/ (React)  ──HTTP/SSE──► backend
```

The CLI is the **single source of truth**. The web backend imports it
(`sys.path` to the repo root) rather than re-implementing scope rules, ARP/NDP
parsing, MAC/OUI vendor logic, or the drift diff. This is the most important
structural decision: **security-critical logic exists once**, is tested once,
and cannot drift between the two interfaces.

## 2. The two-tier pipeline (and why)

| Phase | What | Why split |
|---|---|---|
| 1 · Horizontal sweep | Find *which* hosts are live + name/type them (ICMP/TCP/ARP/NDP/mDNS/NBNS/SNMP/SSDP/TTL + common-port preview) | Cheap, fast, runs unprivileged; you almost always want the inventory first |
| 2 · Vertical deep-dive | Find *what's on* a host (`nmap -sV`, NSE, `-O` if root) | Expensive + noisy; should be **on demand**, per host or "Scan All" |

Separating discovery from enumeration is what makes the tool feel like Angry IP
*and* Zenmap: an instant device list, then opt-in depth. The web UI makes Phase 2
explicitly user-triggered so a scan never blasts every port on every host by
surprise.

## 3. Confidence-graded liveness (anti-false-positive)

Not every "response" proves a host exists. The discovery engine grades evidence:

- **strong** — a completed TCP handshake (real listening service) or an ICMP
  echo reply, or a MAC in the ARP/NDP cache. Cannot be forged by a silent-drop
  firewall.
- **weak** — only a bare TCP `RST` (connection *refused*). A `reject`-style
  firewall sends these for **dead** addresses too, which would make every IP look
  "up". Weak hosts are **suppressed by default** (`--rst-up` to include).

The policy is the pure, unit-tested `DiscoveryEngine._decide(strong, saw_rst,
rst_up)`. A separate **proxy-ARP guard** (`_proxy_macs`) drops a router that
answers ARP for the whole subnet with one MAC — the classic 254-fake-hosts bug.

## 4. Multi-method discovery (each covers the others' blind spots)

| Method | Catches |
|---|---|
| ICMP echo (generous timeout + retry) | Most devices; slow Wi-Fi responders |
| TCP connect probes | ICMP-blocked hosts running a service |
| **ARP cache** (`arp -an`) | ICMP-silent LAN devices (power-save phones, IoT) |
| **NDP cache** (`ndp -an` / `ip -6 neigh`) | Each device's IPv6 (correlated by MAC) |
| **mDNS/Bonjour** | Real device names + types (printers, Apple, cast, HomeKit) |
| **NBNS (NetBIOS)** | Windows / printer / NAS names with no reverse-DNS |
| **SNMP** | Switch/AP/printer `sysName`/`sysDescr` |
| **SSDP/UPnP** | Router / TV / media / console / IoT `friendlyName` + model |
| **TCP port preview** | Open common ports (no nmap/root) → instant grid + sharper device type |
| **Ping TTL** | An honest OS *family* without root |

Names are layered cheapest-first: reverse-DNS → NBNS → SNMP → mDNS → SSDP, each
filling gaps the previous left. The TCP port preview is a fast, fanned-out
connect-scan of the common ports during discovery; its results both populate the
grid immediately and feed the device-type classifier (open-port signatures are
its strongest signal), so DEVICE/OS sharpens before the on-demand `nmap -sV` runs.

This is the measured design thesis (see [`EVALUATION.md`](EVALUATION.md)):
unprivileged, it finds ~3.7× the hosts of `nmap -sn`.

## 5. Web backend — streaming, async, stateless

- **SSE, not polling.** `GET /api/scan/stream` yields `ScanState` snapshots as the
  scan progresses, so the grid fills live. Blocking nmap/ICMP work runs in a
  thread-pool executor so the event loop (and the stream) stay responsive.
- **Stateless w.r.t. the current scan.** The backend holds no "current scan"
  object; the client owns the live state and POSTs it back for the PDF
  (`/api/report/pdf`). Only *completed* scans are persisted (SQLite). This keeps
  the server simple and horizontally restartable.
- **Validated frames.** Pydantic models (`backend/models.py`) are mirrored
  field-for-field by `frontend/src/lib/schema.js`, whose factories coerce every
  field and never throw — a malformed frame can't corrupt the UI tree.

### 5a. Cockpit theming & view preferences

The dashboard is **themeable without a re-render**: `index.css` defines the colour
ramp (chassis + neutral text/border shades) as CSS variables, and Tailwind's
`steel`/`slate` colours are declared as `rgb(var(--token) / <alpha-value>)`. A
single `<html data-theme="light|dark">` swap repaints everything (opacity
modifiers keep working via `<alpha-value>`); signal accents (amber/matrix/crimson)
are shared. **Density** (`data-density`) and **column widths** work the same way —
attribute selectors / inline `gridTemplateColumns` rather than React state for the
visual. `frontend/src/lib/preferences.js` persists theme · density · column widths
to `localStorage` and applies them at import time (before first paint, no flash).
The matrix header and every row consume one shared grid-template string, so
drag-resized columns stay aligned by construction.

## 6. Persistence & drift

`backend/history.py` is a dependency-free SQLite store. Drift ("What Changed")
**reuses the CLI's `diff_reports()`** so the comparison logic lives in one place;
the API just enriches appeared/disappeared IPs with vendor/hostname. Monitor mode
is a declarative React effect that re-schedules a scan after each completion and
raises an alert (+ desktop notification) when drift is detected.

## 7. Security controls (summary)

`ScopeValidator` (loopback/multicast/broadcast/link-local/reserved/oversized,
IPv4 **and** IPv6) + an anti-injection target regex, reused by both front-ends;
public-target refusal, a concurrency cap, and an optional token gate on the API.
Full detail in [`THREAT_MODEL.md`](THREAT_MODEL.md).

## 8. Testing strategy

- **Deterministic unit tests** for all pure logic (guardrails, parsers,
  fingerprinting, CVSS, drift) — no network, safe in CI.
- **FastAPI TestClient** integration tests for every endpoint (scope rejection,
  PDF, history) using *rejected* targets so nothing scans.
- **Property-based fuzzing** (hypothesis) of every parser that touches hostile
  network/API input — they must never raise.
- **Coverage gates** (CLI ≥50%, backend ≥60%; the uncovered remainder is the
  live-network/`rich`-UI I/O that unit tests deliberately don't exercise).
- **SAST + dependency audit** (bandit, pip-audit, npm audit) in CI.
- A **black-box benchmark** vs nmap for measured accuracy.

## 9. Key trade-offs (honest)

| Decision | Trade-off |
|---|---|
| Unprivileged by default | No raw-socket OS fingerprint without `sudo`; TTL family fills the gap |
| Union-as-proxy in the benchmark | Can't see hosts *neither* tool finds → the docker testbed gives true ground truth |
| Single-file CLI imported by the backend | Slightly unusual import path, in exchange for zero logic duplication |
| mDNS run after the active probe | +~5s, but reliable (the 128-thread sweep was starving multicast) |
| Stateless backend | Client must re-send state for the PDF; in exchange the server stays trivial |
