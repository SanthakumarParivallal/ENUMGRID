# Changelog

All notable changes to **ENUMGRID: the Enumeration Platform**. Format based on
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Docs — README redesign (2026-07-10)
- Rebuilt `README.md` around a hand-crafted SVG hero banner (`docs/banner.svg`, cockpit/HUD
  aesthetic, self-contained + theme-safe): an *"why it's different"* comparison vs Angry IP /
  nmap, capability sections grouped by theme (discovery · fingerprinting · deep-scan ·
  vuln-intel · monitoring · UX), and the real multi-run evaluation figure. Every in-page
  anchor and image path was verified, and the accuracy figures were reconciled against
  `docs/EVALUATION.md` (home `/24` recall **1.00** vs `nmap -sn` 0.27; busy `/24`
  **0.98 ± 0.04** vs 0.07). No claims added beyond what the eval/coverage data already backs.

### Hardened — full-repo audit (2026-07-10)
- A line-by-line read of every backend module + the CLI + the non-line-gated React
  views. Verdict: no reachable bugs — injection guards, SSRF surfaces (all fixed
  HTTPS/local endpoints), the RBAC/scope/throttle layer, the raw-packet parsers
  (NBNS/SNMP-BER/passive), and the XSS/PDF-markup sinks are all sound. Two minor
  robustness items were fixed:
  - **`report.py` — defensive numeric coercion.** `/api/report/pdf` accepts a raw
    client dict (not a validated model), so a hand-crafted authenticated POST with a
    string `cvss` or a mixed-type `port` would raise inside `build_pdf` (an unhandled
    500), contradicting its documented "a partial snapshot still renders" contract.
    Numeric fields are now coerced via a `_num()` helper (bad values are skipped, not
    fatal). Unreachable from the real UI (`schema.js` coerces to numbers) — this is
    defence-in-depth. Regression-guarded by `test_nonnumeric_cvss_and_port_still_render`.
  - **`threatintel.py` — wired up the dead cache lock.** `_lock` was declared but never
    acquired while `kev_set()` mutates the process-wide KEV memory cache — which the
    scanner calls concurrently from its thread pool. Benign under the GIL (worst case: a
    duplicate CISA-KEV download on a cold-cache burst), but the lock is now held around
    the cache check/download as intended, so the first caller fetches and the rest reuse.
- No behaviour change for the normal UI/CLI flow. Backend test count 725 → **726**;
  repo total 1221 → **1222**, all suites green, all source modules still 100% line-covered.

### Tested — 100% coverage on the frontend logic layer too (CI-gated)
- **The whole frontend `src/lib/**` layer (the pure logic + security surface) is now
  held at a full 100% line coverage** (statements + functions too), CI-gated per file
  by a new Vitest step (`Unit tests + coverage gate (src/lib at 100%)`). This is the
  browser-side peer of the CLI/backend 100% line gate and closes the last untested
  Python-or-JS surface that was genuinely unit-testable. Newly covered: the
  **view-preference store** (`preferences.js` — theme + column widths, corrupt-JSON /
  unavailable-storage recovery), the **offline scan engine** (`mockScanEngine.js` —
  driven by a fixed-seed PRNG so the randomized generator runs deterministically:
  every host archetype, filtered/UDP ports, the legacy-telnet finding, mid-run stop),
  the **toast provider** (`toast.jsx` — queueing, polite/assertive a11y roles,
  auto-dismiss timing, keyed replace, unmount cleanup), the **focus-trap hook**
  (`useFocusTrap.js` — real Tab/Shift-Tab wrapping + focus restoration), **auth-token
  persistence** (`auth.js` — localStorage round-trip, `authFetch`, the `useApiToken`
  hook), and the **blob-download** path in `exporters.js`.
- Raised the honest way — real jsdom DOM, real timers, real `ThreadPoolExecutor`-free
  async; only true I/O boundaries (`fetch`, `URL.createObjectURL`, a throwing
  `localStorage`) are stubbed. The gate matches the Python **line-coverage** standard
  (lines + functions + statements at 100 per file); branch coverage is reported but
  not gated at 100, so genuinely-unreachable defensive `x || fallback` arms don't have
  to be stripped from otherwise-robust code.
- Removed two provably-dead guards while covering `mockScanEngine.js` (a redundant
  `if (cancelled) return` in `emit`, and a `&& !cancelled` on a completion-only path)
  and one dead updater-form in `preferences.js` — pure dead-code simplification,
  behaviour-identical (verified in the running app: theme toggle persists/applies, and
  the default **no-fake-data** path still fails honestly when the backend is down).
- Frontend test tooling: added `@vitest/coverage-v8`, `jsdom`, `@testing-library/react`
  (dev-only). A small in-memory `Storage` shim (`vitest.setup.js`) stands in for the
  browser's `localStorage`, which jsdom leaves out on the default opaque origin.
- The large stateful React views (`IndustrialDashboard`, `ScanContext`, `CopilotPanel`)
  stay ESLint- + E2E-verified, **not** force-gated to 100% — a 3 000-line DOM view
  driven to full line coverage in jsdom would be coverage theatre. Frontend test count
  108 → **206**; repo total 1123 → **1221**, all green.

### Tested — 100% coverage on the CLI too (CI-gated)
- **`purple_recon.py` (the single-file CLI, 1 095 statements) is now held at a full
  100% line coverage**, up from a 50% floor. The gate (`Run CLI test suite (100%
  coverage gate, no regression)`) fails on any regression. This closes the last big
  Python surface: the **threaded discovery engine** (ICMP/TCP sweep, RST-confidence
  policy, ARP-proxy guard, MAC/vendor enrichment), the **enumeration engine** (nmap
  service/OS parsing **and** the built-in socket-scan fallback + banner grab), the
  **orchestrator** (both phases, discover-only, abort, fatal-error paths), **both
  run-loops** (the `rich` cockpit and the headless fallback, including Ctrl-C), and
  the whole **`main`/`cli`** argument-to-export flow. New file
  `tests/test_purple_recon_coverage.py` (+105 tests); CLI count 92 → **197**, repo
  total 1018 → **1123**.
- Raised the honest way — the network, subprocess, nmap and DNS boundaries are
  mocked (real `socket`/`ThreadPoolExecutor`/thread code runs), never coverage-gamed.
  The only new `# pragma: no cover` is the optional `import nmap` guard.
- **Fixed a genuine test-coverage gap masked by nondeterminism:** the `_mac_vendor`
  non-hex-first-octet (`ValueError`) branch was only ever exercised by the
  property-based fuzz test, so the coverage total flaked between 99% and 100% run to
  run. Added a deterministic case; the gate is now stable at exactly 100%.
- Small testability refactor: the IEEE OUI download URL is now a module constant
  (`_OUI_REGISTRY_URL`) so the HTTPS-only defence-in-depth guard is exercisable.

### Tested — 100% coverage on the entire backend (CI-gated)
- **Every one of the 30 backend modules is now held at a full 100% line coverage**
  (3 990 statements) — up from a 20-module / ≥95%-critical gate. This now includes the
  previously-hardest live-I/O modules: the **async scan engine** (`scanner`,
  `discovery` — driven end-to-end through a stubbed `_run_scan` / signal-source
  boundary), the **FastAPI service** (`app` — every endpoint, worker, and the
  scheduler ticker exercised via the TestClient with internals mocked), the **AI
  copilot** (`copilot` — streaming parsed against mocked Anthropic/OpenAI clients),
  and the credentialed integrations (`credscan`/paramiko, `cloudscan`/boto3,
  `adscan`/ldap3, `passive`/scapy, `mdns`/zeroconf, `osfp`). CI (`Coverage gate —
  all backend modules`) fails on any regression. Backend test count 509 → **725**.
- Coverage was raised with **real tests, never coverage-gaming**: I/O mocked at the
  boundary (urlopen / sockets / http.client / SDK clients / `_run_scan`), real DER
  certs via `cryptography`, real scapy/zeroconf packet objects, fault-injection to
  prove untrusted-input parsers degrade gracefully, and small refactors
  (`security`/`history`/`discovery._ensure_on_path`) that turned untestable
  import-bootstrap branches into unit-testable helpers. The only `# pragma: no cover`
  markers are on optional-dependency `import` guards and CLI `__main__` entrypoints.
- The optional SDKs (`paramiko`, `boto3`, `ldap3`, `scapy`, `anthropic`, `openai`)
  are added to `requirements-dev.txt` so CI installs them and the credentialed/live
  code paths run under mocked network — making the 100% gate meaningful, not a stub.

### Security — end-to-end audit pass
- **Closed an authorization gap on `POST /api/report/pdf`** — every other read/write
  endpoint enforced RBAC, but the PDF/report endpoint had **no token check**, so with
  `ENUMGRID_ADMIN_TOKEN` configured an unauthenticated caller could render arbitrary
  PDFs (CPU) and, via `include_ai_summary`, **spend the operator's own LLM key** and
  trigger outbound provider calls (financial DoS). It is now **read-gated**
  (`token_ok`, viewer/admin) exactly like `/api/copilot/summary`; the dashboard
  already sent its bearer token, so the fix is transparent. Regression-tested
  (`test_report_pdf_is_read_gated_in_token_mode`). Threat model **T18** updated.
- **Patched vulnerable dependencies** — `pip-audit` flagged four advisories:
  `starlette` 1.2.1 → **1.3.1** (PYSEC-2026-248/249; FastAPI's HTTP core, in the
  request path), `msgpack` 1.1.2 → **1.2.1** (GHSA-6v7p-g79w-8964), and
  `cryptography` 48.0.0 → **48.0.1** (GHSA-537c-gmf6-5ccf, pulled in via `paramiko`).
  `requirements.lock` bumped, a `cryptography>=48.0.1` security floor added to
  `backend/requirements.txt`, and `pip-audit` is **back to 0 known CVEs**.
- **Least-privilege container (CWE-250)** — the Docker image ran `uvicorn` as **root**;
  it now runs as a **non-root user** (`enumgrid`, uid 10001). The scanner is designed
  to run unprivileged (raw-socket scans auto-downgrade to connect scans), so no default
  functionality is lost while a web-tier compromise no longer implies host root. Threat
  model **T22** added.
- **Audit coverage** — reviewed command execution (fixed-argv nmap, no shell; strict
  target allowlist), SSRF surfaces (copilot/NVD/OSV/KEV/EPSS use fixed HTTPS endpoints
  with URL-encoded params), XSS (escape-first Markdown renderer, scheme allow-list),
  PDF/reportlab markup escaping, SQLi (parameterized), and secret handling (0600,
  gitignored, never logged) — no further defects found. Full suite **802 tests** green;
  ruff, bandit (0 high/med), pip-audit and npm audit all clean.

### Changed — project layout & tooling
- **Repository restructure** — moved the test suites out of the source
  directories (`backend/test_*.py` → `backend/tests/`, root
  `test_purple_recon.py` → `tests/`) and consolidated `pytest.ini` + `ruff.toml`
  into `pyproject.toml` (one config source; `pythonpath` lets the relocated tests
  resolve their flat imports from any CWD). Purged build/artifact clutter from the
  working tree. CI, `Makefile`, `.dockerignore`, and docs updated in lockstep;
  `uvicorn app:app` and `python purple_recon.py` entrypoints unchanged, all 582
  tests green.

### Fixed
- **`POST /api/schedules` 500 on array `days`** — `schedule.parse_days` assumed a
  comma-separated string and raised `AttributeError` when a client sent `days` as
  a JSON array (e.g. `["mon","wed"]`). It now accepts both the array and the
  comma-string (what the cockpit UI already sends), so the endpoint returns the
  created rule instead of a 500. Found via live end-to-end testing; regression-tested.

### Added — AI copilot (multi-provider incl. free local/cloud, scan-grounded, agentic)
- **In-cockpit AI copilot** (`backend/copilot.py`, `frontend/src/CopilotPanel.jsx`,
  `/api/copilot*`) — a security-analyst chatbot embedded in the dashboard that is
  **grounded in the live scan** (it answers about *your* hosts / ports / CVEs, and
  says so honestly when the context doesn't contain the answer — never fabricates).
- **Four providers, switchable in the dashboard — two of them free.** Ollama
  (**local, keyless, zero-cost** — the scan never leaves the machine; default), Google
  Gemini (**free tier**), plus Anthropic Claude and OpenAI (paid). Gemini and Ollama
  speak the OpenAI wire protocol, so they reuse the OpenAI code path with a different
  base URL. Each SDK is optional; a missing SDK or key returns `ready:false` with a
  reason instead of a fake reply — and if the local Ollama server is down, the chat
  surfaces a real "start Ollama" message, never a fabricated answer. The operator
  pastes any needed key **directly in the panel** (persisted `0600`, gitignored, never
  logged), mirroring the NVD-key pattern — plus `POST /api/copilot/key` / `/provider`.
- **Turnkey Ollama — no terminal required.** The dashboard probes the local Ollama
  server (`/api/tags`) to report, honestly, whether it's running and which models are
  installed; a provider is only `ready` once its chosen model is actually present.
  When it isn't, the panel becomes a guided setup: download link + auto-detect polling
  → **one-click model download with a live streamed progress bar** (`POST
  /api/copilot/ollama/pull`) → a model picker (`POST /api/copilot/model`, persisted).
  Model names are validated; the pull streams Ollama's real byte-level progress.
- **Agentic, human-in-the-loop** — the model can call a `propose_scan` tool; the
  backend never runs it, it surfaces the proposal as a confirm button that launches
  the normal scope-vetted scan. A security tool never scans without the operator.
- **Streaming** — replies stream token-by-token over SSE (`POST /api/copilot/chat`).
  Opens from a floating launcher, the ⌘K palette, or the Settings menu.
- **Readable replies + chat niceties** — copilot answers render as **Markdown**
  (headings, lists, bold, inline/fenced code, links) via a dependency-free,
  HTML-escaping renderer (`frontend/src/lib/markdown.js`) that allow-lists link
  schemes and autolinks **CVE ids to NVD** — XSS-tested. A **Stop** button aborts a
  streaming reply (partial text kept), the **conversation persists** across
  panel close/reopen (local only), and a **New chat** button clears it.
- **Grounded, factual by default** — the copilot runs at a low temperature (0.2) and
  **only arms the `propose_scan` tool when the operator actually asks to scan**
  (`wants_scan`). This fixed a real issue found in live testing: small local models
  (Llama 3.2 3B) would otherwise call the tool — or emit fake tool-call JSON as text —
  instead of answering an analytical question. Now analytical questions get clean
  prose; "run a scan on X" still gets the agentic proposal.
- **AI executive summary in the PDF report** — the export menu's *PDF + AI summary*
  (or `include_ai_summary` on `POST /api/report/pdf`) prepends a grounded,
  copilot-written executive summary (`copilot.summarize_scan`, tools disabled). The
  model's text is HTML-escaped into the report; a copilot failure never blocks it.
- **Copilot evaluation harness** (`evaluation/copilot_eval.py`) — measures the
  copilot's **grounding** (fraction of answers that invent nothing — including *novel*
  fabricated CVE ids, not just pre-listed traps) and **coverage** (expected facts hit)
  over a fixed scan, in the style of `benchmark.py`. Deterministic, unit-tested scoring;
  real numbers when a provider is configured, `--self-test` fixtures otherwise. It
  never fabricates a score. A live run of the free Llama 3.2 scored perfect grounding
  once temperature was lowered, and caught a real CVE hallucination before that fix.

### Added — passive discovery, scheduling & campaigns
- **Passive (zero-packet) discovery** (`backend/passive.py`, `POST /api/passive`,
  runnable standalone) — a stealth discovery mode that **sends nothing on the
  wire**: it listens for the broadcast/multicast chatter hosts emit on their own
  (ARP, DHCP, mDNS, LLMNR, NetBIOS) and reports who is talking. Invisible to an
  IDS watching for scans, and a clean research contrast to active discovery. scapy
  is an optional dependency and capture needs raw-socket privilege; when either is
  missing the endpoint returns `available:false` with a reason (never fabricates
  hosts). The aggregation/classification core is pure + unit-tested.
- **Cron-style scheduled scans** (`backend/schedule.py`, `/api/schedules` CRUD) —
  unattended, time-of-day recurring scans ("sweep 192.168.0.0/24 every weekday at
  02:00") that fire even with no browser open. A background ticker enqueues a
  headless `network_scan` job (the same pipeline the UI drives), so results land
  in history + drift automatically. Rules are scope-validated on creation, persist
  across restarts, and the recurrence math (`due`/`next_run`) is pure + tested.
- **Multi-subnet campaign view** (`backend/campaign.py`, `GET /api/campaign`) —
  rolls the *latest* stored scan of several subnets into one estate-wide picture:
  total unique hosts, open ports, a merged inventory, and mixed device / service /
  severity rollups. Unscanned subnets are shown honestly rather than dropped.
- **Operations panel** (web) — one accessible, focus-trapped modal (⌘K → "Operations",
  or Settings ▸ Operations) with **Passive**, **Schedules** and **Campaign** tabs
  surfacing all three capabilities in the cockpit.
- **SMB share enumeration** — the Recon profile now includes the info-level
  `smb-enum-shares` NSE script (lists shares; not brute/exploit), deepening
  internal enumeration without changing the safe-by-construction posture.

### Added — evaluation & reproducibility
- **Multi-run benchmark statistics** (`evaluation/benchmark.py --runs N`) — repeats
  each tool N times and reports **mean ± 95 % CI** for recall, precision and time
  (previously single-run, no variance). Adds a field of real, install-gated
  baselines — **arp-scan, netdiscover, masscan** — alongside `nmap -sn`
  (`--baselines`), and an optional **recall/time bar chart** (`--plot`, matplotlib).
  Baselines that aren't installed are reported as such, never counted as "found
  nothing". (rustscan is intentionally excluded — it's a port scanner, not a
  host-discovery tool, so a recall comparison would be unfair.)
- **Reproducibility manifest** — every CLI JSON report (`build_report`) and the
  backend (`/api/health` + exported PDF) now embed a provenance block: tool +
  version, exact **git commit**, **nmap version**, Python runtime, OS, and
  timestamp — so a result reproduces by itself. Best-effort and honest (unknowns
  are labelled, never fabricated).

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
- **Action-feedback toasts** (`frontend/src/lib/toast.jsx`) — every operation (scan
  start/stop/complete, privilege elevate/drop, PDF/CSV/JSON export, and failures)
  raises a concise, auto-dismissing toast. Errors use `role="alert"` (assertive),
  the rest `role="status"` (polite); reduced-motion aware. Scan toasts key off state
  transitions, so a scan restored from `localStorage` never fires a spurious
  "complete" on page load.
- **⌘K command palette** (`frontend/src/lib/commandFilter.js`) — a searchable
  launcher for every top action (scan · deep · monitor · elevate · exports ·
  theme/density · focus search · shortcuts) with fuzzy ranking, arrow-key navigation
  and full focus management.
- **Keyboard shortcuts + `?` help** (`frontend/src/lib/shortcuts.js`) — `/` focus
  search · `t` theme · `d` density · `?` help · `Esc` close, plus ⌘K for the palette.
  A focus-trapped help overlay lists them and the Settings menu links to it.
  Deliberately no scan-triggering key, so a stray keystroke can never start a scan.
- **First-run welcome** — a one-time toast points new operators at ⌘K and `?`.
- **Accessibility pass** (WCAG 2.4.3 / 2.4.7 / 4.1.2) — every modal (Privilege,
  shortcuts, command palette, token/NVD popovers) traps keyboard focus and restores
  it to the trigger on close (`frontend/src/lib/useFocusTrap.js`); every command-bar
  control gained a keyboard-only `focus-visible` ring and an `aria-label`, so
  icon-only/label-collapsing buttons are named for screen readers.

### Added — tooling & evaluation
- **Frontend ESLint** (`frontend/eslint.config.js`) — flat config with `react`,
  `react-hooks`, and `jsx-a11y`; wired into CI and `npm run lint`. Fixed the 27
  findings it surfaced (unused imports/directives, a hooks `exhaustive-deps` bug,
  static-element interactions).
- **Privileged benchmark baseline** (`evaluation/benchmark.py --privileged`) — the
  harness can now also run `sudo nmap -sn` (ARP) and report how closely root-nmap
  agrees with EnumGrid, turning the "privileged nmap would tie" caveat into a
  measured, reproducible result (see `docs/EVALUATION.md`).
- **CI** now tests **Python 3.14** (matrix 3.10–3.14) and runs ESLint in the
  frontend job; safe within-major frontend dep bumps (vite/vitest/plugin-react).

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
