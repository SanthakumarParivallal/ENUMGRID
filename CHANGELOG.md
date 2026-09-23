# Changelog

All notable changes to ENUMGRID, the Enumeration Platform, are recorded in this file.

The format follows [Keep a Changelog 1.1.0][kac] and the project versions according to
[Semantic Versioning 2.0.0][semver].

## Conventions

- **Public interface.** For versioning purposes the public interface is the HTTP API
  (`/api/*`), the `purple_recon` CLI flags and exit codes, the `ENUMGRID_*` environment
  variables, and the on-disk report and export schemas. Internal module layout is not part
  of it.
- **Measured claims.** Every quantitative statement below was produced by a checked-in,
  re-runnable harness or captured from a real authorised scan. Each one names its
  artifact under [`evaluation/results/`](evaluation/results/README.md) so a reader can
  re-derive it. Nothing here is estimated, rounded up, or simulated.
- **Limitations are listed.** Where a capability has a known failure mode, or the
  evaluation has a known weakness, it appears under *Known limitations*.

---

## [Unreleased]

A correctness and operator-workflow pass. The headline fix is IPv6: a v6 target passed
scope validation and was then reported **down**, because every probe opened an IPv4
socket. A silent false negative is the worst failure mode for an enumeration tool, so it
is treated as a correctness bug, not a missing feature.

### Fixed

- **IPv6 targets are now actually probed.** `DiscoveryEngine.is_alive` and
  `EnumerationEngine._socket_scan` opened a hardcoded `AF_INET` socket, so every port
  probe against an IPv6 address raised `OSError` and the host was recorded as down.
  Probes now open a socket of the target's own family (`_af_for`), ICMP uses the
  platform's v6 invocation (`ping6` on macOS, where `ping` rejects `-6`; `-6` on Linux
  and Windows), and per-host nmap adds `-6`. Verified against a live IPv6 listener:
  the sweep completes a handshake and returns a `strong` signal where it previously
  returned "down".
- **Reports no longer misattribute the scan.** Every JSON and HTML report recorded
  `author` as the *tool's* author, and the HTML rendered it under the label **Operator**,
  so a client deliverable named the wrong person. Reports now carry `tool_author` and
  `operator` as separate fields, with `operator` resolved from `--operator`,
  `$ENUMGRID_OPERATOR` or the OS login name. `author` is retained as a deprecated alias
  of `operator` so existing report consumers keep working.
- **The product prints its own name.** The pre-scan banner, the live dashboard header and
  the HTML report heading rendered the pre-release name `PURPLERECON`, including in the
  client-facing report. All three now render `ENUMGRID`, and the two conflicting taglines
  are replaced by a single `TAGLINE` constant.
- **Author name.** `AUTHOR` was `santhakumarParivallal`, which reached `--help`, the
  banner and every exported report. Corrected to `Santhakumar Parivallal`, matching
  `CITATION.cff` and `pyproject.toml`.
- **Invalid scan options fail before the scan, not during it.** `--top-ports`, `--ports`
  and `--host-timeout` were passed to nmap unchecked, so `--top-ports 0` or a malformed
  port spec surfaced as an opaque per-host nmap failure after the scan had started.
  `validate_scan_options` now rejects them up front with an actionable message. These
  values were never a shell-injection vector: python-nmap splits the argument string with
  `shlex` and execs a list, never a shell.
- **DNS lookups during scope validation are bounded.** `socket.getaddrinfo` takes no
  timeout and blocks for as long as the system resolver does. Hostname resolution now
  runs on a worker thread with a `DNS_TIMEOUT_S` (5 s) budget, so a blackholed resolver
  cannot stall validation.

### Added

- **Target forms an operator actually types.** Hyphenated ranges in both nmap spellings
  (`192.168.1.10-20` last-octet shorthand and `10.0.0.1-10.0.0.50` fully qualified) and
  hostnames, resolved through DNS. A name with several A/AAAA records expands to all of
  them rather than being silently narrowed to one, and a name that does not resolve is an
  error rather than an empty scope. A range is never widened to a CIDR.
- **Scope files and exclusions.** `-iL/--target-file` reads an engagement scope list (one
  entry per line, `#` comments and inline comments stripped); `--exclude` and
  `--exclude-file` subtract out-of-scope or fragile assets. Excluded addresses are
  reported, so an operator can verify what was left out instead of trusting it. A missing
  or empty scope file is an error, never a silently empty scan.
- **Nmap-compatible XML export** (`--xml`), so results import into Metasploit's
  `db_import`, Faraday, DefectDojo and other nmap-XML consumers. The `scanner` attribute
  is `enumgrid`, not `nmap`: the schema is nmap's, the data is ours, and claiming
  otherwise would misrepresent where the results came from.
- **Markdown export** (`--markdown`) for engagement write-ups.
- **`--version`**, which previously exited 2 as an unrecognized option.
- **`--operator NAME`** to record who ran the scan.
- **Packet-rate limiting for fragile networks.** `--max-rate PPS` caps outbound probe
  packets per second, enforced by a shared token-bucket limiter in both the nmap engine
  (`--max-rate`) and the built-in socket scanner, so the ceiling holds whichever engine
  runs. `--min-rate` and `--timing 0-5` expose nmap's rate floor and timing templates.
  On industrial, medical and legacy networks a hard packets-per-second ceiling is often
  what makes a scan permitted at all.
- **Resumable scans (`--resume FILE`).** A long scan (a `/16` can run for hours) that is
  killed, disconnected or Ctrl-C'd no longer starts over. Progress is journalled to a
  checkpoint after discovery and after each host's enumeration; re-running the same
  command with the same `--resume` path skips discovery and re-enumerates only the hosts
  still pending. A checkpoint written for a different target is refused rather than
  resumed into the wrong scope, and a clean completion consumes the journal.
- **Authenticated SMB enumeration** (backend `POST /api/host/smb`, `backend/smbscan.py`).
  ENUMGRID already discovers shares unauthenticated via nmap; this verifies, with a
  credential, which shares an account can actually read (a read-only listing of each
  share root, no writes, no password guessing). Reaching an administrative share such as
  `C$`/`ADMIN$` is the classic local-admin signal. Optional `smbprotocol` dependency,
  credential-gated, credentials in memory only, mirroring the SSH and LDAP modules.
- **SARIF 2.1.0 export** (`--sarif`). Each reachable service is emitted as one
  SARIF result at level `note`, so exposure surfaces in a code-scanning view (GitHub
  and other SARIF consumers) beside the usual reports. The CLI pipeline carries no CVE
  data, so no severity or CVSS is invented: the export records what is reachable, never
  a vulnerability it did not measure.
- **Greppable output** (`--greppable`/`--grep`, written as `.gnmap`). Nmap's greppable
  line format, one `Host:` line per live host, so results drop straight into the
  `grep`/`awk`/`cut` pipelines an operator already runs. The port tuple keeps Nmap's
  `port/state/protocol/owner/service/rpc/version/` shape, so existing parsers read it
  unchanged.
- **Source interface and source port** (`--interface`, `--source-port`). Route probes
  out of a chosen interface (nmap `-e`) or from a fixed TCP source port (nmap
  `--source-port`), which a firewall allowlist sometimes requires. Both are raw-packet
  controls, so they apply to the nmap engine only and are validated up front; the
  built-in socket scanner cannot honour them.

### Security

- **The web API refuses hostname targets** (`ScopeValidator(resolve_names=False)`).
  Adding hostname support to the shared validator would have extended it to the HTTP API,
  where `vet_target` and the scan resolve the name **separately**: the API vets the
  string, then hands the original string to nmap, which resolves it again. A name
  resolving to a permitted private address at vet time could resolve to loopback or a
  public host moments later, which is DNS rebinding straight through the scope policy
  (threat T1). Resolution is therefore enabled only for the CLI, where the operator types
  the target locally and no such window exists. Covered by a regression test that fails if
  the API attempts a lookup at all.

### Changed

- The CLI test suite no longer performs DNS lookups. Because `validate()` resolves
  hostnames, the property-based fuzz test was sending random strings such as `"Xsv"` to
  the system resolver, making the suite network-dependent and flaky. An autouse fixture
  stubs resolution, restoring the suite's no-network-I/O contract.
- Dependabot no longer raises scheduled version-bump pull requests. All five ecosystems
  in `.github/dependabot.yml` are set to `open-pull-requests-limit: 0`, and the 17 open
  bot branches were deleted, so the repository presents a single `main` branch. Security
  updates are unaffected: GitHub raises those through a separate mechanism that this
  limit does not apply to, so a published advisory still opens a pull request. The groups
  and schedules are retained, so version updates can be restored by raising the limits.
- `make test` now runs the same coverage gates CI enforces. The local target ran plain
  `pytest -q` with no coverage gate while CI ran `--cov-fail-under=100`, so code could
  pass `make test` and still fail CI on coverage (as commit `c8e1580` did, at 99% on the
  CLI). `test-cli`, `test-backend` and `test-frontend` now invoke the identical coverage-
  gated commands (the CLI and every backend module at 100% line coverage, the frontend
  lib via `npm run coverage`), and `test-eval` adds the offline CVE accuracy gate, so a
  coverage regression now fails locally before a push instead of after it.
- Cross-environment discovery evaluation now pools **three** networks (added a real run
  on `192.168.0.0/24`), so the macro-averaged recall is EnumGrid 0.97 ± 0.04 vs `nmap -sn`
  0.49 ± 0.54. The paper, accuracy and publication docs and the pooled plot were
  re-derived from the regenerated `pooled_recall.json`; n = 3 is still small and reported
  as such.
- Test count: **1501** (315 CLI, 794 backend, 178 evaluation, 214 frontend), up from
  1365. `backend/smbscan.py` is covered to the same CI-gated 100% as the other modules.
- Both SVG diagrams are re-synced with the codebase. `docs/architecture.svg` still
  advertised **422 tests**, a stale count from when the diagram was first added; it now
  reads **1501**, matching the banner, the README and the count above. The em dashes in
  the `architecture.svg` and `banner.svg` captions are replaced with the middot the
  diagrams already use as a separator, so the rendered docs hold to the no-em-dash house
  style. Both files still parse as well-formed XML.

---

## [1.0.0] - 2026-09-23

Initial public release. ENUMGRID is a two-tiered, purple-team network enumeration
platform: a fast horizontal discovery sweep followed by on-demand `nmap` service and
vulnerability depth, wrapped in live CVE intelligence and delivered through two
front-ends that share one engine, a single-file terminal cockpit and a web cockpit.

Its organising constraint is that a result is never fabricated. Where the tool cannot
answer, it says so. An unreachable backend produces an error banner instead of a
plausible grid, an uninstalled baseline scanner is reported as unavailable instead of as
having found nothing, and a missing LLM provider returns `ready: false` with a reason
instead of a generated reply. Tests enforce that discipline.

### Added

#### Discovery engine

- **Multi-method, confidence-graded host discovery.** ICMP, TCP, ARP, NDP (IPv6),
  mDNS/Bonjour, NBNS and SSDP/UPnP run together and are merged into a single
  confidence-scored view, with a proxy-ARP guard and RST suppression so a router that
  answers for absent hosts cannot inflate the result.
- **Passive (zero-packet) discovery** (`backend/passive.py`, `POST /api/passive`), a
  stealth mode that transmits nothing and listens instead for the broadcast and multicast
  chatter hosts emit unprompted (ARP, DHCP, mDNS, LLMNR, NetBIOS). It is invisible to an
  IDS watching for scans. `scapy` is optional and capture needs raw-socket privilege; when
  either is missing the endpoint returns `available: false` with a reason.
- **Vendor and device identity.** MAC resolved against the IEEE OUI registry (39,000+
  entries), randomized and locally-administered MAC detection, and a device-type classifier
  ranked ports, then services, then hostname, then vendor.
- **Specific OS identity** (`backend/osfp.py`). TTL, vendor, hostname and device type are
  fused into a concrete product name, and mDNS `model=` and `osxvers=` records resolve the
  exact Apple device and macOS version. With privilege, `nmap -O` is added, and a match
  below `ENUMGRID_OS_MIN_ACCURACY` is labelled `name (nmap guess, NN%)` instead of being
  asserted.
- **Discover-mode port preview.** A fast parallel unprivileged TCP connect scan of common
  service ports runs during discovery, so the grid shows open ports immediately and the
  device classifier gets its strongest signal for free.
- **SNMP device naming** (`backend/snmp.py`), which names switches, APs and printers that
  have no DNS or mDNS presence, from `sysName` and `sysDescr`.

#### Enumeration and scan profiles

- **Two-tier engine.** A horizontal sweep, then on-demand `nmap -sV` depth per host or
  across the whole network.
- **11 Zenmap-style profiles.** Quick, Default, Intense, Recon, Aggressive, Stealth SYN,
  Vulnerability, Safe, All-ports, Comprehensive and UDP, plus validated custom NSE
  scripts and port ranges. Arguments are assembled as a fixed argv with no shell, and
  targets pass an allowlist regex, so the profile surface is injection-safe by
  construction.
- **Privilege auto-adaptation.** The engine detects once, without prompting, whether it
  can scan as root, via passwordless `sudo`, or unprivileged. In the last case it rewrites
  root-only flags to safe equivalents (SYN and UDP become connect, `-O` and
  `--source-port` are dropped, `-A` becomes `-sV -sC`) and records an honest `scan_note`,
  so every profile runs without root. `GET /api/health` and `/api/profiles` expose the
  tier.
- **Adaptive all-ports sweep.** The default service scan covers the top 1000 ports with
  `-sV`, then sweeps all 65,535 on only the hosts that already showed an open port:
  thorough where it pays, cheap on firewalled or dead hosts.
- **Filtered-state confirmation.** Ports left `filtered` are re-probed with a different
  technique (patient TCP connect, or SYN from a DNS source port when privileged).
- **Timeout recovery.** `nmap` discards every result for a host that exceeds
  `--host-timeout` while still listing it as up, which previously surfaced as "no open
  ports". The scanner now detects `timedout="true"` in the XML, retries once with a
  lighter tuning profile, and reports a `Partial result` badge. A single time budget
  (`ENUMGRID_HOST_DEADLINE`, 900 s) covers every stage, with each `nmap --host-timeout`
  clamped to what remains so `nmap` always stops before Python gives up.
- **IPv6 throughout.** A dual-stack `ScopeValidator`, NDP correlation by MAC, and
  `nmap -6`.

#### Vulnerability and threat intelligence

- **Live NVD API 2.0 enrichment** (`backend/cve.py`). Every fingerprinted service is
  matched by CPE against the authoritative NVD feed, so coverage is not a hardcoded list
  and newly-published CVEs appear automatically. Results are cached in local SQLite
  (instant on repeat scans, functional offline once seen), rate-limit aware, with an
  optional API key.
- **Three merged sources.** Live NVD, the NSE `vulners` script run in-scan, and a curated
  offline reference (`backend/vulndb.py`) as a last resort, merged and de-duplicated.
- **Backport-aware matching** (`backend/osv.py`). Credentialed package lists are checked
  against OSV.dev's distro feeds (Ubuntu, Debian, Alpine) so a distro-backported fix is
  not reported as vulnerable.
- **Risk prioritisation** (`backend/threatintel.py`). Findings carry CISA KEV
  (exploited-in-the-wild) status and FIRST EPSS exploit probability, and are ranked KEV,
  then EPSS, then CVSS, so the few that matter surface first.
- **False-positive transparency.** Every finding is banded `confirmed` (an NSE script
  actively tested the host) or `version` (a version or CPE match to verify). Non-finding
  script output is filtered out, and duplicates merge keeping the strongest confidence.
- **Credentialed scanning** (`backend/credscan.py`), an authenticated SSH read of exact
  distro, kernel and package inventory. Host keys are verified by default, and credentials
  are never logged.
- **Web posture audit** (`backend/webscan.py`), a safe passive review of security headers,
  insecure cookies and the TLS certificate, parsed from the DER form with `cryptography`.

#### Web cockpit

- **Command-center shell.** A fixed sidebar (brand, scan pipeline, drift, sessions, engine
  status), a frosted command bar, a SOC-style KPI strip, a collapsible *Nmap scan options*
  drawer and a consolidated Settings menu. Responsive down to 375 px.
- **Live device grid** with per-host and whole-network scanning, rich filters (quick
  chips, device-type and OS-family dropdowns, search), resizable and persisted columns,
  and a sticky per-host detail toolbar.
- **Honest per-host status.** `Ready`, `Queued`, `Scanning`, `Done`, `No ports`, `Partial`
  and `Failed` are distinguished, so a single host scan never looks like it ran against
  the network.
- **Zenmap-style topology map** that sizes its canvas to the data and distributes nodes
  across circumference-proportional rings (verified from 11 to 150 hosts, every node in
  bounds).
- **Runtime privilege elevation.** A Privilege control raises the backend from
  unprivileged to real raw-socket scans by validating a sudo password, with no restart and
  nothing to configure at startup. The password is held only in backend process memory for
  the session; *Drop*, a restart, or `ENUMGRID_AUTO_SUDO=0` clears or forbids it.
- **One-click PDF report** (reportlab) with clickable NVD links, plus CSV and JSON export.
- **SQLite history and drift** (*"What changed"*) and a continuous Monitor mode with
  auto re-scan, drift alerts and desktop notification.
- **Light and dark themes** driven by CSS custom properties, so one `<html data-theme>`
  swap repaints the UI, plus a Cozy/Compact density toggle. Preferences apply before first
  paint, so there is no theme flash.
- **Keyboard and accessibility layer.** A ⌘K command palette with fuzzy ranking,
  single-key shortcuts with a focus-trapped `?` help overlay, focus traps and focus
  restoration on every modal, `aria-label`s and `focus-visible` rings on every command-bar
  control, and polite and assertive toasts. There is deliberately no scan-triggering key,
  so a stray keystroke cannot start a scan.
- **Operations panel**, one modal surfacing Passive discovery, Schedules and Campaign.
- **Honest failure.** If the backend is unreachable the dashboard shows a clear error and
  zeroes its counters. The offline demo engine runs only under an explicit
  `VITE_USE_MOCK=true`.

#### CLI cockpit

- **Single-file `rich` terminal dashboard** (`purple_recon.py`) sharing the engine
  primitives: sweep, `nmap` deep-dive, JSON/HTML/CSV export and config-drift `--diff`.
- **Headless fallback** for non-TTY environments, with Ctrl-C handled on both paths.
- **`pip install`-able**, with an `enumgrid` console entry point.

#### AI copilot

- **Scan-grounded analyst chat** (`backend/copilot.py`, `/api/copilot*`) that answers
  about your hosts, ports and CVEs, and says so when the context does not contain the
  answer.
- **Four providers, two of them free.** Ollama is the default (local, keyless, zero-cost,
  and the scan never leaves the machine), alongside Google Gemini (free tier), Anthropic
  Claude and OpenAI. Gemini and Ollama speak the OpenAI wire protocol and reuse that code
  path. Each SDK is optional; a missing SDK, key or local server yields `ready: false`
  with a reason, never a fabricated reply.
- **Turnkey Ollama setup.** The dashboard probes the local server, reports which models
  are actually installed, and offers a one-click model download with live streamed
  progress. A provider is `ready` only once its chosen model is present.
- **Agentic but human-in-the-loop.** The model may call a `propose_scan` tool. The backend
  never executes it; it surfaces a confirmation button that launches the normal
  scope-vetted scan. The tool is only armed when the operator actually asks to scan, which
  stops small local models from emitting tool calls in place of analysis.
- **Streaming replies over SSE**, rendered through a dependency-free, HTML-escaping
  Markdown renderer that allow-lists link schemes and auto-links CVE ids to NVD.
- **AI executive summary in the PDF report**, grounded and tool-disabled. A copilot failure
  never blocks the report.

#### Automation, integrations and scale

- **Cron-style scheduled scans** (`backend/schedule.py`, `/api/schedules`), unattended
  recurring scans that fire with no browser open, enqueueing the same headless pipeline
  the UI drives so results land in history and drift automatically.
- **Multi-subnet campaign view** (`backend/campaign.py`), which rolls the latest stored
  scan of several subnets into one estate-wide picture. Unscanned subnets are shown as
  such instead of being dropped.
- **Persistent job queue** (`backend/jobs.py`): submit and poll, with a bounded worker pool
  draining a SQLite queue that survives restarts.
- **Cloud and directory discovery.** Read-only AWS EC2, world-open security group and
  public S3 audit (`backend/cloudscan.py`), and Active Directory computer and user
  enumeration over LDAP (`backend/adscan.py`). Both are optional dependencies, and
  credentials are never logged.
- **Outbound alerting** (`backend/notify.py`): webhook, Slack and syslog on scan
  completion, with KEV hits called out.
- **Append-only audit trail** (`backend/audit.py`, `GET /api/audit`), a JSONL record of
  every scan, refusal and credentialed check.
- **Reproducibility manifest.** Every CLI JSON report, plus the backend `/api/health` and
  the exported PDF, embeds tool version, exact git commit, `nmap` version, Python runtime,
  OS and timestamp. Unknowns are labelled, never invented.

#### Access control and deployment

- **RBAC** (`backend/security.py`): admin (scan) and viewer (read-only) tokens compared
  in constant time, plus a per-IP throttle and a concurrency cap.
- **Fail-closed zero-config mode.** With no token configured, `/api/*` is refused for any
  non-loopback peer and for a non-local `Host` header (DNS-rebinding defence), so even a
  `0.0.0.0` bind does not expose the scanner to the LAN.
- **Scope guard.** Loopback, multicast, broadcast, link-local, reserved and oversized
  ranges are refused for IPv4 and IPv6, and public or internet-routable targets are
  refused unless `ENUMGRID_ALLOW_PUBLIC=1`.
- **TLS** via `./start.sh --tls` or a reverse proxy, with SSO documented through an
  authenticating proxy layered on the built-in RBAC.
- **`./start.sh`, one command** that checks prerequisites, creates the venv, installs
  dependencies, frees stuck ports, starts both servers, waits for health and opens the
  browser. Unprivileged by default.
- **Container.** A `Dockerfile` and `docker-compose.yml` with `nmap` baked in, a
  digest-pinned base image, and `uvicorn` running as a non-root user (`enumgrid`, uid
  10001).

#### Evaluation and reproducibility

- **Discovery benchmark** (`evaluation/benchmark.py`), which measures recall, precision and
  time against `nmap -sn` and against installed field baselines (arp-scan, netdiscover,
  masscan). `--runs N` reports mean ± 95% CI, and `--privileged` adds root `nmap -sn` so
  the "privileged nmap would tie" objection is measured instead of argued. A baseline that
  is not installed is reported as unavailable.
- **Detection benchmark** against a pinned 9-host Docker testbed, scoring open ports,
  service, version and planted-CVE recall, with accuracy banded by confidence and a
  repeated-scan stability measure.
- **Offline and live CVE precision and recall** (`evaluation/nvd_precision.py`). The live
  NVD path is scored for documented-CVE recall, version-scoping precision and top-N
  truncation loss, unit-tested against hand-authored NVD 2.0 schema fixtures so CI needs
  no network, with `--live` producing the authoritative number.
- **CVE-detection baselines** (`evaluation/cve_baselines.py`): EnumGrid against
  nmap-`vulners` (version-match) and Nuclei (active-PoC) on the same testbed, plus
  report-file adapters for OpenVAS and Nessus.
- **Cross-environment pooling** (`evaluation/aggregate_runs.py`), macro-averaged recall
  across networks with 95% CIs, the external-validity figure.
- **Scalability harness.** Discovery time and peak memory against address-space size over
  a widening CIDR sweep, with a least-squares fit.
- **Copilot evaluation** (`evaluation/copilot_eval.py`), scoring grounding (the fraction of
  answers inventing nothing, including novel fabricated CVE ids) and coverage over a fixed
  scan.
- **Screenshot redaction** (`docs/screenshots/redact.py`), which blurs the operator
  hostname and MAC column to produce publishable copies. The paper references the redacted
  set.

#### Packaging, tooling and CI

- `pyproject.toml` as the single source for packaging, pytest and ruff configuration;
  pinned `requirements.lock` and `package-lock.json`.
- Six-job CI (`.github/workflows/ci.yml`): lint, security (bandit, `pip-audit` including
  `requirements.lock`, `npm audit`), CLI across Python 3.10 to 3.14, backend, frontend
  (ESLint, Vitest, build), and a CycloneDX SBOM.
- Coverage gates fail the build on any regression.
- `make setup | dev | test | lint | clean` as the local entry points.

### Security

- **No shell anywhere in the scan path.** `nmap` is invoked with a fixed argv, targets
  pass an allowlist regex, and NSE scripts and port ranges are validated against
  allowlists.
- **SSRF-bounded outbound calls.** The copilot, NVD, OSV, KEV and EPSS clients use fixed
  HTTPS endpoints with URL-encoded parameters. SSDP fetches only a `LOCATION` whose host
  matches the responder, over http and https only, and scrapes it with a targeted regex
  instead of an XML parser, which keeps it XXE-safe.
- **Escape-first rendering.** The Markdown renderer escapes HTML before parsing and
  allow-lists link schemes, reportlab's mini-XML markup is escaped for every dynamic value
  in the PDF, and SQL is parameterised throughout.
- **Secret handling.** SSH, AD and cloud credentials, and the sudo password, are held in
  process memory only and never written to disk, logged, or returned. The NVD and copilot
  keys are the single documented exception: they persist to owner-only (`0600`),
  git-ignored files so they survive a restart, and are still never logged. The audit trail
  records that an action happened, never the secret.
- **Least privilege by default.** The scanner is designed to run unprivileged, the
  container runs as a non-root user, and elevation is an explicit, reversible operator
  action instead of a startup requirement.
- **Supply chain.** `pip-audit` runs against the pinned lockfile as well as the open
  ranges, a CycloneDX SBOM is produced per build, and the container base image is pinned
  by `sha256` digest.
- Reporting process and deployment guidance: [`SECURITY.md`](SECURITY.md). Assets, trust
  boundaries and the STRIDE analysis: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

### Known limitations

These are the boundaries of what the release can support.

- **Cross-environment generalisation rests on n = 2 networks.** The pooled recall figure
  has a correspondingly wide interval. [`evaluation/COLLECTING_NETWORKS.md`](evaluation/COLLECTING_NETWORKS.md)
  is the runbook for tightening it; the input must be networks you are authorised to scan.
- **The offline CVE corpus is author-curated**, so its perfect precision and recall are
  open to a fit-to-matcher objection. A frozen, empty held-out corpus template with a
  blind sampling protocol ships at `evaluation/nvd_corpus_heldout.json` to answer it.
- **CPE-dictionary drift is real and unfixed.** NVD indexes some products under a
  different CPE vendor than `nmap` emits (observed: `vsftpd_project` against `vsftpd`),
  which costs live-NVD recall for those services. It is documented as a construct-validity
  limitation in [`docs/ACCURACY.md`](docs/ACCURACY.md) §10 instead of being corrected away.
- **No analyst user study has been run.** A pre-registered protocol with a power analysis
  exists at [`docs/USER_STUDY_PROTOCOL.md`](docs/USER_STUDY_PROTOCOL.md). It needs real
  participants under ethics approval, and its results are not claimed until it is run.
- **The large React views are not line-coverage gated.** `IndustrialDashboard`,
  `ScanContext` and `CopilotPanel` are held by ESLint and the end-to-end path instead.
  Driving a 3,000-line stateful DOM view to 100% in jsdom would mostly measure the test
  harness.
- **`.eg-glass` emits only `-webkit-backdrop-filter` in the production build**, so the
  frosted surfaces do not blur on Firefox. This is cosmetic; the layout and contrast are
  unaffected.
- **Credentialed and cloud paths depend on optional SDKs** (`paramiko`, `boto3`, `ldap3`,
  `scapy`, `zeroconf`). Without them the corresponding endpoints report themselves
  unavailable instead of degrading silently.

### Release verification

Everything below was re-run against the released tree.

Automated tests: 1,365, all green.

| Suite | Tests | Coverage gate |
| --- | ---: | --- |
| CLI, `tests/` | 197 | `purple_recon.py` (1,095 statements) at 100% line |
| Backend, `backend/tests/` | 776 | all 30 modules (3,990 statements) at 100% line |
| Evaluation, `evaluation/` | 178 | scoring math pure and unit-tested |
| Frontend, `frontend/src/**` | 214 | `src/lib/**` at 100% line, function and statement |

**Static analysis.** `ruff` 0 · ESLint 0 (react-hooks + jsx-a11y) · `bandit` 0
high/medium · `pip-audit` 0 known CVEs across `backend/requirements.txt`,
`requirements-dev.txt` and `requirements.lock` · `npm audit` 0.

**API robustness.** All 35 route declarations were driven with 463 malformed, hostile and
out-of-range requests, giving 0 responses in the 5xx range (161 × 200, 167 × 400,
97 × 422, 35 × 404).

**Accessibility.** 0 WCAG 2.1 AA contrast failures on both themes, measured live with
alpha compositing up the ancestor chain across every UI state. The only element flagged by
the sweep is the brand wordmark, which reports a false 1.00 because `background-clip: text`
makes its computed colour transparent, and which WCAG 1.4.3 exempts as a logotype.

**Measured results.** Methodology in [`docs/ACCURACY.md`](docs/ACCURACY.md), raw artifacts
in [`evaluation/results/`](evaluation/results/README.md).

| Claim | Result | Artifact |
| --- | --- | --- |
| Offline CVE precision / recall | 1.00 / 1.00, 0 FP (33 cases) | `cve_precision.json` |
| Live-NVD primary path | recall 8/8, version-scoping 7/7, 0 truncation loss | `nvd_live.json` |
| Detection, 9-host testbed | ports 1.00/1.00 · service 0.89 · version 0.83 · planted CVE 3/3 | `detection_172-28.json` |
| CVE baselines, two schools | nmap-`vulners` 3/3 (133 unexpected) · EnumGrid 2/3 (13) · Nuclei 0/3 | `cve_baselines_172-28.json` |
| Discovery, pooled across environments (n = 2) | EnumGrid 0.99 ± 0.02 vs `nmap -sn` 0.53 ± 0.93 | `pooled_recall.json` |
| Scalability | 46.5 ms/address + 9.1 s fixed, R² = 0.83 | `scalability_172-16-2.json` |
| Copilot grounding | 1.000 ± 0.000 over 5 runs, 0 fabrications | `llama3.2_x5.json` |

---

## Appendix A: pre-release engineering log

The dated record of the hardening passes that produced 1.0.0, retained for provenance and
for the dissertation's audit trail. Entries are newest first. Test counts are cumulative
repository totals at the time of each pass.

### 2026-09-23: release preparation (layout, dependencies, documentation)

**Security**

- **`npm audit` reported 10 advisories (5 high, 4 moderate, 1 low) while the README badge
  and the changelog both claimed zero.** All ten were in build and test tooling:
  `postcss`, `browserslist`, `js-yaml`, `nanoid`, `brace-expansion`,
  `postcss-selector-parser`, `baseline-browser-mapping` and the Vitest chain. None shipped
  in the production bundle, but the published claim was still false. Cleared with a
  non-breaking `npm audit fix` plus a `vitest` and `@vitest/coverage-v8` floor raise
  4.1.8 → 4.1.11, which moves past the `@vitest/mocker` path-traversal advisory (affected
  range `2.1.0-beta.1` to `4.1.10`). Only `package.json` devDependency floors and the
  lockfile changed; `dependencies` is still just React. Re-verified afterwards: ESLint 0,
  214/214 tests, `src/lib/**` still at 100% statements, functions and lines, and a
  byte-identical build output. `npm audit`: 0.

**Added**

- Community-health files, so the repository presents a complete GitHub Community
  Standards profile. `CITATION.cff` drives the *Cite this repository* button with APA and
  BibTeX export; `SUPPORT.md` routes questions, bug reports, security disclosures and
  disputed-measurement reports to the right place and lists the four checks that resolve
  most reports; `.github/CODEOWNERS` makes review ownership explicit and names the
  security, quality-gate and evaluation paths individually; `.github/dependabot.yml`
  tracks all four ecosystems in the repository (pip under `/` and `/backend`, npm under
  `/frontend`, GitHub Actions and the Docker base image), grouping minor and patch bumps
  weekly so the security gates that already run in CI do not go stale.

**Changed**

- `make test` now runs the gate it documents. `test-backend` named two files and
  `evaluation/` was never invoked at all, so the one command contributors are told to
  trust reported success after roughly 200 of the 1,365 tests. It now runs the CLI,
  backend, evaluation and frontend suites, and a `test-eval` target was added.
- Documentation synchronised for release: the README's CI job count corrected (5 → 6,
  because the CycloneDX SBOM job was unlisted), `CONTRIBUTING.md` given the correct gate
  commands (invoked as `python -m <tool>`, which survives a moved or renamed checkout
  where the console scripts' baked-in interpreter path does not) and a *Commit identity*
  section, and the changelog's release links pointed at the real repository instead of the
  `example.com` placeholders they had carried since 1.0.0.
- A `.mailmap` collapses the four historical spellings of the maintainer's identity onto
  one canonical author, so `git shortlog -sne` reports a single contributor across the
  entire history.

**Removed**

- `docs/ENUMGRID_Paper.docx` and `docs/ENUMGRID_Paper.pdf` (5.6 MB of generated binaries).
  Both were last built 2026-07-11 and had drifted from `docs/PAPER.md`, still quoting the
  1,307-test figure against today's 1,365, so a stale rendering could have been submitted
  by mistake. `docs/PUBLICATION.md` now carries the regeneration recipe, and the removed
  copies stay reachable in the history preceding this removal.

**Fixed**

- Published figures that no longer matched their own artifacts. `docs/EVALUATION.md`
  carried the superseded 2026-07-06 discovery run (15-host reference, `nmap -sn` recall
  0.07, "roughly 15 times"), while the only checked-in artifact,
  `evaluation/results/benchmark_172-16-2.json` from 2026-07-11, records an 18-host union
  reference, EnumGrid 17.67 ± 0.65 hosts at recall 0.98 ± 0.04, and `nmap -sn` at 1.00
  host and recall 0.06; `pooled_recall.json` confirms which run is authoritative through
  its `per_env_recall` field. The plot had already been regenerated from the newer run, so
  the figure contradicted its own caption and the README's alt text. The table, the ratio,
  the date and the four documents quoting them are now derived from the artifact.
- `docs/banner.svg` advertised 1292 tests against an actual 1365, and its `aria-label`,
  which screen readers read aloud, carried an em dash that the house-style pass had missed
  because the sweep filtered by source extension rather than scanning every tracked file.
- `CHANGELOG.md` and `docs/PUBLICATION.md` told readers to recover the removed paper
  binaries with `git show 4b1b7f3:…`, a commit orphaned by the history rewrite and
  therefore absent from any fresh clone. Both now describe the location without a volatile
  SHA. The same entry's "all 53 commits" became a count that goes stale on every commit,
  and now reads as the entire history.

- The main column clipped the asset grid on short windows. `<main>` carried
  `lg:overflow-hidden`, so once the viewport was too short for the KPI strip, the scan
  options and the filter toolbar, the surplus was silently cut off with nothing to scroll.
  At 1024 × 480 the toolbar ran 100.5 px below the fold and the grid pane collapsed to
  0 px against 848 px of content, so the host table was not rendered at all. The chrome
  (KPI strip, scan options, filter toolbar) is now `shrink-0`, the grid pane carries a
  `lg:min-h-[8rem]` floor (its sticky column header plus about two rows), and `<main>`
  falls back to `lg:overflow-y-auto` so a cockpit that genuinely does not fit scrolls
  instead of being truncated. Verified across 1920 × 1080, 1280 × 700, 1280 × 400,
  1024 × 600, 768 × 500 and 390 × 844 in 13 UI states each: 0 clipped text nodes, and 0
  again with every scroll container driven to its end. Behaviour at normal sizes is
  unchanged, with `<main>` still reporting no overflow and the grid pane still owning the
  scroll.
- The ⌘K command palette could not be closed with Escape unless focus was still inside its
  search input, because Escape was handled only by that input's `onKeyDown`. Opening the
  palette from the `eg:open-command-palette` event, or clicking a non-focusable part of
  the card, left only the backdrop click. It now closes from the document like every other
  overlay.

### 2026-09-22: sidebar panel compression, and the last icon-toned link

**Fixed**

- The sidebar crushed its own panels instead of scrolling. The column is
  `flex flex-col overflow-y-auto`, but flex items default to `flex-shrink: 1`, so on a
  short viewport the panels were compressed to fit rather than overflowing: the
  container's `scrollHeight` stayed equal to its height, no scrollbar was ever offered,
  and each panel's own `overflow-hidden` sliced off the surplus. At 1280 × 700 the Scan
  Pipeline card rendered 103.8 px against 155 px of content, its border cutting through
  *"Service + version detection"*, and the Session Log lost 86 px, both unreachable.
  Fixed with `[&>*]:shrink-0` on the container, so a panel added later inherits it.
  Verified at 1000, 700, 560, 400 and 300 px: 0 clipped panels at every height.
- `lib/markdown.js` painted every link in a rendered copilot answer with `text-sky-400`,
  the icon tone, measuring 3.99:1 on the light theme at 12 px. Moved to `text-sky-300`
  (5.78 light, 11.52 dark). The underline is the link's non-colour cue under WCAG 1.4.1
  and so needs its own 3:1; at 40% alpha it was 1.86:1 on paper, so it moved to 70%, the
  lowest that clears 3:1 on both themes, with hover taking it to full.

### 2026-09-22: crimson text swept to AA on both themes

**Fixed**

- `text-crimson` measured 3.31 to 3.91:1 on every dark surface it actually sits on, below
  the 4.5:1 that small text needs. 24 small-text sites moved to `text-crimson-glow`
  (8.71 to 10.30:1). Eight sites deliberately keep the saturated tone because they are
  icons or large text, which need 3:1 and measure 3.81. Both tokens are identical on the
  light theme, so the swap is provably a no-op there. Verified by rendering all 25 strings
  at their real size and surface, then re-sweeping the live app: 0 AA failures across 9 UI
  states × 2 themes, roughly 4,400 text nodes.

### 2026-09-22: launcher privilege default, and fixed-position containing blocks

**Changed**

- `./start.sh` is unprivileged by default and no longer prompts for sudo at launch.
  Root-only techniques auto-adapt so every profile still runs, and full fidelity is one
  click away in the app. `--accurate-os` opts back into the launch-time prompt. A default
  run reaches *"Scan engine healthy: unprivileged"* in 8.4 s with no prompt.

**Fixed**

- Dialogs opened from the command bar rendered into a 1016 × 146 box instead of the
  viewport. `.eg-glass` put `backdrop-filter` on the sticky header, and a `backdrop-filter`
  makes an element the containing block for every `position: fixed` descendant, so the
  privilege dialog and the Export and Settings menus resolved `fixed inset-0` against the
  header's own box, putting the dialog's title and close button 65 px above the top of the
  screen with nothing to scroll. The frost now paints on a `::before` layer, which is
  pixel-identical on both themes and returns the viewport to those overlays.
- The privilege and shortcuts dialogs now scroll instead of clipping at both ends in a
  window shorter than the card.

### 2026-09-22: verification pass (fuzzing and the last unthemed colours)

Run as an A/B against the pre-fix tree rather than as a re-reading of the diff: every
claimed defect was reproduced on the old code and re-probed on the new, then the API was
fuzzed with 463 malformed, hostile and out-of-range requests.

**Fixed**

- `GET /api/jobs/{job_id}` returned 500 for an id beyond SQLite's 64-bit range. FastAPI's
  `int` coercion accepts arbitrary precision, so a 21-digit path segment reached the driver
  and raised `OverflowError`. Guarded in `jobs.get()` and the identical `history.get_scan()`
  rather than at the route, so every caller benefits.
- `::selection` hardcoded the cockpit amber wash and white text, which is white on pale
  amber at 1.28:1 on the light theme, so selected text vanished. Now theme-driven: 10.5:1
  on light, unchanged on dark.
- Ten places painted from outside the theme, each invisible or near-invisible on paper: the
  copilot user bubble (1.10:1 measured live), its error box and Stop button, the CVE and
  NVD-key links (1.44:1), two `bg-black/40` surfaces, and the brand wordmark. All now
  read theme tokens, and a new `crimson-glow` carries error text, which must invert across
  themes where `crimson` cannot. After: bubble 5.1:1, error box 6.97:1, links 7.09:1.
- A throttled host was labelled Failed. `/api/host/scan` answers 429 *"server busy"*
  past `ENUMGRID_MAX_SCANS`, reachable from "Scan All" plus a row click, and the dashboard
  collapsed it into the generic error path and showed a red badge for a host `nmap` had
  never been pointed at. The client now honours the server's advice and retries at 750 ms,
  1.5 s and 3 s, failing only if the server stays busy through all four attempts
  (`lib/retry.js`). 504 stays non-retryable, because that scan really did run and time out.

**Verified.** 0 5xx across 463 hostile requests. Tests 1,355 → 1,365.

### 2026-09-22: full API and UI sweep

Every one of the 35 route declarations driven across happy path, malformed input,
out-of-range values and auth; every UI surface driven in both themes down to 375 px.
Fifteen defects, the worst being two unhandled 500s and a light theme failing WCAG AA on 74
elements.

**Fixed: crashes and validation**

- `POST /api/host/credscan` returned 500 on a non-numeric port (`int()` on free-form JSON);
  now a 400 naming the problem. An explicit `0` is refused rather than silently becoming
  22, which `int(x or 22)` had been doing, turning a bad value into a real SSH attempt on
  a port the caller never asked for.
- `POST /api/report/pdf` returned 500 on a malformed payload. A single `_normalise_hosts`
  pass at the entry point now coerces the shape once and drops malformed entries instead of
  rendering blanks, because a report must never show a host that was not in the scan.
- `GET /api/host/webscan` accepted `port=0`, `-1` and `99999`, returning 200 with an
  internal exception name standing in for "that is not a port". Bounded to 1 through 65535.
- `POST /api/jobs/submit` queued out-of-scope network scans, because the scope guard checked
  only the `host_scan` parameter and never `network_scan`. Both are now vetted at submit,
  and a refusal is audited like any other.

**Fixed: honesty**

- The scan-options drawer printed a command that never ran. `/api/profiles` returned each
  profile's declared arguments while `_adapt_args` rewrote them before execution, so an
  unprivileged backend advertised `-sS` and ran `-sT`. The endpoint now also returns
  `effective_args` and an `adapt_note` from a single source of truth.
- `POST /api/settings/nvd-key` accepted any string as an API key and reported a rate limit
  NVD would never grant, so a mistyped paste left every lookup silently falling back to the
  anonymous limit. The runtime setter now validates NVD's documented UUID shape.
- The grid showed a crimson "VULN SCAN" badge during ordinary service scans.

**Fixed: accessibility and layout**

- The light theme failed WCAG AA on 74 elements, worst at 1.39:1, including the primary
  Start Scan button and every OS string in the grid. The chassis and neutral ramp were
  themeable but the three signal accents were shared hex tuned for a near-black surface.
  They are now theme tokens. Light went from 74 failures to 0; dark from 6 to 0.
- The floating copilot launcher covered the Engine panel's honesty note at every desktop
  size; the sidebar now reserves space.
- The target input had no accessible label.

**Fixed: maintenance**

- Replaced deprecated `@app.on_event` handlers with a `lifespan` context manager that also
  holds and awaits the worker and ticker task handles. An unreferenced `create_task` can
  be garbage-collected mid-flight, and shutdown could return while a worker was still
  inside a scan.
- `/api/ad/enum` hung for about 75 s on an unreachable DC, because `ldap3` inherits the OS
  TCP retry schedule. Bounded to 8 s connect and 30 s per operation; measured 75 s → 8 s.
- `HEAD /` returned 405, though `/` is the natural container healthcheck URL.
- The service banner advertised `?target=127.0.0.1`, a target the scope validator refuses,
  so the API's own example was guaranteed to fail. Now a private-LAN example, with a test
  asserting the advertised example passes `vet_target`.

Tests 1,333 → 1,355.

### 2026-09-22: end-to-end audit on a real LAN

Every feature exercised against a real authorised `/24` rather than assumed. The scan
pipeline held up: a deep `vuln` pass on the gateway identified dnsmasq 2.87 and correlated
10 CVEs from both NSE `vulners` and live NVD, EPSS-ranked and confidence-banded, and the 0
CVEs reported for that gateway's lighttpd 1.4.67 was confirmed correct against NVD
directly.

**Fixed**

- **The test suite was writing into the operator's real audit trail.** Endpoint tests call
  the same `audit.record()` the live API does, so every run appended fixture events to the
  file `/api/audit` serves: 647 of 4,650 entries (14%) were synthetic. For a tool whose
  contract is that every recorded result is real, that is a correctness bug. A
  session-scoped fixture now repoints the log at a temp file, and a full backend run leaves
  the real log byte-identical. Entries written before the fix remain and should be purged
  if the trail matters.
- **Pinned dependencies had rotted: 27 advisories** in `requirements.lock`. CI had audited
  only the open ranges, which always resolve to something current, while the pinned set is
  the one that rots silently. CI now audits the lockfile too.
- The dashboard showed a green engine status while the backend was down.
- The PDF inventory table wrapped IP addresses mid-octet at 26 mm; widened to 30 mm with no
  change to total width.
- `.env.example` documented only the legacy token, leaving the admin and viewer RBAC pair,
  all three alerting channels and `ENUMGRID_SSH_AUTOADD` undiscoverable.
- The `/api/settings/nvd-key` docstring claimed the key was held in memory only; it is
  persisted to a `0600` git-ignored file.

### 2026-09-16: startup and live-scan accuracy

**Fixed**

- The backend would not start: a stray leading space before the module docstring of
  `backend/nbns.py` raised `IndentationError` on import.
- Slow hosts read as "no open ports". See *Timeout recovery* above. On the router under
  test this recovered MiniUPnP 2.3.1 on :5000 and a CVSS 9.1 finding.
- Low-confidence `nmap -O` guesses are now labelled rather than asserted. Before this, a
  smart bulb was reported as a "Garmin Virb Elite action camera".
- MAC addresses hidden by macOS 27, where `arp -an` succeeds but lists nothing for some
  unprivileged processes, are now explained by a scan note, and re-read under sudo when the
  session is elevated, instead of silently appearing blank.
- Discovery takes the operator's own hostname and addresses from the OS rather than waiting
  for its own mDNS reply, which was often missed.

### 2026-07-11: publication package

**Added.** The paper draft (`docs/PAPER.md`), a one-page reproducibility map
(`docs/REPRODUCE.md`), screenshot redaction tooling, OpenVAS and Nessus report-file
adapters, and turnkey scaffolding for the operator-only evaluation gaps: a multi-network
collection runbook, a frozen held-out CVE corpus template, and a pre-registered analyst
study protocol. Evaluation suite 163 → 178.

### 2026-07-10: evaluation, positioning and a full-repo audit

**Added.** CVE-detection baselines against nmap-`vulners` and Nuclei, the testbed
broadened from 6 to 9 pinned hosts, cross-environment pooling, the scalability harness, the
live-NVD precision and recall harness, and `docs/CONTRIBUTIONS.md` (contribution framing,
related work, threats to validity, ethics). The live-NVD run surfaced the CPE-drift finding
now documented as a limitation. Evaluation suite 93 → 163; repository total 1,222 → 1,292.

**Fixed.** `report.py` now coerces numeric fields defensively, so a hand-crafted
authenticated POST with a string CVSS cannot raise inside `build_pdf`; `threatintel.py`
actually acquires its declared cache lock around the KEV check and download.

### 2026-07-09: coverage raised to 100% on the CLI and the frontend logic layer

**Added.** `tests/test_purple_recon_coverage.py` (+105) takes `purple_recon.py` from a 50%
floor to a CI-gated 100%, covering the threaded discovery engine, the enumeration engine
and its socket fallback, the orchestrator, both run loops including Ctrl-C, and the whole
`main` and `cli` flow. The frontend `src/lib/**` layer reaches a CI-gated 100% on lines,
functions and statements. Both were raised by mocking only true I/O boundaries.

**Fixed.** A genuine coverage gap masked by nondeterminism: the `_mac_vendor`
non-hex-first-octet branch was exercised only by the property-based fuzz test, so the total
flaked between 99% and 100%. A deterministic case makes the gate stable.

CLI 92 → 197; frontend 108 → 206; repository total 1,018 → 1,221.

### 2026-07-08: backend to 100%, and a security audit pass

**Added.** All 30 backend modules (3,990 statements) reach a CI-gated 100% line coverage,
including the async scan engine, the FastAPI service, the copilot and the credentialed
integrations. Backend 509 → 725.

**Security**

- **Closed an authorization gap on `POST /api/report/pdf`.** Every other endpoint enforced
  RBAC; this one had no token check, so with an admin token configured an unauthenticated
  caller could render arbitrary PDFs and, via `include_ai_summary`, spend the operator's own
  LLM key. Now read-gated like `/api/copilot/summary`.
- **Patched four dependency advisories:** `starlette` 1.2.1 → 1.3.1 (in the request path),
  `msgpack` 1.1.2 → 1.2.1 and `cryptography` 48.0.0 → 48.0.1, plus a security floor so
  the fix cannot be resolved away.
- **Least-privilege container (CWE-250).** The image ran `uvicorn` as root; it now runs as
  uid 10001. No default functionality is lost, because the scanner is designed to run
  unprivileged.

### Earlier: capability build-out

The AI copilot, passive discovery, cron scheduling, campaign aggregation, SSDP discovery,
the adaptive all-ports sweep, the command-center redesign, the light theme, the ⌘K palette
and the accessibility pass were all added across this period, together with the security
audit that made zero-config mode fail-closed to local clients, added the DNS-rebinding
`Host` check, RBAC-gated the history endpoints, capped the PDF host list, and moved token
comparison to `hmac.compare_digest`. Anti-hallucination fixes landed in the same period:
device type no longer inherits from a Wi-Fi chipset vendor, and a randomized MAC no longer
asserts a mobile OS.

---

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html
[1.0.0]: https://github.com/SanthakumarParivallal/ENUMGRID/releases/tag/v1.0.0
