# Screenshots & figure manifest

A curated set of dashboard captures for the dissertation's *Implementation* and
*Evaluation* chapters. Every figure is a **real** run — no mock/demo data — so
each one doubles as evidence for the "results are always real" design principle.

> **Redaction note.** Live captures show real device data from the network you
> scan (hostnames like `santhas-MacBook-Air`, MAC addresses, vendor OUIs). Phone
> MACs are already OS-randomised (locally-administered), but before publishing a
> figure you may want to blur the router MAC and any resolved hostname.

## Captured (data-free UI chrome — committed)

These three figure slots contain **no scan results** (UI chrome only), so they were
captured from the **real** running app (backend up, *no* scan run, `USE_MOCK` off) at
native 2× resolution and are committed here:

| File | State | Notes |
|---|---|---|
| `command-center-standby.png` | Fig 1 — standby shell | Full app shell, `Backend ● FastAPI`, `unprivileged`, `0 / 0 hosts`. |
| `privilege-elevation.png` | Fig 2 — elevation dialog | The sudo-password dialog + the *"held only in the backend's memory — never written to disk, never logged, never returned"* note. |
| `command-palette.png` | Fig 6a — ⌘K palette | The searchable launcher over a dimmed shell. |
| `shortcuts-help.png` | Fig 6b — `?` help overlay | The keyboard-shortcut cheat-sheet (⌘K · `/` · `t` · `?` · `Esc`). |

> **One redaction note for these.** The standby/elevation frames show the operator's
> **own** device (`THIS DEVICE`: `santhas-MacBook-Air.local`, `172.16.2.154`, net
> `172.16.2.0/24` — an authorised LAN). That's this machine, not a scanned host, but the
> hostname carries a name — blur it before publishing if you'd rather not.
>
## Captured (data-bearing — a real authorised scan — committed)

Captured on **2026-07-11** from a **real, unprivileged** scan of the authorised
`172.16.2.0/24` LAN (no sudo, `USE_MOCK` off), native 2×:

| File | State | Notes |
|---|---|---|
| `scan-live.png` | Fig 3 — live scan | Phase 1 · Ping Sweep at **32 %**, `Stop` armed, `LIVE` badge, **8 hosts** populating the matrix in real time. |
| `scan-complete.png` | Fig 4 — completed scan | `PHASE Complete`, **15/15 hosts**, unprivileged **OS fingerprinting** (Mac / Linux / Phone), IPv6 badge, OUI vendor lookup, the **WHAT CHANGED / drift** panel, and the scan-session record. |
| `topology.png` | Fig 5a — topology | Radial map: gateway hub + 14 device nodes, "click a node to nmap it". |
| `mobile.png` | Fig 5b — mobile 390 px | Progressive disclosure — sidebar collapses to ☰, KPIs reflow to a 2-column grid. |

> **Honest caveat on these.** This is a real consumer LAN, so **Open Ports / Services /
> CVEs read `00`** — the discovered hosts are firewalled phones/laptops with no open
> TCP ports (unprivileged connect-scan found none). That is the *true* result, not a gap
> papered over: to populate the ports/versions/CVE columns you would scan a host that
> actually exposes services (a server, or the `evaluation/` docker testbed). Nothing here
> is simulated.
>
> **Redaction before publishing.** These frames show real device data on the authorised
> LAN — real MACs (most are OS-randomised, locally-administered), one OUI vendor string,
> and the operator's own hostname `santhas-MacBook-Air`. Blur the hostname and any MAC
> you'd rather not publish.

## Recommended figure set

| # | Figure | UI state | What it demonstrates |
|---|--------|----------|----------------------|
| 1 | Command-center — standby | Desktop, dark, ≥1440px wide, no scan yet | The full app-shell: sidebar (pipeline + engine panel), command bar, KPI strip, filter toolbar, asset-matrix standby. Establishes the layout. |
| 2 | Runtime privilege elevation | Click the **Privilege** pill → dialog open | The headline feature — unprivileged→raw-socket (`-sS`/`-sU`/`-O`) elevation from the dashboard, with the in-memory-only sudo-password note. |
| 3 | Live scan in progress | ~mid-scan (Phase 2, 30–90%) | Real-time SSE progress bar, phase stepper (P-01 ✓ / P-02 running), hosts populating the matrix live, `LIVE` session badge. |
| 4 | Completed scan | Phase **Complete**, 100% | Deep enumeration: OS fingerprinting (MikroTik RouterOS, macOS), hostname resolution, IPv6 badges, the **drift** panel, and the vuln-scan pipeline (`VULN SCAN`/`QUEUED`). |
| 5 | Responsive + theming | Mobile (375px) and/or light theme | Progressive disclosure on a narrow viewport and the light/dark theme swap — evidence for the accessibility/responsive work. |

## How to reproduce

1. Start the stack: `./start.sh` (backend on `127.0.0.1:8011`) and, in `frontend/`,
   `npm run dev` (UI on `:5173`). The command bar auto-detects your subnet.
2. **Fig 1** — load the UI at a desktop width (≥1440px) so the sidebar is pinned
   (below the `lg` breakpoint it collapses to the ☰ menu).
3. **Fig 2** — click the amber **Privilege** pill in the command bar.
4. **Figs 3–4** — enter an **authorised** target and **Start Scan**; capture once
   mid-scan and again at *Complete*.
5. **Fig 5** — narrow the window to ~375px (or use browser device emulation), and
   toggle the theme via **Settings → Theme**.

Keep captures consistent (same viewport, same target) so the figures read as one
coherent walkthrough.

## Step-by-step capture runbook

**Capture keys.** macOS: `⌘⇧4` then Space to grab a window (or drag a region);
`⌘⇧5` for options. Chrome device toolbar: `⌘⇧M` (Mac) / `Ctrl⇧M`; its ⋮ menu →
*Capture screenshot* exports the exact device-frame PNG. Save each into this folder.

| Fig | Viewport | Exact steps | Contains scan data? | Redact before publishing |
|---|---|---|---|---|
| **1 — Standby shell** | Desktop ≥1440px, dark | Load the UI after `./start.sh`; do **not** start a scan. Capture the whole window. | No | — (no host data on screen) |
| **2 — Privilege elevation** | Desktop ≥1440px | Click the amber **Privilege** pill → the dialog opens. Capture with the dialog + the in-memory-password note visible. **Do not type a real password into frame.** | No | — |
| **3 — Live scan** | Desktop ≥1440px | Enter an **authorised** target → **Start Scan**; capture at ~30–90 % (Phase 2 running, `LIVE` badge, hosts populating). | **Yes** | router MAC, resolved hostnames |
| **4 — Completed scan** | Desktop ≥1440px | Same scan at **Complete** (100 %); expand one host row to show ports/versions/CVEs + the *What Changed* drift panel. | **Yes** | MACs, hostnames |
| **5 — Responsive + theme** | Mobile 375px (device mode) | Narrow to 375px; capture the collapsed shell; toggle **Settings → Theme** and capture light + dark. | Optional | any host data if a scan is loaded |
| **6 — ⌘K palette / `?` help** | Desktop | Press **⌘K** (palette) and **`?`** (shortcut cheat-sheet); capture each overlay. | No | — |

**Honesty rule (non-negotiable).** Figures 3–5 that show hosts/ports/CVEs **must
come from a real scan of a network you are authorised to assess** — never
`VITE_USE_MOCK=true` demo data. Figs 1, 2 and 6 are UI *chrome* (no scan results),
so they carry no data-authenticity concern. This is the same "results are always
real" principle the tool enforces at runtime.

## Generated evaluation figures (not screenshots)

These are produced by the eval harness from **real runs**, for the paper's
*Evaluation* chapter — not captured from the UI:

- **Discovery bar chart** — `python evaluation/benchmark.py <subnet> --runs 5 --plot bench.png`
- **Cross-environment recall** — `python evaluation/aggregate_runs.py net1.json net2.json … --plot pooled.png`
- **Scalability curve** — `python evaluation/scalability_benchmark.py <sweep of CIDRs> --plot scaling.png`

`benchmark_multirun_172-16-2.png` in this folder is one such real-run figure.

## Accessibility captured here

The command-bar controls expose a keyboard focus ring (`focus-visible`) and each
icon-only/label-collapsing button carries an `aria-label` — verifiable with a
browser's accessibility inspector on any of these figures.
