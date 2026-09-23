# Screenshots and figure manifest

A curated set of dashboard captures for the dissertation's *Implementation* and
*Evaluation* chapters. Every figure comes from a real run, with no mock or demo data, so
each one doubles as evidence for the "results are always real" design principle.

> **Redaction note.** Live captures show real device data from the network you
> scan (hostnames like `santhas-MacBook-Air`, MAC addresses, vendor OUIs). Phone
> MACs are already OS-randomised (locally-administered), but before publishing a
> figure you may want to blur the router MAC and any resolved hostname.
>
> **Publish the `*-redacted.png` copies.** `redact.py` (in this folder) blurs the
> operator hostname and the MAC column in every affected frame and writes
> `<name>-redacted.png` next to each original. Put those `-redacted` copies in the
> paper; the un-redacted originals are kept for the operator's
> own reference. Regenerate them with `python docs/screenshots/redact.py`
> (`--check` validates the regions without writing). `mobile.png` needs no
> redaction, because the captured crop shows only the KPI strip and filters, no host data.

## Captured: data-free UI chrome (committed)

These figure slots contain no scan results, only UI chrome, so they were captured
from the real running app (backend up, no scan run, `USE_MOCK` off) at
native 2× resolution and are committed here:

| File | State | Notes |
|---|---|---|
| `command-center-standby.png` | Fig 1, standby shell | Full app shell, `Backend ● FastAPI`, `unprivileged`, `0 / 0 hosts`. |
| `privilege-elevation.png` | Fig 2, elevation dialog | The sudo-password dialog and the note that the password is held only in the backend's memory, never written to disk, logged, or returned. |
| `command-palette.png` | Fig 6a, ⌘K palette | The searchable launcher over a dimmed shell. |
| `shortcuts-help.png` | Fig 6b, `?` help overlay | The keyboard-shortcut cheat-sheet (⌘K · `/` · `t` · `?` · `Esc`). |

> **One redaction note for these.** The standby and elevation frames show the
> operator's own device (`THIS DEVICE`: `santhas-MacBook-Air.local`, `172.16.2.154`,
> on the authorised LAN `172.16.2.0/24`). That is this machine rather than a scanned
> host, but the hostname carries a personal name, so blur it before publishing if you
> would rather not show it.
>
## Captured: data-bearing, from a real authorised scan (committed)

Captured on 2026-07-11 from a real, unprivileged scan of the authorised
`172.16.2.0/24` LAN (no sudo, `USE_MOCK` off), native 2×:

| File | State | Notes |
|---|---|---|
| `scan-live.png` | Fig 3, live scan | Phase 1 · Ping Sweep at 32%, `Stop` armed, `LIVE` badge, 8 hosts populating the matrix in real time. |
| `scan-complete.png` | Fig 4, completed scan | `PHASE Complete`, 15/15 hosts, unprivileged OS fingerprinting (Mac, Linux, Phone), IPv6 badge, OUI vendor lookup, the WHAT CHANGED drift panel, and the scan-session record. |
| `topology.png` | Fig 5a, topology | Radial map: gateway hub plus 14 device nodes, "click a node to nmap it". |
| `mobile.png` | Fig 5b, mobile 390 px | Progressive disclosure: the sidebar collapses to ☰ and the KPIs reflow to a 2-column grid. |

> **Caveat on these.** This is a real consumer LAN, so Open Ports, Services and CVEs
> all read `00`. The discovered hosts are firewalled phones and laptops with no open
> TCP ports (unprivileged connect-scan found none). That is the *true* result, not a gap
> papered over: to populate the ports/versions/CVE columns you would scan a host that
> actually exposes services (a server, or the `evaluation/` docker testbed). Nothing here
> is simulated.
>
> **Redaction before publishing.** These frames show real device data on the authorised
> LAN: real MACs (most are OS-randomised and locally-administered), one OUI vendor string,
> and the operator's own hostname `santhas-MacBook-Air`. Blur the hostname and any MAC
> you'd rather not publish.

## Recommended figure set

| # | Figure | UI state | What it demonstrates |
|---|--------|----------|----------------------|
| 1 | Command-center, standby | Desktop, dark, ≥1440px wide, no scan yet | The full app shell: sidebar (pipeline and engine panel), command bar, KPI strip, filter toolbar, asset-matrix standby. Establishes the layout. |
| 2 | Runtime privilege elevation | Click the Privilege pill so the dialog opens | Elevation from unprivileged to raw-socket (`-sS`, `-sU`, `-O`) from the dashboard, with the in-memory-only sudo-password note. |
| 3 | Live scan in progress | Mid-scan (Phase 2, 30 to 90%) | Real-time SSE progress bar, phase stepper (P-01 done, P-02 running), hosts populating the matrix live, `LIVE` session badge. |
| 4 | Completed scan | Phase Complete, 100% | Deep enumeration: OS fingerprinting (MikroTik RouterOS, macOS), hostname resolution, IPv6 badges, the drift panel, and the vuln-scan pipeline (`VULN SCAN`, `QUEUED`). |
| 5 | Responsive and theming | Mobile (375px) and/or light theme | Progressive disclosure on a narrow viewport, and the light and dark theme swap, as evidence for the accessibility and responsive work. |

## How to reproduce

1. Start the stack: `./start.sh` (backend on `127.0.0.1:8011`) and, in `frontend/`,
   `npm run dev` (UI on `:5173`). The command bar auto-detects your subnet.
2. **Fig 1.** Load the UI at a desktop width (≥1440px) so the sidebar is pinned
   (below the `lg` breakpoint it collapses to the ☰ menu).
3. **Fig 2.** Click the amber Privilege pill in the command bar.
4. **Figs 3 and 4.** Enter an authorised target and press Start Scan, then capture once
   mid-scan and again at *Complete*.
5. **Fig 5.** Narrow the window to about 375px (or use browser device emulation), and
   toggle the theme via Settings → Theme.

Keep captures consistent (same viewport, same target) so the figures read as one
coherent walkthrough.

## Step-by-step capture runbook

**Capture keys.** macOS: `⌘⇧4` then Space to grab a window (or drag a region);
`⌘⇧5` for options. Chrome device toolbar: `⌘⇧M` (Mac) / `Ctrl⇧M`; its ⋮ menu →
*Capture screenshot* exports the exact device-frame PNG. Save each into this folder.

| Fig | Viewport | Exact steps | Contains scan data? | Redact before publishing |
|---|---|---|---|---|
| **1. Standby shell** | Desktop ≥1440px, dark | Load the UI after `./start.sh`, and do not start a scan. Capture the whole window. | No | none (no host data on screen) |
| **2. Privilege elevation** | Desktop ≥1440px | Click the amber Privilege pill so the dialog opens. Capture with the dialog and the in-memory-password note visible. **Do not type a real password into frame.** | No | none |
| **3. Live scan** | Desktop ≥1440px | Enter an authorised target and press Start Scan, then capture at 30 to 90% (Phase 2 running, `LIVE` badge, hosts populating). | **Yes** | router MAC, resolved hostnames |
| **4. Completed scan** | Desktop ≥1440px | The same scan at Complete (100%). Expand one host row to show ports, versions and CVEs alongside the What Changed drift panel. | **Yes** | MACs, hostnames |
| **5. Responsive and theme** | Mobile 375px (device mode) | Narrow to 375px and capture the collapsed shell, then toggle Settings → Theme and capture light and dark. | Optional | any host data if a scan is loaded |
| **6. ⌘K palette and `?` help** | Desktop | Press ⌘K for the palette and `?` for the shortcut cheat-sheet, capturing each overlay. | No | none |

**Honesty rule (non-negotiable).** Figures 3 to 5 that show hosts, ports or CVEs
**must come from a real scan of a network you are authorised to assess**, never
`VITE_USE_MOCK=true` demo data. Figs 1, 2 and 6 are UI *chrome* (no scan results),
so they carry no data-authenticity concern. This is the same "results are always
real" principle the tool enforces at runtime.

## Generated evaluation figures (not screenshots)

These are produced by the eval harness from real runs, for the paper's *Evaluation*
chapter, rather than captured from the UI:

- **Discovery bar chart:** `python evaluation/benchmark.py <subnet> --runs 5 --plot bench.png`
- **Cross-environment recall:** `python evaluation/aggregate_runs.py net1.json net2.json … --plot pooled.png`
- **Scalability curve:** `python evaluation/scalability_benchmark.py <sweep of CIDRs> --plot scaling.png`

`benchmark_multirun_172-16-2.png` in this folder is one such real-run figure.

## Accessibility captured here

The command-bar controls expose a keyboard focus ring (`focus-visible`) and each
icon-only or label-collapsing button carries an `aria-label`, verifiable with a
browser's accessibility inspector on any of these figures.
