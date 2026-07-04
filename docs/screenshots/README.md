# Screenshots & figure manifest

A curated set of dashboard captures for the dissertation's *Implementation* and
*Evaluation* chapters. Every figure is a **real** run — no mock/demo data — so
each one doubles as evidence for the "results are always real" design principle.

> **Redaction note.** Live captures show real device data from the network you
> scan (hostnames like `santhas-MacBook-Air`, MAC addresses, vendor OUIs). Phone
> MACs are already OS-randomised (locally-administered), but before publishing a
> figure you may want to blur the router MAC and any resolved hostname.

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

## Accessibility captured here

The command-bar controls expose a keyboard focus ring (`focus-visible`) and each
icon-only/label-collapsing button carries an `aria-label` — verifiable with a
browser's accessibility inspector on any of these figures.
