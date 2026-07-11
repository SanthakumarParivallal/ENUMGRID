#!/usr/bin/env python3
"""
scalability_benchmark.py — how EnumGrid discovery scales with network size.

The whole evaluation is on `/24`s. A reviewer will ask *"does it scale?"*. This
harness measures **discovery time (and best-effort peak memory) versus the target's
address-space size** across a sweep of increasingly large CIDRs you are authorised
to scan, then fits the scaling curve:

  * **throughput** — addresses probed per second (higher = better);
  * a least-squares **linear fit** (seconds per address + R²) so "does it grow
    linearly with the address space?" is answered with a number, not a hunch.

    # authorised targets only — a widening sweep of the SAME network:
    python scalability_benchmark.py 10.0.0.0/26 10.0.0.0/25 10.0.0.0/24 10.0.0.0/23 \
        --repeat 3 --md scaling.md --plot scaling.png

Two layers, like the rest of the harness:
  * the fit + throughput math is pure and unit-tested (`test_scalability_benchmark.py`),
    so the published curve is trustworthy and runs in CI with no network;
  * the live runner shells out to EnumGrid discovery and is operator-run.

Peak memory is a best-effort figure from ``resource.getrusage`` (a child
high-water mark; KiB on Linux, bytes on macOS — normalised to KB with a caveat)
and is reported, never used to make a claim. Nothing is fabricated: a target that
fails is surfaced as an error, not as "0 seconds".
"""

from __future__ import annotations

import argparse
import glob
import ipaddress
import json
import os
import subprocess  # nosec B404 - invokes purple_recon discovery with fixed list args
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from benchmark import summarize  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------- #
# Pure scaling analysis (unit-tested — the trustworthy core)
# --------------------------------------------------------------------------- #
def cidr_size(target: str) -> int:
    """Number of addresses the target covers (a CIDR's size, a single IP = 1, a
    comma-list = the sum). The independent variable for the scaling curve — known
    exactly a priori, so the x-axis is not itself a measurement."""
    total = 0
    for part in str(target).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            total += ipaddress.ip_network(part, strict=False).num_addresses
        except ValueError:
            total += 1  # a bare hostname/IP → count as one target
    return total


def linear_fit(sizes: list[float], seconds: list[float]) -> dict:
    """Ordinary-least-squares fit of seconds against size.

    Returns ``slope`` (seconds per address), ``intercept`` (fixed overhead, s),
    and ``r2`` (goodness of fit, 1.0 = perfectly linear). ``slope``/``r2`` are
    ``None`` when a line can't be fit (fewer than two distinct x values)."""
    xs = [float(x) for x in sizes]
    ys = [float(y) for y in seconds]
    n = len(xs)
    if n < 2 or len(set(xs)) < 2:
        return {"n": n, "slope": None, "intercept": None, "r2": None}
    sx, sy = sum(xs), sum(ys)
    sxx = sum(x * x for x in xs)
    sxy = sum(x * y for x, y in zip(xs, ys))
    denom = n * sxx - sx * sx
    slope = (n * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / n
    ybar = sy / n
    ss_tot = sum((y - ybar) ** 2 for y in ys)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    r2 = 1.0 if ss_tot == 0 else 1.0 - ss_res / ss_tot
    return {"n": n, "slope": slope, "intercept": intercept, "r2": r2}


def throughput(sizes: list[float], seconds: list[float]) -> float | None:
    """Mean addresses-per-second across samples (skips zero-time samples)."""
    rates = [float(s) / float(t) for s, t in zip(sizes, seconds) if t > 0]
    return (sum(rates) / len(rates)) if rates else None


def analyze(points: list[dict]) -> dict:
    """Fold per-target scaling points into a fit + throughput summary.

    ``points`` = ``[{"target", "size", "seconds": [run times], "hosts", ...}]``.
    Uses each target's MEAN time as its representative sample for the fit."""
    scored = [p for p in points if "error" not in p and p.get("seconds")]
    sizes = [p["size"] for p in scored]
    mean_secs = [summarize(p["seconds"])["mean"] for p in scored]
    return {
        "targets": len(scored),
        "fit": linear_fit(sizes, mean_secs),
        "throughput_addr_per_s": throughput(sizes, mean_secs),
        "points": [
            {"target": p["target"], "size": p["size"],
             "time": summarize(p["seconds"]), "hosts": p.get("hosts"),
             "peak_rss_kb": summarize(p["rss"]) if p.get("rss") else None}
            for p in scored
        ],
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _sec(s: dict) -> str:
    return f"{s['mean']:.1f} ± {s['ci95']:.1f}"


def render_md(result: dict) -> str:
    a = result["analysis"]
    fit = a["fit"]
    tput = a["throughput_addr_per_s"]
    lines = [
        f"### Discovery scalability  ({result['timestamp']})",
        "",
        f"Discovery time vs address-space size over {a['targets']} target(s), "
        f"{result['repeat']} run(s) each.",
        "",
        f"- **Throughput:** {'—' if tput is None else f'{tput:.0f} addresses/s (mean)'}",
        f"- **Linear fit:** " + (
            "not enough distinct sizes to fit" if fit["slope"] is None else
            f"{fit['slope'] * 1000:.3f} ms/address + {fit['intercept']:.1f}s overhead "
            f"(R² = {fit['r2']:.3f})"
        ),
        "",
        "| Target | Addresses | Hosts up | Time (s) | Peak RSS (KB) |",
        "|---|---:|---:|---:|---:|",
    ]
    for p in a["points"]:
        rss = "—" if not p.get("peak_rss_kb") else f"{p['peak_rss_kb']['mean']:.0f}"
        hosts = "—" if p.get("hosts") is None else p["hosts"]
        lines.append(f"| `{p['target']}` | {p['size']} | {hosts} | {_sec(p['time'])} | {rss} |")
    for p in result["points"]:
        if "error" in p:
            lines.append(f"| `{p['target']}` | {p.get('size', '?')} | _error_ | {p['error']} |  |")
    return "\n".join(lines)


def write_plot(result: dict, path: str) -> str | None:
    """Scatter of time vs address-space size + the fitted line. Needs matplotlib;
    returns the path on success, else None (never fabricates a chart)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:  # noqa: BLE001 - matplotlib is an optional plotting extra
        return None
    pts = result["analysis"]["points"]
    if not pts:
        return None
    xs = [p["size"] for p in pts]
    ys = [p["time"]["mean"] for p in pts]
    err = [p["time"]["ci95"] for p in pts]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.errorbar(xs, ys, yerr=err, fmt="o", capsize=4, color="#38bdf8", label="measured")
    fit = result["analysis"]["fit"]
    if fit["slope"] is not None:
        line_x = [min(xs), max(xs)]
        line_y = [fit["slope"] * x + fit["intercept"] for x in line_x]
        ax.plot(line_x, line_y, "--", color="#a78bfa",
                label=f"fit (R²={fit['r2']:.3f})")
    ax.set_xlabel("Address-space size")
    ax.set_ylabel("Discovery time (s)")
    ax.set_title("EnumGrid discovery scalability")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


# --------------------------------------------------------------------------- #
# Live runner (needs the network; operator-run)
# --------------------------------------------------------------------------- #
def _peak_rss_kb() -> float:
    """Child-process high-water RSS in KB (best-effort; platform-normalised)."""
    import resource  # noqa: PLC0415 - POSIX-only, imported lazily on the live path
    raw = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return raw / 1024.0 if sys.platform == "darwin" else float(raw)  # macOS: bytes; Linux: KiB


def time_discovery(target: str) -> tuple[int, float, float | None]:
    """Run EnumGrid discovery once. Returns (hosts_found, seconds, peak_rss_kb|None)."""
    rss_before = None
    try:
        rss_before = _peak_rss_kb()
    except Exception:  # noqa: BLE001 - resource is POSIX-only; memory is best-effort
        rss_before = None
    hosts = 0
    with tempfile.TemporaryDirectory() as tmp:
        t0 = time.monotonic()
        subprocess.run(  # nosec B603 - fixed args, target is operator-supplied
            [sys.executable, os.path.join(_ROOT, "purple_recon.py"),
             target, "--discover", "--no-ui", "-y", "-o", tmp],
            capture_output=True, text=True, check=False,
        )
        seconds = time.monotonic() - t0
        for path in glob.glob(os.path.join(tmp, "enumgrid_*.json")):
            try:
                with open(path, encoding="utf-8") as fh:
                    hosts = len(json.load(fh).get("hosts", []))
            except (OSError, ValueError):
                pass
    rss = None
    if rss_before is not None:
        try:
            rss = max(0.0, _peak_rss_kb() - rss_before) or _peak_rss_kb()
        except Exception:  # noqa: BLE001 - best-effort
            rss = None
    return hosts, seconds, rss


def run(targets: list[str], repeat: int, log=lambda _m: None) -> dict:
    """Time discovery for each target ``repeat`` times and analyse the scaling."""
    points = []
    for target in targets:
        size = cidr_size(target)
        log(f"» {target} ({size} addresses) ×{repeat} …")
        seconds, hosts_last, rss = [], None, []
        try:
            for _ in range(max(1, repeat)):
                hosts, secs, r = time_discovery(target)
                seconds.append(secs)
                hosts_last = hosts
                if r is not None:
                    rss.append(r)
        except Exception as exc:  # noqa: BLE001 - a failure is surfaced, not faked
            points.append({"target": target, "size": size, "error": str(exc)})
            continue
        points.append({"target": target, "size": size, "seconds": seconds,
                       "hosts": hosts_last, "rss": rss})
    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "repeat": repeat,
        "points": points,
        "analysis": analyze(points),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="EnumGrid discovery scalability benchmark")
    ap.add_argument("targets", nargs="+", help="a widening sweep of AUTHORISED CIDRs")
    ap.add_argument("--repeat", type=int, default=3, help="runs per target (default: 3)")
    ap.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    ap.add_argument("--md", metavar="FILE", help="append the markdown table to this path")
    ap.add_argument("--plot", metavar="PNG", help="write a time-vs-size scatter+fit (needs matplotlib)")
    args = ap.parse_args(argv)

    result = run(args.targets, args.repeat, log=lambda m: print(m, file=sys.stderr))
    md = render_md(result)
    if args.plot:
        saved = write_plot(result, args.plot)
        md += f"\n\n{'![scaling](' + args.plot + ')' if saved else '_(plot skipped — matplotlib not installed)_'}"
    print("\n" + md + "\n")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
    if args.md:
        with open(args.md, "a", encoding="utf-8") as fh:
            fh.write(md + "\n\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
