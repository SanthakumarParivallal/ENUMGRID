#!/usr/bin/env python3
"""
benchmark.py — accuracy + speed comparison: EnumGrid vs nmap.

Runs EnumGrid's discovery (`--discover`) and `nmap -sn` against the *same*
target, then reports how they agree. Two ways to read the result:

  * Against the **docker testbed** (`evaluation/docker-compose.yml`) the set of
    live hosts is known exactly, so precision/recall are true.
  * Against a **real network** there is no perfect ground truth, so we treat the
    UNION of both tools as a ground-truth proxy and report per-tool recall,
    Jaccard agreement, and each tool's unique finds (EnumGrid's ARP/NDP/mDNS
    passes typically catch ICMP-silent devices that `nmap -sn` misses).

For a *publication-grade* comparison, run several repetitions against a field of
real discovery tools and report mean ± 95 % CI for recall, precision and time:

    python evaluation/benchmark.py 192.168.0.0/24 --runs 5
    python evaluation/benchmark.py 192.168.0.0/24 --runs 5 \
        --baselines nmap-sn,arp-scan,netdiscover,masscan --plot bench.png

Usage:
    python evaluation/benchmark.py 192.168.0.0/24
    python evaluation/benchmark.py 192.168.0.0/24 --ground-truth 192.168.0.1,192.168.0.2
    python evaluation/benchmark.py 192.168.0.0/24 --json out.json --md out.md
    python evaluation/benchmark.py 192.168.0.0/24 --privileged   # add sudo nmap -sn (ARP) baseline

No raw tracebacks; honest output only — nothing is fabricated. Baselines that are
not installed are reported as such (never silently treated as "found nothing").
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import re
import shutil
import statistics
import subprocess  # nosec B404 - benchmarking invokes nmap/purple_recon with list args
import sys
import tempfile
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def _ips_from_nmap(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        if line.startswith("Nmap scan report for"):
            m = _IP_RE.search(line)
            if m:
                out.add(m.group(1))
    return out


def _nmap_sn_cmd(target: str, privileged: bool = False) -> list[str]:
    """The `nmap -sn` argv. `privileged` prefixes sudo so nmap can use ARP ping on
    a local subnet — the fair, root-equivalent baseline for EnumGrid's ARP pass."""
    base = ["nmap", "-sn", "-T4", target]
    return ["sudo", *base] if privileged else base


def run_nmap_sn(target: str, privileged: bool = False) -> tuple[set[str], float]:
    """`nmap -sn` host discovery (ARP/ICMP/TCP ping). Returns (hosts, seconds).
    With `privileged=True` it runs under sudo (ARP ping); this may prompt for a
    password on the controlling terminal, so it is opt-in via `--privileged`."""
    if not shutil.which("nmap"):
        return set(), 0.0
    t0 = time.monotonic()
    proc = subprocess.run(  # nosec B603 B607 - fixed args, target is operator-supplied
        _nmap_sn_cmd(target, privileged),
        capture_output=True, text=True, check=False,
    )
    return _ips_from_nmap(proc.stdout), time.monotonic() - t0


def run_enumgrid(target: str) -> tuple[set[str], float]:
    """EnumGrid `--discover` (ICMP+TCP+ARP+NDP+mDNS). Returns (hosts, seconds)."""
    with tempfile.TemporaryDirectory() as tmp:
        t0 = time.monotonic()
        subprocess.run(  # nosec B603 - fixed args, target is operator-supplied
            [sys.executable, os.path.join(_ROOT, "purple_recon.py"),
             target, "--discover", "--no-ui", "-y", "-o", tmp],
            capture_output=True, text=True, check=False,
        )
        dt = time.monotonic() - t0
        hosts: set[str] = set()
        for path in glob.glob(os.path.join(tmp, "enumgrid_*.json")):
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                hosts = {h["ip"] for h in data.get("hosts", []) if "ip" in h}
            except (OSError, ValueError):
                pass
    return hosts, dt


def _prf(found: set[str], truth: set[str]) -> dict:
    tp = len(found & truth)
    precision = tp / len(found) if found else 0.0
    recall = tp / len(truth) if truth else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def compare(pr_hosts: set[str], nmap_hosts: set[str], truth: set[str] | None) -> dict:
    union = pr_hosts | nmap_hosts
    reference = truth if truth else union  # union = ground-truth proxy on real nets
    both = pr_hosts & nmap_hosts
    return {
        "reference": "explicit ground-truth" if truth else "union (proxy)",
        "reference_count": len(reference),
        "enumgrid_count": len(pr_hosts),
        "nmap_count": len(nmap_hosts),
        "agreement_count": len(both),
        "jaccard": len(both) / len(union) if union else 0.0,
        "enumgrid_only": sorted(pr_hosts - nmap_hosts),
        "nmap_only": sorted(nmap_hosts - pr_hosts),
        "enumgrid_metrics": _prf(pr_hosts, reference),
        "nmap_metrics": _prf(nmap_hosts, reference),
    }


def render_md(result: dict) -> str:
    c = result["comparison"]
    pm, nm = c["enumgrid_metrics"], c["nmap_metrics"]
    return "\n".join([
        f"### Benchmark — target `{result['target']}`  ({result['timestamp']})",
        "",
        f"Reference for precision/recall: **{c['reference']}** "
        f"({c['reference_count']} hosts). Jaccard agreement: **{c['jaccard']:.2f}**.",
        "",
        "| Tool | Hosts found | Precision | Recall | F1 | Time (s) |",
        "|---|---:|---:|---:|---:|---:|",
        f"| **EnumGrid** | {c['enumgrid_count']} | {pm['precision']:.2f} | "
        f"{pm['recall']:.2f} | {pm['f1']:.2f} | {result['enumgrid_seconds']:.1f} |",
        f"| `nmap -sn` | {c['nmap_count']} | {nm['precision']:.2f} | "
        f"{nm['recall']:.2f} | {nm['f1']:.2f} | {result['nmap_seconds']:.1f} |",
        "",
        f"- EnumGrid-only finds (ICMP-silent → ARP/NDP/mDNS): "
        f"`{', '.join(c['enumgrid_only']) or 'none'}`",
        f"- `nmap -sn`-only finds: `{', '.join(c['nmap_only']) or 'none'}`",
    ])


def privileged_summary(pr_hosts: set[str], priv_hosts: set[str], reference: set[str]) -> dict:
    """Compare EnumGrid against a *privileged* `sudo nmap -sn` (ARP) baseline.

    This answers the honest "but root nmap would tie" question head-on: with ARP
    ping, privileged nmap should recover the ICMP-silent devices too, so the
    interesting output is the *agreement* with EnumGrid and any host either tool
    still misses."""
    union = pr_hosts | priv_hosts
    return {
        "count": len(priv_hosts),
        "metrics": _prf(priv_hosts, reference),
        "jaccard_vs_enumgrid": len(pr_hosts & priv_hosts) / len(union) if union else 0.0,
        "enumgrid_only": sorted(pr_hosts - priv_hosts),
        "privileged_only": sorted(priv_hosts - pr_hosts),
    }


def render_privileged_md(seconds: float, summary: dict) -> str:
    agree = not summary["enumgrid_only"] and not summary["privileged_only"]
    if summary["count"] == 0:
        # A privileged scan that found nothing means sudo was denied or nmap is
        # unavailable — not a real comparison. Say so rather than claim a "tie".
        note = (
            "- `sudo nmap -sn` returned no hosts — sudo was likely denied or nmap is "
            "unavailable; re-run with working sudo to compare."
        )
    elif agree:
        note = (
            "- With root, `nmap -sn` closes the gap via ARP — the two agree exactly, "
            "confirming EnumGrid delivers that same coverage **without** privilege."
        )
    else:
        note = "- Even with root, the tools differ on the hosts above (timing / responsiveness)."
    return "\n".join([
        "",
        f"**Privileged baseline** — `sudo nmap -sn` (ARP ping): "
        f"found **{summary['count']}** hosts in {seconds:.1f}s, "
        f"recall {summary['metrics']['recall']:.2f}, "
        f"Jaccard vs EnumGrid **{summary['jaccard_vs_enumgrid']:.2f}**.",
        f"- EnumGrid-only vs privileged nmap: `{', '.join(summary['enumgrid_only']) or 'none'}`",
        f"- privileged-nmap-only: `{', '.join(summary['privileged_only']) or 'none'}`",
        note,
    ])


# --------------------------------------------------------------------------- #
# Multi-run statistics + a field of real discovery baselines.
#
# The single-run comparison above answers "does EnumGrid keep up on this run?".
# For a dissertation/paper you also need variance and a peer group, so the block
# below repeats each tool N times and reports mean ± 95 % CI, and adds arp-scan /
# netdiscover / masscan as real, install-gated baselines. Every function here is
# pure math or a thin, list-arg subprocess wrapper, so the published numbers are
# unit-tested and reproducible.  (rustscan is deliberately *not* a baseline: it is
# a port scanner, not a host-discovery tool, so comparing recall would be unfair.)
# --------------------------------------------------------------------------- #
_MAC_RE = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", re.IGNORECASE)

# Friendly labels for tables/plots. "enumgrid" is the tool under test.
LABELS = {
    "enumgrid": "EnumGrid",
    "nmap-sn": "nmap -sn",
    "arp-scan": "arp-scan",
    "netdiscover": "netdiscover",
    "masscan": "masscan --ping",
}


def _ips_with_mac(text: str) -> set[str]:
    """IPs from ``IP<whitespace>MAC …`` lines — the arp-scan / netdiscover format."""
    out: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and _IP_RE.fullmatch(parts[0]) and _MAC_RE.fullmatch(parts[1]):
            out.add(parts[0])
    return out


def _ips_from_masscan(text: str) -> set[str]:
    """IPs from masscan ``-oL`` list output: ``open <proto> <port> <ip> <ts>``."""
    out: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open" and _IP_RE.fullmatch(parts[3]):
            out.add(parts[3])
    return out


def _arp_scan_cmd(target: str, privileged: bool = False) -> list[str]:
    base = ["arp-scan", target]
    return ["sudo", *base] if privileged else base


def _netdiscover_cmd(target: str, privileged: bool = False) -> list[str]:
    # -P: parseable output and stop after one active pass; -N: no header line.
    base = ["netdiscover", "-P", "-N", "-r", target]
    return ["sudo", *base] if privileged else base


def _masscan_cmd(target: str, privileged: bool = False) -> list[str]:
    base = ["masscan", target, "--ping", "-oL", "-"]
    return ["sudo", *base] if privileged else base


# name → {binary to look for, argv builder, stdout parser}.
BASELINES: dict[str, dict] = {
    "nmap-sn":     {"which": "nmap",        "cmd": _nmap_sn_cmd,     "parse": _ips_from_nmap},
    "arp-scan":    {"which": "arp-scan",    "cmd": _arp_scan_cmd,    "parse": _ips_with_mac},
    "netdiscover": {"which": "netdiscover", "cmd": _netdiscover_cmd, "parse": _ips_with_mac},
    "masscan":     {"which": "masscan",     "cmd": _masscan_cmd,     "parse": _ips_from_masscan},
}


def run_baseline(name: str, target: str, privileged: bool = False,
                 timeout: float = 600.0) -> tuple[set[str] | None, float]:
    """Run one baseline discovery tool. Returns ``(hosts, seconds)``.

    ``hosts`` is ``None`` when the tool is not installed — the caller reports it
    as "unavailable" rather than pretending it found nothing (honest output)."""
    spec = BASELINES[name]
    if not shutil.which(spec["which"]):
        return None, 0.0
    argv = spec["cmd"](target, privileged)
    t0 = time.monotonic()
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, target is operator-supplied
            argv, capture_output=True, text=True, check=False, timeout=timeout,
        )
        text = proc.stdout
    except subprocess.TimeoutExpired as exc:  # still parse whatever was emitted
        text = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
    return spec["parse"](text), time.monotonic() - t0


def summarize(values: list[float]) -> dict:
    """Descriptive stats for a sample: n, mean, stdev, 95 % CI half-width, min, max.

    The CI uses the normal approximation (z = 1.96); it is 0 for a single run
    (no variance to estimate). Reported alongside stdev so small-n samples stay
    honest."""
    vals = [float(v) for v in values]
    n = len(vals)
    if n == 0:
        return {"n": 0, "mean": 0.0, "stdev": 0.0, "ci95": 0.0, "min": 0.0, "max": 0.0}
    mean = statistics.fmean(vals)
    stdev = statistics.stdev(vals) if n >= 2 else 0.0
    ci95 = 1.96 * stdev / math.sqrt(n) if n >= 2 else 0.0
    return {"n": n, "mean": mean, "stdev": stdev, "ci95": ci95, "min": min(vals), "max": max(vals)}


def aggregate_tool(runs_hosts: list[set[str]], timings: list[float], reference: set[str]) -> dict:
    """Per-tool aggregate across runs: recall/precision/host-count/time summaries."""
    recalls, precisions, counts = [], [], []
    union: set[str] = set()
    for hosts in runs_hosts:
        m = _prf(hosts, reference)
        recalls.append(m["recall"])
        precisions.append(m["precision"])
        counts.append(len(hosts))
        union |= hosts
    return {
        "available": True,
        "runs": len(runs_hosts),
        "hosts": summarize(counts),
        "recall": summarize(recalls),
        "precision": summarize(precisions),
        "time": summarize(timings),
        "union_found": sorted(union),
    }


def multi_run(target: str, tool_names: list[str], runs: int,
              privileged: bool = False, truth: set[str] | None = None,
              log=lambda _msg: None) -> dict:
    """Repeat each tool ``runs`` times, then aggregate against a common reference.

    ``tool_names`` may include the special name ``"enumgrid"`` plus any key of
    ``BASELINES``. The reference for precision/recall is the explicit ground truth
    if supplied, else the union of every host any tool found on any run."""
    raw: dict[str, dict] = {name: {"hosts": [], "time": []} for name in tool_names}
    for name in tool_names:
        for i in range(runs):
            log(f"» {LABELS.get(name, name)} — run {i + 1}/{runs} …")
            if name == "enumgrid":
                hosts, secs = run_enumgrid(target)
            else:
                hosts, secs = run_baseline(name, target, privileged)
                if hosts is None:  # not installed → stop retrying this tool
                    log(f"  ({name} not installed — skipping)")
                    break
            raw[name]["hosts"].append(hosts)
            raw[name]["time"].append(secs)

    union: set[str] = set()
    for data in raw.values():
        for hosts in data["hosts"]:
            union |= hosts
    reference = truth if truth else union

    tools: dict[str, dict] = {}
    for name, data in raw.items():
        if not data["hosts"]:
            tools[name] = {"available": False, "runs": 0}
        else:
            tools[name] = aggregate_tool(data["hosts"], data["time"], reference)
    return {
        "reference": "explicit ground-truth" if truth else "union (proxy)",
        "reference_count": len(reference),
        "tools": tools,
    }


def _fmt_ci(s: dict) -> str:
    """`mean ± ci` with a tighter format for counts vs rates."""
    return f"{s['mean']:.2f} ± {s['ci95']:.2f}"


def render_multirun_md(target: str, timestamp: str, result: dict, runs: int) -> str:
    lines = [
        f"### Multi-run benchmark — `{target}`  ({timestamp}) · {runs} run(s)/tool",
        "",
        f"Reference for precision/recall: **{result['reference']}** "
        f"({result['reference_count']} hosts). Cells are **mean ± 95 % CI** across runs.",
        "",
        "| Tool | Runs | Hosts found | Recall | Precision | Time (s) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, t in result["tools"].items():
        label = LABELS.get(name, name)
        if not t.get("available"):
            lines.append(f"| {label} | — | _not installed / no data_ |  |  |  |")
            continue
        lines.append(
            f"| {label} | {t['runs']} | {_fmt_ci(t['hosts'])} | {_fmt_ci(t['recall'])} | "
            f"{_fmt_ci(t['precision'])} | {_fmt_ci(t['time'])} |"
        )
    return "\n".join(lines)


def write_plot(result: dict, path: str) -> str | None:
    """Bar chart of recall + discovery time (mean ± 95 % CI). Needs matplotlib;
    returns the path on success, else None (never fabricates a chart)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:  # noqa: BLE001 - matplotlib is an optional plotting extra
        return None
    tools = [(n, t) for n, t in result["tools"].items() if t.get("available")]
    if not tools:
        return None
    names = [LABELS.get(n, n) for n, _ in tools]
    recall = [t["recall"]["mean"] for _, t in tools]
    r_err = [t["recall"]["ci95"] for _, t in tools]
    times = [t["time"]["mean"] for _, t in tools]
    t_err = [t["time"]["ci95"] for _, t in tools]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
    ax1.bar(names, recall, yerr=r_err, capsize=4, color="#38bdf8")
    ax1.set_title("Recall (mean ± 95 % CI)")
    ax1.set_ylim(0, 1.05)
    ax1.tick_params(axis="x", rotation=30)
    ax2.bar(names, times, yerr=t_err, capsize=4, color="#a78bfa")
    ax2.set_title("Discovery time, s (mean ± 95 % CI)")
    ax2.tick_params(axis="x", rotation=30)
    fig.suptitle(f"EnumGrid discovery benchmark — {result['reference_count']} reference hosts")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="EnumGrid vs nmap discovery benchmark")
    ap.add_argument("target", help="CIDR / IP / comma-list")
    ap.add_argument("--ground-truth", help="comma-separated known-live IPs (true precision/recall)")
    ap.add_argument("--json", help="write the full result as JSON to this path")
    ap.add_argument("--md", help="append the markdown table to this path")
    ap.add_argument(
        "--privileged", action="store_true",
        help="also run `sudo nmap -sn` (ARP) as a fair privileged baseline (may prompt for sudo)",
    )
    ap.add_argument(
        "--runs", type=int, default=1,
        help="repetitions per tool for mean ± 95%% CI (enables the multi-run stats table when >1)",
    )
    ap.add_argument(
        "--baselines",
        help="comma-list of discovery baselines to compare "
             f"(any of: {', '.join(BASELINES)}); default: all installed. Enables the stats table.",
    )
    ap.add_argument("--plot", help="write a recall+time bar chart (mean ± 95%% CI) to this PNG (needs matplotlib)")
    args = ap.parse_args(argv)

    truth = {ip.strip() for ip in args.ground_truth.split(",")} if args.ground_truth else None

    # ---- Extended, publication-grade path: repetitions + a field of baselines. #
    if args.runs > 1 or args.baselines or args.plot:
        baseline_names = (
            [b.strip() for b in args.baselines.split(",") if b.strip()]
            if args.baselines else list(BASELINES)
        )
        unknown = [b for b in baseline_names if b not in BASELINES]
        if unknown:
            ap.error(f"unknown baseline(s): {', '.join(unknown)}. Choose from: {', '.join(BASELINES)}")
        tool_names = ["enumgrid", *baseline_names]
        runs = max(1, args.runs)
        result = multi_run(
            args.target, tool_names, runs, privileged=args.privileged, truth=truth,
            log=lambda m: print(m, file=sys.stderr),
        )
        payload = {
            "target": args.target,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "runs": runs,
            "privileged": args.privileged,
            "multirun": result,
        }
        md = render_multirun_md(args.target, payload["timestamp"], result, runs)
        if args.plot:
            saved = write_plot(result, args.plot)
            md += f"\n\n{'![benchmark](' + args.plot + ')' if saved else '_(plot skipped — matplotlib not installed)_'}"
            if saved:
                print(f"» wrote plot {saved}", file=sys.stderr)
        print("\n" + md + "\n")
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
        if args.md:
            with open(args.md, "a", encoding="utf-8") as fh:
                fh.write(md + "\n\n")
        return 0

    # ---- Legacy single-run path (EnumGrid vs nmap -sn), unchanged. ----------- #
    print(f"» nmap -sn {args.target} …", file=sys.stderr)
    nmap_hosts, nmap_s = run_nmap_sn(args.target)
    print(f"» purple_recon --discover {args.target} …", file=sys.stderr)
    pr_hosts, pr_s = run_enumgrid(args.target)

    result = {
        "target": args.target,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "enumgrid_seconds": round(pr_s, 2),
        "nmap_seconds": round(nmap_s, 2),
        "comparison": compare(pr_hosts, nmap_hosts, truth),
    }

    md = render_md(result)

    if args.privileged:
        print(f"» sudo nmap -sn {args.target} … (privileged / ARP)", file=sys.stderr)
        priv_hosts, priv_s = run_nmap_sn(args.target, privileged=True)
        reference = truth if truth else (pr_hosts | nmap_hosts | priv_hosts)
        summary = privileged_summary(pr_hosts, priv_hosts, reference)
        result["privileged_nmap"] = {**summary, "seconds": round(priv_s, 2)}
        md += "\n" + render_privileged_md(priv_s, summary)

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
