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

Usage:
    python evaluation/benchmark.py 192.168.0.0/24
    python evaluation/benchmark.py 192.168.0.0/24 --ground-truth 192.168.0.1,192.168.0.2
    python evaluation/benchmark.py 192.168.0.0/24 --json out.json --md out.md

No raw tracebacks; honest output only — nothing is fabricated.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
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


def run_nmap_sn(target: str) -> tuple[set[str], float]:
    """`nmap -sn` host discovery (ARP/ICMP/TCP ping). Returns (hosts, seconds)."""
    if not shutil.which("nmap"):
        return set(), 0.0
    t0 = time.monotonic()
    proc = subprocess.run(  # nosec B603 B607 - fixed args, target is operator-supplied
        ["nmap", "-sn", "-T4", target],
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


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="EnumGrid vs nmap discovery benchmark")
    ap.add_argument("target", help="CIDR / IP / comma-list")
    ap.add_argument("--ground-truth", help="comma-separated known-live IPs (true precision/recall)")
    ap.add_argument("--json", help="write the full result as JSON to this path")
    ap.add_argument("--md", help="append the markdown table to this path")
    args = ap.parse_args(argv)

    truth = {ip.strip() for ip in args.ground_truth.split(",")} if args.ground_truth else None

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
