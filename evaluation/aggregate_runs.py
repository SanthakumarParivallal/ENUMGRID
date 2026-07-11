#!/usr/bin/env python3
"""
aggregate_runs.py — pool `benchmark.py` results across MULTIPLE networks.

`benchmark.py --runs N` gives mean ± 95 % CI for one target. The single biggest
external-validity gap in the evaluation is that those numbers come from *one*
environment. This tool pools several benchmark result files — one per network you
are authorised to scan (home `/24`, office VLAN, IoT segment, cloud VPC…) — into a
**cross-environment** figure: for each tool, the mean recall/precision/time over
environments with a 95 % CI computed *across environments* (each environment is one
sample, so a big network can't dominate — a macro-average).

That turns "EnumGrid beat nmap on my `/24`" into "across N independent networks,
EnumGrid's mean recall is X ± Y" — the generalisation claim a reviewer asks for.

    # produce per-network results first (authorised targets only):
    python benchmark.py 192.168.0.0/24 --runs 5 --json home.json
    python benchmark.py 10.0.5.0/24    --runs 5 --json office.json
    python benchmark.py 172.16.2.0/24  --runs 5 --json iot.json
    # then pool them:
    python aggregate_runs.py home.json office.json iot.json --md pooled.md --plot pooled.png

Both the single-run and multi-run `benchmark.py` JSON shapes are accepted. The math
is pure and unit-tested (see `test_aggregate_runs.py`); nothing is fabricated — a
tool absent from an environment simply isn't counted for that environment.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from benchmark import LABELS, summarize  # noqa: E402


# --------------------------------------------------------------------------- #
# Normalisation — accept either benchmark.py JSON shape (pure)
# --------------------------------------------------------------------------- #
def normalize_result(payload: dict) -> dict:
    """Reduce a benchmark.py result to per-tool scalars for one environment.

    Returns ``{"target", "reference", "tools": {name: {recall, precision, time,
    hosts, runs}}}``. Handles the multi-run shape (``payload["multirun"]``, cells
    are ``summarize`` dicts) and the legacy single-run shape (``payload["comparison"]``)."""
    target = payload.get("target", "")
    tools: dict[str, dict] = {}

    multirun = payload.get("multirun")
    if isinstance(multirun, dict) and multirun.get("tools"):
        for name, t in multirun["tools"].items():
            if not t.get("available"):
                continue
            tools[name] = {
                "recall": t["recall"]["mean"],
                "precision": t["precision"]["mean"],
                "time": t["time"]["mean"],
                "hosts": t["hosts"]["mean"],
                "runs": t.get("runs", t["recall"].get("n", 1)),
            }
        return {"target": target, "reference": multirun.get("reference", ""), "tools": tools}

    comp = payload.get("comparison")
    if isinstance(comp, dict):
        tools["enumgrid"] = {
            "recall": comp["enumgrid_metrics"]["recall"],
            "precision": comp["enumgrid_metrics"]["precision"],
            "time": float(payload.get("enumgrid_seconds", 0.0)),
            "hosts": comp.get("enumgrid_count", 0),
            "runs": 1,
        }
        tools["nmap-sn"] = {
            "recall": comp["nmap_metrics"]["recall"],
            "precision": comp["nmap_metrics"]["precision"],
            "time": float(payload.get("nmap_seconds", 0.0)),
            "hosts": comp.get("nmap_count", 0),
            "runs": 1,
        }
        return {"target": target, "reference": comp.get("reference", ""), "tools": tools}

    return {"target": target, "reference": "", "tools": {}}


# --------------------------------------------------------------------------- #
# Pooling across environments (pure)
# --------------------------------------------------------------------------- #
_METRICS = ("recall", "precision", "time", "hosts")


def pool(environments: list[dict]) -> dict:
    """Macro-average each tool's metrics across environments (one env = one sample).

    ``environments`` = normalised results. For each tool present in ≥1 environment,
    every metric is summarised across the per-environment values (mean ± 95 % CI,
    n = number of environments that ran the tool)."""
    tools: set[str] = set()
    for env in environments:
        tools |= set(env.get("tools", {}))

    per_tool: dict[str, dict] = {}
    for name in sorted(tools):
        samples: dict[str, list[float]] = {m: [] for m in _METRICS}
        per_env: dict[str, float] = {}
        for env in environments:
            t = env.get("tools", {}).get(name)
            if not t:
                continue
            for m in _METRICS:
                samples[m].append(float(t[m]))
            per_env[env.get("target", "")] = float(t["recall"])
        per_tool[name] = {
            "n_envs": len(samples["recall"]),
            **{m: summarize(samples[m]) for m in _METRICS},
            "per_env_recall": per_env,
        }
    return {
        "environments": [e.get("target", "") for e in environments],
        "n_environments": len(environments),
        "tools": per_tool,
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _ci(s: dict) -> str:
    return f"{s['mean']:.2f} ± {s['ci95']:.2f}"


def render_md(pooled: dict, timestamp: str) -> str:
    envs = pooled["environments"]
    lines = [
        f"### Cross-environment discovery — {pooled['n_environments']} network(s)  ({timestamp})",
        "",
        f"Environments: {', '.join(f'`{e}`' for e in envs) or '—'}. Cells are "
        "**mean ± 95 % CI across environments** (each network is one sample).",
        "",
        "| Tool | Environments | Recall | Precision | Hosts | Time (s) |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name in sorted(pooled["tools"]):
        t = pooled["tools"][name]
        label = LABELS.get(name, name)
        lines.append(
            f"| **{label}** | {t['n_envs']} | {_ci(t['recall'])} | {_ci(t['precision'])} | "
            f"{_ci(t['hosts'])} | {_ci(t['time'])} |"
        )
    # Per-environment recall matrix (rows = env, cols = tool).
    tool_names = sorted(pooled["tools"])
    if envs and tool_names:
        lines += ["", "| Environment | " + " | ".join(LABELS.get(n, n) for n in tool_names) + " |",
                  "|---|" + "---:|" * len(tool_names)]
        for env in envs:
            cells = []
            for n in tool_names:
                v = pooled["tools"][n]["per_env_recall"].get(env)
                cells.append("—" if v is None else f"{v:.2f}")
            lines.append(f"| `{env}` | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def write_plot(pooled: dict, path: str) -> str | None:
    """Grouped bar chart: per-tool pooled recall (mean ± 95 % CI across environments).
    Needs matplotlib; returns the path on success, else None (never fabricates)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:  # noqa: BLE001 - matplotlib is an optional plotting extra
        return None
    tools = sorted(pooled["tools"])
    if not tools:
        return None
    names = [LABELS.get(n, n) for n in tools]
    recall = [pooled["tools"][n]["recall"]["mean"] for n in tools]
    err = [pooled["tools"][n]["recall"]["ci95"] for n in tools]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(names, recall, yerr=err, capsize=4, color="#38bdf8")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Recall")
    ax.set_title(f"Discovery recall across {pooled['n_environments']} environments "
                 "(mean ± 95 % CI)")
    ax.tick_params(axis="x", rotation=30)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def load_result(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return normalize_result(json.load(fh))


def main(argv=None) -> int:
    import time  # noqa: PLC0415 - only the CLI path needs a wall clock

    ap = argparse.ArgumentParser(description="Pool benchmark.py results across environments")
    ap.add_argument("results", nargs="+", help="benchmark.py --json result files (one per network)")
    ap.add_argument("--json", metavar="FILE", help="write the pooled result as JSON")
    ap.add_argument("--md", metavar="FILE", help="append the markdown table to this path")
    ap.add_argument("--plot", metavar="PNG", help="write a pooled-recall bar chart (needs matplotlib)")
    args = ap.parse_args(argv)

    environments = [load_result(p) for p in args.results]
    pooled = pool(environments)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    md = render_md(pooled, timestamp)
    if args.plot:
        saved = write_plot(pooled, args.plot)
        md += f"\n\n{'![pooled](' + args.plot + ')' if saved else '_(plot skipped — matplotlib not installed)_'}"
    print("\n" + md + "\n")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"timestamp": timestamp, "pooled": pooled}, fh, indent=2)
    if args.md:
        with open(args.md, "a", encoding="utf-8") as fh:
            fh.write(md + "\n\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
