#!/usr/bin/env python3
"""
cve_precision.py — precision / recall of EnumGrid's OFFLINE version->CVE matcher.

detection_benchmark.py measures CVE *recall* against a live testbed. This harness
measures the harder, higher-stakes property — **precision**: does the matcher
attach the *right* CVE to the *right* version, and never a wrong one? That is
where naive scanners fail (a version number collides with another product's magic
build, a distro backport looks vulnerable, a product name is a substring of
another). Getting a CVE wrong is worse than missing one for a "no fake data" tool.

It runs a labelled corpus (evaluation/cve_corpus.json) through the real matcher
(`backend/vulndb.lookup_offline_cves`) with **closed-world** scoring: each case
pins the EXACT set of CVE ids expected, so

  * a returned id NOT in the expected set is a **false positive** (precision), and
  * an expected id NOT returned is a **false negative** (recall).

Output is micro-averaged precision / recall / F1 with **Wilson score 95 % CIs**
(the correct interval for a binomial proportion near the 0/1 boundary, where the
normal approximation degenerates to a zero-width interval), plus a per-category
breakdown so the boundary / wrong-product / backport traps are visible.

The matcher is fully offline and deterministic, so — unlike the live detection
benchmark — this whole harness runs in CI with no Docker and no network, and its
result is a reproducible dissertation artifact.

Usage:
    python evaluation/cve_precision.py                       # print the table
    python evaluation/cve_precision.py --json out.json --md out.md
    python evaluation/cve_precision.py --min-precision 1.0   # exit 1 if below (CI gate)
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_corpus.json")


# --------------------------------------------------------------------------- #
# Statistics (pure) — Wilson score interval for a binomial proportion
# --------------------------------------------------------------------------- #
def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float | None, float | None]:
    """95 % Wilson score interval for k successes in n Bernoulli trials.

    Preferred over the normal approximation because it stays inside [0, 1] and
    gives a *non-degenerate* interval when the observed proportion is exactly 1.0
    (all correct) or 0.0 — precisely the regime a good matcher lives in. Returns
    (None, None) when there are no trials (the proportion is undefined)."""
    if n <= 0:
        return (None, None)
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, center - half), min(1.0, center + half))


def _prf(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


# --------------------------------------------------------------------------- #
# Scoring (pure, deterministic, unit-tested)
# --------------------------------------------------------------------------- #
def _norm(ids) -> set[str]:
    return {str(c).strip().upper() for c in ids if str(c).strip()}


def score_case(got, expect) -> dict:
    """Closed-world score for one banner: exact expected CVE set vs what matched."""
    got, expect = _norm(got), _norm(expect)
    tp = len(got & expect)
    return {
        "tp": tp,
        "fp": len(got - expect),           # reported a CVE that must NOT be there
        "fn": len(expect - got),           # missed a CVE that MUST be there
        "expect": sorted(expect),
        "got": sorted(got),
        "false_positives": sorted(got - expect),
        "missed": sorted(expect - got),
    }


def aggregate(cases: list[dict]) -> dict:
    """Micro-average precision/recall/F1 with Wilson CIs, plus per-category rollup."""
    tp = sum(c["tp"] for c in cases)
    fp = sum(c["fp"] for c in cases)
    fn = sum(c["fn"] for c in cases)
    prf = _prf(tp, fp, fn)
    p_lo, p_hi = wilson_ci(tp, tp + fp)     # precision over predicted-positives
    r_lo, r_hi = wilson_ci(tp, tp + fn)     # recall over actual-positives

    by_cat: dict[str, dict] = {}
    for c in cases:
        cat = by_cat.setdefault(c["category"], {"tp": 0, "fp": 0, "fn": 0, "cases": 0})
        cat["tp"] += c["tp"]
        cat["fp"] += c["fp"]
        cat["fn"] += c["fn"]
        cat["cases"] += 1
    for cat in by_cat.values():
        cat.update(_prf(cat["tp"], cat["fp"], cat["fn"]))

    return {
        "cases": len(cases),
        "tp": tp, "fp": fp, "fn": fn,
        **prf,
        "precision_ci": [p_lo, p_hi],
        "recall_ci": [r_lo, r_hi],
        "predicted_positives": tp + fp,
        "actual_positives": tp + fn,
        "false_positive_cases": sorted(c["banner"] for c in cases if c["fp"]),
        "false_negative_cases": sorted(c["banner"] for c in cases if c["fn"]),
        "by_category": by_cat,
    }


# --------------------------------------------------------------------------- #
# Corpus + matcher wiring (matcher is offline/deterministic — CI-safe)
# --------------------------------------------------------------------------- #
def load_corpus(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _import_matcher():
    """Lazily import the real offline matcher so pure scoring has no backend dep."""
    backend = os.path.join(_ROOT, "backend")
    if backend not in sys.path:
        sys.path.insert(0, backend)
    from vulndb import lookup_offline_cves  # noqa: PLC0415
    return lookup_offline_cves


def run(corpus: dict, matcher=None) -> dict:
    """Run every corpus case through the matcher and score it (closed-world)."""
    matcher = matcher or _import_matcher()
    scored: list[dict] = []
    for case in corpus.get("cases", []):
        got = [getattr(v, "id", v) for v in matcher(case["banner"])]
        row = score_case(got, case.get("expect", []))
        row["banner"] = case["banner"]
        row["category"] = case.get("category", "")
        row["note"] = case.get("note", "")
        scored.append(row)
    return {
        "matcher": corpus.get("matcher", "vulndb.lookup_offline_cves"),
        "cases": scored,
        "summary": aggregate(scored),
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _ci(pair) -> str:
    lo, hi = pair
    if lo is None:
        return "—"
    return f"[{lo:.3f}, {hi:.3f}]"


def render_md(result: dict) -> str:
    s = result["summary"]
    lines = [
        "### Offline CVE-matching precision / recall "
        f"(`{result['matcher']}`, {s['cases']} labelled cases)",
        "",
        "Closed-world: each banner pins the exact CVE set expected, so any extra id is "
        "a false positive and any missing id a false negative. 95 % Wilson CIs.",
        "",
        "| Metric | Value | 95 % CI | Counts |",
        "|---|---:|:---:|---|",
        f"| **Precision** | {s['precision']:.3f} | {_ci(s['precision_ci'])} | "
        f"{s['tp']}/{s['predicted_positives']} predicted-positive |",
        f"| **Recall** | {s['recall']:.3f} | {_ci(s['recall_ci'])} | "
        f"{s['tp']}/{s['actual_positives']} actual-positive |",
        f"| **F1** | {s['f1']:.3f} |  | fp={s['fp']}, fn={s['fn']} |",
        "",
        "| Category | Cases | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|",
    ]
    for name in sorted(result["summary"]["by_category"]):
        c = result["summary"]["by_category"][name]
        lines.append(
            f"| {name} | {c['cases']} | {c['precision']:.3f} | {c['recall']:.3f} | {c['f1']:.3f} |"
        )
    fp_cases = s["false_positive_cases"]
    fn_cases = s["false_negative_cases"]
    lines += [
        "",
        f"- **False positives:** {', '.join(fp_cases) if fp_cases else 'none'}",
        f"- **False negatives:** {', '.join(fn_cases) if fn_cases else 'none'}",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="EnumGrid offline CVE-matching precision/recall")
    ap.add_argument("--corpus", default=_DEFAULT_CORPUS, help="path to cve_corpus.json")
    ap.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    ap.add_argument("--md", metavar="FILE", help="append the markdown table to this path")
    ap.add_argument("--min-precision", type=float, default=None,
                    help="exit 1 if measured precision is below this (CI gate)")
    ap.add_argument("--min-recall", type=float, default=None,
                    help="exit 1 if measured recall is below this (CI gate)")
    args = ap.parse_args(argv)

    result = run(load_corpus(args.corpus))
    md = render_md(result)
    print("\n" + md + "\n")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"→ wrote {args.json}", file=sys.stderr)
    if args.md:
        with open(args.md, "a", encoding="utf-8") as fh:
            fh.write(md + "\n\n")

    s = result["summary"]
    failed = False
    if args.min_precision is not None and s["precision"] < args.min_precision:
        print(f"FAIL: precision {s['precision']:.3f} < {args.min_precision}", file=sys.stderr)
        failed = True
    if args.min_recall is not None and s["recall"] < args.min_recall:
        print(f"FAIL: recall {s['recall']:.3f} < {args.min_recall}", file=sys.stderr)
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
