#!/usr/bin/env python3
"""
copilot_eval.py — measure the AI copilot's **grounding** and **accuracy**, in the
same spirit as benchmark.py: the scoring is deterministic and unit-tested, and it
never fabricates. Run it with a provider configured (free local Ollama, the Gemini
free tier, or a paid key) and it produces real numbers over a fixed scan; run it
with nothing configured and it says so and exits — it does not invent a score.

Two properties matter for a security copilot, and we score both:

  * **grounding**  — it must NOT invent hosts/ports/CVEs that aren't in the scan
    (ENUMGRID's "no fake data" rule turned into a metric): the fraction of
    hallucination-trap facts the reply correctly *avoids*.
  * **coverage**   — it should surface the facts that matter: the fraction of the
    expected, genuinely-present facts the reply *mentions*.

Usage:
    python evaluation/copilot_eval.py                 # uses the active provider
    python evaluation/copilot_eval.py --provider ollama --model llama3.2
    python evaluation/copilot_eval.py --json out.json
    python evaluation/copilot_eval.py --self-test     # score built-in fixtures
                                                      # (validates the metric math,
                                                      #  no provider/network needed)
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
import sys

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

# ---------------------------------------------------------------------------- #
# Fixed evaluation set — a realistic, in-scope scan (172.16.2.0/24 is authorized)
# plus questions whose ground truth is known. `expect` = facts a correct grounded
# answer should mention; `traps` = plausible facts NOT in the scan that a
# fabricating model might invent.
# ---------------------------------------------------------------------------- #
SCAN_CONTEXT = {
    "target": "172.16.2.0/24",
    "hosts": [
        {"ip": "172.16.2.1", "hostname": "gw", "device_type": "Router", "os": "RouterOS",
         "ports": [{"port": 80, "service": "http"}, {"port": 443, "service": "https"},
                   {"port": 53, "service": "domain"}],
         "vulns": [{"id": "CVE-2021-44228", "severity": "critical"}]},
        {"ip": "172.16.2.5", "hostname": "build01", "device_type": "Server", "os": "Linux",
         "ports": [{"port": 22, "service": "ssh"}, {"port": 8080, "service": "http-proxy"}],
         "vulns": [{"id": "CVE-2022-0778", "severity": "high"}]},
        {"ip": "172.16.2.20", "hostname": "cam", "device_type": "IP Camera", "os": "embedded",
         "ports": [{"port": 554, "service": "rtsp"}], "vulns": []},
    ],
}

# Each `expect` entry is a fact the answer should convey; a nested list means
# "any of these phrasings counts" (so citing "Log4Shell" credits the same as the
# CVE id — we score correctness, not verbosity). `traps` are exact fabrications.
CASES = [
    {
        "q": "Which host is the most exposed, and why?",
        "expect": [["172.16.2.1", "gateway", "gw"]],   # the router: most ports + a critical CVE
        "traps": ["172.16.2.99", "CVE-2099-0001"],
    },
    {
        "q": "Are there any critical vulnerabilities? Name the CVE id(s).",
        "expect": [["CVE-2021-44228", "log4shell", "log4j"]],
        "traps": ["CVE-2017-0144", "CVE-2014-0160"],
    },
    {
        "q": "What is running on 172.16.2.5?",
        "expect": [["ssh", "secure shell", ":22", "port 22"]],
        "traps": ["3389", "rdp"],                       # not open on that host
    },
    {
        "q": "Is host 172.16.2.20 a web server?",
        "expect": [["camera", "rtsp", "not a web"]],    # it's an IP camera (rtsp)
        "traps": ["nginx", "apache"],
    },
    {
        "q": "Give a one-line risk summary of this subnet.",
        "expect": [["172.16.2.1", "gateway", "gw", "log4shell", "cve-2021-44228"]],
        "traps": ["10.0.0.1", "192.168.1.1"],           # out-of-scope addresses
    },
]

# Reference replies used by --self-test and the unit tests: one properly grounded,
# one that hallucinates. They anchor the metric so the published numbers mean
# something.
FIXTURE_GOOD = {
    "Which host is the most exposed, and why?":
        "172.16.2.1 (the gateway) is most exposed — three open ports and a critical CVE-2021-44228.",
    "Are there any critical vulnerabilities? Name the CVE id(s).":
        "Yes: CVE-2021-44228 (critical) on the router. CVE-2022-0778 (high) on 172.16.2.5.",
    "What is running on 172.16.2.5?":
        "172.16.2.5 exposes ssh (22) and an http-proxy (8080).",
    "Is host 172.16.2.20 a web server?":
        "No — 172.16.2.20 is an IP camera exposing rtsp (554), not a web server.",
    "Give a one-line risk summary of this subnet.":
        "Highest risk is 172.16.2.1 (critical Log4Shell); patch it first, then 172.16.2.5.",
}
FIXTURE_HALLUCINATED = {
    "Which host is the most exposed, and why?":
        "172.16.2.99 is the most exposed with CVE-2099-0001 and open RDP.",
    "Are there any critical vulnerabilities? Name the CVE id(s).":
        "Yes — CVE-2017-0144 (EternalBlue) and CVE-2014-0160 (Heartbleed) are present.",
    "What is running on 172.16.2.5?":
        "It runs RDP on 3389 and a Windows domain controller.",
    "Is host 172.16.2.20 a web server?":
        "Yes, it runs nginx and apache serving a web app.",
    "Give a one-line risk summary of this subnet.":
        "The riskiest host is 10.0.0.1 with multiple criticals.",
}


# ---------------------------------------------------------------------------- #
# Scoring (pure, deterministic, unit-tested)
# ---------------------------------------------------------------------------- #
def _mentions(reply: str, needle: str) -> bool:
    return needle.lower() in (reply or "").lower()


def _fact_hit(reply: str, fact) -> bool:
    """A fact is met if the reply mentions it (or any of its accepted phrasings)."""
    alts = fact if isinstance(fact, (list, tuple)) else [fact]
    return any(_mentions(reply, a) for a in alts)


def _fact_label(fact) -> str:
    return " / ".join(fact) if isinstance(fact, (list, tuple)) else str(fact)


def context_cves(context: dict) -> set:
    """Every CVE id genuinely present in the scan context (upper-cased)."""
    return {str(v.get("id", "")).upper()
            for h in (context or {}).get("hosts", [])
            for v in (h.get("vulns") or [])
            if v.get("id")}


def score_case(reply: str, case: dict, known_cves: set | None = None) -> dict:
    """Score one reply. Coverage = expected facts hit. Grounding is strict and
    per-case: it is 1.0 only when the reply invents *nothing* — neither a listed
    trap nor any CVE id that isn't in the scan. Catching *novel* fabricated CVEs
    (not just pre-listed traps) is what makes this an honest "no fake data" check."""
    reply = reply or ""
    must = case.get("expect", [])
    traps = case.get("traps", [])
    hits = sum(1 for f in must if _fact_hit(reply, f))
    tripped = [t for t in traps if _mentions(reply, t)]
    fabricated = []
    if known_cves is not None:
        for cve in _CVE_RE.findall(reply):
            up = cve.upper()
            if up not in known_cves and up not in fabricated:
                fabricated.append(up)
    hallucinated = tripped + [c for c in fabricated if c not in tripped]
    return {
        "question": case["q"],
        "coverage": round(hits / len(must) if must else 1.0, 3),
        "grounding": 0.0 if hallucinated else 1.0,   # strict: any fabrication fails the case
        "missed": [_fact_label(f) for f in must if not _fact_hit(reply, f)],
        "hallucinated": hallucinated,
    }


def aggregate(results: list[dict]) -> dict:
    """Mean coverage/grounding and a combined score across scored cases."""
    n = len(results)
    if not n:
        return {"cases": 0, "coverage": 0.0, "grounding": 0.0, "score": 0.0}
    cov = sum(r["coverage"] for r in results) / n
    grd = sum(r["grounding"] for r in results) / n
    return {
        "cases": n,
        "coverage": round(cov, 3),
        "grounding": round(grd, 3),
        "score": round((cov + grd) / 2, 3),
    }


def summarize(values: list[float]) -> dict:
    """Descriptive stats for a sample: n, mean, stdev, 95 % CI half-width, min, max.

    Mirrors ``benchmark.py``'s statistics helper so both harnesses report variance
    the same way. The CI uses the normal approximation (z = 1.96) and is 0 for a
    single run (no variance to estimate) — small-n samples stay honest."""
    vals = [float(v) for v in values]
    n = len(vals)
    if n == 0:
        return {"n": 0, "mean": 0.0, "stdev": 0.0, "ci95": 0.0, "min": 0.0, "max": 0.0}
    mean = statistics.fmean(vals)
    stdev = statistics.stdev(vals) if n >= 2 else 0.0
    ci95 = 1.96 * stdev / math.sqrt(n) if n >= 2 else 0.0
    return {
        "n": n,
        "mean": round(mean, 3),
        "stdev": round(stdev, 3),
        "ci95": round(ci95, 3),
        "min": round(min(vals), 3),
        "max": round(max(vals), 3),
    }


# ---------------------------------------------------------------------------- #
# Live runner (needs a configured provider; imports the backend copilot lazily)
# ---------------------------------------------------------------------------- #
def _import_copilot():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    backend = os.path.join(root, "backend")
    if backend not in sys.path:
        sys.path.insert(0, backend)
    import copilot  # noqa: PLC0415 - lazy so the pure scoring has no backend dep
    return copilot


def _collect_reply(copilot, question: str, provider, model):
    """Run one turn and return (reply_text, error) — no fabrication on failure."""
    parts: list[str] = []
    for ev in copilot.stream_reply(
        [{"role": "user", "content": question}], SCAN_CONTEXT, provider=provider, model=model
    ):
        kind = ev.get("type")
        if kind == "delta":
            parts.append(ev.get("text", ""))
        elif kind == "error":
            return None, ev.get("message", "error")
    return "".join(parts), None


def run(provider=None, model=None) -> dict:
    """Score every case against a live provider. Returns a full result dict."""
    copilot = _import_copilot()
    prov = provider or copilot.active_provider()
    known = context_cves(SCAN_CONTEXT)
    results = []
    for case in CASES:
        reply, err = _collect_reply(copilot, case["q"], prov, model)
        if err:
            row = {"question": case["q"], "error": err, "coverage": 0.0, "grounding": 0.0,
                   "missed": [_fact_label(f) for f in case["expect"]], "hallucinated": []}
        else:
            row = score_case(reply, case, known_cves=known)
            row["reply"] = reply
        results.append(row)
    return {"provider": prov, "model": model or copilot.active_model(prov),
            "results": results, "summary": aggregate(results)}


def aggregate_runs(runs: list[dict]) -> dict:
    """Aggregate the headline metrics across whole-evaluation runs as mean ± 95 % CI.

    ``runs`` is a list of :func:`run` results. We summarise only what was actually
    measured — the per-run coverage/grounding/score — so nothing is invented; the
    spread (stdev / CI) is what removes the single-run caveat from the writeup."""
    cov = [r["summary"]["coverage"] for r in runs]
    grd = [r["summary"]["grounding"] for r in runs]
    sc = [r["summary"]["score"] for r in runs]
    return {
        "coverage": summarize(cov),
        "grounding": summarize(grd),
        "score": summarize(sc),
    }


def run_many(provider=None, model=None, runs: int = 1) -> dict:
    """Run the full evaluation ``runs`` times and report mean ± 95 % CI.

    Small local models vary run-to-run at temperature 0.2, so a single run's
    coverage is a noisy point estimate. Repeating and reporting the mean ± CI is
    the honest headline number (see docs/COPILOT.md §4.4). The individual runs are
    retained under ``per_run`` so a reader can see the raw spread."""
    n = max(1, int(runs))
    per_run = [run(provider=provider, model=model) for _ in range(n)]
    return {
        "provider": per_run[0]["provider"],
        "model": per_run[0]["model"],
        "runs": n,
        "aggregate": aggregate_runs(per_run),
        "per_run": [r["summary"] for r in per_run],
        "detail": per_run,
    }


def run_fixtures(fixtures: dict) -> dict:
    """Score a set of canned replies — used by --self-test and the unit tests."""
    known = context_cves(SCAN_CONTEXT)
    results = [score_case(fixtures.get(c["q"], ""), c, known_cves=known) for c in CASES]
    return {"provider": "fixture", "results": results, "summary": aggregate(results)}


def _print_report(res: dict) -> None:
    s = res["summary"]
    print(f"\nCopilot evaluation — provider: {res.get('provider')}"
          + (f" · model: {res['model']}" if res.get("model") else ""))
    print("-" * 60)
    for r in res["results"]:
        flag = "ok " if not r.get("error") and not r["hallucinated"] and not r["missed"] else "   "
        print(f"[{flag}] cov={r['coverage']:.2f} grd={r['grounding']:.2f}  {r['question']}")
        if r.get("error"):
            print(f"        error: {r['error']}")
        if r.get("hallucinated"):
            print(f"        hallucinated (not in scan): {', '.join(r['hallucinated'])}")
        if r.get("missed"):
            print(f"        missed: {', '.join(r['missed'])}")
    print("-" * 60)
    print(f"cases={s['cases']}  coverage={s['coverage']:.2f}  "
          f"grounding={s['grounding']:.2f}  score={s['score']:.2f}\n")


def _print_multi(res: dict) -> None:
    """Print a multi-run report: each run's headline metrics, then mean ± 95 % CI."""
    print(f"\nCopilot evaluation — provider: {res.get('provider')}"
          + (f" · model: {res['model']}" if res.get("model") else "")
          + f" · {res['runs']} run(s)")
    print("-" * 60)
    for i, s in enumerate(res["per_run"], 1):
        print(f"  run {i}: cov={s['coverage']:.2f}  grd={s['grounding']:.2f}  score={s['score']:.2f}")
    print("-" * 60)
    agg = res["aggregate"]
    for name in ("coverage", "grounding", "score"):
        a = agg[name]
        print(f"{name:>9}: {a['mean']:.3f} ± {a['ci95']:.3f}  "
              f"(min {a['min']:.2f}, max {a['max']:.2f}, n={a['n']})")
    print()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate the ENUMGRID AI copilot (grounding + accuracy).")
    ap.add_argument("--provider", help="ollama | gemini | anthropic | openai (default: active)")
    ap.add_argument("--model", help="override the model (e.g. llama3.2)")
    ap.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    ap.add_argument("--runs", type=int, default=1, metavar="N",
                    help="repeat the evaluation N times and report mean ± 95%% CI "
                         "(removes single-run variance from the headline number)")
    ap.add_argument("--self-test", action="store_true",
                    help="score built-in grounded + hallucinated fixtures (no provider needed)")
    args = ap.parse_args(argv)

    if args.self_test:
        good = run_fixtures(FIXTURE_GOOD)
        bad = run_fixtures(FIXTURE_HALLUCINATED)
        print("Self-test — grounded reference replies:")
        _print_report(good)
        print("Self-test — hallucinated reference replies (grounding should collapse):")
        _print_report(bad)
        ok = good["summary"]["score"] >= 0.9 and bad["summary"]["grounding"] <= 0.1
        print("metric sanity:", "PASS" if ok else "FAIL")
        return 0 if ok else 1

    copilot = _import_copilot()
    prov = args.provider or copilot.active_provider()
    st = copilot.status()["providers"].get(prov, {})
    if not st.get("ready"):
        print(f"✖ provider '{prov}' is not ready (SDK/key/server). Configure it in the "
              f"dashboard or run with --self-test. Nothing was fabricated.", file=sys.stderr)
        return 2

    if args.runs and args.runs > 1:
        res = run_many(provider=args.provider, model=args.model, runs=args.runs)
        _print_multi(res)
    else:
        res = run(provider=args.provider, model=args.model)
        _print_report(res)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2)
        print(f"→ wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
