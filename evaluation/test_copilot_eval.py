"""
test_copilot_eval.py — the copilot evaluation's metric math (no provider, no
network). Verifies grounding/coverage scoring so the published numbers are
trustworthy: a grounded reference reply scores ~1.0 and a hallucinated one has its
grounding collapse to ~0.0.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import copilot_eval as ce  # noqa: E402


def test_score_case_perfect_grounded_reply():
    case = {"q": "q", "expect": ["172.16.2.1", "CVE-2021-44228"], "traps": ["172.16.2.99"]}
    r = ce.score_case("172.16.2.1 has CVE-2021-44228 (critical).", case)
    assert r["coverage"] == 1.0 and r["grounding"] == 1.0
    assert r["missed"] == [] and r["hallucinated"] == []


def test_score_case_penalises_hallucination():
    case = {"q": "q", "expect": ["172.16.2.1"], "traps": ["172.16.2.99", "CVE-2099-0001"]}
    r = ce.score_case("The risk is on 172.16.2.99 via CVE-2099-0001.", case)
    assert r["grounding"] == 0.0                       # both traps tripped
    assert set(r["hallucinated"]) == {"172.16.2.99", "CVE-2099-0001"}
    assert r["coverage"] == 0.0 and r["missed"] == ["172.16.2.1"]


def test_score_case_partial_coverage():
    case = {"q": "q", "expect": ["ssh", "8080"], "traps": ["3389"]}
    r = ce.score_case("It runs ssh.", case)
    assert r["coverage"] == 0.5 and r["grounding"] == 1.0
    assert r["missed"] == ["8080"]


def test_score_case_accepts_alternative_phrasings():
    # "Log4Shell" should credit the same as citing the CVE id — we score
    # correctness, not exact wording.
    case = {"q": "q", "expect": [["CVE-2021-44228", "log4shell"]], "traps": []}
    assert ce.score_case("It's Log4Shell.", case)["coverage"] == 1.0
    assert ce.score_case("It's CVE-2021-44228.", case)["coverage"] == 1.0
    assert ce.score_case("some other bug", case)["coverage"] == 0.0


def test_score_case_is_case_insensitive():
    case = {"q": "q", "expect": ["CVE-2021-44228"], "traps": []}
    assert ce.score_case("affected by cve-2021-44228", case)["coverage"] == 1.0


def test_empty_reply_is_grounded_but_uncovered():
    case = {"q": "q", "expect": ["ssh"], "traps": ["rdp"]}
    r = ce.score_case("", case)
    assert r["coverage"] == 0.0 and r["grounding"] == 1.0   # says nothing → invents nothing


def test_context_cves_extracts_known():
    assert ce.context_cves(ce.SCAN_CONTEXT) == {"CVE-2021-44228", "CVE-2022-0778"}


def test_grounding_flags_novel_fabricated_cve():
    known = ce.context_cves(ce.SCAN_CONTEXT)
    case = {"q": "q", "expect": [], "traps": []}       # no listed traps at all
    r = ce.score_case("The router has CVE-2017-5638.", case, known_cves=known)
    assert r["grounding"] == 0.0 and "CVE-2017-5638" in r["hallucinated"]
    ok = ce.score_case("It has CVE-2021-44228.", case, known_cves=known)
    assert ok["grounding"] == 1.0 and ok["hallucinated"] == []


def test_aggregate_means_and_score():
    results = [
        {"coverage": 1.0, "grounding": 1.0},
        {"coverage": 0.0, "grounding": 0.0},
    ]
    agg = ce.aggregate(results)
    assert agg["cases"] == 2 and agg["coverage"] == 0.5 and agg["grounding"] == 0.5
    assert agg["score"] == 0.5


def test_aggregate_empty_is_zero_not_crash():
    assert ce.aggregate([]) == {"cases": 0, "coverage": 0.0, "grounding": 0.0, "score": 0.0}


def test_fixtures_separate_grounded_from_hallucinated():
    # The whole point of the eval: the good fixtures score high; the hallucinated
    # ones keep coverage but their grounding collapses.
    good = ce.run_fixtures(ce.FIXTURE_GOOD)["summary"]
    bad = ce.run_fixtures(ce.FIXTURE_HALLUCINATED)["summary"]
    assert good["score"] >= 0.9
    assert bad["grounding"] <= 0.1


def test_self_test_mode_passes(capsys):
    assert ce.main(["--self-test"]) == 0
    out = capsys.readouterr().out
    assert "metric sanity: PASS" in out


# --------------------------------------------------------------------------- #
# Multi-run statistics (mean ± 95 % CI) — pure math, no provider/network.
# --------------------------------------------------------------------------- #
def test_summarize_single_value_has_zero_spread():
    s = ce.summarize([0.8])
    assert s["n"] == 1 and s["mean"] == 0.8
    assert s["stdev"] == 0.0 and s["ci95"] == 0.0        # one run → no variance to estimate
    assert s["min"] == 0.8 and s["max"] == 0.8


def test_summarize_reports_mean_and_ci():
    s = ce.summarize([0.6, 0.8, 1.0])
    assert s["n"] == 3 and abs(s["mean"] - 0.8) < 1e-9
    assert s["stdev"] > 0.0 and s["ci95"] > 0.0          # real spread across runs
    assert s["min"] == 0.6 and s["max"] == 1.0


def test_summarize_empty_is_zero_not_crash():
    assert ce.summarize([]) == {"n": 0, "mean": 0.0, "stdev": 0.0, "ci95": 0.0, "min": 0.0, "max": 0.0}


def _fake_run_result(coverage, grounding):
    """A minimal run() result shaped like the real one, for aggregation tests."""
    return {
        "provider": "fixture", "model": "m",
        "results": [],
        "summary": {"cases": 5, "coverage": coverage, "grounding": grounding,
                    "score": round((coverage + grounding) / 2, 3)},
    }


def test_aggregate_runs_summarizes_headline_metrics():
    runs = [_fake_run_result(0.6, 1.0), _fake_run_result(1.0, 1.0), _fake_run_result(0.8, 1.0)]
    agg = ce.aggregate_runs(runs)
    assert abs(agg["coverage"]["mean"] - 0.8) < 1e-9     # (0.6+1.0+0.8)/3
    assert agg["grounding"]["mean"] == 1.0 and agg["grounding"]["ci95"] == 0.0  # stable
    assert agg["coverage"]["ci95"] > 0.0                 # coverage varies → non-zero CI


def test_run_many_repeats_and_aggregates(monkeypatch):
    # Deterministic canned runs so no provider/network is needed: run_many must call
    # run() N times and fold the per-run summaries into mean ± CI.
    seq = iter([_fake_run_result(0.6, 1.0), _fake_run_result(1.0, 1.0)])
    monkeypatch.setattr(ce, "run", lambda provider=None, model=None: next(seq))
    res = ce.run_many(runs=2)
    assert res["runs"] == 2 and len(res["per_run"]) == 2 and len(res["detail"]) == 2
    assert abs(res["aggregate"]["coverage"]["mean"] - 0.8) < 1e-9
    assert res["aggregate"]["grounding"]["mean"] == 1.0


def test_run_many_clamps_runs_to_at_least_one(monkeypatch):
    monkeypatch.setattr(ce, "run", lambda provider=None, model=None: _fake_run_result(1.0, 1.0))
    res = ce.run_many(runs=0)
    assert res["runs"] == 1 and len(res["per_run"]) == 1
