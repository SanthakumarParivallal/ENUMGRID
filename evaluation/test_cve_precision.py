"""Tests for the offline CVE-matching precision/recall harness (cve_precision.py).

Two layers, mirroring detection_benchmark:
  * the pure scoring/statistics are unit-tested with hand-built inputs, so the
    published precision/recall numbers are trustworthy;
  * an end-to-end pass runs the REAL matcher (backend/vulndb) over the labelled
    corpus and asserts the accuracy floor — this is the CI gate that locks in
    the "no wrong CVE" guarantee and guards the httpd-vs-lighttpd fix forever.
"""

from __future__ import annotations

import json
import os

import cve_precision as cp
import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ALLOWED_CATEGORIES = {"exact", "boundary", "wrong-product", "backport", "control"}


# --------------------------------------------------------------------------- #
# Wilson score interval
# --------------------------------------------------------------------------- #
def test_wilson_perfect_has_nondegenerate_lower_bound():
    """17/17 correct must NOT report a zero-width [1,1] interval (the whole point)."""
    lo, hi = cp.wilson_ci(17, 17)
    assert hi == pytest.approx(1.0, abs=1e-9)
    assert 0.0 < lo < 1.0            # honest uncertainty, not a fake certainty
    assert lo == pytest.approx(0.816, abs=0.01)


def test_wilson_zero_successes_has_zero_lower_bound():
    lo, hi = cp.wilson_ci(0, 10)
    assert lo == pytest.approx(0.0, abs=1e-9)
    assert 0.0 < hi < 1.0


def test_wilson_no_trials_is_undefined():
    assert cp.wilson_ci(0, 0) == (None, None)


def test_wilson_interval_brackets_point_estimate():
    lo, hi = cp.wilson_ci(8, 10)
    assert lo < 0.8 < hi


# --------------------------------------------------------------------------- #
# Per-case scoring
# --------------------------------------------------------------------------- #
def test_score_case_all_correct():
    r = cp.score_case(["CVE-2021-41773"], ["CVE-2021-41773"])
    assert (r["tp"], r["fp"], r["fn"]) == (1, 0, 0)


def test_score_case_false_positive_is_precision_hit():
    r = cp.score_case(["CVE-2021-41773"], [])
    assert r["fp"] == 1 and r["tp"] == 0
    assert r["false_positives"] == ["CVE-2021-41773"]


def test_score_case_false_negative_is_recall_miss():
    r = cp.score_case([], ["CVE-2011-2523"])
    assert r["fn"] == 1 and r["tp"] == 0
    assert r["missed"] == ["CVE-2011-2523"]


def test_score_case_is_case_insensitive_and_ignores_blanks():
    r = cp.score_case(["cve-2021-41773", " "], ["CVE-2021-41773"])
    assert (r["tp"], r["fp"], r["fn"]) == (1, 0, 0)


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #
def _mk(banner, category, got, expect):
    row = cp.score_case(got, expect)
    row["banner"] = banner
    row["category"] = category
    return row


def test_aggregate_micro_averages_and_buckets_by_category():
    cases = [
        _mk("a", "exact", ["CVE-1"], ["CVE-1"]),          # tp
        _mk("b", "boundary", ["CVE-2"], []),               # fp
        _mk("c", "exact", [], ["CVE-3"]),                  # fn
    ]
    agg = cp.aggregate(cases)
    assert (agg["tp"], agg["fp"], agg["fn"]) == (1, 1, 1)
    assert agg["precision"] == pytest.approx(0.5)
    assert agg["recall"] == pytest.approx(0.5)
    assert agg["false_positive_cases"] == ["b"]
    assert agg["false_negative_cases"] == ["c"]
    assert set(agg["by_category"]) == {"exact", "boundary"}
    assert agg["by_category"]["boundary"]["precision"] == pytest.approx(0.0)


def test_aggregate_clean_corpus_is_perfect_with_ci():
    cases = [_mk(str(i), "exact", ["CVE-%d" % i], ["CVE-%d" % i]) for i in range(5)]
    agg = cp.aggregate(cases)
    assert agg["precision"] == 1.0 and agg["recall"] == 1.0
    lo, hi = agg["precision_ci"]
    assert hi == pytest.approx(1.0) and 0.0 < lo < 1.0


# --------------------------------------------------------------------------- #
# Corpus file validity
# --------------------------------------------------------------------------- #
def _corpus():
    return cp.load_corpus(os.path.join(_HERE, "cve_corpus.json"))


def test_corpus_is_well_formed():
    corpus = _corpus()
    banners = [c["banner"] for c in corpus["cases"]]
    assert len(banners) >= 25
    assert len(banners) == len(set(banners)), "duplicate banner in corpus"
    for c in corpus["cases"]:
        assert c["category"] in _ALLOWED_CATEGORIES
        assert isinstance(c["expect"], list)


def test_corpus_covers_every_trap_category():
    cats = {c["category"] for c in _corpus()["cases"]}
    assert _ALLOWED_CATEGORIES <= cats, "corpus must exercise all trap categories"


def test_corpus_expected_ids_are_cve_shaped():
    for c in _corpus()["cases"]:
        for cve in c["expect"]:
            assert cve.upper().startswith("CVE-")


# --------------------------------------------------------------------------- #
# End-to-end against the REAL matcher — the accuracy floor / CI gate
# --------------------------------------------------------------------------- #
def test_real_matcher_scores_perfect_on_corpus():
    result = cp.run(_corpus())
    s = result["summary"]
    assert s["fp"] == 0, f"false positives: {s['false_positive_cases']}"
    assert s["fn"] == 0, f"false negatives: {s['false_negative_cases']}"
    assert s["precision"] == 1.0 and s["recall"] == 1.0


def test_lighttpd_regression_guard():
    """Locks in the fix: 'httpd' must not match inside 'lighttpd'."""
    from vulndb import lookup_offline_cves
    assert [v.id for v in lookup_offline_cves("lighttpd 2.4.49")] == []
    # the genuine Apache build still detects
    assert "CVE-2021-41773" in [v.id for v in lookup_offline_cves("Apache httpd 2.4.49")]
    # lighttpd's own CVE still detects
    assert "CVE-2022-41556" in [v.id for v in lookup_offline_cves("lighttpd 1.4.50")]


def test_wrong_product_version_collision_maps_to_right_product():
    """2.3.4 is vsftpd's magic version; on OpenSSH it must not become vsftpd's CVE."""
    from vulndb import lookup_offline_cves
    ids = [v.id for v in lookup_offline_cves("OpenSSH 2.3.4")]
    assert "CVE-2018-15473" in ids          # the OpenSSH finding is right
    assert "CVE-2011-2523" not in ids       # never the vsftpd one


def test_render_md_smoke():
    md = cp.render_md(cp.run(_corpus()))
    assert "Precision" in md and "Recall" in md
    assert "wrong-product" in md


def test_main_min_precision_gate_passes(tmp_path, capsys):
    out = tmp_path / "r.json"
    rc = cp.main(["--min-precision", "1.0", "--min-recall", "1.0", "--json", str(out)])
    assert rc == 0
    written = json.loads(out.read_text())
    assert written["summary"]["precision"] == 1.0
