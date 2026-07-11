"""Tests for the live-NVD CVE precision/recall harness (nvd_precision.py).

Two layers, mirroring detection_benchmark / cve_precision:
  * the pure scoring + aggregation are unit-tested with hand-built inputs, so the
    published recall / version-scoping numbers are trustworthy;
  * the REAL parser (backend/cve.parse_nvd) is driven over hand-authored NVD-2.0
    SCHEMA FIXTURES (not live captures) to prove the parse+score pipeline end to
    end with no network. The authoritative numbers come from `--live` (operator).

`CVE-2099-*` ids are synthetic filler used only to force the top-N truncation path.
"""

from __future__ import annotations

import json
import os

import nvd_precision as nv
import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_CATEGORIES = {"recall", "version-scope", "wrong-product"}

# --------------------------------------------------------------------------- #
# Hand-authored NVD-2.0 schema fixtures (built via the harness's own schema
# helper so the parser sees the exact production shape). NOT live captures.
# --------------------------------------------------------------------------- #
_TRUNC_DECOYS = [(f"CVE-2099-{1000 + i}", 9.9) for i in range(12)]  # 12 high-CVSS fillers

FIXTURES: list[dict] = [
    {"cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "category": "recall",
     "expect_present": ["CVE-2021-41773"], "expect_absent": [],
     "data": nv._nvd_response([("CVE-2021-42013", 9.8), ("CVE-2021-41773", 7.5)])},
    {"cpe": "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*", "category": "version-scope",
     "expect_present": [], "expect_absent": ["CVE-2021-41773", "CVE-2021-42013"],
     "data": nv._nvd_response([("CVE-2021-44790", 9.8)])},
    {"cpe": "cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*", "category": "recall",
     "expect_present": ["CVE-2099-9999"], "expect_absent": [],
     "data": nv._nvd_response([*_TRUNC_DECOYS, ("CVE-2099-9999", 1.0)])},
    {"cpe": "cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*", "category": "wrong-product",
     "expect_present": [], "expect_absent": ["CVE-2021-41773"],
     "data": nv._nvd_response([("CVE-2023-38408", 9.8)])},
]


# --------------------------------------------------------------------------- #
# raw_cve_ids
# --------------------------------------------------------------------------- #
def test_raw_cve_ids_extracts_and_uppercases():
    data = nv._nvd_response([("cve-2021-41773", 7.5), ("CVE-2021-42013", 9.8)])
    assert nv.raw_cve_ids(data) == {"CVE-2021-41773", "CVE-2021-42013"}


def test_raw_cve_ids_empty_response():
    assert nv.raw_cve_ids({}) == set()
    assert nv.raw_cve_ids({"vulnerabilities": []}) == set()


# --------------------------------------------------------------------------- #
# score_case
# --------------------------------------------------------------------------- #
def test_score_case_recall_hit():
    r = nv.score_case(["CVE-1"], ["CVE-1"], ["CVE-1"], [])
    assert r["n_recalled"] == 1 and r["missed"] == [] and r["n_violations"] == 0


def test_score_case_miss_attributed_to_truncation_when_present_in_raw():
    r = nv.score_case([], ["CVE-1"], ["CVE-1"], [])   # returned nothing, but raw HAD it
    assert r["missed"] == ["CVE-1"]
    assert r["truncated"] == ["CVE-1"]                # dropped by the top-N cap
    assert r["absent_missing"] == []


def test_score_case_miss_attributed_to_absence_when_not_in_raw():
    r = nv.score_case([], [], ["CVE-1"], [])          # NVD never returned it
    assert r["truncated"] == []
    assert r["absent_missing"] == ["CVE-1"]


def test_score_case_version_scoping_violation():
    r = nv.score_case(["CVE-BAD"], ["CVE-BAD"], [], ["CVE-BAD"])
    assert r["n_violations"] == 1 and r["violations"] == ["CVE-BAD"]


def test_score_case_extras_are_not_false_positives():
    """A returned CVE outside both label sets is neither recall nor a violation."""
    r = nv.score_case(["CVE-1", "CVE-EXTRA"], ["CVE-1", "CVE-EXTRA"], ["CVE-1"], [])
    assert r["n_recalled"] == 1 and r["n_violations"] == 0


def test_score_case_is_case_insensitive():
    r = nv.score_case(["cve-1"], ["cve-1"], ["CVE-1"], [])
    assert r["n_recalled"] == 1


# --------------------------------------------------------------------------- #
# aggregate
# --------------------------------------------------------------------------- #
def _mk(cpe, category, returned, raw, present, absent):
    row = nv.score_case(returned, raw, present, absent)
    row["cpe"] = cpe
    row["category"] = category
    return row


def test_aggregate_micro_recall_and_scoping():
    cases = [
        _mk("a", "recall", ["CVE-1"], ["CVE-1"], ["CVE-1"], []),          # recalled
        _mk("b", "recall", [], ["CVE-2"], ["CVE-2"], []),                 # truncated miss
        _mk("c", "version-scope", ["CVE-3"], ["CVE-3"], [], ["CVE-3"]),   # violation
    ]
    s = nv.aggregate(cases)
    assert s["present"] == 2 and s["recalled"] == 1
    assert s["recall"] == pytest.approx(0.5)
    assert s["absent"] == 1 and s["violations"] == 1
    assert s["scoping_precision"] == pytest.approx(0.0)
    assert s["truncation_losses"] == ["CVE-2"]
    assert s["violation_detail"] == [{"cpe": "c", "violations": ["CVE-3"]}]
    assert set(s["by_category"]) == {"recall", "version-scope"}
    assert s["by_category"]["recall"]["recall"] == pytest.approx(0.5)


def test_aggregate_excludes_fetch_errors():
    cases = [
        _mk("ok", "recall", ["CVE-1"], ["CVE-1"], ["CVE-1"], []),
        {"cpe": "bad", "category": "recall", "error": "timeout"},
    ]
    s = nv.aggregate(cases)
    assert s["scored"] == 1 and s["errors"] == ["bad"]
    assert s["recall"] == 1.0


def test_aggregate_perfect_recall_has_nondegenerate_ci():
    cases = [_mk(str(i), "recall", ["CVE-%d" % i], ["CVE-%d" % i], ["CVE-%d" % i], [])
             for i in range(5)]
    s = nv.aggregate(cases)
    assert s["recall"] == 1.0
    lo, hi = s["recall_ci"]
    assert hi == pytest.approx(1.0) and 0.0 < lo < 1.0


def test_aggregate_no_labels_is_defined_as_one():
    """No expect_present / expect_absent anywhere => vacuously perfect, not a crash."""
    s = nv.aggregate([_mk("x", "recall", ["CVE-1"], ["CVE-1"], [], [])])
    assert s["recall"] == 1.0 and s["scoping_precision"] == 1.0


# --------------------------------------------------------------------------- #
# evaluate_response — the REAL parser (backend/cve.parse_nvd) over fixtures
# --------------------------------------------------------------------------- #
def test_evaluate_response_recalls_documented_cve():
    fx = FIXTURES[0]
    r = nv.evaluate_response(fx["data"], fx["expect_present"], fx["expect_absent"])
    assert "CVE-2021-41773" in r["recalled"] and r["missed"] == []


def test_evaluate_response_truncation_loss_is_attributed():
    fx = FIXTURES[2]  # 12 high-CVSS decoys + 1 low-CVSS target => target dropped by top-N
    r = nv.evaluate_response(fx["data"], fx["expect_present"], fx["expect_absent"])
    assert r["missed"] == ["CVE-2099-9999"]
    assert r["truncated"] == ["CVE-2099-9999"]        # present in raw, cut by the cap


def test_version_scope_fixture_reports_no_violation():
    fx = FIXTURES[1]
    r = nv.evaluate_response(fx["data"], fx["expect_present"], fx["expect_absent"])
    assert r["n_violations"] == 0
    assert "CVE-2021-41773" not in r["returned"]


def test_wrong_product_fixture_does_not_leak_other_products_cve():
    fx = FIXTURES[3]
    r = nv.evaluate_response(fx["data"], fx["expect_present"], fx["expect_absent"])
    assert r["n_violations"] == 0 and "CVE-2021-41773" not in r["returned"]


# --------------------------------------------------------------------------- #
# run_fixtures + rendering + self-check set
# --------------------------------------------------------------------------- #
def test_run_fixtures_end_to_end():
    result = nv.run_fixtures(FIXTURES)
    s = result["summary"]
    assert result["source"] == "fixtures"
    assert s["recall"] == pytest.approx(0.5)          # 1 of 2 documented ids (1 truncated)
    assert s["scoping_precision"] == 1.0              # no version-scoping violations
    assert "CVE-2099-9999" in s["truncation_losses"]


def test_selfcheck_fixtures_are_clean():
    """The bundled self-check set (no --live) must parse+score with perfect recall."""
    s = nv.run_fixtures(nv.SELFCHECK_FIXTURES)["summary"]
    assert s["recall"] == 1.0 and s["violations"] == 0


def test_render_md_smoke_marks_fixture_source():
    md = nv.render_md(nv.run_fixtures(FIXTURES))
    assert "Recall" in md and "Version-scoping" in md
    assert "schema fixtures" in md and "--live" in md  # honest: not the live number


# --------------------------------------------------------------------------- #
# Corpus file validity
# --------------------------------------------------------------------------- #
def _corpus():
    return nv.load_corpus(os.path.join(_HERE, "nvd_corpus.json"))


def test_corpus_is_well_formed():
    corpus = _corpus()
    cpes = [c["cpe"] for c in corpus["cases"]]
    assert len(cpes) >= 10
    assert len(cpes) == len(set(cpes)), "duplicate CPE in corpus"
    for c in corpus["cases"]:
        assert c["category"] in _CATEGORIES
        assert c["cpe"].startswith("cpe:2.3:")
        assert isinstance(c["expect_present"], list) and isinstance(c["expect_absent"], list)


def test_corpus_exercises_recall_scoping_and_wrong_product():
    cats = {c["category"] for c in _corpus()["cases"]}
    assert _CATEGORIES <= cats, "corpus must cover recall, version-scope AND wrong-product"


def test_corpus_labelled_ids_are_cve_shaped():
    for c in _corpus()["cases"]:
        for cve in c["expect_present"] + c["expect_absent"]:
            assert cve.upper().startswith("CVE-")


def test_corpus_scope_cases_pin_an_absent_id():
    """Every version-scope / wrong-product case must actually assert something absent."""
    for c in _corpus()["cases"]:
        if c["category"] in {"version-scope", "wrong-product"}:
            assert c["expect_absent"], f"{c['cpe']} pins nothing to exclude"


# --------------------------------------------------------------------------- #
# main() — the fixture self-check path (no network) + gate wiring
# --------------------------------------------------------------------------- #
def test_main_selfcheck_runs_without_network(capsys):
    rc = nv.main([])                       # no --live => fixture self-check
    assert rc == 0
    assert "Recall" in capsys.readouterr().out


def test_main_gates_pass_on_selfcheck(tmp_path):
    out = tmp_path / "r.json"
    rc = nv.main(["--min-recall", "0.5", "--max-violations", "0", "--json", str(out)])
    assert rc == 0
    written = json.loads(out.read_text())
    assert written["summary"]["recall"] == 1.0        # self-check set recalls perfectly


def test_main_min_recall_gate_can_fail():
    assert nv.main(["--min-recall", "1.5"]) == 1      # unsatisfiable => exercises FAIL branch
