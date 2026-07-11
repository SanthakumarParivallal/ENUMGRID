"""
test_detection_benchmark.py — the detection benchmark's scoring math (no Docker,
no network, no nmap). Locks precision/recall/F1 for ports, service-name accuracy,
and planted-CVE recall so the published detection numbers are trustworthy.
"""

from __future__ import annotations

import json
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import detection_benchmark as db  # noqa: E402


# --- ports ----------------------------------------------------------------- #
def test_score_ports_perfect():
    r = db.score_ports({80, 2222}, {80, 2222})
    assert r["precision"] == 1.0 and r["recall"] == 1.0 and r["f1"] == 1.0
    assert r["false_positives"] == [] and r["missed"] == []


def test_score_ports_false_positive_drops_precision():
    # Reported a decoy (23) that is actually closed → precision < 1, recall intact.
    r = db.score_ports({80, 23}, {80})
    assert r["recall"] == 1.0 and r["precision"] == 0.5
    assert r["false_positives"] == [23] and r["missed"] == []


def test_score_ports_missed_drops_recall():
    r = db.score_ports({80}, {80, 2222})
    assert r["precision"] == 1.0 and r["recall"] == 0.5
    assert r["missed"] == [2222] and r["false_positives"] == []


def test_score_ports_empty_truth_and_detection_is_perfect():
    # Probed only decoys, nothing expected, nothing reported → no false positives.
    r = db.score_ports(set(), set())
    assert r["precision"] == 1.0 and r["recall"] == 1.0


# --- services -------------------------------------------------------------- #
def test_score_services_counts_only_found_ports():
    detected = {80: "http", 2222: "ssh"}
    truth = {80: "http", 2222: "ssh", 6379: "redis"}   # redis not found → not scored
    r = db.score_services(detected, truth)
    assert r["scored_ports"] == 2 and r["correct"] == 2 and r["accuracy"] == 1.0


def test_score_services_alias_matches():
    # nmap may label an apache/nginx port "https"/"www"; the alias map treats it
    # as http so a cosmetic name doesn't count as a detection miss.
    assert db.score_services({80: "www"}, {80: "http"})["accuracy"] == 1.0
    assert db.score_services({443: "https"}, {443: "http"})["accuracy"] == 1.0


def test_score_services_records_mismatch():
    r = db.score_services({80: "ftp"}, {80: "http"})
    assert r["accuracy"] == 0.0 and r["mismatches"] == [{"port": 80, "expected": "http", "got": "ftp"}]


def test_score_services_nothing_to_score_is_none():
    assert db.score_services({}, {80: "http"})["accuracy"] is None


# --- versions -------------------------------------------------------------- #
def test_score_versions_substring_match_is_correct():
    # The reported banner CONTAINS the expected token → correct.
    r = db.score_versions({80: "Apache httpd 2.4.49 ((Unix))"}, {80: "2.4.49"})
    assert r["scored_ports"] == 1 and r["correct"] == 1 and r["accuracy"] == 1.0


def test_score_versions_distinguishes_adjacent_builds():
    # The whole point: 2.4.50 must NOT satisfy an expected 2.4.49 (CVE hinges on it).
    r = db.score_versions({80: "Apache httpd 2.4.50"}, {80: "2.4.49"})
    assert r["accuracy"] == 0.0
    assert r["mismatches"] == [{"port": 80, "expected": "2.4.49", "got": "apache httpd 2.4.50"}]


def test_score_versions_skips_ports_without_expected_version():
    # Postgres: service known, version not asserted → not version-scored.
    r = db.score_versions({5432: "PostgreSQL DB"}, {5432: ""})
    assert r["scored_ports"] == 0 and r["accuracy"] is None


def test_score_versions_only_scores_found_ports():
    r = db.score_versions({}, {80: "2.4.49"})
    assert r["scored_ports"] == 0 and r["accuracy"] is None


# --- cves ------------------------------------------------------------------ #
def test_score_cves_recall_and_unexpected():
    r = db.score_cves({"CVE-2021-41773", "CVE-2099-0001"}, ["CVE-2021-41773", "CVE-2021-42013"])
    assert r["recall"] == 0.5
    assert r["recalled"] == ["CVE-2021-41773"] and r["missed"] == ["CVE-2021-42013"]
    assert r["unexpected"] == ["CVE-2099-0001"]      # surfaced, not scored as FP


def test_score_cves_is_case_insensitive():
    r = db.score_cves({"cve-2021-41773"}, ["CVE-2021-41773"])
    assert r["recall"] == 1.0 and r["missed"] == []


def test_score_cves_empty_planted_recall_is_none_but_unexpected_surfaced():
    r = db.score_cves({"CVE-2020-1"}, [])
    assert r["recall"] is None                        # patched host: nothing to recall
    assert r["unexpected"] == ["CVE-2020-1"]          # candidate false positive, flagged


# --- confidence bucketing -------------------------------------------------- #
def test_confidence_samples_tags_each_found_port():
    detected = {"ports": {80: "http", 2222: "ssh"}, "versions": {80: "Apache httpd 2.4.49"},
                "confs": {80: 10, 2222: 3}}
    truth = {"ports": [{"port": 80, "service": "http", "version": "2.4.49"},
                       {"port": 2222, "service": "ssh"},
                       {"port": 6379, "service": "redis"}]}   # 6379 not found → no sample
    rows = db.confidence_samples(detected, truth)
    assert [r["port"] for r in rows] == [80, 2222]
    r80 = next(r for r in rows if r["port"] == 80)
    assert r80["conf"] == 10 and r80["service_ok"] is True and r80["version_ok"] is True
    r2222 = next(r for r in rows if r["port"] == 2222)
    assert r2222["conf"] == 3 and r2222["version_ok"] is None      # no expected version


def test_bucket_confidence_splits_high_and_low():
    samples = [
        {"port": 80, "conf": 10, "service_ok": True, "version_ok": True},
        {"port": 81, "conf": 8, "service_ok": True, "version_ok": False},   # high, wrong version
        {"port": 82, "conf": 3, "service_ok": False, "version_ok": None},   # low, wrong service
        {"port": 83, "conf": None, "service_ok": True, "version_ok": None},  # None → low
    ]
    b = db._bucket_confidence(samples)
    assert b["high"]["n"] == 2 and b["low"]["n"] == 2
    assert b["high"]["service_accuracy"] == 1.0
    assert b["high"]["version_accuracy"] == 0.5      # 1 of 2 versioned high hits correct
    assert b["low"]["service_accuracy"] == 0.5       # 1 of 2 low hits right service
    assert b["low"]["version_accuracy"] is None      # nothing versioned in the low band


def test_bucket_confidence_empty_is_none_not_crash():
    b = db._bucket_confidence([])
    assert b["high"]["n"] == 0 and b["high"]["service_accuracy"] is None


# --- stability (repeated-scan flake) --------------------------------------- #
def test_stability_identical_runs_is_perfect():
    run = {"ports": {80: "http", 22: "ssh"}, "cves": {"CVE-1"}}
    s = db.stability([run, dict(run), dict(run)])
    assert s["port_stability"] == 1.0 and s["service_stability"] == 1.0
    assert s["cve_stability"] == 1.0 and s["flapping_ports"] == []


def test_stability_flapping_port_lowers_port_stability():
    s = db.stability([
        {"ports": {80: "http", 22: "ssh"}, "cves": set()},
        {"ports": {80: "http"}, "cves": set()},               # 22 flapped out
    ])
    assert s["port_stability"] == 0.5                          # 1 stable of 2 seen
    assert s["stable_ports"] == [80] and s["flapping_ports"] == [22]


def test_stability_service_disagreement_lowers_service_stability():
    s = db.stability([
        {"ports": {80: "http"}, "cves": set()},
        {"ports": {80: "unknown"}, "cves": set()},            # same port, different service
    ])
    assert s["port_stability"] == 1.0 and s["service_stability"] == 0.0


def test_stability_single_run_is_trivially_stable():
    s = db.stability([{"ports": {80: "http"}, "cves": set()}])
    assert s["runs"] == 1 and s["port_stability"] == 1.0


def test_stability_cve_jaccard():
    s = db.stability([
        {"ports": {80: "http"}, "cves": {"CVE-1", "CVE-2"}},
        {"ports": {80: "http"}, "cves": {"CVE-1"}},           # CVE-2 flapped
    ])
    assert s["cve_stability"] == 0.5


def test_render_stability_md_smoke():
    result = {"subnet": "172.28.0.0/24", "timestamp": "t", "profile": "vuln",
              "ports": "80", "repeats": 3,
              "hosts": [{"ip": "172.28.0.11", "name": "web-apache",
                         "stability": db.stability([{"ports": {80: "http"}, "cves": set()}] * 3)}]}
    md = db.render_stability_md(result)
    assert "Scan stability" in md and "web-apache" in md and "Port stability" in md


# --- host + aggregate ------------------------------------------------------ #
def _gt_host():
    return {"ip": "172.28.0.11", "name": "web-apache",
            "ports": [{"port": 80, "service": "http", "version": "2.4.49"}],
            "planted_cves": ["CVE-2021-41773", "CVE-2021-42013"]}


def test_score_host_combines_all_axes():
    detected = {"ports": {80: "http"}, "versions": {80: "Apache httpd 2.4.49"},
                "cves": {"CVE-2021-41773", "CVE-2021-42013"}}
    h = db.score_host(detected, _gt_host())
    assert h["ports"]["f1"] == 1.0
    assert h["services"]["accuracy"] == 1.0
    assert h["versions"]["accuracy"] == 1.0
    assert h["cves"]["recall"] == 1.0


def test_score_host_flags_a_wrong_version():
    detected = {"ports": {80: "http"}, "versions": {80: "Apache httpd 2.4.50"},
                "cves": set()}
    h = db.score_host(detected, _gt_host())
    assert h["services"]["accuracy"] == 1.0      # service still right
    assert h["versions"]["accuracy"] == 0.0      # but the version is wrong


def test_aggregate_micro_averages_and_skips_errors():
    hosts = [
        db.score_host({"ports": {80: "http"}, "cves": {"CVE-2021-41773", "CVE-2021-42013"}}, _gt_host()),
        db.score_host({"ports": {6379: "redis"}, "cves": set()},
                      {"ip": "172.28.0.13", "name": "redis",
                       "ports": [{"port": 6379, "service": "redis"}], "planted_cves": []}),
        {"ip": "172.28.0.12", "name": "ssh", "error": "scan failed"},   # skipped
    ]
    agg = db.aggregate(hosts)
    assert agg["hosts_scored"] == 2 and agg["hosts_errored"] == 1
    assert agg["ports"]["precision"] == 1.0 and agg["ports"]["recall"] == 1.0
    assert agg["service_accuracy"] == 1.0
    assert agg["cve_recall"] == 1.0 and agg["cve_planted"] == 2 and agg["cve_recalled"] == 2


def test_aggregate_rolls_up_confidence_buckets():
    detected = {"ports": {80: "http"}, "versions": {80: "Apache httpd 2.4.49"},
                "confs": {80: 10}, "cves": {"CVE-2021-41773", "CVE-2021-42013"}}
    hosts = [db.score_host(detected, _gt_host())]
    agg = db.aggregate(hosts)
    assert agg["confidence_buckets"]["high"]["n"] == 1
    assert agg["confidence_buckets"]["high"]["service_accuracy"] == 1.0
    assert agg["confidence_buckets"]["low"]["n"] == 0


def test_render_md_includes_confidence_table_when_present():
    detected = {"ports": {80: "http"}, "versions": {80: "Apache httpd 2.4.49"},
                "confs": {80: 10}, "cves": {"CVE-2021-41773", "CVE-2021-42013"}}
    hosts = [db.score_host(detected, _gt_host())]
    result = {"subnet": "s", "timestamp": "t", "profile": "vuln", "ports": "80",
              "hosts": hosts, "summary": db.aggregate(hosts)}
    md = db.render_md(result)
    assert "Accuracy by nmap detection confidence" in md
    assert "Version-string accuracy" in md


def test_aggregate_counts_false_positive_ports():
    hosts = [db.score_host({"ports": {80: "http", 23: "telnet"}, "cves": set()},
                           {"ip": "x", "name": "n", "ports": [{"port": 80, "service": "http"}],
                            "planted_cves": []})]
    agg = db.aggregate(hosts)
    assert agg["ports"]["fp"] == 1 and agg["ports"]["precision"] == 0.5


# --- helpers --------------------------------------------------------------- #
def test_ports_spec_for_unions_ports_and_decoys():
    gt = {"decoy_ports": [23], "hosts": [{"ports": [{"port": 80}]}, {"ports": [{"port": 6379}]}]}
    assert db.ports_spec_for(gt) == "23,80,6379"      # sorted, deduped


def test_detected_from_host_reads_open_ports_and_cves():
    # A fake scanner module: PortState enum + Port/Vuln stand-ins, so this needs no
    # backend/nmap import.
    class PortState:
        OPEN = "open"
        OPEN_FILTERED = "open|filtered"
        CLOSED = "closed"
    scanner_mod = SimpleNamespace(PortState=PortState)
    host = {
        "ports": [
            SimpleNamespace(port=80, service="http", version="Apache httpd 2.4.49",
                            state="open", vulns=[SimpleNamespace(id="CVE-2021-41773")]),
            SimpleNamespace(port=25, service="smtp", version="", state="closed", vulns=[]),  # closed → ignored
        ],
        "vulns": [SimpleNamespace(id="CVE-2017-0143")],
    }
    out = db.detected_from_host(host, scanner_mod)
    assert out["ports"] == {80: "http"}
    assert out["versions"] == {80: "Apache httpd 2.4.49"}
    assert out["cves"] == {"CVE-2021-41773", "CVE-2017-0143"}


def test_render_md_smoke():
    hosts = [db.score_host({"ports": {80: "http"}, "cves": {"CVE-2021-41773", "CVE-2021-42013"}}, _gt_host())]
    result = {"subnet": "172.28.0.0/24", "timestamp": "2026-07-08 00:00:00",
              "profile": "vuln", "ports": "80,443", "hosts": hosts, "summary": db.aggregate(hosts)}
    md = db.render_md(result)
    assert "Detection benchmark" in md and "Open ports" in md and "web-apache" in md


def test_ground_truth_file_is_valid_and_consistent():
    # The checked-in ground truth must parse and be internally consistent, or the
    # operator-run benchmark would score against a broken reference.
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ground_truth.json")
    with open(path, encoding="utf-8") as fh:
        gt = json.load(fh)
    assert gt["subnet"] == "172.28.0.0/24"
    ips = [h["ip"] for h in gt["hosts"]]
    assert len(ips) == len(set(ips)) >= 9              # distinct, diverse testbed hosts
    for h in gt["hosts"]:
        assert h["ports"] and all("port" in p and "service" in p for p in h["ports"])
    # device diversity: web, ssh, key-value store, a relational DB, a second RDBMS
    # and a document store are present.
    services = {p["service"] for h in gt["hosts"] for p in h["ports"]}
    assert {"http", "ssh", "redis", "postgresql", "mysql", "mongodb"} <= services
    # both Apache builds carry an expected version token so version-scoring runs and
    # the 2.4.49-vs-2.4.50 distinction (which the CVE match hinges on) is exercised.
    versions = [p.get("version") for h in gt["hosts"] for p in h["ports"] if p.get("version")]
    assert {"2.4.49", "2.4.50"} <= set(versions)
    # two independent hosts carry planted, documented CVEs (recall is measurable, not
    # anecdotal): 2.4.49 → CVE-2021-41773 and 2.4.50 → CVE-2021-42013.
    planted_hosts = [h for h in gt["hosts"] if h.get("planted_cves")]
    assert len(planted_hosts) >= 2
    all_planted = {c for h in planted_hosts for c in h["planted_cves"]}
    assert {"CVE-2021-41773", "CVE-2021-42013"} <= all_planted
    # a service on a non-standard port (redis off 6379) exercises banner-not-port ID.
    nonstd = [p for h in gt["hosts"] for p in h["ports"]
              if p["service"] == "redis" and p["port"] != 6379]
    assert nonstd, "expected a redis on a non-standard port"
