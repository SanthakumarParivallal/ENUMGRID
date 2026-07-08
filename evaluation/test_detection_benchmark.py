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


# --- host + aggregate ------------------------------------------------------ #
def _gt_host():
    return {"ip": "172.28.0.11", "name": "web-apache",
            "ports": [{"port": 80, "service": "http"}],
            "planted_cves": ["CVE-2021-41773", "CVE-2021-42013"]}


def test_score_host_combines_all_axes():
    detected = {"ports": {80: "http"}, "cves": {"CVE-2021-41773", "CVE-2021-42013"}}
    h = db.score_host(detected, _gt_host())
    assert h["ports"]["f1"] == 1.0
    assert h["services"]["accuracy"] == 1.0
    assert h["cves"]["recall"] == 1.0


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
            SimpleNamespace(port=80, service="http", state="open",
                            vulns=[SimpleNamespace(id="CVE-2021-41773")]),
            SimpleNamespace(port=25, service="smtp", state="closed", vulns=[]),  # closed → ignored
        ],
        "vulns": [SimpleNamespace(id="CVE-2017-0143")],
    }
    out = db.detected_from_host(host, scanner_mod)
    assert out["ports"] == {80: "http"}
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
    assert len(ips) == len(set(ips)) == 4              # four distinct testbed hosts
    for h in gt["hosts"]:
        assert h["ports"] and all("port" in p and "service" in p for p in h["ports"])
