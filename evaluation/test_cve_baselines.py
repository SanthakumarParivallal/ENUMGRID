"""
test_cve_baselines.py — the CVE-baseline harness's parsers + comparison math
(no Docker, no network, no nmap/nuclei). Locks how nmap-`vulners` text and Nuclei
JSON-lines are turned into CVE sets, and how per-tool planted-CVE recall,
unexpected sets, and pairwise agreement are computed — so the published
"EnumGrid vs nmap-vulners vs Nuclei" comparison is trustworthy and CI-checked.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cve_baselines as cb  # noqa: E402

# --- parse_cve_ids / nmap-vulners ------------------------------------------ #
# A representative slice of real `nmap --script vulners` output (formatting the
# NSE prints CVE ids in): a table of ids with CVSS scores under the port line.
_NMAP_VULNERS = """
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.49 ((Unix))
| vulners:
|   cpe:/a:apache:http_server:2.4.49:
|       CVE-2021-41773   7.5   https://vulners.com/cve/CVE-2021-41773
|       CVE-2021-42013   9.8   https://vulners.com/cve/CVE-2021-42013
|_      CVE-2021-40438   9.0   https://vulners.com/cve/CVE-2021-40438
"""


def test_parse_cve_ids_extracts_and_uppercases():
    got = cb.parse_cve_ids("found cve-2021-41773 and CVE-2021-42013 today")
    assert got == {"CVE-2021-41773", "CVE-2021-42013"}


def test_parse_cve_ids_empty_and_none_are_safe():
    assert cb.parse_cve_ids("") == set()
    assert cb.parse_cve_ids(None) == set()


def test_parse_nmap_vulners_reads_the_nse_table():
    got = cb.parse_nmap_vulners(_NMAP_VULNERS)
    assert got == {"CVE-2021-41773", "CVE-2021-42013", "CVE-2021-40438"}


def test_parse_nmap_vulners_no_cves_is_empty():
    assert cb.parse_nmap_vulners("80/tcp open http\n| http-title: hi\n") == set()


# --- parse_nuclei_jsonl ---------------------------------------------------- #
def test_parse_nuclei_jsonl_reads_classification_list():
    line = ('{"template-id":"apache-httpd-rce","info":{"name":"Apache RCE",'
            '"classification":{"cve-id":["CVE-2021-41773","CVE-2021-42013"]}}}')
    assert cb.parse_nuclei_jsonl([line]) == {"CVE-2021-41773", "CVE-2021-42013"}


def test_parse_nuclei_jsonl_reads_cve_template_id():
    line = '{"template-id":"CVE-2021-41773","info":{"name":"path traversal"}}'
    assert cb.parse_nuclei_jsonl([line]) == {"CVE-2021-41773"}


def test_parse_nuclei_jsonl_reads_string_classification():
    line = '{"info":{"classification":{"cve-id":"CVE-2018-7600"}}}'
    assert cb.parse_nuclei_jsonl([line]) == {"CVE-2018-7600"}


def test_parse_nuclei_jsonl_ignores_non_cve_and_blank_lines():
    lines = ['{"template-id":"exposed-git-config","info":{"name":"git"}}', "", "   "]
    assert cb.parse_nuclei_jsonl(lines) == set()


def test_parse_nuclei_jsonl_falls_back_to_regex_on_bad_json():
    # A schema change / truncated line must not silently zero the baseline.
    assert cb.parse_nuclei_jsonl(["not json but CVE-2021-44228 here"]) == {"CVE-2021-44228"}


def test_parse_nuclei_jsonl_multiple_findings_union():
    lines = [
        '{"template-id":"CVE-2021-41773"}',
        '{"info":{"classification":{"cve-id":["CVE-2021-42013"]}}}',
    ]
    assert cb.parse_nuclei_jsonl(lines) == {"CVE-2021-41773", "CVE-2021-42013"}


# --- comparison ------------------------------------------------------------ #
def test_compare_host_recall_and_unexpected_per_tool():
    planted = ["CVE-2021-41773", "CVE-2021-42013"]
    tool_cves = {
        "enumgrid": {"CVE-2021-41773", "CVE-2021-42013", "CVE-2021-40438"},  # full recall + extra
        "nmap-vulners": {"CVE-2021-41773"},                                   # half recall
        "nuclei": {"CVE-2021-41773", "CVE-2021-42013"},                       # full recall, no extra
    }
    r = cb.compare_host(planted, tool_cves)
    assert r["planted"] == ["CVE-2021-41773", "CVE-2021-42013"]
    assert r["tools"]["enumgrid"]["recall"] == 1.0
    assert r["tools"]["enumgrid"]["unexpected"] == ["CVE-2021-40438"]
    assert r["tools"]["nmap-vulners"]["recall"] == 0.5
    assert r["tools"]["nmap-vulners"]["missed"] == ["CVE-2021-42013"]
    assert r["tools"]["nuclei"]["recall"] == 1.0 and r["tools"]["nuclei"]["unexpected"] == []


def test_compare_host_is_case_insensitive():
    r = cb.compare_host(["CVE-2021-41773"], {"nuclei": {"cve-2021-41773"}})
    assert r["tools"]["nuclei"]["recall"] == 1.0


def test_compare_host_no_planted_recall_is_none_unexpected_surfaced():
    r = cb.compare_host([], {"nmap-vulners": {"CVE-2020-0001"}})
    assert r["tools"]["nmap-vulners"]["recall"] is None
    assert r["tools"]["nmap-vulners"]["unexpected"] == ["CVE-2020-0001"]


def test_agreement_matrix_jaccard():
    m = cb.agreement_matrix({
        "a": {"CVE-1", "CVE-2"},
        "b": {"CVE-1"},
    })
    assert m["a"]["a"] == 1.0 and m["b"]["b"] == 1.0
    assert m["a"]["b"] == 0.5 and m["b"]["a"] == 0.5


def test_agreement_matrix_two_empty_sets_is_identical():
    m = cb.agreement_matrix({"a": set(), "b": set()})
    assert m["a"]["b"] == 1.0


# --- aggregate ------------------------------------------------------------- #
def _host(ip, planted, tool_cves):
    r = cb.compare_host(planted, tool_cves)
    r.update({"ip": ip, "name": ip, "agreement": cb.agreement_matrix(tool_cves)})
    return r


def test_aggregate_pools_recall_across_hosts():
    hosts = [
        _host("h1", ["CVE-2021-41773", "CVE-2021-42013"],
              {"enumgrid": {"CVE-2021-41773", "CVE-2021-42013"},
               "nmap-vulners": {"CVE-2021-41773"}}),
        _host("h2", ["CVE-2021-42013"],
              {"enumgrid": {"CVE-2021-42013"},
               "nmap-vulners": set()}),
    ]
    agg = cb.aggregate(hosts)
    assert agg["hosts_scored"] == 2
    assert agg["tools"]["enumgrid"]["recall"] == 1.0          # 3/3 planted recalled
    assert agg["tools"]["nmap-vulners"]["recall"] == 1 / 3    # 1/3 planted recalled


def test_aggregate_skips_hosts_without_planted_cves():
    hosts = [_host("patched", [], {"enumgrid": {"CVE-2020-0001"}})]
    agg = cb.aggregate(hosts)
    assert agg["hosts_scored"] == 0 and agg["tools"] == {}


def test_aggregate_skips_errored_hosts():
    hosts = [
        {"ip": "h1", "error": "nmap: boom"},
        _host("h2", ["CVE-2021-42013"], {"enumgrid": {"CVE-2021-42013"}}),
    ]
    agg = cb.aggregate(hosts)
    assert agg["hosts_scored"] == 1 and agg["tools"]["enumgrid"]["recall"] == 1.0


# --- rendering ------------------------------------------------------------- #
def test_render_md_smoke():
    hosts = [_host("172.28.0.11", ["CVE-2021-41773", "CVE-2021-42013"],
                   {"enumgrid": {"CVE-2021-41773", "CVE-2021-42013"},
                    "nmap-vulners": {"CVE-2021-41773"}})]
    result = {"subnet": "172.28.0.0/24", "timestamp": "t", "ports": "80",
              "tools": ["enumgrid", "nmap-vulners"], "hosts": hosts,
              "summary": cb.aggregate(hosts)}
    md = cb.render_md(result)
    assert "CVE-detection baselines" in md
    assert "enumgrid" in md and "nmap-vulners" in md
    assert "Planted-CVE recall" in md


def test_render_md_surfaces_errored_host():
    result = {"subnet": "s", "timestamp": "t", "ports": "80", "tools": ["enumgrid"],
              "hosts": [{"ip": "172.28.0.12", "name": "ssh", "error": "nmap: timeout"}],
              "summary": {"hosts_scored": 0, "tools": {}}}
    md = cb.render_md(result)
    assert "_error_" in md and "timeout" in md


# --- the nuclei target builder (pure) -------------------------------------- #
def test_nuclei_targets_builds_urls_for_web_ports_plus_bare_ip():
    ports = [{"port": 80, "service": "http"}, {"port": 6379, "service": "redis"}]
    targets = cb._nuclei_targets("172.28.0.11", ports)
    assert "172.28.0.11" in targets
    assert "http://172.28.0.11:80" in targets
    assert not any("6379" in t for t in targets)     # non-web port → no URL
