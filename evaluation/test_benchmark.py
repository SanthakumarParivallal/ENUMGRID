"""
test_benchmark.py — the benchmark's metric math (no network).

Verifies the parsing and precision/recall/Jaccard computation so the published
numbers are trustworthy and reproducible.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import benchmark as bm  # noqa: E402


def test_ips_from_nmap_parses_reports():
    text = (
        "Starting Nmap 7.99\n"
        "Nmap scan report for 192.168.0.1\n"
        "Host is up (0.01s latency).\n"
        "Nmap scan report for router.lan (192.168.0.254)\n"
        "Host is up.\n"
        "Nmap done: 256 IP addresses (2 hosts up)\n"
    )
    assert bm._ips_from_nmap(text) == {"192.168.0.1", "192.168.0.254"}


def test_prf_perfect():
    m = bm._prf({"a", "b"}, {"a", "b"})
    assert m == {"precision": 1.0, "recall": 1.0, "f1": 1.0}


def test_prf_partial_recall():
    # Found 2 of 4 true hosts, no false positives.
    m = bm._prf({"a", "b"}, {"a", "b", "c", "d"})
    assert m["precision"] == 1.0
    assert m["recall"] == 0.5
    assert round(m["f1"], 3) == round(2 * 1.0 * 0.5 / 1.5, 3)


def test_prf_empty_is_zero_not_crash():
    assert bm._prf(set(), set()) == {"precision": 0.0, "recall": 0.0, "f1": 0.0}


def test_compare_union_proxy_and_uniques():
    pr_hosts = {"a", "b", "c"}
    nmap_hosts = {"a"}
    c = bm.compare(pr_hosts, nmap_hosts, truth=None)
    assert c["reference"] == "union (proxy)"
    assert c["reference_count"] == 3
    assert c["agreement_count"] == 1
    assert c["enumgrid_only"] == ["b", "c"]
    assert c["nmap_only"] == []
    assert round(c["jaccard"], 3) == round(1 / 3, 3)
    # Against the union proxy EnumGrid has full recall, nmap 1/3.
    assert c["enumgrid_metrics"]["recall"] == 1.0
    assert round(c["nmap_metrics"]["recall"], 3) == round(1 / 3, 3)


def test_compare_with_explicit_ground_truth():
    c = bm.compare({"a", "b"}, {"a"}, truth={"a", "b", "c"})
    assert c["reference"] == "explicit ground-truth"
    assert c["reference_count"] == 3
    assert round(c["enumgrid_metrics"]["recall"], 3) == round(2 / 3, 3)


def test_render_md_is_a_table():
    c = bm.compare({"a", "b"}, {"a"}, truth=None)
    md = bm.render_md({
        "target": "10.0.0.0/24", "timestamp": "now",
        "enumgrid_seconds": 1.0, "nmap_seconds": 2.0, "comparison": c,
    })
    assert "| **EnumGrid** |" in md
    assert "`nmap -sn`" in md


def test_nmap_sn_cmd_privileged_prefixes_sudo():
    assert bm._nmap_sn_cmd("10.0.0.0/24") == ["nmap", "-sn", "-T4", "10.0.0.0/24"]
    assert bm._nmap_sn_cmd("10.0.0.0/24", privileged=True) == [
        "sudo", "nmap", "-sn", "-T4", "10.0.0.0/24",
    ]


def test_privileged_summary_reports_a_tie_when_sets_match():
    pr = priv = {"a", "b", "c"}
    s = bm.privileged_summary(pr, priv, pr | priv)
    assert s["count"] == 3
    assert s["jaccard_vs_enumgrid"] == 1.0
    assert s["enumgrid_only"] == []
    assert s["privileged_only"] == []
    assert s["metrics"]["recall"] == 1.0


def test_privileged_summary_reports_divergence():
    s = bm.privileged_summary({"a", "b"}, {"a", "c"}, {"a", "b", "c"})
    assert s["enumgrid_only"] == ["b"]
    assert s["privileged_only"] == ["c"]
    assert round(s["jaccard_vs_enumgrid"], 3) == round(1 / 3, 3)


def test_render_privileged_md_calls_out_the_no_privilege_win_on_a_tie():
    s = bm.privileged_summary({"a", "b"}, {"a", "b"}, {"a", "b"})
    md = bm.render_privileged_md(1.5, s)
    assert "Privileged baseline" in md
    assert "without" in md.lower()  # the "same coverage without privilege" point


def test_render_privileged_md_flags_a_failed_privileged_scan_instead_of_a_fake_tie():
    # EnumGrid found hosts but `sudo nmap -sn` returned nothing (denied / no nmap):
    # this must NOT be reported as an agreement ("tie") win.
    s = bm.privileged_summary({"a", "b"}, set(), {"a", "b"})
    md = bm.render_privileged_md(0.1, s)
    assert "no hosts" in md.lower()
    assert "without" not in md.lower()  # must not claim the no-privilege coverage win
