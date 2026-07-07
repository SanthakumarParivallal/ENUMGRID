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


# --------------------------------------------------------------------------- #
# Multi-run statistics + baseline parsers (the publication-grade path).
# --------------------------------------------------------------------------- #
def test_summarize_two_values_mean_stdev_ci():
    import math
    s = bm.summarize([2.0, 4.0])
    assert s["n"] == 2
    assert s["mean"] == 3.0
    assert round(s["stdev"], 6) == round(math.sqrt(2), 6)  # sample stdev of {2,4}
    assert round(s["ci95"], 6) == round(1.96 * math.sqrt(2) / math.sqrt(2), 6)
    assert s["min"] == 2.0 and s["max"] == 4.0


def test_summarize_single_value_has_zero_spread():
    s = bm.summarize([5.0])
    assert s == {"n": 1, "mean": 5.0, "stdev": 0.0, "ci95": 0.0, "min": 5.0, "max": 5.0}


def test_summarize_empty_is_zero_not_crash():
    s = bm.summarize([])
    assert s["n"] == 0 and s["mean"] == 0.0 and s["ci95"] == 0.0


def test_ips_with_mac_parses_arpscan_output():
    text = (
        "Interface: en0, type: EN10MB, MAC: aa:aa:aa:aa:aa:aa\n"
        "Starting arp-scan 1.10\n"
        "192.168.0.1\t00:11:22:33:44:55\tNetgear\n"
        "192.168.0.42   de:ad:be:ef:00:01   Apple, Inc.\n"
        "\n"
        "5 packets received by filter, 0 packets dropped\n"
    )
    assert bm._ips_with_mac(text) == {"192.168.0.1", "192.168.0.42"}


def test_ips_with_mac_parses_netdiscover_output():
    text = (
        "192.168.1.1     00:11:22:33:44:55      3      180  Netgear\n"
        "192.168.1.7     aa:bb:cc:dd:ee:ff      1       60  Apple\n"
    )
    assert bm._ips_with_mac(text) == {"192.168.1.1", "192.168.1.7"}


def test_ips_from_masscan_list_format():
    text = (
        "#masscan\n"
        "open icmp 0 192.168.0.1 1720000000\n"
        "open icmp 0 192.168.0.9 1720000001\n"
        "# end\n"
    )
    assert bm._ips_from_masscan(text) == {"192.168.0.1", "192.168.0.9"}


def test_baseline_cmd_builders_and_sudo_prefix():
    assert bm._arp_scan_cmd("10.0.0.0/24") == ["arp-scan", "10.0.0.0/24"]
    assert bm._arp_scan_cmd("10.0.0.0/24", privileged=True)[0] == "sudo"
    assert bm._netdiscover_cmd("10.0.0.0/24") == ["netdiscover", "-P", "-N", "-r", "10.0.0.0/24"]
    assert bm._masscan_cmd("10.0.0.0/24") == ["masscan", "10.0.0.0/24", "--ping", "-oL", "-"]


def test_run_baseline_reports_none_when_tool_missing(monkeypatch):
    monkeypatch.setattr(bm.shutil, "which", lambda _name: None)
    hosts, secs = bm.run_baseline("arp-scan", "10.0.0.0/24")
    assert hosts is None and secs == 0.0  # None => "unavailable", not "found nothing"


def test_aggregate_tool_recall_across_runs():
    # Two runs: first finds {a,b}, second finds {a,b,c}; reference {a,b,c,d}.
    ref = {"a", "b", "c", "d"}
    agg = bm.aggregate_tool([{"a", "b"}, {"a", "b", "c"}], [1.0, 2.0], ref)
    assert agg["available"] is True
    assert agg["runs"] == 2
    assert round(agg["recall"]["mean"], 3) == round((0.5 + 0.75) / 2, 3)
    assert agg["time"]["mean"] == 1.5
    assert agg["union_found"] == ["a", "b", "c"]


def test_multi_run_marks_missing_baseline_unavailable(monkeypatch):
    # enumgrid finds hosts; the baseline binary is absent.
    monkeypatch.setattr(bm, "run_enumgrid", lambda _t: ({"192.168.0.1"}, 1.0))
    monkeypatch.setattr(bm, "run_baseline", lambda *_a, **_k: (None, 0.0))
    res = bm.multi_run("10.0.0.0/24", ["enumgrid", "arp-scan"], runs=2)
    assert res["tools"]["enumgrid"]["available"] is True
    assert res["tools"]["enumgrid"]["runs"] == 2
    assert res["tools"]["arp-scan"]["available"] is False
    assert res["reference_count"] == 1  # only enumgrid's find seeds the union


def test_render_multirun_md_table_and_unavailable_row():
    res = {
        "reference": "union (proxy)", "reference_count": 3,
        "tools": {
            "enumgrid": bm.aggregate_tool([{"a", "b", "c"}], [1.0], {"a", "b", "c"}),
            "arp-scan": {"available": False, "runs": 0},
        },
    }
    md = bm.render_multirun_md("10.0.0.0/24", "now", res, runs=1)
    assert "Multi-run benchmark" in md
    assert "mean ± 95 % CI" in md
    assert "| EnumGrid |" in md
    assert "not installed" in md  # the unavailable baseline is shown honestly
