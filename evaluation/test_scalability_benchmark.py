"""
test_scalability_benchmark.py — the scaling analysis math (no network, no nmap).
Locks CIDR sizing, the least-squares fit (slope / R²) and throughput, so the
published "does it scale?" curve is trustworthy and CI-checked.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scalability_benchmark as sb  # noqa: E402


# --- cidr_size ------------------------------------------------------------- #
def test_cidr_size_of_slash24_is_256():
    assert sb.cidr_size("10.0.0.0/24") == 256


def test_cidr_size_of_single_ip_is_one():
    assert sb.cidr_size("192.168.0.10") == 1
    assert sb.cidr_size("10.0.0.0/32") == 1


def test_cidr_size_of_comma_list_sums():
    assert sb.cidr_size("10.0.0.0/24,10.0.1.0/25") == 256 + 128


def test_cidr_size_of_bad_target_counts_as_one():
    assert sb.cidr_size("not-an-ip") == 1


# --- linear_fit ------------------------------------------------------------ #
def test_linear_fit_perfect_line():
    # seconds = 0.01 * size + 2  → slope 0.01, intercept 2, R² 1.0
    sizes = [256, 512, 1024]
    secs = [0.01 * s + 2 for s in sizes]
    fit = sb.linear_fit(sizes, secs)
    assert abs(fit["slope"] - 0.01) < 1e-9
    assert abs(fit["intercept"] - 2.0) < 1e-9
    assert abs(fit["r2"] - 1.0) < 1e-9


def test_linear_fit_needs_two_distinct_x():
    assert sb.linear_fit([256], [3.0])["slope"] is None          # one point
    assert sb.linear_fit([256, 256], [3.0, 4.0])["slope"] is None  # same x


def test_linear_fit_noisy_data_has_r2_below_one():
    fit = sb.linear_fit([1, 2, 3, 4], [1.0, 2.1, 2.9, 3.8])
    assert fit["slope"] is not None and 0.0 < fit["r2"] < 1.0


# --- throughput ------------------------------------------------------------ #
def test_throughput_mean_addresses_per_second():
    # 256 addr in 2s = 128/s; 512 in 4s = 128/s → mean 128
    assert sb.throughput([256, 512], [2.0, 4.0]) == 128.0


def test_throughput_skips_zero_time_samples():
    assert sb.throughput([256, 512], [0.0, 4.0]) == 128.0


def test_throughput_all_zero_time_is_none():
    assert sb.throughput([256], [0.0]) is None


# --- analyze --------------------------------------------------------------- #
def test_analyze_uses_mean_time_and_skips_errors():
    points = [
        {"target": "10.0.0.0/26", "size": 64, "seconds": [1.0, 1.2], "hosts": 5, "rss": [1000, 1100]},
        {"target": "10.0.0.0/25", "size": 128, "seconds": [2.0, 2.2], "hosts": 9, "rss": []},
        {"target": "10.0.0.0/24", "size": 256, "error": "scan failed"},   # skipped
    ]
    a = sb.analyze(points)
    assert a["targets"] == 2
    assert a["fit"]["slope"] is not None                 # 2 distinct sizes → a line
    assert a["throughput_addr_per_s"] is not None
    # rss present on the first point, absent (None) on the second
    assert a["points"][0]["peak_rss_kb"] is not None
    assert a["points"][1]["peak_rss_kb"] is None


def test_analyze_empty_is_safe():
    a = sb.analyze([])
    assert a["targets"] == 0 and a["fit"]["slope"] is None


# --- rendering ------------------------------------------------------------- #
def test_render_md_smoke():
    result = {
        "timestamp": "t", "repeat": 3,
        "points": [{"target": "10.0.0.0/25", "size": 128, "seconds": [2.0, 2.2],
                    "hosts": 9, "rss": []}],
        "analysis": None,
    }
    result["analysis"] = sb.analyze(result["points"])
    md = sb.render_md(result)
    assert "Discovery scalability" in md and "Throughput" in md
    assert "10.0.0.0/25" in md


def test_render_md_surfaces_errored_target():
    result = {"timestamp": "t", "repeat": 1,
              "points": [{"target": "10.0.0.0/24", "size": 256, "error": "boom"}],
              "analysis": {"targets": 0, "fit": {"slope": None, "intercept": None, "r2": None},
                           "throughput_addr_per_s": None, "points": []}}
    md = sb.render_md(result)
    assert "_error_" in md and "boom" in md
