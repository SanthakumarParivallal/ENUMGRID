"""
test_aggregate_runs.py — the cross-environment pooling math (no network, no files).
Locks how benchmark.py results (both the single-run and multi-run JSON shapes) are
normalised and macro-averaged across environments, so the pooled "recall across N
networks" figure is trustworthy and CI-checked.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aggregate_runs as ar  # noqa: E402


def _summ(mean, n=5, ci=0.0):
    return {"n": n, "mean": mean, "stdev": 0.0, "ci95": ci, "min": mean, "max": mean}


def _multirun_payload(target, enumgrid_recall, nmap_recall):
    return {
        "target": target,
        "multirun": {
            "reference": "union (proxy)",
            "reference_count": 10,
            "tools": {
                "enumgrid": {"available": True, "runs": 5, "hosts": _summ(10),
                             "recall": _summ(enumgrid_recall), "precision": _summ(1.0),
                             "time": _summ(18.0)},
                "nmap-sn": {"available": True, "runs": 5, "hosts": _summ(3),
                            "recall": _summ(nmap_recall), "precision": _summ(1.0),
                            "time": _summ(22.0)},
            },
        },
    }


# --- normalisation --------------------------------------------------------- #
def test_normalize_multirun_shape():
    norm = ar.normalize_result(_multirun_payload("10.0.0.0/24", 1.0, 0.3))
    assert norm["target"] == "10.0.0.0/24"
    assert norm["tools"]["enumgrid"]["recall"] == 1.0
    assert norm["tools"]["nmap-sn"]["recall"] == 0.3
    assert norm["tools"]["enumgrid"]["runs"] == 5


def test_normalize_multirun_skips_unavailable_tool():
    payload = _multirun_payload("10.0.0.0/24", 1.0, 0.3)
    payload["multirun"]["tools"]["masscan"] = {"available": False, "runs": 0}
    norm = ar.normalize_result(payload)
    assert "masscan" not in norm["tools"]


def test_normalize_single_run_shape():
    payload = {
        "target": "192.168.0.0/24",
        "enumgrid_seconds": 17.8,
        "nmap_seconds": 22.9,
        "comparison": {
            "reference": "union (proxy)",
            "enumgrid_count": 11, "nmap_count": 3,
            "enumgrid_metrics": {"precision": 1.0, "recall": 1.0, "f1": 1.0},
            "nmap_metrics": {"precision": 1.0, "recall": 0.27, "f1": 0.43},
        },
    }
    norm = ar.normalize_result(payload)
    assert norm["tools"]["enumgrid"]["recall"] == 1.0
    assert norm["tools"]["enumgrid"]["time"] == 17.8
    assert norm["tools"]["nmap-sn"]["recall"] == 0.27
    assert norm["tools"]["nmap-sn"]["hosts"] == 3


def test_normalize_unknown_shape_is_empty():
    assert ar.normalize_result({"target": "x"})["tools"] == {}


# --- pooling --------------------------------------------------------------- #
def test_pool_macro_averages_across_environments():
    envs = [
        ar.normalize_result(_multirun_payload("home/24", 1.0, 0.30)),
        ar.normalize_result(_multirun_payload("office/24", 0.90, 0.10)),
        ar.normalize_result(_multirun_payload("iot/24", 0.98, 0.05)),
    ]
    pooled = ar.pool(envs)
    assert pooled["n_environments"] == 3
    eg = pooled["tools"]["enumgrid"]
    assert eg["n_envs"] == 3
    # mean recall over the three environment means = (1.0 + 0.90 + 0.98)/3
    assert abs(eg["recall"]["mean"] - (1.0 + 0.90 + 0.98) / 3) < 1e-9
    assert eg["recall"]["ci95"] > 0                       # variance across envs is reported
    assert pooled["tools"]["nmap-sn"]["recall"]["mean"] < eg["recall"]["mean"]


def test_pool_records_per_environment_recall():
    envs = [
        ar.normalize_result(_multirun_payload("home/24", 1.0, 0.30)),
        ar.normalize_result(_multirun_payload("office/24", 0.90, 0.10)),
    ]
    pooled = ar.pool(envs)
    per_env = pooled["tools"]["enumgrid"]["per_env_recall"]
    assert per_env == {"home/24": 1.0, "office/24": 0.90}


def test_pool_counts_only_environments_where_tool_ran():
    a = ar.normalize_result(_multirun_payload("net-a", 1.0, 0.3))
    b = ar.normalize_result(_multirun_payload("net-b", 0.8, 0.2))
    del b["tools"]["nmap-sn"]                              # nmap absent in net-b
    pooled = ar.pool([a, b])
    assert pooled["tools"]["enumgrid"]["n_envs"] == 2
    assert pooled["tools"]["nmap-sn"]["n_envs"] == 1


def test_pool_empty_is_safe():
    pooled = ar.pool([])
    assert pooled["n_environments"] == 0 and pooled["tools"] == {}


# --- rendering ------------------------------------------------------------- #
def test_render_md_smoke():
    envs = [ar.normalize_result(_multirun_payload("home/24", 1.0, 0.30)),
            ar.normalize_result(_multirun_payload("office/24", 0.90, 0.10))]
    md = ar.render_md(ar.pool(envs), "2026-07-10 00:00:00")
    assert "Cross-environment discovery" in md
    assert "EnumGrid" in md and "nmap -sn" in md
    assert "home/24" in md and "office/24" in md
