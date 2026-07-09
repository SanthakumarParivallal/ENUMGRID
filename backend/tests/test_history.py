"""
test_history.py — SQLite persistence + drift computation.

Uses a throwaway DB per test (monkeypatched `history.DB_PATH`) so nothing
touches the real history file and the tests stay deterministic and offline.
"""

from __future__ import annotations

import history
import pytest


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Point the history module at a temp DB for the duration of a test."""
    path = tmp_path / "h.db"
    monkeypatch.setattr(history, "DB_PATH", str(path))
    history.init_db()
    return path


def _snap(target, hosts, finished_at=1000.0):
    return {
        "scan_id": "t",
        "target": target,
        "phase": "Complete",
        "started_at": finished_at - 10,
        "finished_at": finished_at,
        "hosts": hosts,
    }


def _host(ip, status="up", ports=None, vendor=None):
    return {
        "ip": ip,
        "status": status,
        "vendor": vendor,
        "hostname": None,
        "mac": None,
        "os": "Unknown",
        "ports": ports or [],
    }


def test_save_and_list(db):
    rid = history.save_scan(_snap("192.168.0.0/24", [_host("192.168.0.1"), _host("192.168.0.2")]))
    assert rid > 0
    scans = history.list_scans("192.168.0.0/24")
    assert len(scans) == 1
    row = scans[0]
    assert row["target"] == "192.168.0.0/24"
    assert row["host_count"] == 2
    assert row["up_count"] == 2


def test_open_port_counting(db):
    hosts = [
        _host("10.0.0.1", ports=[{"port": 80, "state": "open"}, {"port": 22, "state": "closed"}]),
        _host("10.0.0.2", ports=[{"port": 443, "state": "open|filtered"}]),
    ]
    history.save_scan(_snap("10.0.0.0/24", hosts))
    assert history.list_scans("10.0.0.0/24")[0]["open_ports"] == 2


def test_list_is_newest_first_and_filtered(db):
    history.save_scan(_snap("a/24", [_host("1.1.1.1")], finished_at=100))
    history.save_scan(_snap("b/24", [_host("2.2.2.2")], finished_at=200))
    history.save_scan(_snap("a/24", [_host("1.1.1.1")], finished_at=300))
    a_scans = history.list_scans("a/24")
    assert len(a_scans) == 2
    assert a_scans[0]["finished_at"] == 300  # newest first
    assert {s["target"] for s in history.list_scans()} == {"a/24", "b/24"}


def test_get_scan_parses_snapshot(db):
    rid = history.save_scan(_snap("net/24", [_host("9.9.9.9")]))
    got = history.get_scan(rid)
    assert got is not None
    assert isinstance(got["snapshot"], dict)
    assert got["snapshot"]["hosts"][0]["ip"] == "9.9.9.9"
    assert history.get_scan(999999) is None


# --- drift ---------------------------------------------------------------- #
def test_drift_unavailable_until_two_scans(db):
    history.save_scan(_snap("net/24", [_host("192.168.0.1")]))
    d = history.drift_for_target("net/24")
    assert d["available"] is False
    assert d["scan_count"] == 1


def test_drift_detects_new_and_gone_devices(db):
    history.save_scan(_snap("net/24", [_host("192.168.0.1", vendor="RouterCo"),
                                       _host("192.168.0.5", vendor="OldPhone")], finished_at=100))
    history.save_scan(_snap("net/24", [_host("192.168.0.1", vendor="RouterCo"),
                                       _host("192.168.0.9", vendor="NewLaptop")], finished_at=200))
    d = history.drift_for_target("net/24")
    assert d["available"] is True
    assert d["has_changes"] is True
    appeared = {h["ip"]: h for h in d["appeared_hosts"]}
    disappeared = {h["ip"]: h for h in d["disappeared_hosts"]}
    assert "192.168.0.9" in appeared
    assert appeared["192.168.0.9"]["vendor"] == "NewLaptop"  # enriched
    assert "192.168.0.5" in disappeared


def test_drift_detects_opened_ports(db):
    history.save_scan(_snap("net/24", [_host("10.0.0.1", ports=[{"port": 22, "state": "open", "service": "ssh"}])], finished_at=100))
    history.save_scan(_snap("net/24", [_host("10.0.0.1", ports=[
        {"port": 22, "state": "open", "service": "ssh"},
        {"port": 80, "state": "open", "service": "http"},
    ])], finished_at=200))
    d = history.drift_for_target("net/24")
    assert d["has_changes"] is True
    changed = {c["ip"]: c for c in d["changed_hosts"]}
    assert 80 in changed["10.0.0.1"]["opened_ports"]


def test_drift_no_changes_when_identical(db):
    hosts = [_host("10.0.0.1", ports=[{"port": 22, "state": "open", "service": "ssh"}])]
    history.save_scan(_snap("net/24", hosts, finished_at=100))
    history.save_scan(_snap("net/24", hosts, finished_at=200))
    d = history.drift_for_target("net/24")
    assert d["available"] is True
    assert d["has_changes"] is False


def test_ensure_on_path_inserts_once():
    path = ["/existing"]
    history._ensure_on_path("/root", path)
    assert path == ["/root", "/existing"]         # inserted at the front
    history._ensure_on_path("/root", path)        # already present
    assert path == ["/root", "/existing"]         # → no duplicate


def test_get_scan_tolerates_corrupt_snapshot_json(db):
    # A row whose snapshot column isn't valid JSON degrades to {} rather than raising.
    history.save_scan(_snap("10.0.0.0/24", [_host("10.0.0.1")]))
    with history._connect() as conn:
        conn.execute("UPDATE scans SET snapshot = ? WHERE id = 1", ("not-json",))
    row = history.get_scan(1)
    assert row is not None and row["snapshot"] == {}
