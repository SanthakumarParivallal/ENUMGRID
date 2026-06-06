"""test_audit.py — the append-only audit trail."""

from __future__ import annotations

import audit


def test_record_and_tail_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "AUDIT_LOG", str(tmp_path / "audit.log"))
    audit.record("scan_complete", target="192.168.0.0/24", hosts_up=5, findings=2)
    audit.record("scan_refused", target="127.0.0.1", reason="loopback")
    entries = audit.tail(10)
    assert len(entries) == 2
    # newest first
    assert entries[0]["event"] == "scan_refused"
    assert entries[0]["reason"] == "loopback"
    assert entries[1]["event"] == "scan_complete"
    assert entries[1]["hosts_up"] == 5
    assert "ts" in entries[0]


def test_tail_missing_log_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "AUDIT_LOG", str(tmp_path / "nope.log"))
    assert audit.tail() == []


def test_record_never_raises_on_bad_path(monkeypatch):
    monkeypatch.setattr(audit, "AUDIT_LOG", "/this/path/does/not/exist/audit.log")
    audit.record("scan_complete", target="x")  # must not raise
