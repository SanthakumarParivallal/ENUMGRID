"""test_notify.py — outbound alert summary + sink fan-out (network mocked)."""

from __future__ import annotations

import notify


def test_summarize_counts_findings_and_kev():
    snap = {
        "target": "192.168.0.0/24",
        "hosts": [
            {"status": "up", "ports": [
                {"vulns": [{"id": "CVE-1", "kev": True}, {"id": "CVE-2"}]},
            ], "vulns": [{"id": "CVE-3", "kev": True}]},
            {"status": "down"},
        ],
    }
    s = notify.summarize(snap)
    assert s["hosts"] == 2 and s["hosts_up"] == 1
    assert s["findings"] == 3
    assert s["kev"] == 2


def test_not_configured_is_noop(monkeypatch):
    monkeypatch.setattr(notify, "WEBHOOK_URL", None)
    monkeypatch.setattr(notify, "SLACK_WEBHOOK", None)
    monkeypatch.setattr(notify, "SYSLOG", None)
    assert notify.configured() is False
    # Should send nothing / not raise even if _post_json would explode.
    monkeypatch.setattr(notify, "_post_json", lambda *a: (_ for _ in ()).throw(AssertionError("no send")))
    notify.scan_complete({"target": "x", "hosts_up": 1, "findings": 0, "kev": 0})


def test_webhook_receives_payload(monkeypatch):
    sent = {}
    monkeypatch.setattr(notify, "WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setattr(notify, "SLACK_WEBHOOK", None)
    monkeypatch.setattr(notify, "SYSLOG", None)
    monkeypatch.setattr(notify, "_post_json", lambda url, payload: sent.update(url=url, payload=payload))
    notify.scan_complete({"target": "10.0.0.0/24", "hosts_up": 3, "findings": 4, "kev": 1})
    assert sent["url"] == "https://example.com/hook"
    assert sent["payload"]["type"] == "scan_complete"
    assert sent["payload"]["kev"] == 1


def test_slack_text_mentions_kev():
    txt = notify._slack_text({"target": "x", "hosts_up": 2, "findings": 5, "kev": 1})
    assert "KEV" in txt and "x" in txt


def test_post_json_refuses_non_http(monkeypatch):
    # A non-http(s) URL must never be opened (SSRF/scheme guard).
    called = {"opened": False}

    def fake_urlopen(*a, **k):
        called["opened"] = True
        raise AssertionError("should not open")

    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    notify._post_json("file:///etc/passwd", {"x": 1})
    assert called["opened"] is False
