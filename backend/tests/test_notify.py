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


def test_post_json_opens_an_http_url(monkeypatch):
    opened = {}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_urlopen(req, timeout=None):
        opened["url"] = req.full_url
        return _Resp()

    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    notify._post_json("https://example.com/hook", {"a": 1})
    assert opened["url"] == "https://example.com/hook"


class _FakeSock:
    def __init__(self, sink): self._sink = sink
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def settimeout(self, t): self._sink["timeout"] = t
    def sendto(self, packet, addr): self._sink["packet"], self._sink["addr"] = packet, addr


def test_send_syslog_emits_a_pri_prefixed_packet(monkeypatch):
    sink = {}
    monkeypatch.setattr(notify, "SYSLOG", "127.0.0.1:5514")
    monkeypatch.setattr(notify.socket, "socket", lambda *a, **k: _FakeSock(sink))
    notify._send_syslog("hello world")
    assert sink["addr"] == ("127.0.0.1", 5514)
    assert sink["packet"].startswith(b"<12>EnumGrid: hello world")


def test_send_syslog_ignores_a_malformed_target(monkeypatch):
    monkeypatch.setattr(notify, "SYSLOG", "host:not-a-port")

    def _no_socket(*a, **k):
        raise AssertionError("must not open a socket for a malformed SYSLOG target")

    monkeypatch.setattr(notify.socket, "socket", _no_socket)
    notify._send_syslog("x")            # int('not-a-port') → ValueError → early return


def test_send_syslog_swallows_socket_errors(monkeypatch):
    class _BoomSock:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def settimeout(self, t): pass
        def sendto(self, *a): raise OSError("no route")

    monkeypatch.setattr(notify, "SYSLOG", "127.0.0.1:514")
    monkeypatch.setattr(notify.socket, "socket", lambda *a, **k: _BoomSock())
    notify._send_syslog("x")            # OSError swallowed, never raised


def test_scan_complete_fans_out_to_all_sinks(monkeypatch):
    calls = {"post": [], "syslog": 0}
    monkeypatch.setattr(notify, "WEBHOOK_URL", "https://hook")
    monkeypatch.setattr(notify, "SLACK_WEBHOOK", "https://slack")
    monkeypatch.setattr(notify, "SYSLOG", "127.0.0.1:514")
    monkeypatch.setattr(notify, "_post_json", lambda url, payload: calls["post"].append(url))
    monkeypatch.setattr(notify, "_send_syslog", lambda msg: calls.__setitem__("syslog", calls["syslog"] + 1))
    notify.scan_complete({"target": "x", "hosts_up": 1, "findings": 2, "kev": 1})
    assert calls["post"] == ["https://hook", "https://slack"]   # webhook + slack both fired
    assert calls["syslog"] == 1                                 # + syslog


def test_scan_complete_swallows_sink_errors(monkeypatch):
    monkeypatch.setattr(notify, "WEBHOOK_URL", "https://hook")
    monkeypatch.setattr(notify, "SLACK_WEBHOOK", "https://slack")
    monkeypatch.setattr(notify, "SYSLOG", None)

    def _boom(*a):
        raise OSError("network down")

    monkeypatch.setattr(notify, "_post_json", _boom)
    notify.scan_complete({"target": "x", "hosts_up": 0, "findings": 0, "kev": 0})  # must not raise
