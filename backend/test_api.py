"""
test_api.py — FastAPI endpoint integration tests (TestClient, no real scans).

These drive the actual ASGI app end-to-end: routing, the auth/scope guardrails,
SSE error frames, the PDF endpoint and the history API. Every scan endpoint is
exercised with a *rejected* target (loopback / public / injection) so no test
ever touches the network or nmap — the rejection happens before any scan starts.
"""

from __future__ import annotations

import json

import history
import pytest
import security
from app import app
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture(autouse=True)
def _temp_history(tmp_path, monkeypatch):
    """Isolate every test from the real history DB."""
    monkeypatch.setattr(history, "DB_PATH", str(tmp_path / "h.db"))
    history.init_db()


def _sse_frame(resp_text: str) -> dict:
    line = next(li for li in resp_text.splitlines() if li.startswith("data:"))
    return json.loads(line[len("data:"):].strip())


# --- health / network ------------------------------------------------------ #
def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "max_concurrent_scans" in body and "allow_public" in body
    # privilege auto-adaptation surface
    assert body["capability"] in ("root", "sudo", "unprivileged")
    assert "can_raw" in body


# --- NVD API key: status + runtime set (user-friendly settings) ------------ #
def test_nvd_settings_status():
    r = client.get("/api/settings/nvd")
    assert r.status_code == 200
    body = r.json()
    assert "key_active" in body and "rate_limit" in body
    assert body["get_key_url"].startswith("https://")
    assert "ENUMGRID_NVD_API_KEY" in body["env_hint"]


def test_nvd_key_set_and_clear():
    import cve

    try:
        r = client.post("/api/settings/nvd-key", json={"key": "DEMO-KEY-123"})
        assert r.status_code == 200
        assert r.json()["key_active"] is True
        assert cve.key_active() is True
        assert "50" in client.get("/api/settings/nvd").json()["rate_limit"]
        # clearing drops back to the anonymous limit
        client.post("/api/settings/nvd-key", json={"key": ""})
        assert cve.key_active() is False
    finally:
        cve.set_api_key("")  # never leak test state into other tests


def test_nvd_key_requires_admin(monkeypatch):
    monkeypatch.setattr(security, "ADMIN_TOKEN", "adm1n")
    assert client.post("/api/settings/nvd-key", json={"key": "x"}).status_code == 401
    ok = client.post("/api/settings/nvd-key?token=adm1n", json={"key": ""})
    assert ok.status_code == 200


def test_network_suggestion():
    r = client.get("/api/network")
    assert r.status_code == 200
    assert "suggested_target" in r.json()


# --- scope guardrail on the streaming endpoint (ERROR frame, no scan) ------- #
@pytest.mark.parametrize("target", ["127.0.0.1", "8.8.8.8", "224.0.0.1", "-oG"])
def test_stream_refuses_forbidden_targets(target):
    r = client.get(f"/api/scan/stream?target={target}&id=t")
    assert r.status_code == 200  # refusal is surfaced inline as an ERROR frame
    frame = _sse_frame(r.text)
    assert frame["phase"] == "Error"
    assert frame["message"]  # carries a human reason


# --- per-host scan guardrail (400, no scan) -------------------------------- #
@pytest.mark.parametrize("ip", ["127.0.0.1", "8.8.8.8", "-oG", "a b"])
def test_host_scan_refuses_forbidden(ip):
    r = client.get(f"/api/host/scan?ip={ip}")
    assert r.status_code == 400
    assert "error" in r.json()


# --- optional token gate --------------------------------------------------- #
def test_token_gate(monkeypatch):
    monkeypatch.setattr(security, "API_TOKEN", "s3cret")
    # No token → 401 even for an otherwise-rejected target (auth is checked first).
    assert client.get("/api/scan/stream?target=127.0.0.1").status_code == 401
    assert client.get("/api/host/scan?ip=127.0.0.1").status_code == 401
    # Correct token → passes auth (then hits the scope refusal as usual).
    ok = client.get("/api/scan/stream?target=127.0.0.1&token=s3cret")
    assert ok.status_code == 200
    assert _sse_frame(ok.text)["phase"] == "Error"


# --- PDF report ------------------------------------------------------------ #
def test_report_pdf():
    payload = {
        "target": "192.168.0.0/24",
        "hosts": [
            {"ip": "192.168.0.1", "vendor": "Sagemcom", "device_type": "Router / Gateway",
             "status": "up", "ports": [{"port": 443, "state": "open", "service": "http", "version": "lighttpd"}]}
        ],
    }
    r = client.post("/api/report/pdf", json=payload)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content[:5] == b"%PDF-"
    assert "attachment" in r.headers.get("content-disposition", "")


# --- history + drift ------------------------------------------------------- #
def test_history_empty_then_populated():
    assert client.get("/api/history").json() == {"scans": []}

    history.save_scan(
        {"target": "10.0.0.0/24", "finished_at": 1.0,
         "hosts": [{"ip": "10.0.0.1", "status": "up", "ports": []}]}
    )
    scans = client.get("/api/history?target=10.0.0.0/24").json()["scans"]
    assert len(scans) == 1
    assert scans[0]["host_count"] == 1


def test_history_diff_unavailable_then_changes():
    assert client.get("/api/history/diff?target=10.0.0.0/24").json()["available"] is False

    history.save_scan({"target": "10.0.0.0/24", "finished_at": 1.0,
                       "hosts": [{"ip": "10.0.0.1", "status": "up", "ports": []},
                                 {"ip": "10.0.0.9", "status": "up", "ports": []}]})
    history.save_scan({"target": "10.0.0.0/24", "finished_at": 2.0,
                       "hosts": [{"ip": "10.0.0.1", "status": "up", "ports": []}]})
    diff = client.get("/api/history/diff?target=10.0.0.0/24").json()
    assert diff["available"] is True and diff["has_changes"] is True
    assert any(h["ip"] == "10.0.0.9" for h in diff["disappeared_hosts"])


# --- security response headers --------------------------------------------- #
def test_security_headers_present():
    h = client.get("/api/health").headers
    assert h.get("x-content-type-options") == "nosniff"
    assert h.get("x-frame-options") == "DENY"
    assert "frame-ancestors 'none'" in h.get("content-security-policy", "")
    assert h.get("referrer-policy") == "no-referrer"


# --- open-mode locality guard (anti LAN-exposure / DNS-rebinding) ----------- #
def test_open_mode_blocks_rebinding_host_header():
    # In open (no-token) mode a request whose Host header is a rebound domain is
    # refused, even though the in-process peer is "local" — defeating DNS rebinding.
    r = client.get("/api/health", headers={"host": "evil.example.com"})
    assert r.status_code == 401
    # A genuinely local Host is served.
    assert client.get("/api/health", headers={"host": "localhost:8011"}).status_code == 200


def test_history_requires_token_when_configured(monkeypatch):
    # With auth enabled, the inventory endpoints must NOT be readable without a
    # token (regression: they previously bypassed RBAC unlike /api/audit).
    monkeypatch.setattr(security, "ADMIN_TOKEN", "secret")
    monkeypatch.setattr(security, "API_TOKEN", None)
    monkeypatch.setattr(security, "VIEWER_TOKEN", None)
    assert client.get("/api/history").status_code == 401
    assert client.get("/api/history/diff?target=10.0.0.0/24").status_code == 401
    assert client.get("/api/history?token=secret").status_code == 200
    assert client.get("/api/history/diff?target=10.0.0.0/24&token=secret").status_code == 200
