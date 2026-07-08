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
import passive
import pytest
import schedule
import security
from app import app
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture(autouse=True)
def _temp_history(tmp_path, monkeypatch):
    """Isolate every test from the real history DB + schedule store."""
    monkeypatch.setattr(history, "DB_PATH", str(tmp_path / "h.db"))
    history.init_db()
    # Point the schedule store at a throwaway file so tests never touch the repo's.
    monkeypatch.setattr("app._schedules", schedule.ScheduleStore(str(tmp_path / "s.json")))


def _sse_frame(resp_text: str) -> dict:
    line = next(li for li in resp_text.splitlines() if li.startswith("data:"))
    return json.loads(line[len("data:"):].strip())


# --- request correlation id ------------------------------------------------- #
def test_response_carries_generated_request_id():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert len(r.headers.get("X-Request-Id", "")) == 12   # generated correlation id


def test_inbound_request_id_is_echoed():
    r = client.get("/api/health", headers={"X-Request-Id": "trace-xyz"})
    assert r.headers.get("X-Request-Id") == "trace-xyz"   # client-supplied id preserved


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
    # reproducibility manifest surfaced for provenance
    prov = body["provenance"]
    assert prov["tool"] == "ENUMGRID"
    assert "git_commit" in prov and "nmap_version" in prov and "python_version" in prov


# --- passive (zero-packet) discovery --------------------------------------- #
def test_passive_endpoint_unavailable_without_scapy(monkeypatch):
    # Force the no-scapy path so the test never sniffs or needs root.
    monkeypatch.setattr(passive, "_HAVE_SCAPY", False)
    r = client.post("/api/passive?seconds=5")
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is False and body["count"] == 0
    assert "scapy" in body["reason"].lower()
    assert body["hosts"] == []


def test_passive_endpoint_validates_seconds_bounds():
    # Out-of-range windows are rejected by FastAPI before any capture runs.
    assert client.post("/api/passive?seconds=0").status_code == 422
    assert client.post("/api/passive?seconds=9999").status_code == 422


# --- scheduled scans -------------------------------------------------------- #
def test_schedule_create_list_toggle_delete():
    r = client.post("/api/schedules", json={"target": "192.168.50.0/24", "at": "02:00",
                                             "days": "mon,fri", "mode": "full"})
    assert r.status_code == 201
    rule = r.json()
    assert rule["target"] == "192.168.50.0/24" and rule["at"] == "02:00" and rule["days"] == "mon,fri"
    sid = rule["id"]

    listed = client.get("/api/schedules").json()["schedules"]
    assert any(s["id"] == sid for s in listed)

    toggled = client.post(f"/api/schedules/{sid}/toggle?enabled=false")
    assert toggled.status_code == 200 and toggled.json()["enabled"] is False

    assert client.delete(f"/api/schedules/{sid}").status_code == 200
    assert client.delete(f"/api/schedules/{sid}").status_code == 404  # gone


def test_schedule_create_rejects_bad_time():
    r = client.post("/api/schedules", json={"target": "192.168.50.0/24", "at": "25:00"})
    assert r.status_code == 400
    assert "time" in r.json()["error"].lower()


def test_schedule_create_rejects_out_of_scope_target():
    # A public target is refused by the same ScopeValidator a live scan uses.
    r = client.post("/api/schedules", json={"target": "8.8.8.8", "at": "02:00"})
    assert r.status_code == 400


def test_schedule_create_requires_target():
    assert client.post("/api/schedules", json={"at": "02:00"}).status_code == 400


# --- multi-subnet campaign view --------------------------------------------- #
def test_campaign_aggregates_latest_scans():
    history.save_scan({"target": "192.168.50.0/24", "finished_at": "t1", "hosts": [
        {"ip": "192.168.50.1", "device_type": "Router",
         "ports": [{"port": 80, "service": "http", "state": "open"}]},
    ]}, mode="discover")
    history.save_scan({"target": "10.10.0.0/24", "finished_at": "t2", "hosts": [
        {"ip": "10.10.0.5", "device_type": "Server",
         "ports": [{"port": 22, "service": "ssh", "state": "open"}]},
    ]}, mode="discover")

    r = client.get("/api/campaign?targets=192.168.50.0/24,10.10.0.0/24,172.16.9.0/24")
    assert r.status_code == 200
    body = r.json()
    assert body["totals"]["subnets"] == 3
    assert body["totals"]["scanned_subnets"] == 2       # the third was never scanned
    assert body["totals"]["hosts"] == 2
    assert body["totals"]["open_ports"] == 2
    unscanned = next(s for s in body["subnets"] if s["target"] == "172.16.9.0/24")
    assert unscanned["scanned"] is False and unscanned["hosts"] == 0


# --- runtime privilege elevation endpoints --------------------------------- #
def test_privilege_status_endpoint():
    r = client.get("/api/privilege")
    assert r.status_code == 200
    body = r.json()
    assert body["capability"] in ("root", "sudo", "unprivileged")
    for key in ("can_raw", "is_root", "elevated", "sudo_available", "can_elevate"):
        assert key in body


def test_privilege_elevate_success(monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module, "elevate_sudo", lambda pw: (True, "elevated"))
    monkeypatch.setattr(
        app_module, "privilege_status",
        lambda: {"capability": "sudo", "can_raw": True, "is_root": False,
                 "elevated": True, "sudo_available": True, "can_elevate": True},
    )
    r = client.post("/api/privilege/elevate", json={"password": "x"})  # nosec B105 - test fixture, not a real secret
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["capability"] == "sudo"
    # The secret must never be echoed back.
    assert "password" not in body


def test_privilege_elevate_wrong_password(monkeypatch):
    import app as app_module

    monkeypatch.setattr(app_module, "elevate_sudo", lambda pw: (False, "sudo rejected the password"))
    monkeypatch.setattr(
        app_module, "privilege_status",
        lambda: {"capability": "unprivileged", "can_raw": False, "is_root": False,
                 "elevated": False, "sudo_available": True, "can_elevate": True},
    )
    r = client.post("/api/privilege/elevate", json={"password": "nope"})  # nosec B105 - test fixture, not a real secret
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and "rejected" in body["message"].lower()


def test_privilege_drop(monkeypatch):
    import app as app_module

    called = {"drop": False}

    def _drop():
        called["drop"] = True

    monkeypatch.setattr(app_module, "drop_privileges", _drop)
    r = client.post("/api/privilege/drop")
    assert r.status_code == 200
    assert r.json()["ok"] is True and called["drop"] is True


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


def test_auth_bruteforce_lockout_blocks_remote_after_repeated_401s(monkeypatch):
    """The throttle middleware locks a *remote* IP out (429) after too many 401s,
    and a valid token still works from a fresh IP."""
    security.reset_auth_throttle()
    monkeypatch.setattr(security, "ADMIN_TOKEN", "adm1n")             # token mode
    monkeypatch.setattr(security, "AUTH_MAX_FAILURES", 3)
    # The in-process TestClient is "local"; treat it as remote so the throttle bites.
    monkeypatch.setattr(security, "client_is_local", lambda h: False)
    try:
        for _ in range(3):                                            # 3 bad-token 401s
            assert client.post("/api/settings/nvd-key", json={"key": "x"}).status_code == 401
        locked = client.post("/api/settings/nvd-key", json={"key": "x"})
        assert locked.status_code == 429                              # now locked out
        assert "Retry-After" in locked.headers
        # A correct token is refused too while locked (short-circuited before auth).
        assert client.post("/api/settings/nvd-key?token=adm1n", json={"key": ""}).status_code == 429
    finally:
        security.reset_auth_throttle()


# --- copilot ---------------------------------------------------------------- #
def _sse_frames(resp_text: str) -> list:
    return [json.loads(li[len("data:"):].strip())
            for li in resp_text.splitlines() if li.startswith("data:")]


@pytest.fixture()
def _copilot_isolated(tmp_path, monkeypatch):
    """Keep copilot key/provider files out of the repo during tests, and stub the
    local Ollama probe so status stays hermetic (no network)."""
    import copilot
    monkeypatch.setattr(copilot, "_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(copilot, "ollama_probe", lambda *a, **k: {"up": False, "models": []})
    for var in ("ENUMGRID_ANTHROPIC_API_KEY", "ENUMGRID_OPENAI_API_KEY",
                "ENUMGRID_GEMINI_API_KEY", "ENUMGRID_OLLAMA_API_KEY", "ENUMGRID_COPILOT_PROVIDER"):
        monkeypatch.delenv(var, raising=False)


def test_copilot_status(_copilot_isolated):
    r = client.get("/api/copilot")
    assert r.status_code == 200
    body = r.json()
    assert set(body["providers"]) == {"anthropic", "openai", "gemini", "ollama"}
    assert body["active"] in body["providers"]
    # the two free providers advertise themselves as such for the dashboard
    assert body["providers"]["ollama"]["local"] is True
    assert body["providers"]["ollama"]["requires_key"] is False


def test_copilot_key_set_and_provider_switch(_copilot_isolated):
    r = client.post("/api/copilot/key", json={"provider": "openai", "key": "sk-test"})
    assert r.status_code == 200 and r.json()["key_set"] is True
    assert r.json()["status"]["providers"]["openai"]["key_set"] is True
    assert client.post("/api/copilot/key", json={"provider": "bogus", "key": "x"}).status_code == 400
    sw = client.post("/api/copilot/provider", json={"provider": "openai"})
    assert sw.status_code == 200 and sw.json()["status"]["active"] == "openai"
    assert client.post("/api/copilot/provider", json={"provider": "bogus"}).status_code == 400


def test_copilot_key_requires_admin(monkeypatch, _copilot_isolated):
    monkeypatch.setattr(security, "ADMIN_TOKEN", "adm1n")
    assert client.post("/api/copilot/key", json={"provider": "openai", "key": "x"}).status_code == 401
    assert client.post("/api/copilot/key?token=adm1n",
                       json={"provider": "openai", "key": ""}).status_code == 200


def test_copilot_chat_streams_honest_error_without_key(_copilot_isolated):
    # No key configured → the stream must degrade to an honest error frame, never
    # a fabricated answer, and always terminate with a done frame.
    r = client.post("/api/copilot/chat",
                    json={"messages": [{"role": "user", "content": "hi"}], "provider": "anthropic"})
    assert r.status_code == 200
    frames = _sse_frames(r.text)
    assert frames[0]["type"] == "error"
    assert frames[-1] == {"type": "done"}


def test_copilot_set_model(_copilot_isolated):
    r = client.post("/api/copilot/model", json={"provider": "ollama", "model": "qwen2.5"})
    assert r.status_code == 200 and r.json()["model"] == "qwen2.5"
    assert r.json()["status"]["providers"]["ollama"]["model"] == "qwen2.5"
    # bad provider / bad model name are rejected
    assert client.post("/api/copilot/model", json={"provider": "bogus", "model": "x"}).status_code == 400
    assert client.post("/api/copilot/model",
                       json={"provider": "ollama", "model": "bad name; rm -rf"}).status_code == 400


def test_copilot_ollama_pull_streams_error_when_name_bad(_copilot_isolated):
    # An invalid model name must fail honestly as an SSE error, never silently.
    r = client.post("/api/copilot/ollama/pull", json={"model": "bad name; rm"})
    assert r.status_code == 200
    frames = _sse_frames(r.text)
    assert frames[0]["type"] == "error" and "invalid model" in frames[0]["message"]
    assert frames[-1] == {"type": "done"}


def test_copilot_model_and_pull_require_admin(monkeypatch, _copilot_isolated):
    monkeypatch.setattr(security, "ADMIN_TOKEN", "adm1n")
    assert client.post("/api/copilot/model", json={"provider": "ollama", "model": "llama3.1"}).status_code == 401
    assert client.post("/api/copilot/ollama/pull", json={"model": "llama3.1"}).status_code == 401
    assert client.post("/api/copilot/model?token=adm1n",
                       json={"provider": "ollama", "model": "llama3.1"}).status_code == 200


def test_copilot_summary_is_honest_without_provider(monkeypatch, _copilot_isolated):
    import copilot
    monkeypatch.setattr(copilot, "_HAVE_OPENAI", False)
    monkeypatch.setattr(copilot, "_HAVE_ANTHROPIC", False)
    r = client.post("/api/copilot/summary",
                    json={"context": {"target": "x", "hosts": []}, "provider": "openai"})
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is False and body["error"]     # honest, no fabricated summary


def test_report_pdf_embeds_ai_summary_when_requested(monkeypatch, _copilot_isolated):
    import copilot
    monkeypatch.setattr(copilot, "summarize_scan",
                        lambda *a, **k: {"available": True, "summary": "Top risk is the router.",
                                         "provider": "ollama", "error": None})
    r = client.post("/api/report/pdf",
                    json={"target": "10.0.0.0/24", "hosts": [{"ip": "10.0.0.1"}],
                          "include_ai_summary": True})
    assert r.status_code == 200 and r.content[:5] == b"%PDF-"


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
