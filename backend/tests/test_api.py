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


def test_report_pdf_is_read_gated_in_token_mode(monkeypatch):
    """The PDF endpoint must not be drivable by an unauthenticated caller when
    RBAC is on — it can spend the operator's LLM key (include_ai_summary) and burn
    CPU, exactly like /api/copilot/summary, which is also read-gated."""
    monkeypatch.setattr(security, "API_TOKEN", "s3cret")
    payload = {"target": "192.168.0.0/24", "hosts": [{"ip": "192.168.0.1"}]}
    # No token → 401 (was previously served to anyone).
    assert client.post("/api/report/pdf", json=payload).status_code == 401
    # A viewer token is enough (read-gated): correct token → renders the PDF.
    monkeypatch.setattr(security, "VIEWER_TOKEN", "look")
    ok = client.post("/api/report/pdf?token=look", json=payload)
    assert ok.status_code == 200 and ok.content[:5] == b"%PDF-"


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


# --- endpoint success paths (heavy internals mocked; no scan/network) ------- #
import asyncio  # noqa: E402
from datetime import datetime  # noqa: E402

import app as A  # noqa: E402
from models import Host, HostStatus, ScanPhase, ScanState  # noqa: E402


def test_root_endpoint():
    body = client.get("/").json()
    assert "service" in body and body["health"] == "/api/health"


def test_profiles_lists_scan_profiles():
    body = client.get("/api/profiles").json()
    assert "default" in body["profiles"] and "args" in body["profiles"]["default"]
    assert body["capability"] in ("root", "sudo", "unprivileged")


def test_audit_endpoint():
    assert "entries" in client.get("/api/audit").json()


def test_network_collects_addresses(monkeypatch):
    # Call the endpoint function directly: patching the shared `socket` module
    # would otherwise break the in-process TestClient's own transport sockets.
    import socket as S

    class _Probe:
        def connect(self, addr): pass
        def getsockname(self): return ("192.168.7.20", 0)
        def close(self): pass

    monkeypatch.setattr(S, "socket", lambda *a, **k: _Probe())
    monkeypatch.setattr(S, "gethostname", lambda: "myhost")
    monkeypatch.setattr(S, "getaddrinfo", lambda h, p, fam: [(0, 0, 0, "", ("192.168.7.21", 0))])
    body = A.network()
    assert body["primary_ip"] == "192.168.7.20" and "192.168.7.21" in body["addresses"]
    assert body["network_cidr"] == "192.168.7.0/24"


def test_network_all_none_when_socket_fails(monkeypatch):
    import socket as S

    def _boom(*a, **k):
        raise OSError("no route")

    monkeypatch.setattr(S, "socket", _boom)
    monkeypatch.setattr(S, "gethostname", _boom)
    body = A.network()
    assert body["primary_ip"] is None and body["hostname"] is None
    assert body["suggested_target"] == "192.168.1.0/24"


def test_scan_stream_discover_success(monkeypatch):
    async def fake_disc(target, sid):
        yield ScanState(scan_id=sid, target=target, phase=ScanPhase.PING_SWEEP, progress=10, hosts=[])
        yield ScanState(scan_id=sid, target=target, phase=ScanPhase.COMPLETE, progress=100,
                        hosts=[], finished_at=1.0)

    monkeypatch.setattr(A, "run_discovery", fake_disc)
    r = client.get("/api/scan/stream?target=192.168.50.5&id=t1")
    assert r.status_code == 200 and _sse_frame(r.text)  # first frame parses
    assert _sse_frames(r.text)[-1]["phase"] == "Complete"


def test_scan_stream_full_mode_uses_pipeline(monkeypatch):
    async def fake_pipe(target, sid, deep):
        yield ScanState(scan_id=sid, target=target, phase=ScanPhase.COMPLETE, progress=100,
                        hosts=[], finished_at=1.0)

    monkeypatch.setattr(A, "run_pipeline", fake_pipe)
    r = client.get("/api/scan/stream?target=192.168.50.5&mode=full&deep=1")
    assert _sse_frames(r.text)[-1]["phase"] == "Complete"


def test_host_scan_success(monkeypatch):
    async def fake_scan(ip, deep, profile, scripts, ports, adaptive=False):
        return Host(ip=ip, status=HostStatus.UP, os="Linux")

    monkeypatch.setattr(A, "scan_single_host", fake_scan)
    r = client.get("/api/host/scan?ip=192.168.50.5")
    assert r.status_code == 200 and r.json()["ip"] == "192.168.50.5"


def test_host_scan_timeout_and_error(monkeypatch):
    async def _timeout(*a, **k):
        raise asyncio.TimeoutError()

    monkeypatch.setattr(A, "scan_single_host", _timeout)
    assert client.get("/api/host/scan?ip=192.168.50.5").status_code == 504

    async def _boom(*a, **k):
        raise RuntimeError("scan blew up")

    monkeypatch.setattr(A, "scan_single_host", _boom)
    assert client.get("/api/host/scan?ip=192.168.50.5").status_code == 502


def test_host_credscan_success_and_validation(monkeypatch):
    monkeypatch.setattr(A.credscan, "ssh_facts",
                        lambda ip, user, **k: {"ok": True, "os": "Ubuntu",
                                               "package_list": [("openssl", "3.0")], "vulns": []})
    monkeypatch.setattr(A.osv, "ecosystem_from_os", lambda os_: "Ubuntu")
    monkeypatch.setattr(A.osv, "scan_packages", lambda pkgs, eco: [])
    monkeypatch.setattr(A.threatintel, "enrich", lambda findings: findings)
    body = {"ip": "192.168.50.5", "username": "admin", "password": "x"}  # nosec B105 - test fixture
    r = client.post("/api/host/credscan", json=body)
    assert r.status_code == 200 and r.json()["ok"] is True and "package_list" not in r.json()
    assert client.post("/api/host/credscan", json={"ip": "", "username": ""}).status_code == 400


def test_host_webscan_success(monkeypatch):
    monkeypatch.setattr(A.webscan, "scan", lambda ip, port, https: {"ok": True, "server": "nginx", "vulns": []})
    r = client.get("/api/host/webscan?ip=192.168.50.5&port=80")
    assert r.status_code == 200 and r.json()["ok"] is True


def test_cloud_aws(monkeypatch):
    monkeypatch.setattr(A.cloudscan, "aws_inventory",
                        lambda region: {"ok": True, "assets": [], "findings": []})
    assert client.get("/api/cloud/aws").json()["ok"] is True


def test_ad_enum_success_and_validation(monkeypatch):
    monkeypatch.setattr(A.adscan, "enumerate_domain",
                        lambda *a, **k: {"ok": True, "computers": [], "users": []})
    ok = client.post("/api/ad/enum",
                     json={"dc_host": "dc", "domain": "corp.local", "username": "u", "password": "p"})  # nosec B105 - test fixture
    assert ok.status_code == 200 and ok.json()["ok"] is True
    assert client.post("/api/ad/enum", json={"dc_host": "dc"}).status_code == 400   # missing fields


def test_passive_success(monkeypatch):
    monkeypatch.setattr(A.passive, "discover_passive",
                        lambda s, i: {"available": True, "seconds": s, "hosts": [], "count": 0})
    assert client.post("/api/passive?seconds=5").json()["available"] is True


def test_copilot_chat_and_summary_success(monkeypatch, _copilot_isolated):
    def fake_stream(messages, context, provider=None):
        yield {"type": "delta", "text": "grounded answer"}
        yield {"type": "done"}

    monkeypatch.setattr(A.copilot, "stream_reply", fake_stream)
    frames = _sse_frames(client.post("/api/copilot/chat",
                                     json={"messages": [{"role": "user", "content": "hi"}],
                                           "context": {"target": "x"}}).text)
    assert any(f.get("text") == "grounded answer" for f in frames)

    monkeypatch.setattr(A.copilot, "summarize_scan", lambda ctx, provider=None: {"available": True, "summary": "S"})
    assert client.post("/api/copilot/summary", json={"context": {"target": "x"}}).json()["available"] is True


def test_jobs_submit_list_get(monkeypatch, tmp_path):
    import jobs
    monkeypatch.setattr(jobs, "DB_PATH", str(tmp_path / "jobs.db"))
    jid = client.post("/api/jobs/submit", json={"kind": "host_scan", "ip": "192.168.50.5"}).json()["job_id"]
    assert any(j["id"] == jid for j in client.get("/api/jobs").json()["jobs"])
    assert client.get(f"/api/jobs/{jid}").json()["kind"] == "host_scan"
    assert client.get("/api/jobs/999999").status_code == 404
    assert client.post("/api/jobs/submit", json={"kind": "bogus"}).status_code == 400
    assert client.post("/api/jobs/submit", json={"kind": "host_scan", "ip": "8.8.8.8"}).status_code == 400


def test_job_handlers_run_scans(monkeypatch):
    async def fake_scan(ip, deep, profile, scripts, ports, adaptive=False):
        return Host(ip=ip, status=HostStatus.UP)

    monkeypatch.setattr(A, "scan_single_host", fake_scan)
    assert A._job_host_scan({"ip": "192.168.50.5"})["ip"] == "192.168.50.5"

    async def fake_disc(target, sid):
        yield ScanState(scan_id=sid, target=target, phase=ScanPhase.COMPLETE, progress=100,
                        hosts=[], finished_at=1.0)

    monkeypatch.setattr(A, "run_discovery", fake_disc)
    res = A._job_network_scan({"target": "192.168.50.0/24", "mode": "discover"})
    assert res["ok"] is True and res["target"] == "192.168.50.0/24"


def test_job_network_scan_no_result(monkeypatch):
    async def empty(target, sid, deep):
        return
        yield  # pragma: no cover - marks this an async generator

    monkeypatch.setattr(A, "run_pipeline", empty)
    res = A._job_network_scan({"target": "192.168.50.0/24", "mode": "full"})
    assert res["ok"] is False


def test_scheduler_loop_enqueues_due_rules(monkeypatch, tmp_path):
    import jobs
    import schedule as sch
    monkeypatch.setattr(jobs, "DB_PATH", str(tmp_path / "jobs.db"))
    store = sch.ScheduleStore(str(tmp_path / "s.json"))
    now = datetime.now()
    store.add(target="192.168.50.0/24", at=f"{now.hour:02d}:{now.minute:02d}", days="*")
    monkeypatch.setattr(A, "_schedules", store)

    async def _run():
        A._sched_stop.clear()
        task = asyncio.create_task(A._scheduler_loop())
        await asyncio.sleep(0.1)          # let one iteration enqueue the due rule
        A._sched_stop.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(_run())
    A._sched_stop.clear()
    assert len(jobs.list_jobs()) >= 1     # the due rule fired a job


def test_throttle_clears_streak_on_remote_success(monkeypatch):
    security.reset_auth_throttle()
    monkeypatch.setattr(security, "ADMIN_TOKEN", "adm1n")
    monkeypatch.setattr(security, "client_is_local", lambda h: False)   # treat peer as remote
    security.register_auth_failure("testclient")                        # seed a failure streak
    assert client.get("/api/history?token=adm1n").status_code == 200    # success clears it
    assert security.is_locked_out("testclient") is False
    security.reset_auth_throttle()


def test_request_context_logs_and_reraises(monkeypatch):
    from fastapi.testclient import TestClient as _TC

    def _boom(*a, **k):
        raise RuntimeError("provenance blew up")

    monkeypatch.setattr(A.provenance, "build_info", _boom)
    c = _TC(A.app, raise_server_exceptions=False)
    assert c.get("/api/health").status_code == 500      # middleware logs the error and re-raises


_GATED_ENDPOINTS = [
    ("post", "/api/privilege/elevate", {"password": "x"}),  # nosec B105 - test fixture
    ("post", "/api/privilege/drop", None),
    ("get", "/api/copilot", None),
    ("post", "/api/copilot/provider", {"provider": "openai"}),
    ("post", "/api/copilot/chat", {"messages": []}),
    ("post", "/api/copilot/summary", {"context": {}}),
    ("post", "/api/host/credscan", {"ip": "192.168.50.5", "username": "u"}),
    ("get", "/api/host/webscan?ip=192.168.50.5", None),
    ("get", "/api/campaign?targets=192.168.50.0/24", None),
    ("get", "/api/cloud/aws", None),
    ("post", "/api/ad/enum", {"dc_host": "d", "domain": "c", "username": "u", "password": "p"}),  # nosec B105 - test fixture
    ("post", "/api/passive?seconds=5", None),
    ("post", "/api/jobs/submit", {"kind": "host_scan", "ip": "192.168.50.5"}),
    ("get", "/api/jobs", None),
    ("get", "/api/jobs/1", None),
    ("get", "/api/schedules", None),
    ("post", "/api/schedules", {"target": "192.168.50.0/24", "at": "02:00"}),
    ("post", "/api/schedules/x/toggle?enabled=false", None),
    ("delete", "/api/schedules/x", None),
    ("get", "/api/audit", None),
]


@pytest.mark.parametrize("method,path,body", _GATED_ENDPOINTS)
def test_gated_endpoints_require_auth(monkeypatch, method, path, body):
    # In token mode with no token supplied, every gated endpoint refuses (401).
    monkeypatch.setattr(security, "ADMIN_TOKEN", "adm1n")
    monkeypatch.setattr(security, "VIEWER_TOKEN", None)
    monkeypatch.setattr(security, "API_TOKEN", None)
    fn = getattr(client, method)
    r = fn(path, json=body) if body is not None else fn(path)
    assert r.status_code == 401


def test_privilege_elevate_rejects_non_string_password():
    r = client.post("/api/privilege/elevate", json={"password": 123})  # nosec B105 - test fixture (non-string)
    assert r.status_code == 422       # password must be a string


def test_job_network_scan_full_mode_with_result(monkeypatch):
    async def fake_pipe(target, sid, deep):
        yield ScanState(scan_id=sid, target=target, phase=ScanPhase.COMPLETE, progress=100,
                        hosts=[Host(ip="192.168.50.5", status=HostStatus.UP)], finished_at=1.0)

    monkeypatch.setattr(A, "run_pipeline", fake_pipe)
    res = A._job_network_scan({"target": "192.168.50.0/24", "mode": "full"})
    assert res["ok"] is True and res["mode"] == "full" and res["hosts"] == 1


def test_app_lifespan_starts_and_stops_workers(monkeypatch, tmp_path):
    import jobs
    from fastapi.testclient import TestClient as _TC
    monkeypatch.setattr(jobs, "DB_PATH", str(tmp_path / "jobs.db"))
    A._job_stop.clear()
    A._sched_stop.clear()
    with _TC(A.app) as c:                 # triggers the startup + shutdown event handlers
        assert c.get("/api/health").status_code == 200


class _BusySlot:
    async def __aenter__(self): return False      # at capacity
    async def __aexit__(self, *a): return False


def test_scan_stream_server_busy(monkeypatch):
    monkeypatch.setattr(A, "scan_slot", lambda: _BusySlot())
    frames = _sse_frames(client.get("/api/scan/stream?target=192.168.50.5").text)
    assert any("busy" in f.get("message", "") for f in frames)


def test_host_scan_server_busy(monkeypatch):
    monkeypatch.setattr(A, "scan_slot", lambda: _BusySlot())
    assert client.get("/api/host/scan?ip=192.168.50.5").status_code == 429


def test_scan_stream_swallows_history_and_notify_errors(monkeypatch):
    async def fake_disc(target, sid):
        yield ScanState(scan_id=sid, target=target, phase=ScanPhase.COMPLETE, progress=100,
                        hosts=[], finished_at=1.0)

    def _raise(*a, **k):
        raise RuntimeError("sink down")

    monkeypatch.setattr(A, "run_discovery", fake_disc)
    monkeypatch.setattr(A.history, "save_scan", _raise)
    monkeypatch.setattr(A.notify, "scan_complete", _raise)
    frames = _sse_frames(client.get("/api/scan/stream?target=192.168.50.5").text)
    assert frames[-1]["phase"] == "Complete"      # best-effort sinks failed, stream still completed


def test_host_credscan_and_webscan_reject_out_of_scope():
    assert client.post("/api/host/credscan", json={"ip": "8.8.8.8", "username": "u"}).status_code == 400
    assert client.get("/api/host/webscan?ip=8.8.8.8").status_code == 400


def test_report_pdf_renders_despite_copilot_error(monkeypatch):
    def _raise(*a, **k):
        raise RuntimeError("llm down")

    monkeypatch.setattr(A.copilot, "summarize_scan", _raise)
    r = client.post("/api/report/pdf",
                    json={"target": "x", "hosts": [{"ip": "10.0.0.1"}], "include_ai_summary": True})
    assert r.status_code == 200 and r.content[:5] == b"%PDF-"   # copilot failure swallowed


def test_latest_snapshot_handles_missing_row(monkeypatch):
    monkeypatch.setattr(A.history, "list_scans", lambda t, limit=1: [{"id": 1, "finished_at": "t"}])
    monkeypatch.setattr(A.history, "get_scan", lambda i: None)
    assert A._latest_snapshot("x") == (None, None)


def test_job_network_scan_swallows_save_error(monkeypatch):
    async def fake_disc(target, sid):
        yield ScanState(scan_id=sid, target=target, phase=ScanPhase.COMPLETE, progress=100,
                        hosts=[], finished_at=1.0)

    monkeypatch.setattr(A, "run_discovery", fake_disc)
    monkeypatch.setattr(A.history, "save_scan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db")))
    assert A._job_network_scan({"target": "192.168.50.0/24", "mode": "discover"})["ok"] is True


def test_network_getaddrinfo_error_is_tolerated(monkeypatch):
    import socket as S

    class _Probe:
        def connect(self, addr): pass
        def getsockname(self): return ("192.168.7.20", 0)
        def close(self): pass

    monkeypatch.setattr(S, "socket", lambda *a, **k: _Probe())
    monkeypatch.setattr(S, "gethostname", lambda: "myhost")
    monkeypatch.setattr(S, "getaddrinfo", lambda *a: (_ for _ in ()).throw(OSError()))
    assert A.network()["primary_ip"] == "192.168.7.20"      # getaddrinfo failure tolerated


def test_schedule_toggle_missing_returns_404():
    assert client.post("/api/schedules/nonexistent/toggle?enabled=false").status_code == 404


def test_scheduler_loop_covers_enqueue_error_and_timeout(monkeypatch, tmp_path):
    import jobs
    import schedule as sch
    monkeypatch.setattr(jobs, "DB_PATH", str(tmp_path / "jobs.db"))
    store = sch.ScheduleStore(str(tmp_path / "s.json"))
    now = datetime.now()
    store.add(target="192.168.50.0/24", at=f"{now.hour:02d}:{now.minute:02d}", days="*")
    monkeypatch.setattr(A, "_schedules", store)

    def _enqueue_boom(*a, **k):
        raise RuntimeError("queue full")          # a bad enqueue must not kill the ticker

    monkeypatch.setattr(A.jobs, "enqueue", _enqueue_boom)
    calls = {"n": 0}

    async def fake_wait(fut, timeout):
        calls["n"] += 1
        fut.close()                               # we don't await the stop-event coroutine
        if calls["n"] == 1:
            raise asyncio.TimeoutError()          # exercise the 30s-tick timeout branch
        A._sched_stop.set()                       # end the loop on the second tick

    async def _run():
        A._sched_stop.clear()
        monkeypatch.setattr(A.asyncio, "wait_for", fake_wait)
        await A._scheduler_loop()

    asyncio.run(_run())
    A._sched_stop.clear()
