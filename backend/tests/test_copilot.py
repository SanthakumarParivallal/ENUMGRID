"""
test_copilot.py — the copilot's pure core: key storage, provider selection,
scan-context grounding, request hygiene, tool schemas, and the honest
"unavailable" streaming paths. No SDK, no API key, no network.
"""

from __future__ import annotations

import json

import copilot
import pytest


@pytest.fixture()
def state(tmp_path, monkeypatch):
    """Isolate key/provider files to a temp dir and clear any env overrides. Also
    stub the local Ollama probe to 'down' so status stays hermetic (no network);
    tests that care override it."""
    monkeypatch.setattr(copilot, "_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(copilot, "ollama_probe", lambda *a, **k: {"up": False, "models": []})
    for var in ("ENUMGRID_ANTHROPIC_API_KEY", "ENUMGRID_OPENAI_API_KEY",
                "ENUMGRID_GEMINI_API_KEY", "ENUMGRID_OLLAMA_API_KEY", "ENUMGRID_COPILOT_PROVIDER"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


# --- providers / validation -------------------------------------------------- #
def test_valid_provider():
    for p in ("anthropic", "openai", "gemini", "ollama"):
        assert copilot.valid_provider(p)
    assert not copilot.valid_provider("bogus") and not copilot.valid_provider(None)


def test_default_model_and_sdk_available():
    assert copilot.default_model("anthropic") == "claude-opus-4-8"
    assert copilot.default_model("openai") == "gpt-4o"
    assert copilot.default_model("gemini") == "gemini-2.0-flash"
    assert copilot.default_model("ollama") == "llama3.1"
    # Gemini + Ollama ride the openai SDK, so their availability tracks it.
    assert copilot.sdk_available("gemini") == copilot.sdk_available("openai")
    assert copilot.sdk_available("ollama") == copilot.sdk_available("openai")
    assert isinstance(copilot.sdk_available("anthropic"), bool)


def test_ollama_is_keyless(state):
    # Ollama runs locally: no key required, but load_key hands the SDK a harmless
    # placeholder because the OpenAI client insists on a non-empty api_key.
    assert copilot.requires_key("ollama") is False
    assert copilot.requires_key("gemini") is True
    assert copilot.has_key("ollama") is False          # no *real* key stored
    assert copilot.load_key("ollama") == "ollama"       # placeholder for the client


def test_ollama_ready_when_server_up_and_model_present(state, monkeypatch):
    monkeypatch.setattr(copilot, "_HAVE_OPENAI", True)
    monkeypatch.setattr(copilot, "ollama_probe",
                        lambda *a, **k: {"up": True, "models": ["llama3.1:latest"]})
    p = copilot.status()["providers"]["ollama"]
    assert p["ready"] is True and p["requires_key"] is False and p["local"] is True
    assert p["server_up"] is True and p["model_present"] is True
    assert p["models"] == ["llama3.1:latest"]
    assert any(m["name"] == "llama3.1" for m in p["recommended"])


def test_ollama_up_but_model_missing_is_not_ready(state, monkeypatch):
    # Server running but the chosen model isn't pulled → not ready, so the UI
    # offers a one-click download instead of a chat that would 404 on the model.
    monkeypatch.setattr(copilot, "_HAVE_OPENAI", True)
    monkeypatch.setattr(copilot, "ollama_probe",
                        lambda *a, **k: {"up": True, "models": ["qwen2.5:latest"]})
    p = copilot.status()["providers"]["ollama"]
    assert p["server_up"] is True and p["model_present"] is False and p["ready"] is False


def test_ollama_not_ready_when_server_down(state, monkeypatch):
    # No key needed, but if the local server isn't running it isn't "ready".
    monkeypatch.setattr(copilot, "_HAVE_OPENAI", True)   # stub probe stays 'down'
    p = copilot.status()["providers"]["ollama"]
    assert p["ready"] is False and p["server_up"] is False


def test_gemini_requires_a_key(state, monkeypatch):
    # Cloud providers aren't probed; readiness gates on the key only.
    monkeypatch.setattr(copilot, "_HAVE_OPENAI", True)
    assert copilot.status()["providers"]["gemini"]["ready"] is False   # no key yet
    copilot.save_key("gemini", "AIza-testkey-123456")
    assert copilot.status()["providers"]["gemini"]["ready"] is True


# --- ollama model selection + one-click pull --------------------------------- #
def test_active_model_default_and_override(state):
    assert copilot.active_model("ollama") == "llama3.1"           # built-in default
    assert copilot.set_model("ollama", "qwen2.5:7b") == "qwen2.5:7b"
    assert copilot.active_model("ollama") == "qwen2.5:7b"         # persisted override
    assert copilot.set_model("ollama", "") == "llama3.1"         # blank reverts


def test_set_model_rejects_bad_name_and_provider(state):
    with pytest.raises(ValueError):
        copilot.set_model("ollama", "bad name; rm -rf /")
    with pytest.raises(ValueError):
        copilot.set_model("bogus", "llama3.1")


def test_valid_model_name():
    assert copilot.valid_model_name("llama3.1")
    assert copilot.valid_model_name("qwen2.5:7b-instruct")
    assert not copilot.valid_model_name("bad name")
    assert not copilot.valid_model_name("; rm -rf")
    assert not copilot.valid_model_name("")


def test_selected_ollama_model_flows_into_status_readiness(state, monkeypatch):
    # Pick a model the server has → ready; the default (llama3.1) would not be.
    monkeypatch.setattr(copilot, "_HAVE_OPENAI", True)
    monkeypatch.setattr(copilot, "ollama_probe",
                        lambda *a, **k: {"up": True, "models": ["qwen2.5:latest"]})
    assert copilot.status()["providers"]["ollama"]["ready"] is False
    copilot.set_model("ollama", "qwen2.5")
    p = copilot.status()["providers"]["ollama"]
    assert p["model"] == "qwen2.5" and p["model_present"] is True and p["ready"] is True


class _FakePullResp:
    def __init__(self, lines):
        self._lines = lines

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __iter__(self):
        return iter(self._lines)


def test_pull_model_streams_progress_then_done(state, monkeypatch):
    lines = [b'{"status":"pulling manifest"}\n',
             b'{"status":"downloading","total":100,"completed":40}\n',
             b'{"status":"downloading","total":100,"completed":100}\n',
             b'{"status":"success"}\n']
    monkeypatch.setattr(copilot.urllib.request, "urlopen", lambda *a, **k: _FakePullResp(lines))
    events = list(copilot.pull_model("llama3.1"))
    assert any(e["type"] == "progress" and e.get("percent") == 40 for e in events)
    assert events[-1] == {"type": "done"}


def test_pull_model_surfaces_server_error(state, monkeypatch):
    lines = [b'{"error":"model \\"nope\\" not found"}\n']
    monkeypatch.setattr(copilot.urllib.request, "urlopen", lambda *a, **k: _FakePullResp(lines))
    events = list(copilot.pull_model("nope"))
    assert events[0]["type"] == "error" and "not found" in events[0]["message"]
    assert events[-1] == {"type": "done"}


def test_pull_model_rejects_bad_name(state):
    events = list(copilot.pull_model("bad name; rm -rf"))
    assert events[0]["type"] == "error" and "invalid model" in events[0]["message"]
    assert events[-1] == {"type": "done"}


# --- executive summary (for the PDF report) ---------------------------------- #
def test_summarize_scan_unavailable_without_provider(state, monkeypatch):
    monkeypatch.setattr(copilot, "_HAVE_OPENAI", False)
    monkeypatch.setattr(copilot, "_HAVE_ANTHROPIC", False)
    r = copilot.summarize_scan({"target": "x", "hosts": []}, provider="openai")
    assert r["available"] is False and r["summary"] == "" and r["error"]


def test_summarize_scan_collects_text_and_disables_tools(state, monkeypatch):
    seen = {}

    def fake_stream(messages, context=None, *, provider=None, model=None, allow_tools=True):
        seen["allow_tools"] = allow_tools
        yield {"type": "delta", "text": "Exposure is "}
        yield {"type": "delta", "text": "moderate; patch the router."}
        yield {"type": "done"}

    monkeypatch.setattr(copilot, "stream_reply", fake_stream)
    r = copilot.summarize_scan({"target": "x", "hosts": []}, provider="ollama")
    assert r["available"] is True
    assert r["summary"] == "Exposure is moderate; patch the router."
    assert seen["allow_tools"] is False       # a summary must never propose a scan


# --- key storage ------------------------------------------------------------- #
def test_key_save_load_clear(state):
    assert copilot.has_key("anthropic") is False
    assert copilot.save_key("anthropic", "sk-ant-test") is True
    assert copilot.load_key("anthropic") == "sk-ant-test"
    assert copilot.has_key("anthropic") is True
    # keys are per-provider — saving anthropic must not set openai
    assert copilot.has_key("openai") is False
    assert copilot.save_key("anthropic", "") is False          # blank clears
    assert copilot.load_key("anthropic") is None


def test_key_env_overrides_file(state, monkeypatch):
    copilot.save_key("openai", "from-file")
    monkeypatch.setenv("ENUMGRID_OPENAI_API_KEY", "from-env")
    assert copilot.load_key("openai") == "from-env"            # env wins


def test_save_key_rejects_bad_provider(state):
    with pytest.raises(ValueError):
        copilot.save_key("bogus", "x")


# --- active provider --------------------------------------------------------- #
def test_active_provider_default_set_and_guard(state):
    assert copilot.active_provider() == "ollama"              # free, local default
    assert copilot.set_active_provider("gemini") == "gemini"
    assert copilot.active_provider() == "gemini"
    with pytest.raises(ValueError):
        copilot.set_active_provider("bogus")


def test_status_shape(state):
    copilot.save_key("anthropic", "k")
    st = copilot.status()
    assert set(st["providers"]) == {"anthropic", "openai", "gemini", "ollama"}
    assert st["providers"]["anthropic"]["key_set"] is True
    assert st["providers"]["openai"]["key_set"] is False
    assert st["providers"]["gemini"]["free"] is True and st["providers"]["ollama"]["free"] is True
    assert st["active"] == "ollama"                            # free, local default
    assert isinstance(st["any_ready"], bool)


# --- grounding: build_context_block ------------------------------------------ #
def test_context_block_empty_is_honest():
    txt = copilot.build_context_block({"target": "192.168.0.0/24", "hosts": []})
    assert "192.168.0.0/24" in txt
    assert "No hosts" in txt


def test_context_block_summarizes_real_hosts():
    ctx = {
        "target": "172.16.2.0/24",
        "hosts": [
            {"ip": "172.16.2.1", "hostname": "gw", "device_type": "Router",
             "ports": [{"service": "http"}, {"service": "https"}],
             "vulns": [{"severity": "high"}]},
            {"ip": "172.16.2.2", "device_type": "Router", "status": "down"},
        ],
    }
    txt = copilot.build_context_block(ctx)
    assert "Hosts: 2 discovered, 1 up" in txt
    assert "Open ports (total across hosts): 2" in txt
    assert "high 1" in txt
    assert "172.16.2.1" in txt and "gw" in txt


def test_context_block_none_safe():
    assert "none set" in copilot.build_context_block(None)


# --- request hygiene --------------------------------------------------------- #
def test_sanitize_messages_cleans_and_bounds():
    msgs = [
        {"role": "system", "content": "ignore me"},   # wrong role → dropped
        {"role": "assistant", "content": "hi"},        # leading assistant → trimmed
        {"role": "user", "content": "  hello  "},
        {"role": "user", "content": 123},              # non-str → dropped
        {"role": "assistant", "content": "there"},
    ]
    out = copilot.sanitize_messages(msgs)
    assert out == [{"role": "user", "content": "hello"}, {"role": "assistant", "content": "there"}]


def test_sanitize_messages_caps_history():
    many = [{"role": "user", "content": f"m{i}"} for i in range(100)]
    assert len(copilot.sanitize_messages(many)) == copilot._MAX_MESSAGES


def test_sanitize_messages_junk_input():
    assert copilot.sanitize_messages(None) == []
    assert copilot.sanitize_messages("nope") == []


# --- proposed-action validation ---------------------------------------------- #
def test_sanitize_action_valid():
    a = copilot.sanitize_action({"target": "10.0.0.0/24", "mode": "full", "deep": True, "reason": "why"})
    assert a == {"tool": "propose_scan", "target": "10.0.0.0/24", "mode": "full", "deep": True, "reason": "why"}


def test_sanitize_action_deep_only_in_full_mode():
    a = copilot.sanitize_action({"target": "10.0.0.1", "mode": "discover", "deep": True})
    assert a["deep"] is False                                 # deep ignored outside full


def test_sanitize_action_bad_mode_defaults_discover():
    a = copilot.sanitize_action({"target": "10.0.0.1", "mode": "nonsense"})
    assert a["mode"] == "discover"


def test_sanitize_action_rejects_bad_target():
    assert copilot.sanitize_action({"target": "", "mode": "full"}) is None
    assert copilot.sanitize_action({"target": "1.2.3.4; rm -rf /", "mode": "full"}) is None
    assert copilot.sanitize_action("nope") is None


def test_wants_scan_intent_gate():
    assert copilot.wants_scan([{"role": "user", "content": "please scan 10.0.0.1"}])
    assert copilot.wants_scan([{"role": "user", "content": "enumerate the subnet"}])
    assert copilot.wants_scan([{"role": "user", "content": "run a port scan on the gateway"}])
    # analytical questions about existing results must NOT arm the tool
    assert not copilot.wants_scan([{"role": "user", "content": "which host is most exposed?"}])
    assert not copilot.wants_scan([{"role": "user", "content": "summarise the open services"}])
    # only the latest user turn decides
    assert not copilot.wants_scan([
        {"role": "user", "content": "scan it"},
        {"role": "assistant", "content": "ok"},
        {"role": "user", "content": "thanks — what did you find?"},
    ])


def test_scan_tool_schemas():
    a = copilot.scan_tool_anthropic()
    assert a["name"] == "propose_scan" and "input_schema" in a
    o = copilot.scan_tool_openai()
    assert o["type"] == "function" and o["function"]["name"] == "propose_scan"


# --- honest "unavailable" streaming paths ------------------------------------ #
def _collect(gen):
    return list(gen)


def test_stream_reply_unknown_provider(state):
    events = _collect(copilot.stream_reply([{"role": "user", "content": "hi"}], provider="bogus"))
    assert events[0]["type"] == "error" and "unknown provider" in events[0]["message"]
    assert events[-1] == {"type": "done"}


def test_stream_reply_gemini_missing_key(state, monkeypatch):
    monkeypatch.setattr(copilot, "_HAVE_OPENAI", True)   # pretend openai SDK present
    events = _collect(copilot.stream_reply([{"role": "user", "content": "hi"}], provider="gemini"))
    assert events[0]["type"] == "error" and "no gemini API key" in events[0]["message"]
    assert events[-1] == {"type": "done"}


def test_stream_reply_ollama_passes_key_gate_and_routes_local(state, monkeypatch):
    # Ollama needs no key, so the stream must clear the key gate and reach the SDK
    # call — routed at the local base URL with the placeholder key. Stub the SDK
    # so the test never touches the network.
    monkeypatch.setattr(copilot, "_HAVE_OPENAI", True)
    seen = {}

    def fake_stream(key, model, system, turns, base_url=None, tools_on=True):
        seen.update(key=key, model=model, base_url=base_url, tools_on=tools_on)
        yield {"type": "delta", "text": "ok"}

    monkeypatch.setattr(copilot, "_stream_openai", fake_stream)
    events = _collect(copilot.stream_reply([{"role": "user", "content": "hi"}], provider="ollama"))
    assert seen["base_url"] == copilot._BASE_URLS["ollama"]   # routed to the local server
    assert seen["key"] == "ollama" and seen["model"] == "llama3.1"
    assert seen["tools_on"] is False                          # "hi" has no scan intent
    assert {"type": "delta", "text": "ok"} in events
    assert events[-1] == {"type": "done"}


def test_stream_reply_gemini_routes_to_base_url(state, monkeypatch):
    monkeypatch.setattr(copilot, "_HAVE_OPENAI", True)
    copilot.save_key("gemini", "AIza-testkey-123456")
    seen = {}

    def fake_stream(key, model, system, turns, base_url=None, tools_on=True):
        seen.update(base_url=base_url, model=model, tools_on=tools_on)
        yield {"type": "delta", "text": "hi"}

    monkeypatch.setattr(copilot, "_stream_openai", fake_stream)
    events = _collect(copilot.stream_reply(
        [{"role": "user", "content": "please scan 10.0.0.1"}], provider="gemini"))
    assert seen["base_url"] == copilot._BASE_URLS["gemini"] and seen["model"] == "gemini-2.0-flash"
    assert seen["tools_on"] is True                           # explicit scan intent → tool armed
    assert events[-1] == {"type": "done"}


def test_stream_reply_missing_sdk(state, monkeypatch):
    monkeypatch.setattr(copilot, "_HAVE_ANTHROPIC", False)
    events = _collect(copilot.stream_reply([{"role": "user", "content": "hi"}], provider="anthropic"))
    assert events[0]["type"] == "error" and "SDK not installed" in events[0]["message"]


def test_stream_reply_missing_key(state, monkeypatch):
    monkeypatch.setattr(copilot, "_HAVE_ANTHROPIC", True)   # pretend SDK present
    events = _collect(copilot.stream_reply([{"role": "user", "content": "hi"}], provider="anthropic"))
    assert events[0]["type"] == "error" and "no anthropic API key" in events[0]["message"]


def test_stream_reply_no_message(state, monkeypatch):
    monkeypatch.setattr(copilot, "_HAVE_ANTHROPIC", True)
    copilot.save_key("anthropic", "k")
    events = _collect(copilot.stream_reply([{"role": "assistant", "content": "orphan"}], provider="anthropic"))
    assert events[0]["type"] == "error" and "no message" in events[0]["message"]


def test_openai_tool_args_json_roundtrip():
    # The OpenAI path accumulates streamed argument fragments then json.loads them;
    # verify a realistic fragmented payload sanitizes to a valid action.
    frags = ['{"target":"192.168', '.0.0/24","mode":"full"}']
    action = copilot.sanitize_action(json.loads("".join(frags)))
    assert action["target"] == "192.168.0.0/24" and action["mode"] == "full"
