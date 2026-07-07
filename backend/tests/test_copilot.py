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
    """Isolate key/provider files to a temp dir and clear any env overrides."""
    monkeypatch.setattr(copilot, "_STATE_DIR", str(tmp_path))
    for var in ("ENUMGRID_ANTHROPIC_API_KEY", "ENUMGRID_OPENAI_API_KEY", "ENUMGRID_COPILOT_PROVIDER"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


# --- providers / validation -------------------------------------------------- #
def test_valid_provider():
    assert copilot.valid_provider("anthropic") and copilot.valid_provider("openai")
    assert not copilot.valid_provider("gemini") and not copilot.valid_provider(None)


def test_default_model_and_sdk_available():
    assert copilot.default_model("anthropic") == "claude-opus-4-8"
    assert copilot.default_model("openai") == "gpt-4o"
    assert isinstance(copilot.sdk_available("anthropic"), bool)


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
        copilot.save_key("gemini", "x")


# --- active provider --------------------------------------------------------- #
def test_active_provider_default_set_and_guard(state):
    assert copilot.active_provider() == "anthropic"           # default
    assert copilot.set_active_provider("openai") == "openai"
    assert copilot.active_provider() == "openai"
    with pytest.raises(ValueError):
        copilot.set_active_provider("bogus")


def test_status_shape(state):
    copilot.save_key("anthropic", "k")
    st = copilot.status()
    assert set(st["providers"]) == {"anthropic", "openai"}
    assert st["providers"]["anthropic"]["key_set"] is True
    assert st["providers"]["openai"]["key_set"] is False
    assert st["active"] == "anthropic"
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


def test_scan_tool_schemas():
    a = copilot.scan_tool_anthropic()
    assert a["name"] == "propose_scan" and "input_schema" in a
    o = copilot.scan_tool_openai()
    assert o["type"] == "function" and o["function"]["name"] == "propose_scan"


# --- honest "unavailable" streaming paths ------------------------------------ #
def _collect(gen):
    return list(gen)


def test_stream_reply_unknown_provider(state):
    events = _collect(copilot.stream_reply([{"role": "user", "content": "hi"}], provider="gemini"))
    assert events[0]["type"] == "error" and "unknown provider" in events[0]["message"]
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
