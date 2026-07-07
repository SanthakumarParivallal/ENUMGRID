"""
copilot.py — the ENUMGRID AI copilot: a security-analyst chatbot that is
**grounded in the live scan** and can **propose actions** (scans) for the
operator to confirm.

Design
------
* **Two providers, switchable** — Anthropic Claude (default) and OpenAI. Each is
  an *optional* dependency (`anthropic` / `openai`); when a provider's SDK or key
  is missing we say so honestly (`available: false` + reason) and never fake a
  reply. The operator pastes their own key in the dashboard (persisted 0600,
  gitignored, never logged) — mirroring the NVD-key pattern in ``cve.py``.
* **Grounded** — every request carries a compact, real summary of the current
  scan (hosts, open ports, services, CVEs, severities) built by
  ``build_context_block``. The model answers about *your* network, not in the
  abstract. No scan data is invented.
* **Agentic, human-in-the-loop** — the model may call the ``propose_scan`` tool.
  We do **not** execute it; we surface it as an ``action`` event and the cockpit
  renders a confirm button that runs the normal, scope-vetted scan endpoint. A
  security tool must never launch a scan the operator didn't approve.

The pure pieces (key storage, context building, message/action sanitising, tool
schemas, provider/status logic) are unit-tested with no SDK, no key, no network.
The streaming calls (``stream_reply``) are integration-only.
"""

from __future__ import annotations

import json
import os
import re

try:  # Anthropic Claude — optional (the operator may only use OpenAI, or neither).
    import anthropic  # type: ignore

    _HAVE_ANTHROPIC = True
except Exception:  # noqa: BLE001 - any import/link error means "provider unavailable"
    _HAVE_ANTHROPIC = False

try:  # OpenAI — optional.
    import openai  # type: ignore

    _HAVE_OPENAI = True
except Exception:  # noqa: BLE001
    _HAVE_OPENAI = False

_DIR = os.path.dirname(os.path.abspath(__file__))

# Where per-provider keys + the active-provider choice persist (0600, gitignored).
# A single base dir keeps tests trivial (monkeypatch `_STATE_DIR` → tmp_path).
_STATE_DIR = os.environ.get("ENUMGRID_COPILOT_DIR", _DIR)

PROVIDERS = ("anthropic", "openai")
_DEFAULT_PROVIDER = "anthropic"

# Latest, most capable defaults; overridable per deployment via env. The operator
# can also override the model per-provider without touching code.
_DEFAULT_MODELS = {
    "anthropic": os.environ.get("ENUMGRID_ANTHROPIC_MODEL", "claude-opus-4-8"),
    "openai": os.environ.get("ENUMGRID_OPENAI_MODEL", "gpt-4o"),
}
_ENV_KEYS = {"anthropic": "ENUMGRID_ANTHROPIC_API_KEY", "openai": "ENUMGRID_OPENAI_API_KEY"}

_MAX_TOKENS = 4096          # a chat reply; streaming means no HTTP-timeout worry
_MAX_MESSAGES = 24          # keep the request bounded (drop the oldest turns)
_MAX_MSG_CHARS = 8000       # clamp any single message

SYSTEM_PROMPT = (
    "You are the ENUMGRID Copilot — a concise, expert security analyst embedded in "
    "a network-enumeration cockpit. You help the operator understand and act on the "
    "results of their own authorized scans.\n\n"
    "Rules:\n"
    "- Ground every answer in the SCAN CONTEXT provided below. If the context does "
    "not contain the answer, say so plainly — never invent hosts, ports, CVEs, or "
    "versions.\n"
    "- Be practical and specific: explain findings, prioritise by real risk "
    "(exploitability + exposure, not just CVSS), and suggest concrete next steps.\n"
    "- Authorized use only. Only ever discuss or propose scanning the operator's own "
    "in-scope networks. Never help with unauthorized access, exploitation, evasion, "
    "or attacking third parties.\n"
    "- When a scan would genuinely help answer the request, call the `propose_scan` "
    "tool. It does not run the scan — it suggests one the operator can confirm.\n"
    "- Keep replies tight. Lead with the answer; use short lists over long prose."
)


# --- key storage (mirrors cve.py: env wins, else 0600 file) ------------------- #
def _key_file(provider: str) -> str:
    return os.path.join(_STATE_DIR, f".enumgrid_{provider}_key")


def _provider_file() -> str:
    return os.path.join(_STATE_DIR, ".enumgrid_copilot_provider")


def _read_file(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def _write_secret(path: str, value: str | None) -> None:
    """Persist (0600) or remove a secret file. Best-effort; never logs the value."""
    try:
        if value:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(value)
            os.chmod(path, 0o600)
        elif os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def valid_provider(provider: str | None) -> bool:
    return provider in PROVIDERS


def sdk_available(provider: str) -> bool:
    return {"anthropic": _HAVE_ANTHROPIC, "openai": _HAVE_OPENAI}.get(provider, False)


def load_key(provider: str) -> str | None:
    """The active key for a provider: explicit env var wins, else the saved file."""
    if not valid_provider(provider):
        return None
    return os.environ.get(_ENV_KEYS[provider]) or _read_file(_key_file(provider))


def has_key(provider: str) -> bool:
    return bool(load_key(provider))


def save_key(provider: str, key: str | None) -> bool:
    """Persist (or clear) a provider key. Returns True if a key is now set.

    An env-provided key can't be cleared from disk here, but a pasted key is
    saved owner-only and survives a restart. The value is never logged."""
    if not valid_provider(provider):
        raise ValueError(f"unknown provider '{provider}'")
    key = (key or "").strip()
    _write_secret(_key_file(provider), key or None)
    return has_key(provider)


def active_provider() -> str:
    """The currently-selected provider (persisted; env override; default anthropic)."""
    chosen = os.environ.get("ENUMGRID_COPILOT_PROVIDER") or _read_file(_provider_file())
    return chosen if valid_provider(chosen) else _DEFAULT_PROVIDER


def set_active_provider(provider: str) -> str:
    if not valid_provider(provider):
        raise ValueError(f"unknown provider '{provider}'")
    _write_secret(_provider_file(), provider)
    return provider


def default_model(provider: str) -> str:
    return _DEFAULT_MODELS.get(provider, "")


def status() -> dict:
    """Everything the dashboard needs to render the copilot + key-upload UI.

    Never includes key values — only whether each provider is usable."""
    prov = {
        name: {
            "sdk_installed": sdk_available(name),
            "key_set": has_key(name),
            "model": default_model(name),
            "ready": sdk_available(name) and has_key(name),
        }
        for name in PROVIDERS
    }
    active = active_provider()
    return {
        "providers": prov,
        "active": active,
        "ready": prov.get(active, {}).get("ready", False),
        "any_ready": any(p["ready"] for p in prov.values()),
    }


# --- grounding: turn the live scan into a compact context block --------------- #
def _top_counts(items, key: str, limit: int = 6) -> list:
    counts: dict[str, int] = {}
    for it in items or []:
        val = (it or {}).get(key)
        if val:
            counts[str(val)] = counts.get(str(val), 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]


def build_context_block(context: dict | None) -> str:
    """A short, real, deterministic summary of the current scan for the model.

    Uses only what's actually in `context` (the dashboard's live state). Empty or
    partial input degrades gracefully — it never fabricates a scan."""
    ctx = context or {}
    target = str(ctx.get("target") or "").strip()
    hosts = ctx.get("hosts") if isinstance(ctx.get("hosts"), list) else []
    lines = ["SCAN CONTEXT (the operator's current authorized scan):"]
    lines.append(f"- Target: {target or 'none set'}")
    if not hosts:
        lines.append("- No hosts in the current buffer yet (no scan run, or none found).")
        return "\n".join(lines)

    up = sum(1 for h in hosts if (h or {}).get("status", "up") != "down")
    open_ports = sum(len((h or {}).get("ports") or (h or {}).get("open_ports") or []) for h in hosts)
    vulns = [v for h in hosts for v in ((h or {}).get("vulns") or (h or {}).get("cves") or [])]
    sev = _top_counts(vulns, "severity", limit=5)
    lines.append(f"- Hosts: {len(hosts)} discovered, {up} up")
    lines.append(f"- Open ports (total across hosts): {open_ports}")
    lines.append(f"- Vulnerabilities: {len(vulns)}" + (
        f" (by severity: {', '.join(f'{s} {n}' for s, n in sev)})" if sev else ""))
    services = _top_counts(
        [{"service": p.get("service")} for h in hosts
         for p in ((h or {}).get("ports") or (h or {}).get("open_ports") or []) if isinstance(p, dict)],
        "service", limit=8)
    if services:
        lines.append("- Top services: " + ", ".join(f"{s}×{n}" for s, n in services))
    devices = _top_counts(hosts, "device_type", limit=6)
    if devices:
        lines.append("- Device mix: " + ", ".join(f"{d}×{n}" for d, n in devices))

    # A few concrete host rows so the model can reference real IPs/hostnames.
    sample = []
    for h in hosts[:12]:
        h = h or {}
        ip = h.get("ip") or h.get("address") or "?"
        bits = [str(ip)]
        if h.get("hostname"):
            bits.append(str(h["hostname"]))
        if h.get("os") and h["os"] != "Unknown":
            bits.append(str(h["os"]))
        nports = len(h.get("ports") or h.get("open_ports") or [])
        if nports:
            bits.append(f"{nports} port(s)")
        sample.append("  · " + " / ".join(bits))
    if sample:
        lines.append("- Sample hosts:")
        lines.extend(sample)
    return "\n".join(lines)


# --- request hygiene ---------------------------------------------------------- #
def sanitize_messages(messages) -> list[dict]:
    """Coerce client chat history into clean {role, content} turns.

    Drops junk, clamps length, keeps only the last _MAX_MESSAGES, and guarantees
    the sequence starts with a user turn (providers require it)."""
    out: list[dict] = []
    for m in messages if isinstance(messages, list) else []:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        content = m.get("content")
        if role not in ("user", "assistant") or not isinstance(content, str):
            continue
        content = content.strip()
        if not content:
            continue
        out.append({"role": role, "content": content[:_MAX_MSG_CHARS]})
    out = out[-_MAX_MESSAGES:]
    while out and out[0]["role"] != "user":  # providers require a leading user turn
        out.pop(0)
    return out


_SCAN_PARAMS = {
    "type": "object",
    "properties": {
        "target": {"type": "string",
                   "description": "IP, CIDR, range, or hostname to scan (must be in the operator's authorized scope)"},
        "mode": {"type": "string", "enum": ["discover", "full"],
                 "description": "discover = fast host inventory; full = nmap service/version detection"},
        "deep": {"type": "boolean", "description": "full mode only: also run NSE vulnerability scripts"},
        "reason": {"type": "string", "description": "one short sentence: why this scan helps"},
    },
    "required": ["target", "mode"],
}


def scan_tool_anthropic() -> dict:
    return {"name": "propose_scan",
            "description": "Propose (do not run) a scan the operator can confirm and launch.",
            "input_schema": _SCAN_PARAMS}


def scan_tool_openai() -> dict:
    return {"type": "function", "function": {
        "name": "propose_scan",
        "description": "Propose (do not run) a scan the operator can confirm and launch.",
        "parameters": _SCAN_PARAMS}}


def sanitize_action(raw) -> dict | None:
    """Validate a model-proposed scan into a safe, minimal action dict, or None.

    This is only a *proposal* surfaced to the UI — the real scope check happens
    when the operator confirms and the normal scan endpoint runs `vet_target`."""
    if not isinstance(raw, dict):
        return None
    target = str(raw.get("target") or "").strip()
    if not target or len(target) > 128 or not re.fullmatch(r"[A-Za-z0-9._:/\- ]+", target):
        return None
    mode = raw.get("mode") if raw.get("mode") in ("discover", "full") else "discover"
    reason = str(raw.get("reason") or "").strip()[:200]
    return {"tool": "propose_scan", "target": target, "mode": mode,
            "deep": bool(raw.get("deep")) and mode == "full", "reason": reason}


# --- streaming (integration-only; needs an SDK + a key) ----------------------- #
def _unavailable(reason: str):
    yield {"type": "error", "message": reason}
    yield {"type": "done"}


def stream_reply(messages, context=None, *, provider: str | None = None, model: str | None = None):
    """Yield copilot events for one turn: ``{'type':'delta','text':...}`` chunks,
    an optional ``{'type':'action','action':{...}}`` proposal, ``error``, ``done``.

    Provider- and SDK-agnostic; degrades to an honest error event when a provider,
    SDK, or key is missing (never a fake answer)."""
    provider = provider or active_provider()
    if not valid_provider(provider):
        yield from _unavailable(f"unknown provider '{provider}'"); return
    if not sdk_available(provider):
        pkg = "anthropic" if provider == "anthropic" else "openai"
        yield from _unavailable(f"{provider} SDK not installed (pip install {pkg})"); return
    key = load_key(provider)
    if not key:
        yield from _unavailable(f"no {provider} API key set — add one in the dashboard"); return
    turns = sanitize_messages(messages)
    if not turns:
        yield from _unavailable("no message to send"); return
    model = model or default_model(provider)
    system = SYSTEM_PROMPT + "\n\n" + build_context_block(context)
    try:
        if provider == "anthropic":
            yield from _stream_anthropic(key, model, system, turns)
        else:
            yield from _stream_openai(key, model, system, turns)
    except Exception as exc:  # noqa: BLE001 - surface any provider error honestly
        reason = " ".join(str(exc).split()).strip() or type(exc).__name__
        yield {"type": "error", "message": reason[:300]}
    yield {"type": "done"}


def _stream_anthropic(key: str, model: str, system: str, turns: list[dict]):
    client = anthropic.Anthropic(api_key=key)
    with client.messages.stream(
        model=model, max_tokens=_MAX_TOKENS, system=system,
        tools=[scan_tool_anthropic()], messages=turns,
    ) as stream:
        for text in stream.text_stream:
            if text:
                yield {"type": "delta", "text": text}
        final = stream.get_final_message()
    for block in getattr(final, "content", []) or []:
        if getattr(block, "type", None) == "tool_use" and getattr(block, "name", "") == "propose_scan":
            action = sanitize_action(getattr(block, "input", None))
            if action:
                yield {"type": "action", "action": action}
            break


def _stream_openai(key: str, model: str, system: str, turns: list[dict]):
    client = openai.OpenAI(api_key=key)
    messages = [{"role": "system", "content": system}, *turns]
    tool_args: dict[int, str] = {}
    tool_seen = False
    stream = client.chat.completions.create(
        model=model, messages=messages, tools=[scan_tool_openai()],
        stream=True, max_tokens=_MAX_TOKENS,
    )
    for chunk in stream:
        choice = (chunk.choices or [None])[0]
        delta = getattr(choice, "delta", None)
        if delta is None:
            continue
        if getattr(delta, "content", None):
            yield {"type": "delta", "text": delta.content}
        for tc in getattr(delta, "tool_calls", None) or []:
            tool_seen = True
            idx = getattr(tc, "index", 0) or 0
            frag = getattr(getattr(tc, "function", None), "arguments", None)
            if frag:
                tool_args[idx] = tool_args.get(idx, "") + frag
    if tool_seen:
        for raw in tool_args.values():
            try:
                action = sanitize_action(json.loads(raw))
            except (ValueError, TypeError):
                action = None
            if action:
                yield {"type": "action", "action": action}
                break
