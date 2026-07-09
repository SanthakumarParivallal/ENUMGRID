"""
copilot.py — the ENUMGRID AI copilot: a security-analyst chatbot that is
**grounded in the live scan** and can **propose actions** (scans) for the
operator to confirm.

Design
------
* **Four providers, switchable — two of them free** — Anthropic Claude and OpenAI
  (paid), plus **Ollama** (a model running *locally* — no key, no cloud, no cost)
  and **Google Gemini** (a generous free tier). Ollama and Gemini both speak the
  OpenAI wire protocol, so they reuse the OpenAI code path with a different base
  URL. Each provider is an *optional* dependency (`anthropic` for Claude; the
  `openai` SDK powers OpenAI **and** Gemini **and** Ollama); when a provider's SDK
  or key is missing we say so honestly (`ready: false` + reason) and never fake a
  reply. The operator pastes their own key in the dashboard (persisted 0600,
  gitignored, never logged) — mirroring the NVD-key pattern in ``cve.py``. Ollama
  needs no key at all; it just needs the local Ollama server running.
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
import socket
import urllib.request
from urllib.parse import urlparse

try:  # Anthropic Claude — optional (the operator may only use OpenAI, or neither).
    import anthropic  # type: ignore

    _HAVE_ANTHROPIC = True
except Exception:  # noqa: BLE001  # pragma: no cover - optional dependency; import/link error means unavailable
    _HAVE_ANTHROPIC = False

try:  # OpenAI — optional.
    import openai  # type: ignore

    _HAVE_OPENAI = True
except Exception:  # noqa: BLE001  # pragma: no cover - optional dependency; import/link error means unavailable
    _HAVE_OPENAI = False

_DIR = os.path.dirname(os.path.abspath(__file__))

# Where per-provider keys + the active-provider choice persist (0600, gitignored).
# A single base dir keeps tests trivial (monkeypatch `_STATE_DIR` → tmp_path).
_STATE_DIR = os.environ.get("ENUMGRID_COPILOT_DIR", _DIR)

PROVIDERS = ("ollama", "gemini", "anthropic", "openai")
# Default to the free, local, keyless provider so a fresh install works without a
# paid key. The operator can switch to any provider in the dashboard.
_DEFAULT_PROVIDER = "ollama"

# Providers that don't need an API key. Ollama runs locally and authenticates by
# nothing more than reaching the local server.
_KEYLESS = frozenset({"ollama"})

# OpenAI-compatible providers reuse the `openai` SDK against a different base URL.
# `openai` itself uses the SDK default (None → api.openai.com).
_BASE_URLS = {
    "openai": None,
    "gemini": os.environ.get(
        "ENUMGRID_GEMINI_URL", "https://generativelanguage.googleapis.com/v1beta/openai/"),
    "ollama": os.environ.get("ENUMGRID_OLLAMA_URL", "http://localhost:11434/v1"),
}

# Latest, most capable defaults; overridable per deployment via env. The operator
# can also override the model per-provider without touching code. The free
# defaults (Gemini flash, Llama 3.1) are chosen to support tool use.
_DEFAULT_MODELS = {
    "anthropic": os.environ.get("ENUMGRID_ANTHROPIC_MODEL", "claude-opus-4-8"),
    "openai": os.environ.get("ENUMGRID_OPENAI_MODEL", "gpt-4o"),
    "gemini": os.environ.get("ENUMGRID_GEMINI_MODEL", "gemini-2.0-flash"),
    "ollama": os.environ.get("ENUMGRID_OLLAMA_MODEL", "llama3.1"),
}
_ENV_KEYS = {
    "anthropic": "ENUMGRID_ANTHROPIC_API_KEY",
    "openai": "ENUMGRID_OPENAI_API_KEY",
    "gemini": "ENUMGRID_GEMINI_API_KEY",
    "ollama": "ENUMGRID_OLLAMA_API_KEY",
}

_MAX_TOKENS = 4096          # a chat reply; streaming means no HTTP-timeout worry
_MAX_MESSAGES = 24          # keep the request bounded (drop the oldest turns)
_MAX_MSG_CHARS = 8000       # clamp any single message
# A security analyst should be factual, not creative. A low temperature keeps the
# copilot grounded and consistent (Ollama's default ~0.8 makes small models ramble
# and invent). Tunable, but low by default.
_TEMPERATURE = float(os.environ.get("ENUMGRID_COPILOT_TEMPERATURE", "0.2"))

# Curated Ollama models the dashboard offers as one-click downloads. All three
# support tool use (needed for the propose_scan action). Ordered lightest-first so
# a low-RAM machine has an obvious safe pick; `llama3.1` is the balanced default.
_OLLAMA_RECOMMENDED = (
    {"name": "llama3.2", "label": "Llama 3.2 (3B)", "size": "~2 GB",
     "note": "Lightest — good on ~8 GB RAM"},
    {"name": "llama3.1", "label": "Llama 3.1 (8B)", "size": "~4.7 GB",
     "note": "Balanced default — needs ~16 GB RAM", "recommended": True},
    {"name": "qwen2.5", "label": "Qwen 2.5 (7B)", "size": "~4.7 GB",
     "note": "Strong reasoning + tool use"},
)
# A safe Ollama model tag: starts alphanumeric, then the usual name/tag characters.
_MODEL_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/\-]{0,63}")

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
    "- ALWAYS answer the question directly in text, using the SCAN CONTEXT. NEVER "
    "call a tool instead of answering. For any question about the existing results "
    "(which host is exposed, what's running, what are the risks), just answer in "
    "prose — do not call `propose_scan`.\n"
    "- Only call `propose_scan` when the operator explicitly asks to scan/enumerate "
    "something, or when answering truly needs data on a host not yet in the context — "
    "and even then, give your text answer first. It suggests a scan the operator "
    "confirms; it never runs one.\n"
    "- Authorized use only. Only ever discuss or propose scanning the operator's own "
    "in-scope networks. Never help with unauthorized access, exploitation, evasion, "
    "or attacking third parties.\n"
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
    # Gemini and Ollama are OpenAI-wire-compatible, so they ride the `openai` SDK.
    if provider == "anthropic":
        return _HAVE_ANTHROPIC
    if provider in ("openai", "gemini", "ollama"):
        return _HAVE_OPENAI
    return False


def requires_key(provider: str) -> bool:
    """Whether the provider needs an API key (Ollama runs locally, so it doesn't)."""
    return provider not in _KEYLESS


def _ollama_root() -> str:
    """The Ollama *native* API root (its OpenAI-compat base minus the ``/v1``)."""
    base = _BASE_URLS["ollama"].rstrip("/")
    return base[:-3].rstrip("/") if base.endswith("/v1") else base


def _tcp_up(timeout: float = 0.35) -> bool:
    """Fast TCP connect to the Ollama host:port. Never raises."""
    try:
        parsed = urlparse(_BASE_URLS["ollama"])
        with socket.create_connection((parsed.hostname or "localhost", parsed.port or 11434),
                                      timeout=timeout):
            return True
    except OSError:
        return False


def ollama_probe(timeout: float = 0.6) -> dict:
    """Ask the local Ollama server what it has: ``{'up': bool, 'models': [names]}``.

    A single cheap call powers the whole setup UX — is the server running, and which
    models are already pulled. Never raises (a down/absent server → ``up: False``)."""
    if not _tcp_up():                       # avoid a slow HTTP wait when nothing listens
        return {"up": False, "models": []}
    try:
        with urllib.request.urlopen(f"{_ollama_root()}/api/tags", timeout=timeout) as resp:  # nosec B310 - fixed local Ollama endpoint, scheme not user-controlled
            # Cap the read: a hostile process squatting on the port shouldn't be able
            # to balloon memory. A real tags listing is tiny.
            data = json.loads(resp.read(2_000_000).decode("utf-8", "replace") or "{}")
        models = [m.get("name") for m in (data.get("models") or [])
                  if isinstance(m, dict) and m.get("name")]
        return {"up": True, "models": models}
    except (OSError, ValueError):
        return {"up": True, "models": []}   # server answered TCP but tags failed — still "up"


def _model_installed(name: str, models) -> bool:
    """Whether ``name`` (e.g. ``llama3.1``) matches an installed tag (``llama3.1:latest``)."""
    if not name:
        return False
    base = name.split(":")[0]
    return any(m == name or m.split(":")[0] == base for m in (models or []))


def valid_model_name(name: str | None) -> bool:
    return bool(name) and bool(_MODEL_NAME_RE.fullmatch(name.strip()))


def _model_file(provider: str) -> str:
    return os.path.join(_STATE_DIR, f".enumgrid_{provider}_model")


def active_model(provider: str) -> str:
    """The model to use for a provider: an operator override (persisted) else the
    built-in default. Lets the operator pick from their installed Ollama models."""
    return _read_file(_model_file(provider)) or default_model(provider)


def set_model(provider: str, model: str | None) -> str:
    """Persist (or clear → revert to default) the model for a provider."""
    if not valid_provider(provider):
        raise ValueError(f"unknown provider '{provider}'")
    model = (model or "").strip()
    if model and not valid_model_name(model):
        raise ValueError("invalid model name")
    _write_secret(_model_file(provider), model or None)
    return active_model(provider)


def _stored_key(provider: str) -> str | None:
    """A real key the operator supplied: env var wins, else the saved 0600 file."""
    env = _ENV_KEYS.get(provider)
    return (os.environ.get(env) if env else None) or _read_file(_key_file(provider))


def load_key(provider: str) -> str | None:
    """The key handed to the SDK. A real stored key wins; a keyless provider
    (Ollama) falls back to a harmless placeholder so the OpenAI client — which
    demands a non-empty ``api_key`` — is satisfied."""
    if not valid_provider(provider):
        return None
    key = _stored_key(provider)
    if key:
        return key
    return "ollama" if provider in _KEYLESS else None


def has_key(provider: str) -> bool:
    """Whether the operator has stored a real key (used for the status display).
    Keyless providers report False here but are still ``ready`` — see ``status``."""
    return bool(_stored_key(provider))


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
    prov = {}
    probe = None   # probe the local Ollama server at most once per status call
    for name in PROVIDERS:
        sdk = sdk_available(name)
        needs_key = requires_key(name)
        entry = {
            "sdk_installed": sdk,
            "key_set": has_key(name),
            "requires_key": needs_key,
            "local": name in _KEYLESS,
            "free": name in ("ollama", "gemini"),
            "server_up": None,          # only meaningful for the local provider
            "model": active_model(name),
        }
        if name == "ollama":
            if probe is None:
                probe = ollama_probe() if sdk else {"up": False, "models": []}
            entry["server_up"] = probe["up"]
            entry["models"] = probe["models"]
            entry["model_present"] = _model_installed(entry["model"], probe["models"])
            entry["recommended"] = list(_OLLAMA_RECOMMENDED)
            # Ready only when the server is up AND the chosen model is pulled — else
            # the UI guides setup (install / download) instead of a failing chat.
            entry["ready"] = sdk and probe["up"] and entry["model_present"]
        else:
            # Ready = SDK present and credentials satisfied (a real key OR none needed).
            entry["ready"] = sdk and (has_key(name) or not needs_key)
        prov[name] = entry
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


# Canonical CVE identifier shape, used both to feed REAL ids into the context and
# to catch any id a model emits that isn't backed by the scan (see the guard below).
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)


def _host_cve_ids(host: dict) -> list[str]:
    """Every CVE id attached to one host (from vuln id/cve/name/output), upper-cased."""
    out: list[str] = []
    for v in (host or {}).get("vulns") or (host or {}).get("cves") or []:
        if isinstance(v, dict):
            blob = " ".join(str(v.get(k, "")) for k in ("id", "cve", "name", "title", "output"))
        else:
            blob = str(v)
        out.extend(m.group(0).upper() for m in _CVE_ID_RE.finditer(blob))
    return out


def context_cve_ids(context: dict | None) -> set[str]:
    """The set of CVE ids that actually appear anywhere in the scan context."""
    ctx = context or {}
    hosts = ctx.get("hosts") if isinstance(ctx.get("hosts"), list) else []
    found: set[str] = set()
    for h in hosts:
        found.update(_host_cve_ids(h or {}))
    return found


def ungrounded_cves(text: str, known: set[str]) -> list[str]:
    """CVE ids cited in `text` that are NOT in `known` (deduped, first-seen order).

    This is the deterministic anti-hallucination guard: whatever a model writes,
    any CVE id it invents (not present in the real scan) is caught here."""
    seen: list[str] = []
    for m in _CVE_ID_RE.finditer(text or ""):
        cid = m.group(0).upper()
        if cid not in known and cid not in seen:
            seen.append(cid)
    return seen


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

    # The ACTUAL CVE ids found, with severity + host, so the model cites REAL ones
    # and never has to invent an identifier to answer "name the CVEs". Capped so a
    # busy scan can't blow up the prompt.
    cve_rows: list[str] = []
    seen_cve: set[str] = set()
    for h in hosts:
        h = h or {}
        ip = h.get("ip") or h.get("address") or "?"
        for v in (h.get("vulns") or h.get("cves") or []):
            vd = v if isinstance(v, dict) else {}
            ids = _host_cve_ids({"vulns": [v]})
            if not ids:
                continue
            cid = ids[0]
            if cid in seen_cve:
                continue
            seen_cve.add(cid)
            sev = str(vd.get("severity") or "").strip().lower()
            cve_rows.append(f"  · {cid}{f' [{sev}]' if sev else ''} on {ip}")
            if len(cve_rows) >= 25:
                break
        if len(cve_rows) >= 25:
            break
    if cve_rows:
        lines.append("- CVE findings (cite ONLY these exact ids; never invent another):")
        lines.extend(cve_rows)

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


# Only offer the propose_scan tool when the operator's latest message actually
# expresses scan intent. Small local models (e.g. Llama 3.2 3B) get confused when a
# tool is always present — they call it, or emit fake tool-call JSON as their text —
# so analytical questions ("which host is exposed?") should run tool-free and just
# answer. Bigger models are unaffected; this only removes spurious tool calls.
_SCAN_INTENT_RE = re.compile(
    r"\b(scan|enumerat\w*|nmap|probe|recon\w*|discover\w*|sweep|fingerprint|"
    r"port[\s-]?scan|pentest|brute\w*)\b", re.I)


def wants_scan(turns) -> bool:
    """True if the most recent user turn asks to scan/enumerate something."""
    for m in reversed(turns or []):
        if isinstance(m, dict) and m.get("role") == "user":
            return bool(_SCAN_INTENT_RE.search(str(m.get("content", ""))))
    return False


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


def stream_reply(messages, context=None, *, provider: str | None = None,
                 model: str | None = None, allow_tools: bool = True):
    """Yield copilot events for one turn: ``{'type':'delta','text':...}`` chunks,
    an optional ``{'type':'action','action':{...}}`` proposal, ``error``, ``done``.

    Provider- and SDK-agnostic; degrades to an honest error event when a provider,
    SDK, or key is missing (never a fake answer). ``allow_tools=False`` forces a
    pure text reply (used for report summaries)."""
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
    model = model or active_model(provider)
    system = SYSTEM_PROMPT + "\n\n" + build_context_block(context)
    # Only arm propose_scan when tools are allowed AND the operator asks to scan.
    tools_on = allow_tools and wants_scan(turns)
    try:
        if provider == "anthropic":
            yield from _stream_anthropic(key, model, system, turns, tools_on=tools_on)
        else:
            yield from _stream_openai(key, model, system, turns,
                                      base_url=_BASE_URLS.get(provider), tools_on=tools_on)
    except Exception as exc:  # noqa: BLE001 - surface any provider error honestly
        reason = " ".join(str(exc).split()).strip() or type(exc).__name__
        # Ollama is local: the usual failure is "server not started" — say so plainly.
        if provider == "ollama" and any(w in reason.lower() for w in ("connect", "refused", "connection")):
            reason = (f"Can't reach Ollama at {_BASE_URLS['ollama']}. Start it "
                      f"(`ollama serve`) and pull the model (`ollama pull {model}`).")
        yield {"type": "error", "message": reason[:300]}
    yield {"type": "done"}


def _stream_anthropic(key: str, model: str, system: str, turns: list[dict], tools_on: bool = True):
    client = anthropic.Anthropic(api_key=key)
    kwargs = {"model": model, "max_tokens": _MAX_TOKENS, "system": system,
              "messages": turns, "temperature": _TEMPERATURE}
    if tools_on:
        kwargs["tools"] = [scan_tool_anthropic()]
    with client.messages.stream(**kwargs) as stream:
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


def _stream_openai(key: str, model: str, system: str, turns: list[dict],
                   base_url: str | None = None, tools_on: bool = True):
    # `base_url` lets the same OpenAI SDK drive Gemini and a local Ollama server.
    client = openai.OpenAI(api_key=key, base_url=base_url) if base_url else openai.OpenAI(api_key=key)
    messages = [{"role": "system", "content": system}, *turns]
    tool_args: dict[int, str] = {}
    tool_seen = False
    kwargs = {"model": model, "messages": messages, "stream": True,
              "max_tokens": _MAX_TOKENS, "temperature": _TEMPERATURE}
    if tools_on:
        kwargs["tools"] = [scan_tool_openai()]
    stream = client.chat.completions.create(**kwargs)
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


# --- one-click Ollama model download (streamed progress) ---------------------- #
def pull_model(name: str, timeout: float = 120.0):
    """Stream an Ollama model download as events so the dashboard can show a live
    progress bar — no terminal needed. Yields ``{'type':'progress', percent, ...}``
    frames, then ``done`` or an honest ``error``. Never raises.

    Talks to Ollama's native ``/api/pull`` (newline-delimited JSON). ``name`` is
    validated (no shell — it's a JSON field) so it can't smuggle anything odd."""
    name = (name or "").strip()
    if not valid_model_name(name):
        yield {"type": "error", "message": "invalid model name"}
        yield {"type": "done"}
        return
    payload = json.dumps({"name": name, "stream": True}).encode("utf-8")
    req = urllib.request.Request(
        f"{_ollama_root()}/api/pull", data=payload,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - fixed local Ollama pull endpoint, scheme not user-controlled
            for raw in resp:                      # one JSON object per line
                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if obj.get("error"):
                    yield {"type": "error", "message": str(obj["error"])[:300]}
                    yield {"type": "done"}
                    return
                total = obj.get("total") or 0
                completed = obj.get("completed") or 0
                yield {
                    "type": "progress",
                    "status": str(obj.get("status") or "")[:120],
                    "completed": completed,
                    "total": total,
                    "percent": int(completed * 100 / total) if total else None,
                }
                if obj.get("status") == "success":
                    yield {"type": "done"}
                    return
        yield {"type": "done"}
    except (OSError, ValueError) as exc:
        reason = " ".join(str(exc).split()).strip() or type(exc).__name__
        if any(w in reason.lower() for w in ("refused", "connect", "timed out", "timeout")):
            reason = f"Can't reach Ollama at {_ollama_root()} — start it first (`ollama serve`)."
        yield {"type": "error", "message": reason[:300]}
        yield {"type": "done"}


# --- one-shot executive summary (for the PDF report) -------------------------- #
_SUMMARY_PROMPT = (
    "Write a concise executive summary of this network scan for a security report. "
    "Cover: overall exposure, the most at-risk hosts and why, the notable "
    "vulnerabilities, and the top 2-3 recommended actions. 120-180 words of plain "
    "prose — no markdown headings, no bullet lists. Use ONLY the scan context above; "
    "do not invent hosts, ports, or CVEs."
)


def summarize_scan(context, *, provider: str | None = None, model: str | None = None) -> dict:
    """Generate a plain-text executive summary of a scan (for embedding in the PDF).

    Reuses the grounded, provider-agnostic pipeline with tools disabled (a summary
    is never a scan proposal). Honest: returns ``available: False`` + a reason when
    no provider is ready, and never fabricates."""
    provider = provider or active_provider()
    parts: list[str] = []
    err = None
    for ev in stream_reply([{"role": "user", "content": _SUMMARY_PROMPT}], context,
                           provider=provider, model=model, allow_tools=False):
        kind = ev.get("type")
        if kind == "delta":
            parts.append(ev.get("text", ""))
        elif kind == "error":
            err = ev.get("message")
    text = "".join(parts).strip()
    # Deterministic grounding guard: if the model cited any CVE not present in the
    # real scan, append an explicit integrity note so a fabricated id can never
    # reach the PDF report unflagged. (With real ids now in the context block this
    # should be empty — this is the belt-and-braces safety net.)
    stray = ungrounded_cves(text, context_cve_ids(context)) if text else []
    if stray:
        text += (
            "\n\nData-integrity note: the following CVE identifier(s) in this summary "
            "were not present in the scan data and must be independently verified "
            "before use — " + ", ".join(stray) + "."
        )
    return {"available": bool(text) and not err, "summary": text,
            "provider": provider, "error": err, "ungrounded_cves": stray}
