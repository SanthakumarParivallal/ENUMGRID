/**
 * copilot.js — pure helpers for the AI copilot panel.
 * ---------------------------------------------------------------------------
 * All logic here is side-effect-free and unit-tested: building the grounding
 * context sent to the backend, parsing the SSE event stream, validating the
 * key-upload form, and rendering a proposed action. The React panel
 * (`CopilotPanel.jsx`) owns the network + DOM; this owns the data shaping.
 */

export const PROVIDER_LABELS = Object.freeze({
  ollama: 'Ollama (local)',
  gemini: 'Google Gemini',
  anthropic: 'Anthropic Claude',
  openai: 'OpenAI',
});

// The two free options are surfaced first so the operator reaches them by default.
export const PROVIDER_ORDER = Object.freeze(['ollama', 'gemini', 'anthropic', 'openai']);

export const PROVIDER_HINTS = Object.freeze({
  ollama: {
    tag: 'Local · Free',
    keyless: true,
    url: 'https://ollama.com/download',
    linkText: 'Install Ollama ↗',
    note: 'No key, no cloud — runs on this machine. Install Ollama, run '
      + '“ollama pull llama3.1”, then Connect. Your scan never leaves the laptop.',
  },
  gemini: {
    tag: 'Free tier',
    placeholder: 'AIza…',
    url: 'https://aistudio.google.com/apikey',
    linkText: 'Get a free key ↗',
    note: 'Free tier from Google AI Studio — no billing required.',
  },
  anthropic: { tag: 'Paid', placeholder: 'sk-ant-…', url: 'https://console.anthropic.com/settings/keys' },
  openai: { tag: 'Paid', placeholder: 'sk-…', url: 'https://platform.openai.com/api-keys' },
});

/**
 * Shape the dashboard's live scan state into the compact `context` the backend
 * grounds the model with. Defensive about field names so it never throws on a
 * partial host; caps the host count to keep the request small.
 */
export function buildScanContext(scan) {
  const target = (scan && scan.target) || '';
  const rawHosts = Array.isArray(scan && scan.hosts) ? scan.hosts : [];
  const hosts = rawHosts.slice(0, 128).map((h) => {
    const src = h || {};
    const ports = (src.ports || src.open_ports || src.services || [])
      .filter((p) => p && typeof p === 'object')
      .map((p) => ({ port: p.port, service: p.service || p.name || '' }));
    const vulns = (src.vulns || src.cves || [])
      .filter((v) => v && typeof v === 'object')
      .map((v) => ({ id: v.id || v.cve || '', severity: String(v.severity || '').toLowerCase() }));
    return {
      ip: src.ip || src.address || '',
      hostname: src.hostname || '',
      os: src.os || '',
      device_type: src.device_type || src.deviceType || '',
      status: src.status || 'up',
      ports,
      vulns,
    };
  });
  return { target, hosts };
}

/**
 * Split accumulated SSE text into complete events. Returns the parsed `events`
 * and the trailing `rest` (an incomplete frame) to carry into the next chunk.
 */
export function parseSSE(buffer) {
  const events = [];
  let rest = String(buffer || '');
  let idx = rest.indexOf('\n\n');
  while (idx !== -1) {
    const frame = rest.slice(0, idx);
    rest = rest.slice(idx + 2);
    for (const line of frame.split('\n')) {
      const t = line.trim();
      if (!t.startsWith('data:')) continue;
      try {
        events.push(JSON.parse(t.slice(5).trim()));
      } catch {
        /* skip a malformed frame rather than break the stream */
      }
    }
    idx = rest.indexOf('\n\n');
  }
  return { events, rest };
}

/** Validate the in-dashboard key-upload form. Ollama is local, so it needs no key. */
export function validateKeyForm({ provider, key } = {}) {
  if (!Object.prototype.hasOwnProperty.call(PROVIDER_LABELS, provider)) {
    return { ok: false, error: 'Choose a provider.' };
  }
  if (provider === 'ollama') return { ok: true }; // keyless — connect straight away
  const k = (key || '').trim();
  if (!k) return { ok: false, error: 'Paste an API key.' };
  if (k.length < 12) return { ok: false, error: 'That key looks too short.' };
  return { ok: true };
}

/** Human label for a proposed scan action (used on the confirm button). */
export function summarizeAction(action) {
  if (!action || !action.target) return '';
  const mode =
    action.mode === 'full'
      ? action.deep
        ? 'full + vuln'
        : 'full service'
      : 'discovery';
  return `Run ${mode} scan on ${action.target}`;
}

/** Whether a fetched status makes the copilot usable at all. */
export function isReady(status) {
  return !!(status && status.any_ready);
}

/**
 * The Ollama onboarding step, derived from status. Drives the setup wizard:
 *   sdk_missing → backend lacks the openai SDK
 *   server_down → Ollama isn't installed / running
 *   need_model  → server up, but the chosen model isn't downloaded yet
 *   ready       → good to chat
 */
export function ollamaSetupState(status) {
  const p = status && status.providers && status.providers.ollama;
  if (!p) return 'unknown';
  if (!p.sdk_installed) return 'sdk_missing';
  if (!p.server_up) return 'server_down';
  if (!p.model_present) return 'need_model';
  return 'ready';
}

/** Fallback list of recommended Ollama models if the backend doesn't supply one. */
export const OLLAMA_RECOMMENDED = Object.freeze([
  { name: 'llama3.2', label: 'Llama 3.2 (3B)', size: '~2 GB', note: 'Lightest — good on ~8 GB RAM' },
  { name: 'llama3.1', label: 'Llama 3.1 (8B)', size: '~4.7 GB', note: 'Balanced default — needs ~16 GB RAM', recommended: true },
  { name: 'qwen2.5', label: 'Qwen 2.5 (7B)', size: '~4.7 GB', note: 'Strong reasoning + tool use' },
]);

/** Compact byte formatting for the download progress bar (e.g. 1536 → "1.5 KB"). */
export function formatBytes(n) {
  const num = Number(n);
  if (!Number.isFinite(num) || num <= 0) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = num;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}
