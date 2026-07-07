/**
 * copilot.js — pure helpers for the AI copilot panel.
 * ---------------------------------------------------------------------------
 * All logic here is side-effect-free and unit-tested: building the grounding
 * context sent to the backend, parsing the SSE event stream, validating the
 * key-upload form, and rendering a proposed action. The React panel
 * (`CopilotPanel.jsx`) owns the network + DOM; this owns the data shaping.
 */

export const PROVIDER_LABELS = Object.freeze({
  anthropic: 'Anthropic Claude',
  openai: 'OpenAI',
});

export const PROVIDER_HINTS = Object.freeze({
  anthropic: { placeholder: 'sk-ant-…', url: 'https://console.anthropic.com/settings/keys' },
  openai: { placeholder: 'sk-…', url: 'https://platform.openai.com/api-keys' },
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

/** Validate the in-dashboard key-upload form. */
export function validateKeyForm({ provider, key } = {}) {
  if (provider !== 'anthropic' && provider !== 'openai') {
    return { ok: false, error: 'Choose a provider.' };
  }
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
