import { describe, it, expect } from 'vitest';
import {
  buildScanContext,
  parseSSE,
  validateKeyForm,
  summarizeAction,
  isReady,
  ollamaSetupState,
  formatBytes,
  OLLAMA_RECOMMENDED,
  PROVIDER_LABELS,
  PROVIDER_ORDER,
  PROVIDER_HINTS,
} from './copilot.js';

describe('buildScanContext', () => {
  it('shapes live scan state defensively', () => {
    const ctx = buildScanContext({
      target: '172.16.2.0/24',
      hosts: [
        {
          ip: '172.16.2.1',
          hostname: 'gw',
          os: 'Linux',
          device_type: 'Router',
          ports: [{ port: 80, service: 'http' }],
          vulns: [{ cve: 'CVE-1', severity: 'HIGH' }],
        },
      ],
    });
    expect(ctx.target).toBe('172.16.2.0/24');
    expect(ctx.hosts[0].ip).toBe('172.16.2.1');
    expect(ctx.hosts[0].ports[0]).toEqual({ port: 80, service: 'http' });
    expect(ctx.hosts[0].vulns[0]).toEqual({ id: 'CVE-1', severity: 'high' });
  });

  it('tolerates missing / junk input', () => {
    expect(buildScanContext(null)).toEqual({ target: '', hosts: [] });
    expect(buildScanContext({ hosts: 'nope' }).hosts).toEqual([]);
  });

  it('reads alternate field names (open_ports / address)', () => {
    const ctx = buildScanContext({ hosts: [{ address: '10.0.0.5', open_ports: [{ port: 22, name: 'ssh' }] }] });
    expect(ctx.hosts[0].ip).toBe('10.0.0.5');
    expect(ctx.hosts[0].ports[0].service).toBe('ssh');
  });

  it('caps host count', () => {
    const many = Array.from({ length: 300 }, (_, i) => ({ ip: `10.0.0.${i}` }));
    expect(buildScanContext({ hosts: many }).hosts).toHaveLength(128);
  });

  it('applies every fallback branch (null host, bare port/vuln, defaults)', () => {
    const ctx = buildScanContext({
      hosts: [
        null, // `h || {}` — a null host must not throw
        {
          // `src.services` fallback (neither ports nor open_ports), a port with
          // no service/name, a vuln keyed only by `id`, no ip/status/os.
          services: [{ port: 5 }],
          cves: [{ id: 'CVE-9' }],
          deviceType: 'Printer', // camelCase alt for device_type
        },
      ],
    });
    expect(ctx.hosts[0]).toEqual({
      ip: '', hostname: '', os: '', device_type: '', status: 'up', ports: [], vulns: [],
    });
    expect(ctx.hosts[1].ports[0]).toEqual({ port: 5, service: '' }); // service defaulted
    expect(ctx.hosts[1].vulns[0]).toEqual({ id: 'CVE-9', severity: '' }); // severity defaulted
    expect(ctx.hosts[1].device_type).toBe('Printer'); // camelCase alt read
    expect(ctx.hosts[1].status).toBe('up'); // status defaulted
  });
});

describe('parseSSE', () => {
  it('extracts complete frames and keeps the remainder', () => {
    const { events, rest } = parseSSE('data: {"type":"delta","text":"hi"}\n\ndata: {"type":"do');
    expect(events).toEqual([{ type: 'delta', text: 'hi' }]);
    expect(rest).toBe('data: {"type":"do');
  });

  it('assembles a split frame across chunks', () => {
    const a = parseSSE('data: {"type":"done');
    expect(a.events).toEqual([]);
    const b = parseSSE(a.rest + '"}\n\n');
    expect(b.events).toEqual([{ type: 'done' }]);
  });

  it('skips a malformed frame without throwing', () => {
    const { events } = parseSSE('data: not json\n\ndata: {"type":"delta","text":"ok"}\n\n');
    expect(events).toEqual([{ type: 'delta', text: 'ok' }]);
  });

  it('handles empty / junk buffer', () => {
    expect(parseSSE('').events).toEqual([]);
    expect(parseSSE(null).events).toEqual([]);
  });

  it('ignores non-data lines inside a frame (event:/comment lines)', () => {
    const { events } = parseSSE('event: message\n: keep-alive\ndata: {"type":"delta","text":"x"}\n\n');
    expect(events).toEqual([{ type: 'delta', text: 'x' }]);
  });
});

describe('validateKeyForm', () => {
  it('accepts a plausible key', () => {
    expect(validateKeyForm({ provider: 'anthropic', key: 'sk-ant-abcdef1234' })).toEqual({ ok: true });
    expect(validateKeyForm({ provider: 'gemini', key: 'AIzaSy-abcdef123456' })).toEqual({ ok: true });
  });
  it('treats Ollama as keyless (no key required)', () => {
    expect(validateKeyForm({ provider: 'ollama', key: '' })).toEqual({ ok: true });
    expect(validateKeyForm({ provider: 'ollama' })).toEqual({ ok: true });
  });
  it('rejects unknown provider, empty, and too-short keys', () => {
    expect(validateKeyForm({ provider: 'grok', key: 'x'.repeat(20) }).ok).toBe(false);
    expect(validateKeyForm({ provider: 'openai', key: '  ' }).ok).toBe(false);
    expect(validateKeyForm({ provider: 'gemini', key: 'short' }).ok).toBe(false);
  });
  it('handles being called with no argument at all', () => {
    // Default `= {}` param: provider is undefined → not a known provider.
    expect(validateKeyForm()).toEqual({ ok: false, error: 'Choose a provider.' });
  });
});

describe('summarizeAction', () => {
  it('describes each scan mode', () => {
    expect(summarizeAction({ target: '10.0.0.0/24', mode: 'discover' })).toBe('Run discovery scan on 10.0.0.0/24');
    expect(summarizeAction({ target: 'h', mode: 'full', deep: false })).toBe('Run full service scan on h');
    expect(summarizeAction({ target: 'h', mode: 'full', deep: true })).toBe('Run full + vuln scan on h');
  });
  it('returns empty for junk', () => {
    expect(summarizeAction(null)).toBe('');
    expect(summarizeAction({ mode: 'full' })).toBe('');
  });
});

describe('misc', () => {
  it('isReady reflects any_ready', () => {
    expect(isReady({ any_ready: true })).toBe(true);
    expect(isReady({ any_ready: false })).toBe(false);
    expect(isReady(null)).toBe(false);
  });
  it('exposes provider labels for all four providers', () => {
    expect(PROVIDER_LABELS.anthropic).toMatch(/Claude/);
    expect(PROVIDER_LABELS.openai).toMatch(/OpenAI/);
    expect(PROVIDER_LABELS.gemini).toMatch(/Gemini/);
    expect(PROVIDER_LABELS.ollama).toMatch(/Ollama/);
  });
  it('orders the free providers first and marks them free/keyless', () => {
    expect(PROVIDER_ORDER.slice(0, 2)).toEqual(['ollama', 'gemini']);
    expect(PROVIDER_HINTS.ollama.keyless).toBe(true);
    expect(PROVIDER_HINTS.gemini.tag).toMatch(/Free/);
  });
});

describe('ollamaSetupState', () => {
  const withOllama = (o) => ({ providers: { ollama: o } });
  it('walks the setup steps in order', () => {
    expect(ollamaSetupState(null)).toBe('unknown');
    expect(ollamaSetupState(withOllama({ sdk_installed: false }))).toBe('sdk_missing');
    expect(ollamaSetupState(withOllama({ sdk_installed: true, server_up: false }))).toBe('server_down');
    expect(ollamaSetupState(withOllama({ sdk_installed: true, server_up: true, model_present: false }))).toBe('need_model');
    expect(ollamaSetupState(withOllama({ sdk_installed: true, server_up: true, model_present: true }))).toBe('ready');
  });
});

describe('formatBytes', () => {
  it('formats sizes and ignores junk', () => {
    expect(formatBytes(0)).toBe('');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(5_033_164_800)).toBe('4.7 GB');
    expect(formatBytes('nope')).toBe('');
  });
});

describe('OLLAMA_RECOMMENDED', () => {
  it('offers tool-capable models with one marked recommended', () => {
    expect(OLLAMA_RECOMMENDED.length).toBeGreaterThanOrEqual(2);
    expect(OLLAMA_RECOMMENDED.some((m) => m.recommended)).toBe(true);
    expect(OLLAMA_RECOMMENDED.every((m) => m.name && m.label)).toBe(true);
  });
});
