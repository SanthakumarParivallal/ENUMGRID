import { describe, it, expect } from 'vitest';
import {
  buildScanContext,
  parseSSE,
  validateKeyForm,
  summarizeAction,
  isReady,
  PROVIDER_LABELS,
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
});

describe('validateKeyForm', () => {
  it('accepts a plausible key', () => {
    expect(validateKeyForm({ provider: 'anthropic', key: 'sk-ant-abcdef1234' })).toEqual({ ok: true });
  });
  it('rejects bad provider, empty, and too-short keys', () => {
    expect(validateKeyForm({ provider: 'gemini', key: 'x'.repeat(20) }).ok).toBe(false);
    expect(validateKeyForm({ provider: 'openai', key: '  ' }).ok).toBe(false);
    expect(validateKeyForm({ provider: 'openai', key: 'short' }).ok).toBe(false);
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
  it('exposes provider labels', () => {
    expect(PROVIDER_LABELS.anthropic).toMatch(/Claude/);
    expect(PROVIDER_LABELS.openai).toMatch(/OpenAI/);
  });
});
