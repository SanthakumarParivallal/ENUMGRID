/**
 * schema.test.js — the client-side Pydantic-style coercion layer.
 *
 * The reducer ingests raw SSE frames *only* after they pass through these
 * factories, so this is the firewall that stops a malformed frame from
 * corrupting the UI state tree. These tests pin that contract.
 */

import { describe, it, expect } from 'vitest';
import {
  ScanPhase,
  PortState,
  Severity,
  PortModel,
  HostModel,
  VulnModel,
  ScanStateModel,
  countOpenPorts,
  isCriticalHost,
  summarizeHosts,
} from './schema.js';

describe('PortModel', () => {
  it('applies defaults for an empty payload', () => {
    const p = PortModel({});
    expect(p.port).toBe(0);
    expect(p.protocol).toBe('tcp');
    expect(p.state).toBe(PortState.OPEN);
    expect(p.vulns).toEqual([]);
  });

  it('coerces a string port and bad enum to safe values', () => {
    const p = PortModel({ port: '443', protocol: 'sctp', state: 'weird' });
    expect(p.port).toBe(443);
    expect(p.protocol).toBe('tcp'); // invalid enum → fallback
    expect(p.state).toBe(PortState.OPEN);
  });
});

describe('VulnModel', () => {
  it('defaults severity to info and keeps a finite cvss', () => {
    expect(VulnModel({}).severity).toBe(Severity.INFO);
    expect(VulnModel({ cvss: 9.1 }).cvss).toBe(9.1);
    expect(VulnModel({ cvss: 'NaN' }).cvss).toBeNull();
  });
});

describe('HostModel', () => {
  it('fills mac/vendor/discovered_via and maps nested ports', () => {
    const h = HostModel({
      ip: '192.168.0.1',
      mac: '18:0c:7a:90:48:00',
      vendor: 'Sagemcom',
      discovered_via: 'arp',
      ports: [{ port: 80, service: 'http' }],
    });
    expect(h.ip).toBe('192.168.0.1');
    expect(h.vendor).toBe('Sagemcom');
    expect(h.discovered_via).toBe('arp');
    expect(h.status).toBe('unknown'); // default
    expect(h.ports).toHaveLength(1);
    expect(h.ports[0].port).toBe(80);
  });
});

describe('ScanStateModel', () => {
  it('clamps progress and validates phase', () => {
    const s = ScanStateModel({ progress: 250, phase: 'bogus' });
    expect(s.progress).toBe(100);
    expect(s.phase).toBe(ScanPhase.IDLE);
  });

  it('carries an error message through', () => {
    const s = ScanStateModel({ phase: 'Error', message: 'loopback refused' });
    expect(s.phase).toBe(ScanPhase.ERROR);
    expect(s.message).toBe('loopback refused');
  });

  it('never throws on a garbage payload', () => {
    expect(() => ScanStateModel(null)).not.toThrow();
    expect(ScanStateModel(undefined).hosts).toEqual([]);
  });
});

describe('derived helpers', () => {
  it('countOpenPorts counts open + open|filtered', () => {
    const h = HostModel({
      ip: '10.0.0.1',
      ports: [
        { port: 22, state: 'open' },
        { port: 81, state: 'closed' },
        { port: 443, state: 'open|filtered' },
      ],
    });
    expect(countOpenPorts(h)).toBe(2);
  });

  it('isCriticalHost flags a high-severity vuln', () => {
    const safe = HostModel({ ip: '10.0.0.2', ports: [{ port: 80, state: 'open' }] });
    const bad = HostModel({
      ip: '10.0.0.3',
      ports: [{ port: 445, state: 'open', vulns: [{ id: 'CVE-x', severity: 'high' }] }],
    });
    expect(isCriticalHost(safe)).toBe(false);
    expect(isCriticalHost(bad)).toBe(true);
  });

  it('summarizeHosts rolls up counts', () => {
    const hosts = [
      HostModel({ ip: '10.0.0.1', status: 'up', ports: [{ port: 80, state: 'open', service: 'http' }] }),
      HostModel({ ip: '10.0.0.2', status: 'down' }),
    ];
    const s = summarizeHosts(hosts);
    expect(s.total).toBe(2);
    expect(s.up).toBe(1);
    expect(s.down).toBe(1);
    expect(s.openPorts).toBe(1);
    expect(s.services).toBe(1);
  });
});
