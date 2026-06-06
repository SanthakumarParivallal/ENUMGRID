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
  collectVulns,
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

  it('carries the backend url + confidence through', () => {
    const v = VulnModel({
      id: 'CVE-2023-50387',
      severity: 'high',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-50387',
      confidence: 'version',
    });
    expect(v.url).toBe('https://nvd.nist.gov/vuln/detail/CVE-2023-50387');
    expect(v.confidence).toBe('version');
  });

  it('synthesizes an NVD link for a CVE id when the backend omits one', () => {
    const v = VulnModel({ id: 'CVE-2021-44228' });
    expect(v.url).toBe('https://nvd.nist.gov/vuln/detail/CVE-2021-44228');
  });

  it('rejects an invalid confidence value (no false labelling)', () => {
    expect(VulnModel({ id: 'x', confidence: 'totally-sure' }).confidence).toBe('');
  });

  it('does not invent a link for a non-CVE script finding', () => {
    expect(VulnModel({ id: 'ssl-heartbleed' }).url).toBe('');
  });

  it('carries KEV + EPSS prioritization signals', () => {
    const v = VulnModel({ id: 'CVE-2021-44228', kev: true, epss: 0.97 });
    expect(v.kev).toBe(true);
    expect(v.epss).toBe(0.97);
    const plain = VulnModel({ id: 'CVE-2000-0001' });
    expect(plain.kev).toBe(false);
    expect(plain.epss).toBeNull();
  });
});

describe('HostModel', () => {
  it('fills mac/vendor/discovered_via and maps nested ports', () => {
    const h = HostModel({
      ip: '192.168.0.1',
      mac: '18:0c:7a:90:48:00',
      vendor: 'Sagemcom',
      device_type: 'Router / Gateway',
      discovered_via: 'arp',
      ports: [{ port: 80, service: 'http' }],
    });
    expect(h.ip).toBe('192.168.0.1');
    expect(h.vendor).toBe('Sagemcom');
    expect(h.device_type).toBe('Router / Gateway');
    expect(h.discovered_via).toBe('arp');
    expect(h.status).toBe('unknown'); // default
    expect(h.ports).toHaveLength(1);
    expect(h.ports[0].port).toBe(80);
  });

  it('defaults device_type to empty string when absent', () => {
    expect(HostModel({ ip: '10.0.0.1' }).device_type).toBe('');
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

  it('collectVulns risk-ranks KEV/EPSS above raw CVSS', () => {
    const host = HostModel({
      ip: '10.0.0.9',
      ports: [
        { port: 80, vulns: [
          { id: 'CVE-HIGH-CVSS', severity: 'critical', cvss: 9.8 },          // not exploited
          { id: 'CVE-EXPLOITED', severity: 'high', cvss: 7.5, kev: true },   // KEV → first
          { id: 'CVE-PROBABLE', severity: 'medium', cvss: 5.0, epss: 0.8 },  // high EPSS → second
        ] },
      ],
    });
    const ranked = collectVulns(host).map((v) => v.id);
    expect(ranked[0]).toBe('CVE-EXPLOITED');
    expect(ranked[1]).toBe('CVE-PROBABLE');
    expect(ranked[2]).toBe('CVE-HIGH-CVSS');
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
