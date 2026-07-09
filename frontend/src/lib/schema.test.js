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
  emptyScanState,
  countOpenPorts,
  hostMatchesCategory,
  isCriticalHost,
  criticalCount,
  vulnCount,
  summarizeHosts,
  collectVulns,
  PORT_CATEGORIES,
} from './schema.js';

describe('PortModel', () => {
  it('applies defaults for an empty payload', () => {
    const p = PortModel({});
    expect(p.port).toBe(0);
    expect(p.protocol).toBe('tcp');
    expect(p.state).toBe(PortState.OPEN);
    expect(p.conf).toBeNull(); // no confidence reported → null, never a fake number
    expect(p.vulns).toEqual([]);
  });

  it('coerces a string port and bad enum to safe values', () => {
    const p = PortModel({ port: '443', protocol: 'sctp', state: 'weird' });
    expect(p.port).toBe(443);
    expect(p.protocol).toBe('tcp'); // invalid enum → fallback
    expect(p.state).toBe(PortState.OPEN);
  });

  it('carries nmap detection confidence through, coercing to a number', () => {
    expect(PortModel({ port: 80, conf: 10 }).conf).toBe(10);
    expect(PortModel({ port: 80, conf: '3' }).conf).toBe(3); // string → number
    expect(PortModel({ port: 80, conf: 'high' }).conf).toBeNull(); // garbage → null
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

  it('defaults scan-state transients to false (Ready, not Queued)', () => {
    const h = HostModel({ ip: '10.0.0.2' });
    expect(h.queued).toBe(false);
    expect(h.scanned).toBe(false);
    expect(h.scanError).toBe(false);
    expect(h.vulnScanning).toBe(false);
  });

  it('coerces scan-state transients and carries scan_note', () => {
    const h = HostModel({ ip: '10.0.0.3', queued: 1, scanned: true, scanError: 0, scan_note: 'UDP→connect' });
    expect(h.queued).toBe(true);
    expect(h.scanned).toBe(true);
    expect(h.scanError).toBe(false);
    expect(h.scan_note).toBe('UDP→connect');
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

  it('carries scan_id + timestamps through when the backend supplies them', () => {
    const s = ScanStateModel({
      scan_id: 4242, // coerced to string
      target: '10.0.0.0/24',
      phase: 'Complete',
      progress: 100,
      started_at: 1_700_000_000.5,
      finished_at: 1_700_000_050.25,
    });
    expect(s.scan_id).toBe('4242');
    expect(s.started_at).toBe(1_700_000_000.5);
    expect(s.finished_at).toBe(1_700_000_050.25);
    expect(s.phase).toBe(ScanPhase.COMPLETE);
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

  it('collectVulns falls through to raw CVSS when KEV + EPSS tie', () => {
    // Two findings that tie on KEV (neither) and EPSS (both absent) so the sort
    // decides on CVSS — exercising the CVSS tie-breaker rung of the comparator.
    const host = HostModel({
      ip: '10.0.0.13',
      ports: [{ port: 443, vulns: [
        { id: 'CVE-LOWER-CVSS', severity: 'high', cvss: 5.0 },
        { id: 'CVE-HIGHER-CVSS', severity: 'high', cvss: 8.8 },
      ] }],
    });
    expect(collectVulns(host).map((v) => v.id)).toEqual(['CVE-HIGHER-CVSS', 'CVE-LOWER-CVSS']);
  });

  it('summarizeHosts rolls up counts (open ports, services, criticals, vulns)', () => {
    const hosts = [
      HostModel({
        ip: '10.0.0.1',
        status: 'up',
        ports: [
          { port: 80, state: 'open', service: 'http', critical: true, vulns: [{ id: 'CVE-1' }] },
          { port: 8080, state: 'open', service: 'unknown' }, // 'unknown' service is not counted
          { port: 22, state: 'closed', service: 'ssh' }, // closed → not an open port
        ],
        vulns: [{ id: 'CVE-host' }],
      }),
      HostModel({ ip: '10.0.0.2', status: 'down' }),
    ];
    const s = summarizeHosts(hosts);
    expect(s.total).toBe(2);
    expect(s.up).toBe(1);
    expect(s.down).toBe(1);
    expect(s.openPorts).toBe(2); // 80 + 8080 (22 is closed)
    expect(s.services).toBe(1); // only 'http' — 'unknown' is filtered out
    expect(s.critical).toBe(1); // the flagged port 80
    expect(s.vulns).toBe(2); // 1 host-level + 1 port-level
  });

  it('emptyScanState is a pristine, validated Idle snapshot', () => {
    const s = emptyScanState();
    expect(s.phase).toBe(ScanPhase.IDLE);
    expect(s.progress).toBe(0);
    expect(s.hosts).toEqual([]);
    expect(s.target).toBe('');
    expect(s.scan_id).toBeNull();
  });

  it('countOpenPorts / criticalCount return 0 for a host with no ports', () => {
    expect(countOpenPorts(HostModel({ ip: '10.0.0.4' }))).toBe(0);
    expect(countOpenPorts(null)).toBe(0);
    expect(criticalCount(HostModel({ ip: '10.0.0.4' }))).toBe(0);
    expect(criticalCount(null)).toBe(0);
  });

  it('criticalCount counts only port-level critical flags', () => {
    const h = HostModel({
      ip: '10.0.0.5',
      ports: [
        { port: 445, state: 'open', critical: true },
        { port: 3389, state: 'open', critical: true },
        { port: 80, state: 'open' },
      ],
    });
    expect(criticalCount(h)).toBe(2);
  });

  it('hostMatchesCategory matches an open port in the category, else false', () => {
    const web = HostModel({ ip: '10.0.0.6', ports: [{ port: 443, state: 'open' }] });
    const filtered = HostModel({ ip: '10.0.0.7', ports: [{ port: 443, state: 'filtered' }] });
    expect(hostMatchesCategory(web, 'web')).toBe(true);
    expect(hostMatchesCategory(web, 'ssh')).toBe(false); // no SSH port open
    expect(hostMatchesCategory(filtered, 'web')).toBe(false); // filtered ≠ open
    expect(hostMatchesCategory(web, 'nonsense-key')).toBe(false); // unknown category
    expect(hostMatchesCategory(null, 'web')).toBe(false); // no host
    expect(Object.keys(PORT_CATEGORIES)).toContain('web'); // catalogue is exported
  });

  it('isCriticalHost also flags a host-level (non-port) severe vuln', () => {
    const hostVuln = HostModel({
      ip: '10.0.0.8',
      ports: [{ port: 80, state: 'open' }],
      vulns: [{ id: 'CVE-hostlevel', severity: 'critical' }],
    });
    const portFlag = HostModel({ ip: '10.0.0.9', ports: [{ port: 445, state: 'open', critical: true }] });
    expect(isCriticalHost(hostVuln)).toBe(true); // via host-level vuln
    expect(isCriticalHost(portFlag)).toBe(true); // via port critical flag
    expect(isCriticalHost(null)).toBe(false);
  });

  it('collectVulns merges host-level vulns and tolerates unknown severity in the rank', () => {
    const host = HostModel({
      ip: '10.0.0.10',
      ports: [{ port: 80, vulns: [{ id: 'PORT-VULN', severity: 'low' }] }],
      vulns: [{ id: 'HOST-VULN', severity: 'weird-band' }], // coerced to 'info' by VulnModel
    });
    const all = collectVulns(host);
    const byId = Object.fromEntries(all.map((v) => [v.id, v]));
    expect(byId['PORT-VULN'].port).toBe(80); // tagged with its port
    expect(byId['HOST-VULN'].port).toBeNull(); // host-level → null port
    expect(all).toHaveLength(2);
  });

  it('vulnCount totals host-level + every port-level finding', () => {
    const host = HostModel({
      ip: '10.0.0.11',
      ports: [
        { port: 80, vulns: [{ id: 'A' }, { id: 'B' }] },
        { port: 22 },
      ],
      vulns: [{ id: 'C' }],
    });
    expect(vulnCount(host)).toBe(3);
    expect(vulnCount(HostModel({ ip: '10.0.0.12' }))).toBe(0);
  });
});
