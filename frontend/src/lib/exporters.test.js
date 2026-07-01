import { describe, it, expect } from 'vitest';
import { csvField, hostsToCsv, snapshotToJson, exportFilename } from './exporters.js';

describe('csvField', () => {
  it('quotes fields containing comma, quote or newline', () => {
    expect(csvField('plain')).toBe('plain');
    expect(csvField('a,b')).toBe('"a,b"');
    expect(csvField('he said "hi"')).toBe('"he said ""hi"""');
    expect(csvField('line1\nline2')).toBe('"line1\nline2"');
  });

  it('neutralises spreadsheet formula injection', () => {
    // Attacker-influenced banners/hostnames must not execute in Excel/Sheets.
    expect(csvField('=cmd()')).toBe("'=cmd()");
    expect(csvField('+1+1')).toBe("'+1+1");
    expect(csvField('-2+3')).toBe("'-2+3");
    expect(csvField('@SUM(A1)')).toBe("'@SUM(A1)");
  });

  it('handles null / undefined as empty', () => {
    expect(csvField(null)).toBe('');
    expect(csvField(undefined)).toBe('');
  });
});

describe('hostsToCsv', () => {
  const hosts = [
    {
      ip: '10.0.0.1', hostname: 'gw', status: 'up', vendor: 'Routerboard.com',
      mac: '2c:c8:1b:00:00:01', device_type: 'Router / Gateway', os: 'MikroTik RouterOS',
      ports: [
        { port: 80, service: 'http', version: 'nginx 1.18', state: 'open', vulns: [{ id: 'CVE-1' }] },
        { port: 22, service: 'ssh', version: '', state: 'filtered', vulns: [] },
      ],
      vulns: [],
    },
  ];

  it('emits a header + one row per host with open-port summary and counts', () => {
    const csv = hostsToCsv(hosts);
    const lines = csv.trim().split('\n');
    expect(lines[0]).toBe(
      'ip,hostname,status,vendor,mac,device_type,os,open_ports,open_count,vuln_count',
    );
    // Row: only the OPEN port is summarised; filtered excluded; counts correct.
    const row = lines[1];
    expect(row).toContain('10.0.0.1');
    expect(row).toContain('80/http nginx 1.18');
    expect(row).not.toContain('22/ssh'); // filtered port excluded
    expect(row.endsWith(',1,1')).toBe(true); // open_count=1, vuln_count=1
  });

  it('is safe when hosts is empty', () => {
    expect(hostsToCsv([]).trim().split('\n').length).toBe(1); // header only
  });
});

describe('snapshotToJson', () => {
  it('wraps hosts with an envelope and is valid JSON', () => {
    const out = snapshotToJson('10.0.0.0/24', [{ ip: '10.0.0.1' }]);
    const obj = JSON.parse(out);
    expect(obj.tool).toBe('ENUMGRID');
    expect(obj.target).toBe('10.0.0.0/24');
    expect(obj.host_count).toBe(1);
    expect(obj.hosts[0].ip).toBe('10.0.0.1');
    expect(typeof obj.generated_at).toBe('string');
  });
});

describe('exportFilename', () => {
  it('is filesystem-safe and carries the extension', () => {
    const f = exportFilename('192.168.0.0/24', 'csv');
    expect(f).toMatch(/^enumgrid_192-168-0-0-24_[0-9T-]+\.csv$/);
    expect(exportFilename('', 'json')).toMatch(/^enumgrid_scan_.*\.json$/);
  });
});
