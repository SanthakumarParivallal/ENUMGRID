/**
 * exporters.js — client-side CSV / JSON export of the current scan, matching the
 * CLI's export formats. Pure functions (unit-tested) + a Blob download helper.
 *
 * The CSV escaper also neutralises spreadsheet formula injection (OWASP): device
 * banners, hostnames and vendor strings are attacker-influenced and could start
 * with `=`, `+`, `-`, `@` — which Excel/Sheets would execute as a formula. Such
 * fields are prefixed with a single quote so they render as literal text.
 */

import { PortState } from './schema.js';

const OPEN = new Set([PortState.OPEN, PortState.OPEN_FILTERED]);

function openPorts(host) {
  return (host?.ports || []).filter((p) => OPEN.has(p.state));
}

function vulnTotal(host) {
  let n = host?.vulns?.length || 0;
  for (const p of host?.ports || []) n += p.vulns?.length || 0;
  return n;
}

/** Escape one CSV field: quote when needed, and defuse formula injection. */
export function csvField(value) {
  let s = value == null ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; // neutralise =, +, -, @, tab, CR formulas
  return /["\n,]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** One row per host: the device inventory as CSV (banners kept, safely escaped). */
export function hostsToCsv(hosts = []) {
  const header = [
    'ip', 'hostname', 'status', 'vendor', 'mac', 'device_type', 'os',
    'open_ports', 'open_count', 'vuln_count',
  ];
  const lines = [header.join(',')];
  for (const h of hosts) {
    const open = openPorts(h);
    const openStr = open
      .map((p) => (p.version ? `${p.port}/${p.service} ${p.version}` : `${p.port}/${p.service}`))
      .join('; ');
    lines.push([
      h.ip, h.hostname || '', h.status || '', h.vendor || '', h.mac || '',
      h.device_type || '', h.os || '', openStr, open.length, vulnTotal(h),
    ].map(csvField).join(','));
  }
  return `${lines.join('\n')}\n`;
}

/** The full snapshot as pretty JSON (hosts verbatim, with a small envelope). */
export function snapshotToJson(target, hosts = []) {
  return JSON.stringify(
    {
      tool: 'ENUMGRID',
      target: target || '',
      generated_at: new Date().toISOString(),
      host_count: hosts.length,
      hosts,
    },
    null,
    2,
  );
}

/** A filesystem-safe base name from the target + a timestamp. */
export function exportFilename(target, ext) {
  const safe = String(target || 'scan').replace(/[^a-z0-9]+/gi, '-').replace(/^-+|-+$/g, '') || 'scan';
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  return `enumgrid_${safe}_${stamp}.${ext}`;
}

/** Trigger a browser download of `text` as `filename`. */
export function downloadText(filename, mime, text) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
