/**
 * mockScanEngine.js — a stand-in for the FastAPI + python-nmap backend.
 * ---------------------------------------------------------------------------
 * The real platform streams `ScanState` snapshots over Server-Sent Events as
 * the two-tiered pipeline runs (Ping Sweep -> Nmap Service Scan). Until that
 * endpoint is wired up, this engine emits the *exact same snapshot shape* on a
 * timer so the cockpit is fully alive in development.
 *
 * Contract (mirrors what `EventSource` would give you):
 *   const engine = createScanEngine({ onSnapshot, onDone });
 *   engine.start('192.168.1.0/24', scanId);
 *   engine.stop();
 *
 * `onSnapshot(scanState)` receives a plain object matching schema.ScanState.
 *
 * To switch to the real backend, replace `startScan()` in ScanContext.jsx with
 * an EventSource subscription — the reducer already ingests these snapshots
 * verbatim.
 */

import { ScanPhase, HostStatus, PortState, Protocol } from './schema.js';

/* ------------------------------------------------------ service catalogue -- */

// Realistic (port -> service/version) templates, grouped by host archetype so
// generated assets look like a real corporate subnet rather than noise.
const SERVICE_POOL = {
  ssh: [{ port: 22, service: 'openssh', versions: ['8.9p1 Ubuntu', '9.6p1', '7.4', '8.2p1'] }],
  web: [
    { port: 80, service: 'apache', versions: ['2.4.41', '2.4.52'] },
    { port: 80, service: 'nginx', versions: ['1.18.0', '1.24.0'] },
    { port: 443, service: 'nginx', versions: ['1.18.0', '1.24.0'] },
    { port: 443, service: 'apache', versions: ['2.4.41'] },
    { port: 8080, service: 'http-proxy', versions: ['', 'Jetty 9.4.43'] },
    { port: 8443, service: 'https-alt', versions: [''] },
  ],
  db: [
    { port: 3306, service: 'mysql', versions: ['8.0.32', '5.7.41'] },
    { port: 5432, service: 'postgresql', versions: ['14.5', '15.2'] },
    { port: 1433, service: 'ms-sql-server', versions: ['2019 15.00'] },
    { port: 6379, service: 'redis', versions: ['7.0.11', '6.2.6'] },
    { port: 27017, service: 'mongodb', versions: ['6.0.4'] },
  ],
  windows: [
    { port: 135, service: 'msrpc', versions: [''] },
    { port: 139, service: 'netbios-ssn', versions: [''] },
    { port: 445, service: 'microsoft-ds', versions: ['Windows Server 2019'] },
    { port: 3389, service: 'ms-wbt-server', versions: ['Terminal Services'] },
    { port: 5985, service: 'wsman', versions: [''] },
  ],
  infra: [
    { port: 53, service: 'domain', versions: ['ISC BIND 9.16.1', 'dnsmasq 2.85'] },
    { port: 25, service: 'smtp', versions: ['Postfix'] },
    { port: 21, service: 'ftp', versions: ['vsftpd 3.0.3', 'ProFTPD 1.3.6'] },
    { port: 161, service: 'snmp', versions: [''] },
    { port: 123, service: 'ntp', versions: [''] },
  ],
};

// Ports that trip the "critical findings" placeholder heuristic when open.
const CRITICAL_PORTS = new Set([23, 21, 445, 3389, 6379, 5985]);

// Sample NSE-style findings attached during a deep scan, so the vuln UI is
// populated offline. The live backend produces these from real `--script vuln`.
const SAMPLE_VULNS = {
  21: [{ id: 'CVE-2011-2523', title: 'vsftpd backdoor', severity: 'critical', cvss: 10.0, output: 'State: VULNERABLE\nvsftpd 2.3.4 backdoor command execution.' }],
  23: [{ id: 'CVE-1999-0619', title: 'telnet cleartext auth', severity: 'high', cvss: 7.5, output: 'State: VULNERABLE\nTelnet transmits credentials in cleartext.' }],
  80: [{ id: 'CVE-2021-41773', title: 'http path traversal', severity: 'high', cvss: 7.5, output: 'State: LIKELY VULNERABLE\nApache 2.4.49 path traversal / RCE.' }],
  443: [{ id: 'CVE-2014-0160', title: 'ssl heartbleed', severity: 'high', cvss: 7.5, output: 'State: VULNERABLE\nOpenSSL Heartbleed memory disclosure.' }],
  445: [{ id: 'CVE-2017-0144', title: 'smb ms17-010 eternalblue', severity: 'critical', cvss: 8.1, output: 'State: VULNERABLE\nSMBv1 remote code execution (EternalBlue).' }],
  3389: [{ id: 'CVE-2019-0708', title: 'rdp bluekeep', severity: 'critical', cvss: 9.8, output: 'State: VULNERABLE\nRDP pre-auth RCE (BlueKeep).' }],
  6379: [{ id: 'REDIS-UNAUTH', title: 'unauthenticated redis', severity: 'high', cvss: null, output: 'State: VULNERABLE\nRedis reachable without authentication.' }],
};

const isSevere = (vulns) => vulns.some((v) => v.severity === 'critical' || v.severity === 'high');

/**
 * Offline equivalent of the backend's per-host deep scan: attach sample vulns
 * to a host's open ports. Used by the "Scan Vulns" row action in mock mode.
 */
export function deepScanHost(host) {
  const ports = (host.ports || []).map((p) => {
    const open = p.state === PortState.OPEN || p.state === PortState.OPEN_FILTERED;
    const vulns = open && SAMPLE_VULNS[p.port] ? SAMPLE_VULNS[p.port] : [];
    return { ...p, vulns, critical: p.critical || isSevere(vulns) };
  });
  return { ...host, ports, scanning: false, vulnScanning: false };
}

const OS_BY_ARCHETYPE = {
  'linux-web': ['Linux 5.15 (Ubuntu 22.04)', 'Linux 5.4 (Ubuntu 20.04)', 'Debian 11 (5.10)'],
  'linux-db': ['Linux 5.15 (Ubuntu 22.04)', 'CentOS 7 (3.10)', 'Rocky Linux 9'],
  'windows-server': ['Windows Server 2019', 'Windows Server 2022', 'Windows Server 2016'],
  'windows-client': ['Windows 10 22H2', 'Windows 11 23H2'],
  router: ['pfSense 2.6 (FreeBSD)', 'Cisco IOS 15.x', 'MikroTik RouterOS 7'],
};

const HOSTNAME_PREFIX = {
  'linux-web': ['web', 'app', 'nginx', 'edge'],
  'linux-db': ['db', 'pg', 'sql', 'cache'],
  'windows-server': ['dc', 'ad', 'file', 'rds'],
  'windows-client': ['ws', 'desk', 'laptop'],
  router: ['gw', 'fw', 'rtr'],
};

/* ------------------------------------------------------------- utilities -- */

const rand = (n) => Math.floor(Math.random() * n);
const pick = (arr) => arr[rand(arr.length)];
const chance = (p) => Math.random() < p;

function pickSome(arr, min, max) {
  const count = min + rand(max - min + 1);
  const copy = [...arr];
  const out = [];
  for (let i = 0; i < count && copy.length; i += 1) {
    out.push(copy.splice(rand(copy.length), 1)[0]);
  }
  return out;
}

/**
 * Derive a /24 base like "192.168.1." from common target syntaxes
 * (CIDR, range, or bare prefix). Falls back to 10.0.0. on anything unparseable.
 */
function deriveBaseOctets(target) {
  const m = String(target).match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})/);
  if (m) return `${m[1]}.${m[2]}.${m[3]}.`;
  return '10.0.0.';
}

/* ----------------------------------------------------- blueprint builder -- */

/**
 * Build the eventual, fully-scanned host (its "ground truth"). The engine then
 * reveals this progressively to imitate discovery + enumeration latency.
 */
function buildHostBlueprint(ip, deep) {
  // Decide reachability first — plenty of dead addresses in a real /24.
  if (chance(0.42)) {
    return { ip, hostname: null, status: HostStatus.DOWN, os: 'Unknown', ports: [] };
  }

  const archetype = pick([
    'linux-web',
    'linux-web',
    'linux-db',
    'windows-server',
    'windows-client',
    'router',
  ]);

  let templates = [];
  if (archetype === 'linux-web') {
    templates = [...pickSome(SERVICE_POOL.web, 1, 3), ...SERVICE_POOL.ssh];
    if (chance(0.4)) templates.push(pick(SERVICE_POOL.infra));
  } else if (archetype === 'linux-db') {
    templates = [...pickSome(SERVICE_POOL.db, 1, 2), ...SERVICE_POOL.ssh];
    if (chance(0.5)) templates.push(pick(SERVICE_POOL.web));
  } else if (archetype === 'windows-server') {
    templates = [...pickSome(SERVICE_POOL.windows, 3, 5)];
    if (chance(0.5)) templates.push(pick(SERVICE_POOL.web));
  } else if (archetype === 'windows-client') {
    templates = [...pickSome(SERVICE_POOL.windows, 1, 3)];
  } else {
    templates = [...pickSome(SERVICE_POOL.infra, 1, 3)];
    if (chance(0.6)) templates.push(...SERVICE_POOL.ssh);
  }

  // De-dupe by port, then materialize concrete Port records.
  const seen = new Set();
  const ports = [];
  for (const tpl of templates) {
    if (seen.has(tpl.port)) continue;
    seen.add(tpl.port);

    // Most discovered ports are open; a minority are firewall-filtered.
    const filtered = chance(0.16);
    const open = !filtered;
    const vulns = deep && open && SAMPLE_VULNS[tpl.port] ? SAMPLE_VULNS[tpl.port] : [];
    ports.push({
      port: tpl.port,
      protocol:
        tpl.port === 53 || tpl.port === 161 || tpl.port === 123 ? Protocol.UDP : Protocol.TCP,
      service: tpl.service,
      version: filtered ? '' : pick(tpl.versions),
      state: filtered ? PortState.FILTERED : PortState.OPEN,
      critical: (open && CRITICAL_PORTS.has(tpl.port)) || isSevere(vulns),
      vulns,
    });
  }

  // Occasionally surface a legacy cleartext service as a critical finding.
  if (chance(0.18)) {
    ports.push({
      port: 23,
      protocol: Protocol.TCP,
      service: 'telnet',
      version: 'Linux telnetd',
      state: PortState.OPEN,
      critical: true,
      vulns: deep ? SAMPLE_VULNS[23] : [],
    });
  }

  ports.sort((a, b) => a.port - b.port);

  const hostname = chance(0.78)
    ? `${pick(HOSTNAME_PREFIX[archetype])}-${String(1 + rand(9)).padStart(2, '0')}.corp.local`
    : null;

  return {
    ip,
    hostname,
    status: HostStatus.UP,
    os: pick(OS_BY_ARCHETYPE[archetype]),
    ports,
  };
}

/* --------------------------------------------------------------- engine -- */

/**
 * @param {{
 *   onSnapshot: (state: object) => void,
 *   onDone?: () => void,
 *   tickMs?: number,
 * }} handlers
 */
export function createScanEngine({ onSnapshot, onDone, tickMs = 480 }) {
  let timer = null;
  let cancelled = false;

  function clear() {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  }

  function start(target, scanId, deep = false) {
    cancelled = false;
    clear();

    const base = deriveBaseOctets(target);
    const startedAt = Date.now() / 1000;

    // Choose a spread of last octets to probe (a believable subset of a /24).
    const octets = [];
    const candidateCount = 12 + rand(6); // 12..17 hosts
    const usedOctet = new Set();
    while (octets.length < candidateCount) {
      const o = 1 + rand(60);
      if (!usedOctet.has(o)) {
        usedOctet.add(o);
        octets.push(o);
      }
    }
    octets.sort((a, b) => a - b);

    const blueprints = octets.map((o) => buildHostBlueprint(`${base}${o}`, deep));

    // Mutable, progressively-revealed working copy. `__bp` holds each host's
    // ground truth and is never emitted (see `scrubbed`).
    const revealed = [];
    let sweepIdx = 0;
    let enumIdx = 0; // index into UP hosts for phase 2

    const upHosts = () => revealed.filter((h) => h.status === HostStatus.UP);

    // Build an emit-safe snapshot: strips the private `__bp` field and clones
    // ports so React always sees fresh references.
    const scrubbed = () =>
      revealed.map((h) => ({
        ip: h.ip,
        hostname: h.hostname,
        status: h.status,
        os: h.os,
        scanning: h.scanning,
        ports: h.ports.map((p) => ({ ...p })),
      }));

    const emit = (phase, progress, finished = false) => {
      if (cancelled) return;
      onSnapshot({
        scan_id: scanId,
        target,
        phase,
        progress,
        started_at: startedAt,
        finished_at: finished ? Date.now() / 1000 : null,
        hosts: scrubbed(),
      });
    };

    const step = () => {
      if (cancelled) return;

      /* ---------------- Phase 1: Ping Sweep (host discovery) ------------- */
      if (sweepIdx < blueprints.length) {
        const bp = blueprints[sweepIdx];
        revealed.push({
          ip: bp.ip,
          hostname: bp.status === HostStatus.UP ? bp.hostname : null,
          status: bp.status,
          os: bp.status === HostStatus.UP ? 'Fingerprinting…' : 'Unknown',
          scanning: false,
          ports: [], // withheld until Phase 2 reaches this host
          __bp: bp, // private ground truth, scrubbed before emit
        });
        sweepIdx += 1;

        emit(ScanPhase.PING_SWEEP, Math.round((sweepIdx / blueprints.length) * 40));
        timer = setTimeout(step, tickMs * (bp.status === HostStatus.UP ? 1 : 0.5));
        return;
      }

      /* -------------- Phase 2: Nmap Enumeration (per up-host) ------------ */
      const ups = upHosts();
      if (enumIdx < ups.length) {
        const host = ups[enumIdx];

        if (host.scanning) {
          // Second visit: enumeration finished -> commit ground-truth ports.
          host.scanning = false;
          host.os = host.__bp.os;
          host.hostname = host.__bp.hostname;
          host.ports = host.__bp.ports;
          enumIdx += 1;
        } else {
          // First visit: light up the scanner for this host.
          host.scanning = true;
        }

        const enumProgress = 40 + Math.round((enumIdx / ups.length) * 60);
        emit(ScanPhase.NMAP_ENUMERATION, Math.min(99, enumProgress));
        timer = setTimeout(step, host.scanning ? tickMs * 0.6 : tickMs);
        return;
      }

      /* -------------------------- Completion ---------------------------- */
      emit(ScanPhase.COMPLETE, 100, true);
      clear();
      if (onDone && !cancelled) onDone();
    };

    // Initial Phase-1 frame (empty grid), then start the loop.
    emit(ScanPhase.PING_SWEEP, 0);
    timer = setTimeout(step, tickMs);
  }

  function stop() {
    cancelled = true;
    clear();
  }

  return { start, stop };
}
