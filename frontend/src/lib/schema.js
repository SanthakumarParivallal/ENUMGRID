/**
 * schema.js — Pydantic-style model definitions for the Two-Tiered Scan Pipeline.
 * ---------------------------------------------------------------------------
 * This file is the single source of truth for the *shape* of scan data on the
 * client. It intentionally mirrors the FastAPI/Pydantic backend models:
 *
 *   class Port(BaseModel):
 *       port: int
 *       protocol: Literal["tcp", "udp"] = "tcp"
 *       service: str = "unknown"
 *       version: str = ""
 *       state: Literal["open", "filtered", "closed", "open|filtered"] = "open"
 *       critical: bool = False
 *
 *   class Host(BaseModel):
 *       ip: str
 *       hostname: str | None = None
 *       status: Literal["up", "down", "unknown"] = "unknown"
 *       os: str = "Unknown"
 *       scanning: bool = False
 *       ports: list[Port] = []
 *
 *   class ScanState(BaseModel):
 *       scan_id: str | None = None
 *       target: str = ""
 *       progress: int = 0            # 0..100
 *       phase: ScanPhase = ScanPhase.IDLE
 *       hosts: list[Host] = []
 *       started_at: float | None = None
 *       finished_at: float | None = None
 *
 * The factory functions below apply defaults + coercion + enum validation the
 * same way a Pydantic model would on `Model(**payload)`, so a malformed SSE
 * frame can never corrupt the UI state tree.
 */

/* ------------------------------------------------------------------ enums -- */

/** Phases of the two-tiered pipeline (Ping Sweep -> Nmap Service Scan). */
export const ScanPhase = Object.freeze({
  IDLE: 'Idle',
  PING_SWEEP: 'Ping Sweep',
  NMAP_ENUMERATION: 'Nmap Enumeration',
  COMPLETE: 'Complete',
  HALTED: 'Halted',
  ERROR: 'Error',
});

export const HostStatus = Object.freeze({
  UP: 'up',
  DOWN: 'down',
  UNKNOWN: 'unknown',
});

export const PortState = Object.freeze({
  OPEN: 'open',
  FILTERED: 'filtered',
  CLOSED: 'closed',
  OPEN_FILTERED: 'open|filtered',
});

export const Protocol = Object.freeze({
  TCP: 'tcp',
  UDP: 'udp',
});

/** Vulnerability severity ranking (mirrors backend `Severity`). */
export const Severity = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
});

/** Severities that mark a host/port as a "critical finding". */
export const SEVERE = Object.freeze([Severity.CRITICAL, Severity.HIGH]);

/**
 * Presentation + progress metadata for each phase. `band` is the inclusive
 * progress window the phase occupies, used by the pipeline stepper and the
 * global progress bar to decide what is "done" vs "active".
 */
export const PHASE_META = Object.freeze({
  [ScanPhase.IDLE]: { index: 0, label: 'Standby', short: 'IDLE', band: [0, 0] },
  [ScanPhase.PING_SWEEP]: {
    index: 1,
    label: 'Phase 1 · Ping Sweep',
    short: 'PING SWEEP',
    band: [0, 40],
  },
  [ScanPhase.NMAP_ENUMERATION]: {
    index: 2,
    label: 'Phase 2 · Nmap Enumeration',
    short: 'NMAP ENUM',
    band: [40, 100],
  },
  [ScanPhase.COMPLETE]: { index: 3, label: 'Complete', short: 'COMPLETE', band: [100, 100] },
  [ScanPhase.HALTED]: { index: -1, label: 'Halted', short: 'HALTED', band: [0, 0] },
  [ScanPhase.ERROR]: { index: -1, label: 'Error', short: 'ERROR', band: [0, 0] },
});

/**
 * The two ordered stages of the pipeline, for the sidebar stepper. Kept
 * separate from PHASE_META so terminal states (Complete/Halted) don't appear
 * as steps.
 */
export const PIPELINE_STAGES = Object.freeze([
  {
    phase: ScanPhase.PING_SWEEP,
    code: 'P-01',
    title: 'Ping Sweep',
    detail: 'ICMP / ARP host discovery',
  },
  {
    phase: ScanPhase.NMAP_ENUMERATION,
    code: 'P-02',
    title: 'Nmap Enumeration',
    detail: 'Service + version detection',
  },
]);

/**
 * Quick-filter port groups. Values are the well-known ports each category
 * matches against a host's open ports.
 */
export const PORT_CATEGORIES = Object.freeze({
  web: { label: 'Web (80/443)', ports: [80, 443, 8080, 8443, 8000, 8888] },
  ssh: { label: 'SSH (22)', ports: [22, 2222] },
  database: {
    label: 'Database',
    ports: [3306, 5432, 1433, 1521, 27017, 6379, 5984, 9200, 11211],
  },
});

/* ------------------------------------------------------ coercion helpers -- */

function oneOf(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback;
}

function toInt(value, fallback = 0) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

/** Coerce any non-object (null, undefined, scalar) to {} so factories are total. */
function asObject(value) {
  return value && typeof value === 'object' ? value : {};
}

/* -------------------------------------------------------------- factories -- */

/**
 * @typedef {Object} Port
 * @property {number} port
 * @property {'tcp'|'udp'} protocol
 * @property {string} service
 * @property {string} version
 * @property {'open'|'filtered'|'closed'|'open|filtered'} state
 * @property {boolean} critical
 */

/**
 * @typedef {Object} Vuln
 * @property {string} id        CVE id or NSE script name
 * @property {string} title
 * @property {'critical'|'high'|'medium'|'low'|'info'} severity
 * @property {string} output    trimmed raw script output
 */

/** Build a validated Vuln from a raw (possibly partial) payload. */
export function VulnModel(data = {}) {
  data = asObject(data);
  const score = Number(data.cvss);
  return {
    id: data.id != null ? String(data.id) : 'unknown',
    title: data.title != null ? String(data.title) : '',
    severity: oneOf(data.severity, Object.values(Severity), Severity.INFO),
    cvss: data.cvss != null && Number.isFinite(score) ? score : null,
    output: data.output != null ? String(data.output) : '',
  };
}

/** Build a validated Port from a raw (possibly partial) payload. */
export function PortModel(data = {}) {
  data = asObject(data);
  return {
    port: toInt(data.port, 0),
    protocol: oneOf(data.protocol, Object.values(Protocol), Protocol.TCP),
    service: data.service ? String(data.service) : 'unknown',
    version: data.version != null ? String(data.version) : '',
    state: oneOf(data.state, Object.values(PortState), PortState.OPEN),
    critical: Boolean(data.critical),
    vulns: Array.isArray(data.vulns) ? data.vulns.map(VulnModel) : [],
  };
}

/**
 * @typedef {Object} Host
 * @property {string} ip
 * @property {string|null} hostname
 * @property {'up'|'down'|'unknown'} status
 * @property {string} os
 * @property {boolean} scanning
 * @property {Port[]} ports
 */

/** Build a validated Host from a raw (possibly partial) payload. */
export function HostModel(data = {}) {
  data = asObject(data);
  return {
    ip: String(data.ip ?? ''),
    hostname: data.hostname != null ? String(data.hostname) : null,
    status: oneOf(data.status, Object.values(HostStatus), HostStatus.UNKNOWN),
    os: data.os ? String(data.os) : 'Unknown',
    mac: data.mac != null ? String(data.mac) : null,
    vendor: data.vendor != null ? String(data.vendor) : null,
    device_type: data.device_type != null ? String(data.device_type) : '',
    discovered_via: data.discovered_via != null ? String(data.discovered_via) : '',
    scanning: Boolean(data.scanning),
    vulnScanning: Boolean(data.vulnScanning), // transient: per-host deep scan in flight
    ports: Array.isArray(data.ports) ? data.ports.map(PortModel) : [],
    vulns: Array.isArray(data.vulns) ? data.vulns.map(VulnModel) : [],
  };
}

/**
 * @typedef {Object} ScanState
 * @property {string|null} scan_id
 * @property {string} target
 * @property {number} progress
 * @property {string} phase
 * @property {Host[]} hosts
 * @property {number|null} started_at
 * @property {number|null} finished_at
 */

/** Build a validated ScanState snapshot from a raw SSE payload. */
export function ScanStateModel(data = {}) {
  data = asObject(data);
  return {
    scan_id: data.scan_id != null ? String(data.scan_id) : null,
    target: data.target ? String(data.target) : '',
    progress: clamp(toInt(data.progress, 0), 0, 100),
    phase: oneOf(data.phase, Object.values(ScanPhase), ScanPhase.IDLE),
    hosts: Array.isArray(data.hosts) ? data.hosts.map(HostModel) : [],
    started_at: data.started_at ?? null,
    finished_at: data.finished_at ?? null,
    message: data.message != null ? String(data.message) : null,
  };
}

/** A pristine, empty scan state. */
export function emptyScanState() {
  return ScanStateModel({});
}

/* --------------------------------------------------- derived-data helpers -- */

/** Count ports in the OPEN (or open|filtered) state for a host. */
export function countOpenPorts(host) {
  if (!host?.ports) return 0;
  return host.ports.filter(
    (p) => p.state === PortState.OPEN || p.state === PortState.OPEN_FILTERED,
  ).length;
}

/** Does this host expose at least one open port in the given category key? */
export function hostMatchesCategory(host, categoryKey) {
  const cat = PORT_CATEGORIES[categoryKey];
  if (!cat || !host?.ports) return false;
  return host.ports.some(
    (p) =>
      cat.ports.includes(p.port) &&
      (p.state === PortState.OPEN || p.state === PortState.OPEN_FILTERED),
  );
}

/** A host is "critical" if any port is flagged, or any high/critical vuln exists. */
export function isCriticalHost(host) {
  if (host?.ports?.some((p) => p.critical)) return true;
  const severe = (list) => list?.some((v) => SEVERE.includes(v.severity));
  if (severe(host?.vulns)) return true;
  return Boolean(host?.ports?.some((p) => severe(p.vulns)));
}

/** Count of port-level critical flags on a host. */
export function criticalCount(host) {
  return host?.ports?.filter((p) => p.critical).length ?? 0;
}

/** Flatten every vuln on a host (port-level + host-level), tagged with its port. */
export function collectVulns(host) {
  const out = [];
  for (const port of host?.ports ?? []) {
    for (const v of port.vulns ?? []) out.push({ ...v, port: port.port });
  }
  for (const v of host?.vulns ?? []) out.push({ ...v, port: null });
  // Rank critical → info so the worst findings surface first.
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return out.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
}

/** Total vuln findings on a host. */
export function vulnCount(host) {
  let n = host?.vulns?.length ?? 0;
  for (const port of host?.ports ?? []) n += port.vulns?.length ?? 0;
  return n;
}

/** Roll a flat snapshot up into the headline counters shown in the cockpit. */
export function summarizeHosts(hosts = []) {
  let up = 0;
  let down = 0;
  let openPorts = 0;
  let critical = 0;
  let vulns = 0;
  const services = new Set();

  for (const host of hosts) {
    if (host.status === HostStatus.UP) up += 1;
    else if (host.status === HostStatus.DOWN) down += 1;
    vulns += host.vulns?.length ?? 0;
    for (const port of host.ports) {
      if (port.state === PortState.OPEN || port.state === PortState.OPEN_FILTERED) {
        openPorts += 1;
        if (port.service && port.service !== 'unknown') services.add(port.service);
      }
      if (port.critical) critical += 1;
      vulns += port.vulns?.length ?? 0;
    }
  }

  return {
    total: hosts.length,
    up,
    down,
    openPorts,
    services: services.size,
    critical,
    vulns,
  };
}
