/**
 * IndustrialDashboard.jsx — the operator cockpit.
 * ---------------------------------------------------------------------------
 * A single, self-contained React component (plus small local sub-components)
 * that visualizes the Two-Tiered Scan Pipeline: Phase 1 Ping Sweep -> Phase 2
 * Nmap Service Scan. All scan state is read from `useScan()`; this file is
 * pure presentation + interaction (search, filtering, sorting, row expansion).
 *
 * Layout
 *   ┌─────────────────────────── ControlBar (top) ───────────────────────────┐
 *   │ brand · target input · start/stop · phase status · global progress bar  │
 *   ├──────────────┬──────────────────────────────────────────────────────────┤
 *   │  Sidebar     │  FilterToolbar (search + quick filters)                   │
 *   │  pipeline    │  ──────────────────────────────────────────────────────  │
 *   │  stats       │  AssetMatrix (expandable rows -> per-host port table)     │
 *   │  sessions    │                                                           │
 *   └──────────────┴──────────────────────────────────────────────────────────┘
 */

import React, { useEffect, useMemo, useState } from 'react';
import { useScan } from './context/ScanContext.jsx';
import {
  ScanPhase,
  HostStatus,
  PortState,
  Severity,
  PHASE_META,
  PIPELINE_STAGES,
  PORT_CATEGORIES,
  countOpenPorts,
  criticalCount,
  collectVulns,
  vulnCount,
  hostMatchesCategory,
  isCriticalHost,
} from './lib/schema.js';

/* ========================================================================== *
 * Icons — inline SVG, zero-dependency, stroke-based so they inherit color.
 * ========================================================================== */

const I = ({ children, className = 'w-4 h-4', viewBox = '0 0 24 24', ...rest }) => (
  <svg
    className={className}
    viewBox={viewBox}
    fill="none"
    stroke="currentColor"
    strokeWidth="1.6"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    {...rest}
  >
    {children}
  </svg>
);

const Icon = {
  Radar: ({ className }) => (
    <I className={className}>
      <circle cx="12" cy="12" r="9" className="opacity-30" />
      <circle cx="12" cy="12" r="5" className="opacity-30" />
      <circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none" />
      <g style={{ transformOrigin: '12px 12px' }} className="animate-radar">
        <path d="M12 12 L12 3" />
        <path d="M12 12 L19 9" className="opacity-50" />
      </g>
    </I>
  ),
  Play: ({ className }) => (
    <I className={className}>
      <path d="M6 4.5 L19 12 L6 19.5 Z" fill="currentColor" stroke="none" />
    </I>
  ),
  Stop: ({ className }) => (
    <I className={className}>
      <rect x="6" y="6" width="12" height="12" rx="1.5" fill="currentColor" stroke="none" />
    </I>
  ),
  Chevron: ({ className }) => (
    <I className={className}>
      <path d="M9 6 L15 12 L9 18" />
    </I>
  ),
  Check: ({ className }) => (
    <I className={className}>
      <path d="M4 12.5 L9 17.5 L20 6.5" />
    </I>
  ),
  Alert: ({ className }) => (
    <I className={className}>
      <path d="M12 3 L22 19 L2 19 Z" />
      <path d="M12 10 L12 14" />
      <path d="M12 16.5 L12 16.6" strokeWidth="2.2" />
    </I>
  ),
  Globe: ({ className }) => (
    <I className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12 H21 M12 3 C15 7 15 17 12 21 C9 17 9 7 12 3" />
    </I>
  ),
  Database: ({ className }) => (
    <I className={className}>
      <ellipse cx="12" cy="6" rx="7" ry="3" />
      <path d="M5 6 V18 C5 19.7 8.1 21 12 21 C15.9 21 19 19.7 19 18 V6" />
      <path d="M5 12 C5 13.7 8.1 15 12 15 C15.9 15 19 13.7 19 12" />
    </I>
  ),
  Terminal: ({ className }) => (
    <I className={className}>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M7 9 L10 12 L7 15 M12.5 15 H17" />
    </I>
  ),
  Search: ({ className }) => (
    <I className={className}>
      <circle cx="11" cy="11" r="7" />
      <path d="M16.5 16.5 L21 21" />
    </I>
  ),
  Server: ({ className }) => (
    <I className={className}>
      <rect x="3" y="4" width="18" height="7" rx="1.5" />
      <rect x="3" y="13" width="18" height="7" rx="1.5" />
      <path d="M7 7.5 H7.01 M7 16.5 H7.01" strokeWidth="2.2" />
    </I>
  ),
  Power: ({ className }) => (
    <I className={className}>
      <path d="M12 3 V12" />
      <path d="M7.5 6.5 A7 7 0 1 0 16.5 6.5" />
    </I>
  ),
  X: ({ className }) => (
    <I className={className}>
      <path d="M6 6 L18 18 M18 6 L6 18" />
    </I>
  ),
  Cpu: ({ className }) => (
    <I className={className}>
      <rect x="6" y="6" width="12" height="12" rx="1.5" />
      <rect x="9.5" y="9.5" width="5" height="5" rx="0.5" />
      <path d="M9 3 V6 M15 3 V6 M9 18 V21 M15 18 V21 M3 9 H6 M3 15 H6 M18 9 H21 M18 15 H21" />
    </I>
  ),
  Activity: ({ className }) => (
    <I className={className}>
      <path d="M3 12 H7 L10 4 L14 20 L17 12 H21" />
    </I>
  ),
  Layers: ({ className }) => (
    <I className={className}>
      <path d="M12 3 L21 8 L12 13 L3 8 Z" />
      <path d="M3 13 L12 18 L21 13" />
    </I>
  ),
  Shield: ({ className }) => (
    <I className={className}>
      <path d="M12 3 L20 6 V11 C20 16 16.5 19.5 12 21 C7.5 19.5 4 16 4 11 V6 Z" />
    </I>
  ),
  Bug: ({ className }) => (
    <I className={className}>
      <rect x="8" y="7" width="8" height="11" rx="4" />
      <path d="M4 11 H8 M16 11 H20 M5 6 L8 8 M19 6 L16 8 M4.5 16 H8 M16 16 H19.5 M12 7 V4 M9.5 4.5 L12 3 L14.5 4.5" />
    </I>
  ),
};

/* ========================================================================== *
 * Styling maps
 * ========================================================================== */

const PHASE_STYLE = {
  [ScanPhase.IDLE]: { dot: 'bg-slate-500', text: 'text-slate-400', pulse: false },
  [ScanPhase.PING_SWEEP]: { dot: 'bg-amber', text: 'text-amber', pulse: true },
  [ScanPhase.NMAP_ENUMERATION]: { dot: 'bg-amber', text: 'text-amber', pulse: true },
  [ScanPhase.COMPLETE]: { dot: 'bg-matrix', text: 'text-matrix', pulse: false },
  [ScanPhase.HALTED]: { dot: 'bg-crimson', text: 'text-crimson', pulse: false },
  [ScanPhase.ERROR]: { dot: 'bg-crimson', text: 'text-crimson', pulse: false },
};

const PORT_STATE_STYLE = {
  [PortState.OPEN]: 'text-matrix border-matrix/40 bg-matrix/10',
  [PortState.OPEN_FILTERED]: 'text-amber border-amber/40 bg-amber/10',
  [PortState.FILTERED]: 'text-crimson border-crimson/40 bg-crimson/10',
  [PortState.CLOSED]: 'text-slate-500 border-slate-600/40 bg-slate-700/20',
};

const SEVERITY_STYLE = {
  [Severity.CRITICAL]: 'text-crimson border-crimson/50 bg-crimson/15',
  [Severity.HIGH]: 'text-crimson border-crimson/40 bg-crimson/10',
  [Severity.MEDIUM]: 'text-amber border-amber/40 bg-amber/10',
  [Severity.LOW]: 'text-slate-300 border-slate-600/50 bg-slate-700/20',
  [Severity.INFO]: 'text-slate-400 border-slate-600/40 bg-slate-700/10',
};

// Shared column template so the matrix header and every row stay aligned.
// chevron | status | IP | hostname | vendor | MAC | open-ports | scan-status
const GRID_COLS =
  'grid grid-cols-[34px_52px_minmax(108px,1fr)_minmax(120px,1.2fr)_minmax(120px,1.2fr)_minmax(140px,150px)_72px_118px] items-center';

const QUICK_FILTERS = [
  { key: 'web', label: 'Web · 80/443', Icon: Icon.Globe },
  { key: 'ssh', label: 'SSH · 22', Icon: Icon.Terminal },
  { key: 'database', label: 'Database', Icon: Icon.Database },
  { key: 'critical', label: 'Critical Findings', Icon: Icon.Alert, danger: true },
];

/* ========================================================================== *
 * Small helpers
 * ========================================================================== */

const ipSortKey = (ip) =>
  ip.split('.').reduce((acc, oct) => acc * 256 + (parseInt(oct, 10) || 0), 0);

function hostMatchesQuery(host, q) {
  if (!q) return true;
  const needle = q.toLowerCase();
  if (host.ip.includes(needle)) return true;
  if (host.hostname && host.hostname.toLowerCase().includes(needle)) return true;
  if (host.os && host.os.toLowerCase().includes(needle)) return true;
  if (host.vendor && host.vendor.toLowerCase().includes(needle)) return true;
  if (host.mac && host.mac.toLowerCase().includes(needle)) return true;
  return host.ports.some(
    (p) =>
      String(p.port).includes(needle) ||
      p.service.toLowerCase().includes(needle) ||
      (p.version && p.version.toLowerCase().includes(needle)),
  );
}

function hostMatchesFilter(host, key) {
  if (key === 'critical') return isCriticalHost(host);
  return hostMatchesCategory(host, key);
}

function relativeTime(epochSeconds) {
  if (!epochSeconds) return '—';
  const diff = Math.max(0, Date.now() / 1000 - epochSeconds);
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

/* ========================================================================== *
 * UI primitives
 * ========================================================================== */

function Panel({ title, icon, action, children, className = '', bodyClassName = '' }) {
  return (
    <section
      className={`rounded-md border border-slate-700/70 bg-steel-900/70 shadow-inset-panel backdrop-blur-sm ${className}`}
    >
      {title && (
        <header className="flex items-center justify-between border-b border-slate-700/70 bg-steel-850/80 px-3 py-2">
          <div className="flex items-center gap-2 text-slate-300">
            {icon}
            <h2 className="text-[11px] font-semibold uppercase tracking-[0.14em]">{title}</h2>
          </div>
          {action}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

function StatusDot({ status }) {
  const map = {
    [HostStatus.UP]: 'bg-matrix shadow-glow-matrix',
    [HostStatus.DOWN]: 'bg-crimson/70',
    [HostStatus.UNKNOWN]: 'bg-slate-600',
  };
  return (
    <span className="inline-flex items-center justify-center" title={`Host ${status}`}>
      <span className={`h-2.5 w-2.5 rounded-full ${map[status] || map.unknown}`} />
    </span>
  );
}

function Spinner({ className = 'w-4 h-4' }) {
  return (
    <svg className={`${className} animate-spin`} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2.4" className="opacity-20" />
      <path
        d="M21 12 A9 9 0 0 0 12 3"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Thin badge with monospace content (used for ports, counts, codes). */
function Tag({ children, className = '' }) {
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[11px] leading-none ${className}`}
    >
      {children}
    </span>
  );
}

/* ========================================================================== *
 * A · Global Control Panel (top bar)
 * ========================================================================== */

const SOURCE_BADGE = {
  live: { label: 'Live Stream', dot: 'bg-matrix', text: 'text-matrix' },
  mock: { label: 'Demo Stream', dot: 'bg-amber', text: 'text-amber' },
  null: { label: 'Stream Idle', dot: 'bg-slate-500', text: 'text-slate-400' },
};

function ControlBar() {
  const { target, phase, progress, running, source, deepScan, startScan, stopScan, toggleDeep,
    setTarget } = useScan();
  const [input, setInput] = useState(target);
  const badge = SOURCE_BADGE[source] || SOURCE_BADGE.null;

  // Auto-detect the network you're actually on (via the backend) and pre-fill
  // the target — so "Start Scan" scans the right subnet out of the box.
  useEffect(() => {
    let cancelled = false;
    fetch('/api/network')
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!cancelled && data && data.suggested_target) {
          setInput(data.suggested_target);
          setTarget?.(data.suggested_target);
        }
      })
      .catch(() => {}); // backend offline — keep the default
    return () => {
      cancelled = true;
    };
  }, [setTarget]);

  const phaseStyle = PHASE_STYLE[phase] || PHASE_STYLE[ScanPhase.IDLE];
  const phaseMeta = PHASE_META[phase] || PHASE_META[ScanPhase.IDLE];

  const submit = () => {
    if (running) return;
    startScan(input, deepScan);
  };

  return (
    <header className="sticky top-0 z-30 border-b border-slate-700/80 bg-steel-950/95 backdrop-blur">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-3 px-4 py-3">
        {/* Brand ---------------------------------------------------------- */}
        <div className="flex items-center gap-3 pr-4">
          <div className="grid h-9 w-9 place-items-center rounded border border-amber/40 bg-amber/10 text-amber">
            <Icon.Radar className="h-6 w-6" />
          </div>
          <div className="leading-tight">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-semibold tracking-[0.2em] text-slate-100">
                ENUM<span className="text-amber">GRID</span>
              </span>
              <span className="rounded-sm border border-slate-600 px-1 py-px font-mono text-[9px] uppercase tracking-wider text-slate-500">
                v0.1
              </span>
            </div>
            <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">
              Network Enumeration Platform
            </div>
          </div>
        </div>

        {/* Target + actions ---------------------------------------------- */}
        <div className="flex min-w-[320px] flex-1 items-center gap-2">
          <label className="relative flex flex-1 items-center">
            <span className="pointer-events-none absolute left-3 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
              Target
            </span>
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && submit()}
              spellCheck={false}
              placeholder="192.168.1.0/24"
              disabled={running}
              className="w-full rounded border border-slate-700 bg-steel-900 py-2 pl-[58px] pr-3 font-mono text-sm text-slate-100 outline-none transition focus:border-amber/60 focus:shadow-glow-amber disabled:opacity-60"
            />
          </label>

          {!running ? (
            <button
              onClick={submit}
              className="group inline-flex items-center gap-2 rounded border border-matrix/50 bg-matrix/10 px-4 py-2 text-sm font-semibold text-matrix transition hover:bg-matrix hover:text-steel-950 hover:shadow-glow-matrix focus:outline-none focus:ring-1 focus:ring-matrix"
            >
              <Icon.Play className="h-4 w-4" />
              Start Scan
            </button>
          ) : (
            <button
              onClick={stopScan}
              className="group inline-flex items-center gap-2 rounded border border-crimson/60 bg-crimson/10 px-4 py-2 text-sm font-semibold text-crimson transition hover:bg-crimson hover:text-white hover:shadow-glow-crimson focus:outline-none focus:ring-1 focus:ring-crimson"
            >
              <Icon.Stop className="h-4 w-4" />
              Stop Scan
            </button>
          )}

          {/* Deep scan toggle — adds the NSE vuln-script pass. */}
          <button
            onClick={toggleDeep}
            disabled={running}
            aria-pressed={deepScan}
            title="Deep Scan: run NSE vuln scripts (nmap --script vuln) for real CVE findings. Slower."
            className={`inline-flex shrink-0 items-center gap-1.5 rounded border px-3 py-2 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-50 ${
              deepScan
                ? 'border-crimson/60 bg-crimson/15 text-crimson shadow-glow-crimson'
                : 'border-slate-700 bg-steel-900 text-slate-400 hover:border-slate-500 hover:text-slate-200'
            }`}
          >
            <Icon.Shield className="h-4 w-4" />
            Deep
          </button>
        </div>

        {/* Phase status --------------------------------------------------- */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 rounded border border-slate-700 bg-steel-900 px-3 py-1.5">
            <span
              className={`h-2.5 w-2.5 rounded-full ${phaseStyle.dot} ${
                phaseStyle.pulse ? 'animate-pulse-glow' : ''
              }`}
            />
            <div className="leading-tight">
              <div className="text-[9px] uppercase tracking-widest text-slate-500">Phase</div>
              <div className={`font-mono text-xs font-semibold ${phaseStyle.text}`}>
                {phaseMeta.label}
              </div>
            </div>
          </div>
          <div
            className={`hidden items-center gap-1.5 rounded border border-slate-700 bg-steel-900 px-2.5 py-1.5 sm:flex ${badge.text}`}
            title={
              source === 'live'
                ? 'Streaming from the FastAPI /api/scan/stream backend'
                : source === 'mock'
                  ? 'Using the offline mock engine'
                  : 'Idle — start a scan to open the stream'
            }
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${badge.dot} ${running ? 'animate-pulse-glow' : ''}`}
            />
            <span className="font-mono text-[10px] uppercase tracking-widest">{badge.label}</span>
          </div>
        </div>
      </div>

      {/* Global progress bar ---------------------------------------------- */}
      <GlobalProgress phase={phase} progress={progress} running={running} />
    </header>
  );
}

function GlobalProgress({ phase, progress, running }) {
  const isComplete = phase === ScanPhase.COMPLETE;
  const isHalted = phase === ScanPhase.HALTED || phase === ScanPhase.ERROR;
  const barColor = isHalted ? 'bg-crimson' : isComplete ? 'bg-matrix' : 'bg-amber';
  const glow = isHalted ? '' : isComplete ? 'shadow-glow-matrix' : 'shadow-glow-amber';

  return (
    <div className="relative h-7 border-t border-slate-800 bg-steel-950/80">
      {/* Phase boundary tick at 40% (Ping Sweep -> Nmap). */}
      <div
        className="absolute top-0 z-10 h-full w-px bg-slate-700/80"
        style={{ left: '40%' }}
        title="Phase 1 → Phase 2 boundary"
      />
      <div className="absolute inset-0 flex items-center px-4">
        <div className="relative h-1.5 flex-1 overflow-hidden rounded-full bg-steel-800">
          <div
            className={`progress-stripes h-full rounded-full ${barColor} ${glow} ${
              running ? 'animate-stripe' : ''
            } transition-[width] duration-500 ease-out`}
            style={{ width: `${progress}%` }}
          />
        </div>
        <div className="ml-3 flex items-center gap-3">
          <span className="font-mono text-xs font-semibold tabular-nums text-slate-200">
            {String(progress).padStart(3, ' ')}%
          </span>
        </div>
      </div>
      {/* Phase band labels */}
      <div className="pointer-events-none absolute inset-x-4 bottom-0 flex justify-between">
        <span className="font-mono text-[8px] uppercase tracking-widest text-slate-600">
          ◄ ping sweep
        </span>
        <span className="-translate-x-12 font-mono text-[8px] uppercase tracking-widest text-slate-600">
          nmap enum ►
        </span>
      </div>
    </div>
  );
}

/* ========================================================================== *
 * Sidebar · pipeline stepper + stats + session log
 * ========================================================================== */

function PipelineStepper() {
  const { phase, progress } = useScan();
  const activeIndex = PHASE_META[phase]?.index ?? 0;

  return (
    <Panel title="Scan Pipeline" icon={<Icon.Layers className="h-3.5 w-3.5 text-amber" />}>
      <ol className="relative px-4 py-4">
        {/* connector rail */}
        <span className="absolute bottom-7 left-[27px] top-7 w-px bg-slate-700" aria-hidden />
        {PIPELINE_STAGES.map((stage) => {
          const meta = PHASE_META[stage.phase];
          const isActive = phase === stage.phase;
          const isDone =
            activeIndex > meta.index || phase === ScanPhase.COMPLETE;
          const state = isActive ? 'active' : isDone ? 'done' : 'pending';

          const ring =
            state === 'active'
              ? 'border-amber bg-amber/15 text-amber shadow-glow-amber animate-pulse-glow'
              : state === 'done'
                ? 'border-matrix bg-matrix/15 text-matrix'
                : 'border-slate-600 bg-steel-900 text-slate-500';

          return (
            <li key={stage.phase} className="relative flex gap-3 pb-5 last:pb-0">
              <span
                className={`relative z-10 grid h-7 w-7 shrink-0 place-items-center rounded-full border ${ring}`}
              >
                {state === 'done' ? (
                  <Icon.Check className="h-4 w-4" />
                ) : state === 'active' ? (
                  <Spinner className="h-3.5 w-3.5" />
                ) : (
                  <span className="font-mono text-[10px]">{meta.index}</span>
                )}
              </span>
              <div className="pt-0.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] text-slate-500">{stage.code}</span>
                  <span
                    className={`text-xs font-semibold ${
                      state === 'pending' ? 'text-slate-500' : 'text-slate-200'
                    }`}
                  >
                    {stage.title}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500">{stage.detail}</div>
                {isActive && (
                  <div className="mt-1 font-mono text-[10px] text-amber">
                    ▮ running · {progress}%
                  </div>
                )}
              </div>
            </li>
          );
        })}
      </ol>
    </Panel>
  );
}

function StatGrid() {
  const { stats } = useScan();
  const cells = [
    { label: 'Hosts Up', value: stats.up, accent: 'text-matrix', Icon: Icon.Server },
    { label: 'Unreachable', value: stats.down, accent: 'text-slate-400', Icon: Icon.Power },
    { label: 'Open Ports', value: stats.openPorts, accent: 'text-amber', Icon: Icon.Activity },
    { label: 'Services', value: stats.services, accent: 'text-slate-200', Icon: Icon.Cpu },
  ];
  return (
    <Panel title="Telemetry" icon={<Icon.Activity className="h-3.5 w-3.5 text-amber" />}>
      <div className="grid grid-cols-2 gap-px bg-slate-700/60">
        {cells.map((c) => (
          <div key={c.label} className="bg-steel-900 px-3 py-3">
            <div className="flex items-center gap-1.5 text-slate-500">
              <c.Icon className="h-3.5 w-3.5" />
              <span className="text-[10px] uppercase tracking-wider">{c.label}</span>
            </div>
            <div className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${c.accent}`}>
              {String(c.value).padStart(2, '0')}
            </div>
          </div>
        ))}
      </div>
      {stats.critical > 0 && (
        <div className="flex items-center justify-between border-t border-crimson/30 bg-crimson/10 px-3 py-2">
          <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-crimson">
            <Icon.Alert className="h-3.5 w-3.5" />
            Critical Findings
          </span>
          <span className="font-mono text-sm font-bold text-crimson">{stats.critical}</span>
        </div>
      )}
      {stats.vulns > 0 && (
        <div className="flex items-center justify-between border-t border-crimson/30 bg-crimson/[0.07] px-3 py-2">
          <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-crimson">
            <Icon.Bug className="h-3.5 w-3.5" />
            Vulnerabilities
          </span>
          <span className="font-mono text-sm font-bold text-crimson">{stats.vulns}</span>
        </div>
      )}
    </Panel>
  );
}

function SessionLog() {
  const { sessions, scanId, shortId } = useScan();
  return (
    <Panel
      title="Scan Sessions"
      icon={<Icon.Radar className="h-3.5 w-3.5 text-amber" />}
      bodyClassName="divide-y divide-slate-800 max-h-56 overflow-y-auto"
    >
      {sessions.map((s) => {
        const st = PHASE_STYLE[s.status] || PHASE_STYLE[ScanPhase.IDLE];
        const isCurrent = s.id === scanId;
        return (
          <div
            key={s.id}
            className={`flex items-center gap-3 px-3 py-2.5 ${
              isCurrent ? 'bg-amber/5' : ''
            }`}
          >
            <span className={`h-2 w-2 shrink-0 rounded-full ${st.dot} ${st.pulse ? 'animate-pulse-glow' : ''}`} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate font-mono text-xs text-slate-200">{s.target}</span>
                {isCurrent && (
                  <span className="rounded-sm bg-amber/20 px-1 font-mono text-[8px] uppercase tracking-wider text-amber">
                    live
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 font-mono text-[10px] text-slate-500">
                <span>#{shortId(s.id)}</span>
                <span>·</span>
                <span>{relativeTime(s.startedAt)}</span>
              </div>
            </div>
            <div className="text-right">
              <div className={`font-mono text-[10px] font-semibold uppercase ${st.text}`}>
                {PHASE_META[s.status]?.short || s.status}
              </div>
              <div className="font-mono text-[10px] text-slate-500">
                {s.upCount}/{s.hostCount} up
              </div>
            </div>
          </div>
        );
      })}
    </Panel>
  );
}

function Sidebar() {
  return (
    <aside className="flex w-[320px] shrink-0 flex-col gap-3 overflow-y-auto border-r border-slate-800 bg-steel-950/60 p-3">
      <PipelineStepper />
      <StatGrid />
      <SessionLog />
      <div className="mt-auto px-1 pt-2 font-mono text-[9px] leading-relaxed text-slate-600">
        <p className="uppercase tracking-widest text-slate-500">// operator note</p>
        <p className="mt-1">
          Live frames stream from <span className="text-amber">/api/scan/stream</span> (FastAPI +
          nmap). If the backend is offline, the dashboard falls back to the mock engine
          automatically.
        </p>
      </div>
    </aside>
  );
}

/* ========================================================================== *
 * C · Search & advanced filtering toolbar
 * ========================================================================== */

function FilterToolbar({ query, setQuery, filters, toggleFilter, upOnly, setUpOnly, shown, total }) {
  return (
    <div className="sticky top-0 z-20 flex flex-wrap items-center gap-3 border-b border-slate-800 bg-steel-950/95 px-4 py-3 backdrop-blur">
      {/* Search */}
      <label className="relative flex min-w-[260px] flex-1 items-center">
        <Icon.Search className="pointer-events-none absolute left-3 h-4 w-4 text-slate-500" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          spellCheck={false}
          placeholder="Search IP, hostname, OS, service or version…"
          className="w-full rounded border border-slate-700 bg-steel-900 py-2 pl-9 pr-8 font-mono text-sm text-slate-100 outline-none transition focus:border-amber/60 focus:shadow-glow-amber"
        />
        {query && (
          <button
            onClick={() => setQuery('')}
            className="absolute right-2 text-slate-500 hover:text-slate-200"
            aria-label="Clear search"
          >
            <Icon.X className="h-4 w-4" />
          </button>
        )}
      </label>

      {/* Quick filters */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-[10px] uppercase tracking-widest text-slate-500">
          Filters
        </span>
        {QUICK_FILTERS.map((f) => {
          const active = filters.has(f.key);
          const danger = f.danger;
          const base =
            'inline-flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs font-medium transition';
          const cls = active
            ? danger
              ? 'border-crimson bg-crimson/15 text-crimson shadow-glow-crimson'
              : 'border-amber bg-amber/15 text-amber shadow-glow-amber'
            : 'border-slate-700 bg-steel-900 text-slate-400 hover:border-slate-500 hover:text-slate-200';
          return (
            <button
              key={f.key}
              onClick={() => toggleFilter(f.key)}
              aria-pressed={active}
              className={`${base} ${cls}`}
            >
              <f.Icon className="h-3.5 w-3.5" />
              {f.label}
            </button>
          );
        })}

        {/* Up-only toggle */}
        <button
          onClick={() => setUpOnly((v) => !v)}
          aria-pressed={upOnly}
          className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs font-medium transition ${
            upOnly
              ? 'border-matrix bg-matrix/15 text-matrix'
              : 'border-slate-700 bg-steel-900 text-slate-400 hover:border-slate-500 hover:text-slate-200'
          }`}
        >
          <span className="h-2 w-2 rounded-full bg-current" />
          Up Only
        </button>
      </div>

      <div className="ml-auto font-mono text-xs text-slate-500">
        <span className="text-slate-200">{shown}</span> / {total} hosts
      </div>
    </div>
  );
}

/* ========================================================================== *
 * B · Asset Matrix (main data grid)
 * ========================================================================== */

function SortHeader({ label, active, dir, onClick, className = '' }) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1 text-left uppercase tracking-wider transition hover:text-slate-200 ${
        active ? 'text-amber' : 'text-slate-500'
      } ${className}`}
    >
      {label}
      <span className="font-mono text-[9px]">{active ? (dir === 'asc' ? '▲' : '▼') : '↕'}</span>
    </button>
  );
}

function PortDetailTable({ host }) {
  const { scanHostVulns } = useScan();
  const vulns = collectVulns(host);

  return (
    <div className="space-y-2 px-3 pb-3 pt-1 sm:px-12">
      {/* Per-host toolbar — always visible so nmap can be run on any device. */}
      <div className="flex items-center justify-between rounded border border-slate-700/70 bg-steel-850/60 px-3 py-1.5">
        <div className="flex items-center gap-2 truncate font-mono text-[11px] text-slate-400">
          <Icon.Server className="h-3.5 w-3.5 shrink-0 text-slate-500" />
          <span className="text-slate-200">{host.ip}</span>
          {host.vendor && (
            <>
              <span className="text-slate-600">·</span>
              <span className="text-slate-300">{host.vendor}</span>
            </>
          )}
          {host.mac && (
            <>
              <span className="text-slate-600">·</span>
              <span className="truncate">{host.mac}</span>
            </>
          )}
          {host.os && host.os !== 'Unknown' && (
            <>
              <span className="text-slate-600">·</span>
              <span className="truncate">{host.os}</span>
            </>
          )}
          {host.ports.length > 0 && (
            <>
              <span className="text-slate-600">·</span>
              <span>{host.ports.length} ports</span>
            </>
          )}
          {vulns.length > 0 && (
            <>
              <span className="text-slate-600">·</span>
              <span className="text-crimson">{vulns.length} vulns</span>
            </>
          )}
        </div>
        <button
          onClick={(e) => {
            e.stopPropagation();
            scanHostVulns(host.ip);
          }}
          disabled={host.vulnScanning}
          title="Deep-scan just this host for vulnerabilities (nmap --script vuln,vulners)"
          className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider transition disabled:cursor-not-allowed ${
            host.vulnScanning
              ? 'border-amber/50 bg-amber/10 text-amber'
              : 'border-crimson/50 bg-crimson/10 text-crimson hover:bg-crimson hover:text-white'
          }`}
        >
          {host.vulnScanning ? (
            <>
              <Spinner className="h-3 w-3" />
              Nmap scanning…
            </>
          ) : (
            <>
              <Icon.Search className="h-3.5 w-3.5" />
              {host.ports.length > 0 ? 'Re-scan (nmap)' : 'Nmap Scan'}
            </>
          )}
        </button>
      </div>

      {host.vulnScanning ? (
        <div className="flex items-center gap-2 px-3 py-4 font-mono text-xs text-amber">
          <Spinner className="h-4 w-4" />
          nmap -sV {host.ip} — enumerating services…
        </div>
      ) : host.ports.length ? (
        <>
      <div className="overflow-hidden rounded border border-slate-700/70 bg-steel-950/60">
        {/* header */}
        <div className="grid grid-cols-[80px_72px_minmax(120px,1fr)_minmax(150px,1.5fr)_120px] border-b border-slate-700/70 bg-steel-850 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
          <span>Port</span>
          <span>Proto</span>
          <span>Service</span>
          <span>Version</span>
          <span className="text-right">State</span>
        </div>
        {/* rows */}
        <div className="divide-y divide-slate-800/70">
          {host.ports.map((p) => (
            <div
              key={`${p.port}/${p.protocol}`}
              className={`grid grid-cols-[80px_72px_minmax(120px,1fr)_minmax(150px,1.5fr)_120px] items-center px-3 py-1.5 font-mono text-xs ${
                p.critical ? 'bg-crimson/5' : ''
              }`}
            >
              <span className="flex items-center gap-1.5 font-semibold text-slate-100">
                {p.critical && <Icon.Alert className="h-3 w-3 text-crimson" />}
                {p.port}
              </span>
              <span className="uppercase text-slate-400">{p.protocol}</span>
              <span className="truncate text-slate-200">{p.service}</span>
              <span className="truncate text-slate-400">{p.version || '—'}</span>
              <span className="flex justify-end">
                <Tag className={PORT_STATE_STYLE[p.state]}>{p.state}</Tag>
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Vulnerability findings (from the NSE --script vuln deep pass). */}
      {vulns.length > 0 && (
        <div className="overflow-hidden rounded border border-crimson/30 bg-crimson/[0.04]">
          <div className="flex items-center gap-2 border-b border-crimson/20 bg-crimson/10 px-3 py-1.5">
            <Icon.Bug className="h-3.5 w-3.5 text-crimson" />
            <span className="text-[10px] font-semibold uppercase tracking-wider text-crimson">
              Vulnerability Findings
            </span>
            <span className="font-mono text-[10px] font-bold text-crimson">{vulns.length}</span>
            <span className="ml-auto font-mono text-[9px] uppercase tracking-wider text-slate-500">
              nmap --script vuln
            </span>
          </div>
          <ul className="divide-y divide-slate-800/70">
            {vulns.map((v, i) => (
              <li key={`${v.id}-${i}`} className="flex items-start gap-3 px-3 py-2">
                <span
                  className={`mt-px inline-flex shrink-0 items-center rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-wider ${
                    SEVERITY_STYLE[v.severity] || SEVERITY_STYLE.info
                  }`}
                >
                  {v.severity}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-semibold text-slate-100">{v.id}</span>
                    {v.port != null && (
                      <span className="font-mono text-[10px] text-slate-500">:{v.port}</span>
                    )}
                    {v.cvss != null && (
                      <span className="shrink-0 rounded border border-slate-600/50 bg-slate-800/60 px-1 font-mono text-[9px] font-semibold text-slate-300">
                        CVSS {v.cvss.toFixed(1)}
                      </span>
                    )}
                    {v.title && <span className="truncate text-xs text-slate-400">{v.title}</span>}
                  </div>
                  {v.output && (
                    <p className="mt-0.5 truncate font-mono text-[10px] leading-relaxed text-slate-500">
                      {v.output.replace(/\s*\n\s*/g, ' · ')}
                    </p>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
        </>
      ) : (
        <div className="px-3 py-4 font-mono text-xs text-slate-500">
          {host.status === HostStatus.UP
            ? '// no service scan yet — click "Nmap Scan" to enumerate ports & services'
            : '// host unreachable'}
        </div>
      )}
    </div>
  );
}

function AssetRow({ host, expanded, onToggle }) {
  const openCount = countOpenPorts(host);
  const crit = criticalCount(host);
  const isDown = host.status === HostStatus.DOWN;

  return (
    <div className={isDown ? 'opacity-55' : ''}>
      {/* main row */}
      <div
        role="button"
        tabIndex={0}
        onClick={onToggle}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), onToggle())}
        className={`${GRID_COLS} cursor-pointer px-2 py-2.5 text-sm transition hover:bg-steel-800/60 ${
          expanded ? 'bg-steel-800/40' : ''
        }`}
      >
        {/* chevron */}
        <span className="flex justify-center text-slate-500">
          <Icon.Chevron
            className={`h-4 w-4 transition-transform ${expanded ? 'rotate-90 text-amber' : ''}`}
          />
        </span>
        {/* status */}
        <span className="flex justify-center">
          <StatusDot status={host.status} />
        </span>
        {/* ip */}
        <span className="font-mono font-semibold text-slate-100">{host.ip}</span>
        {/* hostname */}
        <span className="truncate font-mono text-xs text-slate-400">
          {host.hostname || <span className="text-slate-600">— no PTR —</span>}
        </span>
        {/* vendor */}
        <span className="flex items-center gap-1.5 truncate text-xs">
          {host.vendor === '(private/random)' ? (
            <span className="font-mono italic text-slate-500">private</span>
          ) : host.vendor ? (
            <>
              <Icon.Cpu className="h-3.5 w-3.5 shrink-0 text-slate-500" />
              <span className="truncate text-slate-200">{host.vendor}</span>
            </>
          ) : (
            <span className="text-slate-600">—</span>
          )}
        </span>
        {/* mac */}
        <span className="truncate font-mono text-[11px] text-slate-400">
          {host.mac || <span className="text-slate-600">—</span>}
        </span>
        {/* open ports count */}
        <span className="flex items-center justify-center gap-1">
          {isDown ? (
            <span className="font-mono text-xs text-slate-600">—</span>
          ) : (
            <>
              <span
                className={`font-mono text-sm font-bold tabular-nums ${
                  openCount ? 'text-amber' : 'text-slate-500'
                }`}
              >
                {openCount}
              </span>
              {crit > 0 && (
                <span title={`${crit} critical`} className="text-crimson">
                  <Icon.Alert className="h-3.5 w-3.5" />
                </span>
              )}
            </>
          )}
        </span>
        {/* scanning status */}
        <span className="flex justify-end pr-1">
          <ScanStateBadge host={host} />
        </span>
      </div>

      {/* expansion */}
      {expanded && (
        <div className="animate-expand-in border-y border-slate-800 bg-steel-950/40">
          <PortDetailTable host={host} />
        </div>
      )}
    </div>
  );
}

function ScanStateBadge({ host }) {
  if (host.vulnScanning) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded border border-crimson/40 bg-crimson/10 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-crimson">
        <Spinner className="h-3 w-3" />
        Vuln Scan
      </span>
    );
  }
  if (host.scanning) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded border border-amber/40 bg-amber/10 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-amber">
        <Spinner className="h-3 w-3" />
        Scanning
      </span>
    );
  }
  if (host.status === HostStatus.DOWN) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded border border-slate-700 bg-steel-900 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-slate-500">
        Skipped
      </span>
    );
  }
  if (host.ports.length) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded border border-matrix/40 bg-matrix/10 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-matrix">
        <Icon.Check className="h-3 w-3" />
        Done
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded border border-slate-700 bg-steel-900 px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-slate-500">
      Queued
    </span>
  );
}

function MatrixHeader({ sort, onSort, allExpanded, onToggleAll }) {
  return (
    <div
      className={`${GRID_COLS} sticky top-0 z-10 border-b border-slate-700 bg-steel-850/95 px-2 py-2 text-[10px] font-semibold backdrop-blur`}
    >
      <button
        onClick={onToggleAll}
        title={allExpanded ? 'Collapse all' : 'Expand all'}
        className="flex justify-center text-slate-500 hover:text-amber"
      >
        <Icon.Chevron className={`h-4 w-4 transition-transform ${allExpanded ? 'rotate-90' : ''}`} />
      </button>
      <SortHeader
        label=""
        active={sort.key === 'status'}
        dir={sort.dir}
        onClick={() => onSort('status')}
        className="justify-center"
      />
      <SortHeader
        label="IP Address"
        active={sort.key === 'ip'}
        dir={sort.dir}
        onClick={() => onSort('ip')}
      />
      <span className="uppercase tracking-wider text-slate-500">Hostname</span>
      <span className="uppercase tracking-wider text-slate-500">Vendor</span>
      <span className="uppercase tracking-wider text-slate-500">MAC</span>
      <SortHeader
        label="Ports"
        active={sort.key === 'ports'}
        dir={sort.dir}
        onClick={() => onSort('ports')}
        className="justify-center"
      />
      <span className="text-right uppercase tracking-wider text-slate-500">Status</span>
    </div>
  );
}

function EmptyState() {
  const { startScan, target, deepScan } = useScan();
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-4 px-6 py-20 text-center">
      <div className="grid h-16 w-16 place-items-center rounded-full border border-slate-700 bg-steel-900 text-slate-600">
        <Icon.Radar className="h-9 w-9" />
      </div>
      <div>
        <h3 className="font-mono text-sm uppercase tracking-[0.2em] text-slate-300">
          Asset matrix standby
        </h3>
        <p className="mx-auto mt-2 max-w-md text-sm text-slate-500">
          No hosts in the buffer. Enter a target range and start a scan to run Phase 1 host
          discovery, then Phase 2 service enumeration.
        </p>
      </div>
      <button
        onClick={() => startScan(target, deepScan)}
        className="inline-flex items-center gap-2 rounded border border-matrix/50 bg-matrix/10 px-4 py-2 text-sm font-semibold text-matrix transition hover:bg-matrix hover:text-steel-950"
      >
        <Icon.Play className="h-4 w-4" />
        Launch scan on {target}
      </button>
    </div>
  );
}

function AssetMatrix({ hosts }) {
  const [query, setQuery] = useState('');
  const [filters, setFilters] = useState(() => new Set());
  const [upOnly, setUpOnly] = useState(false);
  const [expanded, setExpanded] = useState(() => new Set());
  const [sort, setSort] = useState({ key: 'ip', dir: 'asc' });

  const toggleFilter = (key) =>
    setFilters((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });

  const onSort = (key) =>
    setSort((prev) =>
      prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' },
    );

  const toggleRow = (ip) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(ip) ? next.delete(ip) : next.add(ip);
      return next;
    });

  // Derive the visible host list: filter -> search -> sort.
  const visible = useMemo(() => {
    let rows = hosts;
    if (upOnly) rows = rows.filter((h) => h.status === HostStatus.UP);
    if (filters.size) {
      rows = rows.filter((h) => [...filters].every((k) => hostMatchesFilter(h, k)));
    }
    if (query.trim()) rows = rows.filter((h) => hostMatchesQuery(h, query.trim()));

    const dir = sort.dir === 'asc' ? 1 : -1;
    const sorted = [...rows].sort((a, b) => {
      let cmp = 0;
      if (sort.key === 'ip') cmp = ipSortKey(a.ip) - ipSortKey(b.ip);
      else if (sort.key === 'ports') cmp = countOpenPorts(a) - countOpenPorts(b);
      else if (sort.key === 'status') cmp = a.status.localeCompare(b.status);
      return cmp * dir;
    });
    return sorted;
  }, [hosts, upOnly, filters, query, sort]);

  const allExpanded = visible.length > 0 && visible.every((h) => expanded.has(h.ip));
  const toggleAll = () =>
    setExpanded(allExpanded ? new Set() : new Set(visible.map((h) => h.ip)));

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <FilterToolbar
        query={query}
        setQuery={setQuery}
        filters={filters}
        toggleFilter={toggleFilter}
        upOnly={upOnly}
        setUpOnly={setUpOnly}
        shown={visible.length}
        total={hosts.length}
      />

      {hosts.length === 0 ? (
        <EmptyState />
      ) : (
        <div className="min-h-0 flex-1 overflow-auto">
          <MatrixHeader
            sort={sort}
            onSort={onSort}
            allExpanded={allExpanded}
            onToggleAll={toggleAll}
          />
          {visible.length === 0 ? (
            <div className="px-6 py-16 text-center font-mono text-sm text-slate-500">
              // no hosts match the active search / filters
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {visible.map((host) => (
                <AssetRow
                  key={host.ip}
                  host={host}
                  expanded={expanded.has(host.ip)}
                  onToggle={() => toggleRow(host.ip)}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ========================================================================== *
 * Root
 * ========================================================================== */

export default function IndustrialDashboard() {
  const { hosts, phase } = useScan();

  // Reflect the live phase in the document title — a small cockpit touch.
  useEffect(() => {
    document.title =
      phase === ScanPhase.IDLE
        ? 'ENUMGRID // Network Enumeration'
        : `ENUMGRID // ${PHASE_META[phase]?.short || phase}`;
  }, [phase]);

  return (
    <div className="flex h-screen flex-col overflow-hidden bg-steel-950 text-slate-200">
      <ControlBar />
      <div className="flex min-h-0 flex-1">
        <Sidebar />
        <main className="flex min-h-0 min-w-0 flex-1 flex-col">
          <AssetMatrix hosts={hosts} />
        </main>
      </div>
    </div>
  );
}
