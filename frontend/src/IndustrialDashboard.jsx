/**
 * IndustrialDashboard.jsx — the ENUMGRID command center.
 * ---------------------------------------------------------------------------
 * A professional network-security operations console (v2 redesign). All scan
 * state flows from `useScan()`; this file is presentation + interaction.
 *
 * App shell
 *   ┌──────────┬────────────────────────────────────────────────────────────┐
 *   │ Sidebar  │ CommandBar (target · scan · privilege · export · settings)  │
 *   │  brand   │ ProgressStrip (live phase progress)                         │
 *   │  pipeline│ ── banners ──────────────────────────────────────────────── │
 *   │  privilege KpiStrip (hosts · ports · services · vulns · critical)      │
 *   │  drift   │ ScanConfigPanel (collapsible nmap options)                  │
 *   │  sessions│ AssetMatrix  (matrix ⇄ topology)                            │
 *   └──────────┴────────────────────────────────────────────────────────────┘
 *
 * The one truly new capability vs. the CLI: runtime privilege elevation — the
 * operator can raise the backend from unprivileged to real raw-socket scans
 * (-sS / -sU / -O) by entering a sudo password, without restarting (see
 * PrivilegeControl → /api/privilege/elevate).
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useScan } from './context/ScanContext.jsx';
import { usePreferences, colWidth, COL_DEFAULTS } from './lib/preferences.js';
import { authFetch, useApiToken } from './lib/auth.js';
import { privMeta, rawScanAvailable, canOfferElevation } from './lib/privilege.js';
import { useFocusTrap } from './lib/useFocusTrap.js';
import { useToast } from './lib/toast.jsx';
import CopilotLayer from './CopilotPanel.jsx';
import { SHORTCUTS, isEditableTarget } from './lib/shortcuts.js';
import { filterCommands } from './lib/commandFilter.js';
import {
  DAY_OPTIONS, describeSchedule, splitTargets, validateScheduleForm, severityTone,
} from './lib/operations.js';
import {
  ScanPhase,
  HostStatus,
  PortState,
  Severity,
  PHASE_META,
  PIPELINE_STAGES,
  countOpenPorts,
  criticalCount,
  collectVulns,
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
  Sun: ({ className }) => (
    <I className={className}>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4" />
    </I>
  ),
  Moon: ({ className }) => (
    <I className={className}>
      <path d="M20 14.5 A8 8 0 1 1 9.5 4 A6.2 6.2 0 0 0 20 14.5 Z" />
    </I>
  ),
  Rows: ({ className }) => (
    <I className={className}>
      <rect x="3" y="4" width="18" height="5" rx="1" />
      <rect x="3" y="12" width="18" height="5" rx="1" className="opacity-60" />
    </I>
  ),
  Lock: ({ className }) => (
    <I className={className}>
      <rect x="5" y="11" width="14" height="9" rx="1.5" />
      <path d="M8 11 V8 A4 4 0 0 1 16 8 V11" />
    </I>
  ),
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
  ChevronDown: ({ className }) => (
    <I className={className}>
      <path d="M6 9 L12 15 L18 9" />
    </I>
  ),
  External: ({ className }) => (
    <I className={className}>
      <path d="M14 4 H20 V10" />
      <path d="M20 4 L11 13" />
      <path d="M18 13 V19 A1 1 0 0 1 17 20 H5 A1 1 0 0 1 4 19 V7 A1 1 0 0 1 5 6 H11" />
    </I>
  ),
  Filter: ({ className }) => (
    <I className={className}>
      <path d="M3 5 H21 L14 13 V19 L10 21 V13 Z" />
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
  Info: ({ className }) => (
    <I className={className}>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11 L12 16" />
      <path d="M12 8 L12 8.1" strokeWidth="2.2" />
    </I>
  ),
  Key: ({ className }) => (
    <I className={className}>
      <circle cx="8" cy="8" r="4" />
      <path d="M11 11 L20 20 M17 17 L19 15 M14 14 L16.5 16.5" />
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
  Download: ({ className }) => (
    <I className={className}>
      <path d="M12 3 V15" />
      <path d="M7 10 L12 15 L17 10" />
      <path d="M4 19 H20" />
    </I>
  ),
  Shield: ({ className }) => (
    <I className={className}>
      <path d="M12 3 L20 6 V11 C20 16 16.5 19.5 12 21 C7.5 19.5 4 16 4 11 V6 Z" />
    </I>
  ),
  ShieldCheck: ({ className }) => (
    <I className={className}>
      <path d="M12 3 L20 6 V11 C20 16 16.5 19.5 12 21 C7.5 19.5 4 16 4 11 V6 Z" />
      <path d="M8.5 12 L11 14.5 L15.5 9.5" />
    </I>
  ),
  Bug: ({ className }) => (
    <I className={className}>
      <rect x="8" y="7" width="8" height="11" rx="4" />
      <path d="M4 11 H8 M16 11 H20 M5 6 L8 8 M19 6 L16 8 M4.5 16 H8 M16 16 H19.5 M12 7 V4 M9.5 4.5 L12 3 L14.5 4.5" />
    </I>
  ),
  Bolt: ({ className }) => (
    <I className={className}>
      <path d="M13 2 L4 14 H11 L10 22 L20 9 H13 Z" fill="currentColor" stroke="none" />
    </I>
  ),
  Gauge: ({ className }) => (
    <I className={className}>
      <path d="M4 15 A8 8 0 0 1 20 15" />
      <path d="M12 15 L16 10" />
      <circle cx="12" cy="15" r="1.3" fill="currentColor" stroke="none" />
    </I>
  ),
  Gear: ({ className }) => (
    <I className={className}>
      <circle cx="12" cy="12" r="3.2" />
      <path d="M12 2.5 V5 M12 19 V21.5 M4.2 7 L6.3 8.2 M17.7 15.8 L19.8 17 M4.2 17 L6.3 15.8 M17.7 8.2 L19.8 7 M2.5 12 H5 M19 12 H21.5" />
    </I>
  ),
  Menu: ({ className }) => (
    <I className={className}>
      <path d="M4 7 H20 M4 12 H20 M4 17 H20" />
    </I>
  ),
  Sliders: ({ className }) => (
    <I className={className}>
      <path d="M4 8 H14 M18 8 H20 M4 16 H8 M12 16 H20" />
      <circle cx="16" cy="8" r="2" />
      <circle cx="10" cy="16" r="2" />
    </I>
  ),
  Pulse: ({ className }) => (
    <I className={className}>
      <circle cx="12" cy="12" r="9" className="opacity-30" />
      <path d="M7 12 H9.5 L11 8.5 L13 15.5 L14.5 12 H17" />
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

// Brand colours (match tailwind.config) for inline-style gradient fills.
const PROGRESS_RGB = { amber: '255,179,0', matrix: '0,230,118', crimson: '211,47,47' };

// Shared matrix column template — header + every row use the SAME string so they
// stay aligned. Fixed: chevron, status, IP, ports, scan-status. Resizable
// (persisted px): hostname, vendor, device, mac. Trailing spacer absorbs slack.
const GRID_COLS = 'grid items-center';
function gridTemplate(colWidths) {
  const w = (k) => colWidth(colWidths, k);
  return `34px 48px 128px ${w('hostname')}px ${w('vendor')}px ${w('device')}px ${w('mac')}px 56px 104px minmax(0,1fr)`;
}

const QUICK_FILTERS = [
  { key: 'web', label: 'Web · 80/443', Icon: Icon.Globe },
  { key: 'ssh', label: 'SSH · 22', Icon: Icon.Terminal },
  { key: 'database', label: 'Database', Icon: Icon.Database },
  { key: 'ports', label: 'Open Ports', Icon: Icon.Server },
  { key: 'vulnerable', label: 'Vulnerable (CVE)', Icon: Icon.Bug, danger: true },
  { key: 'critical', label: 'Critical', Icon: Icon.Alert, danger: true },
  { key: 'named', label: 'Has Name', Icon: Icon.Terminal },
];

// Coarse OS family for the OS dropdown filter (derived from the host's OS label).
function osFamily(host) {
  const s = (host?.os || '').toLowerCase();
  if (!s || s === 'unknown' || s === 'fingerprinting…') return '';
  if (s.includes('linux / macos')) return 'Linux / Unix';
  if (s.includes('android')) return 'Android';
  if (s.includes('apple') || /\b(macos|ios|ipados|watchos|tvos)\b/.test(s)) return 'Apple';
  if (s.includes('windows')) return 'Windows';
  if (/(router|routeros|openwrt|forti)/.test(s)) return 'Router';
  if (/(embedded|rtos|iot|smart tv)/.test(s)) return 'IoT / Embedded';
  if (/(linux|unix|nas|raspberry|ubuntu|debian)/.test(s)) return 'Linux / Unix';
  return 'Other';
}

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
  if (key === 'vulnerable') return collectVulns(host).length > 0;
  if (key === 'ports') return countOpenPorts(host) > 0;
  if (key === 'named') return Boolean(host.hostname);
  return hostMatchesCategory(host, key);
}

function relativeTime(epochSeconds) {
  if (!epochSeconds) return '—';
  const diff = Math.max(0, Date.now() / 1000 - epochSeconds);
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

// Close a popover on the Escape key (accessibility). Bound only while `open`.
function useEscapeToClose(open, close) {
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, close]);
}

/* ========================================================================== *
 * UI primitives
 * ========================================================================== */

function Panel({ title, icon, action, children, className = '', bodyClassName = '' }) {
  return (
    <section className={`eg-card overflow-hidden ${className}`}>
      {title && (
        <header className="flex items-center justify-between border-b border-slate-700/60 bg-steel-850/60 px-3 py-2">
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
      <path d="M21 12 A9 9 0 0 0 12 3" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" />
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

/**
 * Full-screen click-catcher that dismisses the overlay it backs. Presentational
 * and aria-hidden: every overlay using it is also closable via Escape and/or an
 * in-view Close control, so the scrim is deliberately kept out of the tab order
 * (a focusable full-screen element would be an accessibility anti-pattern).
 */
function Backdrop({ onClose, className }) {
  // aria-hidden keeps the scrim out of the a11y tree, so click-only is correct
  // (the overlay is closable via Escape / an in-view Close control).
  return <div className={className} onClick={onClose} aria-hidden="true" />;
}

const SOURCE_BADGE = {
  live: { label: 'Live', dot: 'bg-matrix', text: 'text-matrix' },
  mock: { label: 'Demo', dot: 'bg-amber', text: 'text-amber' },
  null: { label: 'Idle', dot: 'bg-slate-500', text: 'text-slate-400' },
};

// Curated, non-intrusive NSE scripts as one-click chips, grouped by category.
// All names are server-validated (no brute/exploit/dos/malware) and match the
// backend name regex, so picking any of these is injection-safe by construction.
const SCRIPT_GROUPS = [
  { label: 'HTTP', scripts: ['http-title', 'http-headers', 'http-server-header', 'http-methods', 'http-enum', 'http-auth', 'http-cors', 'http-security-headers'] },
  { label: 'TLS', scripts: ['ssl-cert', 'ssl-enum-ciphers', 'ssl-date', 'tls-alpn', 'tls-nextprotoneg'] },
  { label: 'SSH', scripts: ['ssh-hostkey', 'ssh-auth-methods', 'ssh2-enum-algos'] },
  { label: 'SMB / Windows', scripts: ['smb-os-discovery', 'smb-security-mode', 'smb2-security-mode', 'smb-protocols', 'smb2-capabilities', 'smb2-time'] },
  { label: 'Naming / services', scripts: ['banner', 'dns-service-discovery', 'nbstat', 'snmp-info', 'rpcinfo', 'ftp-anon', 'smtp-commands'] },
  { label: 'CVE', scripts: ['vulners', 'vuln'] },
];

/* ========================================================================== *
 * NEW — Runtime privilege elevation (the headline feature)
 * A dashboard-driven jump from unprivileged → real raw-socket scans (SYN/UDP/OS
 * detection) by validating a sudo password. No restart, nothing to do at start.
 * ========================================================================== */

// Icon for a privilege tier (raw-capable → filled shield-check, else plain shield).
// The label/tone/note come from the pure `privMeta` helper (lib/privilege.js).
const privIcon = (meta) => (meta.raw ? Icon.ShieldCheck : Icon.Shield);

/** The elevation dialog — enter a sudo password to unlock raw-socket scans. */
function PrivilegeDialog({ onClose }) {
  const { capability, canElevate, elevated, isRoot, elevatePrivilege, dropPrivilege } = useScan();
  const { toast } = useToast();
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null); // { ok, text }
  useEscapeToClose(true, onClose);
  // Trap keyboard focus inside the modal; prefer the password field on open and
  // hand focus back to the trigger (the Privilege pill) on close.
  const pwRef = useRef(null);
  const dialogRef = useFocusTrap({ initialFocus: pwRef });

  const raw = rawScanAvailable(capability);

  const submit = () => {
    if (!pw.trim() || busy) return;
    setBusy(true);
    setMsg(null);
    elevatePrivilege(pw)
      .then((d) => {
        setPw('');
        if (d.ok) {
          // Close on success — the pill updates to "Elevated" and the toast
          // confirms; this also hands focus cleanly back to the trigger.
          toast(d.message || 'Raw-socket scans (SYN/UDP/OS) enabled.', { type: 'success', title: 'Privilege elevated' });
          onClose();
        } else {
          setMsg({ ok: false, text: d.message || 'Failed.' });
          toast(d.message || 'Elevation failed.', { type: 'error' });
        }
      })
      .catch((e) => {
        setMsg({ ok: false, text: e.message || 'Elevation failed.' });
        toast(e.message || 'Elevation failed.', { type: 'error' });
      })
      .finally(() => setBusy(false));
  };

  const drop = () => {
    setBusy(true);
    setMsg(null);
    dropPrivilege()
      .then((d) => {
        toast(d.message || 'Dropped to unprivileged.', { type: 'info' });
        onClose();
      })
      .catch((e) => {
        setMsg({ ok: false, text: e.message || 'Failed.' });
        toast(e.message || 'Failed to drop privileges.', { type: 'error' });
      })
      .finally(() => setBusy(false));
  };

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Scan privilege">
      <Backdrop onClose={onClose} className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div ref={dialogRef} tabIndex={-1} className="eg-card relative z-10 w-full max-w-md p-5 outline-none">
        {/* header */}
        <div className="mb-3 flex items-start justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <span className={`grid h-9 w-9 place-items-center rounded-lg border ${raw ? 'border-matrix/50 bg-matrix/10 text-matrix' : 'border-amber/50 bg-amber/10 text-amber'}`}>
              <Icon.Bolt className="h-5 w-5" />
            </span>
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Scan privilege</h2>
              <p className="font-mono text-[11px] text-slate-500">
                current tier: <span className={raw ? 'text-matrix' : 'text-amber'}>{capability}</span>
              </p>
            </div>
          </div>
          <button onClick={onClose} aria-label="Close" className="rounded p-1 text-slate-500 hover:bg-steel-800 hover:text-slate-200">
            <Icon.X className="h-4 w-4" />
          </button>
        </div>

        {/* capability explainer */}
        <div className="mb-4 grid grid-cols-3 gap-1.5 text-center">
          {[
            { k: '-sS', t: 'SYN stealth' },
            { k: '-sU', t: 'UDP scan' },
            { k: '-O', t: 'OS detect' },
          ].map((c) => (
            <div key={c.k} className={`rounded-lg border px-2 py-2 ${raw ? 'border-matrix/40 bg-matrix/[0.07]' : 'border-slate-700 bg-steel-900'}`}>
              <div className={`font-mono text-sm font-bold ${raw ? 'text-matrix' : 'text-slate-500'}`}>{c.k}</div>
              <div className="mt-0.5 flex items-center justify-center gap-1 text-[10px] text-slate-500">
                {raw ? <Icon.Check className="h-3 w-3 text-matrix" /> : <Icon.X className="h-3 w-3 text-slate-600" />}
                {c.t}
              </div>
            </div>
          ))}
        </div>

        {isRoot ? (
          <p className="rounded-lg border border-matrix/30 bg-matrix/[0.07] px-3 py-2.5 text-xs text-matrix">
            The backend is already running as <b>root</b> — every scan uses real raw sockets. Nothing to elevate.
          </p>
        ) : raw ? (
          <div className="space-y-3">
            <p className="rounded-lg border border-matrix/30 bg-matrix/[0.07] px-3 py-2.5 text-xs text-matrix">
              {elevated
                ? 'This session is elevated — SYN / UDP / OS-detection scans run for real.'
                : 'Passwordless sudo is available, so scans already elevate automatically.'}
            </p>
            {elevated && (
              <button
                onClick={drop}
                disabled={busy}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-600 bg-steel-900 px-3 py-1.5 text-xs font-semibold text-slate-300 transition hover:border-crimson/60 hover:text-crimson disabled:opacity-50"
              >
                <Icon.Power className="h-3.5 w-3.5" /> Drop privileges
              </button>
            )}
          </div>
        ) : canElevate ? (
          <div className="space-y-3">
            <p className="text-xs leading-relaxed text-slate-400">
              Enter your <span className="font-mono text-slate-200">sudo</span> password to elevate this session to
              real raw-socket scans. The password is validated against sudo and held
              <b className="text-slate-300"> only in the backend&#39;s memory</b> for this session — never written to
              disk, never logged, never returned. Click <i>Drop</i> (or restart) to forget it.
            </p>
            <div className="flex items-center gap-2">
              <input
                ref={pwRef}
                type="password"
                value={pw}
                onChange={(e) => setPw(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && submit()}
                placeholder="sudo password…"
                aria-label="sudo password"
                autoComplete="off"
                spellCheck={false}
                className="w-full rounded-lg border border-slate-700 bg-steel-900 px-3 py-2 font-mono text-sm text-slate-100 outline-none transition focus:border-matrix/60 focus:shadow-glow-matrix"
              />
              <button
                onClick={submit}
                disabled={busy || !pw.trim()}
                className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-matrix/50 bg-matrix/15 px-3 py-2 text-sm font-semibold text-matrix transition hover:bg-matrix hover:text-steel-950 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {busy ? <Spinner className="h-4 w-4" /> : <Icon.Bolt className="h-4 w-4" />}
                Elevate
              </button>
            </div>
          </div>
        ) : (
          <p className="rounded-lg border border-slate-700 bg-steel-900 px-3 py-2.5 text-xs text-slate-400">
            No <span className="font-mono">sudo</span> is available on this host (or it&#39;s disabled), so runtime
            elevation isn&#39;t possible. Scans still run — root-only techniques auto-adapt to unprivileged
            equivalents (SYN→connect, UDP→connect, OS detection skipped). For full fidelity, start the backend with{' '}
            <code className="rounded bg-black/40 px-1 font-mono text-amber-200">./start.sh --accurate-os</code>.
          </p>
        )}

        {msg && (
          <p className={`mt-3 flex items-start gap-1.5 font-mono text-[11px] ${msg.ok ? 'text-matrix' : 'text-crimson'}`}>
            {msg.ok ? <Icon.Check className="mt-0.5 h-3.5 w-3.5 shrink-0" /> : <Icon.Alert className="mt-0.5 h-3.5 w-3.5 shrink-0" />}
            <span>{msg.text}</span>
          </p>
        )}

        <p className="mt-4 border-t border-slate-700/60 pt-3 text-[10px] leading-relaxed text-slate-500">
          Only authorized, in-scope networks should ever be scanned. Elevation is gated to the local operator
          (or an admin token when RBAC is enabled).
        </p>
      </div>
    </div>
  );
}

/** Compact privilege pill for the command bar — opens the elevation dialog. */
function PrivilegeControl() {
  const { capability, elevated, canElevate } = useScan();
  const [open, setOpen] = useState(false);
  // Let the command palette (or any component) open this dialog via an event.
  useEffect(() => {
    const openEvt = () => setOpen(true);
    window.addEventListener('eg:open-privilege', openEvt);
    return () => window.removeEventListener('eg:open-privilege', openEvt);
  }, []);
  const meta = privMeta(capability, elevated);
  const Ico = privIcon(meta);
  const offerElevate = canOfferElevation(capability, canElevate);
  const tone = meta.raw
    ? 'border-matrix/45 bg-matrix/10 text-matrix'
    : canElevate
      ? 'border-amber/45 bg-amber/10 text-amber hover:bg-amber/20'
      : 'border-slate-700 bg-steel-900 text-slate-400 hover:border-slate-500 hover:text-slate-200';

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        title={meta.note}
        aria-label={`Scan privilege: ${meta.label}. Open elevation dialog`}
        aria-haspopup="dialog"
        className={`inline-flex shrink-0 items-center gap-1.5 rounded-lg border px-2.5 py-2 text-xs font-semibold outline-none transition focus-visible:ring-2 focus-visible:ring-sky-400 focus-visible:ring-offset-1 focus-visible:ring-offset-steel-950 ${tone} ${elevated ? 'eg-priv-live' : ''}`}
      >
        <Ico className="h-4 w-4" />
        <span className="hidden sm:inline">{meta.label}</span>
        {offerElevate && <Icon.Bolt className="h-3 w-3 opacity-80" />}
      </button>
      {open && <PrivilegeDialog onClose={() => setOpen(false)} />}
    </>
  );
}

/* ========================================================================== *
 * Export menu (PDF report / CSV / JSON) — matches the CLI's export formats.
 * ========================================================================== */

function ExportMenu({ disabled, btnBase }) {
  const { downloadReport, exportCsv, exportJson } = useScan();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  useEscapeToClose(open, useCallback(() => setOpen(false), []));
  const item =
    'flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-xs text-slate-300 transition hover:bg-steel-800 hover:text-slate-100';
  // Handles both sync exports (CSV/JSON) and the async PDF, toasting the outcome.
  const run = (fn, okMsg) => () => {
    setOpen(false);
    try {
      const result = fn();
      if (result && typeof result.then === 'function') {
        result
          .then(() => toast(okMsg, { type: 'success' }))
          .catch(() => toast('Export failed — is the backend running?', { type: 'error' }));
      } else {
        toast(okMsg, { type: 'success' });
      }
    } catch {
      toast('Export failed.', { type: 'error' });
    }
  };
  return (
    <div className="relative">
      <button
        onClick={() => !disabled && setOpen((o) => !o)}
        disabled={disabled}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Export scan results"
        title="Export the current scan — PDF report, CSV or JSON"
        className={`${btnBase} border-slate-700 bg-steel-900 text-slate-300 hover:border-slate-500 hover:text-slate-100 disabled:opacity-50`}
      >
        <Icon.Download className="h-4 w-4" />
        <span className="hidden sm:inline">Export</span>
        <Icon.ChevronDown className="h-3 w-3 opacity-60" />
      </button>
      {open && (
        <>
          <Backdrop onClose={() => setOpen(false)} className="fixed inset-0 z-30" />
          <div role="menu" aria-label="Export format" className="eg-card absolute right-0 z-40 mt-1.5 w-48 p-1.5">
            <button role="menuitem" onClick={run(downloadReport, 'PDF report downloaded.')} className={item}>
              <Icon.Download className="h-3.5 w-3.5 text-crimson" /> PDF report
            </button>
            <button role="menuitem" onClick={run(exportCsv, 'CSV inventory exported.')} className={item}>
              <Icon.Server className="h-3.5 w-3.5 text-matrix" /> CSV (inventory)
            </button>
            <button role="menuitem" onClick={run(exportJson, 'JSON snapshot exported.')} className={item}>
              <Icon.Terminal className="h-3.5 w-3.5 text-amber" /> JSON (full snapshot)
            </button>
          </div>
        </>
      )}
    </div>
  );
}

/* ========================================================================== *
 * Settings menu — theme · density · API token (RBAC) · NVD key. Consolidated so
 * the command bar stays clean.
 * ========================================================================== */

function SettingsMenu({ btnBase }) {
  const { theme, density, toggleTheme, toggleDensity } = usePreferences();
  const [open, setOpen] = useState(false);
  useEscapeToClose(open, useCallback(() => setOpen(false), []));
  const row = 'flex items-center justify-between gap-3 rounded-md px-2 py-1.5 text-xs';
  const toggleBtn = (active) =>
    `inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-[11px] font-semibold transition ${
      active ? 'border-amber/50 bg-amber/10 text-amber' : 'border-slate-700 bg-steel-900 text-slate-400 hover:text-slate-200'
    }`;

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Settings"
        title="Settings — theme, density, API token, NVD key"
        className={`${btnBase} border-slate-700 bg-steel-900 text-slate-400 hover:border-slate-500 hover:text-slate-200`}
      >
        <Icon.Gear className="h-4 w-4" />
      </button>
      {open && (
        <>
          <Backdrop onClose={() => setOpen(false)} className="fixed inset-0 z-30" />
          <div role="menu" aria-label="Settings" className="eg-card absolute right-0 z-40 mt-1.5 w-[280px] p-2">
            <div className="mb-1 px-1 text-[10px] font-semibold uppercase tracking-widest text-slate-500">Appearance</div>
            <div className={row}>
              <span className="text-slate-300">Theme</span>
              <button onClick={toggleTheme} className={toggleBtn(theme === 'light')}>
                {theme === 'light' ? <Icon.Sun className="h-3.5 w-3.5" /> : <Icon.Moon className="h-3.5 w-3.5" />}
                {theme === 'light' ? 'Light' : 'Dark'}
              </button>
            </div>
            <div className={row}>
              <span className="text-slate-300">Density</span>
              <button onClick={toggleDensity} className={toggleBtn(density === 'compact')}>
                <Icon.Rows className="h-3.5 w-3.5" />
                {density === 'compact' ? 'Compact' : 'Cozy'}
              </button>
            </div>
            <div className="my-2 border-t border-slate-700/60" />
            <div className="mb-1 px-1 text-[10px] font-semibold uppercase tracking-widest text-slate-500">Integrations</div>
            <div className="flex flex-col gap-1.5 px-1 py-1">
              <ApiTokenButton />
              <NvdKeyButton />
            </div>
            <div className="my-2 border-t border-slate-700/60" />
            <button
              onClick={() => { setOpen(false); window.dispatchEvent(new Event('eg:open-operations')); }}
              className="flex w-full items-center justify-between rounded-md px-2 py-1.5 text-xs text-slate-300 outline-none transition hover:bg-steel-800 hover:text-slate-100 focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <span className="flex items-center gap-1.5"><Icon.Radar className="h-3.5 w-3.5" /> Operations</span>
              <span className="text-[10px] text-slate-500">passive · schedules · campaign</span>
            </button>
            <button
              onClick={() => { setOpen(false); window.dispatchEvent(new Event('eg:open-copilot')); }}
              className="flex w-full items-center justify-between rounded-md px-2 py-1.5 text-xs text-slate-300 outline-none transition hover:bg-steel-800 hover:text-slate-100 focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <span className="flex items-center gap-1.5"><Icon.Activity className="h-3.5 w-3.5" /> AI Copilot</span>
              <span className="text-[10px] text-slate-500">chat · Claude / OpenAI</span>
            </button>
            <button
              onClick={() => { setOpen(false); window.dispatchEvent(new Event('eg:open-help')); }}
              className="flex w-full items-center justify-between rounded-md px-2 py-1.5 text-xs text-slate-300 outline-none transition hover:bg-steel-800 hover:text-slate-100 focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <span className="flex items-center gap-1.5"><Icon.Terminal className="h-3.5 w-3.5" /> Keyboard shortcuts</span>
              <kbd className="rounded border border-slate-600 bg-steel-900 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">?</kbd>
            </button>
          </div>
        </>
      )}
    </div>
  );
}

/* ========================================================================== *
 * A · Command bar (top)
 * ========================================================================== */

function CommandBar({ onOpenNav }) {
  const {
    target, phase, progress, running, source, deepScan, startScan, stopScan, toggleDeep,
    setTarget, scanAll, hosts, monitor, monitorEverySec, toggleMonitor, setMonitorInterval,
  } = useScan();
  const [input, setInput] = useState(target);
  const hasHosts = hosts.length > 0;
  const unscanned = hosts.filter((h) => h.status === HostStatus.UP && !h.scanned).length;
  const badge = SOURCE_BADGE[source] || SOURCE_BADGE.null;
  const phaseStyle = PHASE_STYLE[phase] || PHASE_STYLE[ScanPhase.IDLE];
  const phaseMeta = PHASE_META[phase] || PHASE_META[ScanPhase.IDLE];

  // Auto-detect the network you're on and pre-fill the target.
  useEffect(() => {
    let cancelled = false;
    authFetch('/api/network')
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!cancelled && data && data.suggested_target) {
          setInput(data.suggested_target);
          setTarget?.(data.suggested_target);
        }
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [setTarget]);

  const submit = () => {
    if (running) return;
    startScan(input, deepScan);
  };

  // Every command-bar button shares this base. `focus:outline-none` drops the
  // browser default; `focus-visible:ring-*` puts a clearly-visible keyboard
  // focus ring back (WCAG 2.4.7) — sky reads on both the dark and light themes.
  const btnBase =
    'inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-semibold transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 focus-visible:ring-offset-1 focus-visible:ring-offset-steel-950 disabled:cursor-not-allowed';

  return (
    <header className="eg-glass sticky top-0 z-30 border-b border-slate-700/70">
      <div className="flex flex-wrap items-center gap-2 px-3 py-2.5 sm:px-4">
        {/* mobile nav + brand */}
        <button
          onClick={onOpenNav}
          aria-label="Open menu"
          className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-slate-700 bg-steel-900 text-slate-300 lg:hidden"
        >
          <Icon.Menu className="h-5 w-5" />
        </button>
        <span className="flex items-center gap-1.5 font-mono text-sm font-bold tracking-[0.16em] lg:hidden">
          ENUM<span className="eg-brand-gradient">GRID</span>
        </span>

        {/* Target field */}
        <label className="relative flex min-w-[200px] flex-1 items-center">
          <span className="pointer-events-none absolute left-3 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
            <Icon.Globe className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">Target</span>
          </span>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && submit()}
            spellCheck={false}
            placeholder="192.168.1.0/24"
            disabled={running}
            className="w-full rounded-lg border border-slate-700 bg-steel-900/80 py-2 pl-[70px] pr-3 font-mono text-sm text-slate-100 outline-none transition focus:border-amber/60 focus:shadow-glow-amber disabled:opacity-60 sm:pl-[76px]"
          />
        </label>

        {/* Primary action */}
        {!running ? (
          <button
            onClick={submit}
            aria-label="Start scan"
            className={`${btnBase} border-matrix/50 bg-matrix/15 text-matrix hover:bg-matrix hover:text-steel-950 hover:shadow-glow-matrix`}
          >
            <Icon.Play className="h-4 w-4" />
            <span className="hidden sm:inline">Start Scan</span>
          </button>
        ) : (
          <button
            onClick={stopScan}
            aria-label="Stop scan"
            className={`${btnBase} border-crimson/60 bg-crimson/15 text-crimson hover:bg-crimson hover:text-white hover:shadow-glow-crimson`}
          >
            <Icon.Stop className="h-4 w-4" />
            <span className="hidden sm:inline">Stop</span>
          </button>
        )}

        {/* Deep toggle */}
        <button
          onClick={toggleDeep}
          disabled={running}
          aria-pressed={deepScan}
          aria-label="Deep scan (NSE vuln scripts)"
          title="Deep Scan: run NSE vuln scripts (nmap --script vuln) for real CVE findings. Slower."
          className={`${btnBase} disabled:opacity-50 ${
            deepScan
              ? 'border-crimson/60 bg-crimson/15 text-crimson shadow-glow-crimson'
              : 'border-slate-700 bg-steel-900 text-slate-400 hover:border-slate-500 hover:text-slate-200'
          }`}
        >
          <Icon.Shield className="h-4 w-4" />
          <span className="hidden md:inline">Deep</span>
        </button>

        {/* Scan All */}
        <button
          onClick={() => scanAll(false)}
          disabled={!unscanned}
          aria-label={`Scan all discovered hosts${unscanned ? ` (${unscanned} pending)` : ''}`}
          title="Run an nmap service scan on every discovered host (ports, services, versions, OS)."
          className={`${btnBase} border-amber/50 bg-amber/10 text-amber hover:bg-amber hover:text-steel-950 disabled:border-slate-700 disabled:bg-steel-900 disabled:text-slate-600`}
        >
          <Icon.Cpu className="h-4 w-4" />
          <span className="hidden md:inline">Scan All{unscanned ? ` (${unscanned})` : ''}</span>
        </button>

        {/* Right cluster — grouped so it stays right-aligned and its dropdowns
            (Export / Settings) always open leftward into content, never off-edge. */}
        <div className="ml-auto flex flex-wrap items-center justify-end gap-2">
          <span className="mx-0.5 hidden h-6 w-px self-center bg-slate-700/70 lg:block" />

          {/* Privilege (the new feature) */}
          <PrivilegeControl />

          {/* Monitor */}
          <button
            onClick={toggleMonitor}
            aria-pressed={monitor}
            aria-label="Monitor mode (auto re-scan on interval)"
            title="Monitor mode: automatically re-scan on an interval and alert on drift."
            className={`${btnBase} ${
              monitor
                ? 'border-matrix/60 bg-matrix/15 text-matrix shadow-glow-matrix'
                : 'border-slate-700 bg-steel-900 text-slate-400 hover:border-slate-500 hover:text-slate-200'
            }`}
          >
            <Icon.Activity className={`h-4 w-4 ${monitor ? 'animate-pulse-glow' : ''}`} />
            <span className="hidden lg:inline">Monitor</span>
          </button>
          {monitor && (
            <select
              value={monitorEverySec}
              onChange={(e) => setMonitorInterval(Number(e.target.value))}
              title="Re-scan interval"
              className="shrink-0 rounded-lg border border-slate-700 bg-steel-900 px-1.5 py-2 font-mono text-xs text-slate-300 outline-none focus:border-matrix/60"
            >
              <option value={30}>30s</option>
              <option value={120}>2m</option>
              <option value={300}>5m</option>
              <option value={900}>15m</option>
            </select>
          )}

          {/* Export + settings */}
          <ExportMenu disabled={!hasHosts} btnBase={btnBase} />
          <SettingsMenu btnBase={btnBase} />

          {/* phase + source pills */}
          <div className="hidden items-center gap-1.5 rounded-lg border border-slate-700 bg-steel-900/70 px-2.5 py-1.5 sm:flex">
            <span className={`h-2 w-2 rounded-full ${phaseStyle.dot} ${phaseStyle.pulse ? 'animate-pulse-glow' : ''}`} />
            <span className="text-[9px] uppercase tracking-widest text-slate-500">Phase</span>
            <span className={`font-mono text-xs font-semibold ${phaseStyle.text}`}>{phaseMeta.label}</span>
          </div>
          <div className={`hidden items-center gap-1.5 rounded-lg border border-slate-700 bg-steel-900/70 px-2 py-1.5 md:flex ${badge.text}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${badge.dot} ${running ? 'animate-pulse-glow' : ''}`} />
            <span className="font-mono text-[10px] uppercase tracking-widest">{badge.label}</span>
          </div>
        </div>
      </div>
      <GlobalProgress phase={phase} progress={progress} running={running} />
    </header>
  );
}

// A phase tag that lights up as the scan moves through it.
const PHASE_TAG_STYLE = {
  active: 'border-amber/60 bg-amber/15 text-amber shadow-glow-amber',
  done: 'border-matrix/40 bg-matrix/10 text-matrix',
  pending: 'border-slate-700 bg-steel-900 text-slate-500',
};
function PhaseTag({ index, label, state }) {
  return (
    <span className={`hidden shrink-0 items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[10px] uppercase tracking-wider transition sm:inline-flex ${PHASE_TAG_STYLE[state]}`}>
      <span className="opacity-70">{index}</span>
      {state === 'done' ? (
        <Icon.Check className="h-3 w-3" />
      ) : (
        <span className={`h-1.5 w-1.5 rounded-full bg-current ${state === 'active' ? 'animate-pulse-glow' : 'opacity-50'}`} />
      )}
      {label}
    </span>
  );
}

function GlobalProgress({ phase, progress, running }) {
  const isComplete = phase === ScanPhase.COMPLETE;
  const isHalted = phase === ScanPhase.HALTED || phase === ScanPhase.ERROR;
  const accent = isHalted ? 'crimson' : isComplete ? 'matrix' : 'amber';
  const rgb = PROGRESS_RGB[accent];
  const glow = isHalted ? 'shadow-glow-crimson' : isComplete ? 'shadow-glow-matrix' : 'shadow-glow-amber';
  const dot = isHalted ? 'bg-crimson' : isComplete ? 'bg-matrix' : 'bg-amber';
  const pctText = isHalted ? 'text-crimson' : isComplete ? 'text-matrix' : 'text-amber';

  const p1 = phase === ScanPhase.PING_SWEEP ? 'active' : progress >= 40 || isComplete ? 'done' : 'pending';
  const p2 = phase === ScanPhase.NMAP_ENUMERATION ? 'active' : isComplete ? 'done' : 'pending';

  return (
    <div className="flex items-center gap-3 border-t border-slate-800/70 bg-steel-950/40 px-4 py-2">
      <PhaseTag index="01" label="Ping Sweep" state={p1} />
      <div className="relative h-2.5 flex-1 rounded-full bg-steel-800 shadow-[inset_0_1px_2px_rgba(0,0,0,0.55)]">
        <div className="absolute top-1/2 z-20 h-3 w-px -translate-y-1/2 bg-slate-600/70" style={{ left: '40%' }} title="Phase 1 → Phase 2" />
        <div
          className={`relative h-full overflow-hidden rounded-full ${glow} transition-[width] duration-500 ease-out`}
          style={{ width: `${progress}%`, background: `linear-gradient(90deg, rgba(${rgb},0.55), rgb(${rgb}))` }}
        >
          {running && <div className="progress-stripes animate-stripe absolute inset-0 opacity-40" />}
        </div>
        {running && progress > 1 && progress < 100 && (
          <div className={`absolute top-1/2 z-30 h-3.5 w-3.5 -translate-x-1/2 -translate-y-1/2 rounded-full ${dot} ${glow} animate-pulse-glow`} style={{ left: `${progress}%` }} />
        )}
      </div>
      <PhaseTag index="02" label="Nmap Enum" state={p2} />
      <div className="flex shrink-0 items-baseline gap-0.5 tabular-nums">
        <span className={`font-mono text-base font-bold ${pctText}`}>{progress}</span>
        <span className="font-mono text-[10px] text-slate-500">%</span>
      </div>
    </div>
  );
}

/* ========================================================================== *
 * B · KPI strip — the SOC-style metric hero.
 * ========================================================================== */

function KpiStrip() {
  const { stats } = useScan();
  const cells = [
    { label: 'Hosts Up', value: stats.up, sub: `${stats.down} down`, accent: 'matrix', Ico: Icon.Server },
    { label: 'Open Ports', value: stats.openPorts, sub: 'reachable', accent: 'amber', Ico: Icon.Activity },
    { label: 'Services', value: stats.services, sub: 'identified', accent: 'slate', Ico: Icon.Cpu },
    { label: 'Vulnerabilities', value: stats.vulns, sub: 'CVE findings', accent: stats.vulns ? 'crimson' : 'slate', Ico: Icon.Bug },
    { label: 'Critical', value: stats.critical, sub: 'need attention', accent: stats.critical ? 'crimson' : 'slate', Ico: Icon.Alert },
  ];
  const accentText = { matrix: 'text-matrix', amber: 'text-amber', crimson: 'text-crimson', slate: 'text-slate-200' };
  const accentIco = { matrix: 'text-matrix', amber: 'text-amber', crimson: 'text-crimson', slate: 'text-slate-500' };
  const accentBar = { matrix: 'from-matrix/70', amber: 'from-amber/70', crimson: 'from-crimson/70', slate: 'from-slate-600/60' };

  return (
    <div className="grid grid-cols-2 gap-2.5 px-3 pt-3 sm:px-4 md:grid-cols-3 xl:grid-cols-5">
      {cells.map((c) => (
        <div key={c.label} className="eg-kpi px-3.5 py-3">
          <div className={`absolute inset-x-0 top-0 h-px bg-gradient-to-r ${accentBar[c.accent]} to-transparent`} />
          <div className="flex items-start justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{c.label}</span>
            <c.Ico className={`h-4 w-4 ${accentIco[c.accent]}`} />
          </div>
          <div className={`mt-1.5 font-mono text-3xl font-bold tabular-nums leading-none ${accentText[c.accent]}`}>
            {String(c.value).padStart(2, '0')}
          </div>
          <div className="mt-1 font-mono text-[10px] text-slate-500">{c.sub}</div>
        </div>
      ))}
    </div>
  );
}

/* ========================================================================== *
 * Sidebar — brand · pipeline · drift · sessions · engine footer.
 * ========================================================================== */

function PipelineStepper() {
  const { phase, progress } = useScan();
  const activeIndex = PHASE_META[phase]?.index ?? 0;
  return (
    <Panel title="Scan Pipeline" icon={<Icon.Layers className="h-3.5 w-3.5 text-amber" />}>
      <ol className="relative px-4 py-4">
        <span className="absolute bottom-7 left-[27px] top-7 w-px bg-slate-700" aria-hidden />
        {PIPELINE_STAGES.map((stage) => {
          const meta = PHASE_META[stage.phase];
          const isActive = phase === stage.phase;
          const isDone = activeIndex > meta.index || phase === ScanPhase.COMPLETE;
          const state = isActive ? 'active' : isDone ? 'done' : 'pending';
          const ring =
            state === 'active'
              ? 'border-amber bg-amber/15 text-amber shadow-glow-amber animate-pulse-glow'
              : state === 'done'
                ? 'border-matrix bg-matrix/15 text-matrix'
                : 'border-slate-600 bg-steel-900 text-slate-500';
          return (
            <li key={stage.phase} className="relative flex gap-3 pb-5 last:pb-0">
              <span className={`relative z-10 grid h-7 w-7 shrink-0 place-items-center rounded-full border ${ring}`}>
                {state === 'done' ? <Icon.Check className="h-4 w-4" /> : state === 'active' ? <Spinner className="h-3.5 w-3.5" /> : <span className="font-mono text-[10px]">{meta.index}</span>}
              </span>
              <div className="pt-0.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] text-slate-500">{stage.code}</span>
                  <span className={`text-xs font-semibold ${state === 'pending' ? 'text-slate-500' : 'text-slate-200'}`}>{stage.title}</span>
                </div>
                <div className="text-[11px] text-slate-500">{stage.detail}</div>
                {isActive && <div className="mt-1 font-mono text-[10px] text-amber">▮ running · {progress}%</div>}
              </div>
            </li>
          );
        })}
      </ol>
    </Panel>
  );
}

function DriftRow({ sign, signClass, ip, label, dim }) {
  return (
    <div className="flex items-center gap-2 px-3 py-2">
      <span className={`w-3 shrink-0 text-center font-mono text-sm font-bold ${signClass}`}>{sign}</span>
      <div className="min-w-0 flex-1">
        <div className={`truncate font-mono text-xs ${dim ? 'text-slate-400' : 'text-slate-200'}`}>{ip}</div>
        <div className="truncate text-[10px] text-slate-500">{label}</div>
      </div>
    </div>
  );
}

function DriftPanel() {
  const { drift } = useScan();
  if (!drift) return null;
  const icon = <Icon.Activity className="h-3.5 w-3.5 text-matrix" />;

  if (!drift.available) {
    return (
      <Panel title="What Changed" icon={icon} bodyClassName="px-3 py-2.5">
        <p className="text-[11px] leading-relaxed text-slate-400">
          Baseline recorded for <span className="font-mono text-slate-300">{drift.target}</span>. Re-scan this network to see what changed since.
        </p>
      </Panel>
    );
  }
  if (!drift.has_changes) {
    return (
      <Panel title="What Changed" icon={icon} bodyClassName="px-3 py-2.5">
        <div className="flex items-center gap-2 text-[11px] font-semibold text-matrix">
          <Icon.Check className="h-3.5 w-3.5" />
          No changes since last scan — network stable.
        </div>
      </Panel>
    );
  }
  const appeared = drift.appeared_hosts || [];
  const disappeared = drift.disappeared_hosts || [];
  const changed = drift.changed_hosts || [];
  return (
    <Panel
      title="What Changed"
      icon={icon}
      action={<span className="rounded-sm bg-matrix/15 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-wider text-matrix">drift</span>}
      bodyClassName="divide-y divide-slate-800 max-h-64 overflow-y-auto"
    >
      {appeared.map((h) => (
        <DriftRow key={`a-${h.ip}`} sign="+" signClass="text-matrix" ip={h.ip} label={`new · ${h.vendor || h.hostname || 'unknown device'}`} />
      ))}
      {disappeared.map((h) => (
        <DriftRow key={`d-${h.ip}`} sign="−" signClass="text-slate-500" ip={h.ip} label={`gone · ${h.vendor || h.hostname || 'offline'}`} dim />
      ))}
      {changed.map((c) => (
        <div key={`c-${c.ip}`} className="px-3 py-2">
          <div className="flex items-center gap-2">
            <span className="w-3 text-center font-mono text-sm font-bold text-amber">~</span>
            <span className="font-mono text-xs text-slate-200">{c.ip}</span>
          </div>
          <div className="mt-1 flex flex-wrap gap-1 pl-5">
            {(c.opened_ports || []).map((p) => (
              <span key={`o-${p}`} className="rounded-sm border border-matrix/40 bg-matrix/10 px-1 font-mono text-[10px] text-matrix">+{p}</span>
            ))}
            {(c.closed_ports || []).map((p) => (
              <span key={`cl-${p}`} className="rounded-sm border border-slate-600/40 bg-slate-700/20 px-1 font-mono text-[10px] text-slate-400">−{p}</span>
            ))}
            {(c.service_changes || []).map((s, i) => (
              <span key={`s-${i}`} className="rounded-sm border border-amber/40 bg-amber/10 px-1 font-mono text-[10px] text-amber" title={`${s.from} → ${s.to}`}>~{s.port}</span>
            ))}
          </div>
        </div>
      ))}
    </Panel>
  );
}

function SessionLog() {
  const { sessions, scanId, shortId } = useScan();
  if (!sessions.length) return null;
  return (
    <Panel title="Scan Sessions" icon={<Icon.Radar className="h-3.5 w-3.5 text-amber" />} bodyClassName="divide-y divide-slate-800 max-h-56 overflow-y-auto">
      {sessions.map((s) => {
        const st = PHASE_STYLE[s.status] || PHASE_STYLE[ScanPhase.IDLE];
        const isCurrent = s.id === scanId;
        return (
          <div key={s.id} className={`flex items-center gap-3 px-3 py-2.5 ${isCurrent ? 'bg-amber/5' : ''}`}>
            <span className={`h-2 w-2 shrink-0 rounded-full ${st.dot} ${st.pulse ? 'animate-pulse-glow' : ''}`} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="truncate font-mono text-xs text-slate-200">{s.target}</span>
                {isCurrent && <span className="rounded-sm bg-amber/20 px-1 font-mono text-[8px] uppercase tracking-wider text-amber">live</span>}
              </div>
              <div className="flex items-center gap-2 font-mono text-[10px] text-slate-500">
                <span>#{shortId(s.id)}</span><span>·</span><span>{relativeTime(s.startedAt)}</span>
              </div>
            </div>
            <div className="text-right">
              <div className={`font-mono text-[10px] font-semibold uppercase ${st.text}`}>{PHASE_META[s.status]?.short || s.status}</div>
              <div className="font-mono text-[10px] text-slate-500">{s.upCount}/{s.hostCount} up</div>
            </div>
          </div>
        );
      })}
    </Panel>
  );
}

/** Engine footer — backend privilege + CVE status, pinned to the sidebar base. */
function EngineFooter() {
  const { capability, elevated, canRaw, source } = useScan();
  const meta = privMeta(capability, elevated);
  const rows = [
    {
      label: 'Backend',
      value: source === 'mock' ? 'demo engine' : 'FastAPI',
      dot: source === 'mock' ? 'bg-amber' : 'bg-matrix',
      valueClass: source === 'mock' ? 'text-amber' : 'text-matrix',
    },
    {
      label: 'Privilege',
      value: meta.label.toLowerCase(),
      dot: canRaw ? 'bg-matrix' : 'bg-slate-500',
      valueClass: canRaw ? 'text-matrix' : 'text-slate-400',
    },
  ];
  return (
    <div className="eg-card mt-auto p-3">
      <div className="mb-2 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
        <Icon.Gauge className="h-3.5 w-3.5 text-amber" /> Engine
      </div>
      <div className="space-y-1.5">
        {rows.map((r) => (
          <div key={r.label} className="flex items-center justify-between">
            <span className="text-[11px] text-slate-500">{r.label}</span>
            <span className="flex items-center gap-1.5">
              <span className={`h-1.5 w-1.5 rounded-full ${r.dot}`} />
              <span className={`font-mono text-[11px] ${r.valueClass}`}>{r.value}</span>
            </span>
          </div>
        ))}
      </div>
      <p className="mt-2 border-t border-slate-700/60 pt-2 font-mono text-[9px] leading-relaxed text-slate-600">
        Results are always real. Backend unreachable → the scan fails with a clear error, never simulated.
      </p>
    </div>
  );
}

function Sidebar({ mobileOpen, onClose }) {
  return (
    <>
      {/* mobile scrim */}
      {mobileOpen && <Backdrop onClose={onClose} className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden" />}
      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-[272px] shrink-0 flex-col gap-3 overflow-y-auto border-r border-slate-800 bg-steel-950/95 p-3 transition-transform duration-200 lg:static lg:z-0 lg:w-[264px] lg:translate-x-0 lg:bg-steel-950/50 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* brand */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="grid h-10 w-10 place-items-center rounded-xl border border-amber/40 bg-gradient-to-br from-amber/20 to-transparent text-amber shadow-glow-amber">
              <Icon.Radar className="h-6 w-6" />
            </div>
            <div className="leading-tight">
              <div className="font-mono text-base font-bold tracking-[0.14em]">
                ENUM<span className="eg-brand-gradient">GRID</span>
              </div>
              <div className="text-[9px] uppercase tracking-[0.18em] text-slate-500">the Enumeration Platform</div>
            </div>
          </div>
          <button onClick={onClose} aria-label="Close menu" className="rounded-lg p-1.5 text-slate-500 hover:bg-steel-800 hover:text-slate-200 lg:hidden">
            <Icon.X className="h-4 w-4" />
          </button>
        </div>

        <PipelineStepper />
        <DriftPanel />
        <SessionLog />
        <EngineFooter />
      </aside>
    </>
  );
}

/* ========================================================================== *
 * C · Search & advanced filtering toolbar
 * ========================================================================== */

function FilterToolbar({
  query, setQuery, filters, toggleFilter, upOnly, setUpOnly,
  deviceFilter, setDeviceFilter, deviceOptions,
  osFilter, setOsFilter, osOptions,
  activeFilterCount, clearFilters, shown, total, view, setView,
}) {
  const selectCls =
    'rounded-lg border border-slate-700 bg-steel-900 py-1.5 pl-2 pr-6 text-xs text-slate-300 outline-none transition hover:border-slate-500 focus:border-amber/60';
  return (
    <div className="sticky top-0 z-20 flex flex-wrap items-center gap-2.5 border-b border-slate-800 bg-steel-950/90 px-3 py-3 backdrop-blur sm:px-4">
      <label className="relative flex min-w-[220px] flex-1 items-center">
        <Icon.Search className="pointer-events-none absolute left-3 h-4 w-4 text-slate-500" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          spellCheck={false}
          type="search"
          aria-label="Search hosts by IP, hostname, OS, service or version"
          placeholder="Search IP, hostname, OS, service or version…"
          className="w-full rounded-lg border border-slate-700 bg-steel-900 py-2 pl-9 pr-8 font-mono text-sm text-slate-100 outline-none transition focus:border-amber/60 focus:shadow-glow-amber"
        />
        {query ? (
          <button onClick={() => setQuery('')} className="absolute right-2 text-slate-500 hover:text-slate-200" aria-label="Clear search">
            <Icon.X className="h-4 w-4" />
          </button>
        ) : (
          <kbd aria-hidden="true" title="Press / to search" className="pointer-events-none absolute right-2.5 hidden rounded border border-slate-700 bg-steel-950 px-1 font-mono text-[10px] text-slate-500 sm:block">/</kbd>
        )}
      </label>

      {/* view toggle */}
      <div className="flex items-center gap-1 rounded-lg border border-slate-700 bg-steel-900 p-0.5">
        {[
          { key: 'table', label: 'Matrix', Ico: Icon.Layers },
          { key: 'map', label: 'Topology', Ico: Icon.Radar },
        ].map(({ key, label, Ico }) => (
          <button
            key={key}
            onClick={() => setView(key)}
            aria-label={`${label} view`}
            aria-pressed={view === key}
            className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[11px] font-semibold transition ${
              view === key ? 'bg-amber/15 text-amber' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Ico className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">{label}</span>
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {QUICK_FILTERS.map((f) => {
          const active = filters.has(f.key);
          const danger = f.danger;
          const base = 'inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition';
          const cls = active
            ? danger
              ? 'border-crimson bg-crimson/15 text-crimson shadow-glow-crimson'
              : 'border-amber bg-amber/15 text-amber shadow-glow-amber'
            : 'border-slate-700 bg-steel-900 text-slate-400 hover:border-slate-500 hover:text-slate-200';
          return (
            <button key={f.key} onClick={() => toggleFilter(f.key)} aria-pressed={active} className={`${base} ${cls}`}>
              <f.Icon className="h-3.5 w-3.5" />
              {f.label}
            </button>
          );
        })}
        <button
          onClick={() => setUpOnly((v) => !v)}
          aria-pressed={upOnly}
          className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition ${
            upOnly ? 'border-matrix bg-matrix/15 text-matrix' : 'border-slate-700 bg-steel-900 text-slate-400 hover:border-slate-500 hover:text-slate-200'
          }`}
        >
          <span className="h-2 w-2 rounded-full bg-current" />
          Up Only
        </button>
        {deviceOptions.length > 0 && (
          <select value={deviceFilter} onChange={(e) => setDeviceFilter(e.target.value)} aria-label="Filter by device type" className={`${selectCls} ${deviceFilter ? 'border-amber text-amber' : ''}`}>
            <option value="">All devices</option>
            {deviceOptions.map((d) => <option key={d} value={d}>{d}</option>)}
          </select>
        )}
        {osOptions.length > 0 && (
          <select value={osFilter} onChange={(e) => setOsFilter(e.target.value)} aria-label="Filter by operating system" className={`${selectCls} ${osFilter ? 'border-amber text-amber' : ''}`}>
            <option value="">All OS</option>
            {osOptions.map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
        )}
        {activeFilterCount > 0 && (
          <button onClick={clearFilters} className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-steel-900 px-2.5 py-1.5 text-xs font-medium text-slate-400 transition hover:border-crimson/60 hover:text-crimson">
            <Icon.X className="h-3.5 w-3.5" />
            Clear ({activeFilterCount})
          </button>
        )}
      </div>

      <div className="ml-auto font-mono text-xs text-slate-500">
        <span className="text-slate-200">{shown}</span> / {total} hosts
      </div>
    </div>
  );
}

/* ========================================================================== *
 * Asset matrix (main data grid)
 * ========================================================================== */

function SortHeader({ label, active, dir, onClick, className = '' }) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1 text-left uppercase tracking-wider transition hover:text-slate-200 ${active ? 'text-amber' : 'text-slate-500'} ${className}`}
    >
      {label}
      <span className="font-mono text-[9px]">{active ? (dir === 'asc' ? '▲' : '▼') : '↕'}</span>
    </button>
  );
}

function ColResizeHandle({ col, onResize, onReset }) {
  const onPointerDown = (e) => {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const cell = e.currentTarget.parentElement;
    const startW = cell ? cell.getBoundingClientRect().width : 120;
    const move = (ev) => onResize(col, startW + (ev.clientX - startX));
    const up = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };
  return (
    <span
      // Pointer-only column-resize grip (decorative to AT): columns have sensible
      // default widths, so there is no keyboard resize to expose.
      aria-hidden="true"
      onPointerDown={onPointerDown}
      onDoubleClick={(e) => { e.stopPropagation(); onReset(col); }}
      onClick={(e) => e.stopPropagation()}
      title="Drag to resize · double-click to reset"
      className="absolute -right-1 top-0 z-10 flex h-full w-2.5 cursor-col-resize touch-none items-center justify-center"
    >
      <span className="h-3.5 w-px bg-slate-600 transition-colors hover:bg-amber" />
    </span>
  );
}

function PortDetailTable({ host }) {
  const { scanHostVulns, profiles, scanProfile, scanScripts, scanPorts } = useScan();
  const vulns = collectVulns(host);
  const profArgs = (profiles?.[scanProfile]?.args || '-sV -Pn -T4').trim();
  const liveCmd = `nmap ${profArgs}` + (scanScripts ? ` --script ${scanScripts}` : '') + (scanPorts ? ` -p ${scanPorts}` : '') + ` ${host.ip}`;

  return (
    <div className="space-y-2 px-3 pb-3 pt-1 sm:px-12">
      <div className="eg-detail-toolbar flex items-start justify-between gap-3 rounded-lg border border-slate-700/70 bg-steel-850/95 px-3 py-1.5 backdrop-blur">
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[11px] text-slate-400">
          <Icon.Server className="h-3.5 w-3.5 shrink-0 text-slate-500" />
          <span className="text-slate-200">{host.ip}</span>
          {host.vendor && (<><span className="text-slate-600">·</span><span className="max-w-[200px] truncate text-slate-300">{host.vendor}</span></>)}
          {host.mac && (<><span className="text-slate-600">·</span><span>{host.mac}</span></>)}
          {host.os && host.os !== 'Unknown' && (<><span className="text-slate-600">·</span><span className="max-w-[200px] truncate">{host.os}</span></>)}
          {host.ports.length > 0 && (<><span className="text-slate-600">·</span><span className="whitespace-nowrap">{host.ports.length} ports</span></>)}
          {vulns.length > 0 && (<><span className="text-slate-600">·</span><span className="whitespace-nowrap text-crimson">{vulns.length} vulns</span></>)}
        </div>
        <button
          onClick={(e) => { e.stopPropagation(); scanHostVulns(host.ip); }}
          disabled={host.vulnScanning}
          title="Deep-scan just this host for vulnerabilities (nmap --script vuln,vulners)"
          className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-lg border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider transition disabled:cursor-not-allowed ${
            host.vulnScanning ? 'border-amber/50 bg-amber/10 text-amber' : 'border-crimson/50 bg-crimson/10 text-crimson hover:bg-crimson hover:text-white'
          }`}
        >
          {host.vulnScanning ? (<><Spinner className="h-3 w-3" />Nmap scanning…</>) : (<><Icon.Search className="h-3.5 w-3.5" />{host.scanned ? 'Re-scan (nmap)' : 'Nmap Scan'}</>)}
        </button>
      </div>

      {host.scan_note && (
        <div className="flex items-start gap-2 rounded-lg border border-amber/30 bg-amber/[0.07] px-3 py-1.5 text-[11px] text-amber/90">
          <Icon.Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            Ran unprivileged — auto-adapted: {host.scan_note}.{' '}
            <span className="text-amber/70">Use the <b>Elevate</b> control (top bar) or run <code>./start.sh --accurate-os</code> for full-fidelity SYN/UDP/OS scans.</span>
          </span>
        </div>
      )}

      {host.ipv6?.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-matrix/30 bg-matrix/[0.06] px-3 py-1.5 font-mono text-[10px] text-slate-300">
          <span className="rounded-sm border border-matrix/40 bg-matrix/10 px-1 text-[8px] font-semibold uppercase tracking-wider text-matrix">IPv6</span>
          {host.ipv6.map((a) => <span key={a} className="text-slate-400">{a}</span>)}
        </div>
      )}

      {host.vulnScanning ? (
        <div className="flex items-start gap-2 overflow-x-auto px-3 py-4 font-mono text-xs text-amber">
          <Spinner className="mt-0.5 h-4 w-4 shrink-0" />
          <span className="whitespace-nowrap"><span className="text-slate-500">$</span> {liveCmd} <span className="text-amber/70">— scanning this host…</span></span>
        </div>
      ) : host.ports.length ? (
        <>
          <div className="overflow-hidden rounded-lg border border-slate-700/70 bg-steel-950/60">
            <div className="grid grid-cols-[80px_72px_minmax(120px,1fr)_minmax(150px,1.5fr)_120px] border-b border-slate-700/70 bg-steel-850 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
              <span>Port</span><span>Proto</span><span>Service</span><span>Version</span><span className="text-right">State</span>
            </div>
            <div className="divide-y divide-slate-800/70">
              {host.ports.map((p) => (
                <div key={`${p.port}/${p.protocol}`} className={`eg-port-row grid grid-cols-[80px_72px_minmax(120px,1fr)_minmax(150px,1.5fr)_120px] items-center px-3 py-1.5 font-mono text-xs ${p.critical ? 'bg-crimson/5' : ''}`}>
                  <span className="flex items-center gap-1.5 font-semibold text-slate-100">
                    {p.critical && <Icon.Alert className="h-3 w-3 text-crimson" />}
                    {p.port}
                  </span>
                  <span className="uppercase text-slate-400">{p.protocol}</span>
                  <span className="min-w-0 truncate text-slate-200">{p.service}</span>
                  <span className="min-w-0 truncate text-slate-400">{p.version || '—'}</span>
                  <span className="flex justify-end"><Tag className={PORT_STATE_STYLE[p.state]}>{p.state}</Tag></span>
                </div>
              ))}
            </div>
          </div>

          {vulns.length > 0 && (
            <div className="overflow-hidden rounded-lg border border-crimson/30 bg-crimson/[0.04]">
              <div className="flex items-center gap-2 border-b border-crimson/20 bg-crimson/10 px-3 py-1.5">
                <Icon.Bug className="h-3.5 w-3.5 text-crimson" />
                <span className="text-[10px] font-semibold uppercase tracking-wider text-crimson">Vulnerability Findings</span>
                <span className="font-mono text-[10px] font-bold text-crimson">{vulns.length}</span>
                <span className="ml-auto font-mono text-[9px] uppercase tracking-wider text-slate-500">nmap --script vuln</span>
              </div>
              <ul className="divide-y divide-slate-800/70">
                {vulns.map((v, i) => (
                  <li key={`${v.id}-${i}`} className="flex items-start gap-3 px-3 py-2">
                    <span className={`mt-px inline-flex shrink-0 items-center rounded border px-1.5 py-0.5 font-mono text-[9px] font-bold uppercase tracking-wider ${SEVERITY_STYLE[v.severity] || SEVERITY_STYLE.info}`}>{v.severity}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                        {v.url ? (
                          <a href={v.url} target="_blank" rel="noopener noreferrer" title={`Open ${v.id} on NVD`} className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-amber-300 underline decoration-dotted underline-offset-2 hover:text-amber-200">
                            {v.id}<Icon.External className="h-3 w-3 opacity-70" />
                          </a>
                        ) : (<span className="font-mono text-xs font-semibold text-slate-100">{v.id}</span>)}
                        {v.port != null && <span className="font-mono text-[10px] text-slate-500">:{v.port}</span>}
                        {v.cvss != null && <span className="shrink-0 rounded border border-slate-600/50 bg-slate-800/60 px-1 font-mono text-[9px] font-semibold text-slate-300">CVSS {v.cvss.toFixed(1)}</span>}
                        {v.kev && <span title="In CISA's KEV catalog — exploited in the wild. Patch first." className="shrink-0 animate-pulse rounded border border-crimson bg-crimson/20 px-1 font-mono text-[9px] font-bold uppercase tracking-wider text-crimson">⚠ KEV · exploited</span>}
                        {v.epss != null && v.epss >= 0.01 && (
                          <span title="FIRST EPSS — probability this CVE is exploited in the next 30 days." className={`shrink-0 rounded border px-1 font-mono text-[9px] font-semibold ${v.epss >= 0.5 ? 'border-amber/60 bg-amber/10 text-amber' : 'border-slate-600/50 bg-slate-800/40 text-slate-400'}`}>EPSS {(v.epss * 100).toFixed(v.epss >= 0.1 ? 0 : 1)}%</span>
                        )}
                        {v.confidence === 'confirmed' && <span title="An NSE script actively confirmed this host vulnerable." className="shrink-0 rounded border border-crimson/50 bg-crimson/10 px-1 font-mono text-[9px] font-semibold uppercase text-crimson">confirmed</span>}
                        {v.confidence === 'version' && <span title="Matched by detected version/CPE. Verify against vendor advisories." className="shrink-0 rounded border border-slate-600/50 bg-slate-800/40 px-1 font-mono text-[9px] font-semibold uppercase text-slate-400">version · verify</span>}
                        {v.title && <span className="truncate text-xs text-slate-400">{v.title}</span>}
                      </div>
                      {v.output && <p className="mt-0.5 truncate font-mono text-[10px] leading-relaxed text-slate-500">{v.output.replace(/\s*\n\s*/g, ' · ')}</p>}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      ) : (
        <div className="px-3 py-4 font-mono text-xs text-slate-500">
          {host.status !== HostStatus.UP
            ? '// host unreachable'
            : host.scanError
              ? '// last scan failed — check the backend is running, then click "Re-scan (nmap)"'
              : host.scanned
                ? '// scan complete — no open ports found in the scanned range'
                : '// no service scan yet — click "Nmap Scan" to enumerate ports & services'}
        </div>
      )}
    </div>
  );
}

function ScanStateBadge({ host }) {
  const cls = 'inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 font-mono text-[10px] uppercase tracking-wider';
  if (host.vulnScanning) return <span className={`${cls} border-crimson/40 bg-crimson/10 text-crimson`}><Spinner className="h-3 w-3" /> Vuln Scan</span>;
  if (host.scanning) return <span className={`${cls} border-amber/40 bg-amber/10 text-amber`}><Spinner className="h-3 w-3" /> Scanning</span>;
  if (host.status === HostStatus.DOWN) return <span className={`${cls} border-slate-700 bg-steel-900 text-slate-500`}>Skipped</span>;
  if (host.queued) return <span className={`${cls} border-amber/30 bg-amber/5 text-amber/80`}><Spinner className="h-3 w-3" /> Queued</span>;
  if (host.scanError) return <span title="The last nmap scan for this host failed — click its row, then Re-scan." className={`${cls} border-crimson/40 bg-crimson/10 text-crimson`}><Icon.Alert className="h-3 w-3" /> Failed</span>;
  if (host.scanned) return <span className={`${cls} border-matrix/40 bg-matrix/10 text-matrix`}><Icon.Check className="h-3 w-3" />{host.ports.length ? 'Done' : 'No ports'}</span>;
  return <span className={`${cls} border-slate-700 bg-steel-900 text-slate-500`}>{host.ports.length ? 'Ports' : 'Ready'}</span>;
}

function AssetRow({ host, expanded, onToggle, template }) {
  const openCount = countOpenPorts(host);
  const crit = criticalCount(host);
  const isDown = host.status === HostStatus.DOWN;
  return (
    <div className={isDown ? 'opacity-55' : ''}>
      <div
        role="button"
        tabIndex={0}
        data-host-row
        aria-expanded={expanded}
        aria-label={`Host ${host.ip}${host.hostname ? ` (${host.hostname})` : ''} — Enter to ${expanded ? 'collapse' : 'expand'}`}
        onClick={onToggle}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), onToggle())}
        style={{ gridTemplateColumns: template }}
        className={`${GRID_COLS} eg-grid-row cursor-pointer px-2 py-2.5 text-sm outline-none transition hover:bg-steel-800/60 focus-visible:bg-steel-800 focus-visible:ring-1 focus-visible:ring-amber/60 ${expanded ? 'bg-steel-800/40' : ''}`}
      >
        <span className="flex justify-center text-slate-500"><Icon.Chevron className={`h-4 w-4 transition-transform ${expanded ? 'rotate-90 text-amber' : ''}`} /></span>
        <span className="flex justify-center"><StatusDot status={host.status} /></span>
        <span className="font-mono font-semibold text-slate-100">{host.ip}</span>
        <span className="min-w-0 truncate font-mono text-xs text-slate-400">{host.hostname || <span className="text-slate-600">— no PTR —</span>}</span>
        <span className="flex min-w-0 items-center gap-1.5 truncate text-xs">
          {host.vendor === '(private/random)' ? <span className="font-mono italic text-slate-500">private</span> : host.vendor ? (<><Icon.Cpu className="h-3.5 w-3.5 shrink-0 text-slate-500" /><span className="truncate text-slate-200">{host.vendor}</span></>) : <span className="text-slate-600">—</span>}
        </span>
        <span className="min-w-0 truncate text-xs leading-tight">
          {host.device_type || (host.os && host.os !== 'Unknown' && host.os !== 'Fingerprinting…') ? (
            <span className="block">
              {host.device_type && <span className="flex items-center gap-1 truncate text-slate-200"><Icon.Layers className="h-3 w-3 shrink-0 text-slate-500" /><span className="truncate">{host.device_type}</span></span>}
              {host.os && host.os !== 'Unknown' && host.os !== 'Fingerprinting…' && <span className="block truncate font-mono text-[10px] text-matrix/80">{host.os}</span>}
            </span>
          ) : <span className="text-slate-600">—</span>}
        </span>
        <span className="flex min-w-0 items-center gap-1 truncate font-mono text-[11px] text-slate-400">
          <span className="truncate">{host.mac || <span className="text-slate-600">—</span>}</span>
          {host.ipv6?.length > 0 && <span title={`IPv6:\n${host.ipv6.join('\n')}`} className="shrink-0 rounded-sm border border-matrix/40 bg-matrix/10 px-1 text-[8px] font-semibold uppercase text-matrix">v6</span>}
        </span>
        <span className="flex items-center justify-center gap-1">
          {isDown ? <span className="font-mono text-xs text-slate-600">—</span> : (
            <>
              <span className={`font-mono text-sm font-bold tabular-nums ${openCount ? 'text-amber' : 'text-slate-500'}`}>{openCount}</span>
              {crit > 0 && <span title={`${crit} critical`} className="text-crimson"><Icon.Alert className="h-3.5 w-3.5" /></span>}
            </>
          )}
        </span>
        <span className="flex justify-end pr-1"><ScanStateBadge host={host} /></span>
      </div>
      {expanded && <div className="animate-expand-in border-y border-slate-800 bg-steel-950/40"><PortDetailTable host={host} /></div>}
    </div>
  );
}

function MatrixHeader({ sort, onSort, allExpanded, onToggleAll, template, onResize, onResetCol }) {
  const ColHead = ({ col, children }) => (
    <span className="relative flex items-center pr-2 uppercase tracking-wider text-slate-500">
      <span className="truncate">{children}</span>
      <ColResizeHandle col={col} onResize={onResize} onReset={onResetCol} />
    </span>
  );
  return (
    <div style={{ gridTemplateColumns: template }} className={`${GRID_COLS} eg-matrix-header sticky top-0 z-10 border-b border-slate-700 bg-steel-850/95 px-2 py-2 text-[10px] font-semibold backdrop-blur`}>
      <button onClick={onToggleAll} title={allExpanded ? 'Collapse all' : 'Expand all'} className="flex justify-center text-slate-500 hover:text-amber">
        <Icon.Chevron className={`h-4 w-4 transition-transform ${allExpanded ? 'rotate-90' : ''}`} />
      </button>
      <SortHeader label="" active={sort.key === 'status'} dir={sort.dir} onClick={() => onSort('status')} className="justify-center" />
      <SortHeader label="IP Address" active={sort.key === 'ip'} dir={sort.dir} onClick={() => onSort('ip')} />
      <ColHead col="hostname">Hostname</ColHead>
      <ColHead col="vendor">Vendor</ColHead>
      <ColHead col="device">Device / OS</ColHead>
      <ColHead col="mac">MAC</ColHead>
      <SortHeader label="Ports" active={sort.key === 'ports'} dir={sort.dir} onClick={() => onSort('ports')} className="justify-center" />
      <span className="text-right uppercase tracking-wider text-slate-500">Status</span>
    </div>
  );
}

function EmptyState() {
  const { startScan, target, deepScan } = useScan();
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-4 px-6 py-20 text-center">
      <div className="relative grid h-20 w-20 place-items-center rounded-2xl border border-slate-700 bg-steel-900 text-slate-500">
        <span className="eg-ring absolute inset-0 rounded-2xl border border-amber/30" />
        <Icon.Radar className="h-10 w-10 text-amber/80" />
      </div>
      <div>
        <h3 className="font-mono text-sm uppercase tracking-[0.2em] text-slate-300">Asset matrix standby</h3>
        <p className="mx-auto mt-2 max-w-md text-sm text-slate-500">
          No hosts in the buffer. Enter a target range and start a scan to run Phase 1 host discovery, then Phase 2 service enumeration.
        </p>
      </div>
      <button onClick={() => startScan(target, deepScan)} className="inline-flex items-center gap-2 rounded-lg border border-matrix/50 bg-matrix/10 px-4 py-2 text-sm font-semibold text-matrix transition hover:bg-matrix hover:text-steel-950">
        <Icon.Play className="h-4 w-4" />
        Launch scan on {target}
      </button>
    </div>
  );
}

/* ========================================================================== *
 * Topology view — a Zenmap-style radial network map.
 * ========================================================================== */

function topoColor(host) {
  if (isCriticalHost(host)) return '#D32F2F';
  const t = (host.device_type || '').toLowerCase();
  if (t.includes('router') || t.includes('gateway')) return '#FFB300';
  if (t.includes('smart') || t.includes('iot') || t.includes('media')) return '#00E676';
  if (t.includes('camera')) return '#D32F2F';
  return '#94a3b8';
}

function TopoNode({ x, y, host, radius, center, onScan }) {
  const color = topoColor(host);
  const last = host.ip.split('.').pop();
  const label = host.hostname || host.vendor || host.device_type || '';
  const open = countOpenPorts(host);
  const tip = `${host.ip}` + (host.hostname ? ` · ${host.hostname}` : '') + (host.vendor ? ` · ${host.vendor}` : '') + (host.device_type ? ` · ${host.device_type}` : '') + (open ? ` · ${open} open` : '') + '\nClick to nmap';
  return (
    <g className="cursor-pointer" onClick={() => onScan(host.ip)}>
      <title>{tip}</title>
      {center && <circle cx={x} cy={y} r={radius + 9} fill="none" stroke={color} strokeOpacity="0.3" />}
      <circle cx={x} cy={y} r={radius} fill={color} fillOpacity="0.14" stroke={color} strokeWidth={center ? 2.5 : 1.5} />
      {host.vulnScanning && (
        <circle cx={x} cy={y} r={radius + 5} fill="none" stroke="#FFB300" strokeWidth="2" strokeDasharray="3 3">
          <animateTransform attributeName="transform" type="rotate" from={`0 ${x} ${y}`} to={`360 ${x} ${y}`} dur="2s" repeatCount="indefinite" />
        </circle>
      )}
      <text x={x} y={y + 4} textAnchor="middle" fontSize={center ? 13 : 11} fontFamily="monospace" fontWeight="bold" fill={color}>.{last}</text>
      <text x={x} y={y + radius + 13} textAnchor="middle" fontSize="9" fontFamily="monospace" fill="#94a3b8">{String(label).slice(0, 18)}</text>
    </g>
  );
}

function TopologyView({ hosts, onScan }) {
  const gw = hosts.find((h) => /router|gateway/i.test(h.device_type || '')) || hosts.find((h) => h.ip.endsWith('.1')) || hosts[0];
  const others = hosts.filter((h) => h !== gw);
  const n = others.length;
  const nodeR = n > 120 ? 6 : n > 60 ? 8 : n > 30 ? 11 : 15;
  const minSpacing = nodeR * 2 + 16;
  const baseR = 120 + nodeR * 3;
  const ringStep = nodeR * 2 + 64;

  const nodes = [];
  let placed = 0;
  let ring = 0;
  while (placed < n) {
    const r = baseR + ring * ringStep;
    const cap = Math.max(6, Math.floor((2 * Math.PI * r) / minSpacing));
    const count = Math.min(cap, n - placed);
    const offset = (ring % 2) * (Math.PI / count);
    for (let p = 0; p < count; p += 1) {
      const angle = (2 * Math.PI * p) / count - Math.PI / 2 + offset;
      nodes.push({ host: others[placed + p], r, angle });
    }
    placed += count;
    ring += 1;
  }
  const ringCount = ring;
  const maxR = baseR + Math.max(0, ringCount - 1) * ringStep;
  const pad = nodeR + 56;
  const size = Math.max(420, 2 * (maxR + pad));
  const cx = size / 2;
  const cy = size / 2;
  const pos = nodes.map((nd) => ({ host: nd.host, x: cx + nd.r * Math.cos(nd.angle), y: cy + nd.r * Math.sin(nd.angle) }));

  return (
    <div className="min-h-0 flex-1 overflow-auto p-4">
      <svg viewBox={`0 0 ${size} ${size}`} className="mx-auto block w-full" style={{ maxWidth: Math.min(size, 1100), minHeight: 420 }} preserveAspectRatio="xMidYMid meet">
        {Array.from({ length: ringCount }, (_, i) => (
          <circle key={`ring-${i}`} cx={cx} cy={cy} r={baseR + i * ringStep} fill="none" stroke="rgb(var(--slate-800))" strokeWidth="1" strokeDasharray="2 5" />
        ))}
        {pos.map((nd) => <line key={`e-${nd.host.ip}`} x1={cx} y1={cy} x2={nd.x} y2={nd.y} stroke="rgb(var(--slate-800))" strokeWidth="1" />)}
        {gw && <TopoNode x={cx} y={cy} host={gw} radius={Math.max(nodeR + 8, 20)} center onScan={onScan} />}
        {pos.map((nd) => <TopoNode key={nd.host.ip} x={nd.x} y={nd.y} host={nd.host} radius={nodeR} onScan={onScan} />)}
      </svg>
      <p className="mt-2 text-center font-mono text-[10px] text-slate-600">
        hub = gateway · {others.length} devices on {ringCount} ring{ringCount === 1 ? '' : 's'} · color = device type (amber router · green smart/IoT · crimson finding) · click a node to nmap it
      </p>
    </div>
  );
}

function AssetMatrix({ hosts, view, setView }) {
  const { scanHostVulns } = useScan();
  const { colWidths, setColWidth } = usePreferences();
  const template = useMemo(() => gridTemplate(colWidths), [colWidths]);
  const [query, setQuery] = useState('');
  const [filters, setFilters] = useState(() => new Set());
  const [upOnly, setUpOnly] = useState(false);
  const [deviceFilter, setDeviceFilter] = useState('');
  const [osFilter, setOsFilter] = useState('');
  const [expanded, setExpanded] = useState(() => new Set());
  const [sort, setSort] = useState({ key: 'ip', dir: 'asc' });

  useEffect(() => {
    const onKey = (e) => {
      const t = e.target;
      const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === '/') {
        const s = document.querySelector('input[type="search"]');
        if (s) { e.preventDefault(); s.focus(); }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const onGridKey = useCallback((e) => {
    if (!['ArrowDown', 'ArrowUp', 'j', 'k'].includes(e.key)) return;
    const rows = [...e.currentTarget.querySelectorAll('[data-host-row]')];
    if (!rows.length) return;
    const idx = rows.indexOf(document.activeElement);
    const down = e.key === 'ArrowDown' || e.key === 'j';
    const next = idx < 0 ? 0 : Math.min(rows.length - 1, Math.max(0, idx + (down ? 1 : -1)));
    e.preventDefault();
    rows[next].focus();
  }, []);

  const deviceOptions = useMemo(() => {
    const set = new Set();
    for (const h of hosts) if (h.device_type) set.add(h.device_type);
    return [...set].sort();
  }, [hosts]);
  const osOptions = useMemo(() => {
    const set = new Set();
    for (const h of hosts) { const f = osFamily(h); if (f) set.add(f); }
    return [...set].sort();
  }, [hosts]);

  const clearFilters = () => { setFilters(new Set()); setUpOnly(false); setDeviceFilter(''); setOsFilter(''); setQuery(''); };
  const activeFilterCount = filters.size + (upOnly ? 1 : 0) + (deviceFilter ? 1 : 0) + (osFilter ? 1 : 0) + (query.trim() ? 1 : 0);
  const toggleFilter = (key) => setFilters((prev) => { const next = new Set(prev); next.has(key) ? next.delete(key) : next.add(key); return next; });
  const onSort = (key) => setSort((prev) => (prev.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  const toggleRow = (ip) => setExpanded((prev) => { const next = new Set(prev); next.has(ip) ? next.delete(ip) : next.add(ip); return next; });

  const visible = useMemo(() => {
    let rows = hosts;
    if (upOnly) rows = rows.filter((h) => h.status === HostStatus.UP);
    if (filters.size) rows = rows.filter((h) => [...filters].every((k) => hostMatchesFilter(h, k)));
    if (deviceFilter) rows = rows.filter((h) => h.device_type === deviceFilter);
    if (osFilter) rows = rows.filter((h) => osFamily(h) === osFilter);
    if (query.trim()) rows = rows.filter((h) => hostMatchesQuery(h, query.trim()));
    const dir = sort.dir === 'asc' ? 1 : -1;
    return [...rows].sort((a, b) => {
      let cmp = 0;
      if (sort.key === 'ip') cmp = ipSortKey(a.ip) - ipSortKey(b.ip);
      else if (sort.key === 'ports') cmp = countOpenPorts(a) - countOpenPorts(b);
      else if (sort.key === 'status') cmp = a.status.localeCompare(b.status);
      return cmp * dir;
    });
  }, [hosts, upOnly, filters, deviceFilter, osFilter, query, sort]);

  const allExpanded = visible.length > 0 && visible.every((h) => expanded.has(h.ip));
  const toggleAll = () => setExpanded(allExpanded ? new Set() : new Set(visible.map((h) => h.ip)));

  const scannedUp = hosts.filter((h) => h.status === HostStatus.UP && h.scanned);
  const closedUp = scannedUp.filter((h) => countOpenPorts(h) === 0);
  const mostlyClosed = scannedUp.length >= 5 && closedUp.length / scannedUp.length >= 0.8;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <FilterToolbar
        query={query} setQuery={setQuery}
        filters={filters} toggleFilter={toggleFilter}
        upOnly={upOnly} setUpOnly={setUpOnly}
        deviceFilter={deviceFilter} setDeviceFilter={setDeviceFilter} deviceOptions={deviceOptions}
        osFilter={osFilter} setOsFilter={setOsFilter} osOptions={osOptions}
        activeFilterCount={activeFilterCount} clearFilters={clearFilters}
        shown={visible.length} total={hosts.length}
        view={view} setView={setView}
      />

      {hosts.length === 0 ? (
        <EmptyState />
      ) : (
        <>
          {mostlyClosed && (
            <div className="flex items-start gap-2 border-b border-amber/25 bg-amber/[0.06] px-3 py-1.5 text-[11px] text-amber/90 sm:px-4">
              <Icon.Info className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>
                <b>{closedUp.length} of {scannedUp.length} scanned hosts show no open ports.</b> This is normal and <b>real</b>, not a tool error — endpoints commonly run a host firewall, and many corporate/guest Wi-Fi networks use <b>client isolation</b> (visible via ARP at layer&nbsp;2 but unreachable over TCP at layer&nbsp;3). Any ports shown are genuinely open; nothing is simulated.
              </span>
            </div>
          )}

          {view === 'map' ? (
            <TopologyView hosts={visible} onScan={scanHostVulns} />
          ) : (
            // Delegated arrow-key navigation between the focusable asset rows (the
            // rows are the real interactive elements); the container only forwards keys.
            // eslint-disable-next-line jsx-a11y/no-static-element-interactions
            <div className="min-h-0 flex-1 overflow-auto" onKeyDown={onGridKey}>
              <MatrixHeader sort={sort} onSort={onSort} allExpanded={allExpanded} onToggleAll={toggleAll} template={template} onResize={setColWidth} onResetCol={(col) => setColWidth(col, COL_DEFAULTS[col])} />
              {visible.length === 0 ? (
                <div className="px-6 py-16 text-center font-mono text-sm text-slate-500">{'// no hosts match the active search / filters'}</div>
              ) : (
                <div className="divide-y divide-slate-800/80">
                  {visible.map((host) => (
                    <AssetRow key={host.ip} host={host} expanded={expanded.has(host.ip)} onToggle={() => toggleRow(host.ip)} template={template} />
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

/* ========================================================================== *
 * Banners
 * ========================================================================== */

function DriftAlertBanner() {
  const { driftAlert, dismissAlert } = useScan();
  if (!driftAlert) return null;
  const { appeared = [], disappeared = [], changed = [] } = driftAlert;
  const sample = [...appeared.map((h) => `+${h.ip}`), ...disappeared.map((h) => `−${h.ip}`), ...changed.map((c) => `~${c.ip}`)].slice(0, 4).join('  ');
  return (
    <div className="flex items-center gap-3 border-b border-amber/40 bg-amber/10 px-4 py-2">
      <Icon.Alert className="h-4 w-4 shrink-0 text-amber" />
      <div className="min-w-0 flex-1">
        <span className="text-sm font-semibold text-amber">Network changed during monitoring</span>
        <span className="ml-2 font-mono text-xs text-amber/90">
          {appeared.length > 0 && `+${appeared.length} new  `}
          {disappeared.length > 0 && `−${disappeared.length} gone  `}
          {changed.length > 0 && `~${changed.length} changed  `}
          <span className="text-amber/70">{sample}</span>
        </span>
      </div>
      <span className="shrink-0 font-mono text-[10px] text-amber/70">{relativeTime(driftAlert.at)}</span>
      <button onClick={dismissAlert} className="shrink-0 rounded-lg border border-amber/40 px-2 py-0.5 text-xs font-semibold text-amber transition hover:bg-amber/20">Dismiss</button>
    </div>
  );
}

function ScanErrorBanner() {
  const { phase, statusMessage } = useScan();
  if (phase !== ScanPhase.ERROR || !statusMessage) return null;
  return (
    <div className="flex items-start gap-3 border-b border-crimson/40 bg-crimson/10 px-4 py-2">
      <Icon.Alert className="mt-0.5 h-4 w-4 shrink-0 text-crimson" />
      <div className="min-w-0 flex-1">
        <span className="text-sm font-semibold text-crimson">Scan error</span>
        <span className="ml-2 text-xs text-slate-300">{statusMessage}</span>
      </div>
    </div>
  );
}

/* ========================================================================== *
 * API token (RBAC) + NVD key settings — rendered inside the settings menu.
 * ========================================================================== */

function ApiTokenButton() {
  const { token, hasToken, setToken } = useApiToken();
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState(token);
  const [msg, setMsg] = useState('');
  const [testing, setTesting] = useState(false);
  useEscapeToClose(open, useCallback(() => setOpen(false), []));

  const apply = () => { setToken(input); setMsg(input.trim() ? '✓ Token saved — attached to all requests.' : 'Token cleared.'); };
  const test = () => {
    setToken(input); setTesting(true); setMsg('');
    authFetch('/api/audit?limit=1')
      .then((r) => {
        if (r.status === 401) setMsg('✗ Token rejected (401). Check ENUMGRID_ADMIN_TOKEN.');
        else if (r.ok) setMsg(input.trim() ? '✓ Token accepted.' : '✓ Reachable — auth is not enabled (open mode).');
        else setMsg(`Backend returned HTTP ${r.status}.`);
      })
      .catch(() => setMsg('✗ Backend unreachable — is it running?'))
      .finally(() => setTesting(false));
  };

  return (
    <div className="relative">
      <button
        onClick={() => { setOpen((o) => !o); setInput(token); setMsg(''); }}
        title="API token — only needed if the backend has RBAC enabled (ENUMGRID_ADMIN_TOKEN)."
        aria-haspopup="dialog"
        aria-expanded={open}
        className={`flex w-full items-center justify-between gap-2 rounded-md border px-2 py-1.5 text-[11px] font-semibold transition ${
          hasToken ? 'border-matrix/40 bg-matrix/10 text-matrix' : 'border-slate-700 bg-steel-900 text-slate-400 hover:border-slate-500 hover:text-slate-200'
        }`}
      >
        <span className="flex items-center gap-1.5"><Icon.Lock className="h-3.5 w-3.5" /> API token (RBAC)</span>
        <span className="font-mono">{hasToken ? 'on' : 'off'}</span>
      </button>
      {open && (
        <>
          <Backdrop onClose={() => setOpen(false)} className="fixed inset-0 z-40" />
          <div role="dialog" aria-label="API token settings" className="eg-card absolute right-0 z-50 mt-1 w-[300px] p-3 text-[11px]">
            <div className="mb-2 flex items-center gap-1.5 font-semibold uppercase tracking-wider text-slate-200"><Icon.Lock className="h-3.5 w-3.5" /> API token (RBAC)</div>
            <p className="mb-2 leading-relaxed text-slate-400">Only needed when the backend runs with a token (<span className="font-mono text-slate-300">ENUMGRID_ADMIN_TOKEN</span>). Sent as a <span className="font-mono text-slate-300">Bearer</span> header, stored in this browser.</p>
            <div className="flex items-center gap-1.5">
              {/* eslint-disable-next-line jsx-a11y/no-autofocus */}
              <input autoFocus type="password" value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && apply()} placeholder="paste API token…" aria-label="API token" spellCheck={false} className="w-full rounded border border-slate-700 bg-steel-900 px-2 py-1 font-mono text-slate-200 outline-none focus:border-amber/60" />
              <button onClick={apply} className="shrink-0 rounded border border-matrix/50 bg-matrix/10 px-2 py-1 font-semibold uppercase tracking-wider text-matrix transition hover:bg-matrix/20">Save</button>
              <button onClick={test} disabled={testing} className="shrink-0 rounded border border-slate-600 bg-steel-900 px-2 py-1 font-semibold uppercase tracking-wider text-slate-300 transition hover:border-slate-400 disabled:opacity-50">{testing ? '…' : 'Test'}</button>
            </div>
            {msg && <p className="mt-1.5 font-mono text-[10px] text-slate-300">{msg}</p>}
          </div>
        </>
      )}
    </div>
  );
}

function NvdKeyButton() {
  const [open, setOpen] = useState(false);
  const [status, setStatus] = useState(null);
  const [keyInput, setKeyInput] = useState('');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');
  useEscapeToClose(open, useCallback(() => setOpen(false), []));

  const refresh = useCallback(() => {
    authFetch('/api/settings/nvd').then((r) => (r.ok ? r.json() : null)).then((d) => d && setStatus(d)).catch(() => {});
  }, []);
  useEffect(() => { refresh(); }, [refresh]);

  const save = () => {
    setSaving(true); setMsg('');
    authFetch('/api/settings/nvd-key', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: keyInput }) })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(r.status === 401 ? 'admin token required' : `HTTP ${r.status}`))))
      .then((d) => { setMsg(d.key_active ? '✓ Key applied — higher rate limit active.' : 'Key cleared.'); setKeyInput(''); refresh(); })
      .catch((e) => setMsg(`✗ ${e.message}`))
      .finally(() => setSaving(false));
  };
  const active = status?.key_active;

  return (
    <div className="relative">
      <button
        onClick={() => { setOpen((o) => !o); refresh(); }}
        title="CVE intelligence — set your free NVD API key for faster vulnerability lookups"
        aria-haspopup="dialog"
        aria-expanded={open}
        className={`flex w-full items-center justify-between gap-2 rounded-md border px-2 py-1.5 text-[11px] font-semibold transition ${
          active ? 'border-matrix/40 bg-matrix/10 text-matrix' : 'border-amber/40 bg-amber/10 text-amber hover:bg-amber/20'
        }`}
      >
        <span className="flex items-center gap-1.5"><Icon.Key className="h-3.5 w-3.5" /> NVD key (CVE)</span>
        <span className="font-mono">{active ? 'active' : 'not set'}</span>
      </button>
      {open && (
        <>
          <Backdrop onClose={() => setOpen(false)} className="fixed inset-0 z-40" />
          <div role="dialog" aria-label="NVD API key settings" className="eg-card absolute right-0 z-50 mt-1 w-[300px] p-3 text-[11px]">
            <div className="mb-2 flex items-center gap-1.5 font-semibold uppercase tracking-wider text-amber"><Icon.Key className="h-3.5 w-3.5" /> NVD API key</div>
            <p className="mb-2 leading-relaxed text-slate-400">A <b>free</b> key raises the live-CVE limit from <b>5</b> to <b>50</b> req/30s. Current: <span className="font-mono text-slate-200">{status?.rate_limit || '—'}</span>.</p>
            <ol className="mb-2 list-decimal space-y-1 pl-4 text-slate-400">
              <li>Get a key: <a href={status?.get_key_url || 'https://nvd.nist.gov/developers/request-an-api-key'} target="_blank" rel="noopener noreferrer" className="font-mono text-amber-300 underline decoration-dotted underline-offset-2 hover:text-amber-200">nvd.nist.gov ↗</a></li>
              <li>Paste it below and click Apply.</li>
            </ol>
            <div className="flex items-center gap-1.5">
              {/* eslint-disable-next-line jsx-a11y/no-autofocus */}
              <input autoFocus type="password" value={keyInput} onChange={(e) => setKeyInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && !saving && keyInput.trim() && save()} placeholder="paste NVD API key…" aria-label="NVD API key" spellCheck={false} className="w-full rounded border border-slate-700 bg-steel-900 px-2 py-1 font-mono text-slate-200 outline-none focus:border-amber/60" />
              <button onClick={save} disabled={saving || !keyInput.trim()} className="shrink-0 rounded border border-matrix/50 bg-matrix/10 px-2 py-1 font-semibold uppercase tracking-wider text-matrix transition hover:bg-matrix/20 disabled:cursor-not-allowed disabled:opacity-50">{saving ? '…' : 'Apply'}</button>
            </div>
            {msg && <p className="mt-1.5 font-mono text-[10px] text-slate-300">{msg}</p>}
            <p className="mt-2 border-t border-slate-700/60 pt-2 text-[10px] text-slate-500">Applying a key here <b className="text-slate-300">persists across restarts</b> (owner-only 0600 file, never logged).</p>
          </div>
        </>
      )}
    </div>
  );
}

/* ========================================================================== *
 * Scan configuration — collapsible advanced nmap options (profile, command,
 * NSE picker, ports). Hidden by default so the cockpit stays uncluttered.
 * ========================================================================== */

function ScanConfigPanel() {
  const {
    profiles, scanProfile, setScanProfile, scanScripts, setScanScripts,
    scanPorts, setScanPorts, capability, canRaw, scanAll, hosts,
  } = useScan();
  const [open, setOpen] = useState(false);
  const entries = Object.entries(profiles || {});
  const sel = profiles[scanProfile] || {};
  const upCount = hosts.filter((h) => h.status === HostStatus.UP).length;
  const field = 'rounded-lg border border-slate-700 bg-steel-900 px-2 py-1 font-mono text-slate-200 outline-none transition focus:border-amber/60';

  const scriptSet = new Set((scanScripts || '').split(',').map((s) => s.trim()).filter(Boolean));
  const toggleScript = (name) => {
    const next = new Set(scriptSet);
    next.has(name) ? next.delete(name) : next.add(name);
    setScanScripts([...next].join(','));
  };

  return (
    <div className="border-b border-slate-800 px-3 pt-2.5 sm:px-4">
      <button
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 rounded-lg border border-slate-700/70 bg-steel-900/60 px-3 py-2 text-left transition hover:border-slate-600"
      >
        <Icon.Sliders className="h-4 w-4 text-amber" />
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">Nmap scan options</span>
        {entries.length > 0 && (
          <span className="rounded-md border border-slate-700 bg-steel-950 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">{sel.label || scanProfile}</span>
        )}
        {scriptSet.size > 0 && <span className="rounded-md border border-amber/40 bg-amber/10 px-1.5 py-0.5 font-mono text-[10px] text-amber">+{scriptSet.size} NSE</span>}
        <span className={`ml-auto inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-semibold ${canRaw ? 'border-matrix/40 bg-matrix/10 text-matrix' : 'border-slate-700 bg-steel-950 text-slate-400'}`}>
          {canRaw ? <Icon.ShieldCheck className="h-3 w-3" /> : <Icon.Shield className="h-3 w-3" />}
          {canRaw ? (capability === 'root' ? 'root' : 'sudo') : 'unprivileged'}
        </span>
        <Icon.ChevronDown className={`h-4 w-4 text-slate-500 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && entries.length === 0 && (
        <div className="eg-drawer mt-2 rounded-lg border border-slate-700/70 bg-steel-900/60 px-3 py-2 font-mono text-[11px] text-slate-500">
          {'// scan profiles unavailable — backend offline'}
        </div>
      )}

      {open && entries.length > 0 && (
        <div className="eg-drawer mt-2 space-y-2.5 rounded-lg border border-slate-700/70 bg-steel-900/60 p-3 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="flex items-center gap-1.5 font-semibold uppercase tracking-widest text-amber"><Icon.Cpu className="h-3.5 w-3.5" /> Profile</span>
            <select value={scanProfile} onChange={(e) => setScanProfile(e.target.value)} aria-label="Nmap scan profile" title="Scan profile — changes the actual nmap command" className={field}>
              {entries.map(([key, p]) => <option key={key} value={key}>{p.label}</option>)}
            </select>
            <button
              onClick={() => scanAll(true)}
              disabled={!upCount}
              title="Run this nmap profile against every live host (re-scans even already-scanned hosts)"
              className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 font-semibold transition ${upCount ? 'border-matrix bg-matrix/15 text-matrix hover:bg-matrix/25' : 'cursor-not-allowed border-slate-700 bg-steel-900 text-slate-600'}`}
            >
              <Icon.Play className="h-3 w-3" /> Run Nmap Scan{upCount ? ` (${upCount})` : ''}
            </button>
            <span className="hidden text-slate-500 lg:inline">{sel.desc}</span>
          </div>

          {sel.args && (
            <div className="overflow-x-auto whitespace-nowrap rounded-lg border border-slate-800 bg-steel-950/70 px-2.5 py-1.5 font-mono text-[10px] text-slate-500">
              <span className="text-slate-600">$</span> nmap <span className="text-slate-300">{sel.args}</span>
              {scriptSet.size > 0 && <span className="text-amber"> --script {[...scriptSet].join(',')}</span>}
              {scanPorts && <span className="text-amber"> -p {scanPorts}</span>}
              {canRaw && !/-A|-sS|-sU/.test(sel.args) && <span className="text-matrix"> -O</span>}
              <span className="text-slate-600"> &lt;host&gt;</span>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <input value={scanScripts} onChange={(e) => setScanScripts(e.target.value)} placeholder="extra NSE scripts — e.g. http-title,ssl-cert" spellCheck={false} aria-label="Extra NSE scripts (comma-separated)" title="Comma-separated NSE script names/categories (intrusive ones blocked server-side)" className={`${field} w-full sm:min-w-[170px] sm:flex-1`} />
            <input value={scanPorts} onChange={(e) => setScanPorts(e.target.value)} placeholder="ports — e.g. 1-1024,3389" spellCheck={false} aria-label="Port spec" title="Explicit port spec" className={`${field} w-full sm:w-40`} />
          </div>

          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">add NSE</span>
              {scriptSet.size > 0 && (
                <button onClick={() => [...scriptSet].forEach((s) => toggleScript(s))} className="rounded border border-slate-700 px-1.5 py-0.5 font-mono text-[10px] text-slate-400 transition hover:border-crimson/60 hover:text-crimson">clear {scriptSet.size}</button>
              )}
            </div>
            {SCRIPT_GROUPS.map((group) => (
              <div key={group.label} className="flex flex-wrap items-center gap-1">
                <span className="mr-1 w-[88px] shrink-0 text-right text-[9px] font-semibold uppercase tracking-wider text-slate-600">{group.label}</span>
                {group.scripts.map((s) => {
                  const on = scriptSet.has(s);
                  return (
                    <button key={s} onClick={() => toggleScript(s)} className={`rounded border px-1.5 py-0.5 font-mono text-[10px] transition ${on ? 'border-amber bg-amber/15 text-amber' : 'border-slate-700 bg-steel-900 text-slate-400 hover:border-slate-500 hover:text-slate-200'}`}>
                      {on ? '✓ ' : '+ '}{s}
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ========================================================================== *
 * Boot splash — a short startup animation the first time the cockpit loads.
 * ========================================================================== */

const BOOT_LINES = [
  'initializing scan engine',
  'loading nmap profiles · 11 ready',
  'arming discovery · ICMP · ARP · NDP · mDNS · NBNS',
  'OS fingerprint fusion online',
  'CVE correlation linked to NVD',
  'ENUMGRID ready',
];

function BootSplash({ onDone }) {
  const [shown, setShown] = useState(0);
  const [leaving, setLeaving] = useState(false);
  useEffect(() => {
    const step = 260;
    const timers = BOOT_LINES.map((_, i) => setTimeout(() => setShown(i + 1), step * i + 250));
    const out = setTimeout(() => setLeaving(true), step * BOOT_LINES.length + 650);
    const done = setTimeout(onDone, step * BOOT_LINES.length + 1200);
    return () => { timers.forEach(clearTimeout); clearTimeout(out); clearTimeout(done); };
  }, [onDone]);
  return (
    <div
      onClick={onDone}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ' || e.key === 'Escape') onDone(); }}
      role="button"
      tabIndex={0}
      aria-label="Skip the intro animation"
      className={`fixed inset-0 z-[80] flex cursor-pointer flex-col items-center justify-center bg-steel-950 transition-opacity duration-500 ${leaving ? 'opacity-0' : 'opacity-100'}`}
    >
      <div className="relative mb-6 h-28 w-28">
        <span className="eg-ring absolute inset-0 rounded-full border border-matrix/40" />
        <span className="eg-ring absolute inset-0 rounded-full border border-matrix/30" style={{ animationDelay: '0.6s' }} />
        <div className="absolute inset-0 flex items-center justify-center rounded-full border border-slate-700 bg-steel-900/80 shadow-glow-matrix"><Icon.Radar className="h-12 w-12 text-matrix" /></div>
      </div>
      <h1 className="font-mono text-3xl font-bold tracking-[0.3em] text-slate-100">ENUM<span className="eg-brand-gradient">GRID</span></h1>
      <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.4em] text-slate-500">the Enumeration Platform</p>
      <div className="relative mt-8 h-40 w-[min(90vw,420px)] overflow-hidden rounded-lg border border-slate-800 bg-black/40 p-4">
        <span className="eg-scanline pointer-events-none absolute inset-x-0 top-0 h-12 bg-gradient-to-b from-matrix/15 to-transparent" />
        <ul className="space-y-1.5 font-mono text-[11px]">
          {BOOT_LINES.slice(0, shown).map((line, i) => (
            <li key={line} className="eg-boot-line flex items-center gap-2 text-slate-400">
              <span className="text-matrix">▸</span><span>{line}</span>
              {i === shown - 1 && shown < BOOT_LINES.length && <span className="text-slate-600">…</span>}
              {i < shown - 1 && <Icon.Check className="ml-auto h-3 w-3 text-matrix" />}
            </li>
          ))}
          {shown >= BOOT_LINES.length && <li className="mt-1 font-mono text-[11px] text-matrix">$ <span className="eg-cursor">█</span></li>}
        </ul>
      </div>
      <p className="mt-4 font-mono text-[9px] uppercase tracking-widest text-slate-600">click to skip</p>
    </div>
  );
}

/* ========================================================================== *
 * Root
 * ========================================================================== */

/**
 * ⌘K / Ctrl-K command palette — a searchable launcher for every top action.
 * Owns its own open state, binds the shortcut + an `eg:open-command-palette`
 * event, and is fully keyboard-driven (type to filter, ↑/↓ to move, ↵ to run).
 */
function CommandPalette() {
  const scan = useScan();
  const { toggleTheme, toggleDensity } = usePreferences();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef(null);
  const listRef = useRef(null);
  const dialogRef = useFocusTrap({ active: open, initialFocus: inputRef });

  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    const openEvt = () => setOpen(true);
    window.addEventListener('keydown', onKey);
    window.addEventListener('eg:open-command-palette', openEvt);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('eg:open-command-palette', openEvt);
    };
  }, []);

  // Fresh query + selection each time it opens.
  useEffect(() => {
    if (open) {
      setQuery('');
      setActive(0);
    }
  }, [open]);

  const runExport = useCallback((fn, okMsg) => {
    try {
      const r = fn();
      if (r && typeof r.then === 'function') {
        r.then(() => toast(okMsg, { type: 'success' })).catch(() => toast('Export failed — is the backend running?', { type: 'error' }));
      } else {
        toast(okMsg, { type: 'success' });
      }
    } catch {
      toast('Export failed.', { type: 'error' });
    }
  }, [toast]);

  const {
    running, target, deepScan, monitor, hosts,
    startScan, stopScan, toggleDeep, toggleMonitor, scanAll,
    downloadReport, exportCsv, exportJson,
  } = scan;
  const unscanned = hosts.filter((h) => h.status === HostStatus.UP && !h.scanned).length;
  const hasHosts = hosts.length > 0;

  const commands = useMemo(() => {
    const list = [];
    if (running) list.push({ id: 'stop', label: 'Stop scan', Icon: Icon.Stop, keywords: ['halt', 'cancel'], run: stopScan });
    else list.push({ id: 'start', label: 'Start scan', Icon: Icon.Play, keywords: ['run', 'go'], run: () => startScan(target, deepScan) });
    if (unscanned) list.push({ id: 'scanall', label: `Scan all live hosts (${unscanned})`, Icon: Icon.Cpu, keywords: ['enumerate', 'services', 'ports'], run: () => scanAll(false) });
    list.push({ id: 'deep', label: `${deepScan ? 'Disable' : 'Enable'} deep scan (NSE vuln)`, Icon: Icon.Shield, keywords: ['cve', 'vulnerability'], run: toggleDeep });
    list.push({ id: 'monitor', label: `${monitor ? 'Stop' : 'Start'} monitor mode`, Icon: Icon.Activity, keywords: ['watch', 'drift', 'interval'], run: toggleMonitor });
    list.push({ id: 'ops', label: 'Operations — passive · schedules · campaign…', Icon: Icon.Radar, keywords: ['passive', 'sniff', 'stealth', 'schedule', 'cron', 'campaign', 'subnet', 'aggregate'], run: () => window.dispatchEvent(new Event('eg:open-operations')) });
    list.push({ id: 'copilot', label: 'Ask the AI Copilot…', Icon: Icon.Activity, keywords: ['ai', 'copilot', 'assistant', 'chat', 'claude', 'openai', 'gpt', 'explain', 'advise'], run: () => window.dispatchEvent(new Event('eg:open-copilot')) });
    list.push({ id: 'priv', label: 'Scan privilege / elevate…', Icon: Icon.Bolt, keywords: ['sudo', 'root', 'raw socket'], run: () => window.dispatchEvent(new Event('eg:open-privilege')) });
    if (hasHosts) {
      list.push({ id: 'pdf', label: 'Export PDF report', Icon: Icon.Download, keywords: ['download', 'report'], run: () => runExport(downloadReport, 'PDF report downloaded.') });
      list.push({ id: 'csv', label: 'Export CSV inventory', Icon: Icon.Server, keywords: ['download', 'spreadsheet'], run: () => runExport(exportCsv, 'CSV inventory exported.') });
      list.push({ id: 'json', label: 'Export JSON snapshot', Icon: Icon.Terminal, keywords: ['download', 'data'], run: () => runExport(exportJson, 'JSON snapshot exported.') });
    }
    list.push({ id: 'search', label: 'Focus search', Icon: Icon.Search, keywords: ['find', 'filter'], run: () => document.querySelector('input[type="search"]')?.focus() });
    list.push({ id: 'theme', label: 'Toggle light / dark theme', Icon: Icon.Moon, keywords: ['dark', 'light', 'appearance'], run: toggleTheme });
    list.push({ id: 'density', label: 'Toggle compact / cozy density', Icon: Icon.Rows, keywords: ['spacing', 'layout'], run: toggleDensity });
    list.push({ id: 'help', label: 'Keyboard shortcuts', Icon: Icon.Terminal, keywords: ['keys', 'cheatsheet'], run: () => window.dispatchEvent(new Event('eg:open-help')) });
    return list;
  }, [running, target, deepScan, monitor, unscanned, hasHosts, startScan, stopScan, toggleDeep, toggleMonitor, scanAll, downloadReport, exportCsv, exportJson, toggleTheme, toggleDensity, runExport]);

  const filtered = filterCommands(commands, query);
  const safeActive = filtered.length ? Math.min(active, filtered.length - 1) : 0;

  // Keep the highlighted row in view as the selection moves.
  useEffect(() => {
    listRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [safeActive, query]);

  const runCmd = (cmd) => {
    if (!cmd) return;
    setOpen(false);
    cmd.run();
  };

  const onInputKey = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(a + 1, filtered.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
    else if (e.key === 'Enter') { e.preventDefault(); runCmd(filtered[safeActive]); }
    else if (e.key === 'Escape') { e.preventDefault(); setOpen(false); }
  };

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[85] flex items-start justify-center p-4 pt-[12vh]" role="dialog" aria-modal="true" aria-label="Command palette">
      <Backdrop onClose={() => setOpen(false)} className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div ref={dialogRef} tabIndex={-1} className="eg-card relative z-10 w-full max-w-lg overflow-hidden p-0 outline-none">
        <div className="flex items-center gap-2 border-b border-slate-700/60 px-3">
          <Icon.Search className="h-4 w-4 shrink-0 text-slate-500" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => { setQuery(e.target.value); setActive(0); }}
            onKeyDown={onInputKey}
            placeholder="Type a command…"
            aria-label="Command palette search"
            spellCheck={false}
            className="w-full bg-transparent py-3 font-mono text-sm text-slate-100 outline-none placeholder:text-slate-500"
          />
          <kbd className="hidden shrink-0 rounded border border-slate-600 bg-steel-900 px-1.5 py-0.5 font-mono text-[10px] text-slate-400 sm:block">esc</kbd>
        </div>
        <ul ref={listRef} className="max-h-[50vh] overflow-y-auto p-1.5" role="listbox" aria-label="Commands">
          {filtered.length === 0 ? (
            <li className="px-3 py-6 text-center font-mono text-xs text-slate-500">{'// no matching command'}</li>
          ) : (
            filtered.map((cmd, i) => {
              const isActive = i === safeActive;
              const Ico = cmd.Icon;
              return (
                <li key={cmd.id}>
                  <button
                    type="button"
                    role="option"
                    aria-selected={isActive}
                    data-active={isActive ? 'true' : undefined}
                    onMouseEnter={() => setActive(i)}
                    onClick={() => runCmd(cmd)}
                    className={`flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left text-xs transition ${
                      isActive ? 'bg-amber/15 text-amber' : 'text-slate-300 hover:bg-steel-800'
                    }`}
                  >
                    {Ico && <Ico className={`h-4 w-4 shrink-0 ${isActive ? 'text-amber' : 'text-slate-500'}`} />}
                    <span className="flex-1">{cmd.label}</span>
                    {isActive && <Icon.Chevron className="h-3.5 w-3.5 opacity-70" />}
                  </button>
                </li>
              );
            })
          )}
        </ul>
      </div>
    </div>
  );
}

/** Modal cheat-sheet of the global keyboard shortcuts (opened with "?"). */
function HelpOverlay({ onClose }) {
  useEscapeToClose(true, onClose);
  const ref = useFocusTrap();
  return (
    <div className="fixed inset-0 z-[75] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Keyboard shortcuts">
      <Backdrop onClose={onClose} className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div ref={ref} tabIndex={-1} className="eg-card relative z-10 w-full max-w-sm p-5 outline-none">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Icon.Terminal className="h-4 w-4 text-amber" /> Keyboard shortcuts
          </h2>
          <button onClick={onClose} aria-label="Close" className="rounded p-1 text-slate-500 outline-none transition hover:bg-steel-800 hover:text-slate-200 focus-visible:ring-2 focus-visible:ring-sky-400">
            <Icon.X className="h-4 w-4" />
          </button>
        </div>
        <ul className="divide-y divide-slate-800/70">
          {SHORTCUTS.map((s) => (
            <li key={s.keys} className="flex items-center justify-between gap-4 py-2 text-xs">
              <span className="text-slate-300">{s.label}</span>
              <kbd className="shrink-0 rounded border border-slate-600 bg-steel-900 px-2 py-0.5 font-mono text-[11px] text-slate-200">{s.keys}</kbd>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

/**
 * Binds the safe global shortcuts (search focus, theme, density, help) and owns
 * the help overlay. Single-key shortcuts are suppressed while typing in a field.
 * Also opens on a window `eg:open-help` event so the Settings menu can trigger it.
 */
function ShortcutsLayer() {
  const { toggleTheme, toggleDensity } = usePreferences();
  const [helpOpen, setHelpOpen] = useState(false);

  useEffect(() => {
    const onKey = (e) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === 'Escape') { setHelpOpen(false); return; }
      if (isEditableTarget(e.target)) return;
      if (e.key === '/') { e.preventDefault(); document.querySelector('input[type="search"]')?.focus(); }
      else if (e.key === '?') { e.preventDefault(); setHelpOpen((o) => !o); }
      else if (e.key === 't') { e.preventDefault(); toggleTheme(); }
      else if (e.key === 'd') { e.preventDefault(); toggleDensity(); }
    };
    const openHelp = () => setHelpOpen(true);
    window.addEventListener('keydown', onKey);
    window.addEventListener('eg:open-help', openHelp);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('eg:open-help', openHelp);
    };
  }, [toggleTheme, toggleDensity]);

  return helpOpen ? <HelpOverlay onClose={() => setHelpOpen(false)} /> : null;
}

/* ========================================================================== *
 * Operations panel — passive discovery · scheduled scans · multi-subnet campaign
 * One modal that surfaces the three headless / aggregate backend capabilities.
 * Opened from the command palette or Settings menu via `eg:open-operations`.
 * ========================================================================== */

const OPS_TABS = [
  { id: 'passive', label: 'Passive', Icon: Icon.Radar },
  { id: 'schedules', label: 'Schedules', Icon: Icon.Activity },
  { id: 'campaign', label: 'Campaign', Icon: Icon.Layers },
];

const opsField =
  'w-full rounded-lg border border-slate-700 bg-steel-900 px-3 py-2 text-sm text-slate-100 outline-none transition focus:border-sky-500 focus-visible:ring-2 focus-visible:ring-sky-400';
const opsBtn =
  'inline-flex items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-xs font-semibold outline-none transition focus-visible:ring-2 focus-visible:ring-sky-400 disabled:opacity-50';

/** Passive (zero-packet) discovery — listen for ARP/DHCP/mDNS/LLMNR/NBNS chatter. */
function PassiveTab() {
  const { toast } = useToast();
  const [seconds, setSeconds] = useState(15);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  const run = () => {
    setBusy(true);
    setResult(null);
    authFetch(`/api/passive?seconds=${seconds}`, { method: 'POST' })
      .then((r) => r.json())
      .then((d) => {
        setResult(d);
        if (d.available) toast(`Heard ${d.count} host${d.count === 1 ? '' : 's'} in ${d.seconds}s.`, { type: 'success', title: 'Passive listen complete' });
        else toast(d.reason || 'Passive capture unavailable.', { type: 'warn', title: 'Passive unavailable' });
      })
      .catch((e) => {
        setResult({ available: false, reason: e.message || 'request failed', hosts: [], count: 0 });
        toast('Passive request failed.', { type: 'error' });
      })
      .finally(() => setBusy(false));
  };

  return (
    <div className="space-y-3">
      <p className="text-[11px] leading-relaxed text-slate-400">
        Listens for the broadcast/multicast traffic hosts emit on their own (ARP, DHCP, mDNS, LLMNR,
        NetBIOS) and reports who is talking. <span className="text-matrix">Sends nothing on the wire</span> —
        stealthy, and a clean contrast to active discovery. Needs <code className="text-slate-300">scapy</code> +
        raw-socket privilege.
      </p>
      <div className="flex items-end gap-2">
        <label className="flex-1">
          <span className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-slate-500">Listen window</span>
          <select className={opsField} value={seconds} onChange={(e) => setSeconds(Number(e.target.value))} disabled={busy}>
            {[10, 15, 30, 60].map((s) => <option key={s} value={s}>{s} seconds</option>)}
          </select>
        </label>
        <button onClick={run} disabled={busy} className={`${opsBtn} border-matrix/45 bg-matrix/10 text-matrix hover:bg-matrix/20`}>
          <Icon.Radar className="h-4 w-4" />{busy ? 'Listening…' : 'Start passive listen'}
        </button>
      </div>

      {result && !result.available && (
        <div className="flex items-start gap-2 rounded-lg border border-amber/40 bg-amber/10 p-3 text-xs text-amber">
          <Icon.Info className="mt-0.5 h-4 w-4 shrink-0" />
          <span>Passive capture unavailable: {result.reason}</span>
        </div>
      )}
      {result && result.available && (
        <div className="rounded-lg border border-slate-700/70">
          <div className="border-b border-slate-800 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
            {result.count} host{result.count === 1 ? '' : 's'} heard
          </div>
          {result.count === 0 ? (
            <p className="px-3 py-4 text-center text-xs text-slate-500">No chatter observed in the window — try a longer listen.</p>
          ) : (
            <div className="max-h-56 overflow-auto">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-steel-900 text-[10px] uppercase tracking-wider text-slate-500">
                  <tr><th className="px-3 py-1.5">IP</th><th className="px-3 py-1.5">MAC</th><th className="px-3 py-1.5">Via</th><th className="px-3 py-1.5">Hostname</th></tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {result.hosts.map((h) => (
                    <tr key={h.ip}>
                      <td className="px-3 py-1.5 font-mono text-slate-200">{h.ip}</td>
                      <td className="px-3 py-1.5 font-mono text-slate-500">{h.mac || '—'}</td>
                      <td className="px-3 py-1.5 text-slate-400">{(h.methods || []).join(', ')}</td>
                      <td className="px-3 py-1.5 text-slate-400">{h.hostname || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** Cron-style scheduled scans — create/list/toggle/delete recurring rules. */
function SchedulesTab() {
  const { toast } = useToast();
  const { target: currentTarget } = useScan();
  const [rules, setRules] = useState(null); // null = loading
  const [target, setTarget] = useState(currentTarget || '');
  const [at, setAt] = useState('02:00');
  const [days, setDays] = useState(new Set());
  const [mode, setMode] = useState('discover');
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    authFetch('/api/schedules')
      .then((r) => (r.ok ? r.json() : { schedules: [] }))
      .then((d) => setRules(d.schedules || []))
      .catch(() => setRules([]));
  }, []);
  useEffect(() => { load(); }, [load]);

  const toggleDay = (d) => setDays((prev) => {
    const next = new Set(prev);
    if (next.has(d)) next.delete(d); else next.add(d);
    return next;
  });

  const add = () => {
    const check = validateScheduleForm({ target, at });
    if (!check.ok) { toast(check.error, { type: 'error' }); return; }
    setBusy(true);
    const daySpec = days.size ? DAY_OPTIONS.filter((o) => days.has(o.value)).map((o) => o.value).join(',') : '*';
    authFetch('/api/schedules', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: target.trim(), at, days: daySpec, mode }),
    })
      .then(async (r) => {
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.error || 'Could not create schedule.');
        toast('Schedule created.', { type: 'success' });
        setDays(new Set());
        load();
      })
      .catch((e) => toast(e.message, { type: 'error' }))
      .finally(() => setBusy(false));
  };

  const setEnabled = (rule, enabled) => {
    authFetch(`/api/schedules/${rule.id}/toggle?enabled=${enabled}`, { method: 'POST' })
      .then((r) => { if (!r.ok) throw new Error(); load(); })
      .catch(() => toast('Could not update schedule.', { type: 'error' }));
  };

  const remove = (rule) => {
    authFetch(`/api/schedules/${rule.id}`, { method: 'DELETE' })
      .then((r) => { if (!r.ok) throw new Error(); toast('Schedule removed.', { type: 'info' }); load(); })
      .catch(() => toast('Could not remove schedule.', { type: 'error' }));
  };

  return (
    <div className="space-y-3">
      <p className="text-[11px] leading-relaxed text-slate-400">
        Unattended, time-of-day scans that fire even with no browser open. Each rule enqueues the same
        pipeline the dashboard uses, so results land in history &amp; drift automatically.
      </p>

      <div className="rounded-lg border border-slate-700/70 p-3">
        <div className="grid grid-cols-2 gap-2">
          <label className="col-span-2">
            <span className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-slate-500">Target</span>
            <input className={`${opsField} font-mono`} value={target} onChange={(e) => setTarget(e.target.value)} placeholder="192.168.0.0/24" />
          </label>
          <label>
            <span className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-slate-500">Time (HH:MM)</span>
            <input className={`${opsField} font-mono`} value={at} onChange={(e) => setAt(e.target.value)} placeholder="02:00" />
          </label>
          <label>
            <span className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-slate-500">Mode</span>
            <select className={opsField} value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="discover">Discovery (fast)</option>
              <option value="full">Full (nmap -sV)</option>
            </select>
          </label>
        </div>
        <div className="mt-2">
          <span className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-slate-500">Days (none = every day)</span>
          <div className="flex flex-wrap gap-1.5">
            {DAY_OPTIONS.map((o) => (
              <button
                key={o.value}
                onClick={() => toggleDay(o.value)}
                aria-pressed={days.has(o.value)}
                className={`rounded-md border px-2 py-1 text-[11px] font-semibold transition ${days.has(o.value) ? 'border-sky-500/50 bg-sky-500/10 text-sky-300' : 'border-slate-700 bg-steel-900 text-slate-400 hover:text-slate-200'}`}
              >{o.label}</button>
            ))}
          </div>
        </div>
        <button onClick={add} disabled={busy} className={`${opsBtn} mt-3 w-full border-sky-500/45 bg-sky-500/10 text-sky-300 hover:bg-sky-500/20`}>
          {busy ? 'Adding…' : 'Add schedule'}
        </button>
      </div>

      <div className="rounded-lg border border-slate-700/70">
        <div className="border-b border-slate-800 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
          Active rules
        </div>
        {rules === null ? (
          <p className="px-3 py-4 text-center text-xs text-slate-500">Loading…</p>
        ) : rules.length === 0 ? (
          <p className="px-3 py-4 text-center text-xs text-slate-500">No schedules yet — add one above.</p>
        ) : (
          <ul className="divide-y divide-slate-800/70">
            {rules.map((r) => (
              <li key={r.id} className="flex items-center justify-between gap-2 px-3 py-2">
                <div className="min-w-0">
                  <div className="truncate font-mono text-xs text-slate-200">{r.target}</div>
                  <div className="text-[11px] text-slate-500">{describeSchedule(r)}</div>
                </div>
                <div className="flex shrink-0 items-center gap-1.5">
                  <button
                    onClick={() => setEnabled(r, !r.enabled)}
                    aria-pressed={r.enabled}
                    className={`rounded-md border px-2 py-1 text-[10px] font-semibold transition ${r.enabled ? 'border-matrix/45 bg-matrix/10 text-matrix' : 'border-slate-700 bg-steel-900 text-slate-500'}`}
                  >{r.enabled ? 'On' : 'Off'}</button>
                  <button onClick={() => remove(r)} aria-label={`Remove schedule for ${r.target}`} className="rounded-md border border-slate-700 p-1 text-slate-500 transition hover:border-crimson/50 hover:text-crimson focus-visible:ring-2 focus-visible:ring-sky-400">
                    <Icon.X className="h-3.5 w-3.5" />
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

/** Multi-subnet campaign — roll up the latest scan of several subnets into one view. */
function CampaignTab() {
  const { toast } = useToast();
  const { target: currentTarget } = useScan();
  const [input, setInput] = useState(currentTarget || '');
  const [busy, setBusy] = useState(false);
  const [data, setData] = useState(null);

  const run = () => {
    const targets = splitTargets(input);
    if (!targets.length) { toast('Enter one or more subnet targets.', { type: 'error' }); return; }
    setBusy(true);
    authFetch(`/api/campaign?targets=${encodeURIComponent(targets.join(','))}`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('request failed'))))
      .then((d) => { setData(d); toast(`Aggregated ${d.totals.scanned_subnets}/${d.totals.subnets} subnets.`, { type: 'success', title: 'Campaign built' }); })
      .catch(() => toast('Could not build campaign view.', { type: 'error' }))
      .finally(() => setBusy(false));
  };

  const tiles = data ? [
    { k: 'Subnets', v: `${data.totals.scanned_subnets}/${data.totals.subnets}` },
    { k: 'Hosts', v: data.totals.hosts },
    { k: 'Open ports', v: data.totals.open_ports },
  ] : [];
  const sevEntries = data ? Object.entries(data.severity).filter(([, n]) => n > 0) : [];

  return (
    <div className="space-y-3">
      <p className="text-[11px] leading-relaxed text-slate-400">
        Combine the <span className="text-slate-200">latest stored scan</span> of several subnets into one
        estate-wide picture. Enter targets (comma / space / newline separated); unscanned subnets are shown too.
      </p>
      <div className="flex items-end gap-2">
        <label className="flex-1">
          <span className="mb-1 block text-[10px] font-semibold uppercase tracking-widest text-slate-500">Subnets</span>
          <input className={`${opsField} font-mono`} value={input} onChange={(e) => setInput(e.target.value)} placeholder="192.168.0.0/24, 10.0.0.0/24" />
        </label>
        <button onClick={run} disabled={busy} className={`${opsBtn} border-sky-500/45 bg-sky-500/10 text-sky-300 hover:bg-sky-500/20`}>
          <Icon.Layers className="h-4 w-4" />{busy ? 'Building…' : 'Aggregate'}
        </button>
      </div>

      {data && (
        <div className="space-y-3">
          <div className="grid grid-cols-3 gap-2">
            {tiles.map((t) => (
              <div key={t.k} className="rounded-lg border border-slate-700/70 bg-steel-900 px-3 py-2 text-center">
                <div className="text-lg font-bold text-slate-100">{t.v}</div>
                <div className="text-[10px] uppercase tracking-widest text-slate-500">{t.k}</div>
              </div>
            ))}
          </div>

          {sevEntries.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {sevEntries.map(([sev, n]) => (
                <span key={sev} className={`rounded-md border px-2 py-0.5 text-[11px] font-semibold ${severityTone(sev)}`}>{n} {sev}</span>
              ))}
            </div>
          )}

          <div className="rounded-lg border border-slate-700/70">
            <div className="border-b border-slate-800 px-3 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-500">Per subnet</div>
            <div className="max-h-40 overflow-auto">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-steel-900 text-[10px] uppercase tracking-wider text-slate-500">
                  <tr><th className="px-3 py-1.5">Subnet</th><th className="px-3 py-1.5">Status</th><th className="px-3 py-1.5 text-right">Hosts</th><th className="px-3 py-1.5 text-right">Open</th></tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {data.subnets.map((s) => (
                    <tr key={s.target}>
                      <td className="px-3 py-1.5 font-mono text-slate-200">{s.target}</td>
                      <td className="px-3 py-1.5">{s.scanned ? <span className="text-matrix">scanned</span> : <span className="text-slate-500">never scanned</span>}</td>
                      <td className="px-3 py-1.5 text-right font-mono text-slate-300">{s.hosts}</td>
                      <td className="px-3 py-1.5 text-right font-mono text-slate-300">{s.open_ports}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/** The Operations modal — tabbed shell around the three capability panels. */
function OperationsPanel({ onClose }) {
  const [tab, setTab] = useState('passive');
  useEscapeToClose(true, onClose);
  const ref = useFocusTrap();
  return (
    <div className="fixed inset-0 z-[78] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-label="Operations">
      <Backdrop onClose={onClose} className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div ref={ref} tabIndex={-1} className="eg-card relative z-10 flex max-h-[85vh] w-full max-w-lg flex-col overflow-hidden p-0 outline-none">
        <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Icon.Radar className="h-4 w-4 text-sky-400" /> Operations
          </h2>
          <button onClick={onClose} aria-label="Close" className="rounded p-1 text-slate-500 outline-none transition hover:bg-steel-800 hover:text-slate-200 focus-visible:ring-2 focus-visible:ring-sky-400">
            <Icon.X className="h-4 w-4" />
          </button>
        </div>
        <div role="tablist" aria-label="Operations sections" className="flex gap-1 border-b border-slate-800 px-3 pt-2">
          {OPS_TABS.map((t) => (
            <button
              key={t.id}
              role="tab"
              aria-selected={tab === t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-1.5 rounded-t-md px-3 py-2 text-xs font-semibold outline-none transition focus-visible:ring-2 focus-visible:ring-sky-400 ${tab === t.id ? 'border-b-2 border-sky-500 text-slate-100' : 'text-slate-500 hover:text-slate-300'}`}
            >
              <t.Icon className="h-3.5 w-3.5" />{t.label}
            </button>
          ))}
        </div>
        <div className="min-h-0 flex-1 overflow-auto p-4">
          {tab === 'passive' && <PassiveTab />}
          {tab === 'schedules' && <SchedulesTab />}
          {tab === 'campaign' && <CampaignTab />}
        </div>
      </div>
    </div>
  );
}

/** Owns the Operations modal; opens on the `eg:open-operations` event. */
function OperationsLayer() {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const openEvt = () => setOpen(true);
    window.addEventListener('eg:open-operations', openEvt);
    return () => window.removeEventListener('eg:open-operations', openEvt);
  }, []);
  return open ? <OperationsPanel onClose={() => setOpen(false)} /> : null;
}

/**
 * Fires action-feedback toasts on meaningful scan-state transitions. Renders
 * nothing — a pure watcher, so scan state stays a plain data concern.
 */
function ScanToasts() {
  const { phase, scanId, target, hosts, statusMessage } = useScan();
  const { toast } = useToast();
  const prev = useRef(null);
  useEffect(() => {
    // First run: adopt current state as the baseline so a scan restored from
    // localStorage on page load doesn't fire spurious "started/complete" toasts.
    if (prev.current === null) {
      prev.current = { phase, scanId };
      return;
    }
    const p = prev.current;
    if (scanId && scanId !== p.scanId) {
      toast(`Scanning ${target}…`, { type: 'info', title: 'Scan started', id: 'eg-scan-status' });
    }
    if (phase !== p.phase) {
      if (phase === ScanPhase.COMPLETE) {
        const up = hosts.filter((h) => h.status === HostStatus.UP).length;
        const openPorts = hosts.reduce((n, h) => n + countOpenPorts(h), 0);
        toast(`${up} host${up === 1 ? '' : 's'} up · ${openPorts} open port${openPorts === 1 ? '' : 's'}`, {
          type: 'success', title: 'Scan complete', id: 'eg-scan-status',
        });
      } else if (phase === ScanPhase.HALTED) {
        toast('Scan stopped.', { type: 'warn', id: 'eg-scan-status' });
      } else if (phase === ScanPhase.ERROR) {
        toast(statusMessage || 'The scan failed — check the backend and target.', {
          type: 'error', title: 'Scan error', id: 'eg-scan-status',
        });
      }
    }
    prev.current = { phase, scanId };
  }, [phase, scanId, target, hosts, statusMessage, toast]);
  return null;
}

export default function IndustrialDashboard() {
  const { hosts, phase } = useScan();
  const { toast } = useToast();
  const [view, setView] = useState('table'); // matrix | topology (shared with toolbar)
  const [navOpen, setNavOpen] = useState(false);
  const [booting, setBooting] = useState(
    () => typeof sessionStorage === 'undefined' || !sessionStorage.getItem('eg_booted'),
  );
  const finishBoot = useCallback(() => {
    try { sessionStorage.setItem('eg_booted', '1'); } catch { /* private mode */ }
    setBooting(false);
  }, []);

  useEffect(() => {
    document.title = phase === ScanPhase.IDLE ? 'ENUMGRID: the Enumeration Platform' : `ENUMGRID // ${PHASE_META[phase]?.short || phase}`;
  }, [phase]);

  // First-ever visit: point the operator at the command palette + shortcuts, once.
  // localStorage (set when it fires) is the idempotency guard — no ref guard, so
  // React StrictMode's mount→unmount→remount still leaves exactly one live timer.
  useEffect(() => {
    if (typeof localStorage === 'undefined' || localStorage.getItem('eg_welcomed')) return undefined;
    const timer = setTimeout(() => {
      toast('Press ⌘K for the command palette · ? for all keyboard shortcuts.', {
        type: 'info', title: 'Welcome to ENUMGRID', duration: 9000,
      });
      try { localStorage.setItem('eg_welcomed', '1'); } catch { /* private mode */ }
    }, 2800); // after the boot splash
    return () => clearTimeout(timer);
  }, [toast]);

  return (
    <div className="relative flex h-screen overflow-hidden text-slate-200">
      <ScanToasts />
      <ShortcutsLayer />
      <OperationsLayer />
      <CopilotLayer />
      <CommandPalette />
      <div className="eg-aurora" />
      {booting && <BootSplash onDone={finishBoot} />}
      <Sidebar mobileOpen={navOpen} onClose={() => setNavOpen(false)} />
      <div className="relative z-10 flex min-h-0 min-w-0 flex-1 flex-col">
        <CommandBar onOpenNav={() => setNavOpen(true)} />
        <DriftAlertBanner />
        <ScanErrorBanner />
        <main className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
          <KpiStrip />
          <ScanConfigPanel />
          <AssetMatrix hosts={hosts} view={view} setView={setView} />
        </main>
      </div>
    </div>
  );
}
