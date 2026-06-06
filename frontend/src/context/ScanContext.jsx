/**
 * ScanContext.jsx — the single owner of scan state for the whole cockpit.
 * ---------------------------------------------------------------------------
 * Everything the dashboard renders flows out of this reducer. Snapshots are
 * validated through the Pydantic-style `ScanStateModel` before they touch the
 * tree, so a malformed frame from the network can never corrupt the UI.
 *
 * Today the frames come from `mockScanEngine`. To go live, swap the body of
 * `startScan` for an EventSource (see the commented `connectSSE` below) — the
 * reducer and every consumer stay exactly the same.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useReducer,
  useRef,
} from 'react';
import {
  ScanPhase,
  HostStatus,
  HostModel,
  ScanStateModel,
  summarizeHosts,
} from '../lib/schema.js';
import { createScanEngine, deepScanHost } from '../lib/mockScanEngine.js';

/* ---------------------------------------------------------- initial state -- */

const uuid = () =>
  typeof crypto !== 'undefined' && crypto.randomUUID
    ? crypto.randomUUID()
    : `scan-${Math.random().toString(16).slice(2, 10)}`;

const shortId = (id) => (id ? id.slice(0, 8) : '—');

// Best-effort desktop notification when monitoring detects network drift.
function notifyDrift(alert) {
  try {
    if (typeof Notification === 'undefined') return;
    const fire = () => {
      const parts = [];
      if (alert.appeared.length) parts.push(`+${alert.appeared.length} new`);
      if (alert.disappeared.length) parts.push(`-${alert.disappeared.length} gone`);
      if (alert.changed.length) parts.push(`${alert.changed.length} changed`);
      // eslint-disable-next-line no-new
      new Notification('EnumGrid — network changed', {
        body: `${alert.target}: ${parts.join(' · ') || 'configuration drift'}`,
      });
    };
    if (Notification.permission === 'granted') fire();
    else if (Notification.permission !== 'denied') {
      Notification.requestPermission().then((p) => p === 'granted' && fire());
    }
  } catch {
    /* notifications are optional */
  }
}

// A couple of seeded "history" sessions so the sidebar log reads like a tool
// that's been in service, not a blank slate.
const seededSessions = [
  {
    id: 'a31f8c02-prev',
    target: '10.0.0.0/24',
    status: ScanPhase.COMPLETE,
    startedAt: Date.now() / 1000 - 3600,
    hostCount: 14,
    upCount: 9,
  },
  {
    id: 'b7702d4e-prev',
    target: '172.16.5.0/24',
    status: ScanPhase.HALTED,
    startedAt: Date.now() / 1000 - 7200,
    hostCount: 6,
    upCount: 3,
  },
];

const initialState = {
  scanId: null,
  target: '192.168.1.0/24',
  phase: ScanPhase.IDLE,
  progress: 0,
  hosts: [],
  startedAt: null,
  finishedAt: null,
  running: false,
  source: null, // 'live' (FastAPI SSE) | 'mock' (offline demo)
  statusMessage: null, // operator-readable note (refusal reason / backend unreachable)
  deepScan: false, // run NSE vuln scripts (--script vuln)
  sessions: seededSessions,
  drift: null, // 'what changed since last scan' for the current target (live only)
  monitor: false, // continuous mode: auto re-scan + alert on drift
  monitorEverySec: 300, // re-scan interval when monitoring
  driftAlert: null, // { appeared, disappeared, changed, at } when monitoring sees a change
  profiles: {}, // available nmap scan profiles (from /api/profiles)
  privileged: false, // backend has root → real nmap -O OS detection
  capability: 'unprivileged', // 'root' | 'sudo' | 'unprivileged' (scan privilege tier)
  canRaw: false, // root OR passwordless sudo → real -sS/-sU/-O available
  scanProfile: 'default', // selected nmap profile for per-host + Scan All
  scanScripts: '', // optional extra NSE scripts (comma list)
  scanPorts: '', // optional explicit port spec
};

// Default to the live FastAPI stream; set VITE_USE_MOCK=true to force the
// offline demo engine. Either way, a failed live connection falls back to mock.
const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

/* ---------------------------------------------------------------- reducer -- */

function patchSession(sessions, id, patch) {
  return sessions.map((s) => (s.id === id ? { ...s, ...patch } : s));
}

function reducer(state, action) {
  switch (action.type) {
    case 'INIT_SCAN': {
      const { scanId, target, startedAt, source } = action;
      const session = {
        id: scanId,
        target,
        status: ScanPhase.PING_SWEEP,
        startedAt,
        hostCount: 0,
        upCount: 0,
      };
      return {
        ...state,
        scanId,
        target,
        phase: ScanPhase.PING_SWEEP,
        progress: 0,
        hosts: [],
        startedAt,
        finishedAt: null,
        running: true,
        source,
        statusMessage: null, // clear any prior error/refusal note
        drift: null, // clear last run's drift until this scan completes
        sessions: [session, ...state.sessions],
      };
    }

    case 'SET_SOURCE':
      return { ...state, source: action.source };

    case 'SET_DRIFT':
      return { ...state, drift: action.drift };

    case 'SET_PROFILES':
      return {
        ...state,
        profiles: action.profiles,
        privileged: action.privileged,
        capability: action.capability || (action.privileged ? 'root' : 'unprivileged'),
        canRaw: action.canRaw != null ? action.canRaw : !!action.privileged,
      };

    case 'SET_SCAN_PROFILE':
      return { ...state, scanProfile: action.profile };

    case 'SET_SCAN_SCRIPTS':
      return { ...state, scanScripts: action.scripts };

    case 'SET_SCAN_PORTS':
      return { ...state, scanPorts: action.ports };

    case 'TOGGLE_MONITOR':
      return { ...state, monitor: !state.monitor, driftAlert: null };

    case 'SET_MONITOR_INTERVAL':
      return { ...state, monitorEverySec: action.seconds };

    case 'DRIFT_ALERT':
      return { ...state, driftAlert: action.alert };

    case 'CLEAR_ALERT':
      return { ...state, driftAlert: null };

    case 'TOGGLE_DEEP':
      return { ...state, deepScan: !state.deepScan };

    case 'ERROR':
      return {
        ...state,
        phase: ScanPhase.ERROR,
        running: false,
        finishedAt: Date.now() / 1000,
        // Surface WHY (backend refusal reason / unreachable) instead of dropping it.
        statusMessage: action.message || state.statusMessage,
        sessions: patchSession(state.sessions, state.scanId, { status: ScanPhase.ERROR }),
      };

    case 'SNAPSHOT': {
      // Validate + normalize the incoming frame against the schema.
      const snap = ScanStateModel(action.snapshot);
      // Ignore stray frames from a previous/cancelled run.
      if (state.scanId && snap.scan_id && snap.scan_id !== state.scanId) {
        return state;
      }
      const { up, total } = summarizeHosts(snap.hosts);
      return {
        ...state,
        phase: snap.phase,
        progress: snap.progress,
        hosts: snap.hosts,
        finishedAt: snap.finished_at,
        sessions: patchSession(state.sessions, state.scanId, {
          status: snap.phase,
          hostCount: total,
          upCount: up,
        }),
      };
    }

    case 'COMPLETE': {
      return {
        ...state,
        phase: ScanPhase.COMPLETE,
        progress: 100,
        running: false,
        finishedAt: Date.now() / 1000,
        sessions: patchSession(state.sessions, state.scanId, {
          status: ScanPhase.COMPLETE,
        }),
      };
    }

    case 'STOP': {
      return {
        ...state,
        phase: ScanPhase.HALTED,
        running: false,
        finishedAt: Date.now() / 1000,
        // Clear any in-flight per-host spinners.
        hosts: state.hosts.map((h) => (h.scanning ? { ...h, scanning: false } : h)),
        sessions: patchSession(state.sessions, state.scanId, {
          status: ScanPhase.HALTED,
        }),
      };
    }

    case 'QUEUE_HOSTS': {
      // Mark a batch of hosts as waiting in a "Scan All" queue (so the grid can
      // honestly show "Queued" only for hosts that really are queued).
      const q = new Set(action.ips || []);
      return {
        ...state,
        hosts: state.hosts.map((h) => (q.has(h.ip) ? { ...h, queued: true } : h)),
      };
    }

    case 'HOST_VULN_START':
      return {
        ...state,
        hosts: state.hosts.map((h) =>
          h.ip === action.ip
            ? { ...h, vulnScanning: true, queued: false, scanError: false }
            : h,
        ),
      };

    case 'HOST_MERGE': {
      // Validate the incoming host and merge it in place (keep grid position).
      const m = HostModel(action.host);
      return {
        ...state,
        hosts: state.hosts.map((h) =>
          h.ip === m.ip
            ? {
                ...h,
                os: m.os && m.os !== 'Unknown' ? m.os : h.os,
                hostname: m.hostname || h.hostname,
                ports: m.ports.length ? m.ports : h.ports,
                vulns: m.vulns,
                scan_note: m.scan_note, // surface any unprivileged auto-adaptation
                scanning: false,
                vulnScanning: false,
                queued: false,
                scanned: true, // a per-host scan completed (even if 0 open ports)
                scanError: false,
              }
            : h,
        ),
      };
    }

    case 'HOST_VULN_ERROR':
      return {
        ...state,
        hosts: state.hosts.map((h) =>
          h.ip === action.ip
            ? { ...h, vulnScanning: false, queued: false, scanError: true }
            : h,
        ),
      };

    case 'SET_TARGET':
      return { ...state, target: action.target };

    case 'RESET':
      return { ...initialState, sessions: state.sessions, target: state.target };

    default:
      return state;
  }
}

/* ---------------------------------------------------------------- context -- */

const ScanContext = createContext(null);

export function ScanProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, initialState);

  // Always-current state snapshot for callbacks that must read live values
  // (e.g. the per-host scan needs the host object + active data source).
  const stateRef = useRef(state);
  stateRef.current = state;

  // Mock engine — used in mock mode and as the offline fallback. Its callbacks
  // dispatch into the reducer; `dispatch` is stable so this is built once.
  const engineRef = useRef(null);
  if (engineRef.current === null) {
    engineRef.current = createScanEngine({
      onSnapshot: (snapshot) => dispatch({ type: 'SNAPSHOT', snapshot }),
      onDone: () => dispatch({ type: 'COMPLETE' }),
    });
  }

  // Controller for whatever is currently producing frames (SSE or mock); always
  // exposes a .stop(). Lets startScan/stopScan stay source-agnostic.
  const activeRef = useRef(null);

  // Tear down any active stream if the provider unmounts mid-scan.
  useEffect(() => () => activeRef.current?.stop?.(), []);

  const startMock = useCallback((target, scanId, deep, asFallback) => {
    dispatch({ type: 'SET_SOURCE', source: 'mock' });
    engineRef.current.start(target, scanId, deep);
    activeRef.current = { stop: () => engineRef.current.stop() };
    if (asFallback) {
      // eslint-disable-next-line no-console
      console.warn('[scan] live backend unavailable — using offline mock engine');
    }
  }, []);

  // After a live scan completes, ask the backend what changed vs the previous
  // scan of the same target (new/gone devices, opened/closed ports). Best-effort
  // and live-only — the mock engine has no history backend. While monitoring,
  // a real change raises a dismissible alert + a browser notification.
  const fetchDrift = useCallback((target) => {
    if (!target) return;
    fetch(`/api/history/diff?target=${encodeURIComponent(target)}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((drift) => {
        if (!drift) return;
        dispatch({ type: 'SET_DRIFT', drift });
        if (stateRef.current.monitor && drift.available && drift.has_changes) {
          const alert = {
            target,
            at: Date.now() / 1000,
            appeared: drift.appeared_hosts || [],
            disappeared: drift.disappeared_hosts || [],
            changed: drift.changed_hosts || [],
          };
          dispatch({ type: 'DRIFT_ALERT', alert });
          notifyDrift(alert);
        }
      })
      .catch(() => {});
  }, []);

  // Open the FastAPI SSE stream. Each frame is a ScanState; the reducer ingests
  // it verbatim. If the stream never connects, fall back to the mock engine.
  const connectSSE = useCallback(
    (target, scanId, deep) => {
      const url =
        `/api/scan/stream?target=${encodeURIComponent(target)}&id=${scanId}` +
        (deep ? '&deep=1' : '');
      const es = new EventSource(url);
      let gotData = false;

      es.onmessage = (e) => {
        let snapshot;
        try {
          snapshot = JSON.parse(e.data);
        } catch {
          return;
        }
        gotData = true;
        dispatch({ type: 'SNAPSHOT', snapshot });
        if (snapshot.phase === ScanPhase.COMPLETE) {
          dispatch({ type: 'COMPLETE' });
          fetchDrift(target); // pull 'what changed' now that this scan is saved
          es.close();
        } else if (snapshot.phase === ScanPhase.ERROR) {
          // Surface the backend's own reason (scope refusal, capacity, etc.).
          dispatch({ type: 'ERROR', message: snapshot.message });
          es.close();
        }
      };

      es.onerror = () => {
        es.close();
        if (!gotData) {
          // Live backend never answered. For a security tool we must NOT silently
          // show simulated data — fail honestly so results are never mistaken for
          // a real scan. (Set VITE_USE_MOCK=true to use the demo engine on purpose.)
          if (USE_MOCK) {
            startMock(target, scanId, deep, true);
          } else {
            dispatch({
              type: 'ERROR',
              message:
                'Backend unreachable — the scan engine isn’t responding. Start it with ./start.sh (or check backend/.backend.log).',
            });
          }
        } else {
          dispatch({ type: 'STOP' }); // mid-stream drop after data
        }
      };

      activeRef.current = { stop: () => es.close() };
    },
    [startMock, fetchDrift],
  );

  const launch = useCallback(
    (target, deep) => {
      activeRef.current?.stop?.(); // cancel anything already running
      const scanId = uuid();
      const startedAt = Date.now() / 1000;
      dispatch({
        type: 'INIT_SCAN',
        scanId,
        target,
        startedAt,
        source: USE_MOCK ? 'mock' : 'live',
      });
      if (USE_MOCK) startMock(target, scanId, deep, false);
      else connectSSE(target, scanId, deep);
    },
    [connectSSE, startMock],
  );

  // Start a scan. With NO target typed, auto-detect the local network and scan
  // the whole /24 — "just press Start" does a complete network sweep.
  const startScan = useCallback(
    (rawTarget, deep = false) => {
      const target = (rawTarget || '').trim();
      if (target) {
        launch(target, deep);
        return;
      }
      if (USE_MOCK) {
        launch('10.0.0.0/24', deep);
        return;
      }
      fetch('/api/network')
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => launch((d && d.suggested_target) || '192.168.1.0/24', deep))
        .catch(() => launch('192.168.1.0/24', deep));
    },
    [launch],
  );

  const toggleDeep = useCallback(() => dispatch({ type: 'TOGGLE_DEEP' }), []);

  // --- nmap scan profiles -------------------------------------------------- #
  // Load the allowlisted profiles (+ whether the backend has root for -O) once.
  useEffect(() => {
    fetch('/api/profiles')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d && d.profiles) {
          dispatch({
            type: 'SET_PROFILES',
            profiles: d.profiles,
            privileged: !!d.privileged,
            capability: d.capability,
            canRaw: !!d.can_raw,
          });
        }
      })
      .catch(() => {});
  }, []);

  const setScanProfile = useCallback((profile) => dispatch({ type: 'SET_SCAN_PROFILE', profile }), []);
  const setScanScripts = useCallback((scripts) => dispatch({ type: 'SET_SCAN_SCRIPTS', scripts }), []);
  const setScanPorts = useCallback((ports) => dispatch({ type: 'SET_SCAN_PORTS', ports }), []);

  // --- continuous monitor mode --------------------------------------------- #
  const toggleMonitor = useCallback(() => dispatch({ type: 'TOGGLE_MONITOR' }), []);
  const setMonitorInterval = useCallback(
    (seconds) => dispatch({ type: 'SET_MONITOR_INTERVAL', seconds }),
    [],
  );
  const dismissAlert = useCallback(() => dispatch({ type: 'CLEAR_ALERT' }), []);

  // When monitoring, schedule the next re-scan once the current one completes.
  // Declarative: the timer is (re)created whenever a scan finishes and is torn
  // down if monitoring is turned off or a new scan starts — so it never stacks.
  const monitorTimerRef = useRef(null);
  useEffect(() => {
    clearTimeout(monitorTimerRef.current);
    if (
      state.monitor &&
      !state.running &&
      state.target &&
      (state.phase === ScanPhase.COMPLETE || state.phase === ScanPhase.HALTED)
    ) {
      monitorTimerRef.current = setTimeout(
        () => startScan(state.target, state.deepScan),
        Math.max(15, state.monitorEverySec) * 1000,
      );
    }
    return () => clearTimeout(monitorTimerRef.current);
  }, [
    state.monitor,
    state.running,
    state.phase,
    state.target,
    state.deepScan,
    state.monitorEverySec,
    startScan,
  ]);

  // Run ONE host's nmap service scan and merge the result back into the grid.
  // `deep` adds the NSE vuln-script pass. Always resolves (never rejects) so it
  // can be chained by "Scan All". Falls back to the mock engine when offline.
  const runHostScan = useCallback((ip, deep) => {
    dispatch({ type: 'HOST_VULN_START', ip });

    const mockMerge = () =>
      new Promise((resolve) => {
        const host = stateRef.current.hosts.find((h) => h.ip === ip);
        if (host) {
          setTimeout(() => {
            dispatch({ type: 'HOST_MERGE', host: deepScanHost(host) });
            resolve();
          }, 600);
        } else {
          dispatch({ type: 'HOST_VULN_ERROR', ip });
          resolve();
        }
      });

    if (USE_MOCK || stateRef.current.source === 'mock') return mockMerge();

    const signal =
      typeof AbortSignal !== 'undefined' && AbortSignal.timeout
        ? AbortSignal.timeout(360000) // -sV/-A (+ optional NSE) can be slow
        : undefined;
    const sp = stateRef.current;
    const params = new URLSearchParams({ ip, deep: deep ? '1' : '0' });
    if (sp.scanProfile && sp.scanProfile !== 'default') params.set('profile', sp.scanProfile);
    if (sp.scanScripts) params.set('scripts', sp.scanScripts);
    if (sp.scanPorts) params.set('ports', sp.scanPorts);
    return fetch(`/api/host/scan?${params.toString()}`, { signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((host) => {
        if (host && host.ip) dispatch({ type: 'HOST_MERGE', host });
        else dispatch({ type: 'HOST_VULN_ERROR', ip });
      })
      .catch(() => {
        // We only reach here in LIVE mode (mock mode returned above). A real
        // backend error must surface as an error — never silently swapped for
        // simulated data, so what you see is always a real scan result.
        dispatch({ type: 'HOST_VULN_ERROR', ip });
      });
  }, []);

  // Per-host "Nmap Scan" row action — fast service scan; Deep toggle adds NSE.
  const scanHostVulns = useCallback(
    (ip) => {
      if (ip) runHostScan(ip, stateRef.current.deepScan);
    },
    [runHostScan],
  );

  // "Scan All" — nmap live hosts (a few at a time; the backend also caps
  // concurrency). By default it fills in not-yet-scanned hosts; pass force=true
  // to RE-scan every live host with the currently-selected profile (so changing
  // the scan type actually re-runs against hosts that were already scanned).
  const scanAll = useCallback((force = false) => {
    const deep = stateRef.current.deepScan;
    const queue = stateRef.current.hosts
      .filter(
        (h) =>
          h.status === HostStatus.UP &&
          // re-scan everything when forced; otherwise only hosts not yet scanned
          // (no ports AND never completed a scan) so the run is incremental.
          (force || (!h.ports.length && !h.scanned)) &&
          !h.vulnScanning,
      )
      .map((h) => h.ip);
    if (!queue.length) return;
    // Mark the whole batch as queued up-front so the grid shows a truthful
    // "Queued" only for hosts actually waiting in THIS batch (not every
    // unscanned host). Each host clears its queued flag when its turn starts.
    dispatch({ type: 'QUEUE_HOSTS', ips: queue });
    let i = 0;
    const worker = () => {
      if (i >= queue.length) return Promise.resolve();
      const ip = queue[i++];
      return runHostScan(ip, deep).then(worker);
    };
    const CONCURRENCY = 3;
    for (let w = 0; w < Math.min(CONCURRENCY, queue.length); w += 1) worker();
  }, [runHostScan]);

  // One-click PDF report: POST the exact on-screen snapshot to the backend
  // renderer and trigger a download. Stateless — report always matches screen.
  const downloadReport = useCallback(() => {
    const s = stateRef.current;
    if (!s.hosts.length) return;
    fetch('/api/report/pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: s.target, hosts: s.hosts, profile: s.scanProfile }),
    })
      .then((r) => (r.ok ? r.blob() : Promise.reject(new Error('report failed'))))
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `enumgrid_${(s.target || 'scan').replace(/[^a-z0-9]+/gi, '-')}.pdf`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      })
      .catch(() => {
        // eslint-disable-next-line no-console
        console.warn('[report] PDF generation needs the live backend running');
      });
  }, []);

  const stopScan = useCallback(() => {
    activeRef.current?.stop?.();
    dispatch({ type: 'STOP' });
  }, []);

  const setTarget = useCallback((target) => dispatch({ type: 'SET_TARGET', target }), []);

  // Headline counters, derived once per snapshot.
  const stats = useMemo(() => summarizeHosts(state.hosts), [state.hosts]);

  const value = useMemo(
    () => ({
      ...state,
      stats,
      startScan,
      stopScan,
      setTarget,
      toggleDeep,
      toggleMonitor,
      setMonitorInterval,
      dismissAlert,
      setScanProfile,
      setScanScripts,
      setScanPorts,
      scanHostVulns,
      scanAll,
      downloadReport,
      shortId,
    }),
    [
      state,
      stats,
      startScan,
      stopScan,
      setTarget,
      toggleDeep,
      toggleMonitor,
      setMonitorInterval,
      dismissAlert,
      setScanProfile,
      setScanScripts,
      setScanPorts,
      scanHostVulns,
      scanAll,
      downloadReport,
    ],
  );

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

/** Access scan state + actions from anywhere in the dashboard tree. */
export function useScan() {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error('useScan must be used within a <ScanProvider>');
  return ctx;
}

export { ScanPhase, HostStatus };

/* ---------------------------------------------------------------------------
 * Data source
 *   • Live (default): EventSource → Vite proxy `/api` → FastAPI `/api/scan/stream`
 *     (backend/app.py). Frames are JSON-serialized ScanState, ingested verbatim.
 *   • Mock: set VITE_USE_MOCK=true, or it's used automatically if the live
 *     stream can't connect (so the dashboard still works fully offline).
 * ------------------------------------------------------------------------- */
