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
  deepScan: false, // run NSE vuln scripts (--script vuln)
  sessions: seededSessions,
  drift: null, // 'what changed since last scan' for the current target (live only)
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
        drift: null, // clear last run's drift until this scan completes
        sessions: [session, ...state.sessions],
      };
    }

    case 'SET_SOURCE':
      return { ...state, source: action.source };

    case 'SET_DRIFT':
      return { ...state, drift: action.drift };

    case 'TOGGLE_DEEP':
      return { ...state, deepScan: !state.deepScan };

    case 'ERROR':
      return {
        ...state,
        phase: ScanPhase.ERROR,
        running: false,
        finishedAt: Date.now() / 1000,
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

    case 'HOST_VULN_START':
      return {
        ...state,
        hosts: state.hosts.map((h) => (h.ip === action.ip ? { ...h, vulnScanning: true } : h)),
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
                scanning: false,
                vulnScanning: false,
              }
            : h,
        ),
      };
    }

    case 'HOST_VULN_ERROR':
      return {
        ...state,
        hosts: state.hosts.map((h) => (h.ip === action.ip ? { ...h, vulnScanning: false } : h)),
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
  // and live-only — the mock engine has no history backend.
  const fetchDrift = useCallback((target) => {
    if (!target) return;
    fetch(`/api/history/diff?target=${encodeURIComponent(target)}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((drift) => {
        if (drift) dispatch({ type: 'SET_DRIFT', drift });
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
          dispatch({ type: 'ERROR' });
          es.close();
        }
      };

      es.onerror = () => {
        es.close();
        if (!gotData) startMock(target, scanId, deep, true); // never connected → fallback
        else dispatch({ type: 'STOP' }); // mid-stream drop after data
      };

      activeRef.current = { stop: () => es.close() };
    },
    [startMock, fetchDrift],
  );

  const startScan = useCallback(
    (rawTarget, deep = false) => {
      const target = (rawTarget || '').trim();
      if (!target) return;
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

  const toggleDeep = useCallback(() => dispatch({ type: 'TOGGLE_DEEP' }), []);

  // Per-host deep scan ("Scan Vulns" row action). Scans just this host and
  // merges its vulns back into the grid without disturbing the others.
  const scanHostVulns = useCallback((ip) => {
    if (!ip) return;
    dispatch({ type: 'HOST_VULN_START', ip });

    const mockMerge = () => {
      const host = stateRef.current.hosts.find((h) => h.ip === ip);
      if (host) {
        setTimeout(() => dispatch({ type: 'HOST_MERGE', host: deepScanHost(host) }), 700);
      } else {
        dispatch({ type: 'HOST_VULN_ERROR', ip });
      }
    };

    // Offline / mock data source → skip the network and simulate locally.
    if (USE_MOCK || stateRef.current.source === 'mock') {
      mockMerge();
      return;
    }

    const signal =
      typeof AbortSignal !== 'undefined' && AbortSignal.timeout
        ? AbortSignal.timeout(150000) // NSE scripts are slow; allow generous time
        : undefined;
    fetch(`/api/host/scan?ip=${encodeURIComponent(ip)}&deep=1`, { signal })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((host) => {
        if (host && host.ip) dispatch({ type: 'HOST_MERGE', host });
        else dispatch({ type: 'HOST_VULN_ERROR', ip });
      })
      .catch((e) => {
        // Connection refused (backend down) → offline mock; timeout → give up.
        if (e && e.name === 'AbortError') dispatch({ type: 'HOST_VULN_ERROR', ip });
        else mockMerge();
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
      scanHostVulns,
      shortId,
    }),
    [state, stats, startScan, stopScan, setTarget, toggleDeep, scanHostVulns],
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
