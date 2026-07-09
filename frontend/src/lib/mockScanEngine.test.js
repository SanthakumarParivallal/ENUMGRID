/**
 * mockScanEngine.test.js — the offline stand-in that streams ScanState
 * snapshots to the cockpit until the live backend is wired in.
 *
 * The generator is intentionally random, so the tests drive it through a
 * **fixed-seed** PRNG: real generation code runs, but the "random" stream is
 * fully reproducible (a deterministic battery of scenarios, not fuzzing — so
 * coverage never flakes). A handful of targeted cases pin the control-flow
 * branches (target parsing, mid-run stop, no onDone) that the battery doesn't
 * deterministically force.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createScanEngine, deepScanHost } from './mockScanEngine.js';
import { PortState, HostStatus, ScanPhase, Protocol } from './schema.js';

// mulberry32 — a tiny, deterministic PRNG. Same seed → same stream, every run.
function seeded(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Run one engine.start() to completion under fake timers; collect snapshots. */
function runToCompletion({ target = '192.168.1.0/24', scanId = 's1', deep = false, tickMs = 5, onDone } = {}) {
  const snapshots = [];
  let doneCount = 0;
  const engine = createScanEngine({
    onSnapshot: (s) => snapshots.push(s),
    onDone: onDone === null ? undefined : (onDone || (() => { doneCount += 1; })),
    tickMs,
  });
  engine.start(target, scanId, deep);
  vi.runAllTimers(); // drain the self-rescheduling setTimeout chain to completion
  return { snapshots, doneCount, engine, final: snapshots[snapshots.length - 1] };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  vi.runOnlyPendingTimers();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('deepScanHost', () => {
  it('attaches sample vulns to open ports with a known CVE and marks them critical', () => {
    const host = {
      ip: '10.0.0.1',
      ports: [
        { port: 445, state: PortState.OPEN, critical: false },       // has SAMPLE_VULNS
        { port: 80, state: PortState.OPEN_FILTERED, critical: false }, // open|filtered still counts
        { port: 9999, state: PortState.OPEN, critical: false },      // no sample vulns
        { port: 23, state: PortState.FILTERED, critical: false },    // closed-ish → skipped
      ],
    };
    const out = deepScanHost(host);
    expect(out.scanning).toBe(false);
    expect(out.vulnScanning).toBe(false);
    const byPort = Object.fromEntries(out.ports.map((p) => [p.port, p]));
    expect(byPort[445].vulns).toHaveLength(1);
    expect(byPort[445].critical).toBe(true); // severe vuln → critical
    expect(byPort[80].vulns.length).toBeGreaterThan(0); // open|filtered gets vulns too
    expect(byPort[9999].vulns).toEqual([]); // no catalogue entry
    expect(byPort[23].vulns).toEqual([]); // not open → no scan
  });

  it('preserves an already-critical flag and tolerates a host with no ports', () => {
    const out = deepScanHost({ ip: '10.0.0.2', ports: [{ port: 9999, state: PortState.OPEN, critical: true }] });
    expect(out.ports[0].critical).toBe(true); // kept even without a vuln
    expect(deepScanHost({ ip: '10.0.0.3' }).ports).toEqual([]); // no ports → empty
  });
});

describe('createScanEngine — deterministic seed battery', () => {
  // A fixed set of seeds × depths. Between them they exercise every host
  // archetype, the reachability coin-flip, filtered ports, UDP services, the
  // legacy-telnet finding, null hostnames, and octet de-duplication. Fixed →
  // the exact same lines execute on every CI run.
  const seeds = [1, 2, 3, 5, 7, 9, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43];

  for (const seed of seeds) {
    for (const deep of [false, true]) {
      it(`completes a full pipeline (seed ${seed}, deep=${deep})`, () => {
        vi.spyOn(Math, 'random').mockImplementation(seeded(seed));
        const { snapshots, doneCount, final } = runToCompletion({ deep, scanId: `s-${seed}` });

        // Terminates at 100% Complete with a finished_at stamp, and calls onDone.
        expect(final.phase).toBe(ScanPhase.COMPLETE);
        expect(final.progress).toBe(100);
        expect(final.finished_at).toBeGreaterThan(0);
        expect(doneCount).toBe(1);

        // First frame is an empty Ping-Sweep grid; snapshots only grow.
        expect(snapshots[0].phase).toBe(ScanPhase.PING_SWEEP);
        expect(snapshots[0].hosts).toEqual([]);

        // Every host is well-formed; a "down" host never leaks ports/hostname.
        for (const h of final.hosts) {
          expect([HostStatus.UP, HostStatus.DOWN]).toContain(h.status);
          if (h.status === HostStatus.DOWN) {
            expect(h.hostname).toBeNull();
            expect(h.os).toBe('Unknown');
          }
        }
      });
    }
  }

  it('across the battery: covers up+down hosts, filtered+UDP ports, telnet, deep vulns, null hostnames', () => {
    const seen = {
      up: false, down: false, filtered: false, udp: false, telnet: false,
      deepVuln: false, nullHostname: false, namedHostname: false,
    };
    for (const seed of seeds) {
      vi.spyOn(Math, 'random').mockImplementation(seeded(seed));
      const { final } = runToCompletion({ deep: true, scanId: `agg-${seed}` });
      for (const h of final.hosts) {
        if (h.status === HostStatus.UP) {
          seen.up = true;
          seen.nullHostname ||= h.hostname === null;
          seen.namedHostname ||= typeof h.hostname === 'string';
          for (const p of h.ports) {
            seen.filtered ||= p.state === PortState.FILTERED;
            seen.udp ||= p.protocol === Protocol.UDP;
            seen.telnet ||= p.port === 23;
            seen.deepVuln ||= (p.vulns && p.vulns.length > 0);
          }
        } else {
          seen.down = true;
        }
      }
      vi.restoreAllMocks();
    }
    // Every branch of the generator is deterministically hit by the fixed battery.
    for (const [key, hit] of Object.entries(seen)) {
      expect(hit, `expected the seed battery to exercise "${key}"`).toBe(true);
    }
  });
});

describe('createScanEngine — targeted control flow', () => {
  it('parses common target syntaxes and falls back to 10.0.0. on gibberish', () => {
    vi.spyOn(Math, 'random').mockImplementation(seeded(4));
    const cidr = runToCompletion({ target: '172.16.2.0/24', scanId: 'c' });
    expect(cidr.final.hosts.every((h) => h.ip.startsWith('172.16.2.'))).toBe(true);

    vi.restoreAllMocks();
    vi.spyOn(Math, 'random').mockImplementation(seeded(4));
    const junk = runToCompletion({ target: 'not-an-ip-at-all', scanId: 'j' });
    expect(junk.final.hosts.every((h) => h.ip.startsWith('10.0.0.'))).toBe(true);
  });

  it('stops mid-run: no snapshots after stop, and onDone never fires', () => {
    vi.spyOn(Math, 'random').mockImplementation(seeded(6));
    const snapshots = [];
    let done = false;
    let stopped = false;
    const engine = createScanEngine({
      onSnapshot: (s) => {
        snapshots.push(s);
        // Cancel from inside a callback once a few hosts have appeared — this
        // is the path that reschedules once and then trips step()'s guard.
        if (!stopped && s.hosts.length >= 3) {
          stopped = true;
          engine.stop();
        }
      },
      onDone: () => { done = true; },
      tickMs: 5,
    });
    engine.start('192.168.1.0/24', 'stop-test');
    vi.runAllTimers();

    const countAtStop = snapshots.length;
    expect(stopped).toBe(true);
    expect(done).toBe(false); // completion never reached
    // Draining any residual timers yields no further snapshots.
    vi.runAllTimers();
    expect(snapshots.length).toBe(countAtStop);
    expect(snapshots[snapshots.length - 1].phase).not.toBe(ScanPhase.COMPLETE);
  });

  it('runs to completion without an onDone handler (no throw)', () => {
    vi.spyOn(Math, 'random').mockImplementation(seeded(8));
    const { final } = runToCompletion({ scanId: 'no-done', onDone: null });
    expect(final.phase).toBe(ScanPhase.COMPLETE);
  });

  it('stop() before start() is harmless and a subsequent start still completes', () => {
    vi.spyOn(Math, 'random').mockImplementation(seeded(10));
    const engine = createScanEngine({ onSnapshot: () => {}, onDone: () => {}, tickMs: 5 });
    expect(() => engine.stop()).not.toThrow(); // clear() with no active timer
    engine.start('10.1.2.0/24', 'restart');
    expect(() => vi.runAllTimers()).not.toThrow();
  });
});
