import { describe, it, expect } from 'vitest';
import { filterCommands, scoreCommand, isSubsequence } from './commandFilter.js';

const CMDS = [
  { id: 'start', label: 'Start scan', keywords: ['run', 'go'] },
  { id: 'stop', label: 'Stop scan' },
  { id: 'theme', label: 'Toggle theme', keywords: ['dark', 'light'] },
  { id: 'csv', label: 'Export CSV', keywords: ['download', 'inventory'] },
];

describe('isSubsequence', () => {
  it('matches in-order character subsequences', () => {
    expect(isSubsequence('stsc', 'start scan')).toBe(true);
    expect(isSubsequence('xyz', 'start scan')).toBe(false);
    expect(isSubsequence('', 'anything')).toBe(true);
  });
});

describe('scoreCommand', () => {
  it('ranks prefix > substring > keyword > fuzzy', () => {
    expect(scoreCommand({ label: 'Start scan' }, 'start')).toBe(100);
    expect(scoreCommand({ label: 'Toggle theme' }, 'theme')).toBe(60);
    expect(scoreCommand({ label: 'Export CSV', keywords: ['inventory'] }, 'inventory')).toBe(30);
    expect(scoreCommand({ label: 'Start scan' }, 'stsc')).toBe(10);
    expect(scoreCommand({ label: 'Start scan' }, 'zzz')).toBe(0);
  });

  it('scores an empty query as a neutral 1 (primitive has no early-out)', () => {
    // filterCommands short-circuits empty queries, but the primitive itself
    // must still return the neutral score for any direct caller.
    expect(scoreCommand({ label: 'Start scan' }, '')).toBe(1);
    expect(scoreCommand({}, '')).toBe(1); // no label / keywords either
  });
});

describe('filterCommands', () => {
  it('returns all commands (copy) for an empty query', () => {
    const out = filterCommands(CMDS, '');
    expect(out).toHaveLength(CMDS.length);
    expect(out).not.toBe(CMDS); // a copy, not the same array
  });

  it('finds by label and by keyword', () => {
    expect(filterCommands(CMDS, 'scan').map((c) => c.id)).toEqual(['start', 'stop']);
    expect(filterCommands(CMDS, 'inventory').map((c) => c.id)).toEqual(['csv']);
    expect(filterCommands(CMDS, 'dark').map((c) => c.id)).toEqual(['theme']);
  });

  it('is case-insensitive and drops non-matches', () => {
    expect(filterCommands(CMDS, 'EXPORT').map((c) => c.id)).toEqual(['csv']);
    expect(filterCommands(CMDS, 'nonsense')).toEqual([]);
  });

  it('orders prefix matches ahead of fuzzy matches', () => {
    const ids = filterCommands(CMDS, 'st').map((c) => c.id);
    // "Start scan" and "Stop scan" both prefix-match "st"; keep curated order.
    expect(ids.slice(0, 2)).toEqual(['start', 'stop']);
  });
});
