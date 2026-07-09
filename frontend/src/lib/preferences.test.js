/**
 * preferences.test.js — persisted cockpit view preferences (theme + column
 * widths). Covers the pure read/write/apply layer (via the public hook and
 * localStorage) and the resilience branches: missing / corrupt / unavailable
 * storage must never throw or lose the operator's other settings.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import {
  DEFAULTS,
  COL_DEFAULTS,
  COL_MIN,
  applyDocumentPrefs,
  usePreferences,
  colWidth,
} from './preferences.js';

const KEY = 'enumgrid_prefs_v1';
const store = (obj) => localStorage.setItem(KEY, JSON.stringify(obj));

beforeEach(() => localStorage.clear());
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  localStorage.clear();
});

describe('constants', () => {
  it('defaults to the dark cockpit with no column overrides', () => {
    expect(DEFAULTS.theme).toBe('dark');
    expect(DEFAULTS.colWidths).toEqual({});
    expect(COL_MIN).toBe(64);
    expect(Object.keys(COL_DEFAULTS)).toEqual(['hostname', 'vendor', 'device', 'mac']);
  });
});

describe('applyDocumentPrefs', () => {
  it('reflects the theme onto <html> (data-theme + color-scheme)', () => {
    applyDocumentPrefs({ theme: 'light' });
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(document.documentElement.style.colorScheme).toBe('light');
    applyDocumentPrefs({ theme: 'dark' });
    expect(document.documentElement.dataset.theme).toBe('dark');
  });

  it('is a no-op when there is no document (SSR / non-DOM host)', () => {
    vi.stubGlobal('document', undefined);
    expect(() => applyDocumentPrefs({ theme: 'light' })).not.toThrow();
  });
});

describe('colWidth', () => {
  it('returns a valid stored width, else the per-column default', () => {
    expect(colWidth({ hostname: 220 }, 'hostname')).toBe(220);
    expect(colWidth({}, 'vendor')).toBe(COL_DEFAULTS.vendor); // absent → default
    expect(colWidth(null, 'mac')).toBe(COL_DEFAULTS.mac); // no map → default
    expect(colWidth({ device: 10 }, 'device')).toBe(COL_DEFAULTS.device); // below COL_MIN → default
  });
});

describe('usePreferences — read() branches', () => {
  it('seeds from a stored light theme + column widths', () => {
    store({ theme: 'light', colWidths: { hostname: 200 } });
    const { result } = renderHook(() => usePreferences());
    expect(result.current.theme).toBe('light');
    expect(result.current.colWidths).toEqual({ hostname: 200 });
  });

  it('normalises an unknown theme to dark and a non-object colWidths to {}', () => {
    store({ theme: 'neon', colWidths: 42 });
    const { result } = renderHook(() => usePreferences());
    expect(result.current.theme).toBe('dark');
    expect(result.current.colWidths).toEqual({});
  });

  it('falls back to defaults when storage is empty', () => {
    const { result } = renderHook(() => usePreferences());
    expect(result.current.theme).toBe('dark');
    expect(result.current.colWidths).toEqual({});
  });

  it('treats a literal "null" JSON payload as empty (|| {})', () => {
    localStorage.setItem(KEY, 'null'); // JSON.parse → null
    const { result } = renderHook(() => usePreferences());
    expect(result.current.theme).toBe('dark');
  });

  it('recovers from corrupt JSON without throwing', () => {
    localStorage.setItem(KEY, '{not valid json');
    const { result } = renderHook(() => usePreferences());
    expect(result.current.theme).toBe('dark'); // caught → DEFAULTS
  });

  it('returns defaults when localStorage is unavailable', () => {
    vi.stubGlobal('localStorage', undefined);
    const { result } = renderHook(() => usePreferences());
    expect(result.current.theme).toBe('dark');
  });
});

describe('usePreferences — setters persist, apply and merge', () => {
  it('toggleTheme flips dark ↔ light and persists', () => {
    const { result } = renderHook(() => usePreferences());
    expect(result.current.theme).toBe('dark');
    act(() => result.current.toggleTheme());
    expect(result.current.theme).toBe('light');
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(JSON.parse(localStorage.getItem(KEY)).theme).toBe('light');
    act(() => result.current.toggleTheme());
    expect(result.current.theme).toBe('dark');
  });

  it('setColWidth clamps to COL_MIN, rounds, and preserves the theme', () => {
    store({ theme: 'light' });
    const { result } = renderHook(() => usePreferences());
    act(() => result.current.setColWidth('hostname', 12.7)); // below COL_MIN
    expect(result.current.colWidths.hostname).toBe(COL_MIN);
    act(() => result.current.setColWidth('vendor', 183.6)); // rounds
    expect(result.current.colWidths.vendor).toBe(184);
    expect(result.current.theme).toBe('light'); // untouched slice preserved
    expect(JSON.parse(localStorage.getItem(KEY)).colWidths.vendor).toBe(184);
  });

  it('resetColWidths clears overrides but keeps the theme', () => {
    const { result } = renderHook(() => usePreferences());
    act(() => result.current.setColWidth('mac', 300));
    act(() => result.current.toggleTheme()); // → light
    act(() => result.current.resetColWidths());
    expect(result.current.colWidths).toEqual({});
    expect(result.current.theme).toBe('light');
  });

  it('a write to a throwing localStorage is swallowed (state still updates)', () => {
    const { result } = renderHook(() => usePreferences());
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('quota exceeded');
    });
    expect(() => act(() => result.current.toggleTheme())).not.toThrow();
    expect(result.current.theme).toBe('light'); // in-memory + document still updated
  });

  it('commits cleanly when localStorage is unavailable (write is skipped)', () => {
    const { result } = renderHook(() => usePreferences());
    vi.stubGlobal('localStorage', undefined);
    expect(() => act(() => result.current.toggleTheme())).not.toThrow();
    expect(result.current.theme).toBe('light'); // applied to document + state, not persisted
    expect(document.documentElement.dataset.theme).toBe('light');
  });
});
