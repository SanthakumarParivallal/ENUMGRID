/**
 * preferences.js — small, persisted UI preferences for the cockpit.
 * ---------------------------------------------------------------------------
 * Two user-tunable view settings, stored in localStorage so they survive a
 * reload and applied to <html data-theme> so plain CSS (variables + attribute
 * selectors) does the styling — no React re-render needed for the visual
 * effect:
 *
 *   • theme     — 'dark' (default cockpit) | 'light' (paper)
 *   • colWidths — per-column pixel widths for the resizable matrix columns
 *
 * Spacing/density is no longer a toggle: the layout is responsive by default
 * (it tightens automatically on smaller viewports), so there's nothing for the
 * operator to tune. The module applies the persisted prefs at import time
 * (before first paint) so there's no flash of the wrong theme.
 */

import { useCallback, useState } from 'react';

const KEY = 'enumgrid_prefs_v1';

export const DEFAULTS = Object.freeze({
  theme: 'dark', // 'dark' | 'light'
  colWidths: {}, // { hostname, vendor, device, mac } -> px
});

/** Default pixel widths for the resizable matrix columns. */
export const COL_DEFAULTS = Object.freeze({
  hostname: 150,
  vendor: 150,
  device: 170,
  mac: 150,
});
export const COL_MIN = 64;

function read() {
  try {
    if (typeof localStorage === 'undefined') return { ...DEFAULTS };
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULTS };
    const p = JSON.parse(raw) || {};
    return {
      theme: p.theme === 'light' ? 'light' : 'dark',
      colWidths: p.colWidths && typeof p.colWidths === 'object' ? { ...p.colWidths } : {},
    };
  } catch {
    return { ...DEFAULTS };
  }
}

function write(prefs) {
  try {
    if (typeof localStorage !== 'undefined') localStorage.setItem(KEY, JSON.stringify(prefs));
  } catch {
    /* storage full / unavailable — non-fatal */
  }
}

/** Reflect theme onto <html> so CSS variables / selectors apply. */
export function applyDocumentPrefs(prefs) {
  if (typeof document === 'undefined') return;
  const el = document.documentElement;
  el.dataset.theme = prefs.theme;
  el.style.colorScheme = prefs.theme;
}

// Apply persisted prefs immediately on import (before first paint).
applyDocumentPrefs(read());

/**
 * React hook: persisted preferences + setters that also persist & apply to the
 * document. Multiple independent callers stay consistent because every commit
 * re-reads the freshest stored value before merging (so e.g. a theme toggle in
 * the header never clobbers column widths owned by the matrix).
 */
export function usePreferences() {
  const [prefs, setPrefs] = useState(read);

  const commit = useCallback((updater) => {
    const base = read(); // freshest persisted state across all hook instances
    const next = typeof updater === 'function' ? updater(base) : { ...base, ...updater };
    next.colWidths = { ...next.colWidths };
    write(next);
    applyDocumentPrefs(next);
    setPrefs(next);
  }, []);

  const toggleTheme = useCallback(
    () => commit((p) => ({ ...p, theme: p.theme === 'light' ? 'dark' : 'light' })),
    [commit],
  );
  const setColWidth = useCallback(
    (col, px) =>
      commit((p) => ({
        ...p,
        colWidths: { ...p.colWidths, [col]: Math.max(COL_MIN, Math.round(px)) },
      })),
    [commit],
  );
  const resetColWidths = useCallback(() => commit((p) => ({ ...p, colWidths: {} })), [commit]);

  return { ...prefs, toggleTheme, setColWidth, resetColWidths };
}

/** Resolve the effective width (px) for a resizable column. */
export function colWidth(colWidths, key) {
  const v = Number(colWidths?.[key]);
  return Number.isFinite(v) && v >= COL_MIN ? v : COL_DEFAULTS[key];
}
