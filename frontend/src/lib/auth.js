/**
 * auth.js — optional API-token support for the dashboard.
 * ---------------------------------------------------------------------------
 * The backend is unauthenticated by default (zero-config localhost dev). When an
 * operator enables RBAC (`ENUMGRID_ADMIN_TOKEN` / `ENUMGRID_VIEWER_TOKEN`), every
 * request must carry the token. This module is the single place that knows the
 * token and attaches it:
 *
 *   • normal `fetch` calls send `Authorization: Bearer <token>` (the recommended
 *     channel — keeps the secret out of URLs/logs);
 *   • the SSE stream (`EventSource`) cannot set headers, so its URL carries the
 *     token as a `?token=` query parameter (localhost only).
 *
 * The token is held in `localStorage` so it survives reloads. With no token set,
 * every helper is a transparent no-op, so the default experience is unchanged.
 */

import { useCallback, useState } from 'react';

const KEY = 'enumgrid_api_token_v1';

function read() {
  try {
    return (typeof localStorage !== 'undefined' && localStorage.getItem(KEY)) || '';
  } catch {
    return '';
  }
}

// Module-level cache so the non-React helpers (authHeaders/streamUrl) can read the
// current token synchronously, without prop-drilling through every fetch site.
let _token = read();

export function getToken() {
  return _token;
}

export function setToken(value) {
  _token = (value || '').trim();
  try {
    if (typeof localStorage === 'undefined') return;
    if (_token) localStorage.setItem(KEY, _token);
    else localStorage.removeItem(KEY);
  } catch {
    /* storage unavailable — token still works for this session */
  }
}

/** Merge `Authorization: Bearer …` into a headers object (no-op when unset). */
export function authHeaders(extra) {
  const h = { ...(extra || {}) };
  if (_token) h.Authorization = `Bearer ${_token}`;
  return h;
}

/** `fetch` wrapper that attaches the bearer token automatically. */
export function authFetch(url, opts = {}) {
  return fetch(url, { ...opts, headers: authHeaders(opts.headers) });
}

/** Append `?token=` for `EventSource` URLs (which can't carry headers). */
export function streamUrl(url) {
  if (!_token) return url;
  return url + (url.includes('?') ? '&' : '?') + `token=${encodeURIComponent(_token)}`;
}

/** React hook: current token + a setter that persists and re-renders. */
export function useApiToken() {
  const [token, setTok] = useState(read);
  const update = useCallback((value) => {
    setToken(value);
    setTok(getToken());
  }, []);
  return { token, hasToken: !!token, setToken: update };
}
