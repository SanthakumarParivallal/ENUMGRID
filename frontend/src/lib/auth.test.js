import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { getToken, setToken, authHeaders, authFetch, streamUrl, useApiToken } from './auth.js';

describe('auth token helpers', () => {
  beforeEach(() => setToken('')); // reset module state between tests

  it('round-trips the token in memory', () => {
    expect(getToken()).toBe('');
    setToken('  abc123  '); // trims
    expect(getToken()).toBe('abc123');
    setToken('');
    expect(getToken()).toBe('');
  });

  it('authHeaders attaches Bearer only when a token is set', () => {
    expect(authHeaders()).toEqual({});
    expect(authHeaders({ 'Content-Type': 'application/json' })).toEqual({
      'Content-Type': 'application/json',
    });
    setToken('secret');
    expect(authHeaders()).toEqual({ Authorization: 'Bearer secret' });
    expect(authHeaders({ 'Content-Type': 'application/json' })).toEqual({
      'Content-Type': 'application/json',
      Authorization: 'Bearer secret',
    });
  });

  it('streamUrl appends the token only when set, choosing ? or &', () => {
    expect(streamUrl('/api/scan/stream?target=x')).toBe('/api/scan/stream?target=x');
    setToken('tok en/+'); // includes chars that must be URL-encoded
    expect(streamUrl('/api/scan/stream?target=x')).toBe(
      '/api/scan/stream?target=x&token=tok%20en%2F%2B',
    );
    expect(streamUrl('/api/profiles')).toBe('/api/profiles?token=tok%20en%2F%2B');
  });

  it('does not mutate the caller-supplied headers object', () => {
    setToken('t');
    const base = { 'Content-Type': 'application/json' };
    const out = authHeaders(base);
    expect(out).not.toBe(base);
    expect(base).toEqual({ 'Content-Type': 'application/json' }); // unchanged
  });
});

const STORAGE_KEY = 'enumgrid_api_token_v1';

describe('token persistence (localStorage)', () => {
  beforeEach(() => {
    localStorage.clear();
    setToken('');
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    localStorage.clear();
    setToken('');
  });

  it('writes the token to storage and a fresh hook reads it back', () => {
    setToken('persisted-tok');
    expect(localStorage.getItem(STORAGE_KEY)).toBe('persisted-tok');
    const { result } = renderHook(() => useApiToken()); // seeds state from read()
    expect(result.current.token).toBe('persisted-tok');
    expect(result.current.hasToken).toBe(true);
  });

  it('removes the stored token when cleared', () => {
    setToken('x');
    setToken('');
    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('is best-effort: a throwing localStorage never breaks token handling', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('quota');
    });
    // Write path swallows the error; the token still works in-memory this session.
    expect(() => setToken('mem-only')).not.toThrow();
    expect(getToken()).toBe('mem-only');
    // Read path (via the hook's initial state) swallows and falls back to ''.
    const { result } = renderHook(() => useApiToken());
    expect(result.current.token).toBe('');
  });

  it('is a transparent no-op when localStorage is entirely unavailable', () => {
    vi.stubGlobal('localStorage', undefined);
    expect(() => setToken('no-storage')).not.toThrow();
    expect(getToken()).toBe('no-storage'); // in-memory cache still works
    const { result } = renderHook(() => useApiToken());
    expect(result.current.token).toBe(''); // read() returns '' with no storage
  });
});

describe('useApiToken hook', () => {
  beforeEach(() => {
    localStorage.clear();
    setToken('');
  });
  afterEach(() => {
    localStorage.clear();
    setToken('');
  });

  it('exposes the current token and updates + persists via its setter', () => {
    const { result } = renderHook(() => useApiToken());
    expect(result.current.token).toBe('');
    expect(result.current.hasToken).toBe(false);

    act(() => result.current.setToken('  live-token  '));
    expect(result.current.token).toBe('live-token'); // trimmed
    expect(result.current.hasToken).toBe(true);
    expect(getToken()).toBe('live-token'); // module cache updated too
    expect(localStorage.getItem(STORAGE_KEY)).toBe('live-token');
  });
});

describe('authFetch', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    setToken('');
  });

  it('delegates to fetch, merging the bearer header and preserving options', async () => {
    const fetchMock = vi.fn(() => Promise.resolve({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);
    setToken('fetch-tok');
    await authFetch('/api/scan', { method: 'POST', headers: { 'X-Trace': '1' } });
    expect(fetchMock).toHaveBeenCalledWith('/api/scan', {
      method: 'POST',
      headers: { 'X-Trace': '1', Authorization: 'Bearer fetch-tok' },
    });
  });

  it('works with no options object (default {}), no header when tokenless', async () => {
    const fetchMock = vi.fn(() => Promise.resolve({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);
    setToken('');
    await authFetch('/api/health');
    expect(fetchMock).toHaveBeenCalledWith('/api/health', { headers: {} });
  });
});
