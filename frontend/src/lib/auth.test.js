import { describe, it, expect, beforeEach } from 'vitest';
import { getToken, setToken, authHeaders, streamUrl } from './auth.js';

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
