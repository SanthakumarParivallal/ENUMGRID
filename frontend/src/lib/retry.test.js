import { describe, it, expect } from 'vitest';
import { isRetryable, retryDelayMs, MAX_ATTEMPTS, RETRYABLE_STATUSES } from './retry.js';

describe('isRetryable', () => {
  it('retries only the "server busy" answer', () => {
    expect(isRetryable(429)).toBe(true);
    expect(RETRYABLE_STATUSES).toEqual([429]);
  });

  it('does not retry a scan that actually ran and failed', () => {
    // 504 is the backend's "scan timed out" — repeating it just spends another
    // full deadline. 400/401/500 are equally final.
    for (const s of [400, 401, 403, 404, 500, 502, 503, 504]) {
      expect(isRetryable(s)).toBe(false);
    }
  });
});

describe('retryDelayMs', () => {
  it('backs off exponentially so a queued burst does not re-collide', () => {
    expect(retryDelayMs(429, 1)).toBe(750);
    expect(retryDelayMs(429, 2)).toBe(1500);
    expect(retryDelayMs(429, 3)).toBe(3000);
  });

  it('gives up after MAX_ATTEMPTS so a permanently busy server is reported', () => {
    expect(retryDelayMs(429, MAX_ATTEMPTS)).toBeNull();
    expect(retryDelayMs(429, MAX_ATTEMPTS + 5)).toBeNull();
  });

  it('never retries a non-retryable status, whatever the attempt', () => {
    expect(retryDelayMs(500, 1)).toBeNull();
    expect(retryDelayMs(504, 2)).toBeNull();
  });

  it('rejects a nonsensical attempt number instead of waiting a fraction', () => {
    // 750 * 2**-1 would be 375ms of "attempt zero"; there is no such attempt.
    expect(retryDelayMs(429, 0)).toBeNull();
    expect(retryDelayMs(429, -3)).toBeNull();
  });

  it('bounds the total added latency before a host is called Failed', () => {
    let total = 0;
    for (let a = 1; a < MAX_ATTEMPTS; a += 1) total += retryDelayMs(429, a);
    expect(total).toBe(5250);
  });
});
