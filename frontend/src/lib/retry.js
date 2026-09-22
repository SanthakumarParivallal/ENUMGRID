/**
 * retry.js — which failed responses are worth trying again, and how long to wait.
 * ---------------------------------------------------------------------------
 * `/api/host/scan` answers **429** with *"server busy — too many concurrent
 * scans, retry shortly"*. That is the backend refusing to start a scan right
 * now, not a report that a scan ran and failed: it happens whenever more than
 * `ENUMGRID_MAX_SCANS` (4) are in flight, which "Scan All" (3 workers) plus a
 * couple of row clicks — or a second open tab — reaches easily.
 *
 * Collapsing it into the generic error path put a red **Failed** badge on a host
 * nmap had never been pointed at, with a tooltip claiming its scan failed. So
 * this module holds the one decision that fixes it: come back shortly, and only
 * call it a failure once the server has stayed busy across several attempts.
 *
 * A 504 is deliberately *not* retryable — that one means the scan ran and hit
 * its deadline, so "failed" is the honest word for it and repeating it would
 * just spend another full timeout.
 */

/** Statuses where the server is saying "not now", not "this failed". */
export const RETRYABLE_STATUSES = Object.freeze([429]);

/** Total attempts, including the first. Worst case adds ~5.25 s before failing. */
export const MAX_ATTEMPTS = 4;

/** True when `status` means the request should be repeated rather than reported. */
export function isRetryable(status) {
  return RETRYABLE_STATUSES.includes(status);
}

/**
 * Milliseconds to wait before the next attempt, or `null` when this response
 * should be surfaced as a failure.
 *
 * `attempt` is 1-based: 1 is the first try, so the delays run 750 ms, 1.5 s, 3 s
 * and the fourth failure is reported. The backoff is exponential so a burst of
 * queued hosts spreads out instead of re-colliding on the same slot.
 */
export function retryDelayMs(status, attempt) {
  if (!isRetryable(status) || attempt >= MAX_ATTEMPTS || attempt < 1) return null;
  return 750 * 2 ** (attempt - 1);
}
