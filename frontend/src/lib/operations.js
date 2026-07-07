/**
 * operations.js — pure helpers for the Operations panel (passive / schedules /
 * campaign). Kept free of React + fetch so the parsing/formatting/validation is
 * unit-testable in isolation, matching the rest of lib/.
 */

/** Weekday chips, in week order (value matches the backend's day tokens). */
export const DAY_OPTIONS = Object.freeze([
  { value: 'mon', label: 'Mon' },
  { value: 'tue', label: 'Tue' },
  { value: 'wed', label: 'Wed' },
  { value: 'thu', label: 'Thu' },
  { value: 'fri', label: 'Fri' },
  { value: 'sat', label: 'Sat' },
  { value: 'sun', label: 'Sun' },
]);

const _TITLE = { mon: 'Mon', tue: 'Tue', wed: 'Wed', thu: 'Thu', fri: 'Fri', sat: 'Sat', sun: 'Sun' };

/** True for a valid 24-hour "HH:MM" string. */
export function isValidTime(at) {
  return /^([01]?\d|2[0-3]):[0-5]\d$/.test(String(at || '').trim());
}

/**
 * Split a free-form targets box (comma / whitespace / newline separated) into a
 * de-duplicated, order-preserving list of non-empty targets.
 */
export function splitTargets(text) {
  const seen = new Set();
  const out = [];
  for (const raw of String(text || '').split(/[\s,]+/)) {
    const t = raw.trim();
    if (t && !seen.has(t)) {
      seen.add(t);
      out.push(t);
    }
  }
  return out;
}

/** Render the backend `days` token ("*" / "mon,fri") as human text. */
export function formatDays(days) {
  const spec = String(days || '*').trim();
  if (!spec || spec === '*') return 'Every day';
  return spec
    .split(',')
    .map((d) => _TITLE[d.trim().toLowerCase()] || d.trim())
    .join(', ');
}

/** One-line human summary of a schedule rule (as returned by the API). */
export function describeSchedule(rule) {
  if (!rule) return '';
  const mode = rule.mode === 'full' ? 'full scan' : 'discovery';
  const deep = rule.deep ? ' +vuln' : '';
  return `${formatDays(rule.days)} at ${rule.at} · ${mode}${deep}`;
}

/** Client-side pre-validation for the schedule form → { ok, error }. */
export function validateScheduleForm({ target, at }) {
  if (!String(target || '').trim()) return { ok: false, error: 'Enter a target (IP / CIDR / range).' };
  if (!isValidTime(at)) return { ok: false, error: 'Enter a valid time as HH:MM (24-hour).' };
  return { ok: true, error: null };
}

/** Severity → Tailwind text/border tone for the campaign risk chips. */
export function severityTone(sev) {
  switch (String(sev || '').toLowerCase()) {
    case 'critical':
    case 'high':
      return 'border-crimson/45 bg-crimson/10 text-crimson';
    case 'medium':
      return 'border-amber/45 bg-amber/10 text-amber';
    default:
      return 'border-slate-700 bg-steel-900 text-slate-400';
  }
}
