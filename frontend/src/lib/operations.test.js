import { describe, it, expect } from 'vitest';
import {
  isValidTime,
  splitTargets,
  formatDays,
  describeSchedule,
  validateScheduleForm,
  severityTone,
  DAY_OPTIONS,
} from './operations.js';

describe('isValidTime', () => {
  it('accepts valid 24-hour times', () => {
    for (const t of ['00:00', '2:00', '02:00', '23:59', '9:05']) expect(isValidTime(t)).toBe(true);
  });
  it('rejects invalid times', () => {
    for (const t of ['24:00', '12:60', 'noon', '', '1200', '2:5']) expect(isValidTime(t)).toBe(false);
  });
});

describe('splitTargets', () => {
  it('splits on commas, spaces and newlines and de-dupes', () => {
    expect(splitTargets('192.168.0.0/24, 10.0.0.0/24\n192.168.0.0/24  8.8.8.8')).toEqual([
      '192.168.0.0/24', '10.0.0.0/24', '8.8.8.8',
    ]);
  });
  it('returns [] for empty input', () => {
    expect(splitTargets('   ')).toEqual([]);
    expect(splitTargets(null)).toEqual([]);
  });
});

describe('formatDays', () => {
  it('maps "*" and empty to "Every day"', () => {
    expect(formatDays('*')).toBe('Every day');
    expect(formatDays('')).toBe('Every day');
    expect(formatDays(null)).toBe('Every day');
  });
  it('titles specific days', () => {
    expect(formatDays('mon,fri')).toBe('Mon, Fri');
  });
});

describe('describeSchedule', () => {
  it('summarises a rule', () => {
    expect(describeSchedule({ days: 'mon,fri', at: '02:00', mode: 'full', deep: true }))
      .toBe('Mon, Fri at 02:00 · full scan +vuln');
    expect(describeSchedule({ days: '*', at: '03:15', mode: 'discover', deep: false }))
      .toBe('Every day at 03:15 · discovery');
  });
  it('is safe on empty', () => {
    expect(describeSchedule(null)).toBe('');
  });
});

describe('validateScheduleForm', () => {
  it('rejects a missing target', () => {
    expect(validateScheduleForm({ target: '', at: '02:00' }).ok).toBe(false);
  });
  it('rejects a bad time', () => {
    expect(validateScheduleForm({ target: '10.0.0.0/24', at: '99:99' }).ok).toBe(false);
  });
  it('accepts a valid rule', () => {
    expect(validateScheduleForm({ target: '10.0.0.0/24', at: '02:00' })).toEqual({ ok: true, error: null });
  });
});

describe('severityTone', () => {
  it('maps severities to distinct tones', () => {
    expect(severityTone('critical')).toContain('crimson');
    expect(severityTone('high')).toContain('crimson');
    expect(severityTone('medium')).toContain('amber');
    expect(severityTone('low')).toContain('slate');
    expect(severityTone('info')).toContain('slate');
  });
});

describe('DAY_OPTIONS', () => {
  it('is the seven weekdays in order', () => {
    expect(DAY_OPTIONS.map((d) => d.value)).toEqual(['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']);
  });
});
