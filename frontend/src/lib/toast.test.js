import { describe, it, expect } from 'vitest';
import { toastTone } from './toast.jsx';

describe('toastTone', () => {
  it('errors are assertive (role="alert") so they are announced immediately', () => {
    expect(toastTone('error').role).toBe('alert');
  });

  it('non-error toasts are polite (role="status")', () => {
    for (const type of ['success', 'warn', 'info', 'anything-else', undefined]) {
      expect(toastTone(type).role).toBe('status');
    }
  });

  it('maps each type to a distinct accent + icon', () => {
    expect(toastTone('success')).toMatchObject({ accent: 'text-matrix', icon: 'check' });
    expect(toastTone('error')).toMatchObject({ accent: 'text-crimson', icon: 'alert' });
    expect(toastTone('warn')).toMatchObject({ accent: 'text-amber', icon: 'alert' });
    expect(toastTone('info').icon).toBe('info');
  });

  it('falls back to the info tone for unknown types', () => {
    expect(toastTone('mystery')).toEqual(toastTone('info'));
  });
});
