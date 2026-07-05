import { describe, it, expect } from 'vitest';
import { SHORTCUTS, isEditableTarget } from './shortcuts.js';

describe('isEditableTarget', () => {
  it('is true for form controls and contenteditable (so typing is not hijacked)', () => {
    expect(isEditableTarget({ tagName: 'INPUT' })).toBe(true);
    expect(isEditableTarget({ tagName: 'TEXTAREA' })).toBe(true);
    expect(isEditableTarget({ tagName: 'SELECT' })).toBe(true);
    expect(isEditableTarget({ isContentEditable: true })).toBe(true);
  });

  it('is false for non-editable elements and nullish targets', () => {
    expect(isEditableTarget({ tagName: 'DIV' })).toBe(false);
    expect(isEditableTarget({ tagName: 'BUTTON' })).toBe(false);
    expect(isEditableTarget(null)).toBe(false);
    expect(isEditableTarget(undefined)).toBe(false);
  });
});

describe('SHORTCUTS', () => {
  it('documents each shortcut with a key and a non-empty label', () => {
    expect(SHORTCUTS.length).toBeGreaterThan(0);
    for (const s of SHORTCUTS) {
      expect(typeof s.keys).toBe('string');
      expect(s.keys.length).toBeGreaterThan(0);
      expect(s.label.length).toBeGreaterThan(0);
    }
  });

  it('does not bind any scan/network-triggering key', () => {
    const keys = SHORTCUTS.map((s) => s.keys);
    expect(keys).not.toContain('s'); // no accidental "start scan"
    expect(keys).not.toContain('Enter');
  });
});
