import { describe, it, expect } from 'vitest';
import { trapTarget } from './useFocusTrap.js';

// A modal's tabbable elements, as plain sentinels (trapTarget is DOM-agnostic).
const items = ['first', 'mid', 'last'];

describe('trapTarget', () => {
  it('wraps Tab on the last element back to the first', () => {
    expect(trapTarget(items, 'last', false)).toBe('first');
  });

  it('wraps Shift+Tab on the first element to the last', () => {
    expect(trapTarget(items, 'first', true)).toBe('last');
  });

  it('lets native Tab handle interior moves (returns null)', () => {
    expect(trapTarget(items, 'first', false)).toBeNull(); // Tab: first → native → mid
    expect(trapTarget(items, 'mid', false)).toBeNull();
    expect(trapTarget(items, 'mid', true)).toBeNull(); // Shift+Tab: mid → native → first
    expect(trapTarget(items, 'last', true)).toBeNull();
  });

  it('pulls focus back to the first item when focus has escaped the container', () => {
    expect(trapTarget(items, 'somewhere-outside', false)).toBe('first');
    expect(trapTarget(items, 'somewhere-outside', true)).toBe('first');
    expect(trapTarget(items, null, false)).toBe('first');
  });

  it('is a no-op when there are no tabbable elements', () => {
    expect(trapTarget([], 'x', false)).toBeNull();
    expect(trapTarget(undefined, 'x', false)).toBeNull();
  });

  it('handles a single tabbable element (Tab and Shift+Tab both keep it)', () => {
    expect(trapTarget(['only'], 'only', false)).toBe('only'); // last → wrap to first (itself)
    expect(trapTarget(['only'], 'only', true)).toBe('only'); // first → wrap to last (itself)
  });
});
