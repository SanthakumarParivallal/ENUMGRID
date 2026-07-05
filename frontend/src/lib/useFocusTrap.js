/**
 * useFocusTrap.js — keyboard focus management for modal dialogs.
 * ---------------------------------------------------------------------------
 * A true modal (aria-modal="true") must keep keyboard focus inside it while
 * open and hand focus back to whatever opened it when it closes (WCAG 2.4.3
 * Focus Order + 2.1.2 No Keyboard Trap — the *good* kind of trap: escapable via
 * the close button / Escape, but Tab can't wander off behind the overlay).
 *
 * The Tab-wrap decision is factored into the pure `trapTarget` helper so it can
 * be unit-tested without a DOM, matching the project's lib-testing convention;
 * the hook itself just wires it to real focus events.
 */

import { useEffect, useRef } from 'react';

// Elements that can receive keyboard focus. `[tabindex="-1"]` is excluded (it is
// programmatically focusable but not part of the Tab order).
const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

/** The tabbable elements inside `container`, in DOM (tab) order. */
export function focusableElements(container) {
  if (!container) return [];
  return Array.from(container.querySelectorAll(FOCUSABLE_SELECTOR)).filter(
    (el) => !el.hasAttribute('disabled') && el.tabIndex !== -1,
  );
}

/**
 * Pure Tab-wrap logic. Given the tabbable `items`, the currently-focused
 * element `active`, and whether Shift is held, return the element focus should
 * jump to — or `null` to let the browser's native Tab handle an interior move.
 *
 *   - focus escaped the container  → pull it back to the first item
 *   - Shift+Tab on the first item  → wrap to the last
 *   - Tab on the last item         → wrap to the first
 */
export function trapTarget(items, active, shiftKey) {
  if (!items || items.length === 0) return null;
  const first = items[0];
  const last = items[items.length - 1];
  if (items.indexOf(active) === -1) return first;
  if (shiftKey && active === first) return last;
  if (!shiftKey && active === last) return first;
  return null;
}

/**
 * Trap focus inside the returned ref'd container while `active`.
 * @param {{ active?: boolean, initialFocus?: React.RefObject }} [opts]
 *   `initialFocus` — element to focus on open (defaults to the first tabbable).
 * @returns a ref to attach to the dialog container.
 */
export function useFocusTrap({ active = true, initialFocus } = {}) {
  const containerRef = useRef(null);
  useEffect(() => {
    if (!active) return undefined;
    const container = containerRef.current;
    if (!container) return undefined;

    // Remember what opened us so we can hand focus back on close.
    const trigger = document.activeElement;

    // Move focus in: the requested element, else the first tabbable, else the
    // container itself (which carries tabindex="-1").
    const target = (initialFocus && initialFocus.current) || focusableElements(container)[0] || container;
    if (target && typeof target.focus === 'function') target.focus();

    const onKeyDown = (e) => {
      if (e.key !== 'Tab') return;
      const next = trapTarget(focusableElements(container), document.activeElement, e.shiftKey);
      if (next) {
        e.preventDefault();
        next.focus();
      }
    };
    container.addEventListener('keydown', onKeyDown);

    return () => {
      container.removeEventListener('keydown', onKeyDown);
      if (trigger && typeof trigger.focus === 'function') trigger.focus();
    };
  }, [active, initialFocus]);

  return containerRef;
}
