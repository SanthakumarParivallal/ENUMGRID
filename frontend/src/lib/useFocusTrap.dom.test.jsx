/**
 * useFocusTrap.dom.test.jsx — the DOM-bound half of the modal focus trap
 * (the pure trapTarget math is covered in useFocusTrap.test.js): the tabbable
 * query, focus-on-open, Tab/Shift+Tab wrapping via real keydown events, and
 * focus restoration to the trigger on unmount.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { useRef } from 'react';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import { focusableElements, useFocusTrap } from './useFocusTrap.js';

afterEach(cleanup);

describe('focusableElements', () => {
  it('returns only genuinely tabbable elements, in DOM order', () => {
    const box = document.createElement('div');
    box.innerHTML =
      '<button>ok</button>' +
      '<button disabled>nope</button>' + // disabled → excluded
      '<span tabindex="-1">nope</span>' + // tabindex -1 → excluded
      '<input />' +
      '<a href="#">link</a>';
    expect(focusableElements(box).map((el) => el.textContent || el.tagName)).toEqual(['ok', 'INPUT', 'link']);
  });

  it('returns [] for a missing container', () => {
    expect(focusableElements(null)).toEqual([]);
  });
});

function Modal({ active = true, withInitial = false }) {
  const target = useRef(null);
  const ref = useFocusTrap({ active, initialFocus: withInitial ? target : undefined });
  return (
    <div ref={ref} tabIndex={-1} data-testid="modal">
      <button>first</button>
      <button ref={withInitial ? target : null}>middle</button>
      <button disabled>disabled</button>
      <a href="#last">last</a>
    </div>
  );
}

describe('useFocusTrap', () => {
  it('moves focus to the first tabbable element on open', () => {
    render(<Modal />);
    expect(document.activeElement.textContent).toBe('first');
  });

  it('honours an explicit initialFocus element', () => {
    render(<Modal withInitial />);
    expect(document.activeElement.textContent).toBe('middle');
  });

  it('wraps Tab from the last element back to the first', () => {
    render(<Modal />);
    screen.getByText('last').focus();
    fireEvent.keyDown(screen.getByTestId('modal'), { key: 'Tab' });
    expect(document.activeElement.textContent).toBe('first');
  });

  it('wraps Shift+Tab from the first element to the last', () => {
    render(<Modal />);
    screen.getByText('first').focus();
    fireEvent.keyDown(screen.getByTestId('modal'), { key: 'Tab', shiftKey: true });
    expect(document.activeElement.textContent).toBe('last');
  });

  it('lets an interior Tab through untouched', () => {
    render(<Modal />);
    screen.getByText('first').focus();
    fireEvent.keyDown(screen.getByTestId('modal'), { key: 'Tab' }); // first ≠ last → null
    expect(document.activeElement.textContent).toBe('first'); // handler didn't move it
  });

  it('ignores non-Tab keys', () => {
    render(<Modal />);
    screen.getByText('first').focus();
    fireEvent.keyDown(screen.getByTestId('modal'), { key: 'Enter' });
    expect(document.activeElement.textContent).toBe('first');
  });

  it('focuses the container itself when it has no tabbable children', () => {
    function Empty() {
      const ref = useFocusTrap({});
      return <div ref={ref} tabIndex={-1} data-testid="empty" />;
    }
    render(<Empty />);
    expect(document.activeElement).toBe(screen.getByTestId('empty'));
  });

  it('does nothing while inactive', () => {
    render(<Modal active={false} />);
    expect(document.activeElement.textContent).not.toBe('first');
  });

  it('is a no-op when the ref is never attached to a node', () => {
    function Detached() {
      useFocusTrap({ active: true }); // ref returned but never spread onto an element
      return <div data-testid="detached" />;
    }
    expect(() => render(<Detached />)).not.toThrow();
  });

  it('restores focus to the trigger when the trap unmounts', () => {
    function Shell({ open }) {
      return (
        <div>
          <button data-testid="trigger">trigger</button>
          {open ? <Modal /> : null}
        </div>
      );
    }
    const { rerender } = render(<Shell open={false} />);
    screen.getByTestId('trigger').focus();
    expect(document.activeElement).toBe(screen.getByTestId('trigger'));

    rerender(<Shell open />); // trap mounts → focus jumps inside
    expect(document.activeElement.textContent).toBe('first');

    rerender(<Shell open={false} />); // trap unmounts → focus handed back to the trigger
    expect(document.activeElement).toBe(screen.getByTestId('trigger'));
  });
});
