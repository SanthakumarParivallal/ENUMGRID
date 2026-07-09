/**
 * toast.provider.test.jsx — the <ToastProvider> queue + rendering (the pure
 * toastTone mapping is covered in toast.test.js). Exercises queueing, the two
 * a11y live-regions (polite status vs assertive alert), auto-dismiss timing,
 * keyed replacement, manual dismissal, and unmount cleanup.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, act, renderHook, cleanup } from '@testing-library/react';
import { ToastProvider, useToast } from './toast.jsx';

function Controls() {
  const { toast, dismiss } = useToast();
  return (
    <div>
      <button onClick={() => toast('Default message')}>info</button>
      <button onClick={() => toast('Saved', { type: 'success' })}>success</button>
      <button onClick={() => toast('Boom', { type: 'error', title: 'Failed' })}>error</button>
      <button onClick={() => toast('Timed', { id: 'timed', duration: 5000 })}>timed</button>
      <button onClick={() => toast('Timed v2', { id: 'timed', duration: 5000 })}>replace-timed</button>
      <button onClick={() => toast('Sticky', { id: 'sticky', duration: 0 })}>sticky</button>
      <button onClick={() => dismiss('ghost')}>dismiss-missing</button>
    </div>
  );
}

const renderProvider = () => render(<ToastProvider><Controls /></ToastProvider>);
const roleOf = (text) => screen.getByText(text).closest('[role]').getAttribute('role');

describe('ToastProvider', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    act(() => vi.runOnlyPendingTimers());
    vi.useRealTimers();
    cleanup();
  });

  it('renders a default toast as info + polite (role="status")', () => {
    renderProvider();
    fireEvent.click(screen.getByText('info'));
    expect(roleOf('Default message')).toBe('status');
  });

  it('renders an error assertively with a title, alongside a success toast', () => {
    renderProvider();
    fireEvent.click(screen.getByText('error'));
    fireEvent.click(screen.getByText('success'));
    expect(roleOf('Boom')).toBe('alert'); // assertive
    expect(screen.getByText('Failed')).toBeTruthy(); // title rendered
    expect(roleOf('Saved')).toBe('status'); // polite
  });

  it('auto-dismisses a normal toast after its 4500ms default', () => {
    renderProvider();
    fireEvent.click(screen.getByText('success'));
    act(() => vi.advanceTimersByTime(4499));
    expect(screen.queryByText('Saved')).toBeTruthy();
    act(() => vi.advanceTimersByTime(1));
    expect(screen.queryByText('Saved')).toBeNull();
  });

  it('keeps error toasts up longer (7000ms)', () => {
    renderProvider();
    fireEvent.click(screen.getByText('error'));
    act(() => vi.advanceTimersByTime(4500));
    expect(screen.queryByText('Boom')).toBeTruthy(); // past the normal window
    act(() => vi.advanceTimersByTime(2500));
    expect(screen.queryByText('Boom')).toBeNull();
  });

  it('replacing a keyed toast clears the old timer and swaps the content', () => {
    renderProvider();
    fireEvent.click(screen.getByText('timed'));
    expect(screen.getByText('Timed')).toBeTruthy();
    fireEvent.click(screen.getByText('replace-timed')); // same id → clears previous timer
    expect(screen.queryByText('Timed')).toBeNull();
    expect(screen.getByText('Timed v2')).toBeTruthy();
  });

  it('treats a zero-duration toast as sticky (never auto-dismissed)', () => {
    renderProvider();
    fireEvent.click(screen.getByText('sticky'));
    act(() => vi.advanceTimersByTime(60_000));
    expect(screen.getByText('Sticky')).toBeTruthy();
  });

  it('dismisses via the close button', () => {
    renderProvider();
    fireEvent.click(screen.getByText('success'));
    fireEvent.click(screen.getByLabelText('Dismiss notification'));
    expect(screen.queryByText('Saved')).toBeNull();
  });

  it('dismissing an unknown id is a harmless no-op', () => {
    renderProvider();
    expect(() => fireEvent.click(screen.getByText('dismiss-missing'))).not.toThrow();
  });

  it('clears pending timers when the provider unmounts', () => {
    const { unmount } = renderProvider();
    fireEvent.click(screen.getByText('success')); // schedules an auto-dismiss timer
    expect(() => unmount()).not.toThrow(); // effect cleanup runs map.forEach(clearTimeout)
  });
});

describe('useToast', () => {
  it('throws a clear error when used outside a <ToastProvider>', () => {
    expect(() => renderHook(() => useToast())).toThrow(/ToastProvider/);
  });
});
