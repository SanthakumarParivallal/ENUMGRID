/**
 * toast.jsx — lightweight, accessible action-feedback toasts.
 * ---------------------------------------------------------------------------
 * A ToastProvider owns a small queue; `useToast().toast(msg, { type })` pushes
 * one and it auto-dismisses. Errors use role="alert" (assertive) so they are
 * announced immediately; everything else uses role="status" (polite). The
 * tone → colour/role/icon mapping is a pure function (`toastTone`) so it is
 * unit-testable like the rest of the lib.
 *
 * Kept independent of ScanContext: the UI decides *when* to toast (see
 * <ScanToasts/>), so scan state stays a pure data concern.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';

const ToastContext = createContext(null);

/** Visual + a11y identity for a toast type. Pure — safe to unit-test. */
export function toastTone(type) {
  switch (type) {
    case 'success':
      return { role: 'status', ring: 'border-matrix/50', accent: 'text-matrix', bar: 'bg-matrix', icon: 'check' };
    case 'error':
      return { role: 'alert', ring: 'border-crimson/50', accent: 'text-crimson', bar: 'bg-crimson', icon: 'alert' };
    case 'warn':
      return { role: 'status', ring: 'border-amber/50', accent: 'text-amber', bar: 'bg-amber', icon: 'alert' };
    default: // 'info'
      return { role: 'status', ring: 'border-sky-500/50', accent: 'text-sky-300', bar: 'bg-sky-400', icon: 'info' };
  }
}

const ICON_PATHS = {
  check: <path d="M4 12.5 L9 17.5 L20 6.5" />,
  alert: (
    <>
      <path d="M12 3 L22 19 L2 19 Z" />
      <path d="M12 10 L12 14" />
      <path d="M12 16.5 L12 16.6" strokeWidth="2.2" />
    </>
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11 L12 16" />
      <path d="M12 8 L12 8.1" strokeWidth="2.2" />
    </>
  ),
};

function ToastIcon({ name, className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {ICON_PATHS[name] || ICON_PATHS.info}
    </svg>
  );
}

let _seq = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const timers = useRef(new Map());

  const dismiss = useCallback((id) => {
    setToasts((list) => list.filter((t) => t.id !== id));
    const tm = timers.current.get(id);
    if (tm) {
      clearTimeout(tm);
      timers.current.delete(id);
    }
  }, []);

  const toast = useCallback((message, opts = {}) => {
    const id = opts.id ?? `t${(_seq += 1)}`;
    const type = opts.type ?? 'info';
    const duration = opts.duration ?? (type === 'error' ? 7000 : 4500);
    // Replace an existing toast with the same id (e.g. a keyed status update).
    setToasts((list) => [...list.filter((t) => t.id !== id), { id, message, type, title: opts.title }]);
    const prev = timers.current.get(id);
    if (prev) clearTimeout(prev);
    if (duration > 0) timers.current.set(id, setTimeout(() => dismiss(id), duration));
    return id;
  }, [dismiss]);

  // Clear any pending timers if the provider unmounts.
  useEffect(() => {
    const map = timers.current;
    return () => map.forEach(clearTimeout);
  }, []);

  const api = useMemo(() => ({ toast, dismiss }), [toast, dismiss]);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[90] flex w-[min(92vw,360px)] flex-col gap-2" aria-live="polite">
        {toasts.map((t) => {
          const tone = toastTone(t.type);
          return (
            <div
              key={t.id}
              role={tone.role}
              className={`eg-toast eg-card pointer-events-auto relative flex items-start gap-2.5 overflow-hidden border ${tone.ring} p-3 pr-9 shadow-xl`}
            >
              <span className={`absolute inset-y-0 left-0 w-1 ${tone.bar}`} aria-hidden="true" />
              <ToastIcon name={tone.icon} className={`mt-0.5 h-4 w-4 shrink-0 ${tone.accent}`} />
              <div className="min-w-0 flex-1">
                {t.title && <div className={`text-xs font-semibold ${tone.accent}`}>{t.title}</div>}
                <div className="break-words text-xs leading-relaxed text-slate-200">{t.message}</div>
              </div>
              <button
                onClick={() => dismiss(t.id)}
                aria-label="Dismiss notification"
                className="absolute right-1.5 top-1.5 rounded p-1 text-slate-500 outline-none transition hover:bg-steel-800 hover:text-slate-200 focus-visible:ring-2 focus-visible:ring-sky-400"
              >
                <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
                  <path d="M6 6 L18 18 M18 6 L6 18" />
                </svg>
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

/** Access the toast API: `const { toast, dismiss } = useToast();` */
export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within a <ToastProvider>');
  return ctx;
}
