/**
 * CopilotPanel.jsx — the ENUMGRID AI copilot as a right-hand slide-over.
 * ---------------------------------------------------------------------------
 * Self-contained (like the Operations panel) to keep the 2.6k-line dashboard
 * calm. It:
 *   • streams a chat grounded in the *current scan* (POST /api/copilot/chat, SSE);
 *   • lets the operator paste an Anthropic or OpenAI key right here and pick the
 *     active provider (POST /api/copilot/key + /provider);
 *   • surfaces model-proposed scans as a confirm button that launches the real,
 *     scope-vetted scan — the model never runs anything on its own.
 *
 * Opened from the command palette / Settings menu via the `eg:open-copilot`
 * event. Pure data shaping lives in `lib/copilot.js` (unit-tested).
 */

import { useCallback, useEffect, useRef, useState } from 'react';

import { useScan } from './context/ScanContext.jsx';
import { authFetch } from './lib/auth.js';
import {
  PROVIDER_HINTS,
  PROVIDER_LABELS,
  buildScanContext,
  isReady,
  parseSSE,
  summarizeAction,
  validateKeyForm,
} from './lib/copilot.js';
import { useToast } from './lib/toast.jsx';
import { useFocusTrap } from './lib/useFocusTrap.js';

function SparkIcon(props) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"
         strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M12 3l1.9 4.6L18.5 9.5 13.9 11.4 12 16l-1.9-4.6L5.5 9.5l4.6-1.9L12 3z" />
      <path d="M19 14.5l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7.7-1.8z" />
    </svg>
  );
}

const fieldCls =
  'w-full rounded-md border border-slate-700 bg-steel-900 px-2.5 py-1.5 text-xs text-slate-100 ' +
  'placeholder:text-slate-500 outline-none focus-visible:ring-2 focus-visible:ring-sky-400';

/** Provider + key upload — shown when nothing is ready, or via the gear. */
function ConnectCard({ status, onSaved }) {
  const { toast } = useToast();
  const [provider, setProvider] = useState((status && status.active) || 'anthropic');
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);

  const save = async () => {
    const check = validateKeyForm({ provider, key });
    if (!check.ok) { toast(check.error, { type: 'error' }); return; }
    setBusy(true);
    try {
      const r = await authFetch('/api/copilot/key', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, key: key.trim() }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || 'Could not save the key.');
      await authFetch('/api/copilot/provider', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider }),
      });
      setKey('');
      toast(`${PROVIDER_LABELS[provider]} connected.`, { type: 'success' });
      onSaved(d.status || null);
    } catch (e) {
      toast(e.message, { type: 'error' });
    } finally {
      setBusy(false);
    }
  };

  const hint = PROVIDER_HINTS[provider] || {};
  const sdkMissing = status && status.providers && status.providers[provider]
    && !status.providers[provider].sdk_installed;

  return (
    <div className="space-y-3 rounded-lg border border-slate-700/70 bg-steel-900/60 p-3">
      <div>
        <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">AI provider</div>
        <div className="flex gap-2">
          {['anthropic', 'openai'].map((p) => (
            <button
              key={p} type="button" onClick={() => setProvider(p)}
              aria-pressed={provider === p}
              className={`flex-1 rounded-md border px-2 py-1.5 text-xs font-semibold transition ${
                provider === p
                  ? 'border-sky-500/50 bg-sky-500/10 text-sky-300'
                  : 'border-slate-700 bg-steel-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              {PROVIDER_LABELS[p]}
            </button>
          ))}
        </div>
      </div>
      <div>
        <label htmlFor="eg-copilot-key" className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-slate-400">
          API key
        </label>
        <input
          id="eg-copilot-key" type="password" autoComplete="off" value={key}
          onChange={(e) => setKey(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') save(); }}
          placeholder={hint.placeholder || 'API key'} className={fieldCls}
        />
        <p className="mt-1 text-[10px] text-slate-500">
          Stored on your machine (0600, gitignored) — never logged.{' '}
          {hint.url && (
            <a href={hint.url} target="_blank" rel="noreferrer" className="text-sky-400 hover:underline">
              Get a key ↗
            </a>
          )}
        </p>
        {sdkMissing && (
          <p className="mt-1 text-[10px] text-amber">
            The {PROVIDER_LABELS[provider]} SDK isn’t installed on the backend
            (<code>pip install {provider}</code>) — the key saves, but chat needs the SDK.
          </p>
        )}
      </div>
      <button
        type="button" onClick={save} disabled={busy}
        className="w-full rounded-md border border-matrix/50 bg-matrix/10 px-3 py-1.5 text-xs font-semibold text-matrix transition hover:bg-matrix hover:text-steel-950 disabled:opacity-50"
      >
        {busy ? 'Saving…' : 'Connect'}
      </button>
    </div>
  );
}

function Bubble({ role, children }) {
  const mine = role === 'user';
  return (
    <div className={`flex ${mine ? 'justify-end' : 'justify-start'}`}>
      <div
        className={`max-w-[85%] whitespace-pre-wrap rounded-lg px-3 py-2 text-xs leading-relaxed ${
          mine
            ? 'bg-sky-500/15 text-sky-100 border border-sky-500/30'
            : 'bg-steel-900/70 text-slate-200 border border-slate-700/70'
        }`}
      >
        {children}
      </div>
    </div>
  );
}

function CopilotPanel({ onClose }) {
  const scan = useScan();
  const { toast } = useToast();
  const inputRef = useRef(null);
  const dialogRef = useFocusTrap({ initialFocus: inputRef });
  const scrollRef = useRef(null);
  const abortRef = useRef(null);

  const [status, setStatus] = useState(null);
  const [showConnect, setShowConnect] = useState(false);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [streaming, setStreaming] = useState(false);

  // Escape to close.
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  // Load status on open; open the connect card if nothing is ready.
  useEffect(() => {
    let alive = true;
    authFetch('/api/copilot')
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => { if (alive) { setStatus(d); setShowConnect(!isReady(d)); } })
      .catch(() => { if (alive) setShowConnect(true); });
    return () => {
      alive = false;
      if (abortRef.current) abortRef.current.abort();
    };
  }, []);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, streaming]);

  const send = useCallback(async () => {
    const text = input.trim();
    if (!text || streaming) return;
    const history = [...messages, { role: 'user', content: text }];
    setMessages([...history, { role: 'assistant', content: '', action: null }]);
    setInput('');
    setStreaming(true);
    const controller = new AbortController();
    abortRef.current = controller;

    const patchLast = (fn) =>
      setMessages((prev) => {
        const next = prev.slice();
        const last = next[next.length - 1];
        if (last && last.role === 'assistant') next[next.length - 1] = fn(last);
        return next;
      });

    try {
      const resp = await authFetch('/api/copilot/chat', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: history, context: buildScanContext(scan) }),
        signal: controller.signal,
      });
      if (!resp.ok || !resp.body) throw new Error(`copilot ${resp.status}`);
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      let sawText = false;
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const { events, rest } = parseSSE(buf);
        buf = rest;
        for (const ev of events) {
          if (ev.type === 'delta' && ev.text) { sawText = true; patchLast((l) => ({ ...l, content: l.content + ev.text })); }
          else if (ev.type === 'action' && ev.action) patchLast((l) => ({ ...l, action: ev.action }));
          else if (ev.type === 'error') patchLast((l) => ({ ...l, content: l.content, error: ev.message }));
        }
      }
      if (!sawText) {
        patchLast((l) => (l.content ? l : { ...l, content: l.error ? '' : '(no response)' }));
      }
    } catch (e) {
      if (e.name !== 'AbortError') patchLast((l) => ({ ...l, error: 'Could not reach the copilot backend.' }));
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  }, [input, streaming, messages, scan]);

  const confirmScan = useCallback((action) => {
    if (!action || !action.target) return;
    scan.setTarget(action.target);
    scan.startScan(action.target, action.mode === 'full');
    toast(`Scanning ${action.target}…`, { type: 'info', title: 'Copilot started a scan' });
    onClose();
  }, [scan, toast, onClose]);

  const ready = isReady(status);

  return (
    <div className="fixed inset-0 z-[70] flex justify-end">
      <button
        type="button" aria-label="Close copilot" tabIndex={-1}
        className="absolute inset-0 bg-steel-950/70 backdrop-blur-sm"
        onClick={onClose}
      />
      <aside
        ref={dialogRef} role="dialog" aria-modal="true" aria-label="ENUMGRID AI Copilot"
        className="relative flex h-full w-full max-w-[420px] flex-col border-l border-slate-700/80 bg-steel-950 shadow-2xl"
      >
        <header className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-md border border-matrix/40 bg-matrix/10 text-matrix">
              <SparkIcon className="h-4 w-4" />
            </span>
            <div>
              <div className="text-sm font-semibold text-slate-100">Copilot</div>
              <div className="text-[10px] text-slate-500">
                {status ? `${PROVIDER_LABELS[status.active] || status.active}${ready ? '' : ' · not connected'}` : 'grounded in your scan'}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1">
            <button
              type="button" aria-label="Copilot settings" title="API key & provider"
              onClick={() => setShowConnect((v) => !v)}
              className="rounded-md p-1.5 text-slate-400 outline-none transition hover:bg-steel-800 hover:text-slate-100 focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></svg>
            </button>
            <button
              type="button" aria-label="Close" onClick={onClose}
              className="rounded-md p-1.5 text-slate-400 outline-none transition hover:bg-steel-800 hover:text-slate-100 focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 6l12 12M18 6L6 18" /></svg>
            </button>
          </div>
        </header>

        <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto px-4 py-4">
          {(showConnect || !ready) && (
            <ConnectCard
              status={status}
              onSaved={(st) => {
                setStatus(st);
                if (isReady(st)) setShowConnect(false);
              }}
            />
          )}

          {messages.length === 0 && ready && !showConnect && (
            <div className="rounded-lg border border-slate-800 bg-steel-900/40 p-3 text-xs text-slate-400">
              <p className="mb-2 font-semibold text-slate-300">Ask about your scan.</p>
              <ul className="space-y-1">
                <li>· “Which hosts are most exposed and why?”</li>
                <li>· “Summarise the open services on this subnet.”</li>
                <li>· “What should I scan next?” — I can propose a scan to run.</li>
              </ul>
            </div>
          )}

          {messages.map((m, i) => (
            <div key={i} className="space-y-2">
              {(m.content || (m.role === 'assistant' && streaming && i === messages.length - 1)) && (
                <Bubble role={m.role}>
                  {m.content || <span className="text-slate-500">…</span>}
                </Bubble>
              )}
              {m.error && (
                <div className="rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-[11px] text-rose-300">
                  {m.error}
                </div>
              )}
              {m.action && (
                <div className="flex justify-start">
                  <div className="max-w-[85%] rounded-lg border border-amber/40 bg-amber/10 p-2.5">
                    <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-amber">Proposed action</div>
                    {m.action.reason && <p className="mb-2 text-[11px] text-slate-300">{m.action.reason}</p>}
                    <button
                      type="button" onClick={() => confirmScan(m.action)}
                      className="rounded-md border border-amber/50 bg-amber/15 px-2.5 py-1 text-[11px] font-semibold text-amber transition hover:bg-amber hover:text-steel-950"
                    >
                      ▶ {summarizeAction(m.action)}
                    </button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        <div className="border-t border-slate-800 p-3">
          <div className="flex items-end gap-2">
            <textarea
              ref={inputRef} rows={1} value={input} disabled={!ready || streaming}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }}
              placeholder={ready ? 'Ask the copilot…  (Enter to send)' : 'Connect a provider to chat'}
              aria-label="Message the copilot"
              className={`${fieldCls} max-h-28 resize-none disabled:opacity-60`}
            />
            <button
              type="button" onClick={send} disabled={!ready || streaming || !input.trim()}
              aria-label="Send"
              className="shrink-0 rounded-md border border-matrix/50 bg-matrix/10 px-3 py-2 text-xs font-semibold text-matrix transition hover:bg-matrix hover:text-steel-950 disabled:opacity-40"
            >
              {streaming ? '…' : 'Send'}
            </button>
          </div>
          <p className="mt-1.5 text-[10px] text-slate-600">
            Grounded in your current scan{scan && scan.hosts ? ` (${scan.hosts.length} host${scan.hosts.length === 1 ? '' : 's'})` : ''}. Authorized use only.
          </p>
        </div>
      </aside>
    </div>
  );
}

/**
 * Owns the copilot modal + its always-visible launcher. Opens on the
 * `eg:open-copilot` event (command palette / Settings) or the floating button.
 * The button sits bottom-LEFT so it never collides with the bottom-right toasts.
 */
export default function CopilotLayer() {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const openEvt = () => setOpen(true);
    window.addEventListener('eg:open-copilot', openEvt);
    return () => window.removeEventListener('eg:open-copilot', openEvt);
  }, []);
  if (open) return <CopilotPanel onClose={() => setOpen(false)} />;
  return (
    <button
      type="button" aria-label="Open AI copilot" title="AI Copilot (grounded in your scan)"
      onClick={() => setOpen(true)}
      className="fixed bottom-4 left-4 z-50 flex items-center gap-2 rounded-full border border-matrix/40 bg-steel-900/90 px-3.5 py-2.5 text-xs font-semibold text-matrix shadow-lg backdrop-blur transition hover:bg-matrix hover:text-steel-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-matrix"
    >
      <SparkIcon className="h-4 w-4" /> Copilot
    </button>
  );
}
