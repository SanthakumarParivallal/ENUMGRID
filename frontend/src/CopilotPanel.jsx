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
  OLLAMA_RECOMMENDED,
  PROVIDER_HINTS,
  PROVIDER_LABELS,
  PROVIDER_ORDER,
  buildScanContext,
  formatBytes,
  isReady,
  ollamaSetupState,
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

const primaryBtn =
  'w-full rounded-md border border-matrix/50 bg-matrix/10 px-3 py-1.5 text-xs font-semibold ' +
  'text-matrix transition hover:bg-matrix hover:text-steel-950 disabled:opacity-50';

/** Live download progress for `ollama pull`, streamed frame-by-frame. */
function PullProgress({ pull }) {
  const pct = typeof pull.percent === 'number' ? pull.percent : null;
  return (
    <div className="rounded-md border border-matrix/30 bg-matrix/5 p-2.5">
      <div className="mb-1 flex items-center justify-between text-[11px]">
        <span className="text-slate-200">Downloading <span className="font-semibold">{pull.model}</span>…</span>
        <span className="font-semibold text-matrix">{pct != null ? `${pct}%` : '…'}</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded bg-steel-800">
        <div
          className={`h-full bg-matrix transition-all ${pct == null ? 'animate-pulse' : ''}`}
          style={{ width: pct != null ? `${pct}%` : '35%' }}
        />
      </div>
      <p className="mt-1 truncate text-[10px] text-slate-500">
        {pull.total ? `${formatBytes(pull.completed)} / ${formatBytes(pull.total)} · ` : ''}{pull.status || 'working…'}
      </p>
      <p className="mt-1 text-[10px] text-slate-600">First download can take a few minutes — you can keep this open.</p>
    </div>
  );
}

/** Turnkey Ollama onboarding: detect the server + models, download a model with a
 *  live progress bar, pick which model to use — no terminal required. */
function OllamaSetup({ status, onSaved, onRefresh }) {
  const { toast } = useToast();
  const p = (status && status.providers && status.providers.ollama) || {};
  const step = ollamaSetupState(status);
  const installed = Array.isArray(p.models) ? p.models : [];
  const recommended = Array.isArray(p.recommended) && p.recommended.length ? p.recommended : OLLAMA_RECOMMENDED;
  const note = (PROVIDER_HINTS.ollama || {}).note;

  const [selected, setSelected] = useState(p.model || 'llama3.1');
  const [pull, setPull] = useState(null);       // { model, percent, status } while downloading
  const [busy, setBusy] = useState(false);
  const pullAbort = useRef(null);

  useEffect(() => { if (p.model) setSelected(p.model); }, [p.model]);

  // Poll while waiting on the server / a model so the card advances on its own once
  // the operator installs and starts Ollama (no manual refresh needed).
  useEffect(() => {
    if (!onRefresh || pull) return undefined;
    if (step !== 'server_down' && step !== 'need_model' && step !== 'unknown') return undefined;
    const id = setInterval(onRefresh, 2500);
    return () => clearInterval(id);
  }, [step, pull, onRefresh]);

  useEffect(() => () => { if (pullAbort.current) pullAbort.current.abort(); }, []);

  const downloadModel = async (model) => {
    setPull({ model, percent: 0, status: 'starting' });
    const controller = new AbortController();
    pullAbort.current = controller;
    let failed = null;
    try {
      const resp = await authFetch('/api/copilot/ollama/pull', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model }), signal: controller.signal,
      });
      if (!resp.ok || !resp.body) throw new Error('pull failed');
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const { events, rest } = parseSSE(buf);
        buf = rest;
        for (const ev of events) {
          if (ev.type === 'progress') {
            setPull({ model, percent: ev.percent, status: ev.status, completed: ev.completed, total: ev.total });
          } else if (ev.type === 'error') {
            failed = ev.message;
          }
        }
      }
      if (failed) {
        toast(failed, { type: 'error' });
      } else {
        setSelected(model);
        await authFetch('/api/copilot/model', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ provider: 'ollama', model }),
        }).catch(() => {});
        toast(`${model} downloaded and selected.`, { type: 'success' });
      }
    } catch (e) {
      if (e.name !== 'AbortError') toast('Download failed — is Ollama running?', { type: 'error' });
    } finally {
      setPull(null);
      pullAbort.current = null;
      if (onRefresh) await onRefresh();
    }
  };

  const useOllama = async () => {
    setBusy(true);
    try {
      if (selected && selected !== p.model) {
        await authFetch('/api/copilot/model', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ provider: 'ollama', model: selected }),
        });
      }
      const r = await authFetch('/api/copilot/provider', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'ollama' }),
      });
      const d = await r.json().catch(() => ({}));
      toast('Ollama connected.', { type: 'success' });
      onSaved((d && d.status) || null);
    } catch {
      toast('Could not select Ollama.', { type: 'error' });
    } finally {
      setBusy(false);
    }
  };

  if (step === 'sdk_missing') {
    return (
      <div className="rounded-md border border-amber/30 bg-amber/5 p-2.5 text-[11px] leading-relaxed text-amber">
        The backend needs the <code>openai</code> SDK to talk to Ollama
        (<code>pip install openai</code>), then restart the backend.
      </div>
    );
  }

  if (step === 'ready') {
    return (
      <div className="space-y-2.5">
        <p className="text-[11px] font-semibold text-matrix">✓ Ollama is running with {p.model} — ready to chat.</p>
        {installed.length > 1 && (
          <label className="block text-[11px] text-slate-400">
            Model
            <select
              value={selected} onChange={(e) => setSelected(e.target.value)}
              className={`${fieldCls} mt-1`}
            >
              {installed.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
          </label>
        )}
        <button type="button" onClick={useOllama} disabled={busy} className={primaryBtn}>
          {busy ? 'Connecting…' : 'Use Ollama'}
        </button>
      </div>
    );
  }

  if (step === 'need_model') {
    return (
      <div className="space-y-2.5">
        <p className="text-[11px] font-semibold text-matrix">✓ Ollama is running. Download a model to finish:</p>
        {pull ? (
          <PullProgress pull={pull} />
        ) : (
          <>
            <div className="space-y-1.5">
              {recommended.map((m) => (
                <button
                  key={m.name} type="button" onClick={() => downloadModel(m.name)}
                  className="flex w-full items-center justify-between gap-2 rounded-md border border-slate-700 bg-steel-900 px-2.5 py-2 text-left transition hover:border-matrix/50 hover:bg-matrix/5"
                >
                  <span className="min-w-0">
                    <span className="block truncate text-xs font-semibold text-slate-100">
                      {m.label}{m.recommended && <span className="ml-1.5 text-[9px] uppercase tracking-wide text-matrix">recommended</span>}
                    </span>
                    <span className="block truncate text-[10px] text-slate-500">{m.size} · {m.note}</span>
                  </span>
                  <span className="shrink-0 text-[11px] font-semibold text-matrix">Download</span>
                </button>
              ))}
            </div>
            {installed.length > 0 && (
              <div className="flex items-end gap-2 border-t border-slate-800 pt-2">
                <label className="min-w-0 flex-1 text-[11px] text-slate-400">
                  …or use an installed model
                  <select value={selected} onChange={(e) => setSelected(e.target.value)} className={`${fieldCls} mt-1`}>
                    {installed.map((m) => <option key={m} value={m}>{m}</option>)}
                  </select>
                </label>
                <button type="button" onClick={useOllama} disabled={busy} className="shrink-0 rounded-md border border-matrix/50 bg-matrix/10 px-3 py-1.5 text-xs font-semibold text-matrix transition hover:bg-matrix hover:text-steel-950 disabled:opacity-50">
                  Use
                </button>
              </div>
            )}
          </>
        )}
      </div>
    );
  }

  // server_down / unknown — guide install, then auto-detect.
  return (
    <div className="space-y-2">
      <p className="text-[11px] leading-relaxed text-slate-300">
        {note}{' '}
        <a href="https://ollama.com/download" target="_blank" rel="noreferrer" className="font-semibold text-sky-400 hover:underline">
          Download Ollama ↗
        </a>
      </p>
      <div className="flex items-center gap-2 rounded-md border border-amber/30 bg-amber/5 px-2.5 py-2 text-[11px] text-amber">
        <span className="h-2 w-2 shrink-0 animate-pulse rounded-full bg-amber" />
        <span>Waiting for Ollama… once installed it starts on its own (or run <code>ollama serve</code>).</span>
      </div>
      <button type="button" onClick={() => onRefresh && onRefresh()} className={primaryBtn}>
        Re-check
      </button>
    </div>
  );
}

/** Provider chooser + credentials — shown when nothing is ready, or via the gear.
 *  Four providers, the two free ones (Ollama · Gemini) first. Ollama gets a full
 *  turnkey setup wizard; the cloud providers get a key field. */
function ConnectCard({ status, onSaved, onRefresh }) {
  const { toast } = useToast();
  const [provider, setProvider] = useState((status && status.active) || 'ollama');
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);

  const hint = PROVIDER_HINTS[provider] || {};
  const keyless = !!hint.keyless;

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
      const pr = await authFetch('/api/copilot/provider', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider }),
      });
      const pd = await pr.json().catch(() => ({}));
      if (!pr.ok) throw new Error(pd.error || 'Could not select the provider.');
      setKey('');
      toast(`${PROVIDER_LABELS[provider]} connected.`, { type: 'success' });
      onSaved((pd && pd.status) || null);
    } catch (e) {
      toast(e.message, { type: 'error' });
    } finally {
      setBusy(false);
    }
  };

  const providerStatus = (status && status.providers && status.providers[provider]) || null;
  const sdkMissing = providerStatus && !providerStatus.sdk_installed;
  const freeTag = provider === 'gemini';

  return (
    <div className="space-y-3 rounded-lg border border-slate-700/70 bg-steel-900/60 p-3">
      <div>
        <div className="mb-1.5 flex items-center justify-between">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">AI provider</span>
          <span className="text-[9px] font-medium uppercase tracking-wide text-matrix">2 free options</span>
        </div>
        <div className="grid grid-cols-2 gap-2">
          {PROVIDER_ORDER.map((pv) => {
            const active = provider === pv;
            const tag = (PROVIDER_HINTS[pv] || {}).tag;
            const free = pv === 'ollama' || pv === 'gemini';
            return (
              <button
                key={pv} type="button" onClick={() => setProvider(pv)} aria-pressed={active}
                className={`rounded-md border px-2 py-1.5 text-left transition ${
                  active
                    ? 'border-sky-500/50 bg-sky-500/10 text-sky-300'
                    : 'border-slate-700 bg-steel-900 text-slate-400 hover:text-slate-200'
                }`}
              >
                <span className="block text-xs font-semibold">{PROVIDER_LABELS[pv]}</span>
                {tag && (
                  <span className={`mt-0.5 block text-[9px] font-medium uppercase tracking-wide ${
                    free ? 'text-matrix' : 'text-slate-500'}`}>
                    {tag}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {keyless ? (
        <OllamaSetup status={status} onSaved={onSaved} onRefresh={onRefresh} />
      ) : (
        <>
          <div>
            <label htmlFor="eg-copilot-key" className="mb-1 block text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              API key {freeTag && <span className="ml-1 text-matrix">(free)</span>}
            </label>
            <input
              id="eg-copilot-key" type="password" autoComplete="off" value={key}
              onChange={(e) => setKey(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') save(); }}
              placeholder={hint.placeholder || 'API key'} className={fieldCls}
            />
            <p className="mt-1 text-[10px] text-slate-500">
              {hint.note ? `${hint.note} ` : ''}Stored on your machine (0600, gitignored) — never logged.{' '}
              {hint.url && (
                <a href={hint.url} target="_blank" rel="noreferrer" className="text-sky-400 hover:underline">
                  {hint.linkText || 'Get a key ↗'}
                </a>
              )}
            </p>
            {sdkMissing && (
              <p className="mt-1 text-[10px] text-amber">
                The {PROVIDER_LABELS[provider]} SDK isn’t installed on the backend
                (<code>pip install {provider === 'gemini' ? 'openai' : provider}</code>) — the key saves, but chat needs the SDK.
              </p>
            )}
          </div>
          <button type="button" onClick={save} disabled={busy} className={primaryBtn}>
            {busy ? 'Saving…' : 'Connect'}
          </button>
        </>
      )}
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

  // Fetch copilot status (used on open and to refresh during Ollama setup polling).
  const loadStatus = useCallback(async () => {
    try {
      const r = await authFetch('/api/copilot');
      const d = r.ok ? await r.json() : null;
      setStatus(d);
      return d;
    } catch {
      return null;
    }
  }, []);

  // Load status on open; open the connect card if nothing is ready.
  useEffect(() => {
    let alive = true;
    loadStatus().then((d) => { if (alive) setShowConnect(!isReady(d)); });
    return () => {
      alive = false;
      if (abortRef.current) abortRef.current.abort();
    };
  }, [loadStatus]);

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
              onRefresh={loadStatus}
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
