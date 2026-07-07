/**
 * markdown.js — a tiny, safe Markdown→HTML renderer for copilot replies.
 * ---------------------------------------------------------------------------
 * LLM answers read far better with headings, lists, code and links than as one
 * grey block of text. We render the small Markdown subset models actually emit —
 * headings, bold/italic, inline + fenced code, ordered/unordered lists,
 * blockquotes, links — and we do it *without a dependency* so there's no new
 * supply-chain surface in a security tool.
 *
 * Safety: this output is injected with `dangerouslySetInnerHTML`, so the golden
 * rule is **all text is HTML-escaped before anything else**. The only tags in the
 * result are ones this file emits; the only hrefs are ones whose scheme we
 * allow-list (http/https/mailto). Raw HTML in the input can never become live
 * markup, and `javascript:`/`data:` link schemes are dropped. Heavily unit-tested,
 * XSS cases included.
 */

const H_CLASS = {
  1: 'mt-1 mb-0.5 text-[13px] font-bold text-slate-100',
  2: 'mt-1 mb-0.5 text-[13px] font-bold text-slate-100',
  3: 'mt-1 mb-0.5 text-xs font-semibold text-slate-200',
  4: 'mt-1 mb-0.5 text-xs font-semibold text-slate-300',
};
const P_CLASS = 'mb-1.5 last:mb-0';
const UL_CLASS = 'my-1 list-disc space-y-0.5 pl-4 marker:text-slate-500';
const OL_CLASS = 'my-1 list-decimal space-y-0.5 pl-4 marker:text-slate-500';
const CODE_CLASS = 'rounded bg-steel-800 px-1 py-0.5 text-[11px] text-matrix';
const PRE_CLASS = 'my-1.5 overflow-x-auto rounded-md border border-slate-800 bg-steel-950 p-2 text-[11px] leading-relaxed text-slate-200';
const QUOTE_CLASS = 'my-1 border-l-2 border-slate-600 pl-2 text-slate-400';
const LINK_CLASS = 'text-sky-400 underline decoration-sky-400/40 underline-offset-2 hover:text-sky-300';
const HR_CLASS = 'my-2 border-slate-700';

const NVD = 'https://nvd.nist.gov/vuln/detail/';

// Private-Use-Area sentinel: can't appear in real reply text, and keeps stashed
// code/link HTML adjacent to surrounding words (no injected spaces).
const S0 = '';
const S1 = '';

/** Escape the four HTML-significant characters. Everything downstream trusts this. */
export function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Allow-list link schemes; input is already HTML-escaped. Returns the url or null. */
function safeUrl(u) {
  const lower = u.trim().toLowerCase();
  if (lower.startsWith('http://') || lower.startsWith('https://') || lower.startsWith('mailto:')) {
    return u.trim();
  }
  return null;
}

/** Bold then italic on an already-escaped fragment. */
function emphasis(str) {
  return str
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/__([^_]+)__/g, '<strong>$1</strong>')
    .replace(/(^|[^*\w])\*([^*\n]+)\*/g, '$1<em>$2</em>')
    .replace(/(^|[^_\w])_([^_\n]+)_/g, '$1<em>$2</em>');
}

/**
 * Inline rendering of one already-HTML-escaped line: code spans, links, bare-URL
 * and CVE autolinks, then emphasis. Code/link HTML is stashed behind sentinels so
 * later passes can't touch its insides.
 */
function inline(escaped) {
  const stash = [];
  const keep = (html) => S0 + (stash.push(html) - 1) + S1;
  let s = escaped;

  // `inline code` — its content is already escaped
  s = s.replace(/`([^`]+)`/g, (_, c) => keep('<code class="' + CODE_CLASS + '">' + c + '</code>'));

  // [label](url) — validate scheme, keep the literal text if it's not allowed
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, label, url) => {
    const safe = safeUrl(url);
    if (!safe) return m;
    return keep(`<a href="${safe}" target="_blank" rel="noreferrer noopener" class="${LINK_CLASS}">${emphasis(label)}</a>`);
  });

  // bare http(s) URLs
  s = s.replace(/(https?:\/\/[^\s<]+[^\s<.,;:!?)])/g, (u) =>
    keep(`<a href="${u}" target="_blank" rel="noreferrer noopener" class="${LINK_CLASS}">${u}</a>`));

  // CVE-YYYY-NNNN → NVD detail page (the reason copilot replies want links)
  s = s.replace(/\bCVE-\d{4}-\d{4,7}\b/gi, (cve) => {
    const id = cve.toUpperCase();
    return keep(`<a href="${NVD}${id}" target="_blank" rel="noreferrer noopener" class="${LINK_CLASS}">${id}</a>`);
  });

  s = emphasis(s);
  return s.replace(new RegExp(S0 + '(\\d+)' + S1, 'g'), (_, i) => stash[Number(i)]);
}

const BLOCK_START = /^(?:```|#{1,6}\s+|\s*[-*+]\s+|\s*\d+\.\s+|\s*>\s?)/;

/** Render a Markdown string to a safe HTML string. */
export function renderMarkdown(md) {
  const lines = String(md == null ? '' : md).replace(/\r\n?/g, '\n').split('\n');
  const out = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // fenced code block ```lang ... ```
    if (/^```/.test(line)) {
      const body = [];
      i += 1;
      while (i < lines.length && !/^```\s*$/.test(lines[i])) { body.push(lines[i]); i += 1; }
      i += 1; // consume closing fence (if any)
      out.push(`<pre class="${PRE_CLASS}"><code>${escapeHtml(body.join('\n'))}</code></pre>`);
      continue;
    }

    if (/^\s*$/.test(line)) { i += 1; continue; }

    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      const lvl = Math.min(h[1].length, 4);
      out.push(`<div class="${H_CLASS[lvl]}">${inline(escapeHtml(h[2].trim()))}</div>`);
      i += 1;
      continue;
    }

    if (/^\s*([-*_])\1{2,}\s*$/.test(line)) { out.push(`<hr class="${HR_CLASS}"/>`); i += 1; continue; }

    if (/^\s*>\s?/.test(line)) {
      const buf = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) { buf.push(lines[i].replace(/^\s*>\s?/, '')); i += 1; }
      out.push(`<blockquote class="${QUOTE_CLASS}">${inline(escapeHtml(buf.join(' ')))}</blockquote>`);
      continue;
    }

    if (/^\s*[-*+]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) { items.push(lines[i].replace(/^\s*[-*+]\s+/, '')); i += 1; }
      out.push(`<ul class="${UL_CLASS}">${items.map((it) => `<li>${inline(escapeHtml(it))}</li>`).join('')}</ul>`);
      continue;
    }

    if (/^\s*\d+\.\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) { items.push(lines[i].replace(/^\s*\d+\.\s+/, '')); i += 1; }
      out.push(`<ol class="${OL_CLASS}">${items.map((it) => `<li>${inline(escapeHtml(it))}</li>`).join('')}</ol>`);
      continue;
    }

    // paragraph — gather consecutive non-blank, non-block lines
    const para = [];
    while (i < lines.length && !/^\s*$/.test(lines[i]) && !BLOCK_START.test(lines[i])) {
      para.push(lines[i]);
      i += 1;
    }
    out.push(`<p class="${P_CLASS}">${para.map((l) => inline(escapeHtml(l))).join('<br/>')}</p>`);
  }

  return out.join('');
}
