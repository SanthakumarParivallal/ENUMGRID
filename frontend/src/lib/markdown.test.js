import { describe, it, expect } from 'vitest';
import { renderMarkdown, escapeHtml } from './markdown.js';

describe('escapeHtml', () => {
  it('escapes the four HTML-significant characters', () => {
    expect(escapeHtml('<a href="x">&')).toBe('&lt;a href=&quot;x&quot;&gt;&amp;');
    expect(escapeHtml(null)).toBe('');
  });
});

describe('renderMarkdown — formatting', () => {
  it('renders headings', () => {
    expect(renderMarkdown('# Title')).toContain('>Title</div>');
    expect(renderMarkdown('### Sub')).toMatch(/font-semibold[^>]*>Sub<\/div>/);
  });

  it('renders bold and italic', () => {
    expect(renderMarkdown('a **bold** b')).toContain('<strong>bold</strong>');
    expect(renderMarkdown('a *it* b')).toContain('<em>it</em>');
    // ** must not be misread as italic
    expect(renderMarkdown('**x**')).not.toContain('<em>');
  });

  it('renders inline and fenced code', () => {
    expect(renderMarkdown('use `nmap -sV`')).toContain('<code');
    const fenced = renderMarkdown('```\nnmap -sV 10.0.0.1\n```');
    expect(fenced).toContain('<pre');
    expect(fenced).toContain('nmap -sV 10.0.0.1');
  });

  it('renders unordered and ordered lists', () => {
    const ul = renderMarkdown('- one\n- two');
    expect(ul).toContain('<ul');
    expect((ul.match(/<li>/g) || []).length).toBe(2);
    const ol = renderMarkdown('1. first\n2. second');
    expect(ol).toContain('<ol');
    expect(ol).toContain('<li>first</li>');
  });

  it('renders blockquotes and horizontal rules', () => {
    expect(renderMarkdown('> note')).toContain('<blockquote');
    expect(renderMarkdown('---')).toContain('<hr');
  });

  it('joins soft-wrapped paragraph lines with <br/>', () => {
    expect(renderMarkdown('line one\nline two')).toContain('line one<br/>line two');
  });

  it('handles null / empty input', () => {
    expect(renderMarkdown(null)).toBe('');
    expect(renderMarkdown('')).toBe('');
  });
});

describe('renderMarkdown — links', () => {
  it('links [label](http…) and sets safe rel/target', () => {
    const html = renderMarkdown('[docs](https://example.com/x)');
    expect(html).toContain('href="https://example.com/x"');
    expect(html).toContain('rel="noreferrer noopener"');
    expect(html).toContain('>docs</a>');
  });

  it('autolinks bare URLs', () => {
    expect(renderMarkdown('see https://nvd.nist.gov here')).toContain('href="https://nvd.nist.gov"');
  });

  it('autolinks CVE ids to the NVD detail page', () => {
    const html = renderMarkdown('affected by CVE-2021-44228 (log4shell)');
    expect(html).toContain('href="https://nvd.nist.gov/vuln/detail/CVE-2021-44228"');
    expect(html).toContain('>CVE-2021-44228</a>');
  });
});

describe('renderMarkdown — XSS safety', () => {
  it('escapes raw HTML so it never becomes live markup', () => {
    const html = renderMarkdown('<img src=x onerror=alert(1)>');
    expect(html).not.toContain('<img');
    expect(html).toContain('&lt;img');
  });

  it('drops javascript: (and other non-allow-listed) link schemes', () => {
    const html = renderMarkdown('[click](javascript:alert(1))');
    expect(html).not.toContain('<a ');
    expect(html.toLowerCase()).not.toContain('href="javascript');
  });

  it('does not execute a script tag hidden in a code span', () => {
    const html = renderMarkdown('`<script>alert(1)</script>`');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });
});

describe('renderMarkdown — sentinel collision regression', () => {
  it('leaves plain numbers untouched (would break with a naive placeholder)', () => {
    const html = renderMarkdown('Found 3 open ports and 5 hosts');
    expect(html).toContain('Found 3 open ports and 5 hosts');
    expect(html).not.toContain('undefined');
  });

  it('keeps code adjacent to surrounding words (no injected spaces)', () => {
    expect(renderMarkdown('run`x`now')).toContain('run<code');
  });
});
