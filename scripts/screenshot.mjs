#!/usr/bin/env node
/**
 * scripts/screenshot.mjs — capture a REAL dashboard screenshot for the README.
 *
 * Drives headless Chrome over the DevTools Protocol (no npm deps — uses Node's
 * built-in fetch + WebSocket): opens the cockpit, runs an actual scan against
 * your local network, waits for results, and writes a PNG. The image is a real
 * scan of YOUR network — never simulated data.
 *
 * Usage:  node scripts/screenshot.mjs [url] [outfile]
 *   defaults: http://127.0.0.1:5173  →  docs/dashboard.png
 * Requires the dev servers running (./start.sh) and Google Chrome installed.
 */
import { spawn } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const URL = process.argv[2] || 'http://127.0.0.1:5173';
const OUT = process.argv[3] || 'docs/dashboard.png';
const CHROME = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const PORT = 9222;
const W = 1440;
const H = 980;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const chrome = spawn(CHROME, [
  '--headless=new', '--disable-gpu', '--hide-scrollbars',
  `--remote-debugging-port=${PORT}`, '--remote-allow-origins=*',
  `--window-size=${W},${H}`, '--force-device-scale-factor=2',
  URL,
], { stdio: 'ignore' });

let nextId = 1;
function cmd(ws, method, params = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const onMsg = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id === id) { ws.removeEventListener('message', onMsg); m.error ? reject(new Error(m.error.message)) : resolve(m.result); }
    };
    ws.addEventListener('message', onMsg);
    ws.send(JSON.stringify({ id, method, params }));
  });
}
const evalJs = (ws, expression) =>
  cmd(ws, 'Runtime.evaluate', { expression, returnByValue: true }).then((r) => r.result.value);

async function main() {
  // Wait for the CDP endpoint, then find the page target.
  let target;
  for (let i = 0; i < 40 && !target; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
      target = list.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
    } catch { /* not up yet */ }
    if (!target) await sleep(250);
  }
  if (!target) throw new Error('Chrome DevTools endpoint never came up');

  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('WS connect failed')); });
  await cmd(ws, 'Page.enable');
  await cmd(ws, 'Runtime.enable');
  await sleep(2500); // let the boot splash auto-dismiss + React mount

  // Kick off a real scan (discovery → auto port-scan of every up host).
  await evalJs(ws, `(() => { const b=[...document.querySelectorAll('button')].find(b=>/start scan/i.test(b.textContent)); if(b) b.click(); return !!b; })()`);

  // Poll until the scan completes (or 150s budget).
  const deadline = Date.now() + 150000;
  let done = false;
  while (Date.now() < deadline) {
    await sleep(4000);
    const st = await evalJs(ws, `(() => { const s=[...document.querySelectorAll('span')].find(s=>s.textContent.trim()==='Phase'); const phase=s?s.nextElementSibling?.textContent?.trim():''; const hosts=(document.body.innerText.match(/(\\d+)\\s*\\/\\s*(\\d+) hosts/)||[])[0]||''; const scanning=/Vuln Scan|Scanning/.test(document.body.innerText); return phase+'|'+hosts+'|'+scanning; })()`);
    const [phase, hosts, scanning] = (st || '').split('|');
    process.stdout.write(`  · ${phase} ${hosts} scanning=${scanning}\n`);
    if (phase === 'Complete' && hosts && !hosts.startsWith('0 ') && scanning === 'false') { done = true; break; }
  }
  await sleep(1500);

  const { data } = await cmd(ws, 'Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, Buffer.from(data, 'base64'));
  console.log(`✓ saved ${OUT} (scan ${done ? 'complete' : 'partial'})`);
  ws.close();
}

main()
  .catch((e) => { console.error('screenshot failed:', e.message); process.exitCode = 1; })
  .finally(() => chrome.kill());
