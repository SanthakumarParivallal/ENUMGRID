import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// When the backend runs with TLS (./start.sh --tls), proxy to https and don't
// reject its self-signed cert. Defaults to plain http for the normal dev flow.
const apiHttps = process.env.VITE_API_HTTPS === '1';
const apiPort = process.env.BACKEND_PORT || '8011';
const apiTarget = `${apiHttps ? 'https' : 'http'}://127.0.0.1:${apiPort}`;

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    // Forward API + SSE calls to the FastAPI backend so the browser hits a
    // same-origin endpoint in dev (no CORS, EventSource just works).
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
        secure: false, // accept the backend's self-signed cert in --tls mode
        // Don't buffer the Server-Sent Events stream.
        configure: (proxy) => {
          proxy.on('proxyRes', (proxyRes) => {
            proxyRes.headers['cache-control'] = 'no-cache, no-transform';
          });
        },
      },
    },
  },

  // Vitest: unit tests run in jsdom so the lib modules that touch the DOM
  // (localStorage, document, Blob/URL, focus, timers) exercise real browser
  // APIs rather than stubs.
  test: {
    environment: 'jsdom',
    // A concrete origin (not the opaque about:blank default) so jsdom enables
    // window.localStorage — the auth token + view-preference modules persist
    // there, and their real read/write branches must run under test.
    environmentOptions: { jsdom: { url: 'http://localhost:5173/' } },
    setupFiles: ['./vitest.setup.js'],
    include: ['src/**/*.test.{js,jsx}'],
    // Coverage is gated on src/lib/** only — the pure logic + security layer
    // (schema coercion, markdown XSS escaping, CSV formula-injection defence,
    // auth token handling, the toast/focus-trap primitives, preferences, the
    // offline scan engine). These are the frontend peer of the CLI/backend
    // 100% gate and are covered honestly (real DOM, real timers; nothing
    // mock-stubbed to fake a line). The large stateful view components
    // (IndustrialDashboard, ScanContext, CopilotPanel) are verified by ESLint
    // (react-hooks + jsx-a11y) and the preview/E2E path, not force-driven to
    // 100% in jsdom — that would be coverage theatre, not a real guarantee.
    coverage: {
      provider: 'v8',
      include: ['src/lib/**/*.{js,jsx}'],
      reporter: ['text', 'text-summary'],
      // Gated on lines + functions + statements at 100%, per file — the same
      // line-coverage standard the Python CLI/backend are held to in CI. Branch
      // coverage is reported for insight but not gated at 100, so genuinely
      // unreachable defensive fallbacks (e.g. `x || safeDefault` where x is
      // always set) don't have to be stripped out of otherwise-robust code.
      thresholds: {
        perFile: true,
        lines: 100,
        functions: 100,
        statements: 100,
      },
    },
  },
});
