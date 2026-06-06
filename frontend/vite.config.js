import { defineConfig } from 'vite';
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
});
