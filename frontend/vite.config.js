import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

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
        target: 'http://127.0.0.1:8011',
        changeOrigin: true,
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
