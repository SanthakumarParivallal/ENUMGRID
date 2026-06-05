import React from 'react';
import { ScanProvider } from './context/ScanContext.jsx';
import IndustrialDashboard from './IndustrialDashboard.jsx';

/**
 * App shell. The ScanProvider owns all scan state (the SSE/stream ingestion
 * point) and exposes it to the dashboard via the `useScan` hook.
 */
export default function App() {
  return (
    <ScanProvider>
      <IndustrialDashboard />
    </ScanProvider>
  );
}
