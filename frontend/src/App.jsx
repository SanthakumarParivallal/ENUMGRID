import React from 'react';
import { ScanProvider } from './context/ScanContext.jsx';
import IndustrialDashboard from './IndustrialDashboard.jsx';
import ErrorBoundary from './ErrorBoundary.jsx';

/**
 * App shell. The ScanProvider owns all scan state (the SSE/stream ingestion
 * point) and exposes it to the dashboard via the `useScan` hook. An outer
 * ErrorBoundary turns any unexpected UI error into a recoverable screen rather
 * than a blank page.
 */
export default function App() {
  return (
    <ErrorBoundary>
      <ScanProvider>
        <IndustrialDashboard />
      </ScanProvider>
    </ErrorBoundary>
  );
}
