import { ScanProvider } from './context/ScanContext.jsx';
import { ToastProvider } from './lib/toast.jsx';
import IndustrialDashboard from './IndustrialDashboard.jsx';
import ErrorBoundary from './ErrorBoundary.jsx';

/**
 * App shell. The ScanProvider owns all scan state (the SSE/stream ingestion
 * point) and exposes it to the dashboard via the `useScan` hook. ToastProvider
 * wraps it so any component (and the <ScanToasts/> watcher) can raise action
 * feedback. An outer ErrorBoundary turns any unexpected UI error into a
 * recoverable screen rather than a blank page.
 */
export default function App() {
  return (
    <ErrorBoundary>
      <ToastProvider>
        <ScanProvider>
          <IndustrialDashboard />
        </ScanProvider>
      </ToastProvider>
    </ErrorBoundary>
  );
}
