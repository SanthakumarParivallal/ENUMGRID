import React from 'react';

/**
 * ErrorBoundary — catches any rendering error in the dashboard tree and shows a
 * friendly, themed recovery screen instead of a blank page. The scan backend is
 * a separate process, so a UI error never affects a running scan; the user can
 * reload to recover. React error boundaries must be class components.
 */
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Keep a console record for debugging; never crash to a blank screen.
    // eslint-disable-next-line no-console
    console.error('[enumgrid] UI error:', error, info?.componentStack);
  }

  handleReload = () => {
    this.setState({ error: null });
    if (typeof window !== 'undefined') window.location.reload();
  };

  render() {
    if (this.state.error) {
      return (
        <div className="flex h-screen flex-col items-center justify-center bg-steel-950 p-6 text-center text-slate-200">
          <div className="max-w-md rounded-lg border border-crimson/40 bg-crimson/10 p-6">
            <h1 className="mb-2 font-mono text-lg font-semibold text-crimson">Interface error</h1>
            <p className="mb-3 text-sm text-slate-400">
              The dashboard hit an unexpected error and stopped rendering. Your scan
              backend is unaffected — reload to recover. If it persists, check the
              browser console and report it.
            </p>
            <p className="mb-4 break-words rounded bg-black/40 px-2 py-1 text-left font-mono text-[11px] text-slate-500">
              {String(this.state.error?.message || this.state.error)}
            </p>
            <button
              onClick={this.handleReload}
              className="rounded border border-matrix/50 bg-matrix/10 px-4 py-2 text-sm font-semibold text-matrix transition hover:bg-matrix hover:text-steel-950"
            >
              Reload dashboard
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
