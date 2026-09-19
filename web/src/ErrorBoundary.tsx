import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props { children: ReactNode }
interface State { error: Error | null }

/** Keeps a render crash from blanking the whole app: shows the error and a
 *  reset button instead of unmounting to a black page. */
export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[fugu] render crash:", error, info.componentStack);
  }

  override render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-8">
          <p className="font-mono text-sm font-bold uppercase tracking-[0.3em] text-red-400">
            fugu · render error
          </p>
          <pre className="max-w-2xl overflow-auto rounded-lg border border-red-900/60 bg-red-950/30 p-4 font-mono text-xs text-red-200">
            {this.state.error.message}
          </pre>
          <button
            onClick={() => { this.setState({ error: null }); location.reload(); }}
            className="rounded-md border border-zinc-700 px-4 py-2 font-mono text-xs text-zinc-300 transition-colors hover:bg-zinc-800"
          >
            reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
