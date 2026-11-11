import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, RotateCw } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

interface ViewErrorBoundaryProps {
  /** Heading of the fallback, e.g. "This view could not be shown". */
  title?: string
  children: ReactNode
}

interface ViewErrorBoundaryState {
  error: Error | null
}

/**
 * Keeps a rendering error inside one view or section instead of unmounting the whole console (React
 * renders nothing at all when an error escapes every boundary). The fallback shows the error and the
 * most common cause in development: Vite reloaded the console while the bridge kept running older
 * code, so a response lacks fields this console expects.
 */
export class ViewErrorBoundary extends Component<ViewErrorBoundaryProps, ViewErrorBoundaryState> {
  state: ViewErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: unknown): ViewErrorBoundaryState {
    return { error: error instanceof Error ? error : new Error(String(error)) }
  }

  componentDidCatch(error: unknown, info: ErrorInfo): void {
    console.error('[sentra-console] a view failed to render', error, info.componentStack)
  }

  render(): ReactNode {
    const { error } = this.state
    if (!error) return this.props.children
    return (
      <Alert variant="destructive" className="border-rose-500/30 bg-rose-500/5">
        <AlertTriangle />
        <AlertTitle className="text-xs font-semibold">{this.props.title ?? 'This view could not be shown'}</AlertTitle>
        <AlertDescription className="flex flex-col items-start gap-2 text-xs">
          <span className="font-mono break-words">{error.message || error.name}</span>
          <span>
            If the bridge was not restarted after an update, it may be sending data in an older shape than this console expects.
            Restart the bridge (for example stop and rerun <span className="font-mono">bun run dev</span>), then retry. Other views
            are not affected.
          </span>
          <Button variant="outline" size="xs" onClick={() => this.setState({ error: null })}>
            <RotateCw /> Retry
          </Button>
        </AlertDescription>
      </Alert>
    )
  }
}
