import type { ReactNode } from 'react'
import { CircleAlert, LoaderCircle, RefreshCw } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { errorMessage } from '@/lib/api'
import type { ScanStatus } from '@/types/api'

export function RunStatusBadge({ status }: { status: ScanStatus }) {
  if (status === 'running') {
    return (
      <Badge variant="outline" className="text-[10px] font-mono border-sky-500/40 text-sky-300 gap-1">
        <LoaderCircle className="size-2.5 animate-spin" />
        running
      </Badge>
    )
  }
  if (status === 'failed') {
    return (
      <Badge variant="outline" className="text-[10px] font-mono border-rose-500/40 text-rose-300">
        failed
      </Badge>
    )
  }
  return (
    <Badge variant="outline" className="text-[10px] font-mono border-emerald-500/40 text-emerald-300">
      completed
    </Badge>
  )
}

export function LoadError({ title, error, onRetry }: { title: string; error: unknown; onRetry: () => void }) {
  return (
    <Alert variant="destructive" className="border-rose-500/40 bg-rose-500/5">
      <CircleAlert />
      <AlertTitle className="text-xs">{title}</AlertTitle>
      <AlertDescription className="text-xs flex flex-col items-start gap-2">
        <span className="break-words">{errorMessage(error)}</span>
        <Button size="xs" variant="outline" onClick={onRetry}>
          <RefreshCw className="size-3" />
          Retry
        </Button>
      </AlertDescription>
    </Alert>
  )
}

/** Label/value pair used in compact detail lists. */
export function Field({ label, children, mono = false }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-3 text-xs py-1 border-b border-zinc-800/60 last:border-b-0">
      <span className="text-zinc-500 shrink-0">{label}</span>
      <span className={`text-zinc-200 text-right min-w-0 break-all ${mono ? 'font-mono text-[11px]' : ''}`}>{children}</span>
    </div>
  )
}
