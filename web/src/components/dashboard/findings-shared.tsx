import { useEffect, useRef, useState, type ComponentProps, type ReactNode } from 'react'
import { cn } from 'cn'
import { AlertCircle, Check, Copy, Loader2, RotateCw } from 'lucide-react'
import { toast } from 'sonner'
import { ApiError, errorMessage } from '@/lib/api'
import { copyText } from '@/lib/clipboard'
import { useConsole } from '@/lib/console-context'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  formatTimestamp,
  permissionRequirement,
  REDACTION_MARKER,
  VERDICT_LABEL,
} from '@/components/dashboard/findings-format'
import type { FindingView, Permission, Severity, TriageVerdict } from '@/types/api'

/**
 * Small presentation helpers shared by the findings, remediation and patch views.
 * Nothing in here fabricates data: every helper only formats values it is given.
 */

// ───────────────────────────── permissions ─────────────────────────────

type ButtonProps = ComponentProps<typeof Button>

/**
 * A button that is disabled (with an explanatory tooltip) when the session lacks `permission`
 * or when `disabledReason` is set. The server still enforces the permission.
 */
export function GatedButton({
  permission,
  disabledReason,
  disabled,
  children,
  ...props
}: ButtonProps & { permission: Permission; disabledReason?: string | null }) {
  const { can } = useConsole()
  const hint = !can(permission) ? permissionRequirement(permission) : (disabledReason ?? null)
  if (!hint) {
    return (
      <Button disabled={disabled} {...props}>
        {children}
      </Button>
    )
  }
  return (
    <Tooltip>
      <TooltipTrigger render={<span className="inline-flex cursor-not-allowed" tabIndex={0} />}>
        <Button disabled {...props}>
          {children}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{hint}</TooltipContent>
    </Tooltip>
  )
}

// ───────────────────────────── severity & triage ─────────────────────────────

const SEVERITY_CLASS: Record<Severity, string> = {
  Critical: 'border-rose-500/40 bg-rose-500/15 text-rose-300',
  High: 'border-orange-500/40 bg-orange-500/15 text-orange-300',
  Medium: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  Low: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
  Informational: 'border-zinc-600 bg-zinc-800/60 text-zinc-300',
  Unknown: 'border-dashed border-zinc-600 text-zinc-400',
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <Badge variant="outline" className={cn('text-[10px] font-semibold', SEVERITY_CLASS[severity], className)}>
      {severity}
    </Badge>
  )
}

const VERDICT_CLASS: Record<TriageVerdict, string> = {
  confirmed: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
  needs_validation: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  rejected: 'border-zinc-600 bg-zinc-800/60 text-zinc-400',
}

export function TriageBadge({ triage }: { triage: FindingView['triage'] }) {
  if (!triage) {
    return (
      <Badge variant="outline" className="text-[10px] border-zinc-700 text-zinc-500">
        Untriaged
      </Badge>
    )
  }
  return (
    <Badge variant="outline" className={cn('text-[10px]', VERDICT_CLASS[triage.verdict])}>
      {VERDICT_LABEL[triage.verdict]}
    </Badge>
  )
}

export function Timestamp({ value, className }: { value: string | null | undefined; className?: string }) {
  return (
    <time dateTime={value ?? undefined} title={value ?? undefined} className={className}>
      {formatTimestamp(value)}
    </time>
  )
}

// ───────────────────────────── redaction markers ─────────────────────────────

/**
 * Renders scanner output (finding snippets, taint-step code) with every core `[REDACTED]` marker
 * visually flagged. Workspace file content uses whole-line bridge markers instead; see SourceViewer.
 */
export function RedactedText({ text }: { text: string }) {
  if (!text.includes(REDACTION_MARKER)) return <>{text}</>
  const parts = text.split(REDACTION_MARKER)
  return (
    <>
      {parts.map((part, index) => (
        <span key={index}>
          {part}
          {index < parts.length - 1 && (
            <span
              className="rounded-sm border border-amber-500/40 bg-amber-500/15 px-1 text-amber-300"
              title="Value redacted before it reached the console"
            >
              redacted
            </span>
          )}
        </span>
      ))}
    </>
  )
}

// ───────────────────────────── feedback ─────────────────────────────

export function ErrorAlert({
  error,
  title = 'Request failed',
  onRetry,
  className,
}: {
  error: unknown
  title?: string
  onRetry?: () => void
  className?: string
}) {
  const status = error instanceof ApiError && error.status > 0 ? `HTTP ${error.status} · ${error.code}` : null
  return (
    <Alert variant="destructive" className={cn('border-rose-500/30 bg-rose-950/20', className)}>
      <AlertCircle />
      <AlertTitle className="text-xs">{title}</AlertTitle>
      <AlertDescription className="flex flex-col gap-2 text-xs">
        <span className="text-rose-200/90">{errorMessage(error)}</span>
        {status && <span className="font-mono text-[10px] text-rose-300/70">{status}</span>}
        {onRetry && (
          <Button variant="outline" size="xs" className="w-fit" onClick={onRetry}>
            <RotateCw /> Retry
          </Button>
        )}
      </AlertDescription>
    </Alert>
  )
}

export function CopyButton({ text, label = 'Copy', className }: { text: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  const timer = useRef<number | null>(null)
  useEffect(() => () => {
    if (timer.current !== null) window.clearTimeout(timer.current)
  }, [])
  async function handleCopy() {
    const ok = await copyText(text)
    if (!ok) {
      toast.error('Copy failed', { description: 'The browser denied clipboard access.' })
      return
    }
    setCopied(true)
    if (timer.current !== null) window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setCopied(false), 1500)
  }
  return (
    <Button
      variant="ghost"
      size="xs"
      className={cn('text-zinc-400 hover:text-zinc-100', className)}
      onClick={() => void handleCopy()}
      title={label}
    >
      {copied ? <Check className="text-emerald-400" /> : <Copy />}
      {copied ? 'Copied' : label}
    </Button>
  )
}

/** Labelled container used for detail sections. */
export function DetailSection({
  title,
  aside,
  children,
  className,
}: {
  title: string
  aside?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={cn('flex flex-col gap-2', className)}>
      <div className="flex items-center justify-between gap-2">
        <h4 className="text-[11px] font-semibold uppercase tracking-wide text-zinc-500">{title}</h4>
        {aside}
      </div>
      {children}
    </section>
  )
}

// ───────────────────────────── confirmation ─────────────────────────────

/**
 * Explicit confirmation for outward-facing or destructive actions. The body must state exactly
 * what will happen. The dialog cannot be dismissed while the action runs.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  children,
  confirmLabel,
  destructive = false,
  busy = false,
  confirmDisabled = false,
  onConfirm,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  children: ReactNode
  confirmLabel: string
  destructive?: boolean
  busy?: boolean
  confirmDisabled?: boolean
  onConfirm: () => void
}) {
  return (
    <Dialog open={open} onOpenChange={(next) => (!busy ? onOpenChange(next) : undefined)}>
      <DialogContent className="max-w-lg border border-zinc-800 bg-zinc-950" showCloseButton={!busy}>
        <DialogHeader>
          <DialogTitle className="text-sm text-zinc-100">{title}</DialogTitle>
          <DialogDescription render={<div />} className="flex flex-col gap-2 text-xs text-zinc-400">
            {children}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="border-zinc-800 bg-zinc-900/60">
          <Button variant="outline" size="sm" disabled={busy} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant={destructive ? 'destructive' : 'default'}
            size="sm"
            disabled={busy || confirmDisabled}
            onClick={onConfirm}
          >
            {busy && <Loader2 className="animate-spin" />}
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
