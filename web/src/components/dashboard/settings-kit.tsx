import { useState, type ReactElement, type ReactNode } from 'react'
import { AlertTriangle, Check, Copy, Loader2, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { ApiError, errorMessage } from '@/lib/api'
import { copyText } from '@/lib/clipboard'
import { useConsole } from '@/lib/console-context'
import type { Permission } from '@/types/api'
import { minimumRoleFor } from './console-format'
import { formatDateTime, permissionHint, relativeTime } from './settings-format'

/**
 * Small UI building blocks shared by the Pull Requests, Webhooks and Settings tabs: honest
 * error/loading states, permission-gated actions, confirmation dialogs and formatting helpers.
 */

/**
 * Renders `children` (a button) when the session holds `permission`; otherwise renders the same
 * control disabled, wrapped in a tooltip that names the missing role and permission.
 */
export function PermissionGate({
  permission,
  children,
  disabledChildren,
}: {
  permission: Permission
  children: ReactElement
  /** The disabled variant to show when the permission is missing. */
  disabledChildren: ReactElement
}) {
  const { can } = useConsole()
  if (can(permission)) return children
  return (
    <Tooltip>
      <TooltipTrigger render={<span className="inline-flex cursor-not-allowed" tabIndex={0} />}>{disabledChildren}</TooltipTrigger>
      <TooltipContent>{permissionHint(permission)}</TooltipContent>
    </Tooltip>
  )
}

/** Button that is disabled with an explanatory tooltip when the permission is missing. */
export function GatedButton({
  permission,
  onClick,
  disabled,
  busy,
  children,
  variant = 'outline',
  size = 'sm',
  className,
}: {
  permission: Permission
  onClick: () => void
  disabled?: boolean
  busy?: boolean
  children: ReactNode
  variant?: 'default' | 'outline' | 'secondary' | 'ghost' | 'destructive'
  size?: 'xs' | 'sm' | 'default'
  className?: string
}) {
  const content = (
    <>
      {busy && <Loader2 className="size-3 animate-spin" />}
      {children}
    </>
  )
  return (
    <PermissionGate
      permission={permission}
      disabledChildren={
        <Button type="button" variant={variant} size={size} className={className} disabled>
          {content}
        </Button>
      }
    >
      <Button type="button" variant={variant} size={size} className={className} onClick={onClick} disabled={disabled || busy}>
        {content}
      </Button>
    </PermissionGate>
  )
}

/** Error banner that shows the bridge's real message and code, with a retry action. */
export function ErrorState({ error, onRetry, title = 'Request failed' }: { error: unknown; onRetry?: () => void; title?: string }) {
  const code = error instanceof ApiError ? error.code : null
  return (
    <Alert variant="destructive" className="border-rose-500/30 bg-rose-500/5">
      <AlertTriangle />
      <AlertTitle className="text-xs font-semibold">{title}</AlertTitle>
      <AlertDescription className="text-xs flex flex-col gap-2">
        <span className="break-words">
          {errorMessage(error)}
          {code && <span className="ml-1 font-mono text-[10px] opacity-70">({code})</span>}
        </span>
        {onRetry && (
          <span>
            <Button type="button" variant="outline" size="xs" onClick={onRetry} className="gap-1">
              <RefreshCw className="size-3" />
              Retry
            </Button>
          </span>
        )}
      </AlertDescription>
    </Alert>
  )
}

export function LoadingRows({ rows = 3, className = 'h-14' }: { rows?: number; className?: string }) {
  return (
    <div className="flex flex-col gap-2" aria-busy="true">
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton key={index} className={`w-full ${className}`} />
      ))}
    </div>
  )
}

/**
 * Confirmation dialog for outward-facing or destructive actions. The description must state
 * exactly what will happen; the confirm button stays busy until `onConfirm` settles.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  children,
  confirmLabel,
  destructive = false,
  onConfirm,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  children: ReactNode
  confirmLabel: string
  destructive?: boolean
  /** Resolve to close the dialog; throw to keep it open (the caller reports the error). */
  onConfirm: () => Promise<void>
}) {
  const [busy, setBusy] = useState(false)
  async function confirm() {
    setBusy(true)
    try {
      await onConfirm()
      onOpenChange(false)
    } catch {
      // The caller already surfaced the error; keep the dialog open so the operator can retry.
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open={open} onOpenChange={(next) => (!busy ? onOpenChange(next) : undefined)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="text-sm font-semibold">{title}</DialogTitle>
          <DialogDescription render={<div />} className="text-xs flex flex-col gap-2 text-muted-foreground">
            {children}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button type="button" variant="outline" size="sm" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button type="button" variant={destructive ? 'destructive' : 'default'} size="sm" onClick={() => void confirm()} disabled={busy}>
            {busy && <Loader2 className="size-3 animate-spin" />}
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Copy button that reports the real clipboard outcome. */
export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    const ok = await copyText(text)
    if (!ok) {
      toast.error('Copy failed', { description: 'The browser did not allow clipboard access. Select the text and copy it manually.' })
      return
    }
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1500)
  }
  return (
    <Button type="button" variant="ghost" size="xs" onClick={() => void copy()} className="gap-1 text-muted-foreground hover:text-foreground">
      {copied ? <Check className="size-3 text-emerald-400" /> : <Copy className="size-3" />}
      {copied ? 'Copied' : label}
    </Button>
  )
}

export function NoTenantState({ feature }: { feature: string }) {
  return (
    <div className="rounded-lg border border-dashed border-border/60 bg-card/30 p-8 text-center text-xs text-muted-foreground">
      No workspace is selected. Register a workspace ({minimumRoleFor('tenant:create')}) to use {feature}.
    </div>
  )
}

/** Relative time with the exact local and ISO timestamps on hover. */
export function TimeAgo({ iso, className }: { iso: string | null | undefined; className?: string }) {
  if (!iso) return <span className={className}>—</span>
  return (
    <time dateTime={iso} title={`${formatDateTime(iso)} (${iso})`} className={className}>
      {relativeTime(iso)}
    </time>
  )
}
