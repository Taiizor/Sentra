import { useState, type ComponentProps, type ReactNode } from 'react'
import { AlertTriangle, Check, Copy, FolderX, Loader2, RotateCw } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { copyText } from '@/lib/clipboard'
import { errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { cn } from '@/lib/utils'
import type { Permission, Severity } from '@/types/api'
import { minimumRoleFor, permissionHint, SEVERITY_CLASS } from './console-format'

/**
 * Small UI building blocks shared by the research, fleet, intel, plugin, studio, console and
 * scan-stream views: permission-aware buttons, honest loading / error / empty states and a
 * confirmation dialog for outward-facing actions.
 */

type ButtonProps = ComponentProps<typeof Button>

/**
 * A button that is disabled with an explanatory tooltip when the session lacks `permission`
 * or when `blockedReason` is set. The server enforces the same permission independently.
 */
export function GatedButton({
  permission,
  blockedReason,
  disabled,
  children,
  ...props
}: ButtonProps & { permission: Permission; blockedReason?: string | null }) {
  const { can } = useConsole()
  const reason = !can(permission) ? permissionHint(permission) : (blockedReason ?? null)
  if (!reason) {
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
      <TooltipContent>{reason}</TooltipContent>
    </Tooltip>
  )
}

export function TabHeader({
  icon,
  title,
  description,
  actions,
}: {
  icon: ReactNode
  title: string
  description: ReactNode
  actions?: ReactNode
}) {
  return (
    <div className="flex flex-col gap-3 border-b border-border/40 pb-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="flex min-w-0 flex-col gap-1">
        <div className="flex items-center gap-2">
          {icon}
          <h2 className="text-base font-semibold tracking-tight text-foreground">{title}</h2>
        </div>
        <div className="max-w-3xl text-xs text-muted-foreground">{description}</div>
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function SectionCard({
  title,
  icon,
  description,
  actions,
  children,
  className,
}: {
  title: ReactNode
  icon?: ReactNode
  description?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <Card size="sm" className={cn('border-border/60 bg-card/40', className)}>
      <CardHeader className="border-b border-border/40">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex min-w-0 flex-col gap-0.5">
            <CardTitle className="flex items-center gap-2 text-sm font-semibold">
              {icon}
              {title}
            </CardTitle>
            {description && <CardDescription className="text-xs">{description}</CardDescription>}
          </div>
          {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">{children}</CardContent>
    </Card>
  )
}

export function ErrorAlert({ error, onRetry, title }: { error: unknown; onRetry?: () => void; title?: string }) {
  return (
    <Alert variant="destructive" className="border-rose-500/30 bg-rose-500/5">
      <AlertTriangle />
      <AlertTitle className="text-xs font-semibold">{title ?? 'Request failed'}</AlertTitle>
      <AlertDescription className="flex flex-col gap-2 text-xs">
        <span className="break-words">{errorMessage(error)}</span>
        {onRetry && (
          <div>
            <Button variant="outline" size="xs" onClick={onRetry}>
              <RotateCw /> Retry
            </Button>
          </div>
        )}
      </AlertDescription>
    </Alert>
  )
}

export function LoadingBlock({ rows = 3, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn('flex flex-col gap-2', className)} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton key={index} className="h-8 w-full bg-zinc-800/60" />
      ))}
    </div>
  )
}

export function EmptyBlock({
  icon,
  title,
  children,
  action,
  className,
}: {
  icon: ReactNode
  title: string
  children?: ReactNode
  action?: ReactNode
  className?: string
}) {
  return (
    <Empty className={cn('border border-dashed border-border/60 bg-background/30 p-5', className)}>
      <EmptyHeader className="max-w-lg">
        <EmptyMedia variant="icon" className="bg-zinc-900 text-zinc-400">
          {icon}
        </EmptyMedia>
        <EmptyTitle className="text-sm">{title}</EmptyTitle>
        {children && <EmptyDescription className="text-xs">{children}</EmptyDescription>}
      </EmptyHeader>
      {action && <EmptyContent>{action}</EmptyContent>}
    </Empty>
  )
}

/** Shown when no workspace (tenant) is registered or selected. */
export function NoTenantState({ feature }: { feature: string }) {
  return (
    <EmptyBlock icon={<FolderX />} title="No workspace selected">
      {feature} is scoped to a registered workspace. Register one ({minimumRoleFor('tenant:create')}, permission: tenant:create) or select
      an existing workspace in the header.
    </EmptyBlock>
  )
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex h-5 items-center rounded border px-1.5 font-mono text-[10px] font-semibold uppercase',
        SEVERITY_CLASS[severity],
        className,
      )}
    >
      {severity}
    </span>
  )
}

export function KeyValue({
  label,
  children,
  mono = false,
  className,
}: {
  label: string
  children: ReactNode
  mono?: boolean
  className?: string
}) {
  return (
    <div className={cn('flex min-w-0 flex-col gap-0.5', className)}>
      <span className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">{label}</span>
      <span className={cn('min-w-0 break-words text-xs text-foreground', mono && 'font-mono text-[11px]')}>{children}</span>
    </div>
  )
}

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <Button
      variant="ghost"
      size="xs"
      className="text-zinc-400 hover:text-zinc-100"
      onClick={async () => {
        const ok = await copyText(text)
        if (!ok) {
          toast.error('Clipboard is not available in this browser context')
          return
        }
        setCopied(true)
        window.setTimeout(() => setCopied(false), 1500)
      }}
    >
      {copied ? <Check className="text-emerald-400" /> : <Copy />}
      {copied ? 'Copied' : label}
    </Button>
  )
}

/** Monospace output pane for real process output (stdout / stderr / JSON). */
export function OutputBlock({
  label,
  text,
  emptyLabel = '(empty)',
  tone = 'default',
  maxHeightClass = 'max-h-80',
}: {
  label: string
  text: string
  emptyLabel?: string
  tone?: 'default' | 'error'
  maxHeightClass?: string
}) {
  return (
    <div className="flex min-w-0 flex-col overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950">
      <div className="flex items-center justify-between border-b border-zinc-800 bg-zinc-900/70 px-2.5 py-1">
        <span className="font-mono text-[11px] text-zinc-400">{label}</span>
        {text && <CopyButton text={text} />}
      </div>
      <pre
        className={cn(
          'overflow-auto whitespace-pre-wrap break-words p-3 font-mono text-[11px] leading-relaxed',
          maxHeightClass,
          tone === 'error' ? 'text-rose-300' : 'text-zinc-200',
          !text && 'italic text-zinc-500',
        )}
      >
        {text || emptyLabel}
      </pre>
    </div>
  )
}

/**
 * Confirmation for outward-facing or destructive actions. `description` must state exactly
 * what will happen.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  destructive = false,
  busy = false,
  onConfirm,
  children,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: ReactNode
  confirmLabel: string
  destructive?: boolean
  busy?: boolean
  onConfirm: () => void
  children?: ReactNode
}) {
  return (
    <Dialog open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <DialogContent className="max-w-md border-border/80 bg-background">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm">
            <AlertTriangle className={cn('size-4', destructive ? 'text-rose-400' : 'text-amber-400')} />
            {title}
          </DialogTitle>
          <DialogDescription render={<div />} className="flex flex-col gap-2 text-xs">
            {description}
          </DialogDescription>
        </DialogHeader>
        {children}
        <DialogFooter>
          <Button variant="outline" size="sm" disabled={busy} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant={destructive ? 'destructive' : 'default'} size="sm" disabled={busy} onClick={onConfirm}>
            {busy && <Loader2 className="animate-spin" />}
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
