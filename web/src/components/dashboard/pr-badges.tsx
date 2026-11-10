import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  CircleDashed,
  CircleSlash,
  Clock,
  Loader2,
  MinusCircle,
  ShieldAlert,
  ShieldQuestion,
  XCircle,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import type { PrSecurityStatus, PrSecurityView, PullRequestView, Severity } from '@/types/api'
import { relativeTime, shortSha } from './settings-format'

/** Display metadata for each PR security status. Wording never implies verification. */
const SECURITY_STATUS: Record<PrSecurityStatus, { label: string; className: string; hint: string }> = {
  not_scanned: {
    label: 'Not scanned',
    className: 'border-border/60 text-muted-foreground bg-muted/20',
    hint: 'Sentra has not scanned this pull request.',
  },
  stale: {
    label: 'Scan stale',
    className: 'border-amber-500/30 text-amber-400 bg-amber-500/5',
    hint: 'The last scan was for an older head commit; the result does not describe the current changes.',
  },
  clean: {
    label: 'No signals',
    className: 'border-emerald-500/30 text-emerald-400 bg-emerald-500/5',
    hint: 'The heuristic scanner reported no signals in the changed files at the scanned commit. This is not a proof of absence.',
  },
  warnings: {
    label: 'Signals',
    className: 'border-amber-500/30 text-amber-400 bg-amber-500/5',
    hint: 'The heuristic scanner reported candidate signals below critical severity.',
  },
  critical: {
    label: 'Critical signals',
    className: 'border-rose-500/30 text-rose-400 bg-rose-500/10',
    hint: 'The heuristic scanner reported at least one critical-severity candidate signal.',
  },
  failed: {
    label: 'Scan failed',
    className: 'border-rose-500/30 text-rose-400 bg-rose-500/5',
    hint: 'The last scan has no complete result: the scanner failed, or not every changed file could be scanned. Signals from the scanned part, if any, are listed in the scan details.',
  },
}

function securityIcon(status: PrSecurityStatus) {
  switch (status) {
    case 'not_scanned':
      return <ShieldQuestion className="size-3" />
    case 'stale':
      return <Clock className="size-3" />
    case 'clean':
      return <CheckCircle2 className="size-3" />
    case 'warnings':
      return <AlertTriangle className="size-3" />
    case 'critical':
      return <ShieldAlert className="size-3" />
    case 'failed':
      return <XCircle className="size-3" />
  }
}

export function SecurityStatusBadge({ security }: { security: PrSecurityView }) {
  const meta = SECURITY_STATUS[security.status]
  const counts =
    security.status === 'warnings' || security.status === 'critical'
      ? ` · ${security.signalsFound ?? 0}${security.criticalCount ? ` (${security.criticalCount} critical)` : ''}`
      : ''
  const scanned = security.scannedAt
    ? ` Scanned ${relativeTime(security.scannedAt)} at ${shortSha(security.scannedHeadSha)}${security.scannedBy ? ` by ${security.scannedBy}` : ''}.`
    : ''
  return (
    <Badge variant="outline" className={`text-[11px] gap-1 ${meta.className}`} title={`${meta.hint}${scanned}`}>
      {securityIcon(security.status)}
      {meta.label}
      {counts}
    </Badge>
  )
}

/** Summary of GitHub's status check rollup for the PR head commit (counts come from GitHub). */
export function ChecksSummary({ checks }: { checks: PullRequestView['checks'] }) {
  if (checks.total === 0) {
    return <span className="text-[11px] text-muted-foreground font-mono">No checks reported</span>
  }
  const state = checks.rollupState?.toLowerCase() ?? null
  const tone =
    state === 'success'
      ? 'text-emerald-400'
      : state === 'failure' || state === 'error'
        ? 'text-rose-400'
        : state === 'pending' || state === 'expected'
          ? 'text-amber-400'
          : 'text-muted-foreground'
  const parts = [`${checks.successful}/${checks.total} passed`]
  if (checks.failed > 0) parts.push(`${checks.failed} failed`)
  if (checks.inProgress > 0) parts.push(`${checks.inProgress} pending`)
  return (
    <span className="text-[11px] font-mono text-muted-foreground" title="GitHub status check rollup for the head commit">
      {state && <span className={`font-semibold uppercase ${tone}`}>{state}</span>}
      {state && ' · '}
      {parts.join(', ')}
    </span>
  )
}

/** Icon for a GitHub Actions status/conclusion pair. A spinner is shown only while work is running. */
export function RunStateIcon({ status, conclusion }: { status: string; conclusion: string | null }) {
  if (status !== 'completed') {
    return status === 'in_progress' ? (
      <Loader2 className="size-3.5 text-amber-400 animate-spin" aria-label={status} />
    ) : (
      <CircleDashed className="size-3.5 text-amber-400" aria-label={status} />
    )
  }
  switch (conclusion) {
    case 'success':
      return <CheckCircle2 className="size-3.5 text-emerald-400" aria-label="success" />
    case 'failure':
    case 'timed_out':
    case 'startup_failure':
      return <XCircle className="size-3.5 text-rose-400" aria-label={conclusion} />
    case 'cancelled':
      return <Ban className="size-3.5 text-muted-foreground" aria-label="cancelled" />
    case 'skipped':
      return <CircleSlash className="size-3.5 text-muted-foreground" aria-label="skipped" />
    case 'action_required':
      return <AlertTriangle className="size-3.5 text-amber-400" aria-label="action required" />
    default:
      return <MinusCircle className="size-3.5 text-muted-foreground" aria-label={conclusion ?? 'unknown'} />
  }
}

const SEVERITY_CLASS: Record<Severity, string> = {
  Critical: 'border-rose-500/40 text-rose-400 bg-rose-500/10',
  High: 'border-orange-500/40 text-orange-400 bg-orange-500/10',
  Medium: 'border-amber-500/40 text-amber-400 bg-amber-500/10',
  Low: 'border-sky-500/40 text-sky-400 bg-sky-500/10',
  Informational: 'border-border/60 text-muted-foreground',
  Unknown: 'border-border/60 text-muted-foreground',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge variant="outline" className={`text-[10px] font-mono ${SEVERITY_CLASS[severity]}`}>
      {severity}
    </Badge>
  )
}
