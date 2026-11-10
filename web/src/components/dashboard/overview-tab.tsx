import type { ReactNode } from 'react'
import { Activity, CheckCircle2, Clock, Cpu, History, Layers, ListChecks } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import { SEVERITIES, type OverviewView, type ScanRunView } from '@/types/api'
import { minimumRoleFor } from './console-format'
import { formatCount, formatDateTime, formatDuration, formatMicroUsd, SEVERITY_BAR_CLASS } from './overview-tab-format'
import { Field, LoadError, RunStatusBadge } from './overview-tab-parts'
import { OverviewTrendCard } from './overview-tab-trend'

const TREND_DAYS = 30
const RECENT_RUNS = 10

const KIND_LABEL: Record<ScanRunView['kind'], string> = {
  sast: 'SAST',
  dependency: 'Dependency audit',
  codeql: 'CodeQL language probe',
  all: 'Full scan',
}

function StatCard({
  title,
  icon,
  value,
  children,
  onClick,
}: {
  title: string
  icon: ReactNode
  value: ReactNode
  children?: ReactNode
  onClick?: () => void
}) {
  const interactive = onClick !== undefined
  return (
    <Card
      className={`border-zinc-800/80 bg-zinc-900/40 ${interactive ? 'hover:bg-zinc-900/70 hover:border-zinc-700 cursor-pointer transition-colors' : ''}`}
      onClick={onClick}
      role={interactive ? 'button' : undefined}
      tabIndex={interactive ? 0 : undefined}
      onKeyDown={interactive ? (event) => (event.key === 'Enter' || event.key === ' ') && onClick() : undefined}
    >
      <CardHeader className="flex flex-row items-center justify-between pb-1 pt-3.5 px-4">
        <CardTitle className="text-xs font-medium text-zinc-400">{title}</CardTitle>
        {icon}
      </CardHeader>
      <CardContent className="px-4 pb-3.5 pt-0 flex flex-col gap-1">
        <div className="text-2xl font-bold text-zinc-100">{value}</div>
        <div className="text-[11px] text-zinc-400 leading-snug">{children}</div>
      </CardContent>
    </Card>
  )
}

function SummaryCards({ overview, onOpenFindings, onOpenPatches }: { overview: OverviewView; onOpenFindings: () => void; onOpenPatches: () => void }) {
  const open = overview.openFindings
  const lastRun = overview.lastRun
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3.5">
      <StatCard title="Open findings" icon={<ListChecks className="size-4 text-zinc-400" />} value={open.total} onClick={onOpenFindings}>
        {open.bySeverity.Critical} critical · {open.bySeverity.High} high · {open.byTriage.untriaged} untriaged
        <span className="block text-zinc-500">Unverified scanner candidates</span>
      </StatCard>

      <StatCard
        title="Last scan with results"
        icon={<Clock className="size-4 text-zinc-400" />}
        value={<span className="text-base">{overview.lastResultRunAt ? formatDateTime(overview.lastResultRunAt) : 'None yet'}</span>}
      >
        {lastRun ? (
          <span className="flex items-center gap-1.5 flex-wrap">
            Latest run: {KIND_LABEL[lastRun.kind]} <RunStatusBadge status={lastRun.status} />
          </span>
        ) : (
          'No scan has run for this workspace yet'
        )}
        <span className="block text-zinc-500">
          {overview.lastCompletedRunAt && overview.lastCompletedRunAt !== overview.lastResultRunAt
            ? `Newest completed run of any kind: ${formatDateTime(overview.lastCompletedRunAt)} (CodeQL probes and skipped dependency stages produce no results)`
            : 'Completed run that produced SAST or dependency results'}
        </span>
      </StatCard>

      <StatCard
        title="Heuristic risk score"
        icon={<Activity className="size-4 text-zinc-400" />}
        value={overview.riskScore ? overview.riskScore.value : <span className="text-base text-zinc-400">Not computed</span>}
      >
        {overview.riskScore ? (
          <code className="font-mono text-[10px] text-zinc-400 break-all" title="Formula reported by the bridge">
            {overview.riskScore.formula}
          </code>
        ) : (
          'No completed run with SAST or dependency results yet'
        )}
      </StatCard>

      <StatCard
        title="Patch candidates"
        icon={<CheckCircle2 className="size-4 text-zinc-400" />}
        value={overview.patches.proposed}
        onClick={onOpenPatches}
      >
        proposed · {overview.patches.applied} applied · {overview.patches.rolledBack} rolled back · {overview.patches.pullRequests} PRs
        <span className="block text-zinc-500">Model-generated · Verification: not run</span>
      </StatCard>
    </div>
  )
}

function BreakdownCard({ overview }: { overview: OverviewView }) {
  const open = overview.openFindings
  // untriaged + confirmed + needs_validation = open.total; rejected findings are still open
  // (the scanner keeps reporting them) but excluded from the total and the severity rows.
  const triage: [string, number][] = [
    ['Untriaged', open.byTriage.untriaged],
    ['Confirmed', open.byTriage.confirmed],
    ['Needs validation', open.byTriage.needs_validation],
  ]
  return (
    <Card className="border-zinc-800/80 bg-zinc-900/40">
      <CardHeader className="pb-2 pt-4 px-4 sm:px-5">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <Layers className="size-4 text-primary" />
          Open findings breakdown
        </CardTitle>
        <CardDescription className="text-xs text-zinc-400">
          {open.total === 0 && open.byTriage.rejected === 0
            ? 'No open findings recorded.'
            : `${open.total} open${open.byTriage.rejected > 0 ? ` (+${open.byTriage.rejected} triaged as rejected, not counted)` : ''} · ${overview.resolvedFindings} resolved since first scan`}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 px-4 sm:px-5 pb-4">
        <div className="flex flex-col gap-1.5">
          {SEVERITIES.map((severity) => {
            const count = open.bySeverity[severity] ?? 0
            const percent = open.total > 0 ? (count / open.total) * 100 : 0
            return (
              <div key={severity} className="flex flex-col gap-0.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-300">{severity}</span>
                  <span className="font-mono text-zinc-400">{count}</span>
                </div>
                <div className="h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                  <div className={`h-full rounded-full ${SEVERITY_BAR_CLASS[severity]}`} style={{ width: `${percent}%` }} />
                </div>
              </div>
            )
          })}
        </div>
        <div className="border-t border-zinc-800/80 pt-2">
          <Field label="SAST rules">{open.bySource.sast ?? 0}</Field>
          <Field label="Dependency advisories (OSV)">{open.bySource.dependency ?? 0}</Field>
        </div>
        <div className="border-t border-zinc-800/80 pt-2">
          {triage.map(([label, count]) => (
            <Field key={label} label={label}>
              {count}
            </Field>
          ))}
          <Field label="Rejected (excluded from open total)">
            <span className="text-zinc-500">{open.byTriage.rejected}</span>
          </Field>
        </div>
      </CardContent>
    </Card>
  )
}

function CoreSessionCard({ overview }: { overview: OverviewView }) {
  const core = overview.core
  const budgetPercent =
    core.budgetLimitMicroUsd && core.budgetLimitMicroUsd > 0 && core.budgetUsedMicroUsd !== null
      ? Math.min(100, (core.budgetUsedMicroUsd / core.budgetLimitMicroUsd) * 100)
      : null
  return (
    <Card className="border-zinc-800/80 bg-zinc-900/40">
      <CardHeader className="pb-2 pt-4 px-4 sm:px-5">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <Cpu className="size-4 text-primary" />
          Core session
        </CardTitle>
        <CardDescription className="text-xs text-zinc-400">Read from this workspace's core store via `sentra status`.</CardDescription>
      </CardHeader>
      <CardContent className="px-4 sm:px-5 pb-4">
        {!core.initialized ? (
          <p className="text-xs text-amber-300 break-words">
            Not initialized{core.error ? `: ${core.error}` : '.'}
          </p>
        ) : (
          <div className="flex flex-col">
            {core.error && <p className="text-xs text-rose-300 break-words pb-1">{core.error}</p>}
            <Field label="Session" mono>
              {core.sessionId ?? '—'}
            </Field>
            <Field label="State">
              <Badge variant="outline" className="text-[10px] font-mono">
                {core.state ?? 'unknown'}
              </Badge>
            </Field>
            <Field label="Mode">{core.mode ?? '—'}</Field>
            <Field label="Classification floor">{core.classificationFloor ?? '—'}</Field>
            <Field label="Context generation">{formatCount(core.contextGeneration)}</Field>
            <Field label="Budget used / limit" mono>
              {formatMicroUsd(core.budgetUsedMicroUsd)} / {formatMicroUsd(core.budgetLimitMicroUsd)}
            </Field>
            {budgetPercent !== null && (
              <div className="h-1 rounded-full bg-zinc-800 overflow-hidden my-1">
                <div className="h-full bg-zinc-400" style={{ width: `${budgetPercent}%` }} />
              </div>
            )}
            <Field label="Core tasks">{formatCount(core.taskCount)}</Field>
            <Field label="Core audit events">{formatCount(core.auditEventCount)}</Field>
            <Field label="Operator audit entries">{formatCount(overview.operatorAuditEntries)}</Field>
            <Field label="Created">{formatDateTime(core.createdAt)}</Field>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function RecentRuns({ runs, loading, error, onRetry, canScan }: {
  runs: ScanRunView[] | undefined
  loading: boolean
  error: unknown
  onRetry: () => void
  canScan: boolean
}) {
  return (
    <Card className="border-zinc-800/80 bg-zinc-900/40">
      <CardHeader className="pt-4 pb-2 px-4 sm:px-5">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <History className="size-4 text-primary" />
          Recent scan runs
        </CardTitle>
        <CardDescription className="text-xs text-zinc-400">The {RECENT_RUNS} most recent runs recorded by the bridge for this workspace.</CardDescription>
      </CardHeader>
      <CardContent className="px-4 sm:px-5 pb-4">
        {error ? (
          <LoadError title="Scan runs unavailable" error={error} onRetry={onRetry} />
        ) : !runs ? (
          loading ? <Skeleton className="h-32 w-full bg-zinc-900" /> : null
        ) : runs.length === 0 ? (
          <p className="text-xs text-zinc-500 py-6 text-center">
            No scan has run for this workspace yet.{' '}
            {canScan ? 'Start one with "Full scan" in the workspace bar above.' : `Starting a scan requires the ${minimumRoleFor('scan:run')} role or higher.`}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Started</TableHead>
                  <TableHead className="text-xs">Kind</TableHead>
                  <TableHead className="text-xs">Status</TableHead>
                  <TableHead className="text-xs">Trigger / actor</TableHead>
                  <TableHead className="text-xs text-right">Duration</TableHead>
                  <TableHead className="text-xs text-right">Files</TableHead>
                  <TableHead className="text-xs text-right">Signals</TableHead>
                  <TableHead className="text-xs text-right">Packages</TableHead>
                  <TableHead className="text-xs text-right">Vulnerable pkgs</TableHead>
                  <TableHead className="text-xs">Git head</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {runs.map((run) => {
                  const stageErrors = run.summary?.stageErrors ?? []
                  return (
                    <TableRow key={run.runId}>
                      <TableCell className="text-[11px] font-mono whitespace-nowrap" title={run.runId}>
                        {formatDateTime(run.startedAt)}
                      </TableCell>
                      <TableCell className="text-xs whitespace-nowrap">{KIND_LABEL[run.kind]}</TableCell>
                      <TableCell className="text-xs">
                        <div className="flex flex-col gap-0.5 items-start">
                          <RunStatusBadge status={run.status} />
                          {run.error && (
                            <span className="text-[10px] text-rose-300 max-w-[220px] truncate" title={run.error}>
                              {run.error}
                            </span>
                          )}
                          {stageErrors.length > 0 && (
                            <span
                              className="text-[10px] text-amber-300"
                              title={stageErrors.map((stage) => `${stage.stage}: ${stage.message}`).join('\n')}
                            >
                              {stageErrors.length} stage error(s)
                            </span>
                          )}
                          {run.summary?.dependencySkippedReason && (
                            <span className="text-[10px] text-zinc-500 max-w-[220px] truncate" title={run.summary.dependencySkippedReason}>
                              Dependency stage skipped
                            </span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-[11px] whitespace-nowrap">
                        {run.trigger} <span className="text-zinc-500 font-mono">{run.actor}</span>
                      </TableCell>
                      <TableCell className="text-[11px] font-mono text-right whitespace-nowrap">{formatDuration(run.startedAt, run.finishedAt)}</TableCell>
                      <TableCell className="text-[11px] font-mono text-right">{formatCount(run.filesScanned)}</TableCell>
                      <TableCell className="text-[11px] font-mono text-right">{formatCount(run.signalsFound)}</TableCell>
                      <TableCell className="text-[11px] font-mono text-right">{formatCount(run.packagesAudited)}</TableCell>
                      <TableCell className="text-[11px] font-mono text-right">{formatCount(run.vulnerablePackages)}</TableCell>
                      <TableCell className="text-[11px] font-mono text-zinc-400" title={run.gitHead ?? undefined}>
                        {run.gitHead ? run.gitHead.slice(0, 8) : '—'}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function OverviewTab() {
  const { tenant, navigate, can } = useConsole()
  const tenantId = tenant?.tenantId ?? null

  const overview = useResource(tenantId ? `overview:${tenantId}` : null, (signal) => api.tenants.overview(tenantId ?? '', signal))
  const trends = useResource(tenantId ? `trends:${tenantId}:${TREND_DAYS}` : null, (signal) =>
    api.tenants.trends(tenantId ?? '', TREND_DAYS, signal),
  )
  const runs = useResource(tenantId ? `scans:${tenantId}:${RECENT_RUNS}` : null, (signal) =>
    api.scans.list(tenantId ?? '', RECENT_RUNS, signal),
  )

  if (!tenant) {
    return <p className="text-xs text-zinc-500">Select a registered workspace to see its overview.</p>
  }

  return (
    <div className="flex flex-col gap-5">
      {overview.error ? (
        <LoadError title="Overview unavailable" error={overview.error} onRetry={overview.reload} />
      ) : !overview.data ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3.5" aria-busy="true">
          {[0, 1, 2, 3].map((index) => (
            <Skeleton key={index} className="h-28 bg-zinc-900" />
          ))}
        </div>
      ) : (
        <SummaryCards
          overview={overview.data}
          onOpenFindings={() => navigate('findings')}
          onOpenPatches={() => navigate('remediation')}
        />
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-8 min-w-0">
          <OverviewTrendCard
            days={TREND_DAYS}
            points={trends.data?.points}
            loading={trends.loading}
            error={trends.error}
            onRetry={trends.reload}
          />
        </div>
        <div className="lg:col-span-4 min-w-0">
          {overview.data ? <BreakdownCard overview={overview.data} /> : !overview.error && <Skeleton className="h-full min-h-60 bg-zinc-900" />}
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-5">
        <div className="xl:col-span-4 min-w-0">
          {overview.data ? <CoreSessionCard overview={overview.data} /> : !overview.error && <Skeleton className="h-64 bg-zinc-900" />}
        </div>
        <div className="xl:col-span-8 min-w-0">
          <RecentRuns
            runs={runs.data?.runs}
            loading={runs.loading}
            error={runs.error}
            onRetry={runs.reload}
            canScan={can('scan:run')}
          />
        </div>
      </div>
    </div>
  )
}
