import { Fragment, useState } from 'react'
import { ChevronDown, ChevronRight, Database } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import type { CoreAuditView } from '@/types/api'
import { JsonBlock } from './audit-tab-parts'
import { formatCount, formatDateTime, formatMicroUsd, shortHash } from './overview-tab-format'
import { Field, LoadError } from './overview-tab-parts'

const CORE_LIMIT = 200

function SessionSummary({ view }: { view: CoreAuditView }) {
  const session = view.session
  if (!session.initialized) {
    return <p className="text-xs text-amber-300 break-words">Core session not initialized{session.error ? `: ${session.error}` : '.'}</p>
  }
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6">
      <div>
        <Field label="Session" mono>
          {session.sessionId ?? '—'}
        </Field>
        <Field label="State">{session.state ?? '—'}</Field>
        <Field label="Mode">{session.mode ?? '—'}</Field>
        <Field label="Classification floor">{session.classificationFloor ?? '—'}</Field>
      </div>
      <div>
        <Field label="Context generation">{formatCount(session.contextGeneration)}</Field>
        <Field label="Budget used / limit" mono>
          {formatMicroUsd(session.budgetUsedMicroUsd)} / {formatMicroUsd(session.budgetLimitMicroUsd)}
        </Field>
        <Field label="Created">{formatDateTime(session.createdAt)}</Field>
        <Field label="Updated">{formatDateTime(session.updatedAt)}</Field>
      </div>
      {session.error && <p className="md:col-span-2 text-xs text-rose-300 break-words pt-1">{session.error}</p>}
    </div>
  )
}

export function CoreStoreAudit() {
  const { tenant } = useConsole()
  const tenantId = tenant?.tenantId ?? null
  const core = useResource(tenantId ? `core-audit:${tenantId}:${CORE_LIMIT}` : null, (signal) =>
    api.tenants.core(tenantId ?? '', CORE_LIMIT, signal),
  )
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set())

  if (!tenant) {
    return <p className="text-xs text-zinc-500 py-6 text-center">Select a registered workspace to read its core store.</p>
  }

  function toggle(eventId: string) {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(eventId)) next.delete(eventId)
      else next.add(eventId)
      return next
    })
  }

  return (
    <div className="flex flex-col gap-4">
      <Card className="border-zinc-800/80 bg-zinc-900/40">
        <CardHeader className="pt-4 pb-2 px-4 sm:px-5">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Database className="size-4 text-primary" />
            Core store · {tenant.name}
          </CardTitle>
          <CardDescription className="text-xs text-zinc-400">
            Session, tasks and audit events from this workspace's Sentra core store, read through a read-only connection. The
            bridge never writes to core stores directly.
          </CardDescription>
        </CardHeader>
        <CardContent className="px-4 sm:px-5 pb-4">
          {core.error ? (
            <LoadError title="Core store unavailable" error={core.error} onRetry={core.reload} />
          ) : !core.data ? (
            <Skeleton className="h-28 w-full bg-zinc-900" />
          ) : (
            <SessionSummary view={core.data} />
          )}
        </CardContent>
      </Card>

      {core.data && (
        <>
          <Card className="border-zinc-800/80 bg-zinc-900/40">
            <CardHeader className="pt-4 pb-2 px-4 sm:px-5">
              <CardTitle className="text-sm font-semibold">Core tasks</CardTitle>
              <CardDescription className="text-xs text-zinc-400">
                {core.data.tasks.length} shown of {core.data.totalTasks.toLocaleString()} recorded
              </CardDescription>
            </CardHeader>
            <CardContent className="px-4 sm:px-5 pb-4">
              {core.data.tasks.length === 0 ? (
                <p className="text-xs text-zinc-500 py-4 text-center">The core has recorded no tasks for this workspace.</p>
              ) : (
                <div className="overflow-x-auto max-h-80">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="text-xs">Seq</TableHead>
                        <TableHead className="text-xs">Title</TableHead>
                        <TableHead className="text-xs">State</TableHead>
                        <TableHead className="text-xs">Created</TableHead>
                        <TableHead className="text-xs">Completed</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {core.data.tasks.map((task) => (
                        <TableRow key={task.taskId}>
                          <TableCell className="font-mono text-[11px] text-zinc-400" title={task.taskId}>
                            #{task.sequenceNumber}
                          </TableCell>
                          <TableCell className="text-xs">{task.title}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className="text-[10px] font-mono">
                              {task.state}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-[11px] whitespace-nowrap">{formatDateTime(task.createdAt)}</TableCell>
                          <TableCell className="font-mono text-[11px] whitespace-nowrap">{formatDateTime(task.completedAt)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="border-zinc-800/80 bg-zinc-900/40">
            <CardHeader className="pt-4 pb-2 px-4 sm:px-5">
              <CardTitle className="text-sm font-semibold">Core audit events</CardTitle>
              <CardDescription className="text-xs text-zinc-400">
                {core.data.events.length} shown of {core.data.totalEvents.toLocaleString()} recorded. Rows without the core's
                versioned envelope are flagged; the console did not verify any core event digest.
              </CardDescription>
            </CardHeader>
            <CardContent className="px-4 sm:px-5 pb-4">
              {core.data.events.length === 0 ? (
                <p className="text-xs text-zinc-500 py-4 text-center">The core has recorded no audit events for this workspace.</p>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-6" />
                        <TableHead className="text-xs">Seq</TableHead>
                        <TableHead className="text-xs">Time</TableHead>
                        <TableHead className="text-xs">Kind</TableHead>
                        <TableHead className="text-xs">Classification</TableHead>
                        <TableHead className="text-xs">Operator</TableHead>
                        <TableHead className="text-xs">Action digest</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {core.data.events.map((event) => {
                        const open = expanded.has(event.eventId)
                        return (
                          <Fragment key={event.eventId}>
                            <TableRow className="cursor-pointer hover:bg-zinc-900/60" onClick={() => toggle(event.eventId)}>
                              <TableCell className="py-2 text-zinc-500">
                                {open ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
                              </TableCell>
                              <TableCell className="font-mono text-[11px] text-zinc-400" title={event.eventId}>
                                #{event.sequenceNumber}
                              </TableCell>
                              <TableCell className="font-mono text-[11px] whitespace-nowrap">{formatDateTime(event.timestamp)}</TableCell>
                              <TableCell className="text-[11px]">
                                <span className="font-mono text-zinc-200">{event.eventKind}</span>
                                {event.nonCoreEnvelope && (
                                  <Badge
                                    variant="outline"
                                    className="ml-1.5 text-[10px] border-amber-500/40 text-amber-300"
                                    title="This row lacks the core's versioned event envelope (for example, written by an earlier version of the web bridge). Treat it as unattested."
                                  >
                                    legacy/non-core envelope
                                  </Badge>
                                )}
                              </TableCell>
                              <TableCell className="font-mono text-[11px]">{event.classification}</TableCell>
                              <TableCell className="font-mono text-[11px] text-zinc-400">{event.operatorId ?? '—'}</TableCell>
                              <TableCell className="font-mono text-[11px] text-zinc-500" title={event.actionDigest ?? 'No digest stored'}>
                                {event.actionDigest ? shortHash(event.actionDigest) : 'none'}
                              </TableCell>
                            </TableRow>
                            {open && (
                              <TableRow className="hover:bg-transparent">
                                <TableCell colSpan={7} className="bg-zinc-950/40 py-3">
                                  <div className="flex flex-col gap-1 text-[11px]">
                                    <span className="text-zinc-500">
                                      Event · session <span className="font-mono">{event.sessionId}</span>
                                      {event.policyId && (
                                        <>
                                          {' '}· policy <span className="font-mono">{event.policyId}</span>
                                        </>
                                      )}
                                    </span>
                                    <JsonBlock value={event.event} />
                                  </div>
                                </TableCell>
                              </TableRow>
                            )}
                          </Fragment>
                        )
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}
