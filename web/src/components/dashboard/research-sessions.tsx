import { Database, ListChecks, Stamp, Wallet } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api } from '@/lib/api'
import { useResource } from '@/lib/use-resource'
import type { CoreSessionView, ResearchSessionsView, TenantView } from '@/types/api'
import { formatDateTime, formatMicroUsd, minimumRoleFor } from './console-format'
import { EmptyBlock, ErrorAlert, KeyValue, LoadingBlock, SectionCard } from './console-kit'

/** The workspace's core session and its tasks, budget reservations and approvals (read-only). */
export function ResearchSessions({ tenant }: { tenant: TenantView }) {
  const view = useResource(`research-sessions:${tenant.tenantId}`, (signal) => api.tenants.researchSessions(tenant.tenantId, signal))

  if (view.error) return <ErrorAlert error={view.error} onRetry={view.reload} title="Could not read the core store" />
  if (!view.data) return <LoadingBlock rows={5} />
  return <SessionsContent data={view.data} />
}

function SessionsContent({ data }: { data: ResearchSessionsView }) {
  return (
    <div className="flex flex-col gap-4">
      <SessionCard session={data.session} />

      <SectionCard
        icon={<ListChecks className="size-4 text-sky-400" />}
        title={`Core tasks (${data.tasks.length})`}
        description="Tasks the Sentra core recorded in this workspace's store, newest first (up to 200)."
      >
        {data.tasks.length === 0 ? (
          <EmptyBlock icon={<ListChecks />} title="No tasks recorded">
            The core has not recorded a task for this workspace's session yet.
          </EmptyBlock>
        ) : (
          <Table className="text-xs">
            <TableHeader>
              <TableRow>
                <TableHead className="text-right">#</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Completed</TableHead>
                <TableHead>Task id</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.tasks.map((task) => (
                <TableRow key={task.taskId}>
                  <TableCell className="text-right font-mono">{task.sequenceNumber}</TableCell>
                  <TableCell className="max-w-80 whitespace-normal">{task.title}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {task.state}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-[11px] text-zinc-400">{formatDateTime(task.createdAt)}</TableCell>
                  <TableCell className="text-[11px] text-zinc-400">{task.completedAt ? formatDateTime(task.completedAt) : 'open'}</TableCell>
                  <TableCell className="font-mono text-[10px] text-zinc-500">{task.taskId}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </SectionCard>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <SectionCard
          icon={<Wallet className="size-4 text-amber-400" />}
          title={`Budget reservations (${data.budgetReservations.length})`}
          description="Model-cost reservations recorded by the core."
        >
          {data.budgetReservations.length === 0 ? (
            <EmptyBlock icon={<Wallet />} title="No budget reservations">
              The core store has no model budget reservation. Model calls made by this console (patch proposals, model
              reconnaissance) are not recorded here, because the bridge never writes the core store.
            </EmptyBlock>
          ) : (
            <Table className="text-xs">
              <TableHeader>
                <TableRow>
                  <TableHead>Model</TableHead>
                  <TableHead className="text-right">Reserved</TableHead>
                  <TableHead className="text-right">Actual</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Reserved at</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.budgetReservations.map((reservation) => (
                  <TableRow key={reservation.reservationId}>
                    <TableCell className="font-mono text-[11px]">{reservation.modelId}</TableCell>
                    <TableCell className="text-right font-mono">{formatMicroUsd(reservation.reservedMicroUsd)}</TableCell>
                    <TableCell className="text-right font-mono">
                      {reservation.actualMicroUsd === null ? 'not settled' : formatMicroUsd(reservation.actualMicroUsd)}
                    </TableCell>
                    <TableCell className="font-mono text-[11px]">{reservation.state}</TableCell>
                    <TableCell className="text-[11px] text-zinc-400">{formatDateTime(reservation.reservedAt)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </SectionCard>

        <SectionCard
          icon={<Stamp className="size-4 text-violet-400" />}
          title={`Approval requests (${data.approvals.length})`}
          description="Actions the core asked an operator to approve."
        >
          {data.approvals.length === 0 ? (
            <EmptyBlock icon={<Stamp />} title="No approval requests">
              The core has not requested approval for any action in this workspace.
            </EmptyBlock>
          ) : (
            <Table className="text-xs">
              <TableHeader>
                <TableRow>
                  <TableHead>Action</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Classification</TableHead>
                  <TableHead>Created / expires</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.approvals.map((approval) => (
                  <TableRow key={approval.requestId}>
                    <TableCell className="max-w-72 whitespace-normal">
                      <div className="font-mono text-[11px] text-zinc-100">{approval.actionName}</div>
                      <div className="text-[11px] text-zinc-400">{approval.displaySummary}</div>
                    </TableCell>
                    <TableCell className="font-mono text-[11px]">{approval.state}</TableCell>
                    <TableCell className="font-mono text-[11px]">{approval.classification}</TableCell>
                    <TableCell className="text-[11px] text-zinc-400">
                      {formatDateTime(approval.createdAt)}
                      <div>{formatDateTime(approval.expiresAt)}</div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </SectionCard>
      </div>
    </div>
  )
}

function SessionCard({ session }: { session: CoreSessionView }) {
  return (
    <SectionCard
      icon={<Database className="size-4 text-emerald-400" />}
      title="Core session"
      description="Each workspace has one local core session, read from its core store through the Sentra CLI."
      actions={
        <Badge
          variant="outline"
          className={session.initialized ? 'border-emerald-500/30 text-emerald-300' : 'border-amber-500/30 text-amber-300'}
        >
          {session.initialized ? 'initialized' : 'not initialized'}
        </Badge>
      }
    >
      {!session.initialized ? (
        <EmptyBlock icon={<Database />} title="No readable core session">
          {session.error ?? 'The core store for this workspace has no session.'} The bridge creates the core store when a
          workspace is registered and recreates a missing store file the next time it checks an existing workspace directory
          (for example when workspace metadata is refreshed). A store that exists but cannot be opened must be
          repaired or moved away on the bridge host by its operator; alternatively, someone with the{' '}
          {minimumRoleFor('tenant:create')} role can unregister this workspace (Settings → Workspaces) and register it again
          under a new workspace id, which starts a new, empty core store.
        </EmptyBlock>
      ) : (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <KeyValue label="Session id" mono className="col-span-2">
            {session.sessionId ?? 'n/a'}
          </KeyValue>
          <KeyValue label="State" mono>
            {session.state ?? 'n/a'}
          </KeyValue>
          <KeyValue label="Mode" mono>
            {session.mode ?? 'n/a'}
          </KeyValue>
          <KeyValue label="Classification floor" mono>
            {session.classificationFloor ?? 'n/a'}
          </KeyValue>
          <KeyValue label="Context generation" mono>
            {session.contextGeneration ?? 'n/a'}
          </KeyValue>
          <KeyValue label="Created">{formatDateTime(session.createdAt)}</KeyValue>
          <KeyValue label="Updated">{formatDateTime(session.updatedAt)}</KeyValue>
          <KeyValue label="Budget used / limit" mono className="col-span-2">
            {session.budgetLimitMicroUsd === null && session.budgetUsedMicroUsd === null
              ? 'no budget set'
              : `${formatMicroUsd(session.budgetUsedMicroUsd)} / ${
                  session.budgetLimitMicroUsd === null ? 'no limit' : formatMicroUsd(session.budgetLimitMicroUsd)
                }`}
          </KeyValue>
          {session.error && (
            <KeyValue label="Read warning" className="col-span-2">
              <span className="text-amber-300">{session.error}</span>
            </KeyValue>
          )}
        </div>
      )}
    </SectionCard>
  )
}
