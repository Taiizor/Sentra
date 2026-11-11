import { ArrowUpRight, ShieldCheck, ShieldX } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useConsole } from '@/lib/console-context'
import type { WebhookDeliveryStatus, WebhookDeliveryView } from '@/types/api'
import { formatDateTime, shortSha } from './settings-format'
import { TimeAgo } from './settings-kit'

const STATUS_META: Record<WebhookDeliveryStatus, { className: string; hint: string }> = {
  rejected: {
    className: 'border-rose-500/30 text-rose-400 bg-rose-500/5',
    hint: 'Authenticated, but the payload could not be read; it was not processed. Deliveries that fail authentication are only counted.',
  },
  duplicate: { className: 'border-border/60 text-muted-foreground', hint: 'A delivery with this id was already received; it was not processed again.' },
  ignored: { className: 'border-border/60 text-muted-foreground', hint: 'Authenticated but not acted on; see the detail column for the reason.' },
  accepted: {
    className: 'border-sky-500/30 text-sky-400 bg-sky-500/5',
    hint: 'Authenticated and accepted: a ping, or a push whose scan is queued or still running.',
  },
  scanned: {
    className: 'border-emerald-500/30 text-emerald-400 bg-emerald-500/5',
    hint: 'A scan of the registered workspace checkout completed; see the detail for whether it matched the pushed commit.',
  },
  failed: { className: 'border-rose-500/30 text-rose-400 bg-rose-500/5', hint: 'Processing or the scan failed; see the detail column.' },
}

export function WebhookDeliveriesTable({ deliveries }: { deliveries: WebhookDeliveryView[] }) {
  const { tenants, setTenantId, navigate } = useConsole()
  const knownTenants = new Set(tenants.map((tenant) => tenant.tenantId))

  function openRun(tenantId: string) {
    setTenantId(tenantId)
    navigate('overview')
  }

  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow className="border-border/40 hover:bg-transparent">
            <TableHead className="text-[11px] h-8">Received</TableHead>
            <TableHead className="text-[11px] h-8">Source</TableHead>
            <TableHead className="text-[11px] h-8">Repository / ref</TableHead>
            <TableHead className="text-[11px] h-8">Signature</TableHead>
            <TableHead className="text-[11px] h-8">Status</TableHead>
            <TableHead className="text-[11px] h-8">Detail</TableHead>
            <TableHead className="text-[11px] h-8">Run</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {deliveries.map((delivery) => {
            const meta = STATUS_META[delivery.status]
            const runTenant = delivery.runId ? delivery.tenantId : null
            return (
              <TableRow key={`${delivery.provider}:${delivery.deliveryId}`} className="border-border/40 align-top">
                <TableCell className="py-2 text-[11px] whitespace-nowrap">
                  <TimeAgo iso={delivery.receivedAt} className="text-foreground" />
                  <div className="text-[10px] text-muted-foreground">{formatDateTime(delivery.receivedAt)}</div>
                </TableCell>
                <TableCell className="py-2 text-[11px]">
                  <div className="font-mono text-foreground">{delivery.provider}</div>
                  <div className="font-mono text-[10px] text-muted-foreground">{delivery.eventType}</div>
                  <div className="font-mono text-[10px] text-muted-foreground truncate max-w-[140px]" title={delivery.deliveryId}>
                    {delivery.deliveryId}
                  </div>
                </TableCell>
                <TableCell className="py-2 text-[11px] whitespace-normal min-w-[160px]">
                  <div className="font-mono text-foreground break-all">{delivery.repository ?? '—'}</div>
                  <div className="font-mono text-[10px] text-muted-foreground break-all">
                    {delivery.ref ?? '—'}
                    {delivery.afterSha && ` @ ${shortSha(delivery.afterSha)}`}
                  </div>
                  {delivery.sender && <div className="text-[10px] text-muted-foreground">by {delivery.sender}</div>}
                </TableCell>
                <TableCell className="py-2 text-[11px]">
                  {delivery.signatureValid ? (
                    <span className="inline-flex items-center gap-1 text-emerald-400">
                      <ShieldCheck className="size-3" />
                      valid
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-rose-400">
                      <ShieldX className="size-3" />
                      invalid
                    </span>
                  )}
                </TableCell>
                <TableCell className="py-2">
                  <Badge variant="outline" className={`text-[10px] font-mono ${meta.className}`} title={meta.hint}>
                    {delivery.status}
                  </Badge>
                </TableCell>
                <TableCell className="py-2 text-[11px] text-muted-foreground whitespace-normal min-w-[200px] break-words">
                  {delivery.detail ?? '—'}
                </TableCell>
                <TableCell className="py-2 text-[11px]">
                  {runTenant ? (
                    knownTenants.has(runTenant) ? (
                      <Button
                        type="button"
                        variant="ghost"
                        size="xs"
                        className="gap-1 font-mono"
                        title={`Run ${delivery.runId} in workspace ${runTenant}`}
                        onClick={() => openRun(runTenant)}
                      >
                        {runTenant}
                        <ArrowUpRight className="size-3" />
                      </Button>
                    ) : (
                      <span className="text-muted-foreground" title={`Run ${delivery.runId}`}>
                        workspace {runTenant} is no longer registered
                      </span>
                    )
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}
