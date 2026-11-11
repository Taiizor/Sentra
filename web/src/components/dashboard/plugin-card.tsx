import { useState } from 'react'
import { CheckCircle2, Loader2, Play, Plug, Stethoscope, XCircle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { api } from '@/lib/api'
import type { PluginProbeView, PluginView, TenantView } from '@/types/api'
import { ErrorAlert, GatedButton, KeyValue } from './console-kit'

/** One discovered adapter manifest, with probe and run actions. */
export function PluginCard({
  plugin,
  tenant,
  onRun,
}: {
  plugin: PluginView
  tenant: TenantView | null
  onRun: (plugin: PluginView) => void
}) {
  const [probing, setProbing] = useState(false)
  const [probe, setProbe] = useState<{ tenantId: string; view: PluginProbeView } | null>(null)
  const [probeError, setProbeError] = useState<unknown>(null)
  const noTenantReason = tenant ? null : 'Select a workspace first'

  const runProbe = async () => {
    if (!tenant) return
    setProbing(true)
    setProbeError(null)
    try {
      setProbe({ tenantId: tenant.tenantId, view: await api.plugins.probe(plugin.id, tenant.tenantId) })
    } catch (failure) {
      setProbe(null)
      setProbeError(failure)
    } finally {
      setProbing(false)
    }
  }

  // A probe result belongs to the workspace it was run against.
  const probeView = probe && tenant && probe.tenantId === tenant.tenantId ? probe.view : null

  return (
    <Card size="sm" className="border-border/60 bg-card/40">
      <CardHeader className="border-b border-border/40">
        <div className="flex items-start justify-between gap-2">
          <div className="flex min-w-0 flex-col gap-0.5">
            <span className="flex items-center gap-1.5 text-sm font-semibold text-zinc-100">
              <Plug className="size-3.5 text-primary" />
              {plugin.name}
              <span className="font-mono text-[11px] font-normal text-zinc-500">{plugin.version}</span>
            </span>
            <span className="break-all font-mono text-[11px] text-zinc-400">{plugin.id}</span>
          </div>
          <Badge variant="outline" className="shrink-0 font-mono text-[10px]">
            {plugin.family}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="grid grid-cols-1 gap-2">
          <KeyValue label="Manifest" mono>
            {plugin.manifestPath}
          </KeyValue>
          <KeyValue label="Executable" mono>
            {plugin.executablePath ?? 'not resolved from the manifest'}
          </KeyValue>
        </div>

        <div className="flex flex-col gap-1">
          <span className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Declared capabilities</span>
          {plugin.capabilities.length === 0 ? (
            <span className="text-xs text-zinc-500">none declared</span>
          ) : (
            <div className="flex flex-wrap gap-1">
              {plugin.capabilities.map((capability) => (
                <Badge key={capability} variant="outline" className="font-mono text-[10px] text-zinc-300">
                  {capability}
                </Badge>
              ))}
            </div>
          )}
        </div>

        <div className="flex flex-col gap-1 rounded-md border border-border/40 bg-background/40 p-2 text-[11px]">
          <span className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Manifest limits</span>
          <span className="text-zinc-300">
            Execution time:{' '}
            {plugin.declaredQuotas ? `${plugin.declaredQuotas.maxExecutionTimeSecs} s` : 'core default'}{' '}
            <span className="text-zinc-500">(enforced by the core, at most one hour; the adapter's process tree is killed when it expires)</span>
          </span>
          <span className="text-zinc-300">
            Frame and output size: <span className="text-zinc-500">(enforced by the core)</span>
          </span>
          <span className="text-zinc-300">
            Memory: {plugin.declaredQuotas ? `${plugin.declaredQuotas.maxMemoryMib} MiB` : 'none declared'}{' '}
            <span className="text-zinc-500">(declared only, not enforced)</span>
          </span>
          <span className="text-zinc-300">
            Egress policy: <span className="font-mono">{plugin.declaredEgressPolicy}</span>{' '}
            <span className="text-zinc-500">(declared only, not enforced)</span>
          </span>
        </div>

        {probeError !== null && <ErrorAlert error={probeError} title="Probe failed" />}
        {probeView && <ProbeResult view={probeView} />}

        <div className="flex flex-wrap items-center gap-2 border-t border-border/40 pt-2">
          <GatedButton
            permission="plugin:probe"
            blockedReason={noTenantReason}
            variant="outline"
            size="sm"
            disabled={probing}
            onClick={() => void runProbe()}
          >
            {probing ? <Loader2 className="animate-spin" /> : <Stethoscope />}
            Probe
          </GatedButton>
          <GatedButton
            permission="plugin:run"
            blockedReason={noTenantReason ?? (plugin.capabilities.length === 0 ? 'No declared capability to run' : null)}
            variant="outline"
            size="sm"
            onClick={() => onRun(plugin)}
          >
            <Play />
            Run…
          </GatedButton>
          <span className="text-[10px] text-zinc-500">Both start the adapter process on the bridge host.</span>
        </div>
      </CardContent>
    </Card>
  )
}

function ProbeResult({ view }: { view: PluginProbeView }) {
  return (
    <div
      className={
        view.applicable
          ? 'flex flex-col gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/5 p-2 text-xs'
          : 'flex flex-col gap-1 rounded-md border border-amber-500/30 bg-amber-500/5 p-2 text-xs'
      }
    >
      <span className="flex items-center gap-1.5 font-semibold">
        {view.applicable ? (
          <CheckCircle2 className="size-3.5 text-emerald-400" />
        ) : (
          <XCircle className="size-3.5 text-amber-400" />
        )}
        Adapter reports: {view.applicable ? 'applicable to this workspace' : 'not applicable'}
      </span>
      {view.unsupportedReason && <span className="text-amber-200">Reason: {view.unsupportedReason}</span>}
      {view.details && <span className="break-words text-zinc-300">{view.details}</span>}
      {view.capabilities.length > 0 && (
        <span className="text-[11px] text-zinc-400">
          Capabilities reported by the adapter: <span className="font-mono">{view.capabilities.join(', ')}</span>
        </span>
      )}
      <span className="text-[10px] text-zinc-500">This is the adapter's self-report; Sentra does not verify it.</span>
    </div>
  )
}
