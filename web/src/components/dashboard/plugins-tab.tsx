import { useMemo, useState } from 'react'
import { PackageOpen, Puzzle, RotateCw } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { api } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import { cn } from '@/lib/utils'
import type { PluginView } from '@/types/api'
import { EmptyBlock, ErrorAlert, LoadingBlock, TabHeader } from './console-kit'
import { PluginCard } from './plugin-card'
import { PluginRunDialog } from './plugin-run-dialog'

const ALL_FAMILIES = '__all__'

/**
 * Out-of-process adapters discovered from the directory configured by the bridge host
 * (SENTRA_PLUGIN_DIR). Discovery is real; adapter output is the adapter's own report.
 */
export function PluginsTab() {
  const { tenant } = useConsole()
  const plugins = useResource('plugins', (signal) => api.plugins.list(signal))
  const [family, setFamily] = useState<string>(ALL_FAMILIES)
  const [runTarget, setRunTarget] = useState<PluginView | null>(null)

  const families = useMemo(() => [...new Set((plugins.data?.plugins ?? []).map((plugin) => plugin.family))].sort(), [plugins.data])
  const visible = (plugins.data?.plugins ?? []).filter((plugin) => family === ALL_FAMILIES || plugin.family === family)

  return (
    <div className="flex flex-col gap-4">
      <TabHeader
        icon={<Puzzle className="size-4 text-primary" />}
        title="Plugins"
        description="Adapters run as separate processes on the bridge host without a sandbox. Quotas and egress policies in a manifest are declarations; they are not enforced."
        actions={
          <Button variant="outline" size="sm" onClick={plugins.reload} disabled={plugins.loading}>
            <RotateCw className={plugins.loading ? 'animate-spin' : undefined} />
            Rediscover
          </Button>
        }
      />

      {plugins.error ? (
        <ErrorAlert error={plugins.error} onRetry={plugins.reload} title="Plugin discovery failed" />
      ) : !plugins.data ? (
        <LoadingBlock rows={4} />
      ) : !plugins.data.configured ? (
        <EmptyBlock icon={<PackageOpen />} title="Plugin discovery is not configured">
          <span className="flex flex-col gap-2">
            <span>
              Set <code className="font-mono">SENTRA_PLUGIN_DIR</code> in the bridge's environment to a directory that
              contains adapter manifests, then restart the bridge. This is a host-operator setting and cannot be changed
              from the console.
            </span>
            <span>
              The example adapters under <code className="font-mono">examples/adapters</code> return simulated output and
              are not loaded.
            </span>
          </span>
        </EmptyBlock>
      ) : (
        <>
          <div className="flex flex-col gap-2 rounded-lg border border-border/60 bg-card/40 p-2.5 text-xs sm:flex-row sm:items-center sm:justify-between">
            <span className="text-zinc-400">
              Directory <span className="break-all font-mono text-zinc-200">{plugins.data.pluginDir}</span> ·{' '}
              {plugins.data.plugins.length} manifest(s)
            </span>
            {families.length > 1 && (
              <div className="flex flex-wrap items-center gap-1">
                {[ALL_FAMILIES, ...families].map((value) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => setFamily(value)}
                    className={cn(
                      'h-6 rounded-md px-2 font-mono text-[11px] transition-colors',
                      family === value ? 'bg-primary text-primary-foreground' : 'text-zinc-400 hover:bg-muted hover:text-zinc-100',
                    )}
                  >
                    {value === ALL_FAMILIES ? 'all' : value}
                  </button>
                ))}
              </div>
            )}
          </div>
          {plugins.data.note && <p className="text-[11px] text-muted-foreground">{plugins.data.note}</p>}

          {plugins.data.plugins.length === 0 ? (
            <EmptyBlock icon={<PackageOpen />} title="No adapter manifests found">
              The configured directory contains no adapter manifest the core could read.
            </EmptyBlock>
          ) : (
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              {visible.map((plugin) => (
                <PluginCard key={plugin.id} plugin={plugin} tenant={tenant} onRun={setRunTarget} />
              ))}
            </div>
          )}
          {!tenant && (
            <Badge variant="outline" className="w-fit text-[11px] text-zinc-400">
              Probe and run need a selected workspace.
            </Badge>
          )}
        </>
      )}

      {runTarget && tenant && (
        <PluginRunDialog
          key={`${runTarget.id}:${tenant.tenantId}`}
          plugin={runTarget}
          tenant={tenant}
          open
          onOpenChange={(open) => !open && setRunTarget(null)}
        />
      )}
    </div>
  )
}
