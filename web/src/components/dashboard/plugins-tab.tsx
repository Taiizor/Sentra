import { useMemo, useRef, useState } from 'react'
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
import { PluginDirectoryPanel } from './plugin-directory-panel'
import { PluginRunDialog } from './plugin-run-dialog'
import { normalizePluginsView } from './plugins-format'

const ALL_FAMILIES = '__all__'

/**
 * Out-of-process adapters discovered from the plugin directory the bridge host uses:
 * SENTRA_PLUGIN_DIR, otherwise the core's platform default. Discovery is real; adapter output is
 * the adapter's own report.
 */
export function PluginsTab() {
  const { tenant } = useConsole()
  // Set by Rediscover so the next listing bypasses the bridge's 15-second listing cache.
  const bypassCacheRef = useRef(false)
  // Normalised so a bridge that still sends the contract 3 shape renders instead of crashing.
  const plugins = useResource('plugins', async (signal) => {
    const refresh = bypassCacheRef.current
    try {
      return normalizePluginsView(await api.plugins.list(signal, { refresh }))
    } finally {
      // An aborted request is superseded by a new one, which still carries the refresh request.
      if (!signal.aborted) bypassCacheRef.current = false
    }
  })
  const rediscover = () => {
    bypassCacheRef.current = true
    plugins.reload()
  }
  const [family, setFamily] = useState<string>(ALL_FAMILIES)
  const [runTarget, setRunTarget] = useState<PluginView | null>(null)

  const families = useMemo(() => [...new Set((plugins.data?.plugins ?? []).map((plugin) => plugin.family))].sort(), [plugins.data])
  const visible = (plugins.data?.plugins ?? []).filter((plugin) => family === ALL_FAMILIES || plugin.family === family)

  return (
    <div className="flex flex-col gap-4">
      <TabHeader
        icon={<Puzzle className="size-4 text-primary" />}
        title="Plugins"
        description="Adapters run as separate processes on the bridge host without a sandbox. The core enforces the manifest's execution time limit and its frame and output quotas and kills the adapter's process tree when a session ends; the declared memory quota and egress policy are not enforced."
        actions={
          <Button variant="outline" size="sm" onClick={rediscover} disabled={plugins.loading}>
            <RotateCw className={plugins.loading ? 'animate-spin' : undefined} />
            Rediscover
          </Button>
        }
      />

      {plugins.error ? (
        <ErrorAlert error={plugins.error} onRetry={rediscover} title="Plugin discovery failed" />
      ) : !plugins.data ? (
        <LoadingBlock rows={4} />
      ) : (
        <>
          <PluginDirectoryPanel view={plugins.data} />

          {!plugins.data.configured ? (
            <EmptyBlock icon={<PackageOpen />} title="Plugin discovery is not configured">
              The example adapters under <code className="font-mono">examples/adapters</code> are never loaded implicitly;
              the Snyk and Ollama examples return simulated output.
            </EmptyBlock>
          ) : plugins.data.plugins.length === 0 ? (
            <EmptyBlock icon={<PackageOpen />} title="No adapters loaded">
              {plugins.data.directoryExists
                ? 'The directory holds no adapter manifest the core could load; see the diagnostics above.'
                : 'The directory does not exist yet.'}
            </EmptyBlock>
          ) : (
            <>
              <div className="flex flex-col gap-2 rounded-lg border border-border/60 bg-card/40 p-2.5 text-xs sm:flex-row sm:items-center sm:justify-between">
                <span className="text-zinc-400">{plugins.data.plugins.length} adapter(s) loaded</span>
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
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                {visible.map((plugin) => (
                  <PluginCard key={plugin.id} plugin={plugin} tenant={tenant} onRun={setRunTarget} />
                ))}
              </div>
              {!tenant && (
                <Badge variant="outline" className="w-fit text-[11px] text-zinc-400">
                  Probe and run need a selected workspace.
                </Badge>
              )}
            </>
          )}

          {plugins.data.configured && plugins.data.note && <p className="text-[11px] text-muted-foreground">{plugins.data.note}</p>}
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
