import { useRef, useState } from 'react'
import { Globe, Play, Radar, Settings, ShieldOff } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { api } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import type { IntelStatusView } from '@/types/api'
import { formatDateTime, minimumRoleFor, permissionHint } from './console-format'
import { ErrorAlert, GatedButton, KeyValue, LoadingBlock, NoTenantState, SectionCard, TabHeader } from './console-kit'
import { DependencyFindings } from './intel-dependency-findings'
import { DependencyInventory } from './intel-inventory'
import { OsvLookup, type OsvLookupHandle } from './intel-osv-lookup'
import { LiveStreamModal } from './live-stream-modal'

/**
 * Dependency vulnerability intelligence from OSV.dev, queried on demand and only when an
 * administrator has enabled outbound OSV lookups. No local advisory mirror exists.
 */
export function ThreatIntelTab() {
  const { tenant, can } = useConsole()
  const status = useResource('intel-status', (signal) => api.intel.status(signal))
  const [scanOpen, setScanOpen] = useState(false)
  const lookupRef = useRef<OsvLookupHandle>(null)

  const osvEnabled = status.data?.osvEnabled ?? null
  const osvBlockedReason =
    osvEnabled === false
      ? `OSV lookups are disabled by policy; someone with the ${minimumRoleFor('settings:write')} role can enable them in Settings`
      : null

  return (
    <div className="flex flex-col gap-4">
      <TabHeader
        icon={<Radar className="size-4 text-violet-400" />}
        title="Threat intelligence"
        description="Known-vulnerability data for this workspace's dependencies, looked up on OSV.dev on demand. Sentra does not keep a local advisory mirror."
      />

      <OsvStatusCard status={status.data} error={status.error} onRetry={status.reload} />

      {!tenant ? (
        <NoTenantState feature="Dependency intelligence" />
      ) : (
        <>
          <DependencyFindings
            tenant={tenant}
            actions={
              <GatedButton permission="scan:run" blockedReason={osvBlockedReason} size="sm" onClick={() => setScanOpen(true)}>
                <Play className="fill-current" />
                Run dependency audit
              </GatedButton>
            }
          />
          <DependencyInventory
            tenant={tenant}
            lookupBlockedReason={
              !can('intel:query')
                ? permissionHint('intel:query')
                : (osvBlockedReason ?? (status.data ? null : 'The OSV policy has not been loaded'))
            }
            onLookup={(pkg) =>
              lookupRef.current?.lookup({ package: pkg.name, ecosystem: pkg.ecosystem ?? '', version: pkg.version })
            }
          />
        </>
      )}

      <OsvLookup ref={lookupRef} blockedReason={osvBlockedReason} />

      {tenant && <LiveStreamModal open={scanOpen} onOpenChange={setScanOpen} kind="dependency" />}
    </div>
  )
}

function OsvStatusCard({
  status,
  error,
  onRetry,
}: {
  status: IntelStatusView | undefined
  error: Error | null
  onRetry: () => void
}) {
  const { can, navigate } = useConsole()
  return (
    <SectionCard
      icon={<Globe className="size-4 text-sky-400" />}
      title="OSV.dev lookups"
      actions={
        status && (
          <Badge
            variant="outline"
            className={
              status.osvEnabled ? 'border-emerald-500/30 text-emerald-300' : 'border-zinc-600 text-zinc-400'
            }
          >
            {status.osvEnabled ? 'enabled' : 'disabled'}
          </Badge>
        )
      }
    >
      {error ? (
        <ErrorAlert error={error} onRetry={onRetry} title="Could not read the OSV policy" />
      ) : !status ? (
        <LoadingBlock rows={2} />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <KeyValue label="Endpoint" mono>
              {status.endpoint}
            </KeyValue>
            <KeyValue label="Cached OSV records">{status.cachedAdvisories.toLocaleString()}</KeyValue>
            <KeyValue label="Last query">{status.lastQueryAt ? formatDateTime(status.lastQueryAt) : 'never'}</KeyValue>
            <KeyValue label="Policy last changed">
              {status.changedAt ? `${formatDateTime(status.changedAt)} by ${status.changedBy ?? 'unknown'}` : 'never changed'}
            </KeyValue>
          </div>
          <p className="text-[11px] text-muted-foreground">{status.privacyNote}</p>
          {!status.osvEnabled && (
            <Alert className="border-amber-500/30 bg-amber-500/5">
              <ShieldOff className="text-amber-400" />
              <AlertTitle className="text-xs font-semibold text-amber-200">Dependency vulnerability lookups are off</AlertTitle>
              <AlertDescription className="flex flex-col gap-2 text-xs">
                <span>
                  Dependency audits are skipped and OSV queries are refused until someone with the {minimumRoleFor('settings:write')} role enables
                  OSV lookups in Settings. The local lockfile inventory below is still available.
                </span>
                {can('settings:write') ? (
                  <div>
                    <Button variant="outline" size="xs" onClick={() => navigate('settings')}>
                      <Settings />
                      Open Settings
                    </Button>
                  </div>
                ) : (
                  <span className="text-[11px] text-zinc-500">{permissionHint('settings:write')}</span>
                )}
              </AlertDescription>
            </Alert>
          )}
        </>
      )}
    </SectionCard>
  )
}
