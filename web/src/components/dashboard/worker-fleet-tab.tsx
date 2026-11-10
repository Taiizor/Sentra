import { useEffect } from 'react'
import { CheckCircle2, Cpu, MonitorCog, Network, RotateCw, Server, ServerOff, Wrench, XCircle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api, errorMessage } from '@/lib/api'
import { useResource } from '@/lib/use-resource'
import type { HostInfo, SystemStatus } from '@/types/api'
import { formatBytes, formatDateTime, formatTime, formatUptime, minimumRoleFor } from './console-format'
import { EmptyBlock, ErrorAlert, KeyValue, LoadingBlock, SectionCard, TabHeader } from './console-kit'

const HOST_POLL_MS = 10_000

/**
 * The bridge host and its tooling. Sentra's core has no persisted remote-worker registry, so
 * this view reports that fact instead of rendering workers, leases or quarantine states.
 */
export function WorkerFleetTab() {
  const status = useResource('system-status', (signal) => api.system.status(signal))
  const host = useResource('system-host', (signal) => api.system.host(signal))
  const reloadHost = host.reload

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') reloadHost()
    }, HOST_POLL_MS)
    return () => window.clearInterval(timer)
  }, [reloadHost])

  const hostInfo: HostInfo | undefined = host.data ?? status.data?.host

  return (
    <div className="flex flex-col gap-4">
      <TabHeader
        icon={<Server className="size-4 text-amber-400" />}
        title="Workers and host"
        description="Remote workers are not available in this release. This page reports the machine that runs the Sentra bridge and the core CLI."
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              status.reload()
              host.reload()
            }}
            disabled={status.loading}
          >
            <RotateCw className={status.loading ? 'animate-spin' : undefined} />
            Refresh
          </Button>
        }
      />

      <RemoteWorkersCard status={status.data} error={status.error} />

      {status.error && !status.data && <ErrorAlert error={status.error} onRetry={status.reload} title="Could not load system status" />}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <SectionCard
          icon={<MonitorCog className="size-4 text-sky-400" />}
          title="Bridge host"
          description={
            hostInfo
              ? `Sampled at ${formatTime(hostInfo.sampledAt)}; refreshed every ${HOST_POLL_MS / 1000} s while this page is visible.`
              : 'Operating-system metrics of the machine running the bridge.'
          }
        >
          {!hostInfo ? (
            host.error ? (
              <ErrorAlert error={host.error} onRetry={host.reload} title="Could not sample the host" />
            ) : (
              <LoadingBlock rows={4} />
            )
          ) : (
            <>
              {host.error && (
                <p className="text-[11px] text-amber-300">
                  The latest refresh failed ({errorMessage(host.error)}); showing the sample from {formatTime(hostInfo.sampledAt)}.
                </p>
              )}
              <HostDetails host={hostInfo} />
            </>
          )}
        </SectionCard>

        <SectionCard icon={<Cpu className="size-4 text-violet-400" />} title="Sentra core CLI">
          {!status.data ? (
            status.error ? <p className="text-xs text-muted-foreground">Unavailable: system status failed to load.</p> : <LoadingBlock rows={3} />
          ) : (
            <CoreDetails status={status.data} cliQueued={hostInfo?.cliQueued ?? null} />
          )}
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <SectionCard
          icon={<Wrench className="size-4 text-emerald-400" />}
          title="Tools on the bridge host"
          description="Executables found on the bridge's PATH. Presence only; versions and licences are not checked."
        >
          {!status.data ? (
            status.error ? <p className="text-xs text-muted-foreground">Unavailable: system status failed to load.</p> : <LoadingBlock rows={4} />
          ) : (
            <Table className="text-xs">
              <TableHeader>
                <TableRow>
                  <TableHead>Tool</TableHead>
                  <TableHead>Found</TableHead>
                  <TableHead>Path</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {status.data.tools.map((tool) => (
                  <TableRow key={tool.name}>
                    <TableCell className="font-mono text-[11px]">{tool.name}</TableCell>
                    <TableCell>
                      {tool.available ? (
                        <CheckCircle2 className="size-3.5 text-emerald-400" aria-label="found" />
                      ) : (
                        <XCircle className="size-3.5 text-zinc-600" aria-label="not found" />
                      )}
                    </TableCell>
                    <TableCell className="max-w-96 truncate font-mono text-[11px] text-zinc-400" title={tool.path ?? undefined}>
                      {tool.path ?? 'not on PATH'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </SectionCard>

        <SectionCard icon={<Network className="size-4 text-amber-400" />} title="Bridge configuration">
          {!status.data ? (
            status.error ? <p className="text-xs text-muted-foreground">Unavailable: system status failed to load.</p> : <LoadingBlock rows={4} />
          ) : (
            <BridgeConfig status={status.data} />
          )}
        </SectionCard>
      </div>
    </div>
  )
}

function RemoteWorkersCard({ status, error }: { status: SystemStatus | undefined; error: Error | null }) {
  return (
    <SectionCard
      icon={<ServerOff className="size-4 text-zinc-400" />}
      title="Remote worker fleet"
      actions={
        status && (
          <Badge variant="outline" className="border-zinc-600 font-mono text-[10px] text-zinc-400">
            registry: not available
          </Badge>
        )
      }
    >
      {!status ? (
        error ? <p className="text-xs text-muted-foreground">Unknown: system status failed to load.</p> : <LoadingBlock rows={1} />
      ) : (
        <EmptyBlock icon={<ServerOff />} title="No remote workers" className="p-4">
          {status.remoteWorkers.note}
        </EmptyBlock>
      )}
    </SectionCard>
  )
}

function HostDetails({ host }: { host: HostInfo }) {
  const usedMemory = Math.max(0, host.totalMemoryBytes - host.freeMemoryBytes)
  const memoryPercent = host.totalMemoryBytes > 0 ? Math.round((usedMemory / host.totalMemoryBytes) * 100) : 0
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
        <KeyValue label="Hostname" mono>
          {host.hostname}
        </KeyValue>
        <KeyValue label="Operating system" mono>
          {host.platform} {host.release}
        </KeyValue>
        <KeyValue label="Architecture" mono>
          {host.arch}
        </KeyValue>
        <KeyValue label="CPU">
          {host.cpuModel ?? 'model not reported'} × {host.cpuCount}
        </KeyValue>
        <KeyValue label="Load average (1 / 5 / 15 min)" mono>
          {host.loadAverage
            ? host.loadAverage.map((value) => value.toFixed(2)).join(' / ')
            : host.platform === 'win32'
              ? 'not available on Windows'
              : 'not reported'}
        </KeyValue>
        <KeyValue label="Host uptime">{formatUptime(host.uptimeSeconds)}</KeyValue>
        <KeyValue label="Bridge process memory (RSS)">{formatBytes(host.processRssBytes)}</KeyValue>
        <KeyValue label="Bun runtime" mono>
          {host.bunVersion}
        </KeyValue>
      </div>
      <div className="flex flex-col gap-1">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-muted-foreground">System memory in use</span>
          <span className="font-mono text-zinc-200">
            {formatBytes(usedMemory)} / {formatBytes(host.totalMemoryBytes)} ({memoryPercent}%)
          </span>
        </div>
        <Progress value={memoryPercent} aria-label="System memory in use" />
      </div>
    </div>
  )
}

function CoreDetails({ status, cliQueued }: { status: SystemStatus; cliQueued: number | null }) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <KeyValue label="Binary" mono className="sm:col-span-2">
        {status.core.binaryPath}
      </KeyValue>
      <KeyValue label="Binary present">
        {status.core.present ? (
          <span className="text-emerald-300">yes</span>
        ) : (
          <span className="text-rose-300">no — scans and console commands cannot run</span>
        )}
      </KeyValue>
      <KeyValue label="Version" mono>
        {status.core.version ?? (status.core.error ? `unknown (${status.core.error})` : 'unknown')}
      </KeyValue>
      <KeyValue label="Bridge mode">{status.mode}</KeyValue>
      <KeyValue label="Core CLI calls waiting for a slot">{cliQueued ?? 'n/a'}</KeyValue>
      <KeyValue label="Bridge data directory" mono className="sm:col-span-2">
        {status.dataDir}
      </KeyValue>
    </div>
  )
}

function BridgeConfig({ status }: { status: SystemStatus }) {
  const { auth, integrations } = status
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <KeyValue label="Bind address" mono>
        {auth.bindHost} {auth.loopbackOnly ? '(loopback only)' : '(reachable beyond loopback)'}
      </KeyValue>
      <KeyValue label="Configured access grants">
        {auth.configuredGrants}
        {auth.generatedLocalToken ? ' + a generated local admin token' : ''}
      </KeyValue>
      <KeyValue label="GitHub credential">{integrations.githubCredentialSource ?? 'not configured'}</KeyValue>
      <KeyValue label="OSV lookups">{integrations.osvEnabled ? 'enabled' : 'disabled'}</KeyValue>
      <KeyValue label="AI providers ready">
        {integrations.aiReadyProviders.length > 0 ? integrations.aiReadyProviders.join(', ') : 'none'}
        {integrations.aiDefaultProvider ? ` (default: ${integrations.aiDefaultProvider})` : ''}
      </KeyValue>
      <KeyValue label="Webhook secrets">
        GitHub {integrations.githubWebhookSecretConfigured ? 'configured' : 'not configured'} · GitLab{' '}
        {integrations.gitlabWebhookTokenConfigured ? 'configured' : 'not configured'}
      </KeyValue>
      <p className="text-[11px] text-muted-foreground sm:col-span-2">
        Read at {formatDateTime(status.host.sampledAt)}. The bind address, access grants and webhook secrets come from the
        bridge's environment (SENTRA_WEB_HOST, SENTRA_WEB_TOKENS, SENTRA_GITHUB_WEBHOOK_SECRET,
        SENTRA_GITLAB_WEBHOOK_TOKEN). AI providers, the stored GitHub token and the OSV policy are changed in
        Settings by someone with the {minimumRoleFor('settings:write')} role.
      </p>
    </div>
  )
}
