import { useEffect } from 'react'
import { Cpu, MonitorCog, Network, RotateCw, Server, ServerOff, Wrench } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import type { HostInfo, SystemStatus, ToolAvailability } from '@/types/api'
import {
  CANNOT_RUN_HERE_LABEL,
  cannotRunHere,
  describeCannotRun,
  formatAccessGrants,
  formatBytes,
  formatDateTime,
  formatHostArchitecture,
  formatTime,
  formatUptime,
  hasCurrentHostShape,
  hasCurrentToolShape,
  MEMORY_SOURCE_LABEL,
  minimumRoleFor,
  toolSearchLocations,
} from './console-format'
import { EmptyBlock, ErrorAlert, KeyValue, LoadingBlock, SectionCard, TabHeader } from './console-kit'
import { ToolsSection } from './host-tools-section'

const HOST_POLL_MS = 10_000

const MEMORY_SOURCE_TITLE: Record<HostInfo['memorySource'], string> = {
  os: 'Available physical memory as reported by the operating system.',
  proc_meminfo: 'MemAvailable from /proc/meminfo: the kernel estimate of memory available without swapping, page cache included.',
  vm_stat:
    'Computed from vm_stat page counts, so memory macOS can reclaim is counted as available (os.freemem() reports only free pages there).',
}

/**
 * The bridge host and its tooling. Sentra's core has no persisted remote-worker registry, so
 * this view reports that fact instead of rendering workers, leases or quarantine states.
 */
export function WorkerFleetTab() {
  const { invalidate } = useConsole()
  const status = useResource('system-status', (signal) => api.system.status(signal))
  const host = useResource('system-host', (signal) => api.system.host(signal))
  const reloadHost = host.reload

  // After a tool path is set or reset: show the row the bridge returned at once, then refetch every
  // view (the system status here, Settings → System, scan and topology messages).
  const applyTool = (tool: ToolAvailability) => {
    const current = status.data
    if (current) status.setData({ ...current, tools: current.tools.map((entry) => (entry.name === tool.name ? tool : entry)) })
    invalidate()
  }

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
              {hasCurrentHostShape(hostInfo) ? <HostDetails host={hostInfo} /> : <RestartBridgeNotice what="the host details" />}
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

      <SectionCard
        icon={<Wrench className="size-4 text-emerald-400" />}
        title="Tools on the bridge host"
        description={`Found automatically on ${toolSearchLocations(status.data?.host?.platform)}, unless a path was set here. Tools are never run to detect them: presence, and whether the file can run on this machine, are read from the file. Versions and licences are not checked.`}
      >
        {!status.data ? (
          status.error ? <p className="text-xs text-muted-foreground">Unavailable: system status failed to load.</p> : <LoadingBlock rows={4} />
        ) : hasCurrentToolShape(status.data) ? (
          <ToolsSection status={status.data} onToolUpdated={applyTool} />
        ) : (
          <RestartBridgeNotice what="the tool search details" />
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
  const usedMemory = Math.max(0, host.totalMemoryBytes - host.availableMemoryBytes)
  const memoryPercent = host.totalMemoryBytes > 0 ? Math.round((usedMemory / host.totalMemoryBytes) * 100) : 0
  const emulated = !!host.archEmulated && !!host.nativeArch && host.nativeArch !== 'unknown'
  const emulator = host.platform === 'darwin' ? 'Rosetta 2' : host.platform === 'win32' ? 'Windows on Arm emulation' : 'emulation'
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
        <KeyValue label="Hostname" mono>
          {host.hostname}
        </KeyValue>
        <KeyValue label="Operating system">
          {host.osName ?? host.platform}
          <span className="block font-mono text-[10px] text-muted-foreground">
            {host.platform} {host.release}
          </span>
        </KeyValue>
        <KeyValue label="Architecture" mono>
          <span
            className={emulated ? 'text-amber-300' : undefined}
            title={emulated ? `The bridge process runs under ${emulator} on ${host.nativeArch} hardware.` : undefined}
          >
            {formatHostArchitecture(host)}
          </span>
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
          <span className="block truncate text-[10px] text-muted-foreground" title={host.runtimePath}>
            {host.runtimePath}
          </span>
          {host.runtimePathNote && (
            <span className="block text-[10px] leading-snug whitespace-normal text-amber-300" title={host.runtimePathNote}>
              install path unknown (bun-node shim shown)
            </span>
          )}
        </KeyValue>
      </div>
      <div className="flex flex-col gap-1">
        <div className="flex flex-wrap items-center justify-between gap-x-3 text-[11px]">
          <span className="text-muted-foreground">System memory in use</span>
          <span className="font-mono text-zinc-200">
            {formatBytes(usedMemory)} / {formatBytes(host.totalMemoryBytes)} ({memoryPercent}%)
          </span>
        </div>
        <Progress value={memoryPercent} aria-label="System memory in use" />
        <span className="text-[10px] text-muted-foreground" title={MEMORY_SOURCE_TITLE[host.memorySource]}>
          {formatBytes(host.availableMemoryBytes)} available · source: <span className="font-mono">{MEMORY_SOURCE_LABEL[host.memorySource]}</span>
        </span>
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
        {!status.core.present ? (
          <span className="text-rose-300">no — scans and console commands cannot run</span>
        ) : status.core.binary && cannotRunHere(status.core.binary) ? (
          <span className="text-rose-300" title={describeCannotRun(status.core.binary)}>
            {CANNOT_RUN_HERE_LABEL}
          </span>
        ) : (
          <span className="text-emerald-300">yes</span>
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
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
      <KeyValue label="Bind address" mono>
        {auth.bindHost} {auth.loopbackOnly ? '(loopback only)' : '(reachable beyond loopback)'}
      </KeyValue>
      <KeyValue label="Configured access grants">{formatAccessGrants(auth)}</KeyValue>
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
      <p className="text-[11px] text-muted-foreground sm:col-span-2 lg:col-span-3">
        Read at {formatDateTime(status.host.sampledAt)}. The bind address, access grants and webhook secrets come from the
        bridge's environment (SENTRA_WEB_HOST, SENTRA_WEB_TOKENS, SENTRA_GITHUB_WEBHOOK_SECRET,
        SENTRA_GITLAB_WEBHOOK_TOKEN). AI providers, the stored GitHub token and the OSV policy are changed in
        Settings by someone with the {minimumRoleFor('settings:write')} role.
      </p>
    </div>
  )
}

/** Placeholder for a section whose data the running bridge does not send yet (it runs older code). */
function RestartBridgeNotice({ what }: { what: string }) {
  return (
    <p className="text-xs text-amber-300">
      The bridge did not send {what}: it is running older code than this console. Restart the bridge (for example stop and
      rerun <span className="font-mono">bun run dev</span>) to see them.
    </p>
  )
}
