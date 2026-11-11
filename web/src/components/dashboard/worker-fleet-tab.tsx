import { useEffect } from 'react'
import { AlertTriangle, CheckCircle2, Cpu, MonitorCog, Network, RotateCw, Server, ServerOff, Wrench, XCircle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api, errorMessage } from '@/lib/api'
import { useResource } from '@/lib/use-resource'
import { cn } from '@/lib/utils'
import type { BinaryInfo, HostInfo, SystemStatus, ToolAvailability } from '@/types/api'
import {
  BINARY_COMPATIBILITY_CLASS,
  describeBinary,
  describeToolPath,
  describeToolSearchScope,
  EXECUTABLE_SOURCE_LABEL,
  formatAccessGrants,
  formatBinaryArchitectures,
  formatBinaryCompatibility,
  formatBytes,
  formatDateTime,
  formatHostArchitecture,
  formatTime,
  formatUptime,
  hasCurrentHostShape,
  hasCurrentToolShape,
  MEMORY_SOURCE_LABEL,
  minimumRoleFor,
  persistedPathLabel,
  persistedPathReadState,
  stalePathAdvice,
  TOOL_USAGE_CLASS,
  TOOL_USAGE_LABEL,
  toolSearchLocations,
  type ToolSearchContext,
} from './console-format'
import { EmptyBlock, ErrorAlert, KeyValue, LoadingBlock, SectionCard, TabHeader } from './console-kit'

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
        description={`Located on ${toolSearchLocations(status.data?.host?.platform)}. Presence and binary architecture are read from the file; tools are never run to detect them, and versions and licences are not checked.`}
      >
        {!status.data ? (
          status.error ? <p className="text-xs text-muted-foreground">Unavailable: system status failed to load.</p> : <LoadingBlock rows={4} />
        ) : hasCurrentToolShape(status.data) ? (
          <ToolsSection status={status.data} />
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
  const archDiffers = !!host.nativeArch && host.nativeArch !== 'unknown' && host.nativeArch !== host.arch
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
            className={archDiffers && host.archEmulated ? 'text-amber-300' : undefined}
            title={
              archDiffers
                ? `The bridge process is ${host.arch}; the hardware is ${host.nativeArch}.${host.archEmulated ? ` The process runs under ${host.platform === 'darwin' ? 'Rosetta 2' : host.platform === 'win32' ? 'Windows on Arm emulation' : 'emulation'}.` : ''}`
                : 'Process and hardware architecture match.'
            }
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
        {status.core.present ? (
          <span className="text-emerald-300">yes</span>
        ) : (
          <span className="text-rose-300">no — scans and console commands cannot run</span>
        )}
      </KeyValue>
      <KeyValue label="Version" mono>
        {status.core.version ?? (status.core.error ? `unknown (${status.core.error})` : 'unknown')}
      </KeyValue>
      <KeyValue label="Binary architecture" mono>
        {status.core.binary ? (
          <BinaryArchitecture binary={status.core.binary} />
        ) : (
          <span className="text-muted-foreground">{status.core.present ? 'not read' : 'n/a'}</span>
        )}
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

/** Architectures read from an executable header, coloured by compatibility with this host. */
function BinaryArchitecture({ binary }: { binary: BinaryInfo }) {
  const compatibility = formatBinaryCompatibility(binary)
  return (
    <span className="inline-flex flex-wrap items-baseline gap-x-1.5 font-mono text-[11px]" title={describeBinary(binary)}>
      <span className="text-zinc-200">{formatBinaryArchitectures(binary)}</span>
      {compatibility && <span className={BINARY_COMPATIBILITY_CLASS[binary.compatibility]}>{compatibility}</span>}
    </span>
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

function ToolsSection({ status }: { status: SystemStatus }) {
  const { tools, toolSearch } = status
  const platform = status.host.platform
  const search = { toolSearch, platform }
  const persisted = persistedPathLabel(platform)
  // A tool in a standard install location is "only" there when the persisted PATH was fully read;
  // otherwise the persisted PATH may list its directory too.
  const persistedRead = persistedPathReadState(toolSearch)
  // Tools the bridge's own environment cannot see, grouped by where they were found. The running Bun
  // (usage "runtime") is left out: starting the bridge by absolute path from a directory that is not
  // on PATH is normal and says nothing about a stale PATH. A runtime started from outside the
  // searched directories has source null and is never listed either.
  const offPath = tools.filter((tool) => tool.available && tool.usage !== 'runtime')
  const persistedOnly = offPath.filter((tool) => tool.source === 'persisted_system_path' || tool.source === 'persisted_user_path')
  const wellKnownOnly = offPath.filter((tool) => tool.source === 'well_known')
  return (
    <div className="flex flex-col gap-3">
      <p className="text-[11px] text-muted-foreground">
        Searched {toolSearch.searchedDirectories} {toolSearch.searchedDirectories === 1 ? 'directory' : 'directories'} at{' '}
        {formatDateTime(toolSearch.refreshedAt)}: {describeToolSearchScope(toolSearch, platform)}.
        {toolSearch.skippedNetworkEntries > 0 &&
          ` ${toolSearch.skippedNetworkEntries} UNC or device PATH ${toolSearch.skippedNetworkEntries === 1 ? 'entry was' : 'entries were'} skipped on purpose: listing a network share would make the bridge authenticate to that host.`}
      </p>
      {toolSearch.persistedPathError &&
        (toolSearch.persistedPathRead ? (
          <p className="text-[11px] text-amber-300">
            Part of {persisted} could not be read ({toolSearch.persistedPathError}). The entries that were read are included in the
            search.
          </p>
        ) : (
          <p className="text-[11px] text-amber-300">
            {persisted.charAt(0).toUpperCase() + persisted.slice(1)} could not be read ({toolSearch.persistedPathError}). Only the
            bridge process PATH and standard install locations were searched.
          </p>
        ))}
      {persistedOnly.length > 0 && (
        <OffPathBanner tools={persistedOnly} found={`in ${persisted}`} advice={stalePathAdvice(platform, 'persisted')} />
      )}
      {wellKnownOnly.length > 0 && (
        <OffPathBanner
          tools={wellKnownOnly}
          found={persistedRead === 'read' ? 'only in a standard install location' : 'in a standard install location'}
          advice={stalePathAdvice(platform, 'well_known', persistedRead)}
        />
      )}
      {(persistedOnly.length > 0 || wellKnownOnly.length > 0) && (
        <p className="text-[11px] text-muted-foreground">
          The only tool the bridge runs itself is gh, from the process PATH or the persisted PATH (never from a standard install
          location); its usage note names the file. Programs the bridge starts, such as the core CLI and plugin adapters, look
          tools up on the bridge process PATH only.
        </p>
      )}
      <Table className="text-xs">
        <TableHeader>
          <TableRow>
            <TableHead>Tool</TableHead>
            <TableHead>Found</TableHead>
            <TableHead>Path</TableHead>
            <TableHead>Architecture</TableHead>
            <TableHead>Used by the bridge</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {tools.map((tool) => (
            <ToolRow key={tool.name} tool={tool} search={search} />
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function OffPathBanner({ tools, found, advice }: { tools: ToolAvailability[]; found: string; advice: string }) {
  return (
    <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 p-2.5 text-[11px] text-amber-200">
      <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-amber-400" />
      <span>
        <span className="font-mono">{tools.map((tool) => tool.name).join(', ')}</span> {tools.length === 1 ? 'was' : 'were'} found{' '}
        {found}, but not on the bridge process PATH. {advice}
      </span>
    </div>
  )
}

function ToolRow({ tool, search }: { tool: ToolAvailability; search: ToolSearchContext }) {
  const count = tool.shadowed.length
  const otherMatches =
    tool.usage === 'runtime' ? (count === 1 ? 'other install' : 'other installs') : count === 1 ? 'later match' : 'later matches'
  return (
    <TableRow>
      <TableCell className="align-top font-mono text-[11px]">{tool.name}</TableCell>
      <TableCell className="align-top">
        {tool.available ? (
          <CheckCircle2 className="size-3.5 text-emerald-400" aria-label="found" />
        ) : (
          <XCircle className="size-3.5 text-zinc-600" aria-label="not found" />
        )}
      </TableCell>
      <TableCell className="max-w-96 align-top">
        {tool.path ? (
          <div className="flex min-w-0 flex-col gap-0.5" title={describeToolPath(tool, search)}>
            <span className="truncate font-mono text-[11px] text-zinc-300">{tool.path}</span>
            <span className="truncate text-[10px] text-muted-foreground">
              {tool.source ? EXECUTABLE_SOURCE_LABEL[tool.source] : 'outside the searched directories'}
              {tool.source && !tool.onProcessPath && <span className="text-amber-300"> · not on the process PATH</span>}
              {tool.resolvedPath && (tool.resolvedVia === 'scoop_shim' ? ' · Scoop shim' : ' · symlink')}
              {count > 0 && ` · ${count} ${otherMatches}`}
            </span>
          </div>
        ) : (
          <span className="text-[11px] text-zinc-500" title={describeToolPath(tool, search)}>
            not found
          </span>
        )}
      </TableCell>
      <TableCell className="align-top">
        {tool.binary ? (
          <BinaryArchitecture binary={tool.binary} />
        ) : (
          <span className="text-[11px] text-zinc-600">{tool.available ? 'not read' : '—'}</span>
        )}
      </TableCell>
      <TableCell className="min-w-56 align-top whitespace-normal">
        <div className="flex flex-col items-start gap-0.5">
          <Badge variant="outline" className={cn('font-mono text-[10px]', TOOL_USAGE_CLASS[tool.usage])}>
            {TOOL_USAGE_LABEL[tool.usage]}
          </Badge>
          {tool.usageNote && <span className="text-[10px] leading-snug text-muted-foreground">{tool.usageNote}</span>}
        </div>
      </TableCell>
    </TableRow>
  )
}
