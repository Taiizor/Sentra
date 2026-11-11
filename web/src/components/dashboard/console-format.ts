import {
  PERMISSION_MIN_ROLE,
  ROLE_LABELS,
  permissionHint as sharedPermissionHint,
  type HostInfo,
  type Permission,
  type RoleLabel,
  type Severity,
  type SystemStatus,
  type ToolAvailability,
  type ToolUsage,
} from '@/types/api'

/**
 * Formatting and display helpers shared by the research, fleet, intel, plugin, studio,
 * console and scan-stream views. Nothing here produces data; it only formats values that
 * came from the bridge.
 */

export function minimumRoleFor(permission: Permission): RoleLabel {
  return ROLE_LABELS[PERMISSION_MIN_ROLE[permission]]
}

/** Display-only explanation derived from the shared role matrix (PERMISSION_MIN_ROLE); the server enforces. */
export function permissionHint(permission: Permission): string {
  return sharedPermissionHint(permission)
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return 'n/a'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value >= 100 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return 'n/a'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return ''
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return 'n/a'
  if (ms < 1000) return `${Math.round(ms)} ms`
  const seconds = ms / 1000
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 2 : 1)} s`
  const minutes = Math.floor(seconds / 60)
  return `${minutes} min ${Math.round(seconds % 60)} s`
}

export function formatUptime(totalSeconds: number): string {
  const days = Math.floor(totalSeconds / 86_400)
  const hours = Math.floor((totalSeconds % 86_400) / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const parts: string[] = []
  if (days > 0) parts.push(`${days}d`)
  if (days > 0 || hours > 0) parts.push(`${hours}h`)
  parts.push(`${minutes}m`)
  return parts.join(' ')
}

/** Budget values in the core store are integer micro-USD. */
export function formatMicroUsd(micro: number | null | undefined): string {
  if (micro === null || micro === undefined) return 'n/a'
  return `$${(micro / 1_000_000).toFixed(micro % 10_000 === 0 ? 2 : 4)}`
}

export function formatCount(value: number | null | undefined): string {
  if (value === null || value === undefined) return 'n/a'
  return value.toLocaleString()
}

/** Pretty-prints `text` when it is a JSON document; returns null otherwise. */
export function tryPrettyJson(text: string): string | null {
  const trimmed = text.trim()
  if (!trimmed || (trimmed[0] !== '{' && trimmed[0] !== '[')) return null
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2)
  } catch {
    return null
  }
}

export const SEVERITY_CLASS: Record<Severity, string> = {
  Critical: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
  High: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  Medium: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  Low: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
  Informational: 'border-zinc-600 bg-zinc-800/60 text-zinc-300',
  Unknown: 'border-zinc-700 bg-zinc-900 text-zinc-400',
}

/** Link to the public OSV record for an advisory id. */
export function osvUrl(advisoryId: string): string {
  return `https://osv.dev/vulnerability/${encodeURIComponent(advisoryId)}`
}

/** Only http(s) links from external data are rendered as anchors. */
export function isSafeHttpUrl(value: string): boolean {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:'
  } catch {
    return false
  }
}

// ───────────────────────────── bridge host and tools ─────────────────────────────

export { persistedPathLabel, persistedPathReadState, stalePathAdvice, toolSearchLocations } from './host-path-advice'
export {
  CANNOT_RUN_HERE_LABEL,
  cannotRunHere,
  describeCannotRun,
  describeToolPath,
  describeToolSearchScope,
  EXECUTABLE_SOURCE_LABEL,
  hasConfiguredPath,
  isChosenPath,
  otherCopiesLabel,
  pinVariable,
  toolActions,
  toolDetectionSummary,
  toolPathPlaceholder,
  toolPathUsageText,
  toolSourceLabel,
  toolStatus,
  type ToolActionButton,
  type ToolActions,
  type ToolSearchContext,
  type ToolStatus,
  type ToolStatusKind,
} from './tool-row-format'

export const TOOL_USAGE_LABEL: Record<ToolUsage, string> = {
  executed: 'executed',
  runtime: 'runtime',
  presence_only: 'presence only',
  not_used: 'not used',
}

export const TOOL_USAGE_CLASS: Record<ToolUsage, string> = {
  executed: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
  runtime: 'border-violet-500/40 bg-violet-500/10 text-violet-300',
  presence_only: 'border-zinc-600 bg-zinc-800/60 text-zinc-300',
  not_used: 'border-zinc-700 bg-zinc-900 text-zinc-500',
}

/**
 * True when a /api/system response has the tool fields this console renders. A bridge started from
 * older code sends tools as {name, available, path} and no toolSearch (contract version 1), or
 * without the console-settable path fields (contract version 2).
 */
export function hasCurrentToolShape(status: SystemStatus): boolean {
  const raw = status as unknown as { toolSearch?: unknown; tools?: unknown; host?: { platform?: unknown } }
  if (!raw.toolSearch || typeof raw.toolSearch !== 'object' || !Array.isArray(raw.tools)) return false
  return raw.tools.every((tool: unknown) => {
    const entry = tool as Partial<Record<keyof ToolAvailability, unknown>> | null
    return (
      !!entry &&
      Array.isArray(entry.shadowed) &&
      typeof entry.usage === 'string' &&
      'resolvedVia' in entry &&
      typeof entry.pathConfigurable === 'boolean' &&
      typeof entry.selection === 'string' &&
      'configuredPath' in entry &&
      'configuredPathProblem' in entry
    )
  })
}

/** True when a HostInfo has the memory and runtime fields this console renders (absent from contract version 1). */
export function hasCurrentHostShape(host: HostInfo): boolean {
  const raw = host as unknown as Partial<Record<keyof HostInfo, unknown>>
  return typeof raw.availableMemoryBytes === 'number' && typeof raw.memorySource === 'string' && typeof raw.runtimePath === 'string'
}

/** The bridge process architecture, e.g. "x64", or "x64 (emulated on arm64)" under Rosetta 2 or Windows on Arm. */
export function formatHostArchitecture(host: HostInfo): string {
  if (host.archEmulated && host.nativeArch && host.nativeArch !== 'unknown') return `${host.arch} (emulated on ${host.nativeArch})`
  return host.arch
}

/** Where "available memory" came from (macOS and Linux do not use os.freemem(), which undercounts there). */
export const MEMORY_SOURCE_LABEL: Record<HostInfo['memorySource'], string> = {
  os: 'OS',
  proc_meminfo: '/proc/meminfo',
  vm_stat: 'vm_stat',
}

/**
 * Access grants from SENTRA_WEB_TOKENS. The generated local admin token exists only when that
 * variable is unset, and is reported as such instead of being added to the count.
 */
export function formatAccessGrants(auth: SystemStatus['auth']): string {
  if (auth.generatedLocalToken && auth.configuredGrants === 0) return 'a generated local admin token (SENTRA_WEB_TOKENS not set)'
  const count = `${auth.configuredGrants} ${auth.configuredGrants === 1 ? 'grant' : 'grants'} from SENTRA_WEB_TOKENS`
  return auth.generatedLocalToken ? `${count} and a generated local admin token` : count
}
