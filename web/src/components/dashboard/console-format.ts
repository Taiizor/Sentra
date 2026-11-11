import {
  PERMISSION_MIN_ROLE,
  ROLE_LABELS,
  permissionHint as sharedPermissionHint,
  type BinaryCompatibility,
  type BinaryFormat,
  type BinaryInfo,
  type ExecutableSource,
  type HostInfo,
  type Permission,
  type RoleLabel,
  type Severity,
  type SystemStatus,
  type ToolAvailability,
  type ToolSearchStatus,
  type ToolUsage,
} from '@/types/api'
import { persistedPathLabel } from './host-path-advice'

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

/** Where the bridge's tool search found an executable. */
export const EXECUTABLE_SOURCE_LABEL: Record<ExecutableSource, string> = {
  process_path: 'process PATH',
  persisted_system_path: 'system PATH (persisted)',
  persisted_user_path: 'user PATH (persisted)',
  well_known: 'standard install location',
}

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

const BINARY_FORMAT_LABEL: Record<BinaryFormat, string> = {
  pe: 'PE (Windows) executable',
  elf: 'ELF executable',
  macho: 'Mach-O executable',
  macho_universal: 'Mach-O universal binary',
  script: 'Script (runs through its interpreter)',
  unknown: 'File format not recognised',
}

export const BINARY_COMPATIBILITY_LABEL: Record<BinaryCompatibility, string> = {
  native: 'native',
  emulated: 'emulated',
  compatible_32bit: '32-bit',
  incompatible: 'incompatible',
  script: 'script',
  unknown: 'unknown',
}

export const BINARY_COMPATIBILITY_CLASS: Record<BinaryCompatibility, string> = {
  native: 'text-emerald-300',
  emulated: 'text-amber-300',
  compatible_32bit: 'text-amber-300',
  unknown: 'text-amber-300',
  incompatible: 'text-rose-300',
  script: 'text-zinc-400',
}

/** Architectures read from the executable's header, e.g. "x64", "x64 + arm64 (universal)" or "script". */
export function formatBinaryArchitectures(binary: BinaryInfo): string {
  if (binary.format === 'script') return 'script'
  if (binary.architectures.length === 0) return 'unknown'
  const joined = binary.architectures.join(' + ')
  return binary.format === 'macho_universal' ? `${joined} (universal)` : joined
}

/**
 * Compatibility label shown next to the architectures, or null when it would repeat them
 * (a script has no machine code, so "script" is already the whole answer).
 */
export function formatBinaryCompatibility(binary: BinaryInfo): string | null {
  if (binary.format === 'script' || binary.compatibility === 'script') return null
  return BINARY_COMPATIBILITY_LABEL[binary.compatibility]
}

/** Multi-line tooltip text describing an executable header. */
export function describeBinary(binary: BinaryInfo): string {
  const lines = [BINARY_FORMAT_LABEL[binary.format]]
  if (binary.format !== 'script') {
    lines.push(`Architectures: ${binary.architectures.length > 0 ? binary.architectures.join(', ') : 'not recognised'}`)
    lines.push(`On this host: ${BINARY_COMPATIBILITY_LABEL[binary.compatibility]}`)
  }
  if (binary.note) lines.push(binary.note)
  return lines.join('\n')
}

/**
 * What the last tool search covered. The persisted PATH is named as searched only when it was
 * read, and a partial read says so (mirrors describeSearchScope on the bridge).
 */
export function describeToolSearchScope(toolSearch: ToolSearchStatus, platform: string): string {
  const persisted = persistedPathLabel(platform)
  if (toolSearch.persistedPathRead && !toolSearch.persistedPathError) return `the bridge process PATH, ${persisted} and standard install locations`
  if (toolSearch.persistedPathRead) return `the bridge process PATH, ${persisted} (only partly read) and standard install locations`
  return `the bridge process PATH and standard install locations (${persisted} ${toolSearch.persistedPathError ? 'could not be read' : 'was not read'})`
}

/** Context for tool tooltips; absent for stored topology reports, which do not record the search. */
export interface ToolSearchContext {
  toolSearch: ToolSearchStatus
  platform: string
}

/** Tooltip for a tool's path cell: symlink or shim target, how it was found and later (shadowed) matches. */
export function describeToolPath(tool: ToolAvailability, search?: ToolSearchContext): string {
  if (!tool.path) {
    return search
      ? `Not found. Searched ${describeToolSearchScope(search.toolSearch, search.platform)}.`
      : 'Not found in the directories searched on the bridge host'
  }
  const lines = [tool.path]
  if (tool.resolvedPath) {
    lines.push(tool.resolvedVia === 'scoop_shim' ? `Scoop shim; runs: ${tool.resolvedPath}` : `Resolves to: ${tool.resolvedPath}`)
  }
  if (tool.source) {
    lines.push(`Found via: ${EXECUTABLE_SOURCE_LABEL[tool.source]}`)
    lines.push(tool.onProcessPath ? 'Visible on the bridge process PATH' : 'Not on the bridge process PATH')
  } else if (tool.usage === 'runtime') {
    lines.push('The running executable; its directory is not one of the searched directories')
  }
  const shadowed = tool.shadowed ?? []
  if (shadowed.length > 0) {
    const heading = tool.usage === 'runtime' ? 'Other installations (not the running executable):' : 'Later matches in search order:'
    lines.push(heading, ...shadowed.map((match) => `  ${match}`))
  }
  return lines.join('\n')
}

/**
 * True when a /api/system response has the tool fields this console renders. A bridge started from
 * older code (contract version 1) sends tools as {name, available, path} and no toolSearch.
 */
export function hasCurrentToolShape(status: SystemStatus): boolean {
  const raw = status as unknown as { toolSearch?: unknown; tools?: unknown; host?: { platform?: unknown } }
  if (!raw.toolSearch || typeof raw.toolSearch !== 'object' || !Array.isArray(raw.tools)) return false
  return raw.tools.every((tool: unknown) => {
    const entry = tool as Partial<Record<keyof ToolAvailability, unknown>> | null
    return !!entry && Array.isArray(entry.shadowed) && typeof entry.usage === 'string' && 'resolvedVia' in entry
  })
}

/** True when a HostInfo has the memory and runtime fields this console renders (absent from contract version 1). */
export function hasCurrentHostShape(host: HostInfo): boolean {
  const raw = host as unknown as Partial<Record<keyof HostInfo, unknown>>
  return typeof raw.availableMemoryBytes === 'number' && typeof raw.memorySource === 'string' && typeof raw.runtimePath === 'string'
}

/** "x64", or "x64 process on arm64 hardware (emulated)" when the process and hardware differ. */
export function formatHostArchitecture(host: HostInfo): string {
  if (!host.nativeArch || host.nativeArch === 'unknown' || host.nativeArch === host.arch) return host.arch
  return `${host.arch} process on ${host.nativeArch} hardware${host.archEmulated ? ' (emulated)' : ''}`
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
