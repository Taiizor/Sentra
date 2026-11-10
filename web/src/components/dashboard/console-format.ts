import { PERMISSION_MIN_ROLE, ROLE_LABELS, permissionHint as sharedPermissionHint, type Permission, type RoleLabel, type Severity } from '@/types/api'

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
