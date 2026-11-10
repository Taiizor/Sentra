import { permissionHint as sharedPermissionHint, type GitHubCredentialSource, type Permission } from '@/types/api'

/**
 * Pure helpers shared by the Pull Requests, Webhooks and Settings tabs (kept out of the
 * component files so React fast refresh keeps working).
 */

/** Display-only explanation derived from the shared role matrix (PERMISSION_MIN_ROLE); the server enforces. */
export function permissionHint(permission: Permission): string {
  return sharedPermissionHint(permission)
}

export const CREDENTIAL_SOURCE_LABEL: Record<GitHubCredentialSource, string> = {
  stored_pat: 'Token stored in Settings',
  env_token: 'GITHUB_TOKEN / GH_TOKEN environment variable',
  gh_cli: 'GitHub CLI session (gh auth token)',
}

export function shortSha(sha: string | null | undefined): string {
  return sha ? sha.slice(0, 7) : '—'
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}

export function relativeTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return '—'
  const time = Date.parse(iso)
  if (Number.isNaN(time)) return iso
  const seconds = Math.round((now - time) / 1000)
  const abs = Math.abs(seconds)
  const suffix = seconds >= 0 ? 'ago' : 'from now'
  if (abs < 45) return seconds >= 0 ? 'just now' : 'in a moment'
  if (abs < 3600) return `${Math.round(abs / 60)} min ${suffix}`
  if (abs < 86_400) return `${Math.round(abs / 3600)} h ${suffix}`
  if (abs < 30 * 86_400) return `${Math.round(abs / 86_400)} d ${suffix}`
  return new Date(time).toLocaleDateString()
}

export function formatDuration(totalSeconds: number | null | undefined): string {
  if (totalSeconds === null || totalSeconds === undefined || !Number.isFinite(totalSeconds)) return '—'
  if (totalSeconds < 60) return `${totalSeconds}s`
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  if (minutes < 60) return `${minutes}m ${seconds}s`
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`
}

/** Seconds between two ISO timestamps, or null when either is missing or the order is invalid. */
export function secondsBetween(start: string | null | undefined, end: string | null | undefined): number | null {
  if (!start || !end) return null
  const delta = (Date.parse(end) - Date.parse(start)) / 1000
  return Number.isFinite(delta) && delta >= 0 ? Math.round(delta) : null
}

/** GitHub Actions status/conclusion as display text. */
export function runStateLabel(status: string, conclusion: string | null): string {
  if (status !== 'completed') return status.replace(/_/g, ' ')
  return (conclusion ?? 'completed').replace(/_/g, ' ')
}
