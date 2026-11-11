import type { Severity } from '@/types/api'

export const SEVERITY_BAR_CLASS: Record<Severity, string> = {
  Critical: 'bg-rose-500',
  High: 'bg-orange-500',
  Medium: 'bg-amber-400',
  Low: 'bg-sky-500',
  Informational: 'bg-zinc-400',
  Unknown: 'bg-zinc-600',
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}

export function formatDuration(startIso: string, endIso: string | null): string {
  if (!endIso) return '—'
  const ms = new Date(endIso).getTime() - new Date(startIso).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '—'
  if (ms < 1000) return `${ms} ms`
  const seconds = ms / 1000
  if (seconds < 60) return `${seconds.toFixed(1)} s`
  const minutes = Math.floor(seconds / 60)
  return `${minutes} min ${Math.round(seconds - minutes * 60)} s`
}

export function formatMicroUsd(value: number | null): string {
  if (value === null) return '—'
  return `$${(value / 1_000_000).toFixed(4)}`
}

export function formatCount(value: number | null | undefined): string {
  return value === null || value === undefined ? '—' : value.toLocaleString()
}

export function shortHash(hash: string | null | undefined, length = 12): string {
  if (!hash) return '—'
  return hash.length > length ? `${hash.slice(0, length)}…` : hash
}
