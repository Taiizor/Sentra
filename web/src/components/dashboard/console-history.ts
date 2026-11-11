import { useSyncExternalStore } from 'react'
import type { ConsoleCommand, ConsoleRunView } from '@/types/api'

/**
 * In-memory history of console runs for this browser tab. It survives switching tabs inside
 * the console but not a page reload, and it is never sent anywhere.
 */
export interface ConsoleHistoryEntry {
  id: number
  principal: string
  tenantId: string
  tenantName: string
  command: ConsoleCommand
  requestedAt: string
  result: ConsoleRunView | null
  error: string | null
}

const MAX_ENTRIES = 25
let entries: readonly ConsoleHistoryEntry[] = []
let nextId = 1
const listeners = new Set<() => void>()

function emit(): void {
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function getSnapshot(): readonly ConsoleHistoryEntry[] {
  return entries
}

export function addConsoleHistoryEntry(entry: Omit<ConsoleHistoryEntry, 'id'>): ConsoleHistoryEntry {
  const stored: ConsoleHistoryEntry = { ...entry, id: nextId++ }
  entries = [stored, ...entries].slice(0, MAX_ENTRIES)
  emit()
  return stored
}

export function clearConsoleHistory(principal: string): void {
  entries = entries.filter((entry) => entry.principal !== principal)
  emit()
}

/** History entries recorded by `principal` (other sign-ins in this tab are not shown). */
export function useConsoleHistory(principal: string): readonly ConsoleHistoryEntry[] {
  const all = useSyncExternalStore(subscribe, getSnapshot, getSnapshot)
  return all.filter((entry) => entry.principal === principal)
}
