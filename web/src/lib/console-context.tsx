import { createContext, useContext } from 'react'
import type { TabId } from '@/lib/router'
import type { Permission, SessionInfo, TenantView } from '@/types/api'

/**
 * Console-wide state: the authenticated session (role and permissions come only from the
 * server), the registered tenants, the selected tenant/tab, and a data version counter that
 * tabs use to refetch after mutations.
 */
export interface ConsoleState {
  session: SessionInfo
  can: (permission: Permission) => boolean
  tenants: TenantView[]
  tenantsLoaded: boolean
  tenantsError: string | null
  /** Currently selected tenant, or null when none is registered/selected. */
  tenant: TenantView | null
  setTenantId: (tenantId: string | null) => void
  refreshTenants: () => Promise<TenantView[]>
  tab: TabId
  navigate: (tab: TabId, options?: { findingId?: string | null }) => void
  selectedFindingId: string | null
  setSelectedFindingId: (findingId: string | null) => void
  /** Increments after any mutation that changes server data; resources refetch on change. */
  dataVersion: number
  invalidate: () => void
  logout: () => Promise<void>
}

/** Provided by <ConsoleProvider> (console-provider.tsx); kept here so this module exports no components. */
export const ConsoleContext = createContext<ConsoleState | null>(null)

export function useConsole(): ConsoleState {
  const value = useContext(ConsoleContext)
  if (!value) throw new Error('useConsole must be used inside <ConsoleProvider>')
  return value
}

/** Convenience: the selected tenant, throwing if none (only use inside tenant-scoped views). */
export function useTenant(): TenantView {
  const { tenant } = useConsole()
  if (!tenant) throw new Error('useTenant requires a selected tenant')
  return tenant
}
