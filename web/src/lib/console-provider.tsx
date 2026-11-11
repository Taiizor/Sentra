import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, errorMessage, UNAUTHENTICATED_EVENT } from '@/lib/api'
import { ConsoleContext, type ConsoleState } from '@/lib/console-context'
import { useRouteState } from '@/lib/router'
import type { Permission, SessionInfo, TenantView } from '@/types/api'

/** Owns the console-wide state described by ConsoleState (see console-context.tsx). */
export function ConsoleProvider({
  session,
  onSignedOut,
  children,
}: {
  session: SessionInfo
  onSignedOut: () => void
  children: ReactNode
}) {
  const route = useRouteState()
  const [tenants, setTenants] = useState<TenantView[]>([])
  const [tenantsLoaded, setTenantsLoaded] = useState(false)
  const [tenantsError, setTenantsError] = useState<string | null>(null)
  const [dataVersion, setDataVersion] = useState(0)

  // State is only set in the promise callbacks, after the request settles, so the initial load
  // below does not update state synchronously inside the effect.
  const refreshTenants = useCallback(
    (): Promise<TenantView[]> =>
      api.tenants.list().then(
        ({ tenants: list }) => {
          setTenants(list)
          setTenantsError(null)
          setTenantsLoaded(true)
          return list
        },
        (error: unknown) => {
          setTenantsError(errorMessage(error))
          setTenantsLoaded(true)
          return []
        },
      ),
    [],
  )

  useEffect(() => {
    void refreshTenants()
  }, [refreshTenants])

  // Keep the selected tenant valid: fall back to the first registered tenant.
  const { tenantId: routeTenantId, setTenantId: setRouteTenantId } = route
  useEffect(() => {
    if (!tenantsLoaded) return
    if (tenants.length === 0) {
      if (routeTenantId !== null) setRouteTenantId(null)
      return
    }
    if (!routeTenantId || !tenants.some((tenant) => tenant.tenantId === routeTenantId)) {
      setRouteTenantId(tenants[0].tenantId)
    }
  }, [tenantsLoaded, tenants, routeTenantId, setRouteTenantId])

  useEffect(() => {
    const onUnauthenticated = () => onSignedOut()
    window.addEventListener(UNAUTHENTICATED_EVENT, onUnauthenticated)
    return () => window.removeEventListener(UNAUTHENTICATED_EVENT, onUnauthenticated)
  }, [onSignedOut])

  const permissions = useMemo(() => new Set(session.permissions), [session.permissions])
  const can = useCallback((permission: Permission) => permissions.has(permission), [permissions])
  const invalidate = useCallback(() => setDataVersion((value) => value + 1), [])
  const logout = useCallback(async () => {
    try {
      await api.auth.logout()
    } finally {
      onSignedOut()
    }
  }, [onSignedOut])

  const tenant = useMemo(
    () => tenants.find((candidate) => candidate.tenantId === route.tenantId) ?? null,
    [tenants, route.tenantId],
  )

  const value: ConsoleState = {
    session,
    can,
    tenants,
    tenantsLoaded,
    tenantsError,
    tenant,
    setTenantId: route.setTenantId,
    refreshTenants,
    tab: route.tab,
    navigate: route.navigate,
    selectedFindingId: route.findingId,
    setSelectedFindingId: route.setFindingId,
    dataVersion,
    invalidate,
    logout,
  }

  return <ConsoleContext.Provider value={value}>{children}</ConsoleContext.Provider>
}
