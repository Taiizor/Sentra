import { useState, useEffect, useCallback, useRef } from 'react'
import type { TenantId, UserRole } from '@/types/sentra'

export const VALID_TABS = [
  'overview',
  'studio',
  'findings',
  'remediation',
  'intel',
  'research',
  'fleet',
  'webhooks',
  'audit',
] as const

export type TabId = (typeof VALID_TABS)[number]

const PATH_TO_TAB: Record<string, TabId> = {
  '': 'overview',
  '/': 'overview',
  '/overview': 'overview',
  '/studio': 'studio',
  '/findings': 'findings',
  '/remediation': 'remediation',
  '/intel': 'intel',
  '/threat-intel': 'intel',
  '/research': 'research',
  '/fleet': 'fleet',
  '/webhooks': 'webhooks',
  '/audit': 'audit',
}

const TAB_TO_PATH: Record<TabId, string> = {
  overview: '/',
  studio: '/studio',
  findings: '/findings',
  remediation: '/remediation',
  intel: '/intel',
  research: '/research',
  fleet: '/fleet',
  webhooks: '/webhooks',
  audit: '/audit',
}

export interface RouterState {
  activeTab: TabId
  currentTenant: TenantId
  currentRole: UserRole
  currentWorkspace: string
  selectedFindingId: string | null
}

function parseUrlState(): RouterState {
  const path = window.location.pathname.replace(/\/+$/, '') || '/'
  const searchParams = new URLSearchParams(window.location.search)
  const hash = window.location.hash.replace(/^#\/?/, '')

  // 1. Resolve Active Tab (Priority: Pathname > Hash > SearchParam > Fallback)
  let activeTab: TabId = PATH_TO_TAB[path] || 'overview'
  if (hash && (VALID_TABS as readonly string[]).includes(hash)) {
    activeTab = hash as TabId
  }
  const tabParam = searchParams.get('tab')
  if (tabParam && (VALID_TABS as readonly string[]).includes(tabParam)) {
    activeTab = tabParam as TabId
  }

  // 2. Resolve Tenant (SearchParam > LocalStorage > Default)
  const tenantParam = searchParams.get('tenant')
  const savedTenant = localStorage.getItem('sentra_tenant')
  const currentTenant = tenantParam || savedTenant || 'sentra-internal'

  // 3. Resolve Role (SearchParam > LocalStorage > Default)
  const roleParam = searchParams.get('role') as UserRole | null
  const savedRole = localStorage.getItem('sentra_role') as UserRole | null
  const validRoles: UserRole[] = ['Viewer', 'Operator', 'SecurityAdmin']
  const currentRole: UserRole =
    (roleParam && validRoles.includes(roleParam) && roleParam) ||
    (savedRole && validRoles.includes(savedRole) && savedRole) ||
    'Operator'

  // 4. Resolve Workspace
  const savedWorkspace = localStorage.getItem('sentra_workspace')
  const currentWorkspace = searchParams.get('workspace') || savedWorkspace || 'E:/MyProject/Mix/GitHub/Sentra'

  // 5. Deep Linked Finding ID
  const selectedFindingId = searchParams.get('finding') || searchParams.get('id') || null

  return {
    activeTab,
    currentTenant,
    currentRole,
    currentWorkspace,
    selectedFindingId,
  }
}

function syncUrlToHistory(state: RouterState, replace = false) {
  const path = TAB_TO_PATH[state.activeTab] || `/${state.activeTab}`
  const params = new URLSearchParams()

  if (state.currentTenant && state.currentTenant !== 'sentra-internal') {
    params.set('tenant', state.currentTenant)
  }

  if (state.selectedFindingId && state.activeTab === 'findings') {
    params.set('finding', state.selectedFindingId)
  }

  const query = params.toString() ? `?${params.toString()}` : ''
  const newUrl = `${path}${query}`
  const currentUrl = `${window.location.pathname}${window.location.search}`

  if (newUrl !== currentUrl) {
    if (replace) {
      window.history.replaceState({ tab: state.activeTab }, '', newUrl)
    } else {
      window.history.pushState({ tab: state.activeTab }, '', newUrl)
    }
  }

  // Persist preferences into localStorage
  try {
    localStorage.setItem('sentra_tenant', state.currentTenant)
    localStorage.setItem('sentra_role', state.currentRole)
    localStorage.setItem('sentra_workspace', state.currentWorkspace)
  } catch {}
}

export function useAppRouter() {
  const [routeState, setRouteState] = useState<RouterState>(parseUrlState)
  const isInitialMount = useRef(true)

  // Listen to browser Back/Forward (popstate)
  useEffect(() => {
    function handlePopState() {
      const newState = parseUrlState()
      setRouteState(newState)
    }

    window.addEventListener('popstate', handlePopState)
    return () => window.removeEventListener('popstate', handlePopState)
  }, [])

  // Synchronize state changes to URL
  useEffect(() => {
    if (isInitialMount.current) {
      isInitialMount.current = false
      // Replace URL on initial mount so canonical path is clean
      syncUrlToHistory(routeState, true)
      return
    }

    syncUrlToHistory(routeState, false)
  }, [routeState])

  const setTab = useCallback((tab: string) => {
    const validTab = (VALID_TABS as readonly string[]).includes(tab) ? (tab as TabId) : 'overview'
    setRouteState((prev) => ({
      ...prev,
      activeTab: validTab,
      // Clear selected finding if leaving findings tab
      selectedFindingId: validTab === 'findings' ? prev.selectedFindingId : null,
    }))
  }, [])

  const setTenant = useCallback((tenant: TenantId) => {
    setRouteState((prev) => ({
      ...prev,
      currentTenant: tenant,
    }))
  }, [])

  const setRole = useCallback((role: UserRole) => {
    setRouteState((prev) => ({
      ...prev,
      currentRole: role,
    }))
  }, [])

  const setWorkspace = useCallback((workspace: string) => {
    setRouteState((prev) => ({
      ...prev,
      currentWorkspace: workspace,
    }))
  }, [])

  const setSelectedFindingId = useCallback((id: string | null) => {
    setRouteState((prev) => ({
      ...prev,
      selectedFindingId: id,
    }))
  }, [])

  return {
    ...routeState,
    setTab,
    setTenant,
    setRole,
    setWorkspace,
    setSelectedFindingId,
  }
}
