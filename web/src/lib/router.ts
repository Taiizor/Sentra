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
  'pull-requests',
  'webhooks',
  'plugins',
  'audit',
  'settings',
] as const

export type TabId = (typeof VALID_TABS)[number]

const ROLE_MAP: Record<string, UserRole> = {
  viewer: 'Viewer',
  operator: 'Operator',
  admin: 'SecurityAdmin',
  securityadmin: 'SecurityAdmin',
  'security-admin': 'SecurityAdmin',
}

function roleToSlug(role: UserRole): string {
  switch (role) {
    case 'SecurityAdmin':
      return 'admin'
    case 'Viewer':
      return 'viewer'
    case 'Operator':
    default:
      return 'operator'
  }
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

  const segments = path.split('/').filter(Boolean)

  let detectedTenant: string | null = null
  let detectedTab: TabId | null = null
  let detectedRole: UserRole | null = null

  // 1. Check query parameters first as fallback / explicit override
  const queryRole = searchParams.get('role')
  if (queryRole && ROLE_MAP[queryRole.toLowerCase()]) {
    detectedRole = ROLE_MAP[queryRole.toLowerCase()]
  }

  const queryTenant = searchParams.get('tenant')
  if (queryTenant) {
    detectedTenant = queryTenant
  }

  const queryTab = searchParams.get('tab')
  if (queryTab && (VALID_TABS as readonly string[]).includes(queryTab)) {
    detectedTab = queryTab as TabId
  }

  if (hash && (VALID_TABS as readonly string[]).includes(hash)) {
    detectedTab = hash as TabId
  }

  // 2. Parse path segments
  // Supported structures:
  // /:tenant/:tab (primary: /acme-corp/overview, /acme-corp/settings)
  // /:tenant/:role/:tab (/acme-corp/operator/overview)
  // /:tenant/:tab/:role (/acme-corp/overview/operator)
  // /:tab (/overview, /settings)
  // /:tenant (/acme-corp)
  if (segments.length === 1) {
    const s0 = segments[0]
    if ((VALID_TABS as readonly string[]).includes(s0)) {
      detectedTab = s0 as TabId
    } else {
      detectedTenant = s0
    }
  } else if (segments.length === 2) {
    const [s0, s1] = segments
    if ((VALID_TABS as readonly string[]).includes(s1)) {
      detectedTenant = s0
      detectedTab = s1 as TabId
    } else if (ROLE_MAP[s0.toLowerCase()] && (VALID_TABS as readonly string[]).includes(s1)) {
      detectedRole = ROLE_MAP[s0.toLowerCase()]
      detectedTab = s1 as TabId
    } else if (ROLE_MAP[s1.toLowerCase()]) {
      detectedTenant = s0
      detectedRole = ROLE_MAP[s1.toLowerCase()]
    } else {
      detectedTenant = s0
    }
  } else if (segments.length >= 3) {
    const [s0, s1, s2] = segments
    if (ROLE_MAP[s1.toLowerCase()] && (VALID_TABS as readonly string[]).includes(s2)) {
      detectedTenant = s0
      detectedRole = ROLE_MAP[s1.toLowerCase()]
      detectedTab = s2 as TabId
    } else if ((VALID_TABS as readonly string[]).includes(s1) && ROLE_MAP[s2.toLowerCase()]) {
      detectedTenant = s0
      detectedTab = s1 as TabId
      detectedRole = ROLE_MAP[s2.toLowerCase()]
    } else if ((VALID_TABS as readonly string[]).includes(s1)) {
      detectedTenant = s0
      detectedTab = s1 as TabId
    }
  }

  // 3. Fallbacks
  const savedTenant = localStorage.getItem('sentra_tenant')
  const currentTenant = (detectedTenant || savedTenant || 'sentra-internal') as TenantId

  const savedRole = localStorage.getItem('sentra_role') as UserRole | null
  const currentRole: UserRole = detectedRole || savedRole || 'Operator'

  const activeTab: TabId = detectedTab || 'overview'

  const savedWorkspace = localStorage.getItem('sentra_workspace')
  const currentWorkspace = searchParams.get('workspace') || savedWorkspace || '.'

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
  const tenant = state.currentTenant || 'sentra-internal'
  const tab = state.activeTab || 'overview'
  const roleSlug = roleToSlug(state.currentRole)

  const basePath = `/${tenant}/${roleSlug}/${tab}`
  const params = new URLSearchParams()

  if (state.selectedFindingId && state.activeTab === 'findings') {
    params.set('finding', state.selectedFindingId)
  }

  const query = params.toString() ? `?${params.toString()}` : ''
  const newUrl = `${basePath}${query}`
  const currentUrl = `${window.location.pathname}${window.location.search}`

  if (newUrl !== currentUrl) {
    if (replace) {
      window.history.replaceState({ tab: state.activeTab, tenant: state.currentTenant, role: state.currentRole }, '', newUrl)
    } else {
      window.history.pushState({ tab: state.activeTab, tenant: state.currentTenant, role: state.currentRole }, '', newUrl)
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
