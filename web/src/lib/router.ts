import { useCallback, useEffect, useState } from 'react'

/**
 * URL state: `/:tenantId/:tab?finding=<id>`. Roles are never part of the URL or local storage:
 * they come only from the authenticated server session.
 */

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

export function isTabId(value: unknown): value is TabId {
  return typeof value === 'string' && (VALID_TABS as readonly string[]).includes(value)
}

export interface RouteState {
  tenantId: string | null
  tab: TabId
  findingId: string | null
}

const TENANT_STORAGE_KEY = 'sentra.lastTenant'
const TENANT_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/

function readStoredTenant(): string | null {
  try {
    const value = window.localStorage.getItem(TENANT_STORAGE_KEY)
    return value && TENANT_RE.test(value) ? value : null
  } catch {
    return null
  }
}

function storeTenant(tenantId: string | null): void {
  try {
    if (tenantId) window.localStorage.setItem(TENANT_STORAGE_KEY, tenantId)
  } catch {
    // storage unavailable (private mode); the URL still carries the tenant
  }
}

export function parseLocation(): RouteState {
  const segments = window.location.pathname.split('/').filter(Boolean).map((segment) => decodeURIComponent(segment))
  const params = new URLSearchParams(window.location.search)
  let tenantId: string | null = null
  let tab: TabId = 'overview'
  if (segments.length >= 1 && TENANT_RE.test(segments[0]) && !isTabId(segments[0])) tenantId = segments[0]
  const tabSegment = tenantId ? segments[1] : segments[0]
  if (isTabId(tabSegment)) tab = tabSegment
  const finding = params.get('finding')
  return {
    tenantId: tenantId ?? readStoredTenant(),
    tab,
    findingId: finding && /^[A-Za-z0-9._:-]{1,128}$/.test(finding) ? finding : null,
  }
}

function buildUrl(state: RouteState): string {
  const base = state.tenantId ? `/${encodeURIComponent(state.tenantId)}/${state.tab}` : `/${state.tab}`
  const params = new URLSearchParams()
  if (state.findingId && state.tab === 'findings') params.set('finding', state.findingId)
  const search = params.toString()
  return search ? `${base}?${search}` : base
}

export function useRouteState() {
  const [state, setState] = useState<RouteState>(parseLocation)

  useEffect(() => {
    const onPop = () => setState(parseLocation())
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  useEffect(() => {
    const url = buildUrl(state)
    const current = `${window.location.pathname}${window.location.search}`
    if (url !== current) window.history.pushState(null, '', url + window.location.hash)
    storeTenant(state.tenantId)
  }, [state])

  const navigate = useCallback((tab: TabId, options: { findingId?: string | null } = {}) => {
    setState((previous) => ({
      ...previous,
      tab,
      findingId: tab === 'findings' ? (options.findingId !== undefined ? options.findingId : previous.findingId) : null,
    }))
  }, [])

  const setTenantId = useCallback((tenantId: string | null) => {
    setState((previous) => (previous.tenantId === tenantId ? previous : { ...previous, tenantId, findingId: null }))
  }, [])

  const setFindingId = useCallback((findingId: string | null) => {
    setState((previous) => ({ ...previous, findingId }))
  }, [])

  return { ...state, navigate, setTenantId, setFindingId }
}
