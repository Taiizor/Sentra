import { useCallback, useEffect, useState, type ComponentType } from 'react'
import { CircleAlert, LoaderCircle, RefreshCw } from 'lucide-react'
import { LoginScreen } from '@/components/auth/login-screen'
import { bootstrapSession, type BootstrapResult } from '@/components/auth/session-bootstrap'
import { AddTenantDialog } from '@/components/dashboard/add-tenant-dialog'
import { AuditTab } from '@/components/dashboard/audit-tab'
import { FindingsTab } from '@/components/dashboard/findings-tab'
import { LiveScannerStudio } from '@/components/dashboard/live-scanner-studio'
import { LiveStreamModal } from '@/components/dashboard/live-stream-modal'
import { OnboardingPanel } from '@/components/dashboard/onboarding-panel'
import { OverviewTab } from '@/components/dashboard/overview-tab'
import { PluginsTab } from '@/components/dashboard/plugins-tab'
import { PullRequestsTab } from '@/components/dashboard/pull-requests-tab'
import { RemediationTab } from '@/components/dashboard/remediation-tab'
import { ResearchTab } from '@/components/dashboard/research-tab'
import { ScannerConsole } from '@/components/dashboard/scanner-console'
import { SettingsTab } from '@/components/dashboard/settings-tab'
import { ThreatIntelTab } from '@/components/dashboard/threat-intel-tab'
import { WebhookTab } from '@/components/dashboard/webhook-tab'
import { WorkerFleetTab } from '@/components/dashboard/worker-fleet-tab'
import { CommandPalette } from '@/components/layout/command-palette'
import { Header } from '@/components/layout/header'
import { navItem } from '@/components/layout/nav-items'
import { MobileSidebar, Sidebar, type SidebarBadges } from '@/components/layout/sidebar'
import { WorkspaceTargetBar } from '@/components/layout/workspace-target-bar'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Toaster } from '@/components/ui/sonner'
import { TooltipProvider } from '@/components/ui/tooltip'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { ConsoleProvider } from '@/lib/console-provider'
import type { TabId } from '@/lib/router'
import { useResource } from '@/lib/use-resource'
import type { ScanKind, SessionInfo } from '@/types/api'

type AuthState = { kind: 'checking' } | BootstrapResult

/** Every view reads its data through useConsole(); none takes props. */
const TAB_COMPONENTS: Record<TabId, ComponentType> = {
  overview: OverviewTab,
  studio: LiveScannerStudio,
  findings: FindingsTab,
  remediation: RemediationTab,
  intel: ThreatIntelTab,
  research: ResearchTab,
  fleet: WorkerFleetTab,
  'pull-requests': PullRequestsTab,
  webhooks: WebhookTab,
  plugins: PluginsTab,
  audit: AuditTab,
  settings: SettingsTab,
}

export function App() {
  const [auth, setAuth] = useState<AuthState>({ kind: 'checking' })

  useEffect(() => {
    let active = true
    void bootstrapSession().then((result) => {
      if (active) setAuth(result)
    })
    return () => {
      active = false
    }
  }, [])

  const handleSignedIn = useCallback((session: SessionInfo) => setAuth({ kind: 'signed_in', session }), [])
  const handleSignedOut = useCallback(() => setAuth({ kind: 'signed_out', error: null }), [])

  return (
    <TooltipProvider>
      {auth.kind === 'checking' && (
        <div className="min-h-screen bg-zinc-950 text-zinc-400 flex items-center justify-center gap-2 text-xs">
          <LoaderCircle className="size-4 animate-spin" />
          Checking your console session…
        </div>
      )}
      {auth.kind === 'signed_out' && <LoginScreen initialError={auth.error} onSignedIn={handleSignedIn} />}
      {auth.kind === 'signed_in' && (
        <ConsoleProvider session={auth.session} onSignedOut={handleSignedOut}>
          <ConsoleShell />
        </ConsoleProvider>
      )}
      <Toaster />
    </TooltipProvider>
  )
}

function ConsoleShell() {
  const { tab, tenant, tenants, tenantsLoaded, tenantsError, refreshTenants } = useConsole()
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [consoleOpen, setConsoleOpen] = useState(false)
  const [registerOpen, setRegisterOpen] = useState(false)
  const [scan, setScan] = useState<{ open: boolean; kind: ScanKind }>({ open: false, kind: 'all' })

  const tenantId = tenant?.tenantId ?? null
  const system = useResource('shell:system', (signal) => api.system.status(signal))
  const overview = useResource(tenantId ? `shell:overview:${tenantId}` : null, (signal) =>
    api.tenants.overview(tenantId ?? '', signal),
  )

  const badges: SidebarBadges = {
    findings: overview.data ? overview.data.openFindings.total : null,
    remediation: overview.data ? overview.data.patches.proposed : null,
  }
  const coreVersion = system.data?.core.version ?? null
  const openPalette = useCallback(() => setPaletteOpen(true), [])
  const openRegister = useCallback(() => setRegisterOpen(true), [])
  const toggleConsole = useCallback(() => setConsoleOpen((value) => !value), [])

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex antialiased selection:bg-primary/30 selection:text-white">
      <Sidebar badges={badges} coreVersion={coreVersion} onOpenPalette={openPalette} />
      <MobileSidebar
        open={mobileNavOpen}
        onOpenChange={setMobileNavOpen}
        badges={badges}
        coreVersion={coreVersion}
        onOpenPalette={() => {
          setMobileNavOpen(false)
          openPalette()
        }}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <Header
          onOpenMobileNav={() => setMobileNavOpen(true)}
          onOpenPalette={openPalette}
          onToggleConsole={toggleConsole}
          consoleOpen={consoleOpen}
          onRegisterWorkspace={openRegister}
        />

        <main className="flex-1 p-3 sm:p-4 md:p-6 flex flex-col gap-4 sm:gap-6 max-w-[1600px] w-full mx-auto">
          {!tenantsLoaded ? (
            <div className="flex flex-col gap-4" aria-busy="true">
              <Skeleton className="h-14 w-full bg-zinc-900" />
              <Skeleton className="h-64 w-full bg-zinc-900" />
            </div>
          ) : (
            <>
              {tenantsError && (
                <Alert variant="destructive" className="border-rose-500/40 bg-rose-500/5">
                  <CircleAlert />
                  <AlertTitle className="text-xs">Workspace registry unavailable</AlertTitle>
                  <AlertDescription className="text-xs flex flex-col items-start gap-2">
                    <span className="break-words">{tenantsError}</span>
                    <Button size="xs" variant="outline" onClick={() => void refreshTenants()}>
                      <RefreshCw className="size-3" />
                      Retry
                    </Button>
                  </AlertDescription>
                </Alert>
              )}
              {tenant && <WorkspaceTargetBar onStartScan={(kind) => setScan({ open: true, kind })} />}
              {consoleOpen && <ScannerConsole />}
              <ActiveView
                // Remount views on workspace switch so no view-local state crosses tenants.
                key={tenantId ?? 'no-tenant'}
                tab={tab}
                hasTenant={tenant !== null}
                noTenants={tenants.length === 0 && !tenantsError}
                onRegisterWorkspace={openRegister}
              />
            </>
          )}
        </main>

        <footer className="border-t border-zinc-800 py-3 px-6 text-[11px] text-zinc-500 bg-zinc-950/60 mt-auto">
          {system.data ? (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-mono">
              <span>Sentra console</span>
              <span>bridge {system.data.mode}</span>
              <span title={system.data.core.error ?? undefined}>
                core {system.data.core.version ?? (system.data.core.present ? 'version unavailable' : 'binary not found')}
              </span>
              <span>
                bind {system.data.auth.bindHost}
                {system.data.auth.loopbackOnly ? ' (loopback only)' : ''}
              </span>
            </div>
          ) : system.error ? (
            <span>Sentra console · bridge status unavailable: {errorMessage(system.error)}</span>
          ) : (
            <span>Sentra console</span>
          )}
        </footer>
      </div>

      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        onToggleConsole={toggleConsole}
        onRegisterWorkspace={openRegister}
      />
      <LiveStreamModal
        open={scan.open}
        onOpenChange={(open) => {
          setScan((current) => ({ ...current, open }))
          // A scan can initialize the core store or follow a new git head; re-read tenant state.
          if (!open) void refreshTenants()
        }}
        kind={scan.kind}
      />
      <AddTenantDialog open={registerOpen} onOpenChange={setRegisterOpen} />
    </div>
  )
}

function ActiveView({
  tab,
  hasTenant,
  noTenants,
  onRegisterWorkspace,
}: {
  tab: TabId
  hasTenant: boolean
  noTenants: boolean
  onRegisterWorkspace: () => void
}) {
  if (navItem(tab).requiresTenant && !hasTenant) {
    if (noTenants) return <OnboardingPanel onRegisterWorkspace={onRegisterWorkspace} />
    // Registry failed to load (alert shown above) or the selection is being resolved.
    return null
  }
  const View = TAB_COMPONENTS[tab]
  return <View />
}

export default App
