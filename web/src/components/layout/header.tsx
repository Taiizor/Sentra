import { useState } from 'react'
import { ChevronDown, Download, FileText, LogOut, Menu, Plus, Search, Terminal, TriangleAlert, UserRound } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { useConsole } from '@/lib/console-context'
import { DisabledReason } from './disabled-reason'
import { exportExecutiveReport, exportSarif } from './export-actions'
import { navItem } from './nav-items'
import { permissionHint, roleBadgeClass } from './permission-hint'

interface HeaderProps {
  onOpenMobileNav: () => void
  onOpenPalette: () => void
  onToggleConsole: () => void
  consoleOpen: boolean
  onRegisterWorkspace: () => void
}

export function Header({ onOpenMobileNav, onOpenPalette, onToggleConsole, consoleOpen, onRegisterWorkspace }: HeaderProps) {
  const { session, can, tenants, tenant, setTenantId, tab, logout } = useConsole()
  const [exporting, setExporting] = useState<'sarif' | 'report' | null>(null)
  const canRegister = can('tenant:create')

  async function runExport(kind: 'sarif' | 'report') {
    if (!tenant || exporting) return
    setExporting(kind)
    try {
      if (kind === 'sarif') await exportSarif(tenant)
      else await exportExecutiveReport(tenant, session)
    } finally {
      setExporting(null)
    }
  }

  return (
    <header className="border-b border-zinc-800/80 bg-zinc-950/80 backdrop-blur sticky top-0 z-20 px-3 sm:px-6 h-14 flex items-center">
      <div className="flex items-center justify-between gap-2 w-full">
        <div className="flex items-center gap-2 sm:gap-3 min-w-0 flex-1">
          <Button
            type="button"
            variant="ghost"
            size="icon-sm"
            onClick={onOpenMobileNav}
            className="md:hidden text-zinc-400 hover:text-zinc-100"
            aria-label="Open navigation"
          >
            <Menu className="size-5" />
          </Button>
          <span className="font-semibold text-xs sm:text-sm text-zinc-100 truncate">{navItem(tab).title}</span>
        </div>

        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
          {/* Workspace (tenant) selector */}
          {tenants.length > 0 ? (
            <Select value={tenant?.tenantId ?? null} onValueChange={(value) => value && setTenantId(String(value))}>
              <SelectTrigger
                className="w-[120px] sm:w-[170px] md:w-[210px] h-8 text-xs bg-zinc-900/80 border-zinc-800 px-2"
                aria-label="Select workspace"
              >
                <SelectValue placeholder="Select workspace">
                  {(value: string | null) => tenants.find((candidate) => candidate.tenantId === value)?.name ?? 'Select workspace'}
                </SelectValue>
              </SelectTrigger>
              <SelectContent className="min-w-[280px] max-w-[calc(100vw-2rem)]">
                <SelectGroup>
                  {tenants.map((candidate) => (
                    <SelectItem key={candidate.tenantId} value={candidate.tenantId}>
                      <span className="flex flex-col min-w-0">
                        <span className="flex items-center gap-1.5 text-xs">
                          {candidate.name}
                          {!candidate.workspaceExists && <TriangleAlert className="size-3 text-amber-400" aria-label="Workspace directory missing" />}
                        </span>
                        <span className="text-[10px] font-mono text-zinc-500 truncate">{candidate.tenantId}</span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>
          ) : (
            <span className="hidden sm:inline text-[11px] text-zinc-500">No workspace registered</span>
          )}

          {canRegister && (
            <Button
              variant="outline"
              size="icon-sm"
              onClick={onRegisterWorkspace}
              title="Register workspace"
              aria-label="Register workspace"
              className="hidden sm:inline-flex bg-zinc-900/80 border-zinc-800 text-zinc-300 hover:text-primary"
            >
              <Plus className="size-3.5" />
            </Button>
          )}

          <Button
            variant="outline"
            size="icon-sm"
            onClick={onOpenPalette}
            className="md:hidden bg-zinc-900/80 border-zinc-800 text-zinc-300"
            aria-label="Search views and findings"
          >
            <Search className="size-3.5" />
          </Button>

          <DisabledReason reason={tenant ? null : 'Select a registered workspace to export its data'} className="hidden sm:inline-flex">
            <DropdownMenu>
              <DropdownMenuTrigger
                disabled={!tenant || exporting !== null}
                className="hidden sm:inline-flex items-center justify-center h-8 text-xs font-medium rounded-md border border-zinc-800 bg-zinc-900/60 text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/80 px-2.5 gap-1.5 transition-colors outline-none disabled:opacity-50 disabled:pointer-events-none"
              >
                <Download className="size-3.5" />
                <span>{exporting ? 'Exporting…' : 'Export'}</span>
                <ChevronDown className="size-3 text-zinc-400" />
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-64 bg-zinc-950 border border-zinc-800 p-1.5 text-zinc-200">
                <DropdownMenuItem onClick={() => void runExport('sarif')} className="text-xs items-start py-1.5">
                  <Download className="size-3.5 text-cyan-400 mt-0.5" />
                  <span className="flex flex-col">
                    <span>Export SARIF</span>
                    <span className="text-[10px] text-zinc-500">Generated by the bridge from open findings</span>
                  </span>
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => void runExport('report')} className="text-xs items-start py-1.5">
                  <FileText className="size-3.5 text-primary mt-0.5" />
                  <span className="flex flex-col">
                    <span>Executive report (HTML)</span>
                    <span className="text-[10px] text-zinc-500">Current counts, findings, patches and audit excerpt</span>
                  </span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </DisabledReason>

          <DisabledReason reason={can('console:run') ? null : permissionHint('console:run')} className="hidden sm:inline-flex">
            <Button
              variant={consoleOpen ? 'secondary' : 'outline'}
              size="sm"
              onClick={onToggleConsole}
              disabled={!can('console:run')}
              aria-pressed={consoleOpen}
              className="hidden sm:inline-flex h-8 text-xs border-zinc-800 px-2.5"
            >
              <Terminal className="size-3.5" />
              <span className="hidden lg:inline">CLI console</span>
            </Button>
          </DisabledReason>

          <DropdownMenu>
            <DropdownMenuTrigger
              className="inline-flex items-center gap-1.5 h-8 rounded-md border border-zinc-800 bg-zinc-900/60 px-2 text-xs text-zinc-300 hover:bg-zinc-800/80 outline-none max-w-[220px]"
              aria-label="Account"
            >
              <UserRound className="size-3.5 text-zinc-400 shrink-0" />
              <span className="hidden lg:inline truncate font-mono text-[11px]">{session.principal}</span>
              <Badge variant="outline" className={`text-[10px] font-mono px-1.5 h-4 ${roleBadgeClass(session.roleLabel)}`}>
                {session.roleLabel}
              </Badge>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-72 bg-zinc-950 border border-zinc-800 p-1.5 text-zinc-200">
              <div className="px-2 py-1.5 flex flex-col gap-1 text-[11px]">
                <span className="text-zinc-400">Signed in as</span>
                <span className="font-mono text-zinc-100 break-all">{session.principal}</span>
                <span className="text-zinc-400">
                  Role <span className="text-zinc-200">{session.roleLabel}</span>, assigned by the bridge from your access token (
                  {session.via === 'session' ? 'session cookie' : 'bearer token'}).
                </span>
                <span className="text-zinc-500">
                  {session.expiresAt ? `Session expires ${new Date(session.expiresAt).toLocaleString()}` : 'No session expiry reported'}
                </span>
              </div>
              {canRegister && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={onRegisterWorkspace} className="text-xs sm:hidden">
                    <Plus className="size-3.5" />
                    Register workspace
                  </DropdownMenuItem>
                </>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => void logout()} className="text-xs">
                <LogOut className="size-3.5" />
                Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
    </header>
  )
}
