import {
  Download,
  Terminal,
  UserCircle,
  Search,
  Code2,
  Plus,
  FileText,
  Settings,
  Menu,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import type { TenantId, TenantView, UserRole } from '@/types/sentra'

interface HeaderProps {
  currentTenant: TenantId
  tenants: TenantView[]
  onTenantChange: (tenant: TenantId) => void
  onOpenAddTenant: () => void
  onOpenSettings: () => void
  onExportReport: () => void
  currentRole: UserRole
  onRoleChange: (role: UserRole) => void
  onExportSarif: () => void
  onToggleConsole: () => void
  onOpenCommandPalette: () => void
  onJumpToStudio: () => void
  onOpenMobileMenu?: () => void
  isConsoleOpen: boolean
  activeTabTitle: string
}

export function Header({
  currentTenant,
  tenants,
  onTenantChange,
  onOpenAddTenant,
  onOpenSettings,
  onExportReport,
  currentRole,
  onRoleChange,
  onExportSarif,
  onToggleConsole,
  onOpenCommandPalette,
  onJumpToStudio,
  onOpenMobileMenu,
  isConsoleOpen,
  activeTabTitle,
}: HeaderProps) {
  return (
    <header className="border-b bg-zinc-950/80 backdrop-blur sticky top-0 z-20 px-3 sm:px-6 py-2.5 border-zinc-800/80">
      <div className="flex flex-wrap items-center justify-between gap-2.5 sm:gap-4">
        {/* Left: Mobile Menu Trigger + View Title & Command Palette Search */}
        <div className="flex items-center gap-2 sm:gap-3 min-w-0">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={onOpenMobileMenu}
            className="lg:hidden size-8 p-0 text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/60 shrink-0"
            title="Open Platform Navigation"
          >
            <Menu className="size-5" />
            <span className="sr-only">Toggle navigation</span>
          </Button>

          <span className="font-bold text-xs sm:text-sm text-zinc-100 truncate max-w-[120px] sm:max-w-none">
            {activeTabTitle}
          </span>

          <Button
            variant="outline"
            size="sm"
            onClick={onOpenCommandPalette}
            className="h-8 text-xs text-zinc-400 bg-zinc-900/60 border-zinc-800 hover:text-zinc-100 flex items-center gap-2 px-2.5 sm:px-3 w-auto sm:w-48 md:w-60 justify-between shrink-0"
          >
            <div className="flex items-center gap-1.5">
              <Search className="size-3.5 shrink-0" />
              <span className="hidden sm:inline">Quick search...</span>
            </div>
            <kbd className="hidden sm:inline-flex pointer-events-none h-5 select-none items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 font-mono text-[10px] font-medium text-zinc-400">
              ⌘K
            </kbd>
          </Button>
        </div>

        {/* Right Controls & Governance */}
        <div className="flex flex-wrap items-center gap-2 sm:gap-2.5 ml-auto">
          {/* Tenant Selector */}
          <div className="flex items-center gap-1 sm:gap-1.5">
            <span className="text-[11px] sm:text-xs font-medium text-zinc-400 hidden sm:inline">Tenant:</span>
            <Select
              value={currentTenant}
              onValueChange={(val) => {
                if (val === '__add_new__') {
                  onOpenAddTenant()
                  return
                }
                if (val) onTenantChange(val as TenantId)
              }}
            >
              <SelectTrigger className="w-[130px] sm:w-[180px] md:w-[220px] h-8 text-xs bg-zinc-900/80 border-zinc-800">
                <SelectValue placeholder="Select Workspace">
                  {(val: string | null) => {
                    const match = tenants?.find((t) => t.tenantId === val)
                    return match ? match.name : (val || 'Select Workspace')
                  }}
                </SelectValue>
              </SelectTrigger>
              <SelectContent className="min-w-[260px] max-w-[calc(100vw-2rem)]">
                <SelectGroup>
                  {(tenants || []).map((t) => (
                    <SelectItem key={t.tenantId} value={t.tenantId}>
                      {t.name}
                    </SelectItem>
                  ))}
                  <SelectSeparator />
                  <SelectItem value="__add_new__" className="text-primary font-medium focus:text-primary">
                    <span className="flex items-center gap-1.5">
                      <Plus className="size-3.5" />
                      + Register New Tenant...
                    </span>
                  </SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>

            <Button
              variant="outline"
              size="sm"
              onClick={onOpenAddTenant}
              title="Register New Organization / Tenant Workspace"
              className="size-8 p-0 bg-zinc-900/80 border-zinc-800 text-zinc-300 hover:text-primary hover:border-primary/50 shrink-0"
            >
              <Plus className="size-3.5" />
            </Button>
          </div>

          {/* RBAC Role Selector */}
          <div className="flex items-center gap-1 sm:gap-1.5">
            <UserCircle className="size-4 text-zinc-400 hidden sm:inline shrink-0" />
            <ToggleGroup
              value={[currentRole]}
              onValueChange={(val) => {
                if (val && val[0]) onRoleChange(val[0] as UserRole)
              }}
              className="border border-zinc-800 rounded-md p-0.5 h-8 bg-zinc-900/80 shrink-0"
            >
              <ToggleGroupItem value="Viewer" className="text-[11px] sm:text-xs px-2 sm:px-2.5 h-7">
                Viewer
              </ToggleGroupItem>
              <ToggleGroupItem value="Operator" className="text-[11px] sm:text-xs px-2 sm:px-2.5 h-7">
                Operator
              </ToggleGroupItem>
              <ToggleGroupItem value="SecurityAdmin" className="text-[11px] sm:text-xs px-2 sm:px-2.5 h-7">
                Admin
              </ToggleGroupItem>
            </ToggleGroup>
          </div>

          {/* Quick Studio Action */}
          <Button
            size="sm"
            onClick={onJumpToStudio}
            className="h-8 text-xs font-semibold px-2 sm:px-3"
            title="Live SAST & Taint Studio"
          >
            <Code2 data-icon="inline-start" className="size-3.5" />
            <span className="hidden sm:inline">Live Studio</span>
          </Button>

          {/* Executive HTML Report Export */}
          <Button
            variant="outline"
            size="sm"
            onClick={onExportReport}
            title="Export Executive CISO & Security Audit HTML Report"
            className="h-8 text-xs border-zinc-800 bg-zinc-900/60 text-zinc-300 hover:text-primary hover:border-primary/50 px-2 sm:px-2.5"
          >
            <FileText data-icon="inline-start" className="size-3.5" />
            <span className="hidden md:inline">Executive Report</span>
          </Button>

          {/* SARIF Export */}
          <Button
            variant="outline"
            size="sm"
            onClick={onExportSarif}
            title="Export OASIS SARIF v2.1.0"
            className="h-8 text-xs border-zinc-800 bg-zinc-900/60 px-2 sm:px-2.5"
          >
            <Download data-icon="inline-start" className="size-3.5" />
            <span className="hidden md:inline">Export SARIF</span>
          </Button>

          {/* Scanner CLI Drawer Toggle */}
          <Button
            variant={isConsoleOpen ? 'secondary' : 'outline'}
            size="sm"
            onClick={onToggleConsole}
            title="Toggle Scanner CLI Terminal"
            className="h-8 text-xs border-zinc-800 px-2 sm:px-2.5"
          >
            <Terminal data-icon="inline-start" className="size-3.5" />
            <span className="hidden sm:inline">CLI</span>
          </Button>

          {/* Platform Settings */}
          <Button
            variant="outline"
            size="sm"
            onClick={onOpenSettings}
            title="Platform Settings & AI Model Providers"
            className="size-8 p-0 border-zinc-800 bg-zinc-900/60 text-zinc-300 hover:text-zinc-100 shrink-0"
          >
            <Settings className="size-3.5" />
          </Button>
        </div>
      </div>
    </header>
  )
}
