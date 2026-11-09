import {
  Download,
  Terminal,
  UserCircle,
  Code2,
  Plus,
  FileText,
  Settings,
  Menu,
  MoreVertical,
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
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
  onJumpToStudio,
  onOpenMobileMenu,
  isConsoleOpen,
  activeTabTitle,
}: HeaderProps) {
  return (
    <header className="border-b bg-zinc-950/80 backdrop-blur sticky top-0 z-20 px-3 sm:px-6 h-14 flex items-center border-zinc-800/80">
      <div className="flex items-center justify-between gap-2 w-full">
        {/* Left: Mobile Menu Trigger + Active View Title */}
        <div className="flex items-center gap-2 sm:gap-3 min-w-0 flex-1">
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

          <span className="font-bold text-xs sm:text-sm text-zinc-100 truncate">
            {activeTabTitle}
          </span>
        </div>

        {/* Right Controls & Governance */}
        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
          {/* Tenant Selector */}
          <div className="flex items-center gap-1">
            <span className="text-[11px] font-medium text-zinc-400 hidden xl:inline">Tenant:</span>
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
              <SelectTrigger className="w-[95px] sm:w-[150px] md:w-[190px] h-8 text-xs bg-zinc-900/80 border-zinc-800 px-2">
                <SelectValue placeholder="Tenant">
                  {(val: string | null) => {
                    const match = tenants?.find((t) => t.tenantId === val)
                    return match ? match.name : (val || 'Tenant')
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
              className="hidden sm:flex size-8 p-0 bg-zinc-900/80 border-zinc-800 text-zinc-300 hover:text-primary hover:border-primary/50 shrink-0"
            >
              <Plus className="size-3.5" />
            </Button>
          </div>

          {/* Desktop RBAC Role Selector (visible on lg:) */}
          <div className="hidden lg:flex items-center gap-1.5">
            <UserCircle className="size-4 text-zinc-400 shrink-0" />
            <ToggleGroup
              value={[currentRole]}
              onValueChange={(val) => {
                if (val && val[0]) onRoleChange(val[0] as UserRole)
              }}
              className="border border-zinc-800 rounded-md p-0.5 h-8 bg-zinc-900/80 shrink-0"
            >
              <ToggleGroupItem value="Viewer" className="text-xs px-2.5 h-7">
                Viewer
              </ToggleGroupItem>
              <ToggleGroupItem value="Operator" className="text-xs px-2.5 h-7">
                Operator
              </ToggleGroupItem>
              <ToggleGroupItem value="SecurityAdmin" className="text-xs px-2.5 h-7">
                Admin
              </ToggleGroupItem>
            </ToggleGroup>
          </div>

          {/* Desktop Quick Studio Action (visible on lg:) */}
          <Button
            size="sm"
            onClick={onJumpToStudio}
            className="hidden lg:flex h-8 text-xs font-semibold px-2.5"
            title="Live SAST & Taint Studio"
          >
            <Code2 data-icon="inline-start" className="size-3.5" />
            <span>Studio</span>
          </Button>

          {/* Desktop Executive HTML Report (visible on xl:) */}
          <Button
            variant="outline"
            size="sm"
            onClick={onExportReport}
            title="Export Executive CISO & Security Audit HTML Report"
            className="hidden xl:flex h-8 text-xs border-zinc-800 bg-zinc-900/60 text-zinc-300 hover:text-primary hover:border-primary/50 px-2.5"
          >
            <FileText data-icon="inline-start" className="size-3.5" />
            <span>Report</span>
          </Button>

          {/* Desktop SARIF Export (visible on xl:) */}
          <Button
            variant="outline"
            size="sm"
            onClick={onExportSarif}
            title="Export OASIS SARIF v2.1.0"
            className="hidden xl:flex h-8 text-xs border-zinc-800 bg-zinc-900/60 px-2.5"
          >
            <Download data-icon="inline-start" className="size-3.5" />
            <span>SARIF</span>
          </Button>

          {/* Scanner CLI Drawer Toggle (visible on tablet and desktop) */}
          <Button
            variant={isConsoleOpen ? 'secondary' : 'outline'}
            size="sm"
            onClick={onToggleConsole}
            title="Toggle Scanner CLI Terminal"
            className="hidden sm:flex h-8 text-xs border-zinc-800 px-2 sm:px-2.5 shrink-0"
          >
            <Terminal data-icon="inline-start" className="size-3.5" />
            <span className="hidden sm:inline">CLI</span>
          </Button>

          {/* Mobile Overflow Menu Button (< lg screens) */}
          <div className="lg:hidden">
            <DropdownMenu>
              <DropdownMenuTrigger
                className="inline-flex items-center justify-center size-8 rounded-lg border border-zinc-800 bg-zinc-900/80 text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800 transition-colors shrink-0"
                title="More options and role governance"
              >
                <MoreVertical className="size-4" />
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56 bg-zinc-950 border border-zinc-800 p-1.5 text-zinc-200">
                <div className="text-[10px] text-zinc-400 font-mono uppercase tracking-wider px-2 py-1 font-semibold">
                  Role Governance
                </div>
                <div className="px-2 py-1 flex items-center gap-1">
                  {(['Viewer', 'Operator', 'SecurityAdmin'] as const).map((r) => (
                    <button
                      key={r}
                      type="button"
                      onClick={() => onRoleChange(r)}
                      className={`flex-1 text-[11px] py-1 rounded font-medium transition-colors ${
                        currentRole === r
                          ? 'bg-primary text-primary-foreground font-bold shadow-sm'
                          : 'bg-zinc-900 text-zinc-400 hover:text-zinc-200'
                      }`}
                    >
                      {r === 'SecurityAdmin' ? 'Admin' : r}
                    </button>
                  ))}
                </div>
                <DropdownMenuSeparator className="my-1.5 border-zinc-800" />
                <DropdownMenuItem
                  onClick={onToggleConsole}
                  className="cursor-pointer text-xs flex items-center gap-2 py-1.5 px-2 hover:bg-zinc-900 rounded"
                >
                  <Terminal className="size-3.5 text-primary" />
                  {isConsoleOpen ? 'Close CLI Terminal' : 'Open CLI Terminal'}
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={onJumpToStudio}
                  className="cursor-pointer text-xs flex items-center gap-2 py-1.5 px-2 hover:bg-zinc-900 rounded"
                >
                  <Code2 className="size-3.5 text-zinc-400" />
                  Live SAST & Taint Studio
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={onExportReport}
                  className="cursor-pointer text-xs flex items-center gap-2 py-1.5 px-2 hover:bg-zinc-900 rounded"
                >
                  <FileText className="size-3.5 text-zinc-400" />
                  Export Executive Report
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={onExportSarif}
                  className="cursor-pointer text-xs flex items-center gap-2 py-1.5 px-2 hover:bg-zinc-900 rounded"
                >
                  <Download className="size-3.5 text-zinc-400" />
                  Export OASIS SARIF v2.1.0
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={onOpenAddTenant}
                  className="cursor-pointer text-xs flex items-center gap-2 py-1.5 px-2 hover:bg-zinc-900 rounded"
                >
                  <Plus className="size-3.5 text-primary" />
                  Register New Tenant...
                </DropdownMenuItem>
                <DropdownMenuSeparator className="my-1.5 border-zinc-800" />
                <DropdownMenuItem
                  onClick={onOpenSettings}
                  className="cursor-pointer text-xs flex items-center gap-2 py-1.5 px-2 hover:bg-zinc-900 rounded"
                >
                  <Settings className="size-3.5 text-zinc-400" />
                  Platform Settings & AI Models
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>

          {/* Desktop Platform Settings Button (lg:flex) */}
          <Button
            variant="outline"
            size="sm"
            onClick={onOpenSettings}
            title="Platform Settings & AI Model Providers"
            className="hidden lg:flex size-8 p-0 border-zinc-800 bg-zinc-900/60 text-zinc-300 hover:text-zinc-100 shrink-0"
          >
            <Settings className="size-3.5" />
          </Button>
        </div>
      </div>
    </header>
  )
}
