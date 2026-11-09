import {
  Download,
  Terminal,
  UserCircle,
  Lock,
  Search,
  Code2,
  CheckCircle2,
  Plus,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
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
  currentRole: UserRole
  onRoleChange: (role: UserRole) => void
  onExportSarif: () => void
  onToggleConsole: () => void
  onOpenCommandPalette: () => void
  onJumpToStudio: () => void
  isConsoleOpen: boolean
  activeTabTitle: string
}

export function Header({
  currentTenant,
  tenants,
  onTenantChange,
  onOpenAddTenant,
  currentRole,
  onRoleChange,
  onExportSarif,
  onToggleConsole,
  onOpenCommandPalette,
  onJumpToStudio,
  isConsoleOpen,
  activeTabTitle,
}: HeaderProps) {
  return (
    <header className="border-b bg-zinc-950/80 backdrop-blur sticky top-0 z-20 px-6 py-2.5 border-zinc-800/80">
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Left: View Title & Command Palette Search Trigger */}
        <div className="flex items-center gap-4">
          <span className="font-bold text-sm text-zinc-100">{activeTabTitle}</span>

          <Button
            variant="outline"
            size="sm"
            onClick={onOpenCommandPalette}
            className="h-8 text-xs text-zinc-400 bg-zinc-900/60 border-zinc-800 hover:text-zinc-100 flex items-center gap-3 w-64 justify-between"
          >
            <div className="flex items-center gap-2">
              <Search className="size-3.5" />
              <span>Quick search...</span>
            </div>
            <kbd className="pointer-events-none inline-flex h-5 select-none items-center gap-1 rounded border border-zinc-700 bg-zinc-800 px-1.5 font-mono text-[10px] font-medium text-zinc-400">
              ⌘K
            </kbd>
          </Button>
        </div>

        {/* Right Controls & Governance */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Tenant Selector */}
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-medium text-zinc-400">Tenant:</span>
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
              <SelectTrigger className="w-[210px] sm:w-[225px] h-8 text-xs bg-zinc-900/80 border-zinc-800">
                <SelectValue placeholder="Select Workspace">
                  {(val: string | null) => {
                    const match = tenants?.find((t) => t.tenantId === val)
                    return match ? match.name : (val || 'Select Workspace')
                  }}
                </SelectValue>
              </SelectTrigger>
              <SelectContent className="min-w-[240px]">
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
              className="size-8 p-0 bg-zinc-900/80 border-zinc-800 text-zinc-300 hover:text-primary hover:border-primary/50"
            >
              <Plus className="size-3.5" />
            </Button>
          </div>

          {/* RBAC Role Selector */}
          <div className="flex items-center gap-2">
            <UserCircle className="size-4 text-zinc-400" />
            <ToggleGroup
              value={[currentRole]}
              onValueChange={(val) => {
                if (val && val[0]) onRoleChange(val[0] as UserRole)
              }}
              className="border border-zinc-800 rounded-md p-0.5 h-8 bg-zinc-900/80"
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

          {/* Quick Studio Action */}
          <Button
            size="sm"
            onClick={onJumpToStudio}
            className="h-8 text-xs font-semibold"
          >
            <Code2 data-icon="inline-start" />
            Live Studio
          </Button>

          {/* SARIF Export */}
          <Button
            variant="outline"
            size="sm"
            onClick={onExportSarif}
            className="h-8 text-xs border-zinc-800 bg-zinc-900/60"
          >
            <Download data-icon="inline-start" />
            Export SARIF
          </Button>

          {/* Scanner CLI Drawer Toggle */}
          <Button
            variant={isConsoleOpen ? 'secondary' : 'outline'}
            size="sm"
            onClick={onToggleConsole}
            className="h-8 text-xs border-zinc-800"
          >
            <Terminal data-icon="inline-start" />
            CLI
          </Button>
        </div>
      </div>
    </header>
  )
}
