import { ShieldAlert, Download, Terminal, UserCircle, Lock } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import type { TenantId, UserRole } from '@/types/sentra'

interface HeaderProps {
  currentTenant: TenantId
  onTenantChange: (tenant: TenantId) => void
  currentRole: UserRole
  onRoleChange: (role: UserRole) => void
  onExportSarif: () => void
  onToggleConsole: () => void
  isConsoleOpen: boolean
}

export function Header({
  currentTenant,
  onTenantChange,
  currentRole,
  onRoleChange,
  onExportSarif,
  onToggleConsole,
  isConsoleOpen,
}: HeaderProps) {
  return (
    <header className="border-b bg-card/50 backdrop-blur sticky top-0 z-10 px-6 py-3">
      <div className="flex flex-wrap items-center justify-between gap-4">
        {/* Brand & Platform Identity */}
        <div className="flex items-center gap-3">
          <div className="bg-primary text-primary-foreground p-2 rounded-lg flex items-center justify-center">
            <ShieldAlert className="size-6" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="font-bold text-lg tracking-tight">Sentra</span>
              <Badge variant="outline" className="text-xs">
                v0.1.0-Phase6
              </Badge>
              <Badge variant="secondary" className="text-xs flex items-center gap-1">
                <Lock className="size-3" />
                Fail-Closed Active
              </Badge>
            </div>
            <span className="text-xs text-muted-foreground">
              Autonomous AI Security Research & Verified Remediation
            </span>
          </div>
        </div>

        {/* Global Controls & RBAC */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Tenant Selector */}
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-muted-foreground">Tenant:</span>
            <Select
              value={currentTenant}
              onValueChange={(val) => {
                if (val) onTenantChange(val as TenantId)
              }}
            >
              <SelectTrigger className="w-[180px] h-8 text-xs">
                <SelectValue placeholder="Select Workspace" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="sentra-internal">Sentra Core (Internal)</SelectItem>
                  <SelectItem value="tenant-alpha">Tenant Alpha (Isolated)</SelectItem>
                  <SelectItem value="acme-corp">Acme Corp (Enterprise)</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>

          {/* RBAC Role Selector */}
          <div className="flex items-center gap-2">
            <UserCircle className="size-4 text-muted-foreground" />
            <ToggleGroup
              value={[currentRole]}
              onValueChange={(val) => {
                if (val && val[0]) onRoleChange(val[0] as UserRole)
              }}
              className="border rounded-md p-0.5 h-8"
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

          {/* Action Buttons */}
          <Button
            variant="outline"
            size="sm"
            onClick={onExportSarif}
            className="h-8 text-xs"
          >
            <Download data-icon="inline-start" />
            Export SARIF
          </Button>

          <Button
            variant={isConsoleOpen ? 'secondary' : 'outline'}
            size="sm"
            onClick={onToggleConsole}
            className="h-8 text-xs"
          >
            <Terminal data-icon="inline-start" />
            Scanner CLI
          </Button>
        </div>
      </div>
    </header>
  )
}
