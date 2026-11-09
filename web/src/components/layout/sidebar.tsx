import {
  ShieldAlert,
  LayoutDashboard,
  Code2,
  AlertTriangle,
  CheckCircle2,
  Globe,
  Brain,
  Server,
  History,
  Lock,
  ChevronRight,
  HardDrive,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { cn } from 'cn'
import type { TenantId, UserRole } from '@/types/sentra'

interface SidebarProps {
  activeTab: string
  onSelectTab: (tab: string) => void
  findingCount: number
  patchCount: number
  auditCount: number
  currentRole: UserRole
  currentTenant: TenantId
}

export function Sidebar({
  activeTab,
  onSelectTab,
  findingCount,
  patchCount,
  auditCount,
  currentRole,
  currentTenant,
}: SidebarProps) {
  const navItems = [
    {
      id: 'overview',
      label: 'Executive Threat Posture',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'studio',
      label: 'Live SAST & Taint Studio',
      icon: Code2,
      badge: 'Interactive',
    },
    {
      id: 'findings',
      label: 'Findings & Call Graphs',
      icon: AlertTriangle,
      badge: `${findingCount}`,
    },
    {
      id: 'remediation',
      label: 'Automated Remediation',
      icon: CheckCircle2,
      badge: `${patchCount} Verified`,
    },
    {
      id: 'intel',
      label: 'OSV Threat Intelligence',
      icon: Globe,
      badge: '250k+',
    },
    {
      id: 'research',
      label: 'Autonomous Research',
      icon: Brain,
      badge: null,
    },
    {
      id: 'fleet',
      label: 'Worker Fleet & Sandboxes',
      icon: Server,
      badge: 'Phase 6',
    },
    {
      id: 'audit',
      label: 'Immutable Audit Trail',
      icon: History,
      badge: `${auditCount}`,
    },
  ]

  return (
    <aside className="w-64 border-r bg-zinc-950/80 backdrop-blur flex flex-col justify-between shrink-0 h-screen sticky top-0 border-zinc-800/80">
      {/* Brand & Platform Identity */}
      <div className="flex flex-col">
        <div className="p-4 border-b border-zinc-800/80 flex items-center gap-3">
          <div className="size-9 rounded-lg bg-primary text-primary-foreground flex items-center justify-center font-bold shadow-lg shadow-primary/20">
            <ShieldAlert className="size-5" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-1.5">
              <span className="font-extrabold text-base tracking-tight text-white">Sentra</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                v0.1.0
              </span>
            </div>
            <span className="text-[11px] text-zinc-400 truncate">
              Autonomous AI Security Core
            </span>
          </div>
        </div>

        {/* Navigation Menu */}
        <nav className="p-3 flex flex-col gap-1">
          <span className="text-[10px] font-semibold tracking-wider text-zinc-500 uppercase px-2 mb-1">
            Platform Capabilities
          </span>
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = activeTab === item.id
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={cn(
                  'w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition-all text-left',
                  isActive
                    ? 'bg-primary/15 text-primary border border-primary/30 shadow-sm'
                    : 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900/60'
                )}
              >
                <div className="flex items-center gap-2.5 truncate">
                  <Icon className={cn('size-4 shrink-0', isActive ? 'text-primary' : 'text-zinc-500')} />
                  <span className="truncate">{item.label}</span>
                </div>
                {item.badge && (
                  <Badge
                    variant={isActive ? 'default' : 'outline'}
                    className={cn(
                      'text-[10px] h-4 px-1.5 font-mono ml-1 shrink-0',
                      isActive ? 'bg-primary text-primary-foreground' : 'text-zinc-400 border-zinc-700'
                    )}
                  >
                    {item.badge}
                  </Badge>
                )}
              </button>
            )
          })}
        </nav>
      </div>

      {/* Footer Security Isolation & Status Widget */}
      <div className="p-3 border-t border-zinc-800/80 flex flex-col gap-2.5 bg-zinc-900/30">
        {/* Security Gates Pill */}
        <div className="p-2.5 rounded-lg border border-zinc-800 bg-zinc-900/60 flex flex-col gap-1.5">
          <div className="flex items-center justify-between text-[11px]">
            <span className="flex items-center gap-1.5 font-semibold text-emerald-400">
              <Lock className="size-3" />
              Fail-Closed Host Boundary
            </span>
            <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
          </div>
          <div className="flex items-center justify-between text-[10px] text-zinc-400 font-mono">
            <span>Egress: Denied</span>
            <span>CAS: 12.4 MiB</span>
          </div>
        </div>

        {/* Tenant and Role Indicator */}
        <div className="flex items-center justify-between px-1 text-[11px] text-zinc-400 font-mono">
          <span className="truncate">Tenant: {currentTenant}</span>
          <Badge variant="outline" className="text-[10px] h-4 px-1 font-mono">
            {currentRole}
          </Badge>
        </div>
      </div>
    </aside>
  )
}
