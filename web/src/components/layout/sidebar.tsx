import {
  LayoutDashboard,
  Code2,
  AlertTriangle,
  CheckCircle2,
  Globe,
  Brain,
  Server,
  History,
  Lock,
  Webhook,
  Activity,
  Cpu,
  Sparkles,
  Layers,
  Search,
  Building2,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { SentraLogo } from '@/components/ui/sentra-logo'
import { Sheet, SheetContent, SheetTitle, SheetDescription } from '@/components/ui/sheet'
import { cn } from 'cn'
import type { TenantId, UserRole } from '@/types/sentra'

export interface SidebarProps {
  activeTab: string
  onSelectTab: (tab: string) => void
  findingCount: number
  patchCount: number
  auditCount: number
  currentRole: UserRole
  currentTenant: TenantId
  onOpenCommandPalette?: () => void
  className?: string
}

export interface MobileSidebarProps extends SidebarProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

type BadgeVariant =
  | 'default'
  | 'cyan'
  | 'rose'
  | 'emerald'
  | 'sky'
  | 'purple'
  | 'amber'
  | 'violet'
  | 'zinc'

interface NavItem {
  id: string
  label: string
  icon: React.ComponentType<{ className?: string }>
  badge: string | null
  badgeVariant: BadgeVariant
}

interface NavCategory {
  id: string
  title: string
  icon: React.ComponentType<{ className?: string }>
  items: NavItem[]
}

function getBadgeClasses(variant: BadgeVariant, isActive: boolean): string {
  switch (variant) {
    case 'rose':
      return 'bg-rose-500/10 text-rose-400 border-rose-500/30 group-hover:border-rose-500/50'
    case 'emerald':
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 group-hover:border-emerald-500/50'
    case 'cyan':
      return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 group-hover:border-cyan-500/50'
    case 'sky':
      return 'bg-sky-500/10 text-sky-400 border-sky-500/30 group-hover:border-sky-500/50'
    case 'purple':
      return 'bg-purple-500/10 text-purple-400 border-purple-500/30 group-hover:border-purple-500/50'
    case 'amber':
      return 'bg-amber-500/10 text-amber-400 border-amber-500/30 group-hover:border-amber-500/50'
    case 'violet':
      return 'bg-violet-500/10 text-violet-400 border-violet-500/30 group-hover:border-violet-500/50'
    case 'zinc':
    default:
      return isActive
        ? 'bg-zinc-800 text-zinc-300 border-zinc-700'
        : 'bg-zinc-900/80 text-zinc-400 border-zinc-800 group-hover:text-zinc-300'
  }
}

function getRoleBadgeClasses(role: UserRole): string {
  switch (role) {
    case 'SecurityAdmin':
      return 'bg-purple-500/15 text-purple-300 border-purple-500/30'
    case 'Operator':
      return 'bg-blue-500/15 text-blue-300 border-blue-500/30'
    case 'Viewer':
    default:
      return 'bg-zinc-800 text-zinc-400 border-zinc-700'
  }
}

function SidebarContent({
  activeTab,
  onSelectTab,
  findingCount,
  patchCount,
  auditCount,
  currentRole,
  currentTenant,
  onOpenCommandPalette,
}: SidebarProps) {
  const categories: NavCategory[] = [
    {
      id: 'posture',
      title: 'Executive Posture',
      icon: Activity,
      items: [
        {
          id: 'overview',
          label: 'Executive Threat Posture',
          icon: LayoutDashboard,
          badge: 'Live',
          badgeVariant: 'cyan',
        },
      ],
    },
    {
      id: 'engine',
      title: 'Core Engine & SAST',
      icon: Cpu,
      items: [
        {
          id: 'studio',
          label: 'SAST & Taint Studio',
          icon: Code2,
          badge: 'Interactive',
          badgeVariant: 'cyan',
        },
        {
          id: 'findings',
          label: 'Findings & Call Graphs',
          icon: AlertTriangle,
          badge: findingCount > 0 ? `${findingCount}` : null,
          badgeVariant: 'rose',
        },
        {
          id: 'research',
          label: 'Autonomous Research',
          icon: Brain,
          badge: '4D Matrix',
          badgeVariant: 'purple',
        },
      ],
    },
    {
      id: 'remediation',
      title: 'Remediation & Intel',
      icon: Sparkles,
      items: [
        {
          id: 'remediation',
          label: 'Auto Remediation',
          icon: CheckCircle2,
          badge: patchCount > 0 ? `${patchCount} Verified` : '0 Verified',
          badgeVariant: 'emerald',
        },
        {
          id: 'intel',
          label: 'OSV Threat Intelligence',
          icon: Globe,
          badge: '250k+ CVEs',
          badgeVariant: 'sky',
        },
      ],
    },
    {
      id: 'governance',
      title: 'Operations & Audit',
      icon: Layers,
      items: [
        {
          id: 'fleet',
          label: 'Worker Fleet & Sandboxes',
          icon: Server,
          badge: 'Phase 6',
          badgeVariant: 'amber',
        },
        {
          id: 'webhooks',
          label: 'CI/CD & Webhook Intake',
          icon: Webhook,
          badge: 'Phase 5',
          badgeVariant: 'violet',
        },
        {
          id: 'audit',
          label: 'Immutable Audit Trail',
          icon: History,
          badge: auditCount > 0 ? `${auditCount}` : null,
          badgeVariant: 'zinc',
        },
      ],
    },
  ]

  return (
    <div className="flex flex-col justify-between h-full min-h-0 select-none bg-zinc-950/90">
      {/* Brand & Command Palette Trigger */}
      <div className="flex flex-col shrink-0">
        <div className="p-4 border-b border-zinc-800/80">
          <SentraLogo size={36} showBadge={true} glow={true} />
        </div>

        {/* Quick Command & Search bar */}
        <div className="px-3 pt-3 pb-1">
          <button
            type="button"
            onClick={() => {
              if (onOpenCommandPalette) {
                onOpenCommandPalette()
              } else {
                window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true }))
              }
            }}
            className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg border border-zinc-800/90 bg-zinc-900/50 hover:bg-zinc-900 hover:border-zinc-700/80 text-zinc-400 hover:text-zinc-200 text-xs transition-all duration-150 group shadow-xs cursor-pointer"
          >
            <div className="flex items-center gap-2">
              <Search className="size-3.5 text-zinc-500 group-hover:text-zinc-300 transition-colors" />
              <span className="text-[11px] text-zinc-400 group-hover:text-zinc-200">Command & Search...</span>
            </div>
            <kbd className="text-[9px] font-mono bg-zinc-800/90 text-zinc-400 px-1.5 py-0.5 rounded border border-zinc-700/60 leading-none group-hover:text-zinc-300">
              ⌘K
            </kbd>
          </button>
        </div>
      </div>

      {/* Navigation Menu by Categories */}
      <nav className="flex-1 min-h-0 overflow-y-auto px-2.5 py-2 space-y-3 scrollbar-thin scrollbar-thumb-zinc-800 scrollbar-track-transparent">
        {categories.map((cat, catIdx) => {
          const CatIcon = cat.icon
          return (
            <div
              key={cat.id}
              className={cn('space-y-1', catIdx > 0 && 'pt-2.5 border-t border-zinc-800/60')}
            >
              {/* Category Header */}
              <div className="px-2 pt-0.5 pb-1 flex items-center justify-between text-[10px] font-bold tracking-wider text-zinc-400 uppercase font-mono">
                <div className="flex items-center gap-1.5">
                  <CatIcon className="size-3 text-zinc-500" />
                  <span>{cat.title}</span>
                </div>
              </div>

              {/* Category Items */}
              <div className="space-y-0.5">
                {cat.items.map((item) => {
                  const Icon = item.icon
                  const isActive = activeTab === item.id
                  return (
                    <button
                      key={item.id}
                      type="button"
                      title={item.label}
                      onClick={() => onSelectTab(item.id)}
                      className={cn(
                        'group relative w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all duration-150 text-left outline-none cursor-pointer',
                        isActive
                          ? 'bg-blue-500/10 text-white font-semibold shadow-xs border border-blue-500/25 before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-1 before:rounded-r-full before:bg-blue-500 before:shadow-[0_0_8px_rgba(59,130,246,0.6)]'
                          : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60 border border-transparent'
                      )}
                    >
                      <div className="flex items-center gap-2.5 truncate min-w-0">
                        <div
                          className={cn(
                            'size-6 rounded-md flex items-center justify-center shrink-0 transition-colors',
                            isActive
                              ? 'bg-blue-500/20 text-blue-400 shadow-xs shadow-blue-500/20'
                              : 'text-zinc-400 group-hover:text-zinc-200 group-hover:bg-zinc-800/60'
                          )}
                        >
                          <Icon className="size-3.5" />
                        </div>
                        <span className="truncate text-[12px]">{item.label}</span>
                      </div>

                      {item.badge && (
                        <span
                          className={cn(
                            'text-[10px] font-mono px-1.5 py-0.5 rounded-md font-medium shrink-0 ml-1.5 border transition-colors',
                            getBadgeClasses(item.badgeVariant, isActive)
                          )}
                        >
                          {item.badge}
                        </span>
                      )}
                    </button>
                  )
                })}
              </div>
            </div>
          )
        })}
      </nav>

      {/* Footer Security Isolation & Status Widget */}
      <div className="p-3 border-t border-zinc-800/80 flex flex-col gap-2.5 bg-zinc-950/80 shrink-0">
        {/* Security Gates Enclave Card */}
        <div className="p-2.5 rounded-lg border border-zinc-800/80 bg-zinc-900/60 flex flex-col gap-2 shadow-xs">
          <div className="flex items-center justify-between text-[11px]">
            <div className="flex items-center gap-1.5 font-medium text-emerald-400">
              <Lock className="size-3 shrink-0" />
              <span className="font-semibold tracking-tight">Fail-Closed Boundary</span>
            </div>
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
            </span>
          </div>

          {/* Telemetry Micro Grid */}
          <div className="grid grid-cols-2 gap-1.5 pt-1 border-t border-zinc-800/50 text-[10px] font-mono text-zinc-400">
            <div className="flex items-center justify-between bg-zinc-950/40 px-1.5 py-0.5 rounded border border-zinc-800/40">
              <span className="text-zinc-500">Egress</span>
              <span className="text-emerald-400 font-semibold">DENIED</span>
            </div>
            <div className="flex items-center justify-between bg-zinc-950/40 px-1.5 py-0.5 rounded border border-zinc-800/40">
              <span className="text-zinc-500">Sandbox</span>
              <span className="text-zinc-300">Isolated</span>
            </div>
            <div className="flex items-center justify-between bg-zinc-950/40 px-1.5 py-0.5 rounded border border-zinc-800/40">
              <span className="text-zinc-500">Memory</span>
              <span className="text-zinc-300">CAS 12.4M</span>
            </div>
            <div className="flex items-center justify-between bg-zinc-950/40 px-1.5 py-0.5 rounded border border-zinc-800/40">
              <span className="text-zinc-500">Engine</span>
              <span className="text-cyan-400">Pure-Rust</span>
            </div>
          </div>
        </div>

        {/* Active Tenant and Role Bar */}
        <div className="flex items-center justify-between px-1 text-[11px]">
          <div className="flex items-center gap-1.5 min-w-0 max-w-[155px]">
            <Building2 className="size-3 text-zinc-500 shrink-0" />
            <span className="truncate text-zinc-400 font-mono text-[10px]" title={currentTenant}>
              {currentTenant.replace('tenant-', '')}
            </span>
          </div>
          <Badge
            variant="outline"
            className={cn('text-[10px] h-4 px-1.5 font-mono shrink-0', getRoleBadgeClasses(currentRole))}
          >
            {currentRole}
          </Badge>
        </div>
      </div>
    </div>
  )
}

/**
 * Desktop Sidebar (visible on large screens lg:)
 */
export function Sidebar({ className, ...props }: SidebarProps) {
  return (
    <aside
      className={cn(
        'hidden lg:flex w-[275px] xl:w-[285px] border-r bg-zinc-950/80 backdrop-blur flex-col justify-between shrink-0 h-screen sticky top-0 border-zinc-800/80 z-20',
        className
      )}
    >
      <SidebarContent {...props} />
    </aside>
  )
}

/**
 * Mobile Drawer Sidebar (slide-over sheet on mobile / tablet)
 */
export function MobileSidebar({ open, onOpenChange, ...props }: MobileSidebarProps) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="left"
        className="w-[300px] sm:w-[320px] max-w-[85vw] p-0 bg-zinc-950 border-r border-zinc-800 text-zinc-100 flex flex-col h-full shadow-2xl"
      >
        <div className="sr-only">
          <SheetTitle>Navigation Menu</SheetTitle>
          <SheetDescription>Platform capabilities and audit controls</SheetDescription>
        </div>
        <SidebarContent
          {...props}
          onSelectTab={(tab) => {
            props.onSelectTab(tab)
            onOpenChange(false)
          }}
        />
      </SheetContent>
    </Sheet>
  )
}
