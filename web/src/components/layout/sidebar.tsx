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
  Search,
  Building2,
  Shield,
  Settings,
  Blocks,
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

interface NavItem {
  id: string
  label: string
  icon: React.ComponentType<{ className?: string }>
  badge?: number | null
  badgeColor?: string
}

interface NavCategory {
  id: string
  title: string
  items: NavItem[]
}

function getRoleBadgeClasses(role: UserRole): string {
  switch (role) {
    case 'SecurityAdmin':
      return 'bg-purple-500/15 text-purple-300 border-purple-500/30'
    case 'Operator':
      return 'bg-blue-500/15 text-blue-300 border-blue-500/30'
    case 'Viewer':
    default:
      return 'bg-muted text-muted-foreground border-border'
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
      title: 'Posture',
      items: [
        {
          id: 'overview',
          label: 'Threat Posture',
          icon: LayoutDashboard,
        },
      ],
    },
    {
      id: 'engine',
      title: 'Security Engine',
      items: [
        {
          id: 'studio',
          label: 'SAST Studio',
          icon: Code2,
        },
        {
          id: 'findings',
          label: 'Findings',
          icon: AlertTriangle,
          badge: findingCount > 0 ? findingCount : null,
          badgeColor: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
        },
        {
          id: 'research',
          label: 'Deep Research',
          icon: Brain,
        },
      ],
    },
    {
      id: 'remediation',
      title: 'Remediation & Intel',
      items: [
        {
          id: 'remediation',
          label: 'Remediation',
          icon: CheckCircle2,
          badge: patchCount > 0 ? patchCount : null,
          badgeColor: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
        },
        {
          id: 'intel',
          label: 'Threat Intel',
          icon: Globe,
        },
      ],
    },
    {
      id: 'operations',
      title: 'Operations',
      items: [
        {
          id: 'fleet',
          label: 'Worker Fleet',
          icon: Server,
        },
        {
          id: 'webhooks',
          label: 'CI/CD Webhooks',
          icon: Webhook,
        },
        {
          id: 'plugins',
          label: 'Plugins & Adapters',
          icon: Blocks,
        },
        {
          id: 'audit',
          label: 'Audit Trail',
          icon: History,
          badge: auditCount > 0 ? auditCount : null,
          badgeColor: 'bg-muted text-muted-foreground border-border',
        },
        {
          id: 'settings',
          label: 'Settings',
          icon: Settings,
        },
      ],
    },
  ]

  return (
    <div className="flex flex-col justify-between h-full min-h-0 select-none bg-sidebar text-sidebar-foreground">
      {/* Brand & Command Palette Trigger */}
      <div className="flex flex-col shrink-0">
        <div className="px-4 py-3.5 border-b border-border/40">
          <SentraLogo size={32} showBadge={true} glow={true} />
        </div>

        {/* Quick Command & Search bar */}
        <div className="px-3 pt-2.5 pb-1">
          <button
            type="button"
            onClick={() => {
              if (onOpenCommandPalette) {
                onOpenCommandPalette()
              } else {
                window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true }))
              }
            }}
            className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-md border border-border/60 bg-muted/30 hover:bg-muted/60 hover:border-border text-muted-foreground hover:text-foreground text-xs transition-colors group cursor-pointer"
          >
            <div className="flex items-center gap-2">
              <Search className="size-3.5 text-muted-foreground group-hover:text-foreground transition-colors" />
              <span className="text-xs">Quick search...</span>
            </div>
            <kbd className="text-[10px] font-mono bg-background/80 text-muted-foreground px-1.5 py-0.2 rounded border border-border/60 leading-none group-hover:text-foreground">
              ⌘K
            </kbd>
          </button>
        </div>
      </div>

      {/* Navigation Menu by Categories */}
      <nav className="flex-1 min-h-0 overflow-y-auto px-2.5 py-2 space-y-3.5 no-scrollbar">
        {categories.map((cat) => (
          <div key={cat.id} className="space-y-0.5">
            {/* Category Header */}
            <div className="px-2 pb-1 text-[10px] font-semibold tracking-wider text-muted-foreground/70 uppercase font-mono">
              {cat.title}
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
                      'group relative w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors text-left outline-none cursor-pointer',
                      isActive
                        ? 'bg-primary/10 text-primary font-semibold before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-0.5 before:rounded-r-full before:bg-primary'
                        : 'text-muted-foreground hover:text-foreground hover:bg-muted/40'
                    )}
                  >
                    <div className="flex items-center gap-2.5 truncate min-w-0">
                      <Icon className={cn('size-4 shrink-0 transition-colors', isActive ? 'text-primary' : 'text-muted-foreground group-hover:text-foreground')} />
                      <span className="truncate text-xs">{item.label}</span>
                    </div>

                    {item.badge !== undefined && item.badge !== null && (
                      <span
                        className={cn(
                          'text-[10px] font-mono px-1.5 py-0.2 rounded-full font-semibold shrink-0 ml-1.5 border',
                          item.badgeColor || 'bg-muted text-muted-foreground border-border'
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
        ))}
      </nav>

      {/* Footer Security Isolation & Status Widget */}
      <div className="p-3 border-t border-border/40 flex flex-col gap-2 shrink-0 bg-card/20">
        {/* Compact Security Enclave Status */}
        <div className="p-2.5 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-1.5 text-xs">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5 text-[11px] font-medium text-emerald-400">
              <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>Enclave Isolated</span>
            </div>
            <Badge variant="outline" className={cn('text-[10px] font-mono px-1.5 py-0', getRoleBadgeClasses(currentRole))}>
              {currentRole}
            </Badge>
          </div>

          <div className="flex items-center justify-between pt-1 border-t border-border/40 text-[10px] font-mono text-muted-foreground">
            <span className="truncate flex items-center gap-1" title={currentTenant}>
              <Building2 className="size-2.5 shrink-0" />
              {currentTenant.replace('tenant-', '')}
            </span>
            <span className="text-muted-foreground/70 shrink-0">Pure-Rust</span>
          </div>
        </div>
      </div>
    </div>
  )
}

export function Sidebar(props: SidebarProps) {
  return (
    <aside
      className={cn(
        'w-64 border-r border-border/60 flex flex-col shrink-0 h-screen sticky top-0 hidden md:flex z-30',
        props.className
      )}
    >
      <SidebarContent {...props} />
    </aside>
  )
}

export function MobileSidebar({ open, onOpenChange, ...props }: MobileSidebarProps) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="left" className="p-0 w-64 bg-sidebar border-r border-border/60">
        <SheetTitle className="sr-only">Navigation Menu</SheetTitle>
        <SheetDescription className="sr-only">Sentra Platform Navigation</SheetDescription>
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
