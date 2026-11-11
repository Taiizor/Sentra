import { FolderGit2, Search } from 'lucide-react'
import { cn } from 'cn'
import { Badge } from '@/components/ui/badge'
import { SentraLogo } from '@/components/ui/sentra-logo'
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet'
import { useConsole } from '@/lib/console-context'
import type { TabId } from '@/lib/router'
import { roleBadgeClass } from './permission-hint'
import { NAV_GROUPS, paletteShortcutLabel } from './nav-items'

/** Counts shown next to nav entries; null hides the badge (no data, or not loaded yet). */
export interface SidebarBadges {
  findings: number | null
  remediation: number | null
}

export interface SidebarProps {
  badges: SidebarBadges
  coreVersion: string | null
  onOpenPalette: () => void
  className?: string
}

export interface MobileSidebarProps extends SidebarProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

const BADGE_TITLES: Partial<Record<TabId, string>> = {
  findings: 'Open candidate findings (unverified)',
  remediation: 'Patch candidates awaiting a decision',
}

function SidebarContent({ badges, coreVersion, onOpenPalette, onNavigate }: SidebarProps & { onNavigate?: () => void }) {
  const { tab, navigate, tenant, session } = useConsole()
  const badgeFor: Partial<Record<TabId, number | null>> = { findings: badges.findings, remediation: badges.remediation }

  return (
    <div className="flex flex-col justify-between h-full min-h-0 select-none bg-sidebar text-sidebar-foreground">
      <div className="flex flex-col shrink-0">
        <div className="px-4 py-3.5 border-b border-border/40">
          <SentraLogo size={32} version={coreVersion} />
        </div>
        <div className="px-3 pt-2.5 pb-1">
          <button
            type="button"
            onClick={onOpenPalette}
            className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-md border border-border/60 bg-muted/30 hover:bg-muted/60 text-muted-foreground hover:text-foreground text-xs transition-colors cursor-pointer"
          >
            <span className="flex items-center gap-2">
              <Search className="size-3.5" />
              Search views & findings
            </span>
            <kbd className="text-[10px] font-mono bg-background/80 px-1.5 py-0.5 leading-none rounded border border-border/60">
              {paletteShortcutLabel()}
            </kbd>
          </button>
        </div>
      </div>

      <nav className="flex-1 min-h-0 overflow-y-auto px-2.5 py-2 space-y-3.5 no-scrollbar" aria-label="Console views">
        {NAV_GROUPS.map((group) => (
          <div key={group.id} className="space-y-0.5">
            <div className="px-2 pb-1 text-[10px] font-semibold tracking-wider text-muted-foreground/70 uppercase font-mono">
              {group.title}
            </div>
            {group.items.map((item) => {
              const Icon = item.icon
              const active = tab === item.id
              const count = badgeFor[item.id] ?? null
              return (
                <button
                  key={item.id}
                  type="button"
                  aria-current={active ? 'page' : undefined}
                  onClick={() => {
                    navigate(item.id)
                    onNavigate?.()
                  }}
                  className={cn(
                    'group relative w-full flex items-center justify-between px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors text-left outline-none cursor-pointer focus-visible:ring-2 focus-visible:ring-ring/50',
                    active
                      ? 'bg-primary/10 text-primary font-semibold before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-0.5 before:rounded-r-full before:bg-primary'
                      : 'text-muted-foreground hover:text-foreground hover:bg-muted/40',
                  )}
                >
                  <span className="flex items-center gap-2.5 truncate min-w-0">
                    <Icon className={cn('size-4 shrink-0', active ? 'text-primary' : 'text-muted-foreground group-hover:text-foreground')} />
                    <span className="truncate">{item.label}</span>
                  </span>
                  {count !== null && count > 0 && (
                    <span
                      title={BADGE_TITLES[item.id]}
                      className="text-[10px] font-mono px-1.5 py-0.5 leading-none rounded-full font-semibold shrink-0 ml-1.5 border bg-zinc-800/70 text-zinc-300 border-zinc-700"
                    >
                      {count}
                    </span>
                  )}
                </button>
              )
            })}
          </div>
        ))}
      </nav>

      <div className="p-3 border-t border-border/40 shrink-0">
        <div className="p-2.5 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-1.5 text-[11px]">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono text-zinc-300 truncate" title={session.principal}>
              {session.principal}
            </span>
            <Badge variant="outline" className={cn('text-[10px] font-mono px-1.5 h-4 shrink-0', roleBadgeClass(session.roleLabel))}>
              {session.roleLabel}
            </Badge>
          </div>
          <div className="flex items-center gap-1.5 pt-1 border-t border-border/40 text-[10px] text-muted-foreground min-w-0">
            <FolderGit2 className="size-3 shrink-0" />
            {tenant ? (
              <span className="truncate" title={`${tenant.name} (${tenant.tenantId})`}>
                {tenant.name} <span className="font-mono text-zinc-500">{tenant.tenantId}</span>
              </span>
            ) : (
              <span>No workspace selected</span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export function Sidebar(props: SidebarProps) {
  return (
    <aside className={cn('w-64 border-r border-border/60 shrink-0 h-screen sticky top-0 hidden md:flex md:flex-col z-30', props.className)}>
      <SidebarContent {...props} />
    </aside>
  )
}

export function MobileSidebar({ open, onOpenChange, ...props }: MobileSidebarProps) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="left" className="p-0 w-64 bg-sidebar border-r border-border/60">
        <SheetTitle className="sr-only">Navigation</SheetTitle>
        <SheetDescription className="sr-only">Sentra console views</SheetDescription>
        <SidebarContent {...props} onNavigate={() => onOpenChange(false)} />
      </SheetContent>
    </Sheet>
  )
}
