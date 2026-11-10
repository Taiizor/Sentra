import {
  Blocks,
  Brain,
  CheckCircle2,
  Code2,
  GitPullRequest,
  Globe,
  History,
  LayoutDashboard,
  ListChecks,
  Server,
  Settings,
  Webhook,
  type LucideIcon,
} from 'lucide-react'
import type { TabId } from '@/lib/router'

/**
 * Single source of navigation labels for the sidebar, header and command palette. Labels are
 * plain nouns describing what each view does today; no capability claims.
 */
export interface NavItem {
  id: TabId
  label: string
  /** Header title for the active view. */
  title: string
  icon: LucideIcon
  /** Views that read tenant-scoped data and cannot render without a registered workspace. */
  requiresTenant: boolean
}

export interface NavGroup {
  id: string
  title: string
  items: NavItem[]
}

export const NAV_GROUPS: NavGroup[] = [
  {
    id: 'workspace',
    title: 'Workspace',
    items: [
      { id: 'overview', label: 'Overview', title: 'Workspace overview', icon: LayoutDashboard, requiresTenant: true },
      { id: 'findings', label: 'Findings', title: 'Findings (unverified candidates)', icon: ListChecks, requiresTenant: true },
      {
        id: 'remediation',
        label: 'Remediation',
        title: 'Remediation (model-generated patch candidates)',
        icon: CheckCircle2,
        requiresTenant: true,
      },
      { id: 'research', label: 'Research', title: 'Research coverage and reconnaissance', icon: Brain, requiresTenant: true },
    ],
  },
  {
    id: 'analysis',
    title: 'Analysis tools',
    items: [
      { id: 'studio', label: 'Snippet scan', title: 'Snippet scan (heuristic rules)', icon: Code2, requiresTenant: false },
      { id: 'intel', label: 'OSV lookup', title: 'OSV advisory lookup', icon: Globe, requiresTenant: false },
      { id: 'plugins', label: 'Plugins', title: 'Plugin adapters', icon: Blocks, requiresTenant: false },
    ],
  },
  {
    id: 'integrations',
    title: 'Integrations',
    items: [
      { id: 'pull-requests', label: 'Pull requests', title: 'GitHub pull requests', icon: GitPullRequest, requiresTenant: true },
      { id: 'webhooks', label: 'Webhooks', title: 'Webhook intake', icon: Webhook, requiresTenant: false },
    ],
  },
  {
    id: 'operations',
    title: 'Operations',
    items: [
      { id: 'fleet', label: 'Host & workers', title: 'Bridge host and workers', icon: Server, requiresTenant: false },
      { id: 'audit', label: 'Audit trail', title: 'Audit trail', icon: History, requiresTenant: false },
      { id: 'settings', label: 'Settings', title: 'Settings', icon: Settings, requiresTenant: false },
    ],
  },
]

export const NAV_ITEMS: NavItem[] = NAV_GROUPS.flatMap((group) => group.items)

export function navItem(tab: TabId): NavItem {
  return NAV_ITEMS.find((item) => item.id === tab) ?? NAV_ITEMS[0]
}

/** Keyboard hint for the command palette, derived from the client platform. */
export function paletteShortcutLabel(): string {
  const platform =
    (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform ?? navigator.platform ?? ''
  return /mac|iphone|ipad/i.test(platform) ? '⌘K' : 'Ctrl K'
}
