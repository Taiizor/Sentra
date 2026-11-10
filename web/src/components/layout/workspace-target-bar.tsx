import { Fragment, useState } from 'react'
import { ChevronDown, Database, FolderGit2, GitBranch, Play, RefreshCw, TriangleAlert } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import type { ScanKind, TenantView } from '@/types/api'
import { DisabledReason } from './disabled-reason'
import { minimumRoleFor, permissionHint } from './permission-hint'

interface WorkspaceTargetBarProps {
  /** Opens the live scan stream for the selected tenant. */
  onStartScan: (kind: ScanKind) => void
}

const SCAN_ACTIONS: { kind: ScanKind; label: string; description: string }[] = [
  { kind: 'sast', label: 'SAST scan', description: 'Heuristic line-based rules over the workspace (sentra scan)' },
  {
    kind: 'dependency',
    label: 'Dependency audit',
    description: 'Lockfile inventory, then OSV.dev advisory lookup when OSV queries are enabled',
  },
  {
    kind: 'codeql',
    label: 'CodeQL language probe',
    description: 'Counts source languages by file extension; CodeQL itself is not run',
  },
]

function GitHeadLabel({ tenant }: { tenant: TenantView }) {
  if (!tenant.gitHead) {
    return <span className="text-zinc-500">No git metadata</span>
  }
  const { branch, sha } = tenant.gitHead
  return (
    <span className="font-mono" title={sha ?? undefined}>
      {branch ?? 'detached HEAD'}
      {sha && <span className="text-zinc-500"> @ {sha.slice(0, 8)}</span>}
    </span>
  )
}

function CoreStoreLabel({ tenant }: { tenant: TenantView }) {
  const { coreStore } = tenant
  if (coreStore.error) {
    return (
      <span className="text-rose-300 truncate max-w-[320px]" title={coreStore.error}>
        Core store error: {coreStore.error}
      </span>
    )
  }
  return coreStore.initialized ? (
    <span className="text-zinc-300">Core store initialized</span>
  ) : (
    <span className="text-amber-300">Core store not initialized</span>
  )
}

export function WorkspaceTargetBar({ onStartScan }: WorkspaceTargetBarProps) {
  const { tenant, can, refreshTenants } = useConsole()
  const [refreshing, setRefreshing] = useState(false)

  if (!tenant) return null

  const scanBlockedReason = !can('scan:run')
    ? permissionHint('scan:run')
    : !tenant.workspaceExists
      ? `The workspace directory does not exist on the bridge host. Restore it at the registered path and refresh, or have someone with the ${minimumRoleFor('tenant:create')} role unregister this workspace (Settings → Workspaces) and register the new location under a new workspace id.`
      : null

  async function refresh(tenantId: string) {
    setRefreshing(true)
    try {
      await api.tenants.get(tenantId, true)
      await refreshTenants()
    } catch (error) {
      toast.error('Could not refresh workspace metadata', { description: errorMessage(error) })
    } finally {
      setRefreshing(false)
    }
  }

  return (
    <div className="border border-zinc-800/80 bg-zinc-900/40 rounded-xl p-2 sm:px-3 sm:py-2 flex flex-col lg:flex-row lg:items-center justify-between gap-2.5">
      <div className="flex items-start sm:items-center gap-2.5 min-w-0 flex-1">
        <div className="size-7 rounded-lg bg-primary/10 border border-primary/25 text-primary flex items-center justify-center shrink-0">
          <FolderGit2 className="size-3.5" />
        </div>
        <div className="flex flex-col gap-0.5 min-w-0">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-xs font-semibold text-zinc-100 truncate">{tenant.name}</span>
            <code className="text-[11px] text-zinc-400 truncate" title={tenant.workspace}>
              {tenant.workspace}
            </code>
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px] text-zinc-400">
            {!tenant.workspaceExists && (
              <span className="flex items-center gap-1 text-amber-300">
                <TriangleAlert className="size-3" />
                Directory not found on the bridge host
              </span>
            )}
            <span className="flex items-center gap-1">
              <GitBranch className="size-3 shrink-0" />
              <GitHeadLabel tenant={tenant} />
            </span>
            <span className="flex items-center gap-1 min-w-0">
              <Database className="size-3 shrink-0" />
              <CoreStoreLabel tenant={tenant} />
            </span>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-1.5 shrink-0 self-end lg:self-auto">
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => void refresh(tenant.tenantId)}
          disabled={refreshing}
          title="Re-read git and core store state"
          aria-label="Refresh workspace metadata"
          className="text-zinc-400 hover:text-zinc-100"
        >
          <RefreshCw className={`size-3.5 ${refreshing ? 'animate-spin' : ''}`} />
        </Button>

        <DisabledReason reason={scanBlockedReason}>
          <Button
            size="sm"
            disabled={scanBlockedReason !== null}
            onClick={() => onStartScan('all')}
            className="h-7.5 text-xs font-semibold px-3"
            title="SAST scan, dependency audit and CodeQL language probe"
          >
            <Play className="size-3 fill-current" />
            Full scan
          </Button>
        </DisabledReason>

        <DisabledReason reason={scanBlockedReason}>
          <DropdownMenu>
            <DropdownMenuTrigger
              disabled={scanBlockedReason !== null}
              className="inline-flex items-center justify-center h-7.5 text-xs font-medium rounded-md border border-zinc-800 bg-zinc-950/80 hover:bg-zinc-800 text-zinc-300 px-2 gap-1 transition-colors outline-none disabled:opacity-50 disabled:pointer-events-none"
            >
              Single stage
              <ChevronDown className="size-3 text-zinc-400" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80 bg-zinc-950 border border-zinc-800 p-1.5 text-zinc-200">
              {SCAN_ACTIONS.map((action, index) => (
                <Fragment key={action.kind}>
                  {index > 0 && <DropdownMenuSeparator />}
                  <DropdownMenuItem onClick={() => onStartScan(action.kind)} className="flex-col items-start gap-0.5 py-1.5 text-xs">
                    <span className="font-medium">{action.label}</span>
                    <span className="text-[10px] text-zinc-500">{action.description}</span>
                  </DropdownMenuItem>
                </Fragment>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </DisabledReason>
      </div>
    </div>
  )
}
