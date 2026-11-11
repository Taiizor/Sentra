import { useState } from 'react'
import { FolderGit2, Trash2, TriangleAlert } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import type { TenantView } from '@/types/api'
import { minimumRoleFor } from './console-format'
import { ConfirmDialog, ErrorState, GatedButton, LoadingRows, TimeAgo } from './settings-kit'

/**
 * Registered workspaces and the admin action to unregister one. Unregistering only removes the
 * registry row (DELETE /api/tenants/:id): the bridge keeps the workspace's core store and every
 * record it already holds, and it never touches the workspace directory.
 */
export function SettingsWorkspaces() {
  const { tenants, tenantsLoaded, tenantsError, refreshTenants, invalidate } = useConsole()
  const [pending, setPending] = useState<TenantView | null>(null)

  async function unregister(target: TenantView) {
    try {
      const result = await api.tenants.remove(target.tenantId)
      toast.success(`Unregistered ${target.name}`, { description: `Core store kept at ${result.coreStoreRetained}` })
      await refreshTenants()
      invalidate()
    } catch (error) {
      toast.error(`${target.name} was not unregistered`, { description: errorMessage(error) })
      throw error
    }
  }

  if (tenantsError && tenants.length === 0) {
    return <ErrorState title="Could not load registered workspaces" error={new Error(tenantsError)} onRetry={() => void refreshTenants()} />
  }
  if (!tenantsLoaded) return <LoadingRows rows={2} className="h-16" />

  return (
    <div className="flex flex-col gap-3">
      <p className="text-[11px] text-muted-foreground">
        A workspace&apos;s directory cannot be changed after registration. To point Sentra at a moved directory, or to start over
        with a fresh core store, unregister the workspace here and register the directory again under a new workspace id.
      </p>
      {tenants.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border/60 bg-card/30 p-6 text-center text-xs text-muted-foreground">
          No workspace is registered.
        </div>
      ) : (
        tenants.map((tenant) => (
          <div key={tenant.tenantId} className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col sm:flex-row sm:items-start gap-2 min-w-0">
            <div className="flex flex-col gap-1 min-w-0 flex-1">
              <span className="flex items-center gap-2 min-w-0 flex-wrap">
                <FolderGit2 className="size-3.5 text-muted-foreground shrink-0" />
                <span className="text-xs font-semibold text-foreground">{tenant.name}</span>
                <code className="font-mono text-[11px] text-muted-foreground">{tenant.tenantId}</code>
              </span>
              <code className="font-mono text-[11px] text-muted-foreground break-all">{tenant.workspace}</code>
              <span className="flex items-center gap-2 flex-wrap text-[11px] text-muted-foreground">
                {!tenant.workspaceExists && (
                  <Badge variant="outline" className="text-[10px] border-amber-500/40 text-amber-300 gap-1">
                    <TriangleAlert className="size-2.5" />
                    directory not found on the bridge host
                  </Badge>
                )}
                {tenant.coreStore.error ? (
                  <span className="text-rose-400 break-words">Core store error: {tenant.coreStore.error}</span>
                ) : (
                  <span>Core store {tenant.coreStore.initialized ? 'initialized' : 'not initialized'}</span>
                )}
                <span>
                  registered <TimeAgo iso={tenant.createdAt} /> by <span className="font-mono">{tenant.createdBy}</span>
                </span>
              </span>
            </div>
            <GatedButton permission="tenant:create" size="xs" variant="ghost" onClick={() => setPending(tenant)} className="text-rose-400 gap-1 shrink-0">
              <Trash2 className="size-3" />
              Unregister
            </GatedButton>
          </div>
        ))
      )}
      <p className="text-[10px] text-muted-foreground">
        Registering and unregistering workspaces needs the {minimumRoleFor('tenant:create')} role (permission tenant:create).
      </p>

      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(open) => (!open ? setPending(null) : undefined)}
        title={pending ? `Unregister ${pending.name}?` : 'Unregister workspace?'}
        confirmLabel="Unregister workspace"
        destructive
        onConfirm={() => (pending ? unregister(pending) : Promise.resolve())}
      >
        {pending && (
          <>
            <p>
              The bridge removes <code className="font-mono">{pending.tenantId}</code> from its workspace registry: it disappears from
              the console and can no longer be scanned. The directory <code className="font-mono break-all">{pending.workspace}</code>{' '}
              is not touched.
            </p>
            <p>
              Nothing else is deleted. The workspace&apos;s core store stays on the bridge host, and the scan runs, findings and patch
              records the bridge holds for this id stay in its database. The action is recorded in the operator audit log.
            </p>
            <p>
              Registering again under the same id is refused while that core store exists (<code className="font-mono">core_store_exists</code>).
              Use a new workspace id, or have the bridge operator move the retained store file away first.
            </p>
          </>
        )}
      </ConfirmDialog>
    </div>
  )
}
