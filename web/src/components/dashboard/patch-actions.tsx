import { useState } from 'react'
import { ArrowRight, ExternalLink, GitPullRequest, RotateCcw, Wrench } from 'lucide-react'
import { toast } from 'sonner'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { Button } from '@/components/ui/button'
import { formatTimestamp } from '@/components/dashboard/findings-format'
import { ConfirmDialog, GatedButton } from '@/components/dashboard/findings-shared'
import { PatchPullRequestDialog } from '@/components/dashboard/patch-pr-dialog'
import type { PatchBundleView } from '@/types/api'

/**
 * Apply / roll back / open-PR actions for one patch bundle. Each action requires an explicit
 * confirmation that states what will happen; the server enforces the permissions.
 */
export function PatchActions({
  patch,
  onUpdated,
  onOpenInRemediation,
}: {
  patch: PatchBundleView
  onUpdated: (next: PatchBundleView) => void
  onOpenInRemediation?: () => void
}) {
  const { tenant, invalidate } = useConsole()
  const [confirm, setConfirm] = useState<'apply' | 'rollback' | 'pr' | null>(null)
  const [busy, setBusy] = useState(false)

  if (!tenant) return null
  const tenantId = tenant.tenantId

  async function run(action: 'apply' | 'rollback') {
    setBusy(true)
    try {
      const next =
        action === 'apply' ? await api.patches.apply(tenantId, patch.bundleId) : await api.patches.rollback(tenantId, patch.bundleId)
      onUpdated(next)
      invalidate()
      toast.success(action === 'apply' ? 'Patch applied to the workspace' : 'Patch rolled back', {
        description: `${next.targetPath} was ${action === 'apply' ? 'modified' : 'restored from the backup'}.`,
      })
      setConfirm(null)
    } catch (error) {
      toast.error(action === 'apply' ? 'Patch was not applied' : 'Rollback failed', { description: errorMessage(error) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {patch.state !== 'applied' && (
        <GatedButton permission="patch:apply" size="sm" onClick={() => setConfirm('apply')}>
          <Wrench /> Apply to workspace
        </GatedButton>
      )}
      {patch.state === 'applied' && (
        <GatedButton permission="patch:apply" size="sm" variant="outline" onClick={() => setConfirm('rollback')}>
          <RotateCcw /> Roll back
        </GatedButton>
      )}
      {patch.pullRequest ? (
        <Button
          size="sm"
          variant="outline"
          render={<a href={patch.pullRequest.url} target="_blank" rel="noreferrer noopener" />}
          nativeButton={false}
        >
          <GitPullRequest /> PR #{patch.pullRequest.number} <ExternalLink className="size-3" />
        </Button>
      ) : (
        <GatedButton permission="github:create-pr" size="sm" variant="outline" onClick={() => setConfirm('pr')}>
          <GitPullRequest /> Create draft pull request
        </GatedButton>
      )}
      {onOpenInRemediation && (
        <Button size="sm" variant="ghost" onClick={onOpenInRemediation}>
          Open in Remediation <ArrowRight />
        </Button>
      )}

      <ConfirmDialog
        open={confirm === 'apply'}
        onOpenChange={(open) => setConfirm(open ? 'apply' : null)}
        title="Apply this patch to the workspace?"
        confirmLabel="Apply patch"
        busy={busy}
        onConfirm={() => void run('apply')}
      >
        <span>
          The bridge will modify <code className="text-zinc-200">{patch.targetPath}</code> inside the workspace{' '}
          <code className="break-all text-zinc-200">{tenant.workspace}</code>. A backup of the current file is kept so
          the change can be rolled back from Remediation.
        </span>
        <span>Hunks are applied all-or-nothing: if they do not match the current file, nothing is written.</span>
        {!patch.appliesCleanly && (
          <span className="text-rose-300">
            The recorded dry-run check says this diff does not apply
            {patch.applyCheckDetail ? `: ${patch.applyCheckDetail}` : '.'} The apply is likely to be refused.
          </span>
        )}
        <span className="text-amber-300">
          Verification: not run. This is unverified model output that has not been compiled or tested.
        </span>
      </ConfirmDialog>

      <ConfirmDialog
        open={confirm === 'rollback'}
        onOpenChange={(open) => setConfirm(open ? 'rollback' : null)}
        title="Roll back this patch?"
        confirmLabel="Roll back"
        destructive
        busy={busy}
        onConfirm={() => void run('rollback')}
      >
        <span>
          The bridge will restore <code className="text-zinc-200">{patch.targetPath}</code> in{' '}
          <code className="break-all text-zinc-200">{tenant.workspace}</code> from the backup taken when this patch
          was applied{patch.appliedAt ? ` (${formatTimestamp(patch.appliedAt)}${patch.appliedBy ? ` by ${patch.appliedBy}` : ''})` : ''}.
        </span>
        <span>
          The bridge first checks that the file still matches the backup with this diff applied. If the file changed after
          the patch was applied, the rollback is refused (<code className="text-zinc-300">target_modified_since_apply</code>)
          and nothing is written; restore the file manually from the backup or with git.
        </span>
      </ConfirmDialog>

      {confirm === 'pr' && (
        <PatchPullRequestDialog
          patch={patch}
          open
          onOpenChange={(open) => setConfirm(open ? 'pr' : null)}
          onCreated={(created) => {
            onUpdated({ ...patch, pullRequest: { number: created.number, url: created.url } })
            invalidate()
          }}
        />
      )}
    </div>
  )
}
