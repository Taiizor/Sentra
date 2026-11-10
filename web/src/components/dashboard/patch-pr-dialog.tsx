import { useState, type ReactNode } from 'react'
import { ExternalLink, GitPullRequest, Loader2, Settings } from 'lucide-react'
import { toast } from 'sonner'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { minimumRoleFor } from '@/components/dashboard/console-format'
import { ErrorAlert } from '@/components/dashboard/findings-shared'
import type { CreatePullRequestResponse, GitHubStatusView, PatchBundleView } from '@/types/api'

const BRANCH_NAME = /^(?!-)[A-Za-z0-9._/-]{1,200}$/

function NotReady({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Alert className="border-amber-500/30 bg-amber-500/5">
      <AlertTitle className="text-xs text-amber-200">{title}</AlertTitle>
      <AlertDescription className="text-xs text-zinc-400">{children}</AlertDescription>
    </Alert>
  )
}

/**
 * Reason the bridge cannot create the pull request at all, or null. Mirrors the server's
 * preconditions: a resolvable GitHub credential and a resolved owner/repo.
 */
function blockingReason(status: GitHubStatusView): { title: string; detail: string } | null {
  if (!status.credential.source) {
    const unreadable = status.viewerErrorKind === 'credential_unreadable' && status.viewerError ? ` ${status.viewerError}` : ''
    return {
      title: 'GitHub is not configured',
      detail: `The bridge has no usable GitHub credential.${unreadable} Someone with the ${minimumRoleFor('settings:write')} role can store a token in Settings, or the bridge operator can provide one through the environment or the gh CLI.`,
    }
  }
  if (!status.repository) {
    return {
      title: 'No GitHub repository for this workspace',
      detail: `No owner/repo is configured and none was detected from the git remote. Someone with the ${minimumRoleFor('settings:write')} role can set the repository in Settings.`,
    }
  }
  return null
}

/**
 * Status problems that do not stop the bridge from trying: the server's pull-request path does
 * not call GitHub's /user endpoint (which app and installation tokens cannot read), and it only
 * needs repository details when no base branch is given.
 */
function warnings(status: GitHubStatusView): { title: string; detail: string }[] {
  const list: { title: string; detail: string }[] = []
  if (status.viewerErrorKind === 'check_failed' && status.viewerError) {
    list.push({
      title: 'Credential check (GitHub /user) failed',
      detail: `${status.viewerError} Creating the pull request may still work (app and installation tokens cannot read /user); if it fails, the bridge's error is shown here.`,
    })
  }
  if (status.repositoryError || !status.repositoryInfo) {
    list.push({
      title: 'Repository details are unavailable',
      detail: `${status.repositoryError ?? 'GitHub returned no repository information.'} The default branch and visibility are unknown; enter the base branch yourself.`,
    })
  }
  return list
}

export function PatchPullRequestDialog({
  patch,
  open,
  onOpenChange,
  onCreated,
}: {
  patch: PatchBundleView
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: (result: CreatePullRequestResponse) => void
}) {
  const { tenant, can, navigate } = useConsole()
  const tenantId = tenant?.tenantId ?? null
  const github = useResource(open && tenantId ? `github-status:${tenantId}` : null, (signal) =>
    api.github.status(tenantId as string, signal),
  )
  // Callers mount this dialog only while it is open, so its state starts fresh every time.
  const [editedBase, setEditedBase] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<CreatePullRequestResponse | null>(null)
  const [createError, setCreateError] = useState<unknown>(null)

  const defaultBranch = github.data?.repositoryInfo?.defaultBranch ?? null
  const baseBranch = editedBase ?? defaultBranch ?? ''

  const status = github.data
  const blocked = status ? blockingReason(status) : null
  const notices = status && !blocked ? warnings(status) : []
  const branchValid = BRANCH_NAME.test(baseBranch.trim())
  const repoName = status?.repositoryInfo?.fullName ?? (status?.repository ? `${status.repository.owner}/${status.repository.repo}` : null)
  const repositoryInfo = status?.repositoryInfo ?? null

  async function handleCreate() {
    if (!tenantId) return
    setBusy(true)
    setCreateError(null)
    try {
      const created = await api.patches.pullRequest(tenantId, patch.bundleId, { baseBranch: baseBranch.trim() })
      setResult(created)
      onCreated(created)
      toast.success(`Draft pull request #${created.number} created`, { description: created.url })
    } catch (error) {
      setCreateError(error)
      toast.error('Pull request was not created', { description: errorMessage(error) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(next) => (!busy ? onOpenChange(next) : undefined)}>
      <DialogContent className="max-w-lg border border-zinc-800 bg-zinc-950" showCloseButton={!busy}>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm text-zinc-100">
            <GitPullRequest className="size-4 text-zinc-400" />
            {result ? 'Pull request created' : 'Create draft pull request?'}
          </DialogTitle>
          <DialogDescription render={<div />} className="flex flex-col gap-3 text-xs text-zinc-400">
            {result ? (
              <div className="flex flex-col gap-1.5">
                <a
                  href={result.url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="inline-flex items-center gap-1 font-medium text-sky-300 hover:underline"
                >
                  #{result.number} · {result.url} <ExternalLink className="size-3" />
                </a>
                <span>
                  Branch <code className="text-zinc-300">{result.branch}</code> into{' '}
                  <code className="text-zinc-300">{result.baseBranch}</code> (base{' '}
                  <code className="text-zinc-500">{result.baseSha.slice(0, 12)}</code>, commit{' '}
                  <code className="text-zinc-500">{result.commitSha.slice(0, 12)}</code>).
                </span>
              </div>
            ) : github.loading && !status ? (
              <div className="flex flex-col gap-2">
                <Skeleton className="h-4 w-2/3 bg-zinc-800/60" />
                <Skeleton className="h-4 w-1/2 bg-zinc-800/60" />
              </div>
            ) : github.error ? (
              <ErrorAlert error={github.error} title="Could not read the GitHub status" onRetry={github.reload} />
            ) : blocked ? (
              <NotReady title={blocked.title}>
                {blocked.detail}
                {can('settings:write') && (
                  <Button
                    variant="outline"
                    size="xs"
                    className="mt-2 w-fit"
                    onClick={() => {
                      onOpenChange(false)
                      navigate('settings')
                    }}
                  >
                    <Settings /> Open Settings
                  </Button>
                )}
              </NotReady>
            ) : status ? (
              <>
                {notices.map((notice) => (
                  <NotReady key={notice.title} title={notice.title}>
                    {notice.detail}
                  </NotReady>
                ))}
                <span>
                  The bridge will push a new branch to{' '}
                  {repositoryInfo ? (
                    <a
                      href={repositoryInfo.htmlUrl}
                      target="_blank"
                      rel="noreferrer noopener"
                      className="font-mono text-zinc-200 hover:underline"
                    >
                      {repoName}
                    </a>
                  ) : (
                    <code className="font-mono text-zinc-200">{repoName}</code>
                  )}
                  {repositoryInfo
                    ? repositoryInfo.private
                      ? ' (private repository)'
                      : ' (public repository)'
                    : ' (visibility unknown)'}{' '}
                  containing{' '}
                  <code className="text-zinc-200">{patch.targetPath}</code> with this diff applied, and open a draft
                  pull request against the base branch below. Everyone with access to the repository can see it.
                </span>
                <span>
                  Head branch:{' '}
                  {patch.branchName ? (
                    <code className="text-zinc-300">{patch.branchName}</code>
                  ) : (
                    'chosen by the bridge when the pull request is created'
                  )}
                </span>
                <label className="flex flex-col gap-1">
                  <span className="text-zinc-300">Base branch</span>
                  <Input
                    value={baseBranch}
                    onChange={(event) => setEditedBase(event.target.value)}
                    className="h-7 font-mono text-xs"
                    aria-invalid={baseBranch.length > 0 && !branchValid}
                    disabled={busy}
                  />
                  {defaultBranch && (
                    <span className="text-[10px] text-zinc-500">Repository default branch: {defaultBranch}</span>
                  )}
                </label>
                <span className="text-amber-300">
                  Verification: not run. The pull request will contain unverified model output.
                </span>
                {createError !== null && <ErrorAlert error={createError} title="The bridge did not create the pull request" />}
              </>
            ) : null}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="border-zinc-800 bg-zinc-900/60">
          {result ? (
            <Button size="sm" onClick={() => onOpenChange(false)}>
              Done
            </Button>
          ) : (
            <>
              <Button variant="outline" size="sm" disabled={busy} onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button
                size="sm"
                disabled={busy || !status || blocked !== null || !branchValid}
                onClick={() => void handleCreate()}
              >
                {busy && <Loader2 className="animate-spin" />}
                Create draft pull request
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
