import { useState } from 'react'
import { ExternalLink, GitBranch, KeyRound, Lock, Pencil, Unlock, UserRound } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import type { GitHubStatusView, TenantView } from '@/types/api'
import { minimumRoleFor } from './console-format'
import { CREDENTIAL_SOURCE_LABEL } from './settings-format'
import { ConfirmDialog, GatedButton } from './settings-kit'

const REPOSITORY_PATTERN = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/

/** Explains the real ways to provide a GitHub credential to the bridge. */
export function GitHubCredentialHelp() {
  return (
    <ol className="list-decimal pl-4 space-y-1.5 text-xs text-muted-foreground">
      <li>
        On the host that runs the Sentra bridge, sign in with the GitHub CLI: <code className="font-mono text-foreground">gh auth login</code>.
        The bridge reads <code className="font-mono">gh auth token</code> (cached for five minutes).
      </li>
      <li>
        Or start the bridge with <code className="font-mono text-foreground">GITHUB_TOKEN</code> or{' '}
        <code className="font-mono text-foreground">GH_TOKEN</code> set in its environment.
      </li>
      <li>
        Or someone with the {minimumRoleFor('settings:write')} role stores a personal access token in <span className="text-foreground">Settings → GitHub credential</span>. A
        stored token takes precedence over the other two sources.
      </li>
    </ol>
  )
}

export function PrRepositoryCard({
  tenant,
  status,
  onStatusChange,
}: {
  tenant: TenantView
  status: GitHubStatusView
  onStatusChange: (next: GitHubStatusView) => void
}) {
  const { invalidate, refreshTenants } = useConsole()
  const [editOpen, setEditOpen] = useState(false)
  const [clearOpen, setClearOpen] = useState(false)
  const [draft, setDraft] = useState('')
  const [saving, setSaving] = useState(false)

  const repository = status.repository
  const info = status.repositoryInfo
  const draftValid = REPOSITORY_PATTERN.test(draft.trim())

  async function saveRepository(value: string | null) {
    try {
      const next = await api.github.setRepository(tenant.tenantId, value)
      onStatusChange(next)
      await refreshTenants()
      invalidate()
      toast.success(value ? `Repository set to ${value}` : 'Configured repository cleared', {
        description: next.repository
          ? `Now using ${next.repository.owner}/${next.repository.repo} (${next.repository.source === 'configured' ? 'configured' : 'git remote'}).`
          : 'No repository could be resolved from the workspace git remote.',
      })
    } catch (error) {
      toast.error('Repository was not changed', { description: errorMessage(error) })
      throw error
    }
  }

  async function submitEdit() {
    if (!draftValid) return
    setSaving(true)
    try {
      await saveRepository(draft.trim())
      setEditOpen(false)
    } catch {
      // reported by saveRepository
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
      {/* Credential */}
      <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-2 min-w-0">
        <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1.5">
          <KeyRound className="size-3" />
          GitHub credential
        </span>
        {status.credential.source ? (
          <>
            <span className="text-xs text-foreground">{CREDENTIAL_SOURCE_LABEL[status.credential.source]}</span>
            {status.viewer ? (
              <span className="text-[11px] text-muted-foreground flex items-center gap-1 flex-wrap">
                <UserRound className="size-3" />
                Authenticated as <span className="font-mono text-foreground">@{status.viewer.login}</span>
                <span className="font-mono">
                  · scopes: {status.viewer.scopes ? status.viewer.scopes : 'not reported (fine-grained token or app)'}
                </span>
              </span>
            ) : null}
            {status.viewerErrorKind === 'check_failed' && status.viewerError && (
              <span className="text-[11px] text-rose-400 break-words">Credential check (GitHub /user) failed: {status.viewerError}</span>
            )}
          </>
        ) : (
          <div className="flex flex-col gap-2">
            <span className="text-xs text-amber-400">Not configured — no GitHub credential is available to the bridge.</span>
            {status.viewerErrorKind === 'credential_unreadable' && status.viewerError && (
              <span className="text-[11px] text-rose-400 break-words">{status.viewerError}</span>
            )}
            <GitHubCredentialHelp />
          </div>
        )}
      </div>

      {/* Repository resolution */}
      <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-2 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1.5">
            <GitBranch className="size-3" />
            Repository for workspace {tenant.name}
          </span>
          <div className="flex items-center gap-1">
            <GatedButton
              permission="settings:write"
              size="xs"
              variant="ghost"
              onClick={() => {
                setDraft(repository ? `${repository.owner}/${repository.repo}` : '')
                setEditOpen(true)
              }}
              className="gap-1"
            >
              <Pencil className="size-3" />
              Set
            </GatedButton>
            {repository?.source === 'configured' && (
              <GatedButton permission="settings:write" size="xs" variant="ghost" onClick={() => setClearOpen(true)}>
                Clear
              </GatedButton>
            )}
          </div>
        </div>
        {repository ? (
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-xs text-foreground">
                {repository.owner}/{repository.repo}
              </span>
              <Badge variant="outline" className="text-[10px] font-mono">
                {repository.source === 'configured' ? 'configured by an admin' : 'detected from git remote'}
              </Badge>
              {info && (
                <Badge variant="outline" className="text-[10px] font-mono gap-1">
                  {info.private ? <Lock className="size-2.5" /> : <Unlock className="size-2.5" />}
                  {info.private ? 'private' : 'public'}
                </Badge>
              )}
            </div>
            {info && (
              <span className="text-[11px] text-muted-foreground flex items-center gap-2 flex-wrap">
                <span>
                  default branch <span className="font-mono text-foreground">{info.defaultBranch}</span>
                </span>
                {info.permissions && (
                  <span className="font-mono">
                    access:{' '}
                    {Object.entries(info.permissions)
                      .filter(([, granted]) => granted)
                      .map(([name]) => name)
                      .join(', ') || 'none'}
                  </span>
                )}
                <a href={info.htmlUrl} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-0.5 hover:text-foreground">
                  open <ExternalLink className="size-2.5" />
                </a>
              </span>
            )}
          </div>
        ) : (
          <span className="text-xs text-amber-400">
            No repository resolved: none is configured and the workspace has no GitHub <code className="font-mono">origin</code> remote.
          </span>
        )}
        {repository && status.repositoryError && <span className="text-[11px] text-rose-400 break-words">{status.repositoryError}</span>}
      </div>

      <Dialog open={editOpen} onOpenChange={(open) => (!saving ? setEditOpen(open) : undefined)}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="text-sm font-semibold">Set GitHub repository</DialogTitle>
            <DialogDescription className="text-xs">
              Links workspace <span className="font-mono">{tenant.tenantId}</span> to a GitHub repository. Pull requests, workflow runs,
              comments and commit statuses for this workspace will use it. Clear it later to fall back to the workspace&apos;s git remote.
            </DialogDescription>
          </DialogHeader>
          <form
            className="flex flex-col gap-1.5"
            onSubmit={(event) => {
              event.preventDefault()
              void submitEdit()
            }}
          >
            <Input
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              placeholder="owner/repository"
              autoComplete="off"
              spellCheck={false}
              className="font-mono text-xs"
              aria-invalid={draft.length > 0 && !draftValid}
            />
            {draft.length > 0 && !draftValid && (
              <span className="text-[11px] text-rose-400">Use the form owner/repository (letters, digits, &quot;-&quot;, &quot;.&quot;, &quot;_&quot;).</span>
            )}
          </form>
          <DialogFooter>
            <Button type="button" variant="outline" size="sm" onClick={() => setEditOpen(false)} disabled={saving}>
              Cancel
            </Button>
            <Button type="button" size="sm" onClick={() => void submitEdit()} disabled={!draftValid || saving}>
              {saving ? 'Saving…' : 'Save repository'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={clearOpen}
        onOpenChange={setClearOpen}
        title="Clear the configured repository?"
        confirmLabel="Clear repository"
        onConfirm={() => saveRepository(null)}
      >
        <p>
          Removes the repository configured for workspace <span className="font-mono">{tenant.tenantId}</span>. The bridge will fall back to
          the GitHub repository detected from the workspace&apos;s git remote, if any.
        </p>
      </ConfirmDialog>
    </div>
  )
}
