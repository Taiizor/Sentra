import { useState } from 'react'
import { GitPullRequest, KeyRound } from 'lucide-react'
import { toast } from 'sonner'
import { Input } from '@/components/ui/input'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import type { GitHubCredentialSource } from '@/types/api'
import { GitHubCredentialHelp } from './pr-repository-card'
import { CREDENTIAL_SOURCE_LABEL } from './settings-format'
import { ConfirmDialog, ErrorState, GatedButton, LoadingRows, TimeAgo } from './settings-kit'

/**
 * GitHub credential management. The token field is write-only: the stored value never comes
 * back from the bridge. Precedence (enforced by the bridge): stored token, then
 * GITHUB_TOKEN/GH_TOKEN, then the GitHub CLI session.
 */
export function SettingsGitHub() {
  const { tenant, can, invalidate } = useConsole()
  const system = useResource('settings:system', (signal) => api.system.status(signal))
  const tenantId = tenant?.tenantId ?? null
  const status = useResource(tenantId ? `gh-status:${tenantId}` : null, (signal) => api.github.status(tenantId ?? '', signal))
  const [token, setToken] = useState('')
  const [saving, setSaving] = useState(false)
  const [clearOpen, setClearOpen] = useState(false)

  const source: GitHubCredentialSource | null | undefined = status.data
    ? status.data.credential.source
    : system.data?.integrations.githubCredentialSource
  const storedConfigured = status.data ? status.data.credential.storedTokenConfigured : source === 'stored_pat'
  const storedUpdatedAt = status.data?.credential.storedTokenUpdatedAt ?? null
  const tokenValid = token.length > 0 && token.length <= 255 && !/\s/.test(token)

  async function store() {
    if (!tokenValid) return
    setSaving(true)
    try {
      const credential = await api.github.setToken(token)
      setToken('')
      invalidate()
      toast.success('GitHub accepted the token; it is now stored', {
        description: credential.source ? `Active credential: ${CREDENTIAL_SOURCE_LABEL[credential.source]}.` : undefined,
      })
    } catch (error) {
      toast.error('GitHub token was not stored', { description: errorMessage(error) })
    } finally {
      setSaving(false)
    }
  }

  async function clear() {
    try {
      const credential = await api.github.clearToken()
      invalidate()
      toast.success('Stored GitHub token removed', {
        description: credential.source
          ? `The bridge now uses: ${CREDENTIAL_SOURCE_LABEL[credential.source]}.`
          : 'No other GitHub credential is available; GitHub features report “not configured”.',
      })
    } catch (error) {
      toast.error('Stored GitHub token was not removed', { description: errorMessage(error) })
      throw error
    }
  }

  if (system.error) return <ErrorState title="Could not load the bridge status" error={system.error} onRetry={system.reload} />
  if (source === undefined) return <LoadingRows rows={2} className="h-20" />

  return (
    <div className="flex flex-col gap-4">
      <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-2">
        <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1.5">
          <GitPullRequest className="size-3" />
          Active credential
        </span>
        {source ? (
          <span className="text-xs text-foreground">{CREDENTIAL_SOURCE_LABEL[source]}</span>
        ) : (
          <div className="flex flex-col gap-2">
            <span className="text-xs text-amber-400">Not configured — the bridge has no GitHub credential.</span>
            <GitHubCredentialHelp />
          </div>
        )}
        {status.data?.viewer && (
          <span className="text-[11px] text-muted-foreground">
            GitHub accepted it as <span className="font-mono text-foreground">@{status.data.viewer.login}</span>
            {status.data.viewer.scopes ? <span className="font-mono"> · scopes: {status.data.viewer.scopes}</span> : ' · scopes not reported (fine-grained token or app)'}
          </span>
        )}
        {status.data?.viewerErrorKind === 'check_failed' && status.data.viewerError && (
          <span className="text-[11px] text-rose-400 break-words">Credential check (GitHub /user) failed: {status.data.viewerError}</span>
        )}
        {status.data?.viewerErrorKind === 'credential_unreadable' && status.data.viewerError && (
          <span className="text-[11px] text-rose-400 break-words">{status.data.viewerError}</span>
        )}
        {status.error && <span className="text-[11px] text-rose-400 break-words">Could not check the credential with GitHub: {errorMessage(status.error)}</span>}
        {!tenantId && source && (
          <span className="text-[11px] text-muted-foreground">Register a workspace to check the credential against GitHub.</span>
        )}
        <span className="text-[11px] text-muted-foreground">
          Precedence: a token stored here, then <code className="font-mono">GITHUB_TOKEN</code>/<code className="font-mono">GH_TOKEN</code>, then
          the GitHub CLI session of the bridge host.
        </span>
      </div>

      <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-2">
        <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1.5">
          <KeyRound className="size-3" />
          Stored personal access token
        </span>
        <div className="text-[11px] text-muted-foreground flex items-center gap-2 flex-wrap">
          {storedConfigured ? (
            <>
              <span className="text-foreground">A token is stored.</span>
              {storedUpdatedAt && (
                <span>
                  updated <TimeAgo iso={storedUpdatedAt} />
                </span>
              )}
              <GatedButton permission="settings:write" size="xs" variant="ghost" onClick={() => setClearOpen(true)} className="text-rose-400">
                Clear token
              </GatedButton>
            </>
          ) : (
            <span>No token is stored in the bridge.</span>
          )}
        </div>
        <form
          className="flex flex-col sm:flex-row gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            void store()
          }}
        >
          <Input
            type="password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            placeholder={storedConfigured ? 'Enter a new token to replace the stored one' : 'github_pat_… or ghp_…'}
            className="h-7 text-xs font-mono flex-1"
            autoComplete="new-password"
            spellCheck={false}
            disabled={!can('settings:write')}
          />
          <GatedButton permission="settings:write" variant="default" size="sm" onClick={() => void store()} busy={saving} disabled={!tokenValid} className="text-xs">
            Store token
          </GatedButton>
        </form>
        <span className="text-[10px] text-muted-foreground">
          Write-only: the token is sent to the bridge once and is never returned to the browser. The bridge checks it against GitHub&apos;s{' '}
          <code className="font-mono">/user</code> endpoint before storing it and refuses tokens GitHub rejects.
        </span>
      </div>

      <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-1.5 text-[11px] text-muted-foreground">
        <span className="text-[10px] uppercase font-semibold">Token permissions used by the console</span>
        <span>
          Read (fine-grained): Metadata, Pull requests, Contents (changed files for PR scans), Actions (workflow runs), Commit statuses and
          Checks (checks summary).
        </span>
        <span>
          Write, only for actions that need the github:comment, github:status or github:create-pr permission: Pull requests (review
          comments and draft pull requests), Commit statuses, Contents (patch branches).
        </span>
        <span>
          Classic tokens: <code className="font-mono">repo</code> (or <code className="font-mono">public_repo</code> for public repositories only).
        </span>
      </div>

      <ConfirmDialog
        open={clearOpen}
        onOpenChange={setClearOpen}
        title="Remove the stored GitHub token?"
        confirmLabel="Remove token"
        destructive
        onConfirm={clear}
      >
        <p>
          Deletes the personal access token stored in the bridge. The bridge will fall back to GITHUB_TOKEN/GH_TOKEN or the GitHub CLI session
          if either is available; otherwise GitHub features report &ldquo;not configured&rdquo;.
        </p>
      </ConfirmDialog>
    </div>
  )
}
