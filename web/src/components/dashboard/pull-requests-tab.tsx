import { useMemo, useRef, useState } from 'react'
import { GitBranch, GitCommit, GitPullRequest, RefreshCw, Search } from 'lucide-react'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { api } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import type { GitHubStatusView, PullRequestListView, PullRequestView } from '@/types/api'
import { minimumRoleFor } from './console-format'
import { ChecksSummary, SecurityStatusBadge } from './pr-badges'
import { PrDetailDialog } from './pr-detail-dialog'
import { PrRepositoryCard } from './pr-repository-card'
import { shortSha } from './settings-format'
import { ErrorState, LoadingRows, NoTenantState, TimeAgo } from './settings-kit'

type Filter = 'all' | 'attention' | 'not_scanned' | 'drafts'

const FILTERS: { id: Filter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'attention', label: 'Signals or failed scan' },
  { id: 'not_scanned', label: 'Not scanned / stale' },
  { id: 'drafts', label: 'Drafts' },
]

function matchesFilter(pr: PullRequestView, filter: Filter): boolean {
  switch (filter) {
    case 'all':
      return true
    case 'attention':
      return pr.security.status === 'critical' || pr.security.status === 'warnings' || pr.security.status === 'failed'
    case 'not_scanned':
      return pr.security.status === 'not_scanned' || pr.security.status === 'stale'
    case 'drafts':
      return pr.isDraft
  }
}

export function PullRequestsTab() {
  const { tenant } = useConsole()
  if (!tenant) return <NoTenantState feature="pull request inspection" />
  return <PullRequestsView key={tenant.tenantId} tenantId={tenant.tenantId} />
}

function PullRequestsView({ tenantId }: { tenantId: string }) {
  const { tenant } = useConsole()
  const status = useResource(`gh-status:${tenantId}`, (signal) => api.github.status(tenantId, signal))
  const repository = status.data?.repository ?? null
  const canListPulls = !!status.data?.credential.source && !!repository
  // Set by the Refresh button so the next pull-request request bypasses the bridge's short-lived cache.
  const bypassCacheRef = useRef(false)
  const pulls = useResource(
    canListPulls && repository ? `gh-pulls:${tenantId}:${repository.owner}/${repository.repo}` : null,
    async (signal) => {
      const refresh = bypassCacheRef.current
      try {
        return await api.github.pulls(tenantId, signal, refresh)
      } finally {
        // An aborted request is superseded by a new one, which still carries the refresh request.
        if (!signal.aborted) bypassCacheRef.current = false
      }
    },
  )

  function refresh() {
    status.reload()
    if (canListPulls) {
      bypassCacheRef.current = true
      pulls.reload()
    }
  }

  if (!tenant) return null

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border/40">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2 flex-wrap">
            <GitPullRequest className="size-5 text-primary" />
            <h2 className="text-base sm:text-lg font-bold tracking-tight text-foreground">Pull Requests</h2>
            {pulls.data && (
              <Badge variant="outline" className="text-xs font-mono border-primary/30 text-primary bg-primary/5">
                {pulls.data.pulls.length} open
              </Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            Open pull requests of the GitHub repository linked to this workspace, their GitHub checks and workflow runs, and Sentra scans of the
            files they change.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={refresh} disabled={status.loading || pulls.loading} className="h-8 text-xs gap-1.5 self-start sm:self-auto">
          <RefreshCw className={`size-3 ${status.loading || pulls.loading ? 'animate-spin text-primary' : ''}`} />
          Refresh
        </Button>
      </div>

      {status.error ? (
        <ErrorState title="Could not read the GitHub configuration" error={status.error} onRetry={status.reload} />
      ) : !status.data ? (
        <LoadingRows rows={1} className="h-24" />
      ) : (
        <PrRepositoryCard tenant={tenant} status={status.data} onStatusChange={(next) => status.setData(next)} />
      )}

      {status.data && <PullRequestList tenantId={tenantId} status={status.data} pulls={pulls} />}
    </div>
  )
}

function PullRequestList({
  tenantId,
  status,
  pulls,
}: {
  tenantId: string
  status: GitHubStatusView
  pulls: { data: PullRequestListView | undefined; error: unknown; reload: () => void }
}) {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<Filter>('all')
  const [selectedNumber, setSelectedNumber] = useState<number | null>(null)

  const list = useMemo(() => pulls.data?.pulls ?? [], [pulls.data])
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return list.filter((pr) => {
      if (!matchesFilter(pr, filter)) return false
      if (!needle) return true
      return (
        pr.title.toLowerCase().includes(needle) ||
        pr.author.login.toLowerCase().includes(needle) ||
        pr.headRef.toLowerCase().includes(needle) ||
        String(pr.number).includes(needle)
      )
    })
  }, [list, query, filter])

  if (!status.credential.source) {
    return (
      <EmptyCard
        title="GitHub is not configured"
        body="Pull requests cannot be listed until the bridge has a GitHub credential. See the options above."
      />
    )
  }
  if (!status.repository) {
    return (
      <EmptyCard
        title="No repository linked to this workspace"
        body={`Someone with the ${minimumRoleFor('settings:write')} role can set owner/repository above, or add a GitHub origin remote to the workspace.`}
      />
    )
  }
  if (pulls.error) return <ErrorState title="Could not list pull requests" error={pulls.error} onRetry={pulls.reload} />
  if (!pulls.data) return <LoadingRows rows={4} className="h-20" />

  const repository = pulls.data.repository
  const repoName = `${repository.owner}/${repository.repo}`
  const selected = selectedNumber === null ? null : (list.find((pr) => pr.number === selectedNumber) ?? null)
  const scannedCurrent = list.filter((pr) => !['not_scanned', 'stale'].includes(pr.security.status)).length
  const critical = list.filter((pr) => pr.security.status === 'critical').length

  return (
    <>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Stat label="Open pull requests" value={list.length} />
        <Stat label="Scanned at current head" value={scannedCurrent} />
        <Stat label="Not scanned / stale" value={list.length - scannedCurrent} />
        <Stat label="With critical signals" value={critical} tone={critical > 0 ? 'text-rose-400' : undefined} />
      </div>

      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search by title, branch, author or number"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            className="pl-8 h-8 text-xs bg-card/60 border-border/60"
          />
        </div>
        <div className="flex items-center gap-1 bg-card/60 p-1 rounded-md border border-border/60 text-xs flex-wrap">
          {FILTERS.map((option) => (
            <button
              key={option.id}
              type="button"
              onClick={() => setFilter(option.id)}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                filter === option.id ? 'bg-primary text-primary-foreground font-semibold' : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      <div className="text-[11px] text-muted-foreground">
        {repoName} · fetched <TimeAgo iso={pulls.data.fetchedAt} />
      </div>

      {list.length === 0 ? (
        <EmptyCard title={`No open pull requests in ${repoName}`} body="GitHub reported no open pull requests for this repository." />
      ) : filtered.length === 0 ? (
        <EmptyCard title="No pull requests match" body="No open pull request matches the current search and filter." />
      ) : (
        <div className="flex flex-col gap-2.5">
          {filtered.map((pr) => (
            <PullRequestRow key={pr.number} pr={pr} onOpen={() => setSelectedNumber(pr.number)} />
          ))}
        </div>
      )}

      {selected && (
        <PrDetailDialog
          tenantId={tenantId}
          repository={repository}
          pr={selected}
          viewerLogin={status.viewer?.login ?? null}
          onClose={() => setSelectedNumber(null)}
        />
      )}
    </>
  )
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-0.5">
      <span className="text-[10px] uppercase font-semibold text-muted-foreground">{label}</span>
      <span className={`text-lg font-bold font-mono ${tone ?? 'text-foreground'}`}>{value}</span>
    </div>
  )
}

function EmptyCard({ title, body }: { title: string; body: string }) {
  return (
    <Card className="border-border/60 bg-card/40">
      <CardContent className="p-8 text-center flex flex-col items-center gap-2">
        <GitPullRequest className="size-7 text-muted-foreground" />
        <div className="text-sm font-semibold text-foreground">{title}</div>
        <div className="text-xs text-muted-foreground max-w-md">{body}</div>
      </CardContent>
    </Card>
  )
}

function PullRequestRow({ pr, onOpen }: { pr: PullRequestView; onOpen: () => void }) {
  return (
    <Card className="border-border/60 bg-card/40 hover:bg-card/70 transition-colors">
      <CardContent className="p-0">
        <button type="button" onClick={onOpen} className="w-full text-left p-3.5 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex items-start gap-3 min-w-0 flex-1">
            <Avatar size="sm" className="mt-0.5">
              {pr.author.avatarUrl && <AvatarImage src={pr.author.avatarUrl} alt="" />}
              <AvatarFallback className="text-[10px]">{pr.author.login.slice(0, 2).toUpperCase()}</AvatarFallback>
            </Avatar>
            <div className="flex flex-col gap-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-xs font-bold text-foreground">#{pr.number}</span>
                <span className="text-sm font-semibold text-foreground break-words">{pr.title}</span>
                {pr.isDraft && (
                  <Badge variant="outline" className="text-[10px] text-muted-foreground">
                    Draft
                  </Badge>
                )}
                {pr.isSentraBranch && (
                  <Badge
                    variant="outline"
                    className="text-[10px] font-mono border-primary/30 text-primary"
                    title="The head branch name starts with sentra/, the prefix Sentra uses for candidate patch branches. The name alone says nothing about who wrote the change, and nothing in it is verified."
                  >
                    sentra branch
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground flex-wrap">
                <span className="font-mono">@{pr.author.login}</span>
                <span className="inline-flex items-center gap-1 font-mono min-w-0">
                  <GitBranch className="size-3 shrink-0" />
                  <span className="truncate max-w-[220px]">{pr.headRef}</span> → {pr.baseRef}
                </span>
                <span className="inline-flex items-center gap-1 font-mono">
                  <GitCommit className="size-3" />
                  {shortSha(pr.headSha)}
                </span>
                <span>
                  {pr.filesCount} files · <span className="text-emerald-400">+{pr.additions}</span> / <span className="text-rose-400">-{pr.deletions}</span>
                </span>
                <span>
                  updated <TimeAgo iso={pr.updatedAt} />
                </span>
              </div>
            </div>
          </div>
          <div className="flex flex-col items-start lg:items-end gap-1 shrink-0 pl-9 lg:pl-0">
            <SecurityStatusBadge security={pr.security} />
            <ChecksSummary checks={pr.checks} />
          </div>
        </button>
      </CardContent>
    </Card>
  )
}
