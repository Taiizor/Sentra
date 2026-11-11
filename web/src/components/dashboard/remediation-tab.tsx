import { useEffect, useMemo, useState } from 'react'
import { cn } from 'cn'
import { ArrowRight, FolderSearch, GitPullRequest, RotateCw, Wrench } from 'lucide-react'
import { api } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { Skeleton } from '@/components/ui/skeleton'
import { permissionRequirement } from '@/components/dashboard/findings-format'
import { ErrorAlert, Timestamp } from '@/components/dashboard/findings-shared'
import { PatchActions } from '@/components/dashboard/patch-actions'
import { ApplyCheckBadge, PatchDetails, PatchStateBadge, UnverifiedModelBadge } from '@/components/dashboard/patch-details'
import { PATCH_STATE_LABEL } from '@/components/dashboard/patch-format'
import { clearRemediationFocus, peekRemediationFocus } from '@/components/dashboard/remediation-focus'
import type { PatchBundleView, PatchState } from '@/types/api'

type StateFilter = PatchState | 'all'
const STATE_FILTERS: StateFilter[] = ['all', 'proposed', 'applied', 'rolled_back']

export function RemediationTab() {
  const { tenant } = useConsole()
  if (!tenant) {
    return (
      <Empty className="border border-zinc-800 py-16">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <FolderSearch />
          </EmptyMedia>
          <EmptyTitle>No workspace selected</EmptyTitle>
          <EmptyDescription>Patch candidates are stored per workspace. Register or select a workspace first.</EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }
  return <RemediationWorkspace key={tenant.tenantId} tenantId={tenant.tenantId} />
}

function PatchListItem({
  patch,
  selected,
  onSelect,
}: {
  patch: PatchBundleView
  selected: boolean
  onSelect: () => void
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={cn(
        'flex w-full flex-col gap-1.5 border-b border-zinc-800/70 px-3 py-2.5 text-left transition-colors last:border-b-0',
        selected ? 'bg-zinc-800/60' : 'hover:bg-zinc-800/30',
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="line-clamp-2 text-xs font-medium text-zinc-100">{patch.title}</span>
        <PatchStateBadge state={patch.state} />
      </div>
      <span className="truncate font-mono text-[11px] text-zinc-400" title={patch.targetPath}>
        {patch.targetPath}
      </span>
      <div className="flex flex-wrap items-center gap-1.5 text-[10px] text-zinc-500">
        <ApplyCheckBadge patch={patch} />
        <span className="font-mono">
          {patch.provider}:{patch.model}
        </span>
        <span>·</span>
        <Timestamp value={patch.createdAt} />
        <span>· {patch.createdBy}</span>
        {patch.pullRequest && (
          <span className="inline-flex items-center gap-0.5 text-sky-300">
            <GitPullRequest className="size-3" /> #{patch.pullRequest.number}
          </span>
        )}
      </div>
    </button>
  )
}

function RemediationWorkspace({ tenantId }: { tenantId: string }) {
  const { can, navigate } = useConsole()
  const patches = useResource(`patches:${tenantId}`, (signal) => api.patches.list(tenantId, signal))
  const [stateFilter, setStateFilter] = useState<StateFilter>('all')
  const [selectedId, setSelectedId] = useState<string | null>(peekRemediationFocus)
  useEffect(() => clearRemediationFocus(), [])

  const all = useMemo(
    () => [...(patches.data?.patches ?? [])].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt)),
    [patches.data],
  )
  const visible = stateFilter === 'all' ? all : all.filter((patch) => patch.state === stateFilter)
  const selected = visible.find((patch) => patch.bundleId === selectedId) ?? visible[0] ?? null

  const counts = useMemo(() => {
    const byState: Record<PatchState, number> = { proposed: 0, applied: 0, rolled_back: 0 }
    let pullRequests = 0
    for (const patch of all) {
      byState[patch.state] += 1
      if (patch.pullRequest) pullRequests += 1
    }
    return { byState, pullRequests }
  }, [all])

  function replacePatch(next: PatchBundleView) {
    patches.setData((current) => ({
      patches: (current?.patches ?? []).map((patch) => (patch.bundleId === next.bundleId ? next : patch)),
    }))
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex flex-col gap-0.5">
          <div className="flex items-center gap-2">
            <Wrench className="size-4 text-zinc-400" />
            <h2 className="text-base font-bold tracking-tight text-zinc-100 sm:text-lg">Remediation</h2>
          </div>
          <p className="text-xs text-zinc-400">
            Patch candidates generated by model providers for SAST findings. Every candidate is unverified model output
            and none has been verified by Sentra.
          </p>
          {patches.data && (
            <p className="text-[11px] text-zinc-500">
              {all.length} candidate{all.length === 1 ? '' : 's'} · {counts.byState.proposed} proposed ·{' '}
              {counts.byState.applied} applied · {counts.byState.rolled_back} rolled back · {counts.pullRequests} with a
              pull request
            </p>
          )}
        </div>
        <Button variant="outline" size="sm" onClick={patches.reload} disabled={patches.loading}>
          <RotateCw className={cn(patches.loading && 'animate-spin')} /> Refresh
        </Button>
      </div>

      {patches.loading && !patches.data ? (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
          <Skeleton className="h-64 bg-zinc-800/50" />
          <Skeleton className="h-64 bg-zinc-800/50" />
        </div>
      ) : patches.error ? (
        <ErrorAlert error={patches.error} title="Could not load patch candidates" onRetry={patches.reload} />
      ) : all.length === 0 ? (
        <Card className="border-zinc-800/80 bg-zinc-900/40">
          <CardContent>
            <Empty className="py-10">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <Wrench />
                </EmptyMedia>
                <EmptyTitle>No patch candidates yet</EmptyTitle>
                <EmptyDescription>
                  Candidates are generated from an open SAST finding in Findings, using a configured AI provider.
                  {!can('ai:generate') && ` ${permissionRequirement('ai:generate')}.`}
                </EmptyDescription>
              </EmptyHeader>
              <EmptyContent>
                <Button size="sm" variant="outline" onClick={() => navigate('findings')}>
                  Open Findings <ArrowRight />
                </Button>
              </EmptyContent>
            </Empty>
          </CardContent>
        </Card>
      ) : (
        <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
          <Card className="gap-0 border-zinc-800/80 bg-zinc-900/40 py-0">
            <CardHeader className="border-b border-zinc-800/80 bg-zinc-950/40 px-3 py-2">
              <div className="flex flex-wrap gap-1">
                {STATE_FILTERS.map((filter) => (
                  <button
                    key={filter}
                    type="button"
                    onClick={() => setStateFilter(filter)}
                    aria-pressed={stateFilter === filter}
                    className={cn(
                      'rounded-md px-2 py-0.5 text-[11px] transition-colors',
                      stateFilter === filter ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300',
                    )}
                  >
                    {filter === 'all' ? `All (${all.length})` : `${PATCH_STATE_LABEL[filter]} (${counts.byState[filter]})`}
                  </button>
                ))}
              </div>
            </CardHeader>
            <CardContent className="max-h-[70vh] overflow-y-auto p-0">
              {visible.length === 0 ? (
                <p className="p-4 text-center text-xs text-zinc-500">No candidates in this state.</p>
              ) : (
                visible.map((patch) => (
                  <PatchListItem
                    key={patch.bundleId}
                    patch={patch}
                    selected={selected?.bundleId === patch.bundleId}
                    onSelect={() => setSelectedId(patch.bundleId)}
                  />
                ))
              )}
            </CardContent>
          </Card>

          {selected && (
            <Card className="gap-0 border-zinc-800/80 bg-zinc-900/40 py-0">
              <CardHeader className="flex flex-col gap-2 border-b border-zinc-800/80 bg-zinc-950/40 px-4 py-3">
                <div className="flex flex-wrap items-center gap-1.5">
                  <UnverifiedModelBadge />
                  <Badge variant="outline" className="border-zinc-800 font-mono text-[10px] text-zinc-500">
                    {selected.bundleId}
                  </Badge>
                </div>
                <CardTitle className="text-sm font-semibold text-zinc-100">{selected.title}</CardTitle>
                <div className="flex flex-wrap items-center gap-2 text-[11px] text-zinc-400">
                  <span>
                    Finding <span className="font-mono text-zinc-300">{selected.findingId}</span>
                  </span>
                  <Button
                    variant="ghost"
                    size="xs"
                    onClick={() => navigate('findings', { findingId: selected.findingId })}
                  >
                    View finding <ArrowRight />
                  </Button>
                </div>
                <PatchActions key={selected.bundleId} patch={selected} onUpdated={replacePatch} />
              </CardHeader>
              <CardContent className="p-4">
                <PatchDetails patch={selected} />
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}
