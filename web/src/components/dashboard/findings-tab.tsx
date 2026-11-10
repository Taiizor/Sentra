import { useMemo, useState } from 'react'
import { cn } from 'cn'
import {
  ArrowDown,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  Download,
  FolderSearch,
  Loader2,
  RotateCw,
  Search,
  ShieldAlert,
} from 'lucide-react'
import { toast } from 'sonner'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { AiPatchModal } from '@/components/dashboard/ai-patch-modal'
import { FindingDetail } from '@/components/dashboard/findings-detail'
import { findingLocation, formatTimestamp, SEVERITY_RANK } from '@/components/dashboard/findings-format'
import { ErrorAlert, SeverityBadge, Timestamp, TriageBadge } from '@/components/dashboard/findings-shared'
import { SEVERITIES, type FindingSource, type FindingState, type FindingView, type ScanRunView, type Severity } from '@/types/api'

type StateFilter = FindingState | 'all'
type SourceFilter = FindingSource | 'all'
type SeverityFilter = Severity | 'all'
type SortField = 'severity' | 'rule' | 'location' | 'lastSeen'

const PAGE_SIZE = 25

const STATE_OPTIONS: { id: StateFilter; label: string }[] = [
  { id: 'open', label: 'Open' },
  { id: 'resolved', label: 'Resolved' },
  { id: 'all', label: 'All' },
]

const SOURCE_LABEL: Record<SourceFilter, string> = { all: 'All sources', sast: 'SAST', dependency: 'Dependencies' }

function matchesSearch(finding: FindingView, query: string): boolean {
  if (!query) return true
  const haystack = [
    finding.ruleId,
    finding.ruleName,
    finding.cwe,
    finding.category,
    finding.filePath,
    finding.dependency?.packageName,
    finding.dependency?.advisoryId,
    ...(finding.dependency?.aliases ?? []),
  ]
  return haystack.some((value) => value?.toLowerCase().includes(query))
}

function compareFindings(a: FindingView, b: FindingView, field: SortField): number {
  switch (field) {
    case 'severity':
      return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
    case 'rule':
      return a.ruleId.localeCompare(b.ruleId)
    case 'location':
      return findingLocation(a).localeCompare(findingLocation(b), undefined, { numeric: true })
    case 'lastSeen':
      return Date.parse(a.lastSeenAt) - Date.parse(b.lastSeenAt)
  }
}

async function downloadSarif(tenantId: string): Promise<void> {
  const document_ = await api.findings.sarif(tenantId)
  const blob = new Blob([JSON.stringify(document_, null, 2)], { type: 'application/sarif+json' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `sentra-${tenantId}-open-findings.sarif`
  anchor.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function describeRun(run: ScanRunView): string {
  return `${formatTimestamp(run.finishedAt ?? run.startedAt)} · ${run.kind} · ${run.status}`
}

function SortHead({
  field,
  label,
  sort,
  onToggle,
  className,
}: {
  field: SortField
  label: string
  sort: { field: SortField; desc: boolean }
  onToggle: (field: SortField) => void
  className?: string
}) {
  const active = sort.field === field
  return (
    <TableHead className={cn('select-none text-xs font-semibold text-zinc-300', className)} aria-sort={active ? (sort.desc ? 'descending' : 'ascending') : undefined}>
      <button type="button" className="inline-flex items-center gap-1 hover:text-zinc-100" onClick={() => onToggle(field)}>
        {label}
        {active && (sort.desc ? <ArrowDown className="size-3" /> : <ArrowUp className="size-3" />)}
      </button>
    </TableHead>
  )
}

export function FindingsTab() {
  const { tenant } = useConsole()
  if (!tenant) {
    return (
      <Empty className="border border-zinc-800 py-16">
        <EmptyHeader>
          <EmptyMedia variant="icon">
            <FolderSearch />
          </EmptyMedia>
          <EmptyTitle>No workspace selected</EmptyTitle>
          <EmptyDescription>Findings are recorded per workspace. Register or select a workspace first.</EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }
  return <FindingsWorkspace key={tenant.tenantId} tenantId={tenant.tenantId} />
}

function FindingsWorkspace({ tenantId }: { tenantId: string }) {
  const { can, navigate, selectedFindingId, setSelectedFindingId } = useConsole()
  const [stateFilter, setStateFilter] = useState<StateFilter>('open')
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>('all')
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all')
  const [search, setSearch] = useState('')
  const [sort, setSort] = useState<{ field: SortField; desc: boolean }>({ field: 'severity', desc: true })
  const [pageState, setPageState] = useState<{ filterKey: string; page: number }>({ filterKey: '', page: 0 })
  const [patchTarget, setPatchTarget] = useState<FindingView | null>(null)
  const [exporting, setExporting] = useState(false)

  const filter = {
    state: stateFilter,
    source: sourceFilter === 'all' ? undefined : sourceFilter,
    severity: severityFilter === 'all' ? undefined : severityFilter,
  }
  const list = useResource(`findings:${tenantId}:${stateFilter}:${sourceFilter}:${severityFilter}`, (signal) =>
    api.findings.list(tenantId, filter, signal),
  )
  const scans = useResource(`scans:${tenantId}:recent`, (signal) => api.scans.list(tenantId, 20, signal))

  const query = search.trim().toLowerCase()
  const findings = list.data?.findings
  const visible = useMemo(() => {
    const matched = (findings ?? []).filter((finding) => matchesSearch(finding, query))
    return matched.sort((a, b) => {
      const primary = compareFindings(a, b, sort.field)
      if (primary !== 0) return sort.desc ? -primary : primary
      return findingLocation(a).localeCompare(findingLocation(b), undefined, { numeric: true })
    })
  }, [findings, query, sort])

  const counts = useMemo(() => {
    const bySeverity = new Map<Severity, number>()
    let untriaged = 0
    for (const finding of findings ?? []) {
      bySeverity.set(finding.severity, (bySeverity.get(finding.severity) ?? 0) + 1)
      if (!finding.triage) untriaged += 1
    }
    return { bySeverity, untriaged }
  }, [findings])

  // Any filter or search change returns to the first page.
  const filterKey = `${stateFilter}|${sourceFilter}|${severityFilter}|${query}`
  const page = pageState.filterKey === filterKey ? pageState.page : 0
  const setPage = (next: number) => setPageState({ filterKey, page: next })
  const pageCount = Math.max(1, Math.ceil(visible.length / PAGE_SIZE))
  const currentPage = Math.min(page, pageCount - 1)
  const pageRows = visible.slice(currentPage * PAGE_SIZE, currentPage * PAGE_SIZE + PAGE_SIZE)

  // Selected finding: prefer the fresh server copy; the list row fills in while it loads.
  const listSelection = selectedFindingId ? (findings ?? []).find((finding) => finding.findingId === selectedFindingId) : undefined
  const detail = useResource(selectedFindingId ? `finding:${tenantId}:${selectedFindingId}` : null, (signal) =>
    api.findings.get(tenantId, selectedFindingId as string, signal),
  )
  const selected = detail.data ?? listSelection ?? null

  const runs = useMemo(
    () => [...(scans.data?.runs ?? [])].sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt)),
    [scans.data],
  )
  const lastRun = runs[0] ?? null
  const lastCompleted = runs.find((run) => run.status === 'completed') ?? null
  const filtersActive = sourceFilter !== 'all' || severityFilter !== 'all' || stateFilter !== 'open'

  function toggleSort(field: SortField) {
    setSort((current) => (current.field === field ? { field, desc: !current.desc } : { field, desc: field !== 'rule' && field !== 'location' }))
  }

  async function handleExport() {
    setExporting(true)
    try {
      await downloadSarif(tenantId)
    } catch (error) {
      toast.error('SARIF export failed', { description: errorMessage(error) })
    } finally {
      setExporting(false)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex flex-col gap-0.5">
          <h2 className="text-base font-bold tracking-tight text-zinc-100 sm:text-lg">Findings</h2>
          <p className="text-xs text-zinc-400">
            Candidates reported by the SAST scanner and OSV dependency lookups for this workspace. Every entry is an
            unverified candidate; a triage verdict records an operator decision.
          </p>
          <p className="text-[11px] text-zinc-500">
            {scans.loading && !scans.data
              ? 'Loading scan history…'
              : scans.error
                ? `Scan history unavailable: ${errorMessage(scans.error)}`
                : lastRun
                  ? `Last scan: ${describeRun(lastRun)}`
                  : 'No scan has run for this workspace yet.'}
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <Button variant="outline" size="sm" onClick={list.reload} disabled={list.loading}>
            <RotateCw className={cn(list.loading && 'animate-spin')} /> Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={() => void handleExport()} disabled={exporting}>
            {exporting ? <Loader2 className="animate-spin" /> : <Download />} Export SARIF (open findings)
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex overflow-hidden rounded-lg border border-zinc-800">
          {STATE_OPTIONS.map((option) => (
            <button
              key={option.id}
              type="button"
              onClick={() => setStateFilter(option.id)}
              aria-pressed={stateFilter === option.id}
              className={cn(
                'px-2.5 py-1 text-xs transition-colors',
                stateFilter === option.id ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200',
              )}
            >
              {option.label}
            </button>
          ))}
        </div>
        <Select
          value={sourceFilter}
          onValueChange={(value) => {
            if (value === 'all' || value === 'sast' || value === 'dependency') setSourceFilter(value)
          }}
        >
          <SelectTrigger className="h-7.5 w-[140px] border-zinc-800 bg-zinc-950/80 text-xs">
            <SelectValue>{(value: string | null) => SOURCE_LABEL[(value ?? 'all') as SourceFilter] ?? 'All sources'}</SelectValue>
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {(Object.keys(SOURCE_LABEL) as SourceFilter[]).map((id) => (
                <SelectItem key={id} value={id}>
                  {SOURCE_LABEL[id]}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
        <Select
          value={severityFilter}
          onValueChange={(value) => {
            if (value === 'all') setSeverityFilter('all')
            else if (SEVERITIES.some((severity) => severity === value)) setSeverityFilter(value as Severity)
          }}
        >
          <SelectTrigger className="h-7.5 w-[140px] border-zinc-800 bg-zinc-950/80 text-xs">
            <SelectValue>{(value: string | null) => (!value || value === 'all' ? 'All severities' : value)}</SelectValue>
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              <SelectItem value="all">All severities</SelectItem>
              {SEVERITIES.map((severity) => (
                <SelectItem key={severity} value={severity}>
                  {severity}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
        <div className="relative min-w-[220px] flex-1 sm:max-w-sm">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-zinc-500" />
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search rule, CWE, file, package, advisory…"
            className="h-7.5 border-zinc-800 bg-zinc-950/80 pl-8 text-xs"
          />
        </div>
        {(filtersActive || query) && (
          <Button
            variant="ghost"
            size="sm"
            className="text-zinc-400"
            onClick={() => {
              setStateFilter('open')
              setSourceFilter('all')
              setSeverityFilter('all')
              setSearch('')
            }}
          >
            Reset filters
          </Button>
        )}
      </div>

      <Card className="gap-0 border-zinc-800/80 bg-zinc-900/40 py-0 shadow-xs">
        <CardHeader className="border-b border-zinc-800/80 bg-zinc-950/40 px-4 py-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <CardTitle className="text-xs font-semibold text-zinc-200">
              {STATE_OPTIONS.find((option) => option.id === stateFilter)?.label} findings
            </CardTitle>
            {findings && (
              <>
                <Badge variant="outline" className="border-zinc-800 font-mono text-[10px] text-zinc-400">
                  {query ? `${visible.length} of ${findings.length}` : findings.length}
                </Badge>
                {SEVERITIES.filter((severity) => counts.bySeverity.get(severity)).map((severity) => (
                  <span key={severity} className="inline-flex items-center gap-1 text-[10px] text-zinc-500">
                    <SeverityBadge severity={severity} className="h-4 px-1.5 text-[9px]" />
                    {counts.bySeverity.get(severity)}
                  </span>
                ))}
                <span className="text-[10px] text-zinc-500">· {counts.untriaged} untriaged</span>
              </>
            )}
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {list.loading && !list.data ? (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 6 }, (_, index) => (
                <Skeleton key={index} className="h-7 w-full bg-zinc-800/50" />
              ))}
            </div>
          ) : list.error ? (
            <div className="p-4">
              <ErrorAlert error={list.error} title="Could not load findings" onRetry={list.reload} />
            </div>
          ) : findings && findings.length === 0 ? (
            <Empty className="py-12">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <ShieldAlert />
                </EmptyMedia>
                {scans.data && runs.length === 0 ? (
                  <>
                    <EmptyTitle>No scan has run for this workspace yet</EmptyTitle>
                    <EmptyDescription>Findings appear here after a scan completes.</EmptyDescription>
                  </>
                ) : filtersActive ? (
                  <>
                    <EmptyTitle>No findings match these filters</EmptyTitle>
                    <EmptyDescription>
                      {lastCompleted ? `Last completed scan: ${describeRun(lastCompleted)}.` : 'No scan has completed yet.'}
                    </EmptyDescription>
                  </>
                ) : (
                  <>
                    <EmptyTitle>No open findings</EmptyTitle>
                    <EmptyDescription>
                      {lastCompleted
                        ? `No open finding is recorded. Last completed scan: ${describeRun(lastCompleted)}.`
                        : 'No scan has completed for this workspace yet.'}
                    </EmptyDescription>
                  </>
                )}
              </EmptyHeader>
              {scans.data && runs.length === 0 && can('scan:run') && (
                <EmptyContent>
                  <Button size="sm" variant="outline" onClick={() => navigate('overview')}>
                    Go to Overview to run a scan
                  </Button>
                </EmptyContent>
              )}
            </Empty>
          ) : visible.length === 0 ? (
            <Empty className="py-12">
              <EmptyHeader>
                <EmptyTitle>No findings match “{search.trim()}”</EmptyTitle>
                <EmptyDescription>The search covers rule, CWE, category, file, package and advisory IDs.</EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <>
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader className="bg-zinc-950/40">
                    <TableRow className="border-zinc-800/80 hover:bg-transparent">
                      <SortHead field="severity" label="Severity" sort={sort} onToggle={toggleSort} className="w-[110px]" />
                      <SortHead field="rule" label="Rule" sort={sort} onToggle={toggleSort} />
                      <SortHead field="location" label="Location" sort={sort} onToggle={toggleSort} />
                      <TableHead className="w-[100px] text-xs font-semibold text-zinc-300">Source</TableHead>
                      <TableHead className="w-[130px] text-xs font-semibold text-zinc-300">Triage</TableHead>
                      {stateFilter === 'all' && (
                        <TableHead className="w-[90px] text-xs font-semibold text-zinc-300">State</TableHead>
                      )}
                      <SortHead field="lastSeen" label="Last seen" sort={sort} onToggle={toggleSort} className="w-[170px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {pageRows.map((finding) => (
                      <TableRow
                        key={finding.findingId}
                        tabIndex={0}
                        aria-selected={finding.findingId === selectedFindingId}
                        onClick={() => setSelectedFindingId(finding.findingId)}
                        onKeyDown={(event) => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault()
                            setSelectedFindingId(finding.findingId)
                          }
                        }}
                        className={cn(
                          'cursor-pointer border-zinc-800/70 hover:bg-zinc-800/40',
                          finding.findingId === selectedFindingId && 'bg-zinc-800/50',
                        )}
                      >
                        <TableCell>
                          <SeverityBadge severity={finding.severity} />
                        </TableCell>
                        <TableCell className="max-w-[320px] text-xs">
                          <div className="flex flex-col">
                            <span className="truncate font-medium text-zinc-100">{finding.ruleName}</span>
                            <span className="truncate font-mono text-[10px] text-zinc-500">
                              {finding.ruleId}
                              {finding.cwe ? ` · ${finding.cwe}` : ''}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="max-w-[300px] font-mono text-[11px] text-zinc-400">
                          <span className="block truncate" title={findingLocation(finding)}>
                            {findingLocation(finding)}
                          </span>
                        </TableCell>
                        <TableCell className="text-[11px] text-zinc-400">
                          {finding.source === 'sast' ? 'SAST' : 'Dependency'}
                        </TableCell>
                        <TableCell>
                          <TriageBadge triage={finding.triage} />
                        </TableCell>
                        {stateFilter === 'all' && (
                          <TableCell className="text-[11px] text-zinc-400">
                            {finding.state === 'open' ? 'Open' : 'Resolved'}
                          </TableCell>
                        )}
                        <TableCell className="text-[11px] text-zinc-500">
                          <Timestamp value={finding.lastSeenAt} />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              {pageCount > 1 && (
                <div className="flex items-center justify-between border-t border-zinc-800/80 px-4 py-2 text-[11px] text-zinc-500">
                  <span>
                    {currentPage * PAGE_SIZE + 1}–{Math.min(visible.length, (currentPage + 1) * PAGE_SIZE)} of {visible.length}
                  </span>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      disabled={currentPage === 0}
                      onClick={() => setPage(currentPage - 1)}
                      aria-label="Previous page"
                    >
                      <ChevronLeft />
                    </Button>
                    <span>
                      {currentPage + 1} / {pageCount}
                    </span>
                    <Button
                      variant="ghost"
                      size="icon-xs"
                      disabled={currentPage >= pageCount - 1}
                      onClick={() => setPage(currentPage + 1)}
                      aria-label="Next page"
                    >
                      <ChevronRight />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <Sheet
        open={selectedFindingId !== null}
        onOpenChange={(open) => {
          if (open) return
          setSelectedFindingId(null)
          setPatchTarget(null)
        }}
      >
        <SheetContent side="right" className="w-full border-zinc-800 bg-zinc-950 sm:max-w-2xl lg:max-w-3xl">
          <SheetHeader className="border-b border-zinc-800">
            <SheetTitle className="pr-8 text-sm text-zinc-100">{selected ? selected.ruleName : 'Finding'}</SheetTitle>
            <SheetDescription className="font-mono text-[11px] text-zinc-500">
              {selected ? findingLocation(selected) : selectedFindingId}
            </SheetDescription>
          </SheetHeader>
          <div className="flex-1 overflow-y-auto p-4">
            {selected ? (
              <FindingDetail finding={selected} onGeneratePatch={() => setPatchTarget(selected)} />
            ) : detail.error ? (
              <ErrorAlert error={detail.error} title="Could not load this finding" onRetry={detail.reload} />
            ) : (
              <div className="flex flex-col gap-2">
                <Skeleton className="h-5 w-1/3 bg-zinc-800/60" />
                <Skeleton className="h-4 w-2/3 bg-zinc-800/60" />
                <Skeleton className="h-40 w-full bg-zinc-800/60" />
              </div>
            )}
          </div>
          {/* Rendered inside the sheet so it is a nested dialog of the sheet, not an outside press. */}
          {patchTarget && (
            <AiPatchModal
              key={patchTarget.findingId}
              finding={patchTarget}
              open
              onOpenChange={(open) => {
                if (!open) setPatchTarget(null)
              }}
            />
          )}
        </SheetContent>
      </Sheet>
    </div>
  )
}
