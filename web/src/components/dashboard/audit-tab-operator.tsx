import { Fragment, useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, CircleAlert, CircleCheck, LoaderCircle, Search, ShieldCheck, X } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { DisabledReason } from '@/components/layout/disabled-reason'
import { permissionHint } from '@/components/layout/permission-hint'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import type { AuditLogEntryView, AuditLogPage, AuditVerificationView } from '@/types/api'
import { CopyValueButton, JsonBlock, OutcomeBadge } from './audit-tab-parts'
import { formatDateTime, shortHash } from './overview-tab-format'
import { LoadError } from './overview-tab-parts'

const PAGE_SIZE = 100
type OutcomeFilter = 'all' | AuditLogEntryView['outcome']

interface OlderPages {
  /** The first page these older pages were loaded after; a refetch of page one invalidates them. */
  base: AuditLogPage
  entries: AuditLogEntryView[]
  nextBefore: number | null
}

/** What the head checkpoint contributed to a successful verification. */
function checkpointNote(result: AuditVerificationView): string {
  if (result.checkpointSeq === null) {
    return 'No head checkpoint was stored when this ran, so removal of the newest entries could not be checked. The bridge starts a checkpoint with the next entry it appends.'
  }
  return `The newest entry matches the head checkpoint (#${result.checkpointSeq}). Removal of newer entries would have been reported, unless the checkpoint was also deleted or replaced with an earlier copy.`
}

function VerificationResult({ result }: { result: AuditVerificationView }) {
  if (result.valid) {
    return (
      <Alert className="border-emerald-500/40 bg-emerald-500/5 text-emerald-200">
        <CircleCheck />
        <AlertTitle className="text-xs">Chain verified by the bridge</AlertTitle>
        <AlertDescription className="text-xs text-emerald-200/80 flex flex-col gap-1">
          <span>
            {result.checkedEntries.toLocaleString()} entries recomputed at {formatDateTime(result.verifiedAt)}; no break found.
          </span>
          <span>{checkpointNote(result)}</span>
          <span className="flex items-center gap-1 font-mono text-[11px] break-all">
            head {result.headHash}
            <CopyValueButton value={result.headHash} label="head hash" />
          </span>
          <span className="text-emerald-200/70">
            {result.checkedEntries > 0
              ? `To check later what the checkpoint cannot, record this head hash as the hash of entry #${result.checkedEntries} outside the bridge and confirm that the entry still carries it.`
              : 'The log held no entries when it was checked.'}
          </span>
          <span className="text-emerald-200/70">Limits stated by the bridge: {result.limitation}</span>
        </AlertDescription>
      </Alert>
    )
  }
  return (
    <Alert variant="destructive" className="border-rose-500/40 bg-rose-500/5">
      <CircleAlert />
      <AlertTitle className="text-xs">Chain verification failed</AlertTitle>
      <AlertDescription className="text-xs flex flex-col gap-1">
        <span>
          First invalid entry: {result.firstInvalidSeq !== null ? `#${result.firstInvalidSeq}` : 'unknown'} · checked{' '}
          {result.checkedEntries.toLocaleString()} entries at {formatDateTime(result.verifiedAt)}
        </span>
        {result.reason && <span className="break-words">{result.reason}</span>}
        <span>
          Head checkpoint: {result.checkpointSeq !== null ? `#${result.checkpointSeq}` : 'none stored, or it failed its MAC check'}
        </span>
        <span className="font-mono text-[11px] break-all">head {result.headHash}</span>
        <span className="text-[11px] opacity-80">Limits stated by the bridge: {result.limitation}</span>
      </AlertDescription>
    </Alert>
  )
}

export function OperatorAuditChain() {
  const { tenant, can } = useConsole()
  const [scope, setScope] = useState<'tenant' | 'all'>(tenant ? 'tenant' : 'all')
  const filterTenant = scope === 'tenant' && tenant ? tenant.tenantId : null

  const first = useResource(`audit-log:${filterTenant ?? '*'}`, (signal) => api.audit.log({ tenant: filterTenant, limit: PAGE_SIZE }, signal))
  const [older, setOlder] = useState<OlderPages | null>(null)
  const [loadingOlder, setLoadingOlder] = useState(false)
  const [olderError, setOlderError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set())
  const [search, setSearch] = useState('')
  const [outcome, setOutcome] = useState<OutcomeFilter>('all')
  const [verification, setVerification] = useState<AuditVerificationView | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [verifyError, setVerifyError] = useState<string | null>(null)

  const olderPages = older && first.data && older.base === first.data ? older : null
  const entries = useMemo(
    () => (first.data ? [...first.data.entries, ...(olderPages?.entries ?? [])] : []),
    [first.data, olderPages],
  )
  const nextBefore = olderPages ? olderPages.nextBefore : (first.data?.nextBefore ?? null)

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    return entries.filter((entry) => {
      if (outcome !== 'all' && entry.outcome !== outcome) return false
      if (!query) return true
      return [entry.action, entry.actor, entry.role, entry.target ?? '', entry.tenantId ?? '', String(entry.seq)].some((field) =>
        field.toLowerCase().includes(query),
      )
    })
  }, [entries, search, outcome])

  async function loadOlder() {
    const base = first.data
    if (!base || nextBefore === null || loadingOlder) return
    setLoadingOlder(true)
    setOlderError(null)
    try {
      const page = await api.audit.log({ tenant: filterTenant, limit: PAGE_SIZE, before: nextBefore })
      setOlder((current) => ({
        base,
        entries: [...(current && current.base === base ? current.entries : []), ...page.entries],
        nextBefore: page.nextBefore,
      }))
    } catch (error) {
      setOlderError(errorMessage(error))
    } finally {
      setLoadingOlder(false)
    }
  }

  async function verifyChain() {
    setVerifying(true)
    setVerifyError(null)
    try {
      setVerification(await api.audit.verify())
      // Verification itself appends an `audit_chain_verified` entry.
      first.reload()
    } catch (error) {
      setVerifyError(errorMessage(error))
    } finally {
      setVerifying(false)
    }
  }

  function toggle(seq: number) {
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(seq)) next.delete(seq)
      else next.add(seq)
      return next
    })
  }

  return (
    <div className="flex flex-col gap-4">
      <Card className="border-zinc-800/80 bg-zinc-900/40">
        <CardHeader className="pt-4 pb-2 px-4 sm:px-5">
          <div className="flex flex-col md:flex-row md:items-start justify-between gap-3">
            <div className="flex flex-col gap-1">
              <CardTitle className="text-sm font-semibold">Operator audit chain</CardTitle>
              <CardDescription className="text-xs text-zinc-400 max-w-3xl">
                Actions recorded by the console bridge, such as sign-ins, workspace registration, state-changing requests and
                denied requests. Each entry stores an HMAC-SHA256 over the previous entry's hash and its own content, keyed
                with the bridge secret, and every new entry also advances a MAC-protected head checkpoint kept in the bridge
                database. "Verify chain" recomputes the chain on the server from the first entry to the newest stored one and
                compares its end with that checkpoint. It detects edited, reordered or removed entries, including removal of the
                newest entries (or of all of them) while the checkpoint is still in place. It cannot detect removal of the newest
                entries when the checkpoint is also deleted or replaced with an earlier copy, a rollback of the whole database,
                or changes made by someone holding the bridge secret: for those, compare the head hash and entry count with
                values you recorded outside the bridge.
              </CardDescription>
            </div>
            <DisabledReason reason={can('audit:verify') ? null : permissionHint('audit:verify')}>
              <Button
                size="sm"
                variant="outline"
                onClick={() => void verifyChain()}
                disabled={!can('audit:verify') || verifying}
                className="h-8 text-xs border-zinc-700 shrink-0"
              >
                {verifying ? <LoaderCircle className="size-3.5 animate-spin" /> : <ShieldCheck className="size-3.5" />}
                {verifying ? 'Verifying…' : 'Verify chain'}
              </Button>
            </DisabledReason>
          </div>
        </CardHeader>
        <CardContent className="px-4 sm:px-5 pb-4 flex flex-col gap-3">
          {verifyError && (
            <Alert variant="destructive" className="border-rose-500/40 bg-rose-500/5">
              <CircleAlert />
              <AlertTitle className="text-xs">Verification request failed</AlertTitle>
              <AlertDescription className="text-xs break-words">{verifyError}</AlertDescription>
            </Alert>
          )}
          {verification && <VerificationResult result={verification} />}

          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-1.5">
              {tenant && (
                <div className="flex rounded-md border border-zinc-800 p-0.5 text-[11px]">
                  {(['tenant', 'all'] as const).map((value) => (
                    <button
                      key={value}
                      type="button"
                      onClick={() => setScope(value)}
                      className={`px-2 py-1 rounded ${scope === value ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'}`}
                    >
                      {value === 'tenant' ? tenant.name : 'All entries'}
                    </button>
                  ))}
                </div>
              )}
              <div className="flex rounded-md border border-zinc-800 p-0.5 text-[11px]">
                {(['all', 'success', 'failure', 'denied'] as const).map((value) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => setOutcome(value)}
                    className={`px-2 py-1 rounded capitalize ${outcome === value ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'}`}
                  >
                    {value}
                  </button>
                ))}
              </div>
            </div>
            <div className="relative w-full lg:w-72">
              <Search className="size-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none" />
              <Input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Filter loaded entries"
                className="pl-8 pr-7 h-8 text-xs bg-zinc-950/60 border-zinc-800"
              />
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch('')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-200"
                  aria-label="Clear filter"
                >
                  <X className="size-3" />
                </button>
              )}
            </div>
          </div>

          {first.error ? (
            <LoadError title="Audit log unavailable" error={first.error} onRetry={first.reload} />
          ) : !first.data ? (
            <Skeleton className="h-48 w-full bg-zinc-900" />
          ) : (
            <>
              <p className="text-[11px] text-zinc-500">
                {filtered.length} shown · {entries.length} loaded · {first.data.total.toLocaleString()} total
                {filterTenant ? ` for ${filterTenant}` : ''}
              </p>
              {entries.length === 0 ? (
                <p className="text-xs text-zinc-500 py-8 text-center">
                  {filterTenant ? 'No audit entries reference this workspace yet.' : 'The audit log is empty.'}
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-6" />
                        <TableHead className="text-xs">Seq</TableHead>
                        <TableHead className="text-xs">Time</TableHead>
                        <TableHead className="text-xs">Actor</TableHead>
                        <TableHead className="text-xs">Action</TableHead>
                        <TableHead className="text-xs">Target</TableHead>
                        <TableHead className="text-xs">Outcome</TableHead>
                        <TableHead className="text-xs">Hash</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filtered.map((entry) => {
                        const open = expanded.has(entry.seq)
                        return (
                          <Fragment key={entry.seq}>
                            <TableRow className="cursor-pointer hover:bg-zinc-900/60" onClick={() => toggle(entry.seq)}>
                              <TableCell className="py-2">
                                <button
                                  type="button"
                                  aria-expanded={open}
                                  aria-label={open ? 'Collapse entry' : 'Expand entry'}
                                  className="text-zinc-500"
                                  onClick={(event) => {
                                    event.stopPropagation()
                                    toggle(entry.seq)
                                  }}
                                >
                                  {open ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
                                </button>
                              </TableCell>
                              <TableCell className="font-mono text-[11px] text-zinc-400">#{entry.seq}</TableCell>
                              <TableCell className="font-mono text-[11px] whitespace-nowrap">{formatDateTime(entry.ts)}</TableCell>
                              <TableCell className="text-[11px] whitespace-nowrap">
                                <span className="font-mono text-zinc-200">{entry.actor}</span>{' '}
                                <span className="text-zinc-500">{entry.role}</span>
                              </TableCell>
                              <TableCell className="font-mono text-[11px] text-zinc-200">{entry.action}</TableCell>
                              <TableCell className="text-[11px] text-zinc-400 max-w-[260px] truncate" title={entry.target ?? undefined}>
                                {entry.tenantId && <span className="font-mono text-zinc-500">{entry.tenantId} · </span>}
                                {entry.target ?? '—'}
                              </TableCell>
                              <TableCell>
                                <OutcomeBadge outcome={entry.outcome} />
                              </TableCell>
                              <TableCell className="font-mono text-[11px] text-zinc-500" title={entry.hash}>
                                {shortHash(entry.hash)}
                              </TableCell>
                            </TableRow>
                            {open && (
                              <TableRow className="hover:bg-transparent">
                                <TableCell colSpan={8} className="bg-zinc-950/40 py-3">
                                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                                    <div className="flex flex-col gap-1">
                                      <span className="text-[11px] text-zinc-500">Details</span>
                                      <JsonBlock value={entry.details} />
                                    </div>
                                    <div className="flex flex-col gap-2 text-[11px]">
                                      <div className="flex flex-col gap-0.5">
                                        <span className="text-zinc-500">Previous hash</span>
                                        <span className="flex items-start gap-1 font-mono text-zinc-300 break-all">
                                          {entry.prevHash}
                                          <CopyValueButton value={entry.prevHash} label="previous hash" />
                                        </span>
                                      </div>
                                      <div className="flex flex-col gap-0.5">
                                        <span className="text-zinc-500">Entry hash (HMAC)</span>
                                        <span className="flex items-start gap-1 font-mono text-zinc-300 break-all">
                                          {entry.hash}
                                          <CopyValueButton value={entry.hash} label="entry hash" />
                                        </span>
                                      </div>
                                    </div>
                                  </div>
                                </TableCell>
                              </TableRow>
                            )}
                          </Fragment>
                        )
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}
              {olderError && <p className="text-xs text-rose-300 break-words">Could not load older entries: {olderError}</p>}
              {nextBefore !== null && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => void loadOlder()}
                  disabled={loadingOlder}
                  className="self-center h-8 text-xs border-zinc-800"
                >
                  {loadingOlder && <LoaderCircle className="size-3.5 animate-spin" />}
                  Load older entries
                </Button>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
