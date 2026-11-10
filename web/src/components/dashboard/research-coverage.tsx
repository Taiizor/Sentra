import { useMemo, useState } from 'react'
import { CheckCircle2, ClipboardList, Loader2, Pencil, Plus, Search, ShieldCheck, Trash2, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import { cn } from '@/lib/utils'
import type { CoverageStatus, CoverageUnitView, CoverageValidationView, TenantView } from '@/types/api'
import { formatDateTime, permissionHint } from './console-format'
import { ConfirmDialog, EmptyBlock, ErrorAlert, GatedButton, LoadingBlock, SectionCard } from './console-kit'
import { CoverageUnitDialog } from './research-coverage-form'
import { COVERAGE_STATUSES } from './research-coverage-id'

const STATUS_CLASS: Record<CoverageStatus, string> = {
  planned: 'border-zinc-600 text-zinc-300',
  candidate: 'border-amber-500/40 text-amber-300',
  covered: 'border-emerald-500/40 text-emerald-300',
  needs_validation: 'border-sky-500/40 text-sky-300',
  deferred: 'border-zinc-700 text-zinc-500',
  blocked: 'border-rose-500/40 text-rose-300',
  out_of_scope: 'border-zinc-700 text-zinc-500',
}

const ALL = 'all'

/** Operator-maintained coverage ledger for the workspace, with server-side structural validation. */
export function CoverageLedger({ tenant }: { tenant: TenantView }) {
  const { can, invalidate } = useConsole()
  const coverage = useResource(`coverage:${tenant.tenantId}`, (signal) => api.research.coverage(tenant.tenantId, signal))
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<CoverageStatus | typeof ALL>(ALL)
  const [editor, setEditor] = useState<{ unit: CoverageUnitView | null; nonce: number } | null>(null)
  const [deleting, setDeleting] = useState<CoverageUnitView | null>(null)
  const [deleteBusy, setDeleteBusy] = useState(false)
  const [validating, setValidating] = useState(false)
  const [validation, setValidation] = useState<CoverageValidationView | null>(null)
  const [validationError, setValidationError] = useState<unknown>(null)

  const units = useMemo(() => coverage.data?.units ?? [], [coverage.data])
  const counts = useMemo(() => {
    const result = new Map<CoverageStatus, number>()
    for (const unit of units) result.set(unit.status, (result.get(unit.status) ?? 0) + 1)
    return result
  }, [units])
  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase()
    return units.filter((unit) => {
      if (statusFilter !== ALL && unit.status !== statusFilter) return false
      if (!needle) return true
      return [unit.coverageId, unit.surface, unit.boundary, unit.subsystem, unit.attackClass, unit.owner ?? '']
        .join('\n')
        .toLowerCase()
        .includes(needle)
    })
  }, [units, search, statusFilter])

  const canWrite = can('research:write')

  const validate = async () => {
    setValidating(true)
    setValidationError(null)
    try {
      setValidation(await api.research.validate(tenant.tenantId))
    } catch (failure) {
      setValidation(null)
      setValidationError(failure)
    } finally {
      setValidating(false)
    }
  }

  const confirmDelete = async () => {
    if (!deleting) return
    setDeleteBusy(true)
    try {
      await api.research.deleteUnit(tenant.tenantId, deleting.coverageId)
      toast.success('Coverage unit deleted')
      coverage.setData((current) => ({ units: (current?.units ?? []).filter((unit) => unit.coverageId !== deleting.coverageId) }))
      setDeleting(null)
      setValidation(null)
      invalidate()
    } catch (failure) {
      toast.error(failure instanceof Error ? failure.message : String(failure))
    } finally {
      setDeleteBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <SectionCard
        icon={<ClipboardList className="size-4 text-sky-400" />}
        title={`Coverage ledger${coverage.data ? ` (${units.length} units)` : ''}`}
        description="What has been reviewed, recorded by operators per surface, trust boundary, subsystem and attack class. Entries are claims, not evidence."
        actions={
          <>
            <GatedButton permission="read" variant="outline" size="sm" disabled={validating || units.length === 0} onClick={() => void validate()}>
              {validating ? <Loader2 className="animate-spin" /> : <ShieldCheck />}
              Validate
            </GatedButton>
            <GatedButton permission="research:write" size="sm" onClick={() => setEditor({ unit: null, nonce: Date.now() })}>
              <Plus />
              Add unit
            </GatedButton>
          </>
        }
      >
        {coverage.error ? (
          <ErrorAlert error={coverage.error} onRetry={coverage.reload} title="Could not load the coverage ledger" />
        ) : !coverage.data ? (
          <LoadingBlock rows={4} />
        ) : units.length === 0 ? (
          <EmptyBlock icon={<ClipboardList />} title="The coverage ledger is empty">
            No coverage unit has been recorded for this workspace.{' '}
            {canWrite ? 'Add the first unit to start tracking review coverage.' : permissionHint('research:write') + ' to add units.'}
          </EmptyBlock>
        ) : (
          <>
            <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
              <div className="flex flex-wrap items-center gap-1">
                {[ALL, ...COVERAGE_STATUSES].map((value) => {
                  const count = value === ALL ? units.length : (counts.get(value as CoverageStatus) ?? 0)
                  if (value !== ALL && count === 0) return null
                  return (
                    <button
                      key={value}
                      type="button"
                      onClick={() => setStatusFilter(value as CoverageStatus | typeof ALL)}
                      className={cn(
                        'h-6 rounded-md px-2 font-mono text-[11px] transition-colors',
                        statusFilter === value ? 'bg-primary text-primary-foreground' : 'text-zinc-400 hover:bg-muted hover:text-zinc-100',
                      )}
                    >
                      {value} {count}
                    </button>
                  )
                })}
              </div>
              <div className="relative w-full max-w-xs">
                <Search className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-zinc-500" />
                <Input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Filter units"
                  className="h-7 pl-7 text-xs"
                  aria-label="Filter coverage units"
                />
              </div>
            </div>
            {filtered.length === 0 ? (
              <p className="py-4 text-center text-xs text-muted-foreground">No unit matches the current filter.</p>
            ) : (
              <Table className="text-xs">
                <TableHeader>
                  <TableRow>
                    <TableHead>Surface / boundary</TableHead>
                    <TableHead>Subsystem / attack class</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Wave</TableHead>
                    <TableHead>Owner</TableHead>
                    <TableHead className="text-right">Paths / checks / results</TableHead>
                    <TableHead>Updated</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map((unit) => (
                    <TableRow key={unit.coverageId}>
                      <TableCell className="max-w-72 whitespace-normal">
                        <div className="break-all font-mono text-[11px] text-zinc-100">{unit.surface}</div>
                        <div className="break-all font-mono text-[10px] text-zinc-500">{unit.boundary}</div>
                      </TableCell>
                      <TableCell className="max-w-64 whitespace-normal">
                        <div className="break-all font-mono text-[11px] text-zinc-300">{unit.subsystem}</div>
                        <div className="break-all text-[11px] text-zinc-400">{unit.attackClass}</div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={cn('font-mono text-[10px]', STATUS_CLASS[unit.status])}>
                          {unit.status}
                        </Badge>
                        {unit.unresolved && (
                          <div className="mt-0.5 max-w-48 truncate text-[10px] text-amber-300" title={unit.unresolved}>
                            {unit.unresolved}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-right font-mono">{unit.wave}</TableCell>
                      <TableCell className="text-[11px]">{unit.owner ?? <span className="text-zinc-600">none</span>}</TableCell>
                      <TableCell
                        className="text-right font-mono text-[11px]"
                        title={[...unit.reviewedPaths, ...unit.localChecks, ...unit.resultFingerprints].join('\n') || undefined}
                      >
                        {unit.reviewedPaths.length} / {unit.localChecks.length} / {unit.resultFingerprints.length}
                      </TableCell>
                      <TableCell className="text-[11px] text-zinc-400">
                        {formatDateTime(unit.updatedAt)}
                        <div className="text-[10px] text-zinc-600">{unit.updatedBy}</div>
                      </TableCell>
                      <TableCell className="text-right">
                        {canWrite && (
                          <div className="flex justify-end gap-1">
                            <Button
                              variant="ghost"
                              size="icon-xs"
                              aria-label="Edit unit"
                              onClick={() => setEditor({ unit, nonce: Date.now() })}
                            >
                              <Pencil />
                            </Button>
                            <Button variant="ghost" size="icon-xs" aria-label="Delete unit" onClick={() => setDeleting(unit)}>
                              <Trash2 className="text-rose-400" />
                            </Button>
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </>
        )}
      </SectionCard>

      {validationError !== null && <ErrorAlert error={validationError} title="Validation could not run" />}
      {validation && <ValidationResult validation={validation} />}

      {editor && (
        <CoverageUnitDialog
          key={editor.nonce}
          tenant={tenant}
          unit={editor.unit}
          open
          onOpenChange={(open) => !open && setEditor(null)}
          onSaved={(saved) => {
            coverage.setData((current) => {
              const others = (current?.units ?? []).filter((unit) => unit.coverageId !== saved.coverageId)
              return { units: [...others, saved].sort((a, b) => (a.coverageId < b.coverageId ? -1 : 1)) }
            })
            setValidation(null)
            invalidate()
          }}
        />
      )}

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        title="Delete coverage unit?"
        description={
          <>
            <p>This permanently removes the ledger entry below from this workspace's coverage ledger. Findings are not affected.</p>
            <code className="block break-all rounded bg-zinc-950 p-2 font-mono text-[11px] text-zinc-300">{deleting?.coverageId}</code>
          </>
        }
        confirmLabel="Delete unit"
        destructive
        busy={deleteBusy}
        onConfirm={() => void confirmDelete()}
      />
    </div>
  )
}

function ValidationResult({ validation }: { validation: CoverageValidationView }) {
  const grouped = useMemo(() => {
    const groups = new Map<string, CoverageValidationView['errors']>()
    for (const error of validation.errors) {
      const list = groups.get(error.coverageId) ?? []
      list.push(error)
      groups.set(error.coverageId, list)
    }
    return [...groups.entries()]
  }, [validation])

  return (
    <SectionCard
      icon={
        validation.valid ? <CheckCircle2 className="size-4 text-emerald-400" /> : <XCircle className="size-4 text-rose-400" />
      }
      title={
        validation.valid
          ? `No rule violations in ${validation.checkedUnits} unit(s)`
          : `${validation.errors.length} rule violation(s) in ${grouped.length} of ${validation.checkedUnits} unit(s)`
      }
      description={`Structural validation by the bridge at ${formatDateTime(validation.validatedAt)}. It checks the ledger entries for consistency; it does not show that the coverage was achieved.`}
    >
      {grouped.length > 0 && (
        <ul className="flex flex-col gap-2">
          {grouped.map(([coverageId, errors]) => (
            <li key={coverageId} className="rounded-md border border-rose-500/20 bg-rose-500/5 p-2">
              <code className="block break-all font-mono text-[11px] text-zinc-200">{coverageId || '(ledger)'}</code>
              <ul className="mt-1 flex flex-col gap-0.5">
                {errors.map((error, index) => (
                  <li key={`${error.rule}-${index}`} className="text-[11px] text-rose-200">
                    <span className="font-mono text-rose-300">{error.rule}</span>: {error.message}
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      )}
    </SectionCard>
  )
}
