import { useState, type ReactNode } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { api } from '@/lib/api'
import type { CoverageStatus, CoverageUnitView, TenantView, UpsertCoverageUnitRequest } from '@/types/api'
import { ErrorAlert } from './console-kit'
import {
  composeCoverageId,
  COVERAGE_MAX_LIST_ITEMS,
  COVERAGE_MAX_STRING,
  COVERAGE_MAX_WAVE,
  COVERAGE_STATUS_RULE,
  COVERAGE_STATUSES,
  segmentProblem,
  splitLines,
} from './research-coverage-id'

/** Create (unit = null) or edit a coverage ledger unit. Identity segments are fixed when editing. */
export function CoverageUnitDialog({
  tenant,
  unit,
  open,
  onOpenChange,
  onSaved,
}: {
  tenant: TenantView
  unit: CoverageUnitView | null
  open: boolean
  onOpenChange: (open: boolean) => void
  onSaved: (unit: CoverageUnitView) => void
}) {
  const editing = unit !== null
  const [surface, setSurface] = useState(unit?.surface ?? '')
  const [boundary, setBoundary] = useState(unit?.boundary ?? '')
  const [subsystem, setSubsystem] = useState(unit?.subsystem ?? '')
  const [attackClass, setAttackClass] = useState(unit?.attackClass ?? '')
  const [status, setStatus] = useState<CoverageStatus>(unit?.status ?? 'planned')
  const [wave, setWave] = useState(String(unit?.wave ?? 1))
  const [owner, setOwner] = useState(unit?.owner ?? '')
  const [reviewedPaths, setReviewedPaths] = useState((unit?.reviewedPaths ?? []).join('\n'))
  const [localChecks, setLocalChecks] = useState((unit?.localChecks ?? []).join('\n'))
  const [fingerprints, setFingerprints] = useState((unit?.resultFingerprints ?? []).join('\n'))
  const [unresolved, setUnresolved] = useState(unit?.unresolved ?? '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<unknown>(null)

  const problems = [
    segmentProblem('Surface', surface),
    segmentProblem('Boundary', boundary),
    segmentProblem('Subsystem', subsystem),
    segmentProblem('Attack class', attackClass),
  ].filter((problem): problem is string => problem !== null)
  const coverageId = editing ? unit.coverageId : problems.length === 0 ? composeCoverageId({ surface, boundary, subsystem, attackClass }) : null

  const waveNumber = wave.trim() === '' ? Number.NaN : Number(wave)
  const lists = {
    reviewedPaths: splitLines(reviewedPaths),
    localChecks: splitLines(localChecks),
    resultFingerprints: splitLines(fingerprints),
  }
  const allEntries = [...lists.reviewedPaths, ...lists.localChecks, ...lists.resultFingerprints, owner.trim(), unresolved.trim()]
  const fieldProblem =
    !Number.isInteger(waveNumber) || waveNumber < 0 || waveNumber > COVERAGE_MAX_WAVE
      ? `Wave must be a whole number from 0 to ${COVERAGE_MAX_WAVE}`
      : Object.values(lists).some((list) => list.length > COVERAGE_MAX_LIST_ITEMS)
        ? `Each list accepts at most ${COVERAGE_MAX_LIST_ITEMS} entries`
        : allEntries.some((value) => value.length > COVERAGE_MAX_STRING)
          ? `List entries, the owner and the unresolved reason are limited to ${COVERAGE_MAX_STRING} characters each`
          : null

  const save = async () => {
    if (!coverageId || fieldProblem) return
    const body: UpsertCoverageUnitRequest = {
      surface,
      boundary,
      subsystem,
      attackClass,
      status,
      wave: waveNumber,
      owner: owner.trim() || null,
      reviewedPaths: lists.reviewedPaths,
      localChecks: lists.localChecks,
      resultFingerprints: lists.resultFingerprints,
      unresolved: unresolved.trim() || null,
    }
    setSaving(true)
    setError(null)
    try {
      const saved = await api.research.upsertUnit(tenant.tenantId, coverageId, body)
      toast.success(editing ? 'Coverage unit updated' : 'Coverage unit added')
      onSaved(saved)
      onOpenChange(false)
    } catch (failure) {
      setError(failure)
    } finally {
      setSaving(false)
    }
  }

  const segmentInput = (value: string, setValue: (next: string) => void, placeholder: string) => (
    <Input
      value={value}
      disabled={editing}
      placeholder={placeholder}
      onChange={(event) => setValue(event.target.value.toLowerCase())}
      className="h-8 font-mono text-xs"
      maxLength={63}
      aria-invalid={!editing && value !== '' && segmentProblem('Segment', value) !== null}
    />
  )

  return (
    <Dialog open={open} onOpenChange={(next) => !saving && onOpenChange(next)}>
      <DialogContent className="flex max-h-[92vh] max-w-2xl flex-col overflow-hidden border-border/80 bg-background sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="text-sm">{editing ? 'Edit coverage unit' : 'Add coverage unit'}</DialogTitle>
          <DialogDescription className="text-xs">
            A coverage unit records an operator's claim about what was reviewed. It is not evidence and does not change
            any finding.
          </DialogDescription>
        </DialogHeader>

        <div className="flex min-h-0 flex-col gap-3 overflow-y-auto pr-1">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <Field label="Entry surface">{segmentInput(surface, setSurface, 'e.g. public-api')}</Field>
            <Field label="Trust boundary">{segmentInput(boundary, setBoundary, 'e.g. unauthenticated-to-app')}</Field>
            <Field label="Subsystem">{segmentInput(subsystem, setSubsystem, 'e.g. user-service')}</Field>
            <Field label="Attack class">{segmentInput(attackClass, setAttackClass, 'e.g. sql-injection')}</Field>
          </div>
          <div className="rounded-md border border-border/40 bg-background/40 p-2">
            <span className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Coverage id</span>
            {coverageId ? (
              <code className="block break-all font-mono text-[11px] text-zinc-300">{coverageId}</code>
            ) : (
              <span className="block text-[11px] text-amber-300">{problems[0]}</span>
            )}
            {!editing && (
              <span className="text-[10px] text-zinc-500">
                The four segments joined with '/'. Each is 1-63 characters of a-z, 0-9, '_' or '-'. They cannot be changed
                after creation.
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <Field label="Status">
              <Select value={status} onValueChange={(value) => value && setStatus(value as CoverageStatus)}>
                <SelectTrigger className="w-full font-mono text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {COVERAGE_STATUSES.map((value) => (
                    <SelectItem key={value} value={value}>
                      {value}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
            <Field label="Wave">
              <Input
                type="number"
                min={0}
                max={COVERAGE_MAX_WAVE}
                step={1}
                value={wave}
                onChange={(event) => setWave(event.target.value)}
                className="h-8 font-mono text-xs"
              />
            </Field>
            <Field label="Owner (optional)">
              <Input value={owner} onChange={(event) => setOwner(event.target.value)} className="h-8 text-xs" maxLength={COVERAGE_MAX_STRING} />
            </Field>
          </div>
          {COVERAGE_STATUS_RULE[status] && <p className="text-[11px] text-sky-300">{COVERAGE_STATUS_RULE[status]}</p>}

          <Field label="Reviewed paths (one per line, workspace-relative)">
            <Textarea
              value={reviewedPaths}
              onChange={(event) => setReviewedPaths(event.target.value)}
              rows={3}
              className="font-mono text-xs"
            />
          </Field>
          <Field label="Local checks (one per line)">
            <Textarea value={localChecks} onChange={(event) => setLocalChecks(event.target.value)} rows={2} className="font-mono text-xs" />
          </Field>
          <Field label="Result fingerprints or finding ids (one per line)">
            <Textarea value={fingerprints} onChange={(event) => setFingerprints(event.target.value)} rows={2} className="font-mono text-xs" />
          </Field>
          <Field label="Unresolved reason or blocker (optional)">
            <Textarea value={unresolved} onChange={(event) => setUnresolved(event.target.value)} rows={2} className="text-xs" />
          </Field>

          {fieldProblem && <p className="text-[11px] text-rose-300">{fieldProblem}</p>}
          {error !== null && <ErrorAlert error={error} title="The bridge rejected the coverage unit" />}
        </div>

        <DialogFooter>
          <Button variant="outline" size="sm" disabled={saving} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button size="sm" disabled={saving || !coverageId || fieldProblem !== null} onClick={() => void save()}>
            {saving && <Loader2 className="animate-spin" />}
            {editing ? 'Save changes' : 'Add unit'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
      {label}
      {children}
    </label>
  )
}
