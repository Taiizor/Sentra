import { useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { permissionRequirement, VERDICT_LABEL } from '@/components/dashboard/findings-format'
import { GatedButton, Timestamp } from '@/components/dashboard/findings-shared'
import type { FindingView, TriageVerdict } from '@/types/api'

const VERDICTS: { id: TriageVerdict; hint: string }[] = [
  { id: 'confirmed', hint: 'A real issue that needs a fix' },
  { id: 'needs_validation', hint: 'Plausible; needs manual or dynamic validation' },
  { id: 'rejected', hint: 'False positive or not applicable' },
]

const MAX_REASON = 2000

/**
 * Shows the recorded triage decision and, for permitted users, records a new one.
 * Callers key it by finding and recorded decision so the form resets when either changes.
 */
export function FindingTriageForm({ finding }: { finding: FindingView }) {
  const { tenant, can, invalidate } = useConsole()
  const [verdict, setVerdict] = useState<TriageVerdict>(finding.triage?.verdict ?? 'confirmed')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const trimmed = reason.trim()

  async function submit() {
    if (!tenant || trimmed.length === 0) return
    setBusy(true)
    try {
      await api.findings.triage(tenant.tenantId, finding.findingId, { verdict, reason: trimmed })
      toast.success(`Triage recorded: ${VERDICT_LABEL[verdict]}`)
      setReason('')
      invalidate()
    } catch (error) {
      toast.error('Triage was not recorded', { description: errorMessage(error) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-3">
      {finding.triage ? (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/50 px-3 py-2 text-xs">
          <div className="flex flex-wrap items-center gap-1.5 text-zinc-300">
            <span className="font-semibold">{VERDICT_LABEL[finding.triage.verdict]}</span>
            <span className="text-zinc-500">
              by {finding.triage.by} · <Timestamp value={finding.triage.at} />
            </span>
          </div>
          <p className="mt-1 whitespace-pre-wrap text-zinc-400">{finding.triage.reason}</p>
        </div>
      ) : (
        <p className="text-xs text-zinc-500">No triage decision has been recorded for this finding.</p>
      )}

      {can('finding:triage') ? (
        <form
          className="flex flex-col gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            void submit()
          }}
        >
          <Select
            value={verdict}
            onValueChange={(value) => {
              if (value === 'confirmed' || value === 'needs_validation' || value === 'rejected') setVerdict(value)
            }}
            disabled={busy}
          >
            <SelectTrigger className="h-8 w-full border-zinc-800 bg-zinc-900 text-xs">
              <SelectValue>
                {(value: string | null) =>
                  value === 'confirmed' || value === 'needs_validation' || value === 'rejected'
                    ? VERDICT_LABEL[value]
                    : 'Select a verdict'
                }
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {VERDICTS.map((option) => (
                  <SelectItem key={option.id} value={option.id}>
                    {VERDICT_LABEL[option.id]} — {option.hint}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <Textarea
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            maxLength={MAX_REASON}
            placeholder="Reason (required): what you checked and why you reached this verdict"
            className="min-h-20 border-zinc-800 bg-zinc-900 text-xs"
            disabled={busy}
            required
          />
          <div className="flex items-center justify-between gap-2">
            <span className="text-[10px] text-zinc-600">
              {reason.length}/{MAX_REASON}
            </span>
            <GatedButton
              permission="finding:triage"
              type="submit"
              size="sm"
              disabled={busy}
              disabledReason={trimmed.length === 0 ? 'A reason is required' : null}
            >
              {busy && <Loader2 className="animate-spin" />}
              Record triage
            </GatedButton>
          </div>
        </form>
      ) : (
        <p className="text-[11px] text-zinc-500">{permissionRequirement('finding:triage')} to record a triage decision.</p>
      )}
    </div>
  )
}
