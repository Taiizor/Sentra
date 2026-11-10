import { useState } from 'react'
import { AlertTriangle, Loader2, Play } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { api } from '@/lib/api'
import type { PluginRunView, PluginView, TenantView } from '@/types/api'
import { ErrorAlert, KeyValue, OutputBlock } from './console-kit'

type Step = 'form' | 'confirm' | 'running' | 'result'

function parseArgs(text: string): { value: Record<string, unknown> | null; error: string | null } {
  const trimmed = text.trim()
  if (!trimmed) return { value: {}, error: null }
  try {
    const parsed: unknown = JSON.parse(trimmed)
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { value: null, error: 'Arguments must be a JSON object, e.g. {"ruleset": "default"}' }
    }
    return { value: parsed as Record<string, unknown>, error: null }
  } catch (error) {
    return { value: null, error: `Invalid JSON: ${error instanceof Error ? error.message : String(error)}` }
  }
}

/**
 * Runs one declared capability of an adapter after an explicit confirmation. The adapter is a
 * host subprocess without a sandbox; its output is reported by the adapter, not admitted evidence.
 */
export function PluginRunDialog({
  plugin,
  tenant,
  open,
  onOpenChange,
}: {
  plugin: PluginView
  tenant: TenantView
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [step, setStep] = useState<Step>('form')
  const [capability, setCapability] = useState<string>(plugin.capabilities[0] ?? '')
  const [argsText, setArgsText] = useState('{}')
  const [result, setResult] = useState<PluginRunView | null>(null)
  const [error, setError] = useState<unknown>(null)

  const parsed = parseArgs(argsText)
  const busy = step === 'running'

  const close = (next: boolean) => {
    if (busy) return
    onOpenChange(next)
    if (!next) {
      setStep('form')
      setResult(null)
      setError(null)
    }
  }

  const run = async () => {
    if (!parsed.value || !capability) return
    setStep('running')
    setError(null)
    try {
      const args = Object.keys(parsed.value).length > 0 ? parsed.value : undefined
      const view = await api.plugins.run(plugin.id, { tenantId: tenant.tenantId, capability, args })
      setResult(view)
      setStep('result')
      toast.message(`Adapter ${plugin.id} finished (reported exit code ${view.exitCode})`)
    } catch (failure) {
      setError(failure)
      setStep('confirm')
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="flex max-h-[90vh] max-w-2xl flex-col overflow-hidden border-border/80 bg-background sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="text-sm">Run adapter capability</DialogTitle>
          <DialogDescription className="text-xs">
            <span className="font-mono">{plugin.id}</span> {plugin.version} · requested for workspace {tenant.name}. The
            adapter's summary states the directory it actually ran in.
          </DialogDescription>
        </DialogHeader>

        <div className="flex min-h-0 flex-col gap-3 overflow-y-auto">
          {step === 'form' && (
            <>
              {plugin.capabilities.length === 0 ? (
                <p className="text-xs text-amber-300">The manifest declares no capabilities, so there is nothing to run.</p>
              ) : (
                <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
                  Capability (declared by the manifest)
                  <Select value={capability} onValueChange={(value) => value && setCapability(value)}>
                    <SelectTrigger className="w-full font-mono text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {plugin.capabilities.map((value) => (
                        <SelectItem key={value} value={value}>
                          {value}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </label>
              )}
              <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
                Arguments (JSON object passed to the adapter)
                <Textarea
                  value={argsText}
                  onChange={(event) => setArgsText(event.target.value)}
                  spellCheck={false}
                  rows={6}
                  className="font-mono text-xs"
                  aria-invalid={parsed.error !== null}
                />
              </label>
              {parsed.error && <p className="text-[11px] text-rose-300">{parsed.error}</p>}
            </>
          )}

          {(step === 'confirm' || step === 'running') && (
            <>
              <div className="flex flex-col gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-100">
                <span className="flex items-center gap-1.5 font-semibold text-amber-200">
                  <AlertTriangle className="size-3.5" />
                  This executes adapter code on the bridge host
                </span>
                <p>
                  The bridge will start{' '}
                  <code className="break-all font-mono text-[11px]">{plugin.executablePath ?? '(executable resolved by the core)'}</code>{' '}
                  as a subprocess under the bridge's user account (minimal environment, normal network access) and ask it
                  to run{' '}
                  <code className="font-mono text-[11px]">{capability}</code>. It is not sandboxed: the declared quotas and
                  egress policy are not enforced.
                </p>
                <p>Whatever the adapter reports is shown as-is and is not admitted as evidence.</p>
              </div>
              <OutputBlock label="arguments" text={JSON.stringify(parsed.value ?? {}, null, 2)} maxHeightClass="max-h-40" />
              {error !== null && <ErrorAlert error={error} title="The adapter run failed" />}
              {busy && (
                <p className="flex items-center gap-1.5 text-xs text-sky-300">
                  <Loader2 className="size-3.5 animate-spin" />
                  Adapter process running on the bridge host (not sandboxed)…
                </p>
              )}
            </>
          )}

          {step === 'result' && result && <PluginRunResult result={result} />}
        </div>

        <DialogFooter>
          {step === 'form' && (
            <>
              <Button variant="outline" size="sm" onClick={() => close(false)}>
                Cancel
              </Button>
              <Button size="sm" disabled={!parsed.value || !capability} onClick={() => setStep('confirm')}>
                Review
              </Button>
            </>
          )}
          {(step === 'confirm' || step === 'running') && (
            <>
              <Button variant="outline" size="sm" disabled={busy} onClick={() => setStep('form')}>
                Back
              </Button>
              <Button variant="destructive" size="sm" disabled={busy} onClick={() => void run()}>
                {busy ? <Loader2 className="animate-spin" /> : <Play />}
                Run adapter
              </Button>
            </>
          )}
          {step === 'result' && (
            <>
              <Button variant="outline" size="sm" onClick={() => setStep('form')}>
                Run again
              </Button>
              <Button size="sm" onClick={() => close(false)}>
                Close
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function PluginRunResult({ result }: { result: PluginRunView }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <KeyValue label="Reported exit code">
          <Badge
            variant="outline"
            className={result.exitCode === 0 ? 'border-emerald-500/30 text-emerald-300' : 'border-rose-500/30 text-rose-300'}
          >
            {result.exitCode}
          </Badge>
        </KeyValue>
        <KeyValue label="Capability" mono>
          {result.capability}
        </KeyValue>
        <KeyValue label="Task" mono>
          {result.taskId ?? 'none recorded'}
        </KeyValue>
      </div>
      <KeyValue label="Adapter summary">{result.summary || '(empty)'}</KeyValue>
      <div className="flex flex-col gap-1">
        <span className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
          Adapter-reported references (not admitted evidence)
        </span>
        {result.reportedEvidenceRefs.length === 0 ? (
          <span className="text-xs text-zinc-500">none</span>
        ) : (
          <ul className="flex flex-col gap-0.5">
            {result.reportedEvidenceRefs.map((ref) => (
              <li key={ref} className="break-all font-mono text-[11px] text-zinc-300">
                {ref}
              </li>
            ))}
          </ul>
        )}
      </div>
      <OutputBlock label="stdout" text={result.stdout} maxHeightClass="max-h-56" />
      <OutputBlock label="stderr" text={result.stderr} tone="error" maxHeightClass="max-h-40" />
    </div>
  )
}
