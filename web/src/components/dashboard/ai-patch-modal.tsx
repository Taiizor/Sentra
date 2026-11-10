import { useMemo, useState } from 'react'
import { Bot, Loader2, Lock, Settings, Sparkles } from 'lucide-react'
import { toast } from 'sonner'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorAlert, GatedButton, SeverityBadge } from '@/components/dashboard/findings-shared'
import { PatchActions } from '@/components/dashboard/patch-actions'
import { PatchDetails } from '@/components/dashboard/patch-details'
import { requestRemediationFocus } from '@/components/dashboard/remediation-focus'
import { minimumRoleFor } from '@/components/dashboard/console-format'
import type { FindingView, PatchBundleView, ProviderId, ProviderStatusView } from '@/types/api'

/**
 * Generates a patch candidate for one SAST finding through a configured model provider.
 * The request takes as long as the provider takes; the result is unverified model output.
 * Callers key the modal by finding ID so each finding starts from a clean state.
 */
export function AiPatchModal({
  finding,
  open,
  onOpenChange,
}: {
  finding: FindingView
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { tenant, navigate, invalidate } = useConsole()
  const settings = useResource(open ? 'ai-settings' : null, (signal) => api.ai.settings(signal))
  const [providerChoice, setProviderChoice] = useState<ProviderId | null>(null)
  const [generating, setGenerating] = useState(false)
  const [generateError, setGenerateError] = useState<unknown>(null)
  const [patch, setPatch] = useState<PatchBundleView | null>(null)

  const readyProviders = useMemo(
    () => (settings.data?.providers ?? []).filter((provider) => provider.ready),
    [settings.data],
  )
  const defaultProvider = settings.data?.defaultProvider ?? null
  const selected: ProviderStatusView | null = useMemo(() => {
    const byId = (id: ProviderId | null) => readyProviders.find((provider) => provider.id === id) ?? null
    return byId(providerChoice) ?? byId(defaultProvider) ?? readyProviders[0] ?? null
  }, [readyProviders, providerChoice, defaultProvider])

  async function handleGenerate() {
    if (!tenant || !selected) return
    setGenerating(true)
    setGenerateError(null)
    try {
      const result = await api.patches.generate(tenant.tenantId, finding.findingId, { provider: selected.id })
      setPatch(result)
      invalidate()
      toast.success('Patch candidate generated', { description: 'Unverified model output — review before use.' })
    } catch (error) {
      setGenerateError(error)
      toast.error('Patch generation failed', { description: errorMessage(error) })
    } finally {
      setGenerating(false)
    }
  }

  function openSettings() {
    onOpenChange(false)
    navigate('settings')
  }

  function openInRemediation() {
    if (patch) requestRemediationFocus(patch.bundleId)
    onOpenChange(false)
    navigate('remediation')
  }

  const fileLabel = finding.filePath ?? 'the affected file'

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-4xl overflow-y-auto border border-zinc-800 bg-zinc-950 sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-sm text-zinc-100">
            <Sparkles className="size-4 text-zinc-400" />
            Generate patch candidate
          </DialogTitle>
          <DialogDescription render={<div />} className="flex flex-wrap items-center gap-1.5 text-xs text-zinc-400">
            <SeverityBadge severity={finding.severity} />
            <span className="font-mono text-zinc-300">{finding.ruleId}</span>
            <span>{finding.ruleName}</span>
            {finding.filePath && (
              <span className="font-mono text-zinc-500">
                {finding.filePath}
                {finding.line !== null ? `:${finding.line}` : ''}
              </span>
            )}
          </DialogDescription>
        </DialogHeader>

        {!tenant ? (
          <Alert>
            <AlertTitle className="text-xs">No workspace selected</AlertTitle>
          </Alert>
        ) : patch ? (
          <div className="flex flex-col gap-4">
            <PatchDetails patch={patch} />
            <div className="border-t border-zinc-800 pt-3">
              <PatchActions patch={patch} onUpdated={setPatch} onOpenInRemediation={openInRemediation} />
            </div>
          </div>
        ) : settings.loading && !settings.data ? (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-8 w-1/2 bg-zinc-800/60" />
            <Skeleton className="h-16 w-full bg-zinc-800/60" />
          </div>
        ) : settings.error ? (
          <ErrorAlert error={settings.error} title="Could not load AI provider settings" onRetry={settings.reload} />
        ) : readyProviders.length === 0 || !selected ? (
          <Alert className="border-amber-500/30 bg-amber-500/5">
            <Bot />
            <AlertTitle className="text-xs text-amber-200">No AI provider configured</AlertTitle>
            <AlertDescription className="flex flex-col gap-2 text-xs text-zinc-400">
              <span>Someone with the {minimumRoleFor('settings:write')} role can configure one in Settings → AI providers.</span>
              <Button variant="outline" size="xs" className="w-fit" onClick={openSettings}>
                <Settings /> Open Settings
              </Button>
            </AlertDescription>
          </Alert>
        ) : (
          <div className="flex flex-col gap-4">
            <label className="flex flex-col gap-1.5 text-xs">
              <span className="text-zinc-300">Model provider</span>
              <Select
                value={selected.id}
                onValueChange={(value) => {
                  if (typeof value === 'string') setProviderChoice(value as ProviderId)
                }}
                disabled={generating}
              >
                <SelectTrigger className="h-8 w-full max-w-sm border-zinc-800 bg-zinc-900 text-xs">
                  <SelectValue>
                    {(value: string | null) => {
                      const provider = readyProviders.find((candidate) => candidate.id === value)
                      return provider ? `${provider.label} · ${provider.model ?? 'model not set'}` : 'Select a provider'
                    }}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {readyProviders.map((provider) => (
                      <SelectItem key={provider.id} value={provider.id}>
                        {provider.label} · {provider.model ?? 'model not set'}
                        {provider.id === defaultProvider ? ' (default)' : ''}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            </label>

            <div className="flex items-start gap-2 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2 text-xs text-zinc-300">
              <Lock className="mt-0.5 size-3.5 shrink-0 text-zinc-400" />
              <div className="flex flex-col gap-1">
                <span>
                  An excerpt (±60 lines) of <code className="text-zinc-100">{fileLabel}</code> will be sent to{' '}
                  {selected.label} ({selected.model ?? 'model not set'}).
                </span>
                <span className="text-zinc-500">
                  Endpoint: <span className="font-mono">{selected.endpoint}</span>
                  {selected.usesCustomEndpoint ? ' (custom endpoint)' : ''}
                </span>
              </div>
            </div>

            <div className="flex items-start gap-2 text-[11px] text-zinc-500">
              <Bot className="mt-0.5 size-3.5 shrink-0" />
              The result is unverified model output. Sentra does not compile, test or re-scan it; verification is
              reported as “not run”.
            </div>

            {generateError !== null && !generating && (
              <ErrorAlert error={generateError} title="Patch generation failed" onRetry={() => void handleGenerate()} />
            )}

            <div className="flex flex-wrap items-center gap-3 border-t border-zinc-800 pt-3">
              <GatedButton permission="ai:generate" size="sm" disabled={generating} onClick={() => void handleGenerate()}>
                {generating ? <Loader2 className="animate-spin" /> : <Sparkles />}
                {generating ? `Waiting for ${selected.label}…` : 'Generate patch candidate'}
              </GatedButton>
              {generating && (
                <span className="text-[11px] text-zinc-500">
                  Closing this dialog does not cancel the request; a completed candidate appears in Remediation.
                </span>
              )}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
