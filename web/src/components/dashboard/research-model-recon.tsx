import { useEffect, useMemo, useState } from 'react'
import { Bot, Loader2, Settings, Sparkles, TriangleAlert } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { MarkdownView } from '@/components/ui/markdown-view'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import { cn } from '@/lib/utils'
import type { ModelReconReportView, ProviderId, ReconWorkflow, TenantView } from '@/types/api'
import { formatCount, formatDateTime, formatDuration, minimumRoleFor, permissionHint } from './console-format'
import { CopyButton, EmptyBlock, ErrorAlert, GatedButton, KeyValue, LoadingBlock, SectionCard } from './console-kit'

const DEFAULT_PROVIDER = '__default__'

const WORKFLOWS: { value: ReconWorkflow; label: string; description: string }[] = [
  { value: 'scout', label: 'Scout', description: 'Asks the model to outline entry surfaces and trust boundaries.' },
  { value: 'threat-model', label: 'Threat model', description: 'Asks the model to draft a threat model for the workspace.' },
]

/** Model-generated reconnaissance notes. Everything shown here is unverified model output. */
export function ModelRecon({ tenant }: { tenant: TenantView }) {
  const { can, invalidate, navigate } = useConsole()
  const reports = useResource(`recon-model:${tenant.tenantId}`, (signal) => api.research.modelReports(tenant.tenantId, signal))
  const ai = useResource('ai-settings', (signal) => api.ai.settings(signal))
  const [workflow, setWorkflow] = useState<ReconWorkflow>('scout')
  const [provider, setProvider] = useState<string>(DEFAULT_PROVIDER)
  const [runningSince, setRunningSince] = useState<number | null>(null)
  const [now, setNow] = useState(() => Date.now())
  const [error, setError] = useState<unknown>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  useEffect(() => {
    if (runningSince === null) return
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [runningSince])

  const readyProviders = useMemo(() => (ai.data?.providers ?? []).filter((entry) => entry.ready), [ai.data])
  const defaultProvider = ai.data?.defaultProvider ?? null
  const defaultReady = defaultProvider !== null && readyProviders.some((entry) => entry.id === defaultProvider)
  const chosen = provider === DEFAULT_PROVIDER ? (defaultReady ? defaultProvider : null) : (provider as ProviderId)
  const chosenStatus = readyProviders.find((entry) => entry.id === chosen) ?? null

  const blockedReason = ai.data
    ? readyProviders.length === 0
      ? 'No AI provider is ready'
      : chosen === null
        ? 'Select a provider (no ready default provider is set)'
        : null
    : null

  const sorted = useMemo(
    () => [...(reports.data?.reports ?? [])].sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0)),
    [reports.data],
  )
  const selected = sorted.find((report) => report.reportId === selectedId) ?? sorted[0] ?? null

  const run = async () => {
    setRunningSince(Date.now())
    setNow(Date.now())
    setError(null)
    try {
      const body = chosen === null ? { workflow } : { workflow, provider: chosen }
      const report = await api.research.runModelRecon(tenant.tenantId, body)
      reports.setData((current) => ({ reports: [report, ...(current?.reports ?? []).filter((r) => r.reportId !== report.reportId)] }))
      setSelectedId(report.reportId)
      toast.message(`Model output received from ${report.provider} (${report.model}); it is unverified`)
      invalidate()
    } catch (failure) {
      setError(failure)
    } finally {
      setRunningSince(null)
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <SectionCard
        icon={<Sparkles className="size-4 text-violet-400" />}
        title="Model reconnaissance"
        description="Sends the core's prompt for the chosen workflow (`sentra prompt`) plus the latest topology report of this workspace to a configured model provider and stores the answer. If no topology report exists, one is computed first. The answer is a candidate for a human to check, never a finding."
      >
        {ai.error ? (
          <p className="text-[11px] text-amber-300">
            The provider list could not be loaded ({errorMessage(ai.error)}). A run will use the bridge's default provider,
            if one is set.
          </p>
        ) : ai.data && readyProviders.length === 0 ? (
          <div className="flex flex-col gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 p-2.5 text-xs text-amber-100">
            <span>
              No AI provider is ready. Someone with the {minimumRoleFor('settings:write')} role configures providers and keys in
              Settings (permission: settings:write).
            </span>
            {can('settings:write') && (
              <div>
                <Button variant="outline" size="xs" onClick={() => navigate('settings')}>
                  <Settings />
                  Open Settings
                </Button>
              </div>
            )}
          </div>
        ) : null}

        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[12rem_16rem_auto] sm:items-end">
          <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
            Workflow
            <Select value={workflow} onValueChange={(value) => value && setWorkflow(value as ReconWorkflow)}>
              <SelectTrigger className="w-full text-xs">
                <SelectValue>{(value: string | null) => WORKFLOWS.find((entry) => entry.value === value)?.label ?? value}</SelectValue>
              </SelectTrigger>
              <SelectContent>
                {WORKFLOWS.map((entry) => (
                  <SelectItem key={entry.value} value={entry.value}>
                    {entry.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </label>
          <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
            Provider
            <Select value={provider} onValueChange={(value) => value && setProvider(value)} disabled={!ai.data}>
              <SelectTrigger className="w-full text-xs">
                <SelectValue>
                  {(value: string | null) =>
                    value === DEFAULT_PROVIDER
                      ? defaultReady
                        ? `Default (${defaultProvider})`
                        : 'Default (none ready)'
                      : (readyProviders.find((entry) => entry.id === value)?.label ?? value)
                  }
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={DEFAULT_PROVIDER}>{defaultReady ? `Default (${defaultProvider})` : 'Default (none ready)'}</SelectItem>
                {readyProviders.map((entry) => (
                  <SelectItem key={entry.id} value={entry.id}>
                    {entry.label}
                    {entry.model ? ` · ${entry.model}` : ''}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </label>
          <GatedButton permission="ai:generate" blockedReason={blockedReason} disabled={runningSince !== null} onClick={() => void run()}>
            {runningSince !== null ? <Loader2 className="animate-spin" /> : <Bot />}
            Run
          </GatedButton>
        </div>
        <p className="text-[11px] text-muted-foreground">
          {WORKFLOWS.find((entry) => entry.value === workflow)?.description}{' '}
          {chosenStatus
            ? `The prompt is sent to ${chosenStatus.label}${chosenStatus.usesCustomEndpoint ? ` at ${chosenStatus.endpoint}` : ''}.`
            : ''}
        </p>
        {runningSince !== null && (
          <p className="flex items-center gap-1.5 text-xs text-sky-300">
            <Loader2 className="size-3.5 animate-spin" />
            Waiting for {chosenStatus ? `${chosenStatus.label}${chosenStatus.model ? ` (${chosenStatus.model})` : ''}` : 'the provider'} ·{' '}
            {formatDuration(now - runningSince)}
          </p>
        )}
        {error !== null && <ErrorAlert error={error} title="The model request failed" />}
        {!can('ai:generate') && <p className="text-[11px] text-zinc-500">{permissionHint('ai:generate')} to run a request.</p>}
      </SectionCard>

      {reports.error ? (
        <ErrorAlert error={reports.error} onRetry={reports.reload} title="Could not load stored model reports" />
      ) : !reports.data ? (
        <LoadingBlock rows={3} />
      ) : sorted.length === 0 ? (
        <EmptyBlock icon={<Bot />} title="No model reconnaissance for this workspace yet">
          Stored model answers for this workspace appear here after a run.
        </EmptyBlock>
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[16rem_1fr]">
          <SectionCard title={`Stored reports (${sorted.length})`}>
            <ul className="flex flex-col gap-1">
              {sorted.map((report) => (
                <li key={report.reportId}>
                  <button
                    type="button"
                    onClick={() => setSelectedId(report.reportId)}
                    className={cn(
                      'flex w-full flex-col rounded-md border px-2 py-1.5 text-left text-xs transition-colors',
                      selected?.reportId === report.reportId ? 'border-primary/50 bg-primary/10' : 'border-transparent hover:bg-muted/50',
                    )}
                  >
                    <span className="font-medium text-zinc-100">{WORKFLOWS.find((entry) => entry.value === report.workflow)?.label ?? report.workflow}</span>
                    <span className="truncate text-[10px] text-zinc-500">
                      {formatDateTime(report.createdAt)} · {report.provider}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </SectionCard>
          {selected && <ReconReport report={selected} />}
        </div>
      )}
    </div>
  )
}

function ReconReport({ report }: { report: ModelReconReportView }) {
  return (
    <SectionCard
      icon={<Bot className="size-4 text-violet-400" />}
      title={`${WORKFLOWS.find((entry) => entry.value === report.workflow)?.label ?? report.workflow} · ${report.provider}`}
      actions={<CopyButton text={report.output} label="Copy output" />}
    >
      <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-2.5 text-xs text-amber-100">
        <TriangleAlert className="mt-0.5 size-4 shrink-0 text-amber-400" />
        <div className="flex flex-col gap-0.5">
          <span className="font-semibold text-amber-200">Unverified model output</span>
          <span>{report.disclaimer}</span>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <KeyValue label="Provider / model" mono>
          {report.provider} / {report.model}
        </KeyValue>
        <KeyValue label="Requested">
          {formatDateTime(report.createdAt)} by {report.createdBy}
        </KeyValue>
        <KeyValue label="Tokens in / out" mono>
          {formatCount(report.inputTokens)} / {formatCount(report.outputTokens)}
        </KeyValue>
        <KeyValue label="Latency" mono>
          {formatDuration(report.latencyMs)}
        </KeyValue>
        <KeyValue label="Topology context" mono className="col-span-2 md:col-span-4">
          {report.topologyReportId ? `topology report ${report.topologyReportId}` : 'no topology report was included'}
        </KeyValue>
      </div>
      <Badge variant="outline" className="w-fit border-amber-500/40 text-[10px] text-amber-300">
        Unverified model output
      </Badge>
      <div className="max-h-[36rem] overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-3">
        <MarkdownView content={report.output} />
      </div>
    </SectionCard>
  )
}
