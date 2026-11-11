import { useCallback, useEffect, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  Boxes,
  CheckCircle2,
  Circle,
  CircleDashed,
  Code2,
  FileSearch,
  Layers,
  Loader2,
  MinusCircle,
  Play,
  Square,
  Terminal,
  XCircle,
} from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { ApiError, api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { cn } from '@/lib/utils'
import type { CodeqlProgressView, ScanKind, ScanRunView, ScanStreamEvent } from '@/types/api'
import { codeqlStageHint, isPackDownload, STOP_SCAN_PARAGRAPHS } from './codeql-text'
import { formatDuration, formatTime, minimumRoleFor } from './console-format'
import { ConfirmDialog, CopyButton, GatedButton, NoTenantState } from './console-kit'
import { ScanRunSummaryView } from './stream-summary'

type StageName = Extract<ScanStreamEvent, { type: 'stage' }>['stage']
type StageStatus = 'pending' | Extract<ScanStreamEvent, { type: 'stage' }>['status']
type Phase = 'idle' | 'running' | 'finished' | 'failed' | 'aborted'

interface StageState {
  name: StageName
  status: StageStatus
  message: string | null
  /** Latest CodeQL progress line while the stage runs (contract 6). */
  activity: string | null
}

type LogEntry =
  | { id: number; kind: 'log'; stream: 'stdout' | 'stderr' | 'bridge'; text: string; ts: string }
  | { id: number; kind: 'progress'; progress: CodeqlProgressView; ts: string }
  | { id: number; kind: 'stage'; stage: StageName; status: StageStatus; message: string }
  | { id: number; kind: 'error'; code: string; message: string }

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never
type NewLogEntry = DistributiveOmit<LogEntry, 'id'>

interface LogState {
  entries: LogEntry[]
  /** Entries removed from the view because the in-memory cap was reached. */
  dropped: number
}

const EMPTY_LOG: LogState = { entries: [], dropped: 0 }
const MAX_LOG_ENTRIES = 4000

const STAGE_LABEL: Record<StageName, string> = {
  sast: 'Static analysis',
  dependency: 'Dependency audit',
  codeql: 'CodeQL (language probe, host analysis when enabled)',
  persist: 'Persist run and reconcile findings',
}

/** Stages the bridge is expected to report per scan kind; unreported stages stay visible as such. */
const KIND_STAGES: Record<ScanKind, StageName[]> = {
  sast: ['sast', 'persist'],
  dependency: ['dependency', 'persist'],
  codeql: ['codeql', 'persist'],
  all: ['sast', 'dependency', 'codeql', 'persist'],
}

const KIND_OPTIONS: { kind: ScanKind; label: string; icon: typeof Layers; description: string }[] = [
  {
    kind: 'sast',
    label: 'Static analysis',
    icon: FileSearch,
    description: 'Runs the Sentra core heuristic rules (`sentra scan`) over the workspace. Matches are unverified candidates.',
  },
  {
    kind: 'dependency',
    label: 'Dependency audit',
    icon: Boxes,
    description:
      'Reads lockfiles with `sentra inventory`, then queries OSV.dev for known vulnerabilities. Requires OSV lookups to be enabled; package names leave this host.',
  },
  {
    kind: 'codeql',
    label: 'CodeQL',
    icon: Code2,
    description:
      'Counts files per CodeQL language (`sentra codeql`). When an admin enabled CodeQL host analysis (Settings > CodeQL), also runs `sentra codeql analyze` on the bridge host with build mode none; otherwise CodeQL is not run and the stage says why. The first analysis may first download query packs (several minutes on a slow connection) unless they were downloaded in Settings > CodeQL > Query packs.',
  },
  {
    kind: 'all',
    label: 'All stages',
    icon: Layers,
    description: 'Runs static analysis, the dependency audit and the CodeQL stage in one run.',
  },
]

/** Wall-clock time for event handlers (kept outside components so render stays pure). */
function currentTimeMs(): number {
  return Date.now()
}

function initialStages(kind: ScanKind): StageState[] {
  return KIND_STAGES[kind].map((name) => ({ name, status: 'pending', message: null, activity: null }))
}

/**
 * Starts a real scan through the bridge and renders its server-sent events: stage
 * transitions, core process output and the persisted run summary. There is no synthetic
 * progress; aborting closes the stream and the bridge terminates the core process.
 */
export function LiveStreamModal({
  open,
  onOpenChange,
  kind,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  kind: ScanKind
}) {
  const { tenant, navigate, invalidate } = useConsole()
  const [selectedKind, setSelectedKind] = useState<ScanKind>(kind)
  const [phase, setPhase] = useState<Phase>('idle')
  const [stages, setStages] = useState<StageState[]>(() => initialStages(kind))
  const [log, setLog] = useState<LogState>(EMPTY_LOG)
  const [run, setRun] = useState<ScanRunView | null>(null)
  const [failure, setFailure] = useState<unknown>(null)
  const [startedAt, setStartedAt] = useState<number | null>(null)
  const [endedAt, setEndedAt] = useState<number | null>(null)
  const [now, setNow] = useState(() => Date.now())
  const [confirm, setConfirm] = useState<'close' | 'stop' | null>(null)
  const [autoScroll, setAutoScroll] = useState(true)
  /** True once the core reported a query pack download in this run. */
  const [packDownloadSeen, setPackDownloadSeen] = useState(false)

  const controllerRef = useRef<AbortController | null>(null)
  const nextIdRef = useRef(0)
  const runIdRef = useRef<string | null>(null)
  const logEndRef = useRef<HTMLDivElement | null>(null)
  const wasOpenRef = useRef(open)

  const resetToIdle = useCallback((nextKind: ScanKind) => {
    setSelectedKind(nextKind)
    setPhase('idle')
    setStages(initialStages(nextKind))
    setLog(EMPTY_LOG)
    setRun(null)
    setFailure(null)
    setStartedAt(null)
    setEndedAt(null)
    setPackDownloadSeen(false)
  }, [])

  // Each time the dialog opens (and no scan is running) start from the requested kind.
  useEffect(() => {
    // controllerRef is only set while a stream is active.
    if (open && !wasOpenRef.current && controllerRef.current === null) resetToIdle(kind)
    wasOpenRef.current = open
  }, [open, kind, resetToIdle])

  // Abort a running stream if the modal is unmounted; the bridge then kills the core process.
  useEffect(() => () => controllerRef.current?.abort(), [])

  useEffect(() => {
    if (phase !== 'running') return
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [phase])

  useEffect(() => {
    if (autoScroll) logEndRef.current?.scrollIntoView({ block: 'nearest' })
  }, [log, autoScroll])

  const appendEntry = useCallback((entry: NewLogEntry) => {
    const id = nextIdRef.current++
    setLog((current) => {
      const entries = [...current.entries, { ...entry, id } as LogEntry]
      if (entries.length <= MAX_LOG_ENTRIES) return { entries, dropped: current.dropped }
      const overflow = entries.length - MAX_LOG_ENTRIES
      return { entries: entries.slice(overflow), dropped: current.dropped + overflow }
    })
  }, [])

  const handleEvent = useCallback(
    (event: ScanStreamEvent) => {
      switch (event.type) {
        case 'run':
        case 'complete':
          runIdRef.current = event.run.runId
          setRun(event.run)
          break
        case 'stage':
          setStages((current) => {
            const exists = current.some((stage) => stage.name === event.stage)
            // A finished stage no longer shows its last progress line.
            const activity = (stage: StageState) => (event.status === 'started' ? stage.activity : null)
            const updated = current.map((stage) =>
              stage.name === event.stage ? { ...stage, status: event.status, message: event.message, activity: activity(stage) } : stage,
            )
            return exists ? updated : [...updated, { name: event.stage, status: event.status, message: event.message, activity: null }]
          })
          appendEntry({ kind: 'stage', stage: event.stage, status: event.status, message: event.message })
          break
        case 'progress':
          setStages((current) =>
            current.map((stage) => (stage.name === event.stage ? { ...stage, activity: event.progress.text } : stage)),
          )
          if (isPackDownload(event.progress)) setPackDownloadSeen(true)
          appendEntry({ kind: 'progress', progress: event.progress, ts: event.ts })
          break
        case 'log':
          appendEntry({ kind: 'log', stream: event.stream, text: event.text, ts: event.ts })
          break
        case 'error':
          appendEntry({ kind: 'error', code: event.code, message: event.message })
          break
      }
    },
    [appendEntry],
  )

  const startScan = async () => {
    if (!tenant || controllerRef.current !== null) return
    const controller = new AbortController()
    controllerRef.current = controller
    setStages(initialStages(selectedKind))
    setLog(EMPTY_LOG)
    setRun(null)
    runIdRef.current = null
    setFailure(null)
    setPackDownloadSeen(false)
    const started = currentTimeMs()
    setStartedAt(started)
    setNow(started)
    setEndedAt(null)
    setPhase('running')
    try {
      const finalRun = await api.scans.stream(tenant.tenantId, selectedKind, handleEvent, controller.signal)
      setRun(finalRun)
      setPhase(finalRun.status === 'failed' ? 'failed' : 'finished')
      if (finalRun.status === 'failed') toast.error(`Scan failed${finalRun.error ? `: ${finalRun.error}` : ''}`)
      else toast.success(`Scan ${finalRun.runId} finished`)
      invalidate()
    } catch (error) {
      const aborted = controller.signal.aborted || (error instanceof DOMException && error.name === 'AbortError')
      if (!aborted) setFailure(error)
      setPhase(aborted ? 'aborted' : 'failed')
      // The run may have been persisted before the stream ended; show the bridge's record of it.
      await refreshPersistedRun(tenant.tenantId)
      invalidate()
    } finally {
      setEndedAt(currentTimeMs())
      if (controllerRef.current === controller) controllerRef.current = null
    }
  }

  /** Re-reads the run from the bridge; a run that is still marked running is not summarised. */
  const refreshPersistedRun = async (tenantId: string) => {
    const runId = runIdRef.current
    if (!runId) {
      setRun(null)
      return
    }
    try {
      const persisted = await api.scans.get(tenantId, runId)
      setRun(persisted.status === 'running' ? null : persisted)
    } catch {
      setRun(null)
    }
  }

  const abortScan = () => {
    controllerRef.current?.abort()
  }

  const handleDialogOpenChange = (next: boolean) => {
    if (!next && phase === 'running') {
      setConfirm('close')
      return
    }
    onOpenChange(next)
  }

  const confirmAbort = () => {
    const closing = confirm === 'close'
    abortScan()
    setConfirm(null)
    if (closing) onOpenChange(false)
  }

  const elapsedMs = startedAt === null ? null : (endedAt ?? now) - startedAt
  // Match the error code, not the HTTP status: the bridge can also report `scan_in_progress` as an
  // in-stream error event (a scan started between its pre-check and the run), which carries no status.
  const scanInProgressConflict = failure instanceof ApiError && failure.code === 'scan_in_progress'
  const { entries, dropped: droppedEntries } = log
  const logText = entries.map(entryToText).join('\n')

  return (
    <Dialog open={open} onOpenChange={handleDialogOpenChange}>
      <DialogContent className="flex max-h-[92vh] w-full max-w-4xl flex-col gap-0 overflow-hidden border-border/80 bg-background p-0 sm:max-w-4xl">
        <DialogHeader className="gap-1 border-b border-border/60 bg-card/60 px-5 py-3 pr-12">
          <div className="flex flex-wrap items-center gap-2">
            <Terminal className="size-4 shrink-0 text-primary" />
            <DialogTitle className="text-sm font-semibold">Workspace scan</DialogTitle>
            <PhaseBadge phase={phase} elapsedMs={elapsedMs} />
          </div>
          <DialogDescription className="text-xs">
            {tenant ? (
              <>
                <span className="text-zinc-300">{tenant.name}</span> ·{' '}
                <span className="break-all font-mono text-[11px]">{tenant.workspace}</span>
              </>
            ) : (
              'No workspace selected.'
            )}
          </DialogDescription>
        </DialogHeader>

        <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-5">
          {!tenant ? (
            <NoTenantState feature="Scanning" />
          ) : phase === 'idle' ? (
            <KindSelector selected={selectedKind} onSelect={setSelectedKind} workspaceExists={tenant.workspaceExists} />
          ) : (
            <>
              <StageList stages={stages} phase={phase} packDownloadSeen={packDownloadSeen} />

              {failure !== null && (
                <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/5 p-3 text-xs text-rose-200">
                  <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-rose-400" />
                  <div className="flex flex-col gap-0.5">
                    <span className="font-semibold">
                      {scanInProgressConflict ? 'A scan is already running for this workspace' : 'The scan did not complete'}
                    </span>
                    <span className="break-words">{errorMessage(failure)}</span>
                  </div>
                </div>
              )}
              {phase === 'aborted' && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-200">
                  The stream was closed by you. The bridge stops the core process (and CodeQL with it) when the stream is
                  cancelled; partial results are only shown if the bridge persisted them. Query packs that finished
                  downloading stay in the pack cache.
                </div>
              )}

              <div className="flex min-h-0 flex-col overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950">
                <div className="flex items-center justify-between gap-2 border-b border-zinc-800 bg-zinc-900/70 px-3 py-1.5">
                  <span className="font-mono text-[11px] text-zinc-400">
                    Event log ({entries.length.toLocaleString()} entries
                    {droppedEntries > 0 ? `, ${droppedEntries.toLocaleString()} earlier entries not shown` : ''})
                  </span>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="xs"
                      className={cn('text-[10px]', autoScroll ? 'text-primary' : 'text-zinc-500')}
                      onClick={() => setAutoScroll((value) => !value)}
                    >
                      Follow: {autoScroll ? 'on' : 'off'}
                    </Button>
                    {logText && <CopyButton text={logText} label="Copy log" />}
                  </div>
                </div>
                <div className="h-64 overflow-auto p-3 font-mono text-[11px] leading-relaxed">
                  {entries.length === 0 ? (
                    <p className="py-6 text-center italic text-zinc-500">
                      {phase === 'running' ? 'Waiting for the first event from the bridge…' : 'No events were received.'}
                    </p>
                  ) : (
                    entries.map((entry) => <LogLine key={entry.id} entry={entry} />)
                  )}
                  <div ref={logEndRef} />
                </div>
              </div>

              {run && phase !== 'running' && <ScanRunSummaryView run={run} />}
              {run && phase === 'running' && (
                <p className="font-mono text-[11px] text-muted-foreground">
                  Run {run.runId} started {formatTime(run.startedAt)} by {run.actor}
                </p>
              )}
            </>
          )}
        </div>

        <div className="flex flex-col gap-2 border-t border-border/60 bg-card/60 px-5 py-3 sm:flex-row sm:items-center sm:justify-end">
          {phase === 'idle' && (
            <>
              <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
                Close
              </Button>
              <GatedButton
                permission="scan:run"
                blockedReason={
                  !tenant
                    ? 'Select a workspace first'
                    : !tenant.workspaceExists
                      ? 'The registered workspace directory does not exist on the bridge host'
                      : null
                }
                size="sm"
                onClick={() => void startScan()}
              >
                <Play className="fill-current" />
                Start scan
              </GatedButton>
            </>
          )}
          {phase === 'running' && (
            <Button variant="destructive" size="sm" onClick={() => setConfirm('stop')}>
              <Square className="fill-current" />
              Stop scan
            </Button>
          )}
          {(phase === 'finished' || phase === 'failed' || phase === 'aborted') && (
            <>
              <Button variant="outline" size="sm" onClick={() => resetToIdle(selectedKind)}>
                New scan
              </Button>
              <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
                Close
              </Button>
              <Button
                size="sm"
                onClick={() => {
                  onOpenChange(false)
                  navigate('findings')
                }}
              >
                View findings
                <ArrowRight />
              </Button>
            </>
          )}
        </div>
      </DialogContent>

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(next) => !next && setConfirm(null)}
        title={confirm === 'close' ? 'Close and stop the running scan?' : 'Stop the running scan?'}
        description={
          <>
            {STOP_SCAN_PARAGRAPHS.map((paragraph) => (
              <p key={paragraph}>{paragraph}</p>
            ))}
          </>
        }
        confirmLabel="Stop scan"
        destructive
        onConfirm={confirmAbort}
      />
    </Dialog>
  )
}

function PhaseBadge({ phase, elapsedMs }: { phase: Phase; elapsedMs: number | null }) {
  if (phase === 'idle') return null
  const elapsed = elapsedMs === null ? '' : ` · ${formatDuration(elapsedMs)}`
  const styles: Record<Exclude<Phase, 'idle'>, string> = {
    running: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
    finished: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
    failed: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
    aborted: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
  }
  return (
    <Badge variant="outline" className={cn('font-mono text-[10px]', styles[phase])}>
      {phase === 'running' && <Loader2 className="animate-spin" />}
      {phase}
      {elapsed}
    </Badge>
  )
}

function KindSelector({
  selected,
  onSelect,
  workspaceExists,
}: {
  selected: ScanKind
  onSelect: (kind: ScanKind) => void
  workspaceExists: boolean
}) {
  return (
    <div className="flex flex-col gap-3">
      <span className="text-xs font-semibold text-zinc-200">What to run</span>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {KIND_OPTIONS.map((option) => {
          const Icon = option.icon
          const active = option.kind === selected
          return (
            <button
              key={option.kind}
              type="button"
              onClick={() => onSelect(option.kind)}
              aria-pressed={active}
              className={cn(
                'flex flex-col gap-1 rounded-lg border p-3 text-left transition-colors',
                active ? 'border-primary bg-primary/10' : 'border-zinc-800 bg-zinc-950/60 hover:border-zinc-700',
              )}
            >
              <span className="flex items-center justify-between gap-2 text-xs font-semibold text-zinc-100">
                <span className="flex items-center gap-1.5">
                  <Icon className="size-3.5 text-primary" />
                  {option.label}
                </span>
                {active && <CheckCircle2 className="size-3.5 text-primary" />}
              </span>
              <span className="text-[11px] text-zinc-400">{option.description}</span>
            </button>
          )
        })}
      </div>
      {!workspaceExists && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 p-2.5 text-xs text-amber-200">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
          The registered workspace directory was not found on the bridge host, so it cannot be scanned. Restore it at the
          registered path, or have someone with the {minimumRoleFor('tenant:create')} role unregister this workspace
          (Settings → Workspaces) and register the new location under a new workspace id.
        </div>
      )}
      <p className="text-[11px] text-muted-foreground">
        The scan runs on the bridge host. Findings are reconciled against previous runs of this workspace; nothing is
        written to the workspace itself.
      </p>
    </div>
  )
}

function StageList({ stages, phase, packDownloadSeen }: { stages: StageState[]; phase: Phase; packDownloadSeen: boolean }) {
  return (
    <ol className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
      {stages.map((stage) => {
        const pendingLabel = phase === 'running' ? 'waiting' : 'not reported by the bridge'
        const stageRunning = phase === 'running' && stage.status === 'started'
        const hint = stage.name === 'codeql' ? codeqlStageHint({ stageRunning, packDownloadSeen }) : null
        return (
          <li
            key={stage.name}
            className="flex items-start gap-2 rounded-lg border border-border/60 bg-card/40 px-2.5 py-2 text-xs"
          >
            <StageIcon status={stage.status} running={phase === 'running'} />
            <div className="flex min-w-0 flex-col gap-0.5">
              <span className="font-medium text-zinc-100">
                {STAGE_LABEL[stage.name]}{' '}
                <span className="font-mono text-[10px] text-zinc-500">
                  {stage.status === 'pending' ? pendingLabel : stage.status}
                </span>
              </span>
              {stage.message && <span className="break-words text-[11px] text-zinc-400">{stage.message}</span>}
              {stageRunning && stage.activity && (
                <span className="flex items-start gap-1 break-words text-[11px] text-sky-300" aria-live="polite">
                  <Loader2 className="mt-0.5 size-3 shrink-0 animate-spin" />
                  {stage.activity}
                </span>
              )}
              {hint && <span className="break-words text-[10px] text-zinc-500">{hint}</span>}
            </div>
          </li>
        )
      })}
    </ol>
  )
}

function StageIcon({ status, running }: { status: StageStatus; running: boolean }) {
  const className = 'mt-0.5 size-3.5 shrink-0'
  switch (status) {
    case 'started':
      return running ? (
        <Loader2 className={cn(className, 'animate-spin text-sky-400')} />
      ) : (
        <Circle className={cn(className, 'text-sky-400')} />
      )
    case 'completed':
      return <CheckCircle2 className={cn(className, 'text-emerald-400')} />
    case 'failed':
      return <XCircle className={cn(className, 'text-rose-400')} />
    case 'skipped':
      return <MinusCircle className={cn(className, 'text-zinc-500')} />
    default:
      return <CircleDashed className={cn(className, 'text-zinc-600')} />
  }
}

const STREAM_CLASS = { stdout: 'text-zinc-200', stderr: 'text-amber-300', bridge: 'text-sky-300' } as const

function LogLine({ entry }: { entry: LogEntry }) {
  if (entry.kind === 'stage') {
    return (
      <div className="my-0.5 text-violet-300">
        ── stage {entry.stage}: {entry.status}
        {entry.message ? ` — ${entry.message}` : ''}
      </div>
    )
  }
  if (entry.kind === 'error') {
    return (
      <div className="text-rose-300">
        error [{entry.code}]: {entry.message}
      </div>
    )
  }
  if (entry.kind === 'progress') {
    const failed = entry.progress.event === 'step_failed'
    return (
      <div className="flex gap-2">
        <span className="shrink-0 select-none text-zinc-600">{formatTime(entry.ts)}</span>
        <span className="w-12 shrink-0 select-none text-zinc-600">codeql</span>
        <span className={cn('min-w-0 whitespace-pre-wrap break-words', failed ? 'text-rose-300' : entry.progress.event === 'heartbeat' ? 'text-zinc-400' : 'text-emerald-300')}>
          {entry.progress.text}
        </span>
      </div>
    )
  }
  return (
    <div className="flex gap-2">
      <span className="shrink-0 select-none text-zinc-600">{formatTime(entry.ts)}</span>
      <span className="w-12 shrink-0 select-none text-zinc-600">{entry.stream}</span>
      <span className={cn('min-w-0 whitespace-pre-wrap break-all', STREAM_CLASS[entry.stream])}>{entry.text}</span>
    </div>
  )
}

function entryToText(entry: LogEntry): string {
  if (entry.kind === 'stage') return `-- stage ${entry.stage}: ${entry.status}${entry.message ? ` - ${entry.message}` : ''}`
  if (entry.kind === 'error') return `error [${entry.code}]: ${entry.message}`
  if (entry.kind === 'progress') return `${entry.ts} codeql ${entry.progress.text}`
  return `${entry.ts} ${entry.stream} ${entry.text}`
}
