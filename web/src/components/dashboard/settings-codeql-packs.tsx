import { useEffect, useRef, useState } from 'react'
import { Download, Loader2, Package, RefreshCw, Square } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import { cn } from '@/lib/utils'
import type { CodeqlPackStatus, CodeqlPacksDownloadView, CodeqlPacksStreamEvent, CodeqlSettingsView } from '@/types/api'
import { downloadOutcomeTitle, packStatusText, PACKS_DOWNLOAD_STOP_TEXT, PACKS_STOPPING_TEXT, runningText, waitForPackDownloadToEnd } from './codeql-text'
import { formatBytes, formatTime } from './console-format'
import { ConfirmDialog, ErrorState, GatedButton, LoadingRows, TimeAgo } from './settings-kit'

interface DownloadLine {
  id: number
  ts: string
  text: string
  tone: 'progress' | 'heartbeat' | 'failed' | 'bridge' | 'stderr'
}

const MAX_LINES = 300

const STATUS_CLASS: Record<CodeqlPackStatus, string> = {
  present: 'border-emerald-500/30 text-emerald-300',
  downloaded: 'border-emerald-500/30 text-emerald-300',
  missing: 'border-amber-500/30 text-amber-300',
  failed: 'border-rose-500/30 text-rose-300',
  not_analysable: 'border-zinc-700 text-zinc-400',
}

const TONE_CLASS: Record<DownloadLine['tone'], string> = {
  progress: 'text-emerald-300',
  heartbeat: 'text-zinc-400',
  failed: 'text-rose-300',
  bridge: 'text-sky-300',
  stderr: 'text-amber-300',
}

/**
 * Settings > CodeQL > Query packs: which query packs the configured suite needs per language,
 * whether each is present (CodeQL distribution or the bridge's pack cache), and a download of the
 * missing ones ahead of scans, with live progress. Closing the stream (Stop, or leaving the page)
 * stops the download; completed packs stay in the cache.
 */
export function CodeqlPacksPanel({ settings, onChanged }: { settings: CodeqlSettingsView; onChanged: () => void }) {
  const { can } = useConsole()
  const forceRef = useRef(false)
  const resource = useResource(`settings:codeql:packs:${settings.settings.suite}`, (signal) => {
    const fresh = forceRef.current
    forceRef.current = false
    return api.codeql.packs(signal, fresh)
  })
  const [deselected, setDeselected] = useState<Set<string>>(() => new Set())
  const [downloading, setDownloading] = useState(false)
  const [lines, setLines] = useState<DownloadLine[]>([])
  const [activity, setActivity] = useState<string | null>(null)
  const [result, setResult] = useState<CodeqlPacksDownloadView | null>(null)
  const [failure, setFailure] = useState<unknown>(null)
  const [stopped, setStopped] = useState(false)
  const [stopping, setStopping] = useState(false)
  const [confirmStop, setConfirmStop] = useState(false)
  const controllerRef = useRef<AbortController | null>(null)
  const waitRef = useRef<AbortController | null>(null)
  const mountedRef = useRef(true)
  const nextIdRef = useRef(0)

  // Leaving the page closes the stream, which stops the download on the bridge.
  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      controllerRef.current?.abort()
      waitRef.current?.abort()
    }
  }, [])

  const refresh = (fresh: boolean) => {
    forceRef.current = fresh
    resource.reload()
  }

  const append = (text: string, tone: DownloadLine['tone'], ts: string) => {
    const id = nextIdRef.current++
    setLines((current) => [...current, { id, ts, text, tone }].slice(-MAX_LINES))
  }

  const onEvent = (event: CodeqlPacksStreamEvent) => {
    if (event.type === 'progress') {
      setActivity(event.progress.text)
      const tone = event.progress.event === 'step_failed' ? 'failed' : event.progress.event === 'heartbeat' ? 'heartbeat' : 'progress'
      append(event.progress.text, tone, event.ts)
    } else if (event.type === 'log') {
      append(event.text, event.stream === 'stderr' ? 'stderr' : 'bridge', event.ts)
    }
  }

  const packs = resource.data
  const missing = packs?.missing ?? []
  const chosen = missing.filter((language) => !deselected.has(language))

  async function startDownload() {
    if (controllerRef.current !== null || chosen.length === 0) return
    const controller = new AbortController()
    controllerRef.current = controller
    setDownloading(true)
    setLines([])
    setActivity(null)
    setResult(null)
    setFailure(null)
    setStopped(false)
    try {
      const outcome = await api.codeql.downloadPacks({ languages: chosen }, onEvent, controller.signal)
      setResult(outcome)
      if (outcome.packs.available) resource.setData(outcome.packs)
      const title = downloadOutcomeTitle(outcome)
      if (outcome.outcome === 'completed' || outcome.outcome === 'nothing_to_do') toast.success(title, { description: outcome.message })
      else toast.error(title, { description: outcome.message })
    } catch (error) {
      if (controller.signal.aborted || (error instanceof DOMException && error.name === 'AbortError')) setStopped(true)
      else {
        setFailure(error)
        toast.error('The query packs were not downloaded', { description: errorMessage(error) })
      }
    } finally {
      if (controllerRef.current === controller) controllerRef.current = null
      setDownloading(false)
      setActivity(null)
      if (controller.signal.aborted && mountedRef.current) {
        // The bridge keeps the CodeQL lock until the core has stopped CodeQL and exited; a listing
        // read right away would still report this download as running. Wait until it no longer does.
        setStopping(true)
        const waiter = new AbortController()
        waitRef.current = waiter
        const view = await waitForPackDownloadToEnd(() => api.codeql.packs(waiter.signal, true), { signal: waiter.signal })
        if (waitRef.current === waiter) waitRef.current = null
        if (!waiter.signal.aborted && mountedRef.current) {
          if (view) resource.setData(view)
          else refresh(true)
          setStopping(false)
          onChanged()
        }
      } else if (mountedRef.current) {
        refresh(true)
        onChanged()
      }
    }
  }

  if (resource.error) return <ErrorState title="Could not read the CodeQL query packs" error={resource.error} onRetry={() => refresh(true)} />
  if (!packs) return <LoadingRows rows={1} className="h-24" />

  const blockedReason = stopping
    ? PACKS_STOPPING_TEXT
    : !packs.available
    ? (packs.problem ?? 'The query packs cannot be read now.')
    : downloading
      ? null
      : packs.downloadBlockedReason
        ? packs.downloadBlockedReason
        : missing.length === 0
          ? 'Every analysable language has its query pack.'
          : chosen.length === 0
            ? 'Select at least one language to download.'
            : null

  return (
    <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-2 min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1.5">
          <Package className="size-3" />
          Query packs ({packs.suite} suite)
        </span>
        <Button type="button" size="xs" variant="ghost" onClick={() => refresh(true)} disabled={resource.loading || downloading || stopping}>
          <RefreshCw className={cn('size-3', resource.loading && 'animate-spin')} />
          Refresh
        </Button>
      </div>
      <p className="text-[11px] text-muted-foreground">
        Each analysed language needs its CodeQL query pack (codeql/&lt;language&gt;-queries) with the suite file. Packs come from the CodeQL
        distribution (a CodeQL bundle ships them) or from the bridge&apos;s pack cache. A missing pack makes the first scan download it
        (when pack download is allowed), which can take several minutes per pack on a slow connection; downloading them here first
        avoids that wait. Checked <TimeAgo iso={packs.checkedAt} />.
      </p>

      {!packs.available ? (
        <p className="text-[11px] text-amber-300/90">{packs.problem}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-[11px]">
            <thead>
              <tr className="text-left text-muted-foreground">
                <th className="py-1 pr-2 font-normal">Download</th>
                <th className="py-1 pr-2 font-normal">Language</th>
                <th className="py-1 pr-2 font-normal">Status</th>
                <th className="py-1 pr-2 font-normal">Version</th>
                <th className="py-1 pr-2 font-normal">Size</th>
                <th className="py-1 font-normal">Location or reason</th>
              </tr>
            </thead>
            <tbody>
              {packs.languages.map((pack) => {
                const isMissing = missing.includes(pack.language)
                return (
                  <tr key={pack.language} className="border-t border-border/20 align-top">
                    <td className="py-1 pr-2">
                      {isMissing ? (
                        <input
                          type="checkbox"
                          aria-label={`Download ${pack.pack ?? pack.language}`}
                          checked={!deselected.has(pack.language)}
                          disabled={downloading || !can('settings:write')}
                          onChange={(event) =>
                            setDeselected((current) => {
                              const next = new Set(current)
                              if (event.target.checked) next.delete(pack.language)
                              else next.add(pack.language)
                              return next
                            })
                          }
                        />
                      ) : null}
                    </td>
                    <td className="py-1 pr-2 font-mono">{pack.language}</td>
                    <td className="py-1 pr-2">
                      <Badge variant="outline" className={cn('text-[10px]', STATUS_CLASS[pack.status])}>
                        {packStatusText(pack)}
                      </Badge>
                    </td>
                    <td className="py-1 pr-2 font-mono">{pack.version ?? '—'}</td>
                    <td className="py-1 pr-2 whitespace-nowrap">{pack.sizeBytes !== null ? formatBytes(pack.sizeBytes) : '—'}</td>
                    <td className="py-1 break-all">
                      {pack.location ? <span className="font-mono">{pack.location}</span> : <span className="text-muted-foreground">{pack.reason ?? '—'}</span>}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {stopping ? (
        <p className="flex items-start gap-1 text-[11px] text-sky-300" aria-live="polite">
          <Loader2 className="mt-0.5 size-3 shrink-0 animate-spin" />
          {PACKS_STOPPING_TEXT}
        </p>
      ) : (
        packs.running && !downloading && <p className="text-[11px] text-sky-300">{runningText(packs.running)}</p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {downloading ? (
          <Button type="button" size="sm" variant="destructive" onClick={() => setConfirmStop(true)}>
            <Square className="fill-current" />
            Stop download
          </Button>
        ) : (
          <GatedButton permission="settings:write" variant="outline" disabled={blockedReason !== null} onClick={() => void startDownload()}>
            <Download className="size-3" />
            Download missing packs{chosen.length > 0 ? ` (${chosen.join(', ')})` : ''}
          </GatedButton>
        )}
        {!downloading && blockedReason && can('settings:write') && <span className="text-[10px] text-muted-foreground">{blockedReason}</span>}
      </div>
      <p className="text-[10px] text-muted-foreground">
        Runs <code>sentra codeql packs --download</code> with this bridge&apos;s codeql launcher: one <code>codeql pack download</code> per
        pack from the registry CodeQL is configured for (by default GitHub&apos;s container registry, ghcr.io) into the pack cache, within
        the pack download timeout ({settings.settings.downloadTimeoutMinutes} min). It shares the one-at-a-time CodeQL lock with host
        analysis, so scans skip host analysis while it runs. Leaving this page or pressing Stop stops it; packs that finished
        downloading stay in the cache.
      </p>

      {downloading && activity && (
        <p className="flex items-start gap-1 text-[11px] text-sky-300" aria-live="polite">
          <Loader2 className="mt-0.5 size-3 shrink-0 animate-spin" />
          {activity}
        </p>
      )}
      {lines.length > 0 && (
        <div className="max-h-48 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-2 font-mono text-[11px] leading-relaxed">
          {lines.map((line) => (
            <div key={line.id} className="flex gap-2">
              <span className="shrink-0 select-none text-zinc-600">{formatTime(line.ts)}</span>
              <span className={cn('min-w-0 whitespace-pre-wrap break-words', TONE_CLASS[line.tone])}>{line.text}</span>
            </div>
          ))}
        </div>
      )}
      {result && (
        <p className={cn('text-[11px]', result.outcome === 'completed' || result.outcome === 'nothing_to_do' ? 'text-emerald-300' : 'text-amber-300')}>
          {downloadOutcomeTitle(result)}: {result.message}
        </p>
      )}
      {stopped && <p className="text-[11px] text-amber-300">{PACKS_DOWNLOAD_STOP_TEXT}</p>}
      {failure !== null && <p className="text-[11px] text-rose-300">{errorMessage(failure)}</p>}

      <ConfirmDialog
        open={confirmStop}
        onOpenChange={setConfirmStop}
        title="Stop the query pack download?"
        confirmLabel="Stop download"
        destructive
        onConfirm={async () => {
          controllerRef.current?.abort()
        }}
      >
        <p>{PACKS_DOWNLOAD_STOP_TEXT}</p>
      </ConfirmDialog>
    </div>
  )
}
