import { useState, type ReactNode } from 'react'
import { FileText, ShieldAlert, Terminal } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { useResource } from '@/lib/use-resource'
import type { CodeqlSettingsView, CodeqlSuite, UpdateCodeqlSettingsRequest } from '@/types/api'
import { parseExcludeText, runningText } from './codeql-text'
import { CodeqlPacksPanel } from './settings-codeql-packs'
import { permissionHint } from './settings-format'
import { ConfirmDialog, ErrorState, LoadingRows, TimeAgo } from './settings-kit'

const SUITE_LABEL: Record<CodeqlSuite, string> = {
  'code-scanning': 'code-scanning (default queries)',
  'security-extended': 'security-extended (more queries, more false positives)',
}

const LAUNCHER_SOURCE_LABEL: Record<string, string> = {
  environment: 'SENTRA_CODEQL_BIN',
  process_path: 'process PATH',
  persisted_system_path: 'system PATH (persisted)',
  persisted_user_path: 'user PATH (persisted)',
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-start gap-0.5 sm:gap-3 py-1 border-b border-border/20 last:border-b-0">
      <span className="text-[11px] text-muted-foreground sm:w-44 shrink-0">{label}</span>
      <span className="text-[11px] text-foreground min-w-0 break-words">{children}</span>
    </div>
  )
}

/**
 * CodeQL host analysis: off by default, enabled only by an admin who accepts the CodeQL licence
 * terms in the same request. Import and GitHub sync (Findings tab) work without it.
 */
export function SettingsCodeql() {
  const { can, invalidate } = useConsole()
  const resource = useResource('settings:codeql', (signal) => api.codeql.settings(signal))
  const [confirmEnable, setConfirmEnable] = useState(false)
  const [termsChecked, setTermsChecked] = useState(false)
  const [saving, setSaving] = useState(false)

  async function save(body: UpdateCodeqlSettingsRequest, success: string) {
    setSaving(true)
    try {
      const next = await api.codeql.updateSettings(body)
      resource.setData(next)
      invalidate()
      toast.success(success)
    } catch (error) {
      toast.error('The CodeQL settings were not changed', { description: errorMessage(error) })
      throw error
    } finally {
      setSaving(false)
    }
  }

  if (resource.error) return <ErrorState title="Could not load the CodeQL settings" error={resource.error} onRetry={resource.reload} />
  if (!resource.data) return <LoadingRows rows={2} className="h-28" />
  const view = resource.data
  const canWrite = can('settings:write')
  const { settings } = view

  const toggle = (
    <Switch
      checked={settings.enabled}
      disabled={!canWrite || saving}
      onCheckedChange={(checked) => {
        if (checked) {
          setTermsChecked(false)
          setConfirmEnable(true)
        } else void save({ enabled: false }, 'CodeQL host analysis disabled').catch(() => undefined)
      }}
      aria-label="Enable CodeQL host analysis"
    />
  )

  return (
    <div className="flex flex-col gap-3">
      <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-2">
        <div className="flex items-center justify-between gap-3">
          <div className="flex flex-col gap-0.5">
            <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
              <Terminal className="size-3.5 text-muted-foreground" />
              CodeQL host analysis
            </span>
            <span className="text-[11px] text-muted-foreground">
              Scans run <code>sentra codeql analyze</code> on the bridge host with build mode none. Off by default.
            </span>
          </div>
          {canWrite ? (
            toggle
          ) : (
            <Tooltip>
              <TooltipTrigger render={<span className="inline-flex cursor-not-allowed" tabIndex={0} />}>{toggle}</TooltipTrigger>
              <TooltipContent>{permissionHint('settings:write')}</TooltipContent>
            </Tooltip>
          )}
        </div>
        <span className={`text-xs ${settings.enabled ? 'text-emerald-400' : 'text-muted-foreground'}`}>
          {settings.enabled ? 'Enabled' : 'Disabled — scans run only the language probe.'}
        </span>
        {view.skipMessage && (
          <p className="text-[11px] text-amber-300/90">
            {view.skipReason === 'disabled' ? '' : 'A scan would not start host analysis now: '}
            {view.skipMessage}
          </p>
        )}
        {view.running && (
          <p className="text-[11px] text-sky-300">
            {runningText(view.running)} Started <TimeAgo iso={view.running.startedAt} />.
          </p>
        )}
        {settings.termsAcceptedAt && (
          <span className="text-[11px] text-muted-foreground">
            Licence terms accepted by {settings.termsAcceptedBy ?? 'unknown'} <TimeAgo iso={settings.termsAcceptedAt} />.
          </span>
        )}
        {view.updatedAt && (
          <span className="text-[11px] text-muted-foreground">
            Last changed <TimeAgo iso={view.updatedAt} />
            {view.updatedBy ? ` by ${view.updatedBy}` : ''}.
          </span>
        )}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
        <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-1.5 min-w-0">
          <span className="text-[10px] uppercase font-semibold text-muted-foreground">Launcher and storage</span>
          <Row label="codeql launcher">
            {view.launcher.path ? (
              <span className="font-mono break-all">{view.launcher.path}</span>
            ) : (
              <span className="text-amber-300">none can be run</span>
            )}
          </Row>
          <Row label="Chosen through">
            {view.launcher.source ? (LAUNCHER_SOURCE_LABEL[view.launcher.source] ?? view.launcher.source) : '—'}
          </Row>
          {view.launcher.problem && <Row label="Problem">{view.launcher.problem}</Row>}
          <Row label="Pack cache">
            <span className="font-mono break-all">{view.packCache}</span>
          </Row>
          <Row label="TypeScript runtime">
            {view.typescriptRuntime ? (
              <span className="font-mono break-all">{view.typescriptRuntime}</span>
            ) : (
              <span className="text-amber-300">not passed</span>
            )}
          </Row>
          {view.typescriptRuntimeNote && <p className="text-[11px] text-muted-foreground">{view.typescriptRuntimeNote}</p>}
          <p className="text-[11px] text-muted-foreground pt-1">
            The launcher is SENTRA_CODEQL_BIN when the host operator sets it, otherwise codeql on the bridge&apos;s process PATH or the
            persisted PATH (on Windows only codeql.exe). It cannot be set in the console.
          </p>
        </div>

        <CodeqlOptions key={view.updatedAt ?? 'defaults'} view={view} canWrite={canWrite} saving={saving} onSave={save} />
      </div>

      <CodeqlPacksPanel settings={view} onChanged={resource.reload} />

      <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-1.5">
        <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1.5">
          <FileText className="size-3" />
          CodeQL licence terms (summary)
        </span>
        <TermsSummary view={view} />
      </div>

      <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-500/5 flex items-start gap-2">
        <ShieldAlert className="size-3.5 mt-0.5 shrink-0 text-amber-400" />
        <p className="text-[11px] text-muted-foreground">{view.isolationNote}</p>
      </div>

      <ConfirmDialog
        open={confirmEnable}
        onOpenChange={setConfirmEnable}
        title="Enable CodeQL host analysis?"
        confirmLabel="Accept terms and enable"
        onConfirm={async () => {
          if (!termsChecked) {
            toast.error('Confirm that you accept the CodeQL licence terms first')
            throw new Error('terms not confirmed')
          }
          await save({ enabled: true, acceptTerms: true }, 'CodeQL host analysis enabled')
        }}
      >
        <p>
          Scans will run CodeQL on this bridge host against the workspace (build mode none: no build, no target code executed; the
          extractors parse the workspace code on the host). Your acceptance is recorded with your name in the audit log.
        </p>
        <TermsSummary view={view} />
        <label className="flex items-start gap-2 text-foreground text-xs pt-1">
          <input type="checkbox" className="mt-0.5" checked={termsChecked} onChange={(event) => setTermsChecked(event.target.checked)} />
          <span>I have read the CodeQL terms in the distribution&apos;s LICENSE.md and my use of CodeQL on this host is permitted by them.</span>
        </label>
      </ConfirmDialog>
    </div>
  )
}

function TermsSummary({ view }: { view: CodeqlSettingsView }) {
  return (
    <div className="flex flex-col gap-1">
      <ul className="list-disc pl-4 text-[11px] text-muted-foreground flex flex-col gap-0.5">
        {view.terms.summary.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
      <p className="text-[11px] text-muted-foreground">
        Authoritative text: {view.terms.location}{' '}
        {view.launcher.licenseFile && (
          <>
            On this host: <span className="font-mono break-all">{view.launcher.licenseFile}</span>.{' '}
          </>
        )}
        Copy published with the CodeQL CLI binaries (it may differ from your version):{' '}
        <a href={view.terms.referenceUrl} target="_blank" rel="noreferrer noopener" className="text-sky-300 hover:underline break-all">
          {view.terms.referenceUrl}
        </a>
        . This summary is not legal advice.
      </p>
    </div>
  )
}

function CodeqlOptions({
  view,
  canWrite,
  saving,
  onSave,
}: {
  view: CodeqlSettingsView
  canWrite: boolean
  saving: boolean
  onSave: (body: UpdateCodeqlSettingsRequest, success: string) => Promise<void>
}) {
  const { settings, bounds } = view
  const [suite, setSuite] = useState<CodeqlSuite>(settings.suite)
  const [allowPackDownload, setAllowPackDownload] = useState(settings.allowPackDownload)
  const [timeout, setTimeoutValue] = useState(String(settings.timeoutMinutes))
  const [downloadTimeout, setDownloadTimeout] = useState(String(settings.downloadTimeoutMinutes))
  const [threads, setThreads] = useState(String(settings.threads))
  const [ram, setRam] = useState(settings.ramMb === null ? '' : String(settings.ramMb))
  const [exclude, setExclude] = useState((settings.excludePaths ?? []).join('\n'))

  const intIn = (text: string, min: number, max: number) => {
    const value = Number(text)
    return Number.isInteger(value) && value >= min && value <= max ? value : null
  }
  const timeoutValue = intIn(timeout, bounds.timeoutMinutes.min, bounds.timeoutMinutes.max)
  const downloadBounds = bounds.downloadTimeoutMinutes ?? { min: 5, max: 180 }
  const downloadTimeoutValue = intIn(downloadTimeout, downloadBounds.min, downloadBounds.max)
  const threadsValue = intIn(threads, bounds.threads.min, bounds.threads.max)
  const ramValue = ram.trim() === '' ? null : intIn(ram.trim(), bounds.ramMb.min, bounds.ramMb.max)
  const ramValid = ram.trim() === '' || ramValue !== null
  const excludeBounds = bounds.excludePaths ?? { maxEntries: 50, maxChars: 200 }
  const excludeParsed = parseExcludeText(exclude, excludeBounds)
  const valid = timeoutValue !== null && downloadTimeoutValue !== null && threadsValue !== null && ramValid && excludeParsed.problem === null
  const disabled = !canWrite || saving

  return (
    <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-2 min-w-0">
      <span className="text-[10px] uppercase font-semibold text-muted-foreground">Analysis options</span>
      <div className="flex items-center justify-between gap-3">
        <span className="text-[11px] text-foreground">Allow query pack download</span>
        <Switch checked={allowPackDownload} disabled={disabled} onCheckedChange={setAllowPackDownload} aria-label="Allow query pack download" />
      </div>
      <p className="text-[11px] text-muted-foreground">
        The CodeQL CLI distribution ships no query packs. With download allowed, a scan downloads the missing packs for the suite
        from GitHub&apos;s container registry (ghcr.io) into the pack cache before analyzing (first run only; several minutes on a slow
        connection). Download them ahead under Query packs below, or install the CodeQL bundle; otherwise analysis is skipped.
      </p>
      <label className="flex flex-col gap-1 text-[11px] text-foreground">
        Query suite
        <Select value={suite} onValueChange={(value) => value && setSuite(value as CodeqlSuite)} disabled={disabled}>
          <SelectTrigger className="h-7.5 text-xs">
            <SelectValue>{(value: string | null) => SUITE_LABEL[(value ?? 'code-scanning') as CodeqlSuite] ?? value}</SelectValue>
          </SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {(Object.keys(SUITE_LABEL) as CodeqlSuite[]).map((id) => (
                <SelectItem key={id} value={id}>
                  {SUITE_LABEL[id]}
                </SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
      </label>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <label className="flex flex-col gap-1 text-[11px] text-foreground">
          Analysis timeout (minutes)
          <Input value={timeout} onChange={(event) => setTimeoutValue(event.target.value)} disabled={disabled} inputMode="numeric" aria-invalid={timeoutValue === null} className="h-7.5 text-xs" />
          <span className="text-[10px] text-muted-foreground">
            {bounds.timeoutMinutes.min}–{bounds.timeoutMinutes.max}. Version check, database creation and analysis together.
          </span>
        </label>
        <label className="flex flex-col gap-1 text-[11px] text-foreground">
          Pack download timeout (minutes)
          <Input
            value={downloadTimeout}
            onChange={(event) => setDownloadTimeout(event.target.value)}
            disabled={disabled}
            inputMode="numeric"
            aria-invalid={downloadTimeoutValue === null}
            className="h-7.5 text-xs"
          />
          <span className="text-[10px] text-muted-foreground">
            {downloadBounds.min}–{downloadBounds.max}. Query pack downloads have their own budget and do not use up the analysis timeout.
          </span>
        </label>
        <label className="flex flex-col gap-1 text-[11px] text-foreground">
          Threads
          <Input value={threads} onChange={(event) => setThreads(event.target.value)} disabled={disabled} inputMode="numeric" aria-invalid={threadsValue === null} className="h-7.5 text-xs" />
          <span className="text-[10px] text-muted-foreground">
            {bounds.threads.min}–{bounds.threads.max}
          </span>
        </label>
        <label className="flex flex-col gap-1 text-[11px] text-foreground">
          RAM (MiB, optional)
          <Input
            value={ram}
            onChange={(event) => setRam(event.target.value)}
            disabled={disabled}
            inputMode="numeric"
            placeholder={view.ramAuto ? `automatic (${view.ramAuto.mb} MiB now)` : 'automatic'}
            aria-invalid={!ramValid}
            className="h-7.5 text-xs"
          />
          <span className="text-[10px] text-muted-foreground">
            {bounds.ramMb.min}–{bounds.ramMb.max}. {view.ramAuto?.rule ?? 'Without a value the bridge chooses the limit from the memory available on the host.'}
          </span>
        </label>
      </div>
      <label className="flex flex-col gap-1 text-[11px] text-foreground">
        Exclude from extraction (one glob per line)
        <Textarea
          value={exclude}
          onChange={(event) => setExclude(event.target.value)}
          disabled={disabled}
          rows={4}
          spellCheck={false}
          aria-invalid={excludeParsed.problem !== null}
          className="font-mono text-xs"
        />
        <span className={`text-[10px] ${excludeParsed.problem ? 'text-rose-300' : 'text-muted-foreground'}`}>
          {excludeParsed.problem
            ? `Not saved: ${excludeParsed.problem}.`
            : `Relative to the workspace, / as separator, no .. and no ':'; at most ${excludeBounds.maxEntries} globs of ${excludeBounds.maxChars} characters. Passed as --exclude (CodeQL's LGTM_INDEX_FILTERS), which the javascript, python, ruby and actions extractors honour, so build and dependency output is not analysed.`}
        </span>
      </label>
      <div className="flex items-center gap-2">
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={disabled || !valid}
          onClick={() =>
            void onSave(
              {
                suite,
                allowPackDownload,
                timeoutMinutes: timeoutValue ?? undefined,
                downloadTimeoutMinutes: downloadTimeoutValue ?? undefined,
                threads: threadsValue ?? undefined,
                ramMb: ramValue,
                excludePaths: excludeParsed.globs,
              },
              'CodeQL analysis options saved',
            ).catch(() => undefined)
          }
        >
          Save options
        </Button>
        {!canWrite && (
          <Badge variant="outline" className="text-[10px]">
            {permissionHint('settings:write')}
          </Badge>
        )}
      </div>
    </div>
  )
}
