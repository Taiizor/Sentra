import { useState } from 'react'
import { History, Loader2, Play, SquareTerminal, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { cn } from '@/lib/utils'
import type { ConsoleCommand, ConsoleRunView } from '@/types/api'
import { formatDuration, formatTime, tryPrettyJson } from './console-format'
import { addConsoleHistoryEntry, clearConsoleHistory, useConsoleHistory, type ConsoleHistoryEntry } from './console-history'
import { GatedButton, NoTenantState, OutputBlock, SectionCard, TabHeader } from './console-kit'

const COMMANDS: { command: ConsoleCommand; template: string; description: string }[] = [
  { command: 'version', template: 'sentra --version --json', description: 'Version of the core binary the bridge uses.' },
  {
    command: 'status',
    template: 'sentra status --database <workspace core store> --workspace <workspace> --json',
    description: "Core session state for this workspace's core store. Read-only.",
  },
  {
    command: 'scan',
    template: 'sentra scan --workspace <workspace> --json',
    description: 'Heuristic static analysis of the workspace, shown as raw output. Use "Scan workspace" to record a run and update findings.',
  },
  {
    command: 'codeql',
    template: 'sentra codeql --workspace <workspace> --json',
    description: 'Counts files per CodeQL language and prints suggested commands. CodeQL itself is not run.',
  },
  {
    command: 'inventory',
    template: 'sentra inventory --workspace <workspace> --json',
    description: 'Lockfiles and locked packages parsed by the core. Read-only, no network access.',
  },
  { command: 'skills', template: 'sentra skills list --json', description: 'Skill catalog embedded in the core binary.' },
  {
    command: 'plugins',
    template: 'sentra plugin list --dir <plugin directory> --json',
    description:
      "Adapter manifests in the bridge's plugin directory (SENTRA_PLUGIN_DIR, otherwise the core's platform default; refused when there is none, see the Plugins tab). Lists manifests only; no adapter is started.",
  },
]

function quoteArg(arg: string): string {
  return /[\s"']/.test(arg) ? JSON.stringify(arg) : arg
}

/**
 * Runs one allow-listed core CLI command for the selected workspace and shows its real
 * output. The bridge decides the exact argv; the console only picks the command.
 */
export function ScannerConsole() {
  const { tenant, session } = useConsole()
  const history = useConsoleHistory(session.principal)
  const [command, setCommand] = useState<ConsoleCommand>('status')
  const [busy, setBusy] = useState(false)
  const [selectedId, setSelectedId] = useState<number | null>(null)

  const definition = COMMANDS.find((entry) => entry.command === command) ?? COMMANDS[0]
  const selected = history.find((entry) => entry.id === selectedId) ?? history[0] ?? null

  const run = async () => {
    if (!tenant || busy) return
    setBusy(true)
    const requestedAt = new Date().toISOString()
    let result: ConsoleRunView | null = null
    let error: string | null = null
    try {
      result = await api.console.run(tenant.tenantId, command)
    } catch (failure) {
      error = errorMessage(failure)
    } finally {
      setBusy(false)
    }
    const entry = addConsoleHistoryEntry({
      principal: session.principal,
      tenantId: tenant.tenantId,
      tenantName: tenant.name,
      command,
      requestedAt,
      result,
      error,
    })
    setSelectedId(entry.id)
  }

  return (
    <div className="flex flex-col gap-4">
      <TabHeader
        icon={<SquareTerminal className="size-4 text-emerald-400" />}
        title="Core CLI console"
        description="Runs one allow-listed `sentra` command on the bridge host against the selected workspace and shows its exit code and output."
      />

      {!tenant ? (
        <NoTenantState feature="The CLI console" />
      ) : (
        <SectionCard icon={<SquareTerminal className="size-4 text-zinc-400" />} title="Command">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
            <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
              Command
              <Select value={command} onValueChange={(value) => value && setCommand(value as ConsoleCommand)}>
                <SelectTrigger className="w-48 font-mono text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {COMMANDS.map((entry) => (
                    <SelectItem key={entry.command} value={entry.command}>
                      {entry.command}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </label>
            <GatedButton permission="console:run" size="default" disabled={busy} onClick={() => void run()}>
              {busy ? <Loader2 className="animate-spin" /> : <Play />}
              Run
            </GatedButton>
          </div>
          <div className="flex flex-col gap-1 rounded-md border border-border/40 bg-background/40 p-2.5">
            <span className="text-xs text-zinc-300">{definition.description}</span>
            <code className="break-all font-mono text-[11px] text-zinc-400">{definition.template}</code>
            <span className="text-[10px] text-zinc-500">
              The bridge fills in the paths for {tenant.name} and returns the exact argv it executed with the result. Output
              is capped at 256 KiB per stream.
            </span>
          </div>
        </SectionCard>
      )}

      {history.length > 0 && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[16rem_1fr]">
          <SectionCard
            icon={<History className="size-4 text-zinc-400" />}
            title="History"
            description="This browser tab only; cleared on reload."
            actions={
              <Button
                variant="ghost"
                size="icon-xs"
                aria-label="Clear history"
                title="Clear history"
                onClick={() => {
                  clearConsoleHistory(session.principal)
                  setSelectedId(null)
                }}
              >
                <Trash2 />
              </Button>
            }
          >
            <ul className="flex flex-col gap-1">
              {history.map((entry) => (
                <li key={entry.id}>
                  <button
                    type="button"
                    onClick={() => setSelectedId(entry.id)}
                    className={cn(
                      'flex w-full items-center justify-between gap-2 rounded-md border px-2 py-1.5 text-left text-xs transition-colors',
                      selected?.id === entry.id ? 'border-primary/50 bg-primary/10' : 'border-transparent hover:bg-muted/50',
                    )}
                  >
                    <span className="flex min-w-0 flex-col">
                      <span className="font-mono text-zinc-100">{entry.command}</span>
                      <span className="truncate text-[10px] text-zinc-500">
                        {formatTime(entry.requestedAt)} · {entry.tenantName}
                      </span>
                    </span>
                    <ExitBadge entry={entry} />
                  </button>
                </li>
              ))}
            </ul>
          </SectionCard>

          {selected && <RunOutput key={selected.id} entry={selected} />}
        </div>
      )}
    </div>
  )
}

function ExitBadge({ entry }: { entry: ConsoleHistoryEntry }) {
  if (!entry.result) {
    return (
      <Badge variant="outline" className="shrink-0 border-rose-500/30 font-mono text-[10px] text-rose-300">
        error
      </Badge>
    )
  }
  const ok = entry.result.exitCode === 0 && !entry.result.timedOut
  return (
    <Badge
      variant="outline"
      className={cn('shrink-0 font-mono text-[10px]', ok ? 'border-emerald-500/30 text-emerald-300' : 'border-rose-500/30 text-rose-300')}
    >
      {entry.result.timedOut ? 'timeout' : `exit ${entry.result.exitCode}`}
    </Badge>
  )
}

function RunOutput({ entry }: { entry: ConsoleHistoryEntry }) {
  const [raw, setRaw] = useState(false)
  const result = entry.result
  const pretty = result ? tryPrettyJson(result.stdout) : null
  return (
    <SectionCard
      icon={<SquareTerminal className="size-4 text-emerald-400" />}
      title={`${entry.command} · ${entry.tenantName}`}
      description={`Requested ${formatTime(entry.requestedAt)}`}
      actions={
        pretty && (
          <Button variant="ghost" size="xs" onClick={() => setRaw((value) => !value)}>
            {raw ? 'Formatted JSON' : 'Raw stdout'}
          </Button>
        )
      }
    >
      {!result ? (
        <p className="text-xs text-rose-300">The bridge refused or failed the request: {entry.error}</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2 text-[11px] text-zinc-400">
            <ExitBadge entry={entry} />
            <span>duration {formatDuration(result.durationMs)}</span>
            {result.timedOut && <span className="text-rose-300">killed after the bridge timeout</span>}
          </div>
          <code className="break-all rounded border border-zinc-800 bg-zinc-950 px-2 py-1 font-mono text-[11px] text-zinc-300">
            $ {result.argv.map(quoteArg).join(' ')}
          </code>
          <OutputBlock label={pretty && !raw ? 'stdout (JSON, formatted)' : 'stdout'} text={pretty && !raw ? pretty : result.stdout} maxHeightClass="max-h-[28rem]" />
          {result.stderr && <OutputBlock label="stderr" text={result.stderr} tone="error" maxHeightClass="max-h-48" />}
        </>
      )}
    </SectionCard>
  )
}
