import { AlertTriangle, CheckCircle2, FolderCog, Info, Lightbulb, XCircle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { PluginDiagnosticSeverity, PluginDiagnosticView } from '@/types/api'
import {
  diagnosticSummary,
  directoryStateLabel,
  LEGACY_PLUGINS_VIEW_NOTE,
  PLUGIN_DIRECTORY_READ_ONLY_NOTE,
  PLUGIN_DIRECTORY_SOURCE_LABEL,
  type PluginsTabView,
} from './plugins-format'

/**
 * Where the bridge looks for plugin adapters, where that setting comes from, and what discovery
 * reported. Read-only: the directory is chosen on the bridge host, never in the console.
 */
export function PluginDirectoryPanel({ view }: { view: PluginsTabView }) {
  const state = directoryStateLabel(view)
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-border/60 bg-card/40 p-3 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <FolderCog className="size-3.5 text-primary" />
        <span className="font-semibold text-zinc-100">Plugin directory</span>
        <Badge variant="outline" className="font-mono text-[10px]" title="Where the directory comes from">
          {view.directorySource === 'none' ? 'not configured' : PLUGIN_DIRECTORY_SOURCE_LABEL[view.directorySource]}
        </Badge>
        {state && (
          <Badge
            variant="outline"
            className={cn('text-[10px]', view.directoryExists ? 'border-emerald-500/40 text-emerald-300' : 'border-amber-500/40 text-amber-300')}
          >
            {view.directoryExists ? <CheckCircle2 className="size-3" /> : <AlertTriangle className="size-3" />}
            {state}
          </Badge>
        )}
      </div>

      {view.directory ? (
        <span className="break-all font-mono text-[11px] text-zinc-200">{view.directory}</span>
      ) : (
        <span className="text-zinc-400">No plugin directory is in use, so no adapter can be listed, probed or run.</span>
      )}

      {view.hint && (
        <p className="flex items-start gap-1.5 text-zinc-300">
          <Lightbulb className="mt-0.5 size-3.5 shrink-0 text-amber-300" />
          <span className="break-words">{view.hint}</span>
        </p>
      )}

      <p className="text-[11px] text-muted-foreground">{PLUGIN_DIRECTORY_READ_ONLY_NOTE}</p>
      {view.legacy && <p className="text-[11px] text-amber-300/80">{LEGACY_PLUGINS_VIEW_NOTE}</p>}

      {view.diagnostics.length > 0 && <PluginDiagnosticsList diagnostics={view.diagnostics} />}
    </div>
  )
}

const SEVERITY_ICON: Record<PluginDiagnosticSeverity, { icon: typeof Info; className: string }> = {
  error: { icon: XCircle, className: 'text-rose-400' },
  warning: { icon: AlertTriangle, className: 'text-amber-400' },
  info: { icon: Info, className: 'text-sky-400' },
}

function PluginDiagnosticsList({ diagnostics }: { diagnostics: PluginDiagnosticView[] }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
        Diagnostics · {diagnosticSummary(diagnostics)}
      </span>
      <ul className="flex flex-col divide-y divide-border/40 rounded-md border border-border/40 bg-background/40">
        {diagnostics.map((diagnostic, index) => {
          const { icon: Icon, className } = SEVERITY_ICON[diagnostic.severity]
          return (
            <li key={`${diagnostic.code}:${diagnostic.path ?? ''}:${index}`} className="flex gap-2 p-2">
              <Icon className={cn('mt-0.5 size-3.5 shrink-0', className)} aria-label={diagnostic.severity} />
              <div className="flex min-w-0 flex-col gap-0.5">
                <span className="flex flex-wrap items-center gap-1.5">
                  <span className={cn('text-[10px] font-semibold uppercase', className)}>{diagnostic.severity}</span>
                  <code className="break-all font-mono text-[11px] text-zinc-200">{diagnostic.code}</code>
                </span>
                {diagnostic.message && <span className="break-words text-zinc-300">{diagnostic.message}</span>}
                {diagnostic.path && <span className="break-all font-mono text-[10px] text-zinc-500">{diagnostic.path}</span>}
              </div>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
