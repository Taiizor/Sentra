import { useRef, useState, type ReactNode } from 'react'
import { AlertTriangle, CheckCircle2, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import { cn } from '@/lib/utils'
import type { SystemStatus, ToolAvailability } from '@/types/api'
import {
  describeToolPath,
  describeToolSearchScope,
  EXECUTABLE_SOURCE_LABEL,
  formatDateTime,
  hasConfiguredPath,
  isChosenPath,
  otherCopiesLabel,
  permissionHint,
  persistedPathLabel,
  persistedPathReadState,
  stalePathAdvice,
  TOOL_USAGE_CLASS,
  TOOL_USAGE_LABEL,
  toolActions,
  toolStatus,
  type ToolSearchContext,
} from './console-format'
import { ConfirmDialog } from './console-kit'
import { ToolPathDialog } from './tool-path-dialog'

/**
 * The tools table of the Host & workers page. Tools are found automatically; an administrator
 * (settings:write) can set the path of a tool the bridge never runs when detection misses it.
 * `onToolUpdated` receives the row the bridge returns after a path is set or reset.
 */
export function ToolsSection({ status, onToolUpdated }: { status: SystemStatus; onToolUpdated: (tool: ToolAvailability) => void }) {
  const { can } = useConsole()
  const canWrite = can('settings:write')
  const [editing, setEditing] = useState<ToolAvailability | null>(null)
  const [resetting, setResetting] = useState<ToolAvailability | null>(null)
  const [resetBusy, setResetBusy] = useState(false)
  // Each row's path button ("Set path" / "Change"), and the tool whose dialog is open: saving or
  // resetting re-renders that row (Reset to automatic disappears), so focus is returned to the
  // row's path button explicitly instead of to whatever opened the dialog.
  const pathButtons = useRef(new Map<string, HTMLElement>())
  const focusTool = useRef<string | null>(null)
  const returnFocus = () => (focusTool.current ? pathButtons.current.get(focusTool.current) : undefined) ?? true
  const openEditor = (tool: ToolAvailability) => {
    focusTool.current = tool.name
    setEditing(tool)
  }
  const openReset = (tool: ToolAvailability) => {
    focusTool.current = tool.name
    setResetting(tool)
  }
  const registerPathButton = (name: string) => (element: HTMLElement | null) => {
    if (element) pathButtons.current.set(name, element)
    else pathButtons.current.delete(name)
  }

  const { tools, toolSearch } = status
  const platform = status.host.platform
  const search = { toolSearch, platform }
  const persisted = persistedPathLabel(platform)
  // A tool in a standard install location is "only" there when the persisted PATH was fully read;
  // otherwise the persisted PATH may list its directory too.
  const persistedRead = persistedPathReadState(toolSearch)
  // Tools the bridge's own environment cannot see, grouped by where they were found. Left out:
  // - the running Bun (usage "runtime"): starting the bridge by absolute path from a directory that
  //   is not on PATH is normal and says nothing about a stale PATH (a runtime started from outside
  //   the searched directories has source null and is never listed either);
  // - tools whose path someone chose (in the console or through SENTRA_GH_BIN), including a console
  //   path that is broken: the row itself says so, and PATH advice would not apply to that choice.
  const offPath = tools.filter(
    (tool) => tool.available && tool.usage !== 'runtime' && !isChosenPath(tool) && !hasConfiguredPath(tool),
  )
  const persistedOnly = offPath.filter((tool) => tool.source === 'persisted_system_path' || tool.source === 'persisted_user_path')
  const wellKnownOnly = offPath.filter((tool) => tool.source === 'well_known')

  async function reset() {
    const tool = resetting
    if (!tool || resetBusy) return
    setResetBusy(true)
    try {
      const response = await api.system.clearToolPath(tool.name)
      onToolUpdated(response.tool)
      setResetting(null)
      toast.success(`${tool.name}: back to automatic detection`, {
        description: response.tool.available && response.tool.path ? `Found ${response.tool.path}` : 'Automatic detection did not find it.',
      })
    } catch (failure) {
      toast.error(`${tool.name}: the path was not reset`, { description: errorMessage(failure) })
    } finally {
      setResetBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-[11px] text-muted-foreground">
        Searched {toolSearch.searchedDirectories} {toolSearch.searchedDirectories === 1 ? 'directory' : 'directories'} at{' '}
        {formatDateTime(toolSearch.refreshedAt)}: {describeToolSearchScope(toolSearch, platform)}.
        {toolSearch.skippedNetworkEntries > 0 &&
          ` ${toolSearch.skippedNetworkEntries} UNC or device PATH ${toolSearch.skippedNetworkEntries === 1 ? 'entry was' : 'entries were'} skipped on purpose: listing a network share would make the bridge authenticate to that host.`}
      </p>
      {toolSearch.persistedPathError &&
        (toolSearch.persistedPathRead ? (
          <p className="text-[11px] text-amber-300">
            Part of {persisted} could not be read ({toolSearch.persistedPathError}). The entries that were read are included in the
            search.
          </p>
        ) : (
          <p className="text-[11px] text-amber-300">
            {persisted.charAt(0).toUpperCase() + persisted.slice(1)} could not be read ({toolSearch.persistedPathError}). Only the
            bridge process PATH and standard install locations were searched.
          </p>
        ))}
      {persistedOnly.length > 0 && (
        <OffPathBanner tools={persistedOnly} found={`in ${persisted}`} advice={stalePathAdvice(platform, 'persisted')} />
      )}
      {wellKnownOnly.length > 0 && (
        <OffPathBanner
          tools={wellKnownOnly}
          found={persistedRead === 'read' ? 'only in a standard install location' : 'in a standard install location'}
          advice={stalePathAdvice(platform, 'well_known', persistedRead)}
        />
      )}
      {(persistedOnly.length > 0 || wellKnownOnly.length > 0) && (
        <p className="text-[11px] text-muted-foreground">
          The only tool the bridge runs itself is gh, from SENTRA_GH_BIN, the process PATH or the persisted PATH (never from a
          standard install location or a path set in the console); its usage note names the file. Programs the bridge starts, such
          as the core CLI and plugin adapters, look tools up on the bridge process PATH only.
        </p>
      )}
      <Table className="text-xs">
        <TableHeader>
          <TableRow>
            <TableHead>Tool</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Path</TableHead>
            <TableHead>Used by the bridge</TableHead>
            {canWrite && (
              <TableHead>
                <span className="sr-only">Path actions</span>
              </TableHead>
            )}
          </TableRow>
        </TableHeader>
        <TableBody>
          {tools.map((tool) => (
            <ToolRow
              key={tool.name}
              tool={tool}
              search={search}
              actions={
                canWrite ? (
                  <ToolActions tool={tool} onEdit={openEditor} onReset={openReset} pathButtonRef={registerPathButton(tool.name)} />
                ) : null
              }
            />
          ))}
        </TableBody>
      </Table>
      <p className="text-[11px] text-muted-foreground">
        {canWrite
          ? 'Set a path when automatic detection misses a tool or finds the wrong installation. gh and bun cannot be set here: the bridge runs gh and runs on bun, and a path entered in the console never becomes a program the bridge runs.'
          : `When automatic detection misses a tool, its path can be set here. ${permissionHint('settings:write')}.`}
      </p>

      <ToolPathDialog tool={editing} platform={platform} onClose={() => setEditing(null)} onSaved={onToolUpdated} finalFocus={returnFocus} />
      <ConfirmDialog
        finalFocus={returnFocus}
        open={resetting !== null}
        onOpenChange={(open) => !open && setResetting(null)}
        title={`Reset ${resetting?.name ?? 'the tool'} to automatic detection?`}
        description={
          <>
            <span>
              Removes the path set in the console
              {resetting?.configuredPath ? (
                <>
                  {' '}
                  (<span className="font-mono break-all">{resetting.configuredPath}</span>)
                </>
              ) : null}
              . The row then shows what automatic detection finds.
            </span>
            <span>The change applies to the whole bridge and is recorded in the operator audit log.</span>
          </>
        }
        confirmLabel="Reset to automatic"
        busy={resetBusy}
        onConfirm={() => void reset()}
      />
    </div>
  )
}

function OffPathBanner({ tools, found, advice }: { tools: ToolAvailability[]; found: string; advice: string }) {
  return (
    <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 p-2.5 text-[11px] text-amber-200">
      <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-amber-400" />
      <span>
        <span className="font-mono">{tools.map((tool) => tool.name).join(', ')}</span> {tools.length === 1 ? 'was' : 'were'} found{' '}
        {found}, but not on the bridge process PATH. {advice}
      </span>
    </div>
  )
}

function ToolRow({ tool, search, actions }: { tool: ToolAvailability; search: ToolSearchContext; actions: ReactNode | null }) {
  const otherCopies = otherCopiesLabel(tool)
  const chosen = isChosenPath(tool)
  return (
    <TableRow>
      <TableCell className="align-top font-mono text-[11px]">{tool.name}</TableCell>
      <TableCell className="max-w-56 align-top whitespace-normal">
        <ToolStatusCell tool={tool} />
      </TableCell>
      <TableCell className="max-w-96 align-top">
        <div className="flex min-w-0 flex-col gap-0.5" title={describeToolPath(tool, search)}>
          {tool.path ? (
            <>
              <span className="truncate font-mono text-[11px] text-zinc-300">{tool.path}</span>
              <span className="truncate text-[10px] text-muted-foreground">
                {tool.source ? (
                  <span className={chosen ? 'text-sky-300' : undefined}>{EXECUTABLE_SOURCE_LABEL[tool.source] ?? tool.source}</span>
                ) : (
                  'outside the searched directories'
                )}
                {tool.source && !chosen && !tool.onProcessPath && <span className="text-amber-300"> · not on the process PATH</span>}
                {tool.resolvedPath && (tool.resolvedVia === 'scoop_shim' ? ' · Scoop shim' : ' · symlink')}
                {otherCopies && ` · ${otherCopies}`}
              </span>
            </>
          ) : (
            <span className="text-[11px] text-zinc-500">not found</span>
          )}
          {tool.configuredPathProblem &&
            (hasConfiguredPath(tool) ? (
              <span className="truncate text-[10px] text-amber-300">
                set in console: <span className="font-mono">{tool.configuredPath}</span> (cannot be used)
              </span>
            ) : (
              <span className="truncate text-[10px] text-amber-300">SENTRA_GH_BIN is set but cannot be used</span>
            ))}
        </div>
      </TableCell>
      <TableCell className="min-w-56 align-top whitespace-normal">
        <div className="flex flex-col items-start gap-0.5">
          <Badge variant="outline" className={cn('font-mono text-[10px]', TOOL_USAGE_CLASS[tool.usage])}>
            {TOOL_USAGE_LABEL[tool.usage]}
          </Badge>
          {tool.usageNote && <span className="text-[10px] leading-snug text-muted-foreground">{tool.usageNote}</span>}
        </div>
      </TableCell>
      {actions !== null && <TableCell className="max-w-56 align-top whitespace-normal">{actions}</TableCell>}
    </TableRow>
  )
}

const STATUS_ICON_CLASS = 'mt-px size-3.5 shrink-0'

function ToolStatusCell({ tool }: { tool: ToolAvailability }) {
  const status = toolStatus(tool)
  if (status.kind === 'found') {
    return (
      <span className="inline-flex items-start gap-1.5 text-[11px] text-emerald-300" title={status.title}>
        <CheckCircle2 className={cn(STATUS_ICON_CLASS, 'text-emerald-400')} aria-hidden />
        {status.label}
      </span>
    )
  }
  if (status.kind === 'not_found') {
    return (
      <span className="inline-flex items-start gap-1.5 text-[11px] text-zinc-500" title={status.title}>
        <XCircle className={cn(STATUS_ICON_CLASS, 'text-zinc-600')} aria-hidden />
        {status.label}
      </span>
    )
  }
  if (status.kind === 'configured_broken') {
    return (
      <span className="inline-flex items-start gap-1.5 text-[11px] text-amber-300" title={status.title}>
        <AlertTriangle className={cn(STATUS_ICON_CLASS, 'text-amber-400')} aria-hidden />
        <span className="flex flex-col">
          {status.label}
          {status.detail && <span className="text-[10px] text-muted-foreground">{status.detail}</span>}
        </span>
      </span>
    )
  }
  return (
    <span className="inline-flex items-start gap-1.5 text-[11px] leading-snug text-rose-300" title={status.title}>
      <AlertTriangle className={cn(STATUS_ICON_CLASS, 'text-rose-400')} aria-hidden />
      {status.label}
    </span>
  )
}

/**
 * Path actions for an administrator. Tools the bridge executes (gh) or runs on (bun) are not
 * settable; the row shows how to set them instead, when there is a way. The path button is always
 * the first child of the same wrapper, so React keeps the same element (and keyboard focus) when a
 * save or reset turns "Set path" into "Change" or removes "Reset to automatic".
 */
function ToolActions({
  tool,
  onEdit,
  onReset,
  pathButtonRef,
}: {
  tool: ToolAvailability
  onEdit: (tool: ToolAvailability) => void
  onReset: (tool: ToolAvailability) => void
  pathButtonRef: (element: HTMLElement | null) => void
}) {
  const actions = toolActions(tool)
  if (!actions.edit) {
    return actions.hint ? <span className="text-[10px] leading-snug text-muted-foreground">{actions.hint}</span> : null
  }
  return (
    <div className="flex flex-wrap gap-1">
      <Button
        ref={pathButtonRef}
        variant={actions.edit.primary ? 'default' : 'ghost'}
        size="xs"
        className={!actions.edit.primary && !actions.reset ? 'text-muted-foreground' : undefined}
        onClick={() => onEdit(tool)}
        aria-label={actions.edit.ariaLabel}
      >
        {actions.edit.label}
      </Button>
      {actions.reset && (
        <Button variant="outline" size="xs" onClick={() => onReset(tool)} aria-label={actions.reset.ariaLabel}>
          {actions.reset.label}
        </Button>
      )}
    </div>
  )
}
