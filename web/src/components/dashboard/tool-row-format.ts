import type { BinaryFormat, BinaryInfo, ExecutableSource, ToolAvailability, ToolSearchStatus } from '../../types/api'
import { persistedPathLabel } from './host-path-advice'

/**
 * Wording of the tools table (Host & workers) and the tool badges (Settings → System): status,
 * path tooltip, path actions and the tool path dialog. Free of React and path aliases so the bridge
 * unit tests can check it; console-format re-exports everything here.
 */

/** Where the bridge's tool search found an executable. */
export const EXECUTABLE_SOURCE_LABEL: Record<ExecutableSource, string> = {
  process_path: 'process PATH',
  persisted_system_path: 'system PATH (persisted)',
  persisted_user_path: 'user PATH (persisted)',
  well_known: 'standard install location',
  configured: 'set in console',
  environment: 'host environment variable',
}

/** The variable that pins a tool's path on the bridge host (selection 'environment'). */
export function pinVariable(toolName: string): string {
  return toolName === 'codeql' ? 'SENTRA_CODEQL_BIN' : 'SENTRA_GH_BIN'
}

/** Source label of a row: the pinning variable for an environment row, else the search source. */
export function toolSourceLabel(tool: Pick<ToolAvailability, 'name' | 'source'>): string | null {
  if (!tool.source) return null
  if (tool.source === 'environment') return pinVariable(tool.name)
  return EXECUTABLE_SOURCE_LABEL[tool.source] ?? tool.source
}

/** True when the row's path was chosen (in the console, or through SENTRA_GH_BIN / SENTRA_CODEQL_BIN) rather than found by the search. */
export function isChosenPath(tool: ToolAvailability): boolean {
  return tool.selection === 'configured' || tool.selection === 'environment'
}

/**
 * A path set in the console for this tool, broken or not. Tool rows of topology reports stored by
 * bridges older than contract version 3 have no configuredPath field.
 */
export function hasConfiguredPath(tool: ToolAvailability): boolean {
  return typeof tool.configuredPath === 'string'
}

/** True when the file's header says it cannot run on the bridge host (another OS or architecture). */
export function cannotRunHere(binary: BinaryInfo | null | undefined): binary is BinaryInfo {
  return binary?.compatibility === 'incompatible'
}

export const CANNOT_RUN_HERE_LABEL = 'found, but built for another platform — cannot run here'

/** Formats a header judged unable to run can have (scripts and unrecognised files never are). */
const BUILT_FOR_FORMAT: Partial<Record<BinaryFormat, string>> = {
  pe: 'PE (Windows) executable',
  elf: 'ELF executable',
  macho: 'Mach-O executable',
  macho_universal: 'Mach-O universal binary',
}

/**
 * Tooltip detail behind a "cannot run here" warning: what the file is built for and why it cannot
 * run. Architectures are not displayed anywhere else on the page.
 */
export function describeCannotRun(binary: BinaryInfo): string {
  const lines = [BUILT_FOR_FORMAT[binary.format] ?? 'Executable']
  const architectures = binary.architectures.filter((arch) => arch !== 'unknown')
  if (architectures.length > 0) lines.push(`Built for: ${architectures.join(', ')}`)
  if (binary.note) lines.push(binary.note)
  return lines.join('\n')
}

export type ToolStatusKind = 'found' | 'not_found' | 'configured_broken' | 'cannot_run'

export interface ToolStatus {
  kind: ToolStatusKind
  label: string
  /** Second line under the label: what a row with a broken chosen path shows instead. */
  detail: string | null
  /** Tooltip with the details behind the label. */
  title: string
}

/**
 * The chosen path of a row whose configuredPathProblem is set: a path set in the console, or, when
 * the row has none, the variable that pins it on the bridge host (SENTRA_GH_BIN, SENTRA_CODEQL_BIN).
 */
function brokenPathName(tool: ToolAvailability): string {
  return hasConfiguredPath(tool) ? `The path set in the console (${tool.configuredPath})` : `The ${pinVariable(tool.name)} path`
}

/** What the row shows instead of a broken chosen path, including when that file cannot run here either. */
function brokenPathFallback(tool: ToolAvailability): string {
  if (tool.available && tool.path) {
    const found = `Automatic detection found ${tool.path}, which is shown instead.`
    if (!cannotRunHere(tool.binary)) return found
    return `${found} Its header says it cannot run on this host:\n${describeCannotRun(tool.binary)}`
  }
  return hasConfiguredPath(tool) ? 'Automatic detection did not find it either.' : `${tool.name} is reported as not found until ${pinVariable(tool.name)} is fixed.`
}

function brokenPathDetail(tool: ToolAvailability): string {
  if (tool.available) return cannotRunHere(tool.binary) ? 'showing automatic detection: built for another platform — cannot run here' : 'showing automatic detection'
  return hasConfiguredPath(tool) ? 'automatic detection: not found' : 'not used until fixed'
}

/**
 * One status per tool row. A broken chosen path wins, because the row then shows what automatic
 * detection found (if anything) instead of what was chosen; the detail line and the tooltip still
 * say when that file cannot run here.
 */
export function toolStatus(tool: ToolAvailability): ToolStatus {
  if (tool.configuredPathProblem) {
    return {
      kind: 'configured_broken',
      label: hasConfiguredPath(tool) ? 'configured path broken' : `${pinVariable(tool.name)} path broken`,
      detail: brokenPathDetail(tool),
      title: `${brokenPathName(tool)} cannot be used: ${tool.configuredPathProblem}\n${brokenPathFallback(tool)}`,
    }
  }
  if (!tool.available) return { kind: 'not_found', label: 'not found', detail: null, title: 'Not found' }
  if (cannotRunHere(tool.binary)) {
    return {
      kind: 'cannot_run',
      label: CANNOT_RUN_HERE_LABEL,
      detail: null,
      title: `The file exists, but its header says it cannot run on this host.\n${describeCannotRun(tool.binary)}`,
    }
  }
  return { kind: 'found', label: 'found', detail: null, title: tool.path ? `Found: ${tool.path}` : 'Found' }
}

/** Example shown in the tool path field, in the bridge host's path syntax. */
export function toolPathPlaceholder(tool: string, platform: string): string {
  if (platform === 'win32') return `C:\\Tools\\${tool}\\${tool}.exe`
  if (platform === 'darwin') return `/opt/homebrew/bin/${tool}`
  return `/usr/local/bin/${tool}`
}

/**
 * What the last tool search covered. The persisted PATH is named as searched only when it was
 * read, and a partial read says so (mirrors describeSearchScope on the bridge).
 */
export function describeToolSearchScope(toolSearch: ToolSearchStatus, platform: string): string {
  const persisted = persistedPathLabel(platform)
  if (toolSearch.persistedPathRead && !toolSearch.persistedPathError) return `the bridge process PATH, ${persisted} and standard install locations`
  if (toolSearch.persistedPathRead) return `the bridge process PATH, ${persisted} (only partly read) and standard install locations`
  return `the bridge process PATH and standard install locations (${persisted} ${toolSearch.persistedPathError ? 'could not be read' : 'was not read'})`
}

/**
 * How tools are found, as Settings → System says it. The exception (a chosen path) belongs to the
 * search; nothing about finding a tool runs it.
 */
export function toolDetectionSummary(toolSearch: ToolSearchStatus, platform: string): string {
  return `Found automatically by searching ${describeToolSearchScope(toolSearch, platform)}, unless a path was set in the console (or SENTRA_GH_BIN for gh, SENTRA_CODEQL_BIN for codeql). Finding a tool never runs it.`
}

/** Context for tool tooltips; absent for stored topology reports, which do not record the search. */
export interface ToolSearchContext {
  toolSearch: ToolSearchStatus
  platform: string
}

/**
 * The row's other copies (shadowed), counted for the path cell. For a path chosen in the console or
 * through SENTRA_GH_BIN they are what automatic detection found, its first choice included, not
 * later matches.
 */
export function otherCopiesLabel(tool: ToolAvailability): string | null {
  const count = tool.shadowed?.length ?? 0
  if (count === 0) return null
  if (tool.usage === 'runtime') return `${count} ${count === 1 ? 'other install' : 'other installs'}`
  if (isChosenPath(tool)) return `${count} other ${count === 1 ? 'copy' : 'copies'} found automatically`
  return `${count} ${count === 1 ? 'later match' : 'later matches'}`
}

function otherCopiesHeading(tool: ToolAvailability): string {
  if (tool.usage === 'runtime') return 'Other installations (not the running executable):'
  if (tool.selection === 'environment') return `Other copies found by automatic detection (not run while ${pinVariable(tool.name)} is set):`
  if (tool.selection === 'configured') return 'Other copies found by automatic detection (not reported while a path is set in the console):'
  return 'Later matches in search order:'
}

/**
 * Tooltip for a tool's path cell: where the path came from (console, SENTRA_GH_BIN or the PATH
 * search), symlink or shim target, a broken console path, other copies and, for tools that cannot
 * be set in the console, how to set them instead.
 */
export function describeToolPath(tool: ToolAvailability, search?: ToolSearchContext): string {
  const lines: string[] = []
  if (tool.configuredPathProblem) {
    lines.push(`${brokenPathName(tool)} cannot be used: ${tool.configuredPathProblem}`, brokenPathFallback(tool))
  }
  if (!tool.path) {
    lines.push(
      search
        ? `Not found. Searched ${describeToolSearchScope(search.toolSearch, search.platform)}.`
        : 'Not found in the directories searched on the bridge host',
    )
  } else {
    lines.push(tool.path)
    if (tool.source === 'configured' && tool.configuredPath && tool.configuredPath !== tool.path) {
      lines.push(`Found in the folder set in the console: ${tool.configuredPath}`)
    }
    if (tool.resolvedPath) {
      lines.push(tool.resolvedVia === 'scoop_shim' ? `Scoop shim; runs: ${tool.resolvedPath}` : `Resolves to: ${tool.resolvedPath}`)
    }
    if (tool.source === 'configured') {
      lines.push('Path set in the console. The bridge checks that the file exists and can run on this host; it never runs it.')
    } else if (tool.source === 'environment') {
      lines.push(`Path set by ${pinVariable(tool.name)} in the bridge environment.`)
    } else if (tool.source) {
      lines.push(`Found via: ${EXECUTABLE_SOURCE_LABEL[tool.source] ?? tool.source}`)
      lines.push(tool.onProcessPath ? 'Visible on the bridge process PATH' : 'Not on the bridge process PATH')
    } else if (tool.usage === 'runtime') {
      lines.push('The running executable; its directory is not one of the searched directories')
    }
  }
  const shadowed = tool.shadowed ?? []
  if (shadowed.length > 0) lines.push(otherCopiesHeading(tool), ...shadowed.map((match) => `  ${match}`))
  if (tool.pathHint) lines.push(tool.pathHint)
  return lines.join('\n')
}

export interface ToolActionButton {
  /** Visible text. */
  label: string
  /** Accessible name: starts with the visible text (WCAG 2.5.3 Label in Name), then names the tool. */
  ariaLabel: string
}

export interface ToolActions {
  /**
   * Opens the path dialog: "Set path" when nothing was found, "Change" otherwise. Present in every
   * state of a settable tool, so the button stays in place, keeping keyboard focus, when the row
   * changes after a save or reset.
   */
  edit: (ToolActionButton & { primary: boolean }) | null
  /** Only while a path is set in the console. */
  reset: ToolActionButton | null
  /** How to set the path of a tool that cannot be set in the console, when there is a way. */
  hint: string | null
}

/** Path actions an administrator gets for a row. gh and codeql (executed by the bridge) and bun (runs it) have none. */
export function toolActions(tool: ToolAvailability): ToolActions {
  if (!tool.pathConfigurable) return { edit: null, reset: null, hint: tool.pathHint ?? null }
  const configured = hasConfiguredPath(tool)
  const edit =
    configured || tool.available
      ? { label: 'Change', ariaLabel: `Change path for ${tool.name}`, primary: false }
      : { label: 'Set path', ariaLabel: `Set path for ${tool.name}`, primary: true }
  const reset = configured ? { label: 'Reset to automatic', ariaLabel: `Reset to automatic detection for ${tool.name}` } : null
  return { edit, reset, hint: null }
}

/** Where a path set in the console is used, as the tool path dialog says it (every tool appears in topology reports). */
export function toolPathUsageText(tool: string): string {
  return `The path is used on this page, in Settings → System and in topology reports. Programs the bridge starts (the core CLI and plugin adapters) still look ${tool} up on the bridge process PATH.`
}
