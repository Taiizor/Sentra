import type {
  PluginDiagnosticSeverity,
  PluginDiagnosticView,
  PluginDirectorySource,
  PluginsView,
  PluginView,
} from '../../types/api'

/**
 * Wording and response normalisation for the Plugins tab. Kept free of React and path aliases so
 * the bridge's unit tests can import it.
 */

export const PLUGIN_DIRECTORY_SOURCE_LABEL: Record<PluginDirectorySource, string> = {
  environment: 'SENTRA_PLUGIN_DIR',
  platform_default: 'platform default',
  none: 'none',
}

/** Why there is no directory input in the console. */
export const PLUGIN_DIRECTORY_READ_ONLY_NOTE =
  'The directory cannot be set from the console: adapters in it run as programs on the bridge host.'

export const LEGACY_PLUGINS_VIEW_NOTE =
  'This bridge predates plugin directory detection and diagnostics (contract 4). Restart it to see where the directory comes from and what discovery reported.'

/** The listing as the tab renders it; `legacy` marks a bridge that sent the contract 3 shape. */
export interface PluginsTabView extends PluginsView {
  legacy: boolean
}

const SOURCES: readonly PluginDirectorySource[] = ['environment', 'platform_default', 'none']
const SEVERITIES: readonly PluginDiagnosticSeverity[] = ['error', 'warning', 'info']

function text(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null
}

function diagnostic(value: unknown): PluginDiagnosticView[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return []
  const entry = value as Record<string, unknown>
  return [
    {
      severity: SEVERITIES.includes(entry.severity as PluginDiagnosticSeverity) ? (entry.severity as PluginDiagnosticSeverity) : 'warning',
      code: text(entry.code) ?? 'unknown',
      message: typeof entry.message === 'string' ? entry.message : '',
      path: text(entry.path),
    },
  ]
}

/**
 * Accepts the current shape and the one bridges before contract 4 sent ({ pluginDir, configured,
 * plugins, note }): those only used SENTRA_PLUGIN_DIR and reported no diagnostics.
 */
export function normalizePluginsView(raw: unknown): PluginsTabView {
  const body = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {}
  const directory = text(body.directory) ?? text(body.pluginDir)
  const knownSource = SOURCES.includes(body.directorySource as PluginDirectorySource)
  const directorySource: PluginDirectorySource = knownSource
    ? (body.directorySource as PluginDirectorySource)
    : directory !== null
      ? 'environment'
      : 'none'
  const diagnostics = Array.isArray(body.diagnostics) ? body.diagnostics.flatMap(diagnostic) : []
  return {
    directory,
    directorySource,
    directoryExists: typeof body.directoryExists === 'boolean' ? body.directoryExists : directory !== null,
    pluginDir: directory,
    configured: typeof body.configured === 'boolean' ? body.configured : directory !== null,
    plugins: Array.isArray(body.plugins) ? (body.plugins as PluginView[]) : [],
    diagnostics,
    hasErrors: typeof body.hasErrors === 'boolean' ? body.hasErrors : diagnostics.some((entry) => entry.severity === 'error'),
    hint: text(body.hint),
    note: typeof body.note === 'string' ? body.note : '',
    legacy: !knownSource,
  }
}

/** "2 errors, 1 warning"; empty when there are no diagnostics. */
export function diagnosticSummary(diagnostics: readonly PluginDiagnosticView[]): string {
  const parts: string[] = []
  for (const severity of SEVERITIES) {
    const count = diagnostics.filter((entry) => entry.severity === severity).length
    if (count === 0) continue
    const noun = severity === 'info' ? 'note' : severity
    parts.push(`${count} ${noun}${count === 1 ? '' : 's'}`)
  }
  return parts.join(', ')
}

/** Short state of the directory for the header badge. */
export function directoryStateLabel(view: Pick<PluginsView, 'directory' | 'directoryExists'>): string | null {
  if (view.directory === null) return null
  return view.directoryExists ? 'exists' : 'does not exist'
}
