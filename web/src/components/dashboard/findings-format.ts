import {
  FINDING_ORIGINS,
  permissionHint as sharedPermissionHint,
  type CodeqlAnalysisOutcome,
  type CodeqlAnalysisView,
  type FindingOrigin,
  type FindingSource,
  type FindingView,
  type Permission,
  type Severity,
  type TriageVerdict,
} from '../../types/api'

export const FINDING_SOURCE_LABEL: Record<FindingSource, string> = {
  sast: 'SAST',
  dependency: 'Dependency',
  codeql: 'CodeQL',
}

export const FINDING_ORIGIN_LABEL: Record<FindingOrigin, string> = {
  host_analysis: 'host analysis',
  sarif_import: 'SARIF import',
  github_code_scanning: 'GitHub code scanning',
}

/**
 * What a run's CodeQL host analysis did. Runs stored before `outcome` existed are derived: a
 * CodeQL stage error means it failed (a failed analysis was stored with attempted true and no
 * skip reason, like a successful one).
 */
export function codeqlAnalysisOutcome(
  analysis: Pick<CodeqlAnalysisView, 'outcome' | 'attempted' | 'skipReason' | 'languages'>,
  stageErrors: readonly { stage: string }[],
): CodeqlAnalysisOutcome {
  if (analysis.outcome) return analysis.outcome
  if (stageErrors.some((entry) => entry.stage === 'codeql')) return 'failed'
  if (analysis.skipReason || !analysis.attempted) return 'skipped'
  return analysis.languages.some((entry) => entry.status === 'analyzed') ? 'analyzed' : 'failed'
}

/** "analyzed", "failed", or "not run (<reason>)" for the run summary. */
export function codeqlOutcomeLabel(
  analysis: Pick<CodeqlAnalysisView, 'outcome' | 'attempted' | 'skipReason' | 'languages'>,
  stageErrors: readonly { stage: string }[],
): string {
  const outcome = codeqlAnalysisOutcome(analysis, stageErrors)
  if (outcome === 'analyzed') return 'analyzed'
  if (outcome === 'failed') return 'failed'
  return analysis.skipReason ? `not run (${analysis.skipReason.replace(/_/g, ' ')})` : 'not run'
}

/** "host analysis 3 · SARIF import 3 · GitHub code scanning 1" (origins with findings only). */
export function codeqlOriginBreakdown(byOrigin: Partial<Record<FindingOrigin, number>> | null | undefined): string {
  if (!byOrigin) return ''
  return FINDING_ORIGINS.filter((origin) => (byOrigin[origin] ?? 0) > 0)
    .map((origin) => `${FINDING_ORIGIN_LABEL[origin]} ${byOrigin[origin]}`)
    .join(' · ')
}

/** Shown wherever CodeQL findings are totalled. */
export const CODEQL_PER_ORIGIN_NOTE =
  'Each origin is stored and counted on its own: one CodeQL result reported by host analysis, a SARIF import and GitHub code scanning counts once per origin.'

/** e.g. "SAST", "CodeQL · SARIF import"; unknown values (a newer bridge) are shown as they are. */
export function findingSourceLabel(finding: Pick<FindingView, 'source' | 'origin'>): string {
  const source = FINDING_SOURCE_LABEL[finding.source] ?? String(finding.source)
  if (finding.source !== 'codeql' || !finding.origin) return source
  return `${source} · ${FINDING_ORIGIN_LABEL[finding.origin] ?? finding.origin}`
}

/**
 * Formatting helpers shared by the findings, remediation and patch views. They only format the
 * values they are given; nothing here produces data. Free of React and path aliases so the bridge
 * unit tests can check the CodeQL outcome helpers.
 */

/** Display-only explanation derived from the shared role matrix (PERMISSION_MIN_ROLE); the server enforces. */
export function permissionRequirement(permission: Permission): string {
  return sharedPermissionHint(permission)
}

export const SEVERITY_RANK: Record<Severity, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Informational: 1,
  Unknown: 0,
}

export const VERDICT_LABEL: Record<TriageVerdict, string> = {
  confirmed: 'Confirmed',
  needs_validation: 'Needs validation',
  rejected: 'Rejected',
}

/** The core scanner labels credential matches with this category. */
export function isSecretFinding(finding: Pick<FindingView, 'category'>): boolean {
  return (finding.category ?? '').toUpperCase() === 'SECRET_LEAK'
}

export function findingLocation(finding: FindingView): string {
  if (finding.source === 'dependency' && finding.dependency) {
    return `${finding.dependency.packageName}@${finding.dependency.packageVersion}`
  }
  if (finding.filePath) return finding.line !== null ? `${finding.filePath}:${finding.line}` : finding.filePath
  return '—'
}

export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return '—'
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString()
}

/**
 * Marker the core scanner writes into finding snippets (and taint-step code) in place of the
 * secret part of a credential match, e.g. `AKIA...[REDACTED]`.
 */
export const REDACTION_MARKER = '[REDACTED]'

/**
 * The bridge's file endpoint (GET /api/tenants/:id/files) replaces every line that carries an
 * open SECRET_LEAK finding with exactly `[redacted by Sentra: <rule ids>]`. It never redacts
 * inside a line, so only a whole line in this form is a redaction; the same text elsewhere is
 * file content.
 */
const BRIDGE_REDACTED_LINE = /^\[redacted by Sentra: ([^\]\r\n]*)\]\r?$/

/** Rule ids named by a bridge-redacted line, or null when `line` is ordinary file content. */
export function bridgeRedactedLineRules(line: string): string[] | null {
  const match = BRIDGE_REDACTED_LINE.exec(line)
  if (!match) return null
  return match[1]
    .split(',')
    .map((ruleId) => ruleId.trim())
    .filter((ruleId) => ruleId.length > 0)
}

/** Number of lines in file content that the bridge replaced with its redaction marker. */
export function countBridgeRedactedLines(lines: readonly string[]): number {
  return lines.reduce((count, line) => (bridgeRedactedLineRules(line) ? count + 1 : count), 0)
}
