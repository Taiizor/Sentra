import { permissionHint as sharedPermissionHint, type FindingView, type Permission, type Severity, type TriageVerdict } from '@/types/api'

/**
 * Formatting helpers shared by the findings, remediation and patch views. They only format the
 * values they are given; nothing here produces data.
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
