import type { PrScanResultView, PrStatusRequest, PullRequestView } from '@/types/api'
import { shortSha } from './settings-format'

/**
 * Pure helpers for the pull request "Comment & status" panel: the editable comment draft and the
 * commit-status suggestion are built only from the stored scan result and never claim verification.
 */

export type CommitState = PrStatusRequest['state']

export const COMMIT_STATES: { value: CommitState; label: string }[] = [
  { value: 'success', label: 'success' },
  { value: 'failure', label: 'failure' },
  { value: 'pending', label: 'pending' },
  { value: 'error', label: 'error' },
]

/**
 * States the bridge accepts for a given scan of the current head commit. Mirrors
 * allowedCommitStates in web/server/services/pr-scan.ts, which enforces the rule on the server;
 * this copy only explains the choice in the UI.
 */
export function allowedStates(scanAtHead: PrScanResultView | null): CommitState[] {
  if (!scanAtHead) return ['pending']
  switch (scanAtHead.status) {
    case 'clean':
      return ['success', 'pending']
    case 'warnings':
      return ['success', 'failure', 'pending']
    case 'critical':
      return ['failure', 'pending']
    case 'failed':
      return ['error', 'pending']
  }
}

/** Context name used by the bridge for commit statuses (web/server/github.ts). */
export const STATUS_CONTEXT = 'sentra/security-scan'
const MAX_COMMENT_MATCHES = 10

/** Strips characters that could break out of a Markdown code span. */
function codeSpan(value: string): string {
  return `\`${value.replace(/[`\r\n|]/g, ' ').slice(0, 200)}\``
}

/** Builds an editable comment draft from the real scan result. Never claims verification. */
export function buildCommentDraft(pr: PullRequestView, scan: PrScanResultView | null | undefined): string {
  if (!scan) {
    return [
      '### Sentra scan',
      '',
      `Sentra has not scanned this pull request (head ${codeSpan(shortSha(pr.headSha))}).`,
    ].join('\n')
  }
  const lines = ['### Sentra heuristic SAST scan (unverified candidates)', '']
  lines.push(`- Commit scanned: ${codeSpan(shortSha(scan.headSha))}`)
  if (scan.headSha !== pr.headSha) {
    lines.push(`- Note: the pull request head has since moved to ${codeSpan(shortSha(pr.headSha))}; this result describes the older commit.`)
  }
  lines.push(`- Changed files: ${scan.filesConsidered} (scanned ${scan.filesScanned}, not scanned ${scan.skipped.length})`)
  if (scan.status === 'failed') {
    // 'failed' is either a scanner failure or a partial scan (changed files the bridge could not
    // download or hand to the scanner); signals found in the scanned part are still listed.
    lines.push(`- Result: incomplete${scan.error ? ` (${plainText(scan.error)})` : ''}`)
    if (scan.matches.length === 0) {
      lines.push('', 'The scan has no complete result, so there is nothing to report.')
      return lines.join('\n')
    }
    lines.push(`- Candidate signals in the scanned files: ${scan.signalsFound} (critical ${scan.criticalCount}, high ${scan.highCount})`, '')
    appendMatchTable(lines, scan)
    lines.push(
      '',
      'Files that were not scanned may contain further issues. These are candidates from line-based pattern matching. Each needs human review; none has been verified.',
    )
    return lines.join('\n')
  }
  lines.push(`- Candidate signals: ${scan.signalsFound} (critical ${scan.criticalCount}, high ${scan.highCount})`, '')
  if (scan.matches.length === 0) {
    lines.push(
      'No signals were reported in the scanned files. The rules cover a limited set of patterns; this is not evidence that the change is free of vulnerabilities.',
    )
    return lines.join('\n')
  }
  appendMatchTable(lines, scan)
  lines.push('', 'These are candidates from line-based pattern matching. Each needs human review; none has been verified.')
  return lines.join('\n')
}

/** Collapses text to one line so it cannot open a Markdown block or table cell inside a list item. */
function plainText(value: string): string {
  return value.replace(/[\r\n|]+/g, ' ').trim().slice(0, 500)
}

function appendMatchTable(lines: string[], scan: PrScanResultView): void {
  lines.push('| Severity | Rule | Location |', '| --- | --- | --- |')
  for (const match of scan.matches.slice(0, MAX_COMMENT_MATCHES)) {
    lines.push(`| ${match.severity} | ${codeSpan(match.ruleId)} ${match.ruleName.replace(/[|\r\n]/g, ' ')} | ${codeSpan(`${match.filePath}:${match.line}`)} |`)
  }
  if (scan.matches.length > MAX_COMMENT_MATCHES) {
    lines.push('', `${scan.matches.length - MAX_COMMENT_MATCHES} more signals are not listed here.`)
  }
}

/** Suggested commit-status description and (optional) state from the scan. The state is never applied automatically. */
export function suggestStatus(pr: PullRequestView, scan: PrScanResultView | null | undefined): { state: CommitState | null; description: string } {
  if (!scan) return { state: 'pending', description: 'Not scanned by Sentra' }
  if (scan.headSha !== pr.headSha) return { state: 'pending', description: `Sentra scan is for an older commit (${shortSha(scan.headSha)})` }
  if (scan.status === 'failed') return { state: 'error', description: 'Sentra scan has no complete result (scanner failure or partial coverage)' }
  const description = `Sentra heuristic SAST: ${scan.signalsFound} candidate signal${scan.signalsFound === 1 ? '' : 's'} (${scan.criticalCount} critical) in ${scan.filesScanned} files at ${shortSha(scan.headSha)}`.slice(0, 140)
  if (scan.status === 'critical') return { state: 'failure', description }
  if (scan.status === 'clean') return { state: 'success', description }
  return { state: null, description }
}
