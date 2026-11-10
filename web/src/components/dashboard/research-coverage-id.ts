import type { CoverageStatus } from '@/types/api'

/**
 * Client-side mirror of the bridge's coverage-unit input rules (web/server/services/coverage.ts).
 * The bridge validates again; these helpers only give early feedback in the form.
 *
 * A coverage id is `<surface>/<boundary>/<subsystem>/<attackClass>`; every segment is 1-63
 * characters of a-z, 0-9, '_' or '-' and starts with a letter or digit.
 */
export const COVERAGE_SEGMENT_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/
export const COVERAGE_MAX_STRING = 500
export const COVERAGE_MAX_LIST_ITEMS = 200
export const COVERAGE_MAX_WAVE = 10_000

export const COVERAGE_STATUSES: readonly CoverageStatus[] = [
  'planned',
  'candidate',
  'covered',
  'needs_validation',
  'deferred',
  'blocked',
  'out_of_scope',
]

/** What the bridge's ledger validator expects from a unit with each status. */
export const COVERAGE_STATUS_RULE: Partial<Record<CoverageStatus, string>> = {
  covered: 'Validation expects reviewed paths and local checks for a covered unit.',
  candidate: 'Validation expects at least one finding fingerprint or finding id for a candidate unit.',
  needs_validation: 'Validation expects the unresolved reason for this status.',
  deferred: 'Validation expects the unresolved reason for this status.',
  blocked: 'Validation expects the unresolved reason for this status.',
  out_of_scope: 'Validation expects the unresolved reason for this status.',
}

export interface CoverageSegments {
  surface: string
  boundary: string
  subsystem: string
  attackClass: string
}

export function composeCoverageId(segments: CoverageSegments): string {
  return [segments.surface, segments.boundary, segments.subsystem, segments.attackClass].join('/')
}

/** Returns why `value` cannot be a coverage id segment, or null when it can. */
export function segmentProblem(label: string, value: string): string | null {
  if (value.length === 0) return `${label} is required`
  if (!COVERAGE_SEGMENT_PATTERN.test(value)) {
    return `${label} must be 1-63 characters of a-z, 0-9, '_' or '-' and start with a letter or digit`
  }
  return null
}

/** Splits a multi-line text field into trimmed, non-empty, de-duplicated entries. */
export function splitLines(text: string): string[] {
  return [
    ...new Set(
      text
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line.length > 0),
    ),
  ]
}
