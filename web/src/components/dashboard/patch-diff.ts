/**
 * Unified-diff parser used by the patch views. Line numbers come only from hunk headers;
 * nothing is inferred, re-ordered or labelled beyond what the diff text itself states.
 */

export type DiffRowKind = 'file' | 'meta' | 'hunk' | 'add' | 'del' | 'context' | 'note'

export interface DiffRow {
  kind: DiffRowKind
  text: string
  oldLine: number | null
  newLine: number | null
}

export interface ParsedDiff {
  rows: DiffRow[]
  additions: number
  deletions: number
  hunks: number
  /** Hunks whose body does not match the line counts declared in their `@@` header. */
  inconsistentHunks: number
}

const HUNK_HEADER = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/

export function parseUnifiedDiff(diff: string): ParsedDiff {
  const lines = diff.replace(/\r\n/g, '\n').split('\n')
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()

  const rows: DiffRow[] = []
  let additions = 0
  let deletions = 0
  let hunks = 0
  let inconsistentHunks = 0

  let inHunk = false
  let hunkInconsistent = false
  let oldLine = 0
  let newLine = 0
  let oldLeft = 0
  let newLeft = 0

  const closeHunk = () => {
    if (inHunk && (hunkInconsistent || oldLeft !== 0 || newLeft !== 0)) inconsistentHunks += 1
    inHunk = false
    hunkInconsistent = false
  }

  for (const line of lines) {
    const header = HUNK_HEADER.exec(line)
    if (header) {
      closeHunk()
      hunks += 1
      inHunk = true
      oldLine = Number(header[1])
      oldLeft = header[2] === undefined ? 1 : Number(header[2])
      newLine = Number(header[3])
      newLeft = header[4] === undefined ? 1 : Number(header[4])
      rows.push({ kind: 'hunk', text: line, oldLine: null, newLine: null })
      continue
    }

    if (inHunk) {
      const expectingBody = oldLeft > 0 || newLeft > 0
      const isFileHeader = line.startsWith('--- ') || line.startsWith('+++ ') || line.startsWith('diff ')
      const sign = line.charAt(0)
      if (sign === '\\') {
        rows.push({ kind: 'note', text: line, oldLine: null, newLine: null })
        continue
      }
      if (expectingBody || (!isFileHeader && (sign === '+' || sign === '-' || sign === ' '))) {
        // Lines past the declared counts are still shown, without numbers, and flagged.
        if (!expectingBody) hunkInconsistent = true
        if (sign === '+') {
          rows.push({ kind: 'add', text: line.slice(1), oldLine: null, newLine: expectingBody ? newLine++ : null })
          newLeft -= 1
          additions += 1
          continue
        }
        if (sign === '-') {
          rows.push({ kind: 'del', text: line.slice(1), oldLine: expectingBody ? oldLine++ : null, newLine: null })
          oldLeft -= 1
          deletions += 1
          continue
        }
        if (sign === ' ' || line === '') {
          rows.push({
            kind: 'context',
            text: line.slice(1),
            oldLine: expectingBody ? oldLine++ : null,
            newLine: expectingBody ? newLine++ : null,
          })
          oldLeft -= 1
          newLeft -= 1
          continue
        }
        // Any other prefix inside a hunk body is malformed; fall through and show it verbatim.
        hunkInconsistent = true
      }
      closeHunk()
    }

    const isFileLine = line.startsWith('diff ') || line.startsWith('--- ') || line.startsWith('+++ ')
    rows.push({ kind: isFileLine ? 'file' : 'meta', text: line, oldLine: null, newLine: null })
  }
  closeHunk()

  return { rows, additions, deletions, hunks, inconsistentHunks }
}
