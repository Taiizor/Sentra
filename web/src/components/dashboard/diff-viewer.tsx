import { useState, useMemo } from 'react'
import {
  Copy,
  Check,
  Columns2,
  AlignLeft,
  FileCode,
  FileText,
  ChevronDown,
  ChevronRight,
} from 'lucide-react'
import { toast } from 'sonner'
import { copyText } from '@/lib/clipboard'
import { Button } from '@/components/ui/button'

interface DiffViewerProps {
  diff: string
  title?: string
  filePath?: string
  defaultMode?: 'unified' | 'split' | 'raw'
  maxHeight?: string
  collapsible?: boolean
  defaultExpanded?: boolean
}

interface ParsedDiffLine {
  type: 'header' | 'hunk' | 'deletion' | 'addition' | 'context'
  content: string
  oldLineNumber?: number
  newLineNumber?: number
  pairedWith?: string
}

interface SplitRow {
  type: 'hunk' | 'change' | 'context'
  hunkHeader?: string
  left?: {
    type: 'deletion' | 'context' | 'empty'
    content: string
    lineNumber?: number
    pairedWith?: string
  }
  right?: {
    type: 'addition' | 'context' | 'empty'
    content: string
    lineNumber?: number
    pairedWith?: string
  }
}

/**
 * Computes word/token diff highlights between an old string and a new string.
 * Finds common prefix and common suffix, highlighting the differing center.
 */
function highlightWordDiff(
  text: string,
  comparisonText: string | undefined,
  type: 'deletion' | 'addition'
) {
  if (!comparisonText || text === comparisonText) {
    return <span>{text}</span>
  }

  // Find common prefix length
  let prefixLen = 0
  const minLen = Math.min(text.length, comparisonText.length)
  while (prefixLen < minLen && text[prefixLen] === comparisonText[prefixLen]) {
    prefixLen++
  }

  // Find common suffix length (ensuring no overlap with prefix)
  let suffixLen = 0
  while (
    suffixLen < minLen - prefixLen &&
    text[text.length - 1 - suffixLen] === comparisonText[comparisonText.length - 1 - suffixLen]
  ) {
    suffixLen++
  }

  const prefix = text.slice(0, prefixLen)
  const diffPart = text.slice(prefixLen, text.length - suffixLen)
  const suffix = text.slice(text.length - suffixLen)

  const highlightClass =
    type === 'deletion'
      ? 'bg-rose-500/35 text-rose-100 rounded px-0.5 font-semibold'
      : 'bg-emerald-500/35 text-emerald-100 rounded px-0.5 font-semibold'

  return (
    <>
      <span>{prefix}</span>
      {diffPart && <span className={highlightClass}>{diffPart}</span>}
      <span>{suffix}</span>
    </>
  )
}

/**
 * Basic syntax coloring for common languages (Rust, TypeScript, Python, JSON)
 */
function renderSyntaxHighlit(
  text: string,
  pairedText?: string,
  changeType?: 'deletion' | 'addition'
) {
  if (!text) return <span className="opacity-0">.</span>

  // If there's an active word diff pairing, use word diff highlighting
  if (changeType && pairedText) {
    return highlightWordDiff(text, pairedText, changeType)
  }

  // Comment highlight
  const trimmed = text.trim()
  if (trimmed.startsWith('//') || trimmed.startsWith('#')) {
    return <span className="text-zinc-500 italic">{text}</span>
  }

  return <span>{text}</span>
}

export function DiffViewer({
  diff,
  title,
  filePath,
  defaultMode = 'unified',
  maxHeight = 'max-h-[380px]',
  collapsible = false,
  defaultExpanded = true,
}: DiffViewerProps) {
  const [mode, setMode] = useState<'unified' | 'split' | 'raw'>(defaultMode)
  const [copied, setCopied] = useState(false)
  const [isExpanded, setIsExpanded] = useState(defaultExpanded)

  const parsed = useMemo(() => {
    const rawLines = (diff || '').replace(/\r\n/g, '\n').split('\n')
    const parsedLines: ParsedDiffLine[] = []
    let oldLine = 1
    let newLine = 1
    let additions = 0
    let deletions = 0
    let detectedFile = filePath || ''

    for (const line of rawLines) {
      // Git header metadata lines to skip
      if (
        line.startsWith('diff --git') ||
        line.startsWith('index ') ||
        line.startsWith('similarity index') ||
        line.startsWith('rename from') ||
        line.startsWith('rename to') ||
        line.startsWith('new file mode') ||
        line.startsWith('deleted file mode')
      ) {
        continue
      }

      if (line.startsWith('--- ')) {
        if (!detectedFile) detectedFile = line.slice(4).trim().replace(/^a\//, '')
        continue
      }
      if (line.startsWith('+++ ')) {
        if (!detectedFile || detectedFile.startsWith('a/')) {
          detectedFile = line.slice(4).trim().replace(/^b\//, '')
        }
        continue
      }
      if (line.startsWith('@@ ')) {
        const match = line.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/)
        if (match) {
          oldLine = parseInt(match[1], 10)
          newLine = parseInt(match[2], 10)
        }
        parsedLines.push({ type: 'hunk', content: line })
        continue
      }

      if (line.startsWith('-')) {
        deletions++
        parsedLines.push({
          type: 'deletion',
          content: line.slice(1),
          oldLineNumber: oldLine++,
        })
      } else if (line.startsWith('+')) {
        additions++
        parsedLines.push({
          type: 'addition',
          content: line.slice(1),
          newLineNumber: newLine++,
        })
      } else {
        const text = line.startsWith(' ') ? line.slice(1) : line
        parsedLines.push({
          type: 'context',
          content: text,
          oldLineNumber: oldLine++,
          newLineNumber: newLine++,
        })
      }
    }

    // Build Split (Side-by-Side) Rows & Pair Deletions/Additions for Word Diff
    const splitRows: SplitRow[] = []
    let currentDeletions: ParsedDiffLine[] = []
    let currentAdditions: ParsedDiffLine[] = []

    function flushChanges() {
      const maxLen = Math.max(currentDeletions.length, currentAdditions.length)
      for (let i = 0; i < maxLen; i++) {
        const del = currentDeletions[i]
        const add = currentAdditions[i]

        if (del && add) {
          del.pairedWith = add.content
          add.pairedWith = del.content
        }

        splitRows.push({
          type: 'change',
          left: del
            ? {
                type: 'deletion',
                content: del.content,
                lineNumber: del.oldLineNumber,
                pairedWith: add?.content,
              }
            : { type: 'empty', content: '' },
          right: add
            ? {
                type: 'addition',
                content: add.content,
                lineNumber: add.newLineNumber,
                pairedWith: del?.content,
              }
            : { type: 'empty', content: '' },
        })
      }
      currentDeletions = []
      currentAdditions = []
    }

    for (const pl of parsedLines) {
      if (pl.type === 'hunk') {
        flushChanges()
        splitRows.push({ type: 'hunk', hunkHeader: pl.content })
      } else if (pl.type === 'deletion') {
        currentDeletions.push(pl)
      } else if (pl.type === 'addition') {
        currentAdditions.push(pl)
      } else if (pl.type === 'context') {
        flushChanges()
        splitRows.push({
          type: 'context',
          left: { type: 'context', content: pl.content, lineNumber: pl.oldLineNumber },
          right: { type: 'context', content: pl.content, lineNumber: pl.newLineNumber },
        })
      }
    }
    flushChanges()

    return {
      filePath: detectedFile || 'patch.diff',
      additions,
      deletions,
      unifiedLines: parsedLines,
      splitRows,
    }
  }, [diff, filePath])

  async function handleCopyDiff() {
    await copyText(diff)
    setCopied(true)
    toast.success('Unified diff copied to clipboard')
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="flex flex-col border border-zinc-800 rounded-xl bg-zinc-950 overflow-hidden shadow-lg">
      {/* Diff Header Bar */}
      <div className="px-4 py-2.5 bg-zinc-900/90 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-3 text-xs select-none">
        <div className="flex items-center gap-2.5 min-w-0 max-w-full">
          {collapsible && (
            <button
              type="button"
              onClick={() => setIsExpanded(!isExpanded)}
              className="text-zinc-400 hover:text-zinc-100 p-0.5 shrink-0"
              title={isExpanded ? 'Collapse Diff' : 'Expand Diff'}
            >
              {isExpanded ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
            </button>
          )}

          <div className="size-6 rounded-md bg-primary/10 border border-primary/20 text-primary flex items-center justify-center shrink-0">
            <FileCode className="size-3.5" />
          </div>

          <span className="font-mono font-bold text-zinc-200 truncate">
            {title || parsed.filePath}
          </span>

          <div className="flex items-center gap-1 font-mono text-[11px] shrink-0 ml-1">
            <span className="text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-1.5 py-0.5 rounded font-bold">
              +{parsed.additions}
            </span>
            <span className="text-rose-400 bg-rose-500/10 border border-rose-500/20 px-1.5 py-0.5 rounded font-bold">
              -{parsed.deletions}
            </span>
          </div>
        </div>

        {/* View Controls & Copy Button */}
        <div className="flex items-center gap-2 shrink-0">
          {/* Mode Switcher */}
          <div className="flex items-center p-0.5 rounded-lg border border-zinc-800 bg-zinc-950/80 text-xs">
            <button
              type="button"
              onClick={() => setMode('unified')}
              className={`px-2 py-1 rounded-md text-[11px] font-medium flex items-center gap-1.5 transition-colors ${
                mode === 'unified'
                  ? 'bg-zinc-800 text-zinc-100 font-bold shadow-xs'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
              title="Unified (Inline) Diff View"
            >
              <AlignLeft className="size-3" />
              Unified
            </button>
            <button
              type="button"
              onClick={() => setMode('split')}
              className={`px-2 py-1 rounded-md text-[11px] font-medium flex items-center gap-1.5 transition-colors ${
                mode === 'split'
                  ? 'bg-zinc-800 text-zinc-100 font-bold shadow-xs'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
              title="Split (Side-by-Side) Diff View"
            >
              <Columns2 className="size-3" />
              Split
            </button>
            <button
              type="button"
              onClick={() => setMode('raw')}
              className={`px-2 py-1 rounded-md text-[11px] font-medium flex items-center gap-1.5 transition-colors ${
                mode === 'raw'
                  ? 'bg-zinc-800 text-zinc-100 font-bold shadow-xs'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
              title="Raw Unified Patch View"
            >
              <FileText className="size-3" />
              Raw
            </button>
          </div>

          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopyDiff}
            className="h-7 text-xs text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800"
          >
            {copied ? <Check className="size-3 mr-1 text-emerald-400" /> : <Copy className="size-3 mr-1" />}
            <span className="hidden sm:inline">Copy Diff</span>
            <span className="inline sm:hidden">Copy</span>
          </Button>
        </div>
      </div>

      {/* Diff Content Body */}
      {isExpanded && (
        <div
          className={`overflow-x-auto overflow-y-auto font-mono text-[12px] leading-5 ${maxHeight} divide-y divide-zinc-800/40 select-text`}
        >
          {/* Raw Mode */}
          {mode === 'raw' && (
            <pre className="p-4 text-xs font-mono text-zinc-300 whitespace-pre overflow-x-auto leading-relaxed">
              {diff}
            </pre>
          )}

          {/* Unified (Inline) View */}
          {mode === 'unified' && (
            <table className="w-full border-collapse">
              <tbody>
                {parsed.unifiedLines.map((line, idx) => {
                  if (line.type === 'hunk') {
                    return (
                      <tr
                        key={idx}
                        className="bg-cyan-500/10 text-cyan-400 border-y border-cyan-500/20 font-bold"
                      >
                        <td className="w-12 px-2 py-0.5 text-right text-cyan-500/70 select-none text-[10px]">
                          ...
                        </td>
                        <td className="w-12 px-2 py-0.5 text-right text-cyan-500/70 select-none text-[10px]">
                          ...
                        </td>
                        <td className="w-6 px-1 py-0.5 text-center text-cyan-400 select-none">
                          @@
                        </td>
                        <td className="px-3 py-0.5 text-cyan-300 font-bold whitespace-pre">
                          {line.content}
                        </td>
                      </tr>
                    )
                  }

                  const isAddition = line.type === 'addition'
                  const isDeletion = line.type === 'deletion'

                  return (
                    <tr
                      key={idx}
                      className={`transition-colors ${
                        isAddition
                          ? 'bg-emerald-500/15 text-emerald-200 border-l-2 border-emerald-500'
                          : isDeletion
                            ? 'bg-rose-500/15 text-rose-200 border-l-2 border-rose-500'
                            : 'hover:bg-zinc-900/40 text-zinc-300'
                      }`}
                    >
                      {/* Old Line Number */}
                      <td className="w-12 px-2 py-0.5 text-right text-zinc-600 select-none text-[11px] font-mono border-r border-zinc-800/60">
                        {line.oldLineNumber || ''}
                      </td>

                      {/* New Line Number */}
                      <td className="w-12 px-2 py-0.5 text-right text-zinc-600 select-none text-[11px] font-mono border-r border-zinc-800/60">
                        {line.newLineNumber || ''}
                      </td>

                      {/* Gutter Indicator (+, -, ' ') */}
                      <td
                        className={`w-6 px-1 py-0.5 text-center font-bold select-none text-[12px] ${
                          isAddition
                            ? 'text-emerald-400'
                            : isDeletion
                              ? 'text-rose-400'
                              : 'text-zinc-600'
                        }`}
                      >
                        {isAddition ? '+' : isDeletion ? '-' : ' '}
                      </td>

                      {/* Code Content with Word Diff */}
                      <td className="px-3 py-0.5 whitespace-pre font-mono">
                        {renderSyntaxHighlit(
                          line.content,
                          line.pairedWith,
                          isAddition ? 'addition' : isDeletion ? 'deletion' : undefined
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}

          {/* Split (Side-by-Side) View */}
          {mode === 'split' && (
            <table className="w-full border-collapse table-fixed min-w-[580px]">
              <thead>
                <tr className="bg-zinc-900/60 text-zinc-400 text-[11px] border-b border-zinc-800/80">
                  <th className="w-1/2 px-3 py-1 text-left font-semibold border-r border-zinc-800/80">
                    <span className="flex items-center gap-1.5 text-rose-300">
                      <span className="size-2 rounded-full bg-rose-500" />
                      Original (Vulnerable Baseline)
                    </span>
                  </th>
                  <th className="w-1/2 px-3 py-1 text-left font-semibold">
                    <span className="flex items-center gap-1.5 text-emerald-300">
                      <span className="size-2 rounded-full bg-emerald-500" />
                      Remediated (Three-Tier Patched)
                    </span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {parsed.splitRows.map((row, idx) => {
                  if (row.type === 'hunk') {
                    return (
                      <tr
                        key={idx}
                        className="bg-cyan-500/10 text-cyan-400 border-y border-cyan-500/20 font-bold"
                      >
                        <td
                          colSpan={2}
                          className="px-3 py-0.5 text-cyan-300 font-bold whitespace-pre text-[11px]"
                        >
                          {row.hunkHeader}
                        </td>
                      </tr>
                    )
                  }

                  const leftIsDel = row.left?.type === 'deletion'
                  const rightIsAdd = row.right?.type === 'addition'

                  return (
                    <tr key={idx} className="divide-x divide-zinc-800/80">
                      {/* Left Side (Original / Deletion) */}
                      <td
                        className={`p-0 align-top ${
                          leftIsDel
                            ? 'bg-rose-500/15 text-rose-200 border-l-2 border-rose-500'
                            : row.left?.type === 'empty'
                              ? 'bg-zinc-950/40 text-zinc-600'
                              : 'text-zinc-300'
                        }`}
                      >
                        <div className="flex items-start">
                          <span className="w-10 px-1 py-0.5 text-right text-zinc-600 select-none text-[11px] font-mono shrink-0 border-r border-zinc-800/50">
                            {row.left?.lineNumber || ''}
                          </span>
                          <span
                            className={`w-5 px-1 py-0.5 text-center font-bold select-none shrink-0 ${
                              leftIsDel ? 'text-rose-400' : 'text-zinc-600'
                            }`}
                          >
                            {leftIsDel ? '-' : ' '}
                          </span>
                          <span className="px-2 py-0.5 whitespace-pre font-mono overflow-x-hidden text-ellipsis flex-1">
                            {renderSyntaxHighlit(
                              row.left?.content || '',
                              row.left?.pairedWith,
                              leftIsDel ? 'deletion' : undefined
                            )}
                          </span>
                        </div>
                      </td>

                      {/* Right Side (Patched / Addition) */}
                      <td
                        className={`p-0 align-top ${
                          rightIsAdd
                            ? 'bg-emerald-500/15 text-emerald-200 border-l-2 border-emerald-500'
                            : row.right?.type === 'empty'
                              ? 'bg-zinc-950/40 text-zinc-600'
                              : 'text-zinc-300'
                        }`}
                      >
                        <div className="flex items-start">
                          <span className="w-10 px-1 py-0.5 text-right text-zinc-600 select-none text-[11px] font-mono shrink-0 border-r border-zinc-800/50">
                            {row.right?.lineNumber || ''}
                          </span>
                          <span
                            className={`w-5 px-1 py-0.5 text-center font-bold select-none shrink-0 ${
                              rightIsAdd ? 'text-emerald-400' : 'text-zinc-600'
                            }`}
                          >
                            {rightIsAdd ? '+' : ' '}
                          </span>
                          <span className="px-2 py-0.5 whitespace-pre font-mono overflow-x-hidden text-ellipsis flex-1">
                            {renderSyntaxHighlit(
                              row.right?.content || '',
                              row.right?.pairedWith,
                              rightIsAdd ? 'addition' : undefined
                            )}
                          </span>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}
