import { useState, useMemo } from 'react'
import {
  Copy,
  Check,
  Columns2,
  AlignLeft,
  GitCompare,
  Code2,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { toast } from 'sonner'
import { copyText } from '@/lib/clipboard'

interface SurgicalDiffViewProps {
  diff: string
  title?: string
  filePath?: string
  className?: string
  defaultMode?: 'unified' | 'split'
}

interface ParsedLine {
  type: 'header' | 'comment' | 'deletion' | 'addition' | 'context'
  content: string
  raw: string
  oldLineNumber?: number
  newLineNumber?: number
  pairedWith?: string
}

export function SurgicalDiffView({
  diff,
  title,
  filePath,
  className = '',
  defaultMode = 'unified',
}: SurgicalDiffViewProps) {
  const [mode, setMode] = useState<'unified' | 'split'>(defaultMode)
  const [copied, setCopied] = useState(false)

  const parsed = useMemo(() => {
    if (!diff) {
      return { lines: [], hasDiffMarkers: false, additions: 0, deletions: 0, rawLines: [] }
    }

    const rawLines = diff.replace(/\r\n/g, '\n').split('\n')
    let additions = 0
    let deletions = 0
    let oldLine = 1
    let newLine = 1

    const hasDiffMarkers = rawLines.some(
      (l) => l.startsWith('-') || l.startsWith('+') || l.startsWith('@@') || l.startsWith('---')
    )

    const lines: ParsedLine[] = []

    for (const line of rawLines) {
      if (line.startsWith('---') || line.startsWith('+++')) {
        lines.push({ type: 'header', content: line, raw: line })
        continue
      }

      if (line.startsWith('@@')) {
        const match = line.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/)
        if (match) {
          oldLine = parseInt(match[1], 10)
          newLine = parseInt(match[2], 10)
        }
        lines.push({ type: 'header', content: line, raw: line })
        continue
      }

      if (line.trim().startsWith('//') || line.trim().startsWith('#')) {
        lines.push({ type: 'comment', content: line, raw: line })
        continue
      }

      if (line.startsWith('-')) {
        deletions++
        lines.push({
          type: 'deletion',
          content: line.slice(1).trimStart(),
          raw: line,
          oldLineNumber: oldLine++,
        })
      } else if (line.startsWith('+')) {
        additions++
        lines.push({
          type: 'addition',
          content: line.slice(1).trimStart(),
          raw: line,
          newLineNumber: newLine++,
        })
      } else {
        const text = line.startsWith(' ') ? line.slice(1) : line
        lines.push({
          type: 'context',
          content: text,
          raw: line,
          oldLineNumber: oldLine++,
          newLineNumber: newLine++,
        })
      }
    }

    // Pair adjacent deletions and additions for word-level highlighting
    const pairedLines = [...lines]
    for (let i = 0; i < pairedLines.length; i++) {
      if (pairedLines[i].type === 'deletion' && pairedLines[i + 1]?.type === 'addition') {
        pairedLines[i].pairedWith = pairedLines[i + 1].content
        pairedLines[i + 1].pairedWith = pairedLines[i].content
      }
    }

    return { lines: pairedLines, hasDiffMarkers, additions, deletions, rawLines }
  }, [diff])

  async function handleCopy() {
    await copyText(diff)
    setCopied(true)
    toast.success('Remediation diff copied to clipboard')
    setTimeout(() => setCopied(false), 2000)
  }

  // Fallback: If not a diff with + or -, show as clean replacement code
  if (!parsed.hasDiffMarkers) {
    return (
      <div className={`rounded-xl border border-emerald-500/30 bg-zinc-950 overflow-hidden shadow-lg ${className}`}>
        <div className="flex items-center justify-between px-3.5 py-2 bg-emerald-950/20 border-b border-emerald-500/20 text-xs">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold">
            <Code2 className="size-4" />
            <span>{title || 'Recommended Replacement'}</span>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            className="h-6 px-2 text-[11px] text-zinc-400 hover:text-zinc-100"
          >
            {copied ? <Check className="size-3 text-emerald-400 mr-1" /> : <Copy className="size-3 mr-1" />}
            {copied ? 'Copied' : 'Copy'}
          </Button>
        </div>
        <div className="p-3.5 font-mono text-xs overflow-x-auto text-emerald-300 bg-zinc-950/80 leading-relaxed">
          <pre className="whitespace-pre">{diff}</pre>
        </div>
      </div>
    )
  }

  // Split view rows
  const deletionsList = parsed.lines.filter((l) => l.type === 'deletion')
  const additionsList = parsed.lines.filter((l) => l.type === 'addition')

  return (
    <div className={`flex flex-col rounded-xl border border-zinc-800 bg-zinc-950 overflow-hidden shadow-lg ${className}`}>
      {/* Diff Header Bar */}
      <div className="flex flex-wrap items-center justify-between px-3.5 py-2.5 bg-zinc-900/90 border-b border-zinc-800 text-xs select-none gap-2">
        <div className="flex items-center gap-2 min-w-0 max-w-full">
          <div className="size-6 rounded-md bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center shrink-0">
            <GitCompare className="size-3.5" />
          </div>
          <span className="font-mono font-bold text-zinc-200 truncate">
            {title || filePath || 'Surgical Diff Remedy'}
          </span>
          <div className="flex items-center gap-1.5 font-mono text-[10px] ml-1 shrink-0">
            <Badge variant="outline" className="px-1.5 py-0 border-emerald-500/30 bg-emerald-500/10 text-emerald-400 font-bold">
              +{parsed.additions}
            </Badge>
            <Badge variant="outline" className="px-1.5 py-0 border-rose-500/30 bg-rose-500/10 text-rose-400 font-bold">
              -{parsed.deletions}
            </Badge>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {/* Mode Switcher */}
          <div className="flex items-center p-0.5 rounded-lg border border-zinc-800 bg-zinc-950 text-xs">
            <button
              type="button"
              onClick={() => setMode('unified')}
              className={`px-2 py-0.5 rounded text-[11px] font-medium flex items-center gap-1 transition-colors ${
                mode === 'unified'
                  ? 'bg-zinc-800 text-zinc-100 font-bold shadow-xs'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <AlignLeft className="size-3" />
              Unified
            </button>
            <button
              type="button"
              onClick={() => setMode('split')}
              className={`px-2 py-0.5 rounded text-[11px] font-medium flex items-center gap-1 transition-colors ${
                mode === 'split'
                  ? 'bg-zinc-800 text-zinc-100 font-bold shadow-xs'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Columns2 className="size-3" />
              Split
            </button>
          </div>

          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            className="h-7 px-2 text-[11px] text-zinc-400 hover:text-zinc-100"
          >
            {copied ? <Check className="size-3.5 text-emerald-400 mr-1" /> : <Copy className="size-3.5 mr-1" />}
            {copied ? 'Copied' : 'Copy'}
          </Button>
        </div>
      </div>

      {/* Unified Diff View */}
      {mode === 'unified' ? (
        <div className="overflow-x-auto font-mono text-xs divide-y divide-zinc-850/40 select-text">
          {parsed.lines.map((line, idx) => {
            if (line.type === 'header') {
              return (
                <div
                  key={idx}
                  className="px-3 py-1 bg-sky-950/20 text-sky-400 text-[11px] font-semibold flex items-center gap-2 border-l-2 border-sky-500/60"
                >
                  <span>{line.raw}</span>
                </div>
              )
            }

            if (line.type === 'comment') {
              return (
                <div key={idx} className="px-3 py-1 bg-zinc-900/50 text-zinc-400 text-[11px] italic">
                  {line.raw}
                </div>
              )
            }

            if (line.type === 'deletion') {
              return (
                <div
                  key={idx}
                  className="flex items-start px-2 py-1 bg-rose-950/30 hover:bg-rose-950/50 transition-colors text-rose-200 border-l-2 border-rose-500"
                >
                  <span className="w-8 text-right text-rose-400/60 select-none text-[11px] shrink-0 mr-2">
                    {line.oldLineNumber || ''}
                  </span>
                  <span className="w-4 text-rose-400 font-bold select-none shrink-0">-</span>
                  <div className="flex-1 whitespace-pre-wrap break-all">
                    <DiffWordHighlight text={line.content} comparison={line.pairedWith} type="deletion" />
                  </div>
                </div>
              )
            }

            if (line.type === 'addition') {
              return (
                <div
                  key={idx}
                  className="flex items-start px-2 py-1 bg-emerald-950/30 hover:bg-emerald-950/50 transition-colors text-emerald-200 border-l-2 border-emerald-500"
                >
                  <span className="w-8 text-right text-emerald-400/60 select-none text-[11px] shrink-0 mr-2">
                    {line.newLineNumber || ''}
                  </span>
                  <span className="w-4 text-emerald-400 font-bold select-none shrink-0">+</span>
                  <div className="flex-1 whitespace-pre-wrap break-all">
                    <DiffWordHighlight text={line.content} comparison={line.pairedWith} type="addition" />
                  </div>
                </div>
              )
            }

            return (
              <div
                key={idx}
                className="flex items-start px-2 py-0.5 hover:bg-zinc-900/60 transition-colors text-zinc-300"
              >
                <span className="w-8 text-right text-zinc-600 select-none text-[11px] shrink-0 mr-2">
                  {line.oldLineNumber || ''}
                </span>
                <span className="w-4 text-zinc-600 select-none shrink-0"> </span>
                <div className="flex-1 whitespace-pre-wrap break-all">{line.content}</div>
              </div>
            )
          })}
        </div>
      ) : (
        /* Split (Side-by-Side) Diff View */
        <div className="overflow-x-auto select-text">
          <div className="grid grid-cols-2 divide-x divide-zinc-800 font-mono text-xs min-w-[500px]">
          {/* Left: Deletions (Before) */}
          <div className="flex flex-col divide-y divide-zinc-850/40 bg-zinc-950/80">
            <div className="px-3 py-1.5 bg-rose-950/20 border-b border-rose-900/30 text-rose-300 text-[11px] font-semibold flex items-center justify-between">
              <span>Original (Vulnerable)</span>
              <span className="font-mono text-[10px] text-rose-400/70">-{parsed.deletions}</span>
            </div>
            {deletionsList.map((del, idx) => (
              <div
                key={idx}
                className="flex items-start px-2 py-1 bg-rose-950/25 hover:bg-rose-950/45 text-rose-200 border-l-2 border-rose-500"
              >
                <span className="w-7 text-right text-rose-400/60 select-none text-[11px] shrink-0 mr-1.5">
                  {del.oldLineNumber || ''}
                </span>
                <span className="w-3 text-rose-400 font-bold select-none shrink-0">-</span>
                <div className="flex-1 whitespace-pre-wrap break-all">
                  <DiffWordHighlight text={del.content} comparison={del.pairedWith} type="deletion" />
                </div>
              </div>
            ))}
            {deletionsList.length === 0 && (
              <div className="p-4 text-center text-zinc-600 text-xs italic">No removed lines</div>
            )}
          </div>

          {/* Right: Additions (After) */}
          <div className="flex flex-col divide-y divide-zinc-850/40 bg-zinc-950/80">
            <div className="px-3 py-1.5 bg-emerald-950/20 border-b border-emerald-900/30 text-emerald-300 text-[11px] font-semibold flex items-center justify-between">
              <span>Remediated (Safe)</span>
              <span className="font-mono text-[10px] text-emerald-400/70">+{parsed.additions}</span>
            </div>
            {additionsList.map((add, idx) => (
              <div
                key={idx}
                className="flex items-start px-2 py-1 bg-emerald-950/25 hover:bg-emerald-950/45 text-emerald-200 border-l-2 border-emerald-500"
              >
                <span className="w-7 text-right text-emerald-400/60 select-none text-[11px] shrink-0 mr-1.5">
                  {add.newLineNumber || ''}
                </span>
                <span className="w-3 text-emerald-400 font-bold select-none shrink-0">+</span>
                <div className="flex-1 whitespace-pre-wrap break-all">
                  <DiffWordHighlight text={add.content} comparison={add.pairedWith} type="addition" />
                </div>
              </div>
            ))}
            {additionsList.length === 0 && (
              <div className="p-4 text-center text-zinc-600 text-xs italic">No added lines</div>
            )}
          </div>
        </div>
      </div>
      )}
    </div>
  )
}

/**
 * Word/Token Highlight for Differing Segments
 */
function DiffWordHighlight({
  text,
  comparison,
  type,
}: {
  text: string
  comparison?: string
  type: 'deletion' | 'addition'
}) {
  if (!comparison || text === comparison) {
    return <span>{text}</span>
  }

  let prefixLen = 0
  const minLen = Math.min(text.length, comparison.length)
  while (prefixLen < minLen && text[prefixLen] === comparison[prefixLen]) {
    prefixLen++
  }

  let suffixLen = 0
  while (
    suffixLen < minLen - prefixLen &&
    text[text.length - 1 - suffixLen] === comparison[comparison.length - 1 - suffixLen]
  ) {
    suffixLen++
  }

  const prefix = text.slice(0, prefixLen)
  const diffPart = text.slice(prefixLen, text.length - suffixLen)
  const suffix = text.slice(text.length - suffixLen)

  const highlightClass =
    type === 'deletion'
      ? 'bg-rose-500/40 text-rose-100 rounded px-1 font-bold'
      : 'bg-emerald-500/40 text-emerald-100 rounded px-1 font-bold'

  return (
    <>
      <span>{prefix}</span>
      {diffPart ? <span className={highlightClass}>{diffPart}</span> : null}
      <span>{suffix}</span>
    </>
  )
}
