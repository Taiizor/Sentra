import { useMemo, useState } from 'react'
import { cn } from 'cn'
import { AlertTriangle, FileDiff } from 'lucide-react'
import { CopyButton } from '@/components/dashboard/findings-shared'
import { parseUnifiedDiff, type DiffRow, type DiffRowKind } from '@/components/dashboard/patch-diff'

/** Faithful rendering of a unified diff (unified, split or raw), with a copy button. */

type SplitRow = { kind: 'full'; row: DiffRow } | { kind: 'pair'; left: DiffRow | null; right: DiffRow | null }

function toSplitRows(rows: DiffRow[]): SplitRow[] {
  const result: SplitRow[] = []
  let index = 0
  while (index < rows.length) {
    const row = rows[index]
    if (row.kind === 'context') {
      result.push({ kind: 'pair', left: row, right: row })
      index += 1
      continue
    }
    if (row.kind === 'del' || row.kind === 'add') {
      const removed: DiffRow[] = []
      const added: DiffRow[] = []
      while (index < rows.length && rows[index].kind === 'del') removed.push(rows[index++])
      while (index < rows.length && rows[index].kind === 'add') added.push(rows[index++])
      const count = Math.max(removed.length, added.length)
      for (let offset = 0; offset < count; offset += 1) {
        result.push({ kind: 'pair', left: removed[offset] ?? null, right: added[offset] ?? null })
      }
      continue
    }
    result.push({ kind: 'full', row })
    index += 1
  }
  return result
}

const ROW_CLASS: Record<DiffRowKind, string> = {
  file: 'bg-zinc-900 text-zinc-300 font-semibold',
  meta: 'text-zinc-500',
  hunk: 'bg-sky-950/40 text-sky-300',
  add: 'bg-emerald-950/40 text-emerald-200',
  del: 'bg-rose-950/40 text-rose-200',
  context: 'text-zinc-300',
  note: 'text-zinc-500 italic',
}

const SIGN: Partial<Record<DiffRowKind, string>> = { add: '+', del: '-', context: ' ' }

function Gutter({ value }: { value: number | null }) {
  return (
    <span className="w-10 shrink-0 select-none border-r border-zinc-800/80 pr-1.5 text-right text-[10px] leading-5 text-zinc-600">
      {value ?? ''}
    </span>
  )
}

function CodeText({ text }: { text: string }) {
  // A zero-width placeholder keeps empty lines at full height.
  return <span className="whitespace-pre pl-2 pr-4">{text.length > 0 ? text : '\u200b'}</span>
}

function UnifiedRows({ rows }: { rows: DiffRow[] }) {
  return (
    <div className="min-w-full w-max">
      {rows.map((row, index) => (
        <div key={index} className={cn('flex leading-5', ROW_CLASS[row.kind])}>
          {row.kind === 'add' || row.kind === 'del' || row.kind === 'context' ? (
            <>
              <Gutter value={row.oldLine} />
              <Gutter value={row.newLine} />
              <span className="w-4 shrink-0 select-none text-center opacity-70">{SIGN[row.kind]}</span>
              <CodeText text={row.text} />
            </>
          ) : (
            <span className="whitespace-pre px-3">{row.text}</span>
          )}
        </div>
      ))}
    </div>
  )
}

function SplitCell({ row, side }: { row: DiffRow | null; side: 'left' | 'right' }) {
  if (!row) return <div className="flex min-w-0 flex-1 bg-zinc-900/40 leading-5" />
  const kind = row.kind
  return (
    <div className={cn('flex min-w-0 flex-1 leading-5', kind === 'context' ? ROW_CLASS.context : ROW_CLASS[kind])}>
      <Gutter value={side === 'left' ? row.oldLine : row.newLine} />
      <span className="w-4 shrink-0 select-none text-center opacity-70">{SIGN[kind]}</span>
      <CodeText text={row.text} />
    </div>
  )
}

function SplitRows({ rows }: { rows: DiffRow[] }) {
  const split = useMemo(() => toSplitRows(rows), [rows])
  return (
    <div className="min-w-full w-max">
      {split.map((entry, index) =>
        entry.kind === 'full' ? (
          <div key={index} className={cn('whitespace-pre px-3 leading-5', ROW_CLASS[entry.row.kind])}>
            {entry.row.text}
          </div>
        ) : (
          <div key={index} className="grid grid-cols-2 divide-x divide-zinc-800">
            <SplitCell row={entry.left} side="left" />
            <SplitCell row={entry.right} side="right" />
          </div>
        ),
      )}
    </div>
  )
}

type DiffMode = 'unified' | 'split' | 'raw'
const MODES: { id: DiffMode; label: string }[] = [
  { id: 'unified', label: 'Unified' },
  { id: 'split', label: 'Split' },
  { id: 'raw', label: 'Raw' },
]

export function DiffViewer({
  diff,
  filePath,
  title,
  maxHeightClass = 'max-h-[420px]',
}: {
  diff: string
  filePath?: string | null
  title?: string
  maxHeightClass?: string
}) {
  const [mode, setMode] = useState<DiffMode>('unified')
  const parsed = useMemo(() => parseUnifiedDiff(diff), [diff])
  const empty = diff.trim().length === 0

  return (
    <div className="flex flex-col overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 bg-zinc-900/70 px-3 py-1.5 text-xs">
        <div className="flex min-w-0 items-center gap-2">
          <FileDiff className="size-3.5 shrink-0 text-zinc-400" />
          <span className="truncate font-mono text-zinc-300" title={filePath ?? title}>
            {title ?? filePath ?? 'Unified diff'}
          </span>
          {!empty && (
            <span className="shrink-0 font-mono text-[10px]">
              <span className="text-emerald-400">+{parsed.additions}</span>{' '}
              <span className="text-rose-400">-{parsed.deletions}</span>{' '}
              <span className="text-zinc-500">
                · {parsed.hunks} hunk{parsed.hunks === 1 ? '' : 's'}
              </span>
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <div className="flex overflow-hidden rounded-md border border-zinc-800">
            {MODES.map((option) => (
              <button
                key={option.id}
                type="button"
                onClick={() => setMode(option.id)}
                className={cn(
                  'px-2 py-0.5 text-[10px] transition-colors',
                  mode === option.id ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300',
                )}
                aria-pressed={mode === option.id}
              >
                {option.label}
              </button>
            ))}
          </div>
          <CopyButton text={diff} label="Copy diff" />
        </div>
      </div>

      {parsed.inconsistentHunks > 0 && (
        <div className="flex items-center gap-1.5 border-b border-amber-500/20 bg-amber-500/5 px-3 py-1 text-[11px] text-amber-300">
          <AlertTriangle className="size-3 shrink-0" />
          {parsed.inconsistentHunks} hunk{parsed.inconsistentHunks === 1 ? '' : 's'} do not match the line counts in
          their @@ header; line numbers after the mismatch are omitted.
        </div>
      )}

      <div className={cn('overflow-auto font-mono text-[11px]', maxHeightClass)}>
        {empty ? (
          <div className="p-4 text-center text-xs text-zinc-500">The diff is empty.</div>
        ) : mode === 'raw' ? (
          <pre className="w-max min-w-full whitespace-pre p-3 leading-5 text-zinc-300">{diff}</pre>
        ) : mode === 'split' ? (
          <SplitRows rows={parsed.rows} />
        ) : (
          <UnifiedRows rows={parsed.rows} />
        )}
      </div>
    </div>
  )
}
