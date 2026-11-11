import { Fragment, useState } from 'react'
import { ChevronDown, ChevronRight, SearchCheck } from 'lucide-react'
import { MarkdownView } from '@/components/ui/markdown-view'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import type { SastMatchView, SnippetScanView } from '@/types/api'
import { formatDateTime } from './console-format'
import { EmptyBlock, SeverityBadge } from './console-kit'

/** Matches returned by `sentra scan` for a snippet, rendered without any additions. */
export function StudioResults({
  result,
  scannedAt,
  stale,
}: {
  result: SnippetScanView
  scannedAt: string
  stale: boolean
}) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
        <span>
          <span className="font-mono text-zinc-200">{result.fileName}</span> scanned {formatDateTime(scannedAt)}
        </span>
        <span>files scanned: {result.filesScanned}</span>
        <span>signals: {result.signalsFound}</span>
        {stale && <span className="text-amber-300">The editor changed after this scan; results refer to the scanned version.</span>}
      </div>
      {result.matches.length === 0 ? (
        <EmptyBlock icon={<SearchCheck />} title={`No signals from Sentra's rules for ${result.fileName}`}>
          The core rules emitted nothing for this input. The rules are heuristic and selected by file name, so the absence
          of a signal is not evidence that the code is safe.
        </EmptyBlock>
      ) : (
        <MatchTable matches={result.matches} />
      )}
      <p className="text-[11px] text-muted-foreground">
        Signals are unverified candidates. Snippet results are not added to the findings catalog.
      </p>
    </div>
  )
}

function MatchTable({ matches }: { matches: SastMatchView[] }) {
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set())
  const toggle = (index: number) =>
    setExpanded((current) => {
      const next = new Set(current)
      if (next.has(index)) next.delete(index)
      else next.add(index)
      return next
    })

  return (
    <Table className="text-xs">
      <TableHeader>
        <TableRow>
          <TableHead className="w-6" />
          <TableHead>Line</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Rule</TableHead>
          <TableHead>CWE</TableHead>
          <TableHead>Category</TableHead>
          <TableHead>Snippet</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {matches.map((match, index) => {
          const open = expanded.has(index)
          const hasRationale = !!match.rationale
          return (
            <Fragment key={`${match.ruleId}:${match.line}:${index}`}>
              <TableRow
                className={hasRationale ? 'cursor-pointer' : undefined}
                onClick={hasRationale ? () => toggle(index) : undefined}
              >
                <TableCell>
                  {hasRationale &&
                    (open ? <ChevronDown className="size-3.5 text-zinc-400" /> : <ChevronRight className="size-3.5 text-zinc-400" />)}
                </TableCell>
                <TableCell className="font-mono">{match.line}</TableCell>
                <TableCell>
                  <SeverityBadge severity={match.severity} />
                </TableCell>
                <TableCell className="max-w-64 whitespace-normal">
                  <div className="font-mono text-[11px] text-zinc-100">{match.ruleId}</div>
                  <div className="text-[11px] text-zinc-400">{match.ruleName}</div>
                </TableCell>
                <TableCell className="font-mono text-[11px]">{match.cwe ?? 'n/a'}</TableCell>
                <TableCell className="text-[11px]">{match.category ?? 'n/a'}</TableCell>
                <TableCell className="max-w-80 truncate font-mono text-[11px] text-zinc-300" title={match.snippet ?? undefined}>
                  {match.snippet ?? 'not returned'}
                </TableCell>
              </TableRow>
              {open && match.rationale && (
                <TableRow className="hover:bg-transparent">
                  <TableCell />
                  <TableCell colSpan={6} className="whitespace-normal">
                    <div className="rounded border border-zinc-800 bg-zinc-950 p-2">
                      <MarkdownView content={match.rationale} />
                    </div>
                  </TableCell>
                </TableRow>
              )}
            </Fragment>
          )
        })}
      </TableBody>
    </Table>
  )
}
