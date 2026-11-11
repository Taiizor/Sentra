import { useState } from 'react'
import { FileSearch, Info, ScanLine } from 'lucide-react'
import { toast } from 'sonner'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api, errorMessage } from '@/lib/api'
import { useConsole } from '@/lib/console-context'
import type { PrScanResultView, PullRequestView } from '@/types/api'
import { SecurityStatusBadge, SeverityBadge } from './pr-badges'
import { shortSha } from './settings-format'
import { ErrorState, GatedButton, LoadingRows, TimeAgo } from './settings-kit'

export function PrScanPanel({
  tenantId,
  pr,
  scan,
  loading,
  error,
  onRetry,
  onScanned,
}: {
  tenantId: string
  pr: PullRequestView
  scan: PrScanResultView | null | undefined
  loading: boolean
  error: unknown
  onRetry: () => void
  onScanned: (result: PrScanResultView) => void
}) {
  const { invalidate } = useConsole()
  const [scanning, setScanning] = useState(false)

  async function runScan() {
    setScanning(true)
    try {
      const result = await api.github.scan(tenantId, pr.number)
      onScanned(result)
      invalidate()
      if (result.status === 'failed') {
        toast.error(`Scan of #${pr.number} has no complete result`, { description: result.error ?? 'The scanner did not return a result.' })
      } else {
        toast.success(`Scanned #${pr.number} at ${shortSha(result.headSha)}`, {
          description: `${result.filesScanned} of ${result.filesConsidered} changed files scanned · ${result.signalsFound} candidate signals (${result.criticalCount} critical, ${result.highCount} high).`,
        })
      }
    } catch (failure) {
      toast.error(`Could not scan #${pr.number}`, { description: errorMessage(failure) })
    } finally {
      setScanning(false)
    }
  }

  const stale = scan ? scan.headSha !== pr.headSha : false

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center gap-2 flex-wrap text-xs">
          {scan ? (
            <SecurityStatusBadge
              security={{
                status: stale ? 'stale' : scan.status,
                scannedHeadSha: scan.headSha,
                scannedAt: scan.scannedAt,
                scannedBy: scan.scannedBy,
                signalsFound: scan.signalsFound,
                criticalCount: scan.criticalCount,
                highCount: scan.highCount,
                filesScanned: scan.filesScanned,
                filesConsidered: scan.filesConsidered,
              }}
            />
          ) : (
            !loading && <span className="text-muted-foreground">Not scanned yet.</span>
          )}
          {scan && (
            <span className="text-[11px] text-muted-foreground">
              commit <span className="font-mono text-foreground">{shortSha(scan.headSha)}</span> · <TimeAgo iso={scan.scannedAt} /> by{' '}
              <span className="font-mono">{scan.scannedBy}</span>
            </span>
          )}
        </div>
        <GatedButton permission="github:scan" variant="default" onClick={() => void runScan()} busy={scanning} className="gap-1.5 text-xs">
          {!scanning && <ScanLine className="size-3" />}
          {scanning ? 'Scanning changed files…' : 'Scan changed files'}
        </GatedButton>
      </div>

      <div className="flex gap-2 rounded-md border border-border/50 bg-muted/20 p-2.5 text-[11px] text-muted-foreground">
        <Info className="size-3.5 shrink-0 mt-0.5" />
        <span>
          Only the files this pull request changes are scanned, as they exist at its head commit (currently{' '}
          <span className="font-mono text-foreground">{shortSha(pr.headSha)}</span>). The bridge downloads them through the GitHub API into a
          private temporary directory and runs Sentra&apos;s line-based scanner over them; the pull request is not checked out or executed.
          Every match is an unverified candidate that needs review.
        </span>
      </div>

      {stale && scan && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-2.5 text-[11px] text-amber-300">
          This result is for commit <span className="font-mono">{shortSha(scan.headSha)}</span>; the pull request head is now{' '}
          <span className="font-mono">{shortSha(pr.headSha)}</span>. Scan again to describe the current changes.
        </div>
      )}

      {error ? (
        <ErrorState title="Could not load the last scan" error={error} onRetry={onRetry} />
      ) : loading && scan === undefined ? (
        <LoadingRows rows={2} />
      ) : !scan ? (
        <div className="rounded-lg border border-dashed border-border/60 p-6 text-center text-xs text-muted-foreground flex flex-col items-center gap-1.5">
          <FileSearch className="size-5" />
          Sentra has not scanned this pull request yet.
        </div>
      ) : (
        <PrScanResult scan={scan} />
      )}
    </div>
  )
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex flex-col gap-0.5 rounded-md border border-border/50 bg-card/40 px-2.5 py-1.5">
      <span className="text-[10px] uppercase font-semibold text-muted-foreground">{label}</span>
      <span className="font-mono text-sm text-foreground">{value}</span>
    </div>
  )
}

function PrScanResult({ scan }: { scan: PrScanResultView }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
        <Metric label="Changed files" value={scan.filesConsidered} />
        <Metric label="Scanned" value={scan.filesScanned} />
        <Metric label="Skipped" value={scan.skipped.length} />
        <Metric label="Signals" value={scan.signalsFound} />
        <Metric label="Critical / High" value={`${scan.criticalCount} / ${scan.highCount}`} />
      </div>

      {scan.error && (
        <div className="rounded-md border border-rose-500/30 bg-rose-500/5 p-2.5 text-[11px] text-rose-300 break-words">
          Scan error: {scan.error}
        </div>
      )}

      {scan.matches.length > 0 ? (
        <div className="rounded-lg border border-border/60 overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="border-border/40 hover:bg-transparent">
                <TableHead className="text-[11px] h-8">Severity</TableHead>
                <TableHead className="text-[11px] h-8">Rule</TableHead>
                <TableHead className="text-[11px] h-8">Location</TableHead>
                <TableHead className="text-[11px] h-8">Evidence</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scan.matches.map((match, index) => (
                <TableRow key={`${match.ruleId}:${match.filePath}:${match.line}:${index}`} className="border-border/40 align-top">
                  <TableCell className="py-2">
                    <SeverityBadge severity={match.severity} />
                  </TableCell>
                  <TableCell className="py-2 text-[11px] whitespace-normal min-w-[160px]">
                    <div className="font-mono text-foreground">{match.ruleId}</div>
                    <div className="text-muted-foreground">{match.ruleName}</div>
                    {match.cwe && <div className="font-mono text-[10px] text-muted-foreground">{match.cwe}</div>}
                  </TableCell>
                  <TableCell className="py-2 font-mono text-[11px] text-foreground whitespace-normal break-all min-w-[140px]">
                    {match.filePath}:{match.line}
                  </TableCell>
                  <TableCell className="py-2 text-[11px] whitespace-normal min-w-[220px]">
                    {match.snippet && (
                      <pre className="font-mono text-[10.5px] bg-zinc-950/70 border border-border/40 rounded px-2 py-1 whitespace-pre-wrap break-all text-zinc-300">
                        {match.snippet}
                      </pre>
                    )}
                    {match.rationale && <div className="mt-1 text-muted-foreground">{match.rationale}</div>}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      ) : scan.status !== 'failed' ? (
        <div className="rounded-md border border-border/50 p-3 text-[11px] text-muted-foreground">
          No signals in the {scan.filesScanned} scanned file{scan.filesScanned === 1 ? '' : 's'} at {shortSha(scan.headSha)}. The heuristic rules
          cover a limited set of patterns; this does not show the change is free of vulnerabilities.
        </div>
      ) : null}

      {scan.skipped.length > 0 && (
        <details className="rounded-md border border-border/50 bg-card/30 p-2.5 text-[11px]">
          <summary className="cursor-pointer text-muted-foreground">
            {scan.skipped.length} changed file{scan.skipped.length === 1 ? ' was' : 's were'} not scanned
          </summary>
          <ul className="mt-2 flex flex-col gap-1">
            {scan.skipped.map((file) => (
              <li key={file.path} className="flex flex-wrap gap-x-2">
                <span className="font-mono text-foreground break-all">{file.path}</span>
                <span className="text-muted-foreground">— {file.reason}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  )
}
