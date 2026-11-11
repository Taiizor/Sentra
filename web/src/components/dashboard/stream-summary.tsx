import type { ReactNode } from 'react'
import { AlertTriangle, Boxes, Code2, FileSearch, GitCompareArrows } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { SEVERITIES, type LockfileView, type ScanRunView } from '@/types/api'
import { formatCount, formatDateTime } from './console-format'
import { CopyButton, KeyValue, SeverityBadge } from './console-kit'
import { codeqlAnalysisOutcome, codeqlOutcomeLabel } from './findings-format'

/** Renders the persisted result of one scan run exactly as the bridge reported it. */
export function ScanRunSummaryView({ run }: { run: ScanRunView }) {
  const summary = run.summary
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-3 rounded-lg border border-border/60 bg-card/40 p-3 sm:grid-cols-4">
        <KeyValue label="Run" mono>
          {run.runId}
        </KeyValue>
        <KeyValue label="Status">
          <Badge
            variant="outline"
            className={
              run.status === 'completed'
                ? 'border-emerald-500/30 text-emerald-300'
                : run.status === 'failed'
                  ? 'border-rose-500/30 text-rose-300'
                  : 'border-sky-500/30 text-sky-300'
            }
          >
            {run.status}
          </Badge>
        </KeyValue>
        <KeyValue label="Started">{formatDateTime(run.startedAt)}</KeyValue>
        <KeyValue label="Finished">{run.finishedAt ? formatDateTime(run.finishedAt) : 'not finished'}</KeyValue>
        <KeyValue label="Kind" mono>
          {run.kind}
        </KeyValue>
        <KeyValue label="Trigger / actor">
          {run.trigger} · {run.actor}
        </KeyValue>
        <KeyValue label="Git HEAD" mono>
          {run.gitHead ?? 'not a git checkout or not detected'}
        </KeyValue>
        <KeyValue label="Workspace" mono>
          {run.workspace}
        </KeyValue>
      </div>

      {run.error && (
        <div className="flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/5 p-2.5 text-xs text-rose-200">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-rose-400" />
          <span className="break-words">{run.error}</span>
        </div>
      )}

      {!summary ? (
        <p className="text-xs text-muted-foreground">The bridge did not record a summary for this run.</p>
      ) : (
        <>
          <div className="grid grid-cols-3 gap-2">
            <Metric label="New findings" value={summary.newFindings} tone="text-amber-300" />
            <Metric label="Resolved findings" value={summary.resolvedFindings} tone="text-emerald-300" />
            <Metric label="Still open" value={summary.stillOpen} tone="text-zinc-100" />
          </div>

          {summary.sast && (
            <SummarySection icon={<FileSearch className="size-3.5 text-amber-400" />} title="Static analysis (heuristic rules)">
              <div className="flex flex-wrap gap-4">
                <KeyValue label="Files scanned">{formatCount(summary.sast.filesScanned)}</KeyValue>
                <KeyValue label="Signals">{formatCount(summary.sast.signalsFound)}</KeyValue>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {SEVERITIES.map((severity) => (
                  <span key={severity} className="inline-flex items-center gap-1">
                    <SeverityBadge severity={severity} />
                    <span className="font-mono text-[11px] text-zinc-300">{summary.sast?.bySeverity[severity] ?? 0}</span>
                  </span>
                ))}
              </div>
              <p className="text-[11px] text-muted-foreground">Signals are unverified candidates.</p>
            </SummarySection>
          )}

          {summary.dependency ? (
            <SummarySection icon={<Boxes className="size-3.5 text-sky-400" />} title="Dependency audit">
              <div className="flex flex-wrap gap-4">
                <KeyValue label="Packages audited">{formatCount(summary.dependency.packagesAudited)}</KeyValue>
                <KeyValue label="Vulnerable packages">{formatCount(summary.dependency.vulnerablePackages)}</KeyValue>
                <KeyValue label="Vulnerabilities">{formatCount(summary.dependency.vulnerabilities)}</KeyValue>
                <KeyValue label="Advisory source">
                  {summary.dependency.advisorySource}, queried {formatDateTime(summary.dependency.queriedAt)}
                </KeyValue>
              </div>
              <LockfileList lockfiles={summary.dependency.lockfiles} />
            </SummarySection>
          ) : summary.dependencySkippedReason ? (
            <SummarySection icon={<Boxes className="size-3.5 text-zinc-500" />} title="Dependency audit skipped">
              <p className="text-xs text-zinc-300">{summary.dependencySkippedReason}</p>
            </SummarySection>
          ) : null}

          {summary.codeql && (
            <SummarySection icon={<Code2 className="size-3.5 text-violet-400" />} title="CodeQL language probe">
              <div className="flex flex-wrap gap-4">
                <KeyValue label="Primary language">{summary.codeql.primaryLanguage ?? 'none detected'}</KeyValue>
                <KeyValue label="CodeQL CLI">
                  {summary.codeql.codeqlInstalled ? 'found on the bridge host' : 'CodeQL not installed on the bridge host'}
                </KeyValue>
              </div>
              {summary.codeql.detectedLanguages.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {summary.codeql.detectedLanguages.map((entry) => (
                    <Badge key={entry.language} variant="outline" className="font-mono text-[10px]">
                      {entry.language}: {entry.filesCount} files
                    </Badge>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">No files matched a CodeQL-supported language extension.</p>
              )}
              {(summary.codeql.suggestedCreateCommand || summary.codeql.suggestedAnalyzeCommand) && (
                <div className="flex flex-col gap-1.5">
                  <span className="text-[11px] text-muted-foreground">
                    Suggested commands printed by the language probe (the probe counts files by extension and does not run CodeQL):
                  </span>
                  {[summary.codeql.suggestedCreateCommand, summary.codeql.suggestedAnalyzeCommand]
                    .filter((command): command is string => !!command)
                    .map((command) => (
                      <div
                        key={command}
                        className="flex items-center justify-between gap-2 rounded border border-zinc-800 bg-zinc-950 px-2 py-1"
                      >
                        <code className="break-all font-mono text-[11px] text-zinc-300">{command}</code>
                        <CopyButton text={command} />
                      </div>
                    ))}
                </div>
              )}
            </SummarySection>
          )}

          {summary.codeqlAnalysis && (
            <SummarySection icon={<Code2 className="size-3.5 text-violet-400" />} title="CodeQL host analysis">
              <div className="flex flex-wrap gap-4">
                <KeyValue label="Outcome">
                  <span className={codeqlAnalysisOutcome(summary.codeqlAnalysis, summary.stageErrors) === 'failed' ? 'text-rose-300' : undefined}>
                    {codeqlOutcomeLabel(summary.codeqlAnalysis, summary.stageErrors)}
                  </span>
                </KeyValue>
                {summary.codeqlAnalysis.codeqlVersion && <KeyValue label="CodeQL">{summary.codeqlAnalysis.codeqlVersion}</KeyValue>}
                {summary.codeqlAnalysis.suite && <KeyValue label="Suite">{summary.codeqlAnalysis.suite}</KeyValue>}
                {codeqlAnalysisOutcome(summary.codeqlAnalysis, summary.stageErrors) === 'analyzed' && (
                  <KeyValue label="Results">{formatCount(summary.codeqlAnalysis.resultsTotal)}</KeyValue>
                )}
              </div>
              <p className="text-xs text-zinc-300">{summary.codeqlAnalysis.message}</p>
              {summary.codeqlAnalysis.languages.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {summary.codeqlAnalysis.languages.map((entry) => (
                    <Badge key={entry.language} variant="outline" className="font-mono text-[10px]" title={entry.reason ?? undefined}>
                      {entry.language}: {entry.status}
                      {entry.status === 'analyzed' ? ` (${entry.results})` : ''}
                    </Badge>
                  ))}
                </div>
              )}
              {summary.codeqlAnalysis.warnings.length > 0 && (
                <ul className="list-disc pl-4 text-[11px] text-amber-300/90">
                  {summary.codeqlAnalysis.warnings.map((warning) => (
                    <li key={warning}>{warning}</li>
                  ))}
                </ul>
              )}
            </SummarySection>
          )}

          {summary.stageErrors.length > 0 && (
            <SummarySection icon={<AlertTriangle className="size-3.5 text-rose-400" />} title="Stage errors">
              <ul className="flex flex-col gap-1">
                {summary.stageErrors.map((entry, index) => (
                  <li key={`${entry.stage}-${index}`} className="text-xs text-rose-200">
                    <span className="font-mono text-rose-300">{entry.stage}</span>: {entry.message}
                  </li>
                ))}
              </ul>
            </SummarySection>
          )}
        </>
      )}
    </div>
  )
}

function Metric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="flex flex-col rounded-lg border border-border/60 bg-card/40 p-2.5">
      <span className="text-[10px] font-semibold uppercase text-muted-foreground">{label}</span>
      <span className={`font-mono text-lg font-semibold ${tone}`}>{value.toLocaleString()}</span>
    </div>
  )
}

function SummarySection({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-border/60 bg-background/40 p-3">
      <span className="flex items-center gap-1.5 text-xs font-semibold text-zinc-100">
        {icon}
        {title}
      </span>
      {children}
    </div>
  )
}

export function LockfileList({ lockfiles }: { lockfiles: LockfileView[] }) {
  if (lockfiles.length === 0) {
    return <p className="text-xs text-muted-foreground">No supported lockfiles were found in the workspace.</p>
  }
  return (
    <ul className="flex flex-col gap-1">
      {lockfiles.map((lockfile) => (
        <li key={lockfile.path} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px]">
          <GitCompareArrows className="size-3 text-zinc-500" />
          <span className="font-mono text-zinc-200">{lockfile.path}</span>
          <span className="text-zinc-500">
            {lockfile.kind}
            {lockfile.ecosystem ? ` · ${lockfile.ecosystem}` : ''} · {lockfile.packages} packages
          </span>
          {lockfile.parseError && <span className="text-rose-300">parse error: {lockfile.parseError}</span>}
        </li>
      ))}
    </ul>
  )
}
