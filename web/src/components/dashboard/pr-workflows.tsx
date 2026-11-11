import { useState } from 'react'
import { ChevronDown, ChevronRight, ExternalLink, RefreshCw, Workflow } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { api } from '@/lib/api'
import { useResource } from '@/lib/use-resource'
import type { PullRequestView, WorkflowJobView, WorkflowRunView } from '@/types/api'
import { RunStateIcon } from './pr-badges'
import { formatDuration, runStateLabel, secondsBetween, shortSha } from './settings-format'
import { ErrorState, LoadingRows, TimeAgo } from './settings-kit'

/** GitHub Actions runs for the PR's head commit, with their jobs and steps as reported by GitHub. */
export function PrWorkflows({ tenantId, pr }: { tenantId: string; pr: PullRequestView }) {
  const workflows = useResource(`gh-workflows:${tenantId}:${pr.number}:${pr.headSha}`, (signal) =>
    api.github.workflows(tenantId, pr.number, signal),
  )

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] text-muted-foreground">
          GitHub Actions runs for head commit <span className="font-mono text-foreground">{shortSha(pr.headSha)}</span>. Status checks from
          other CI systems are only counted in the PR&apos;s checks summary.
        </span>
        <Button type="button" variant="outline" size="xs" onClick={workflows.reload} disabled={workflows.loading} className="gap-1 shrink-0">
          <RefreshCw className={`size-3 ${workflows.loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {workflows.error ? (
        <ErrorState title="Could not load workflow runs" error={workflows.error} onRetry={workflows.reload} />
      ) : !workflows.data ? (
        <LoadingRows rows={3} />
      ) : workflows.data.runs.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border/60 p-6 text-center text-xs text-muted-foreground flex flex-col items-center gap-1.5">
          <Workflow className="size-5" />
          No GitHub Actions runs for {shortSha(workflows.data.headSha)}.
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {workflows.data.runs.map((run) => (
            <RunCard key={run.id} run={run} />
          ))}
        </div>
      )}
    </div>
  )
}

function RunCard({ run }: { run: WorkflowRunView }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-lg border border-border/60 bg-card/40">
      <div className="flex items-start gap-2 p-2.5 hover:bg-muted/20 rounded-lg">
        <button
          type="button"
          onClick={() => setOpen((value) => !value)}
          className="flex flex-1 min-w-0 items-start gap-2 text-left"
          aria-expanded={open}
        >
          {open ? <ChevronDown className="size-3.5 mt-0.5 shrink-0" /> : <ChevronRight className="size-3.5 mt-0.5 shrink-0" />}
          <RunStateIcon status={run.status} conclusion={run.conclusion} />
          <div className="flex flex-col gap-0.5 min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-semibold text-foreground">{run.name}</span>
              <Badge variant="outline" className="text-[10px] font-mono">
                {runStateLabel(run.status, run.conclusion)}
              </Badge>
              <span className="text-[10px] font-mono text-muted-foreground">
                #{run.runNumber}
                {run.runAttempt > 1 ? ` · attempt ${run.runAttempt}` : ''}
              </span>
            </div>
            <span className="text-[11px] text-muted-foreground flex flex-wrap gap-x-2">
              <span className="font-mono">{run.workflowPath}</span>
              <span>event: {run.event}</span>
              {run.headBranch && <span className="font-mono">{run.headBranch}</span>}
              <span>
                started <TimeAgo iso={run.runStartedAt ?? run.createdAt} />
              </span>
              <span>
                updated <TimeAgo iso={run.updatedAt} />
              </span>
              <span>
                {run.jobs.length} job{run.jobs.length === 1 ? '' : 's'}
              </span>
            </span>
          </div>
        </button>
        <a
          href={run.htmlUrl}
          target="_blank"
          rel="noreferrer noopener"
          className="text-[11px] text-muted-foreground hover:text-foreground inline-flex items-center gap-0.5 shrink-0"
        >
          GitHub <ExternalLink className="size-3" />
        </a>
      </div>
      {open && (
        <div className="border-t border-border/40 p-2.5 flex flex-col gap-2">
          {run.jobs.length === 0 ? (
            <span className="text-[11px] text-muted-foreground">GitHub reported no jobs for this run.</span>
          ) : (
            run.jobs.map((job) => <JobBlock key={job.id} job={job} />)
          )}
        </div>
      )}
    </div>
  )
}

function JobBlock({ job }: { job: WorkflowJobView }) {
  const duration = secondsBetween(job.startedAt, job.completedAt)
  return (
    <div className="rounded-md border border-border/40 bg-zinc-950/40">
      <div className="flex items-center gap-2 px-2.5 py-1.5 border-b border-border/30">
        <RunStateIcon status={job.status} conclusion={job.conclusion} />
        <span className="text-[11px] font-semibold text-foreground flex-1 min-w-0 truncate">{job.name}</span>
        <span className="text-[10px] font-mono text-muted-foreground">{runStateLabel(job.status, job.conclusion)}</span>
        <span className="text-[10px] font-mono text-muted-foreground">{formatDuration(duration)}</span>
        {job.htmlUrl && (
          <a href={job.htmlUrl} target="_blank" rel="noreferrer noopener" className="text-muted-foreground hover:text-foreground">
            <ExternalLink className="size-3" />
          </a>
        )}
      </div>
      {job.steps.length === 0 ? (
        <div className="px-2.5 py-1.5 text-[11px] text-muted-foreground">No steps reported.</div>
      ) : (
        <ol className="flex flex-col">
          {job.steps.map((step) => (
            <li key={step.number} className="flex items-center gap-2 px-2.5 py-1 text-[11px] border-b border-border/20 last:border-b-0">
              <span className="w-5 text-right font-mono text-[10px] text-muted-foreground">{step.number}</span>
              <RunStateIcon status={step.status} conclusion={step.conclusion} />
              <span className="flex-1 min-w-0 truncate text-foreground" title={step.name}>
                {step.name}
              </span>
              <span className="font-mono text-[10px] text-muted-foreground">{runStateLabel(step.status, step.conclusion)}</span>
              <span className="w-14 text-right font-mono text-[10px] text-muted-foreground">{formatDuration(step.durationSeconds)}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}
