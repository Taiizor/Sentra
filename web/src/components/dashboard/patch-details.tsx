import { cn } from 'cn'
import { Bot, CheckCircle2, ExternalLink, FlaskConical, ShieldQuestion, XCircle } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { DiffViewer } from '@/components/dashboard/diff-viewer'
import { CopyButton, DetailSection, Timestamp } from '@/components/dashboard/findings-shared'
import { PATCH_STATE_LABEL } from '@/components/dashboard/patch-format'
import type { PatchBundleView, PatchState } from '@/types/api'

/**
 * Read-only presentation of a model-generated patch bundle. Every field shown comes from the
 * bundle; model text is labelled as unverified and verification is always "not run".
 */

const PATCH_STATE_CLASS: Record<PatchState, string> = {
  proposed: 'border-zinc-600 text-zinc-300',
  applied: 'border-sky-500/40 bg-sky-500/10 text-sky-300',
  rolled_back: 'border-zinc-700 bg-zinc-800/60 text-zinc-400',
}

export function PatchStateBadge({ state }: { state: PatchState }) {
  return (
    <Badge variant="outline" className={cn('text-[10px]', PATCH_STATE_CLASS[state])}>
      {PATCH_STATE_LABEL[state]}
    </Badge>
  )
}

export function UnverifiedModelBadge() {
  return (
    <Badge variant="outline" className="gap-1 border-amber-500/40 bg-amber-500/10 text-[10px] text-amber-300">
      <Bot /> Unverified model output
    </Badge>
  )
}

export function ApplyCheckBadge({ patch }: { patch: PatchBundleView }) {
  return patch.appliesCleanly ? (
    <Badge variant="outline" className="gap-1 border-emerald-500/30 text-[10px] text-emerald-300" title="Dry-run apply against the workspace file">
      <CheckCircle2 /> Applies cleanly
    </Badge>
  ) : (
    <Badge variant="outline" className="gap-1 border-rose-500/30 text-[10px] text-rose-300" title={patch.applyCheckDetail ?? undefined}>
      <XCircle /> Does not apply
    </Badge>
  )
}

/** The prominent verification notice required on every patch view. */
export function VerificationNotRunNotice({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        'flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs',
        className,
      )}
    >
      <ShieldQuestion className="mt-0.5 size-4 shrink-0 text-amber-400" />
      <div className="flex flex-col gap-0.5">
        <span className="font-semibold text-amber-200">Verification: not run</span>
        <span className="text-zinc-400">
          No isolated verifier exists yet. This patch has not been compiled, tested or re-scanned by Sentra. Review
          the diff yourself before applying it or opening a pull request.
        </span>
      </div>
    </div>
  )
}

function ModelText({ text }: { text: string }) {
  return <p className="whitespace-pre-wrap text-xs leading-relaxed text-zinc-300">{text}</p>
}

function CodeBlock({ code, label }: { code: string; label: string }) {
  return (
    <div className="flex min-w-0 flex-col overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950">
      <div className="flex items-center justify-between border-b border-zinc-800 bg-zinc-900/70 px-3 py-1 text-[11px] text-zinc-400">
        <span>{label}</span>
        <CopyButton text={code} />
      </div>
      <pre className="max-h-64 overflow-auto p-3 font-mono text-[11px] leading-5 text-zinc-300">{code}</pre>
    </div>
  )
}

export function PatchDetails({ patch }: { patch: PatchBundleView }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-zinc-400">
        <UnverifiedModelBadge />
        <PatchStateBadge state={patch.state} />
        <ApplyCheckBadge patch={patch} />
        <span className="font-mono text-zinc-500">
          {patch.provider}:{patch.model}
        </span>
        <span>·</span>
        <span>
          generated <Timestamp value={patch.createdAt} /> by <span className="text-zinc-300">{patch.createdBy}</span>
        </span>
      </div>

      <VerificationNotRunNotice />

      <DetailSection title="Dry-run apply check">
        <div
          className={cn(
            'rounded-lg border px-3 py-2 text-xs',
            patch.appliesCleanly
              ? 'border-emerald-500/20 bg-emerald-500/5 text-emerald-200'
              : 'border-rose-500/20 bg-rose-500/5 text-rose-200',
          )}
        >
          {patch.appliesCleanly
            ? `The diff applies to the current content of ${patch.targetPath}.`
            : `The diff does not apply to the current content of ${patch.targetPath}.`}
          {patch.applyCheckDetail && (
            <span className="mt-1 block font-mono text-[11px] text-zinc-400">{patch.applyCheckDetail}</span>
          )}
        </div>
      </DetailSection>

      {patch.rootCause && (
        <DetailSection title="Root cause (model output)">
          <ModelText text={patch.rootCause} />
        </DetailSection>
      )}
      {patch.rationale && (
        <DetailSection title="Rationale (model output)">
          <ModelText text={patch.rationale} />
        </DetailSection>
      )}

      <DetailSection title="Unified diff">
        <DiffViewer diff={patch.diff} filePath={patch.targetPath} title={patch.targetPath} />
      </DetailSection>

      {(patch.originalSnippet || patch.patchedSnippet) && (
        <DetailSection title="Snippets (model output)">
          <div className="grid gap-2 md:grid-cols-2">
            {patch.originalSnippet && <CodeBlock code={patch.originalSnippet} label="Original" />}
            {patch.patchedSnippet && <CodeBlock code={patch.patchedSnippet} label="Patched" />}
          </div>
        </DetailSection>
      )}

      {patch.testCode && (
        <DetailSection
          title="Suggested test"
          aside={
            <span className="flex items-center gap-1 text-[10px] text-amber-300">
              <FlaskConical className="size-3" /> suggested, not executed
            </span>
          }
        >
          <CodeBlock code={patch.testCode} label="Test code proposed by the model" />
        </DetailSection>
      )}

      {(patch.branchName || patch.commitMessage) && (
        <DetailSection title="Proposed branch & commit (model output)">
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
            {patch.branchName && (
              <>
                <dt className="text-zinc-500">Branch</dt>
                <dd className="break-all font-mono text-zinc-300">{patch.branchName}</dd>
              </>
            )}
            {patch.commitMessage && (
              <>
                <dt className="text-zinc-500">Commit message</dt>
                <dd className="whitespace-pre-wrap font-mono text-zinc-300">{patch.commitMessage}</dd>
              </>
            )}
          </dl>
        </DetailSection>
      )}

      <DetailSection title="History">
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
          <dt className="text-zinc-500">Bundle</dt>
          <dd className="break-all font-mono text-zinc-400">{patch.bundleId}</dd>
          <dt className="text-zinc-500">Generated</dt>
          <dd className="text-zinc-300">
            <Timestamp value={patch.createdAt} /> · {patch.createdBy}
          </dd>
          {patch.appliedAt && (
            <>
              <dt className="text-zinc-500">Applied</dt>
              <dd className="text-zinc-300">
                <Timestamp value={patch.appliedAt} /> · {patch.appliedBy ?? 'unknown'}
              </dd>
            </>
          )}
          {patch.rolledBackAt && (
            <>
              <dt className="text-zinc-500">Rolled back</dt>
              <dd className="text-zinc-300">
                <Timestamp value={patch.rolledBackAt} /> · {patch.rolledBackBy ?? 'unknown'}
              </dd>
            </>
          )}
          {patch.pullRequest && (
            <>
              <dt className="text-zinc-500">Pull request</dt>
              <dd>
                <a
                  href={patch.pullRequest.url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="inline-flex items-center gap-1 text-sky-300 hover:underline"
                >
                  #{patch.pullRequest.number} <ExternalLink className="size-3" />
                </a>
              </dd>
            </>
          )}
        </dl>
      </DetailSection>
    </div>
  )
}
