import { useMemo, useState } from 'react'
import { CircleDot, ExternalLink, MessageSquare, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { api, errorMessage } from '@/lib/api'
import type { PrCommentResponse, PrScanResultView, PrStatusResponse, PullRequestView } from '@/types/api'
import { COMMIT_STATES, STATUS_CONTEXT, allowedStates, buildCommentDraft, suggestStatus, type CommitState } from './pr-publish-format'
import { shortSha } from './settings-format'
import { ConfirmDialog, GatedButton } from './settings-kit'

export function PrPublishPanel({
  tenantId,
  repository,
  pr,
  scan,
  viewerLogin,
}: {
  tenantId: string
  repository: { owner: string; repo: string }
  pr: PullRequestView
  scan: PrScanResultView | null | undefined
  viewerLogin: string | null
}) {
  const repoLabel = `${repository.owner}/${repository.repo}#${pr.number}`
  const draft = useMemo(() => buildCommentDraft(pr, scan), [pr, scan])
  const suggestion = useMemo(() => suggestStatus(pr, scan), [pr, scan])
  const allowed = useMemo(() => allowedStates(scan && scan.headSha === pr.headSha ? scan : null), [pr, scan])

  const [body, setBody] = useState(draft)
  const [commentConfirm, setCommentConfirm] = useState(false)
  const [posted, setPosted] = useState<PrCommentResponse | null>(null)

  const [state, setState] = useState<CommitState | null>(null)
  const [description, setDescription] = useState(suggestion.description)
  const [statusConfirm, setStatusConfirm] = useState(false)
  const [statusResult, setStatusResult] = useState<PrStatusResponse | null>(null)

  async function postComment() {
    try {
      const response = await api.github.comment(tenantId, pr.number, body)
      setPosted(response)
      toast.success(`Comment posted on ${repoLabel}`, { description: response.url })
    } catch (error) {
      toast.error('Comment was not posted', { description: errorMessage(error) })
      throw error
    }
  }

  async function postStatus() {
    if (!state) return
    try {
      const response = await api.github.commitStatus(tenantId, pr.number, { state, description: description.trim() })
      setStatusResult(response)
      toast.success(`Commit status set to ${response.state}`, { description: `${STATUS_CONTEXT} on ${shortSha(response.sha)}` })
    } catch (error) {
      toast.error('Commit status was not set', { description: errorMessage(error) })
      throw error
    }
  }

  const author = viewerLogin ? `@${viewerLogin}` : 'the account behind the configured GitHub credential'

  return (
    <div className="flex flex-col gap-4">
      {/* Review comment */}
      <section className="flex flex-col gap-2">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
            <MessageSquare className="size-3.5" />
            Review comment
          </span>
          <Button type="button" variant="ghost" size="xs" onClick={() => setBody(draft)} className="gap-1 text-muted-foreground" disabled={body === draft}>
            <RotateCcw className="size-3" />
            Reset to scan summary
          </Button>
        </div>
        <p className="text-[11px] text-muted-foreground">
          Prefilled from the latest Sentra scan of this pull request. Edit it before posting; the text is published exactly as written.
        </p>
        <Textarea
          value={body}
          onChange={(event) => setBody(event.target.value)}
          className="font-mono text-[11px] min-h-40 max-h-80"
          spellCheck={false}
          maxLength={60_000}
        />
        <div className="flex items-center justify-between gap-2 flex-wrap">
          {posted ? (
            <a href={posted.url} target="_blank" rel="noreferrer noopener" className="text-[11px] text-emerald-400 inline-flex items-center gap-1 hover:underline">
              Comment #{posted.id} posted <ExternalLink className="size-3" />
            </a>
          ) : (
            <span className="text-[11px] text-muted-foreground">Needs GitHub permission to write pull request comments.</span>
          )}
          <GatedButton permission="github:comment" variant="default" onClick={() => setCommentConfirm(true)} disabled={body.trim().length === 0} className="text-xs">
            Post review comment
          </GatedButton>
        </div>
      </section>

      {/* Commit status */}
      <section className="flex flex-col gap-2 border-t border-border/40 pt-4">
        <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
          <CircleDot className="size-3.5" />
          Commit status <span className="font-mono text-[11px] text-muted-foreground">{STATUS_CONTEXT}</span>
        </span>
        <p className="text-[11px] text-muted-foreground">
          You choose the state; Sentra never sets it for you. The bridge only publishes states backed by its stored scan of the current head
          commit — here: <span className="font-mono text-foreground">{allowed.join(', ')}</span>. Suggestion from the scan:{' '}
          {suggestion.state ? (
            <button type="button" className="font-mono text-foreground underline underline-offset-2" onClick={() => setState(suggestion.state)}>
              {suggestion.state}
            </button>
          ) : (
            <span className="font-mono">none — decide after reviewing the signals</span>
          )}
          .
        </p>
        <div className="flex flex-col sm:flex-row gap-2">
          <Select value={state} onValueChange={(value) => setState((value as CommitState | null) ?? null)}>
            <SelectTrigger size="sm" className="w-full sm:w-40 text-xs">
              <SelectValue placeholder="Choose a state">{(value: CommitState | null) => value ?? 'Choose a state'}</SelectValue>
            </SelectTrigger>
            <SelectContent>
              {COMMIT_STATES.map((option) => (
                <SelectItem key={option.value} value={option.value} disabled={!allowed.includes(option.value)}>
                  {option.label}
                  {!allowed.includes(option.value) && ' (not backed by the scan)'}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Input
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            maxLength={140}
            placeholder="Description shown on GitHub (max 140 characters)"
            className="text-xs h-7 flex-1"
          />
        </div>
        <div className="flex items-center justify-between gap-2 flex-wrap">
          {statusResult ? (
            <span className="text-[11px] text-emerald-400">
              Set to <span className="font-mono">{statusResult.state}</span> on <span className="font-mono">{shortSha(statusResult.sha)}</span>
              {statusResult.sha !== pr.headSha && (
                <span className="text-amber-400"> (the head moved since this list was loaded)</span>
              )}
            </span>
          ) : (
            <span className="text-[11px] text-muted-foreground">Needs GitHub permission to write commit statuses.</span>
          )}
          <GatedButton
            permission="github:status"
            variant="default"
            onClick={() => setStatusConfirm(true)}
            disabled={!state || description.trim().length === 0}
            className="text-xs"
          >
            Set commit status
          </GatedButton>
        </div>
      </section>

      <ConfirmDialog
        open={commentConfirm}
        onOpenChange={setCommentConfirm}
        title={`Publish a comment on ${repoLabel}?`}
        confirmLabel="Publish comment"
        onConfirm={postComment}
      >
        <p>
          This publishes a public comment on <span className="font-mono text-foreground">{repoLabel}</span> as {author}. Everyone who can read the
          repository will see it. It can only be edited or deleted on GitHub afterwards.
        </p>
        <p>The comment body is the text in the editor ({body.trim().length} characters).</p>
      </ConfirmDialog>

      <ConfirmDialog
        open={statusConfirm}
        onOpenChange={setStatusConfirm}
        title={`Set commit status on ${repoLabel}?`}
        confirmLabel={`Set ${state ?? ''}`.trim()}
        onConfirm={postStatus}
      >
        <p>
          This sets the commit status <span className="font-mono text-foreground">{STATUS_CONTEXT}</span> to{' '}
          <span className="font-mono text-foreground">{state}</span> on the head commit of {repoLabel} (expected{' '}
          <span className="font-mono text-foreground">{shortSha(pr.headSha)}</span>) as {author}.
        </p>
        <p>
          Description: <span className="text-foreground">&ldquo;{description.trim()}&rdquo;</span>
        </p>
        <p>Branch protection rules that require this context will use this state when deciding whether the pull request can merge.</p>
      </ConfirmDialog>
    </div>
  )
}
