import { useEffect, useMemo, useRef, useState } from 'react'
import { cn } from 'cn'
import { AlertTriangle, FileCode2, FileWarning, Maximize2, Minimize2 } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import { useResource } from '@/lib/use-resource'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { bridgeRedactedLineRules, countBridgeRedactedLines } from '@/components/dashboard/findings-format'
import { CopyButton, ErrorAlert } from '@/components/dashboard/findings-shared'
import type { TaintStepView } from '@/types/api'

/**
 * Shows a workspace file exactly as the bridge returns it (FileContentView), with line numbers,
 * the reported line highlighted, scanner-reported taint steps tagged, redaction markers flagged
 * and truncation stated. It never substitutes other content when the file cannot be read.
 */

const ROLE_STYLE: Record<TaintStepView['role'], { label: string; row: string; tag: string }> = {
  SOURCE: {
    label: 'SOURCE',
    row: 'bg-amber-950/30 border-l-2 border-amber-500',
    tag: 'border-amber-500/40 bg-amber-500/15 text-amber-300',
  },
  PROPAGATION: {
    label: 'PROPAGATION',
    row: 'bg-sky-950/30 border-l-2 border-sky-500',
    tag: 'border-sky-500/40 bg-sky-500/15 text-sky-300',
  },
  SANITIZER: {
    label: 'SANITIZER',
    row: 'bg-emerald-950/30 border-l-2 border-emerald-500',
    tag: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300',
  },
  SINK: {
    label: 'SINK',
    row: 'bg-rose-950/30 border-l-2 border-rose-500',
    tag: 'border-rose-500/40 bg-rose-500/15 text-rose-300',
  },
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`
}

function explainFileError(error: Error): { title: string; hint: string | null } {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 403:
        return {
          title: 'The bridge refused to read this file',
          hint: 'The path is outside the registered workspace or is blocked by the bridge policy.',
        }
      case 404:
        return {
          title: 'File not found in the workspace',
          hint: 'It may have been moved or deleted since the scan that reported this finding.',
        }
      case 413:
        return { title: 'File too large to display', hint: null }
      case 415:
        return {
          title: 'File cannot be displayed as text',
          hint: 'The bridge only serves text files; binary or undecodable content is not shown.',
        }
      default:
        break
    }
  }
  return { title: 'Could not load the source file', hint: null }
}

/** One file line as returned by the bridge; a whole-line bridge redaction marker is flagged. */
function SourceLineText({ text }: { text: string }) {
  const ruleIds = bridgeRedactedLineRules(text)
  if (!ruleIds) return <>{text}</>
  return (
    <span
      className="rounded-sm border border-amber-500/40 bg-amber-500/15 px-1 text-amber-300"
      title="The bridge withheld this line because it carries an open secret finding"
    >
      line redacted by the bridge{ruleIds.length > 0 ? ` · ${ruleIds.join(', ')}` : ''}
    </span>
  )
}

export function SourceViewer({
  tenantId,
  path,
  line,
  taintTrace,
}: {
  tenantId: string
  /** Workspace-relative path as reported by the scanner. */
  path: string
  line: number | null
  taintTrace?: TaintStepView[] | null
}) {
  const [expanded, setExpanded] = useState(false)
  const file = useResource(`file:${tenantId}:${path}`, (signal) => api.findings.file(tenantId, path, signal))
  const scrollRef = useRef<HTMLDivElement | null>(null)
  const targetRef = useRef<HTMLDivElement | null>(null)

  const lines = useMemo(() => {
    const content = file.data?.content ?? ''
    const split = content.replace(/\r\n/g, '\n').split('\n')
    if (split.length > 1 && split[split.length - 1] === '') split.pop()
    return split
  }, [file.data])

  const redactions = useMemo(() => countBridgeRedactedLines(lines), [lines])

  const stepsByLine = useMemo(() => {
    const map = new Map<number, TaintStepView[]>()
    for (const step of taintTrace ?? []) {
      if (step.line === null) continue
      map.set(step.line, [...(map.get(step.line) ?? []), step])
    }
    return map
  }, [taintTrace])

  // Center the reported line inside the viewer (without scrolling the surrounding page).
  useEffect(() => {
    const container = scrollRef.current
    const target = targetRef.current
    if (!container || !target) return
    container.scrollTop = Math.max(0, target.offsetTop - container.clientHeight / 2)
  }, [file.data, line, expanded])

  const lineBeyondExcerpt = file.data !== undefined && line !== null && line > lines.length

  return (
    <div className="flex flex-col overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 bg-zinc-900/70 px-3 py-1.5 text-xs">
        <div className="flex min-w-0 items-center gap-2">
          <FileCode2 className="size-3.5 shrink-0 text-zinc-400" />
          <span className="truncate font-mono text-zinc-300" title={path}>
            {path}
          </span>
          {line !== null && (
            <Badge variant="outline" className="border-zinc-700 font-mono text-[10px] text-zinc-400">
              line {line}
            </Badge>
          )}
          {file.data?.language && (
            <Badge variant="outline" className="border-zinc-800 text-[10px] text-zinc-500">
              {file.data.language}
            </Badge>
          )}
        </div>
        <div className="flex items-center gap-1">
          <CopyButton text={line !== null ? `${path}:${line}` : path} label="Copy path" />
          <Button
            variant="ghost"
            size="icon-xs"
            className="text-zinc-400 hover:text-zinc-100"
            onClick={() => setExpanded((value) => !value)}
            title={expanded ? 'Collapse' : 'Expand'}
          >
            {expanded ? <Minimize2 /> : <Maximize2 />}
          </Button>
        </div>
      </div>

      {file.data && (file.data.truncated || redactions > 0 || lineBeyondExcerpt) && (
        <div className="flex flex-col gap-0.5 border-b border-zinc-800 bg-zinc-900/40 px-3 py-1.5 text-[11px]">
          {file.data.truncated && (
            <span className="flex items-center gap-1.5 text-amber-300">
              <AlertTriangle className="size-3 shrink-0" />
              Truncated by the bridge: showing {lines.length.toLocaleString()} line{lines.length === 1 ? '' : 's'} of a{' '}
              {formatBytes(file.data.sizeBytes)} file.
            </span>
          )}
          {lineBeyondExcerpt && (
            <span className="flex items-center gap-1.5 text-amber-300">
              <AlertTriangle className="size-3 shrink-0" />
              Line {line} is not part of the returned content.
            </span>
          )}
          {redactions > 0 && (
            <span className="text-zinc-400">
              {redactions} line{redactions === 1 ? ' was' : 's were'} replaced by the bridge before reaching the console
              because {redactions === 1 ? 'it carries' : 'they carry'} an open secret finding.
            </span>
          )}
        </div>
      )}

      <div
        ref={scrollRef}
        className={cn('relative overflow-auto font-mono text-[11px]', expanded ? 'max-h-[640px]' : 'max-h-[320px]')}
      >
        {file.loading && !file.data ? (
          <div className="flex flex-col gap-1.5 p-3">
            {Array.from({ length: 8 }, (_, index) => (
              <Skeleton key={index} className="h-3.5 bg-zinc-800/60" style={{ width: `${40 + ((index * 23) % 55)}%` }} />
            ))}
          </div>
        ) : file.error ? (
          <div className="p-3">
            <ErrorAlert
              error={file.error}
              title={explainFileError(file.error).title}
              onRetry={file.reload}
            />
            {explainFileError(file.error).hint && (
              <p className="mt-2 flex items-start gap-1.5 text-[11px] text-zinc-500">
                <FileWarning className="mt-0.5 size-3 shrink-0" />
                {explainFileError(file.error).hint}
              </p>
            )}
          </div>
        ) : file.data && file.data.content.length === 0 ? (
          <div className="p-4 text-center text-xs text-zinc-500">The file is empty.</div>
        ) : file.data ? (
          <div className="w-max min-w-full py-1">
            {lines.map((text, index) => {
              const number = index + 1
              const steps = stepsByLine.get(number)
              const isTarget = number === line
              const style = steps ? ROLE_STYLE[steps[steps.length - 1].role] : null
              return (
                <div
                  key={number}
                  ref={isTarget ? targetRef : undefined}
                  className={cn(
                    'flex leading-5 hover:bg-zinc-900/60',
                    style?.row,
                    isTarget && !style && 'bg-rose-950/30 border-l-2 border-rose-500',
                    isTarget && 'ring-1 ring-inset ring-rose-500/40',
                  )}
                >
                  <span className="w-12 shrink-0 select-none pr-3 text-right text-[10px] text-zinc-600">{number}</span>
                  <span className="whitespace-pre pr-4 text-zinc-300">
                    {steps?.map((step) => (
                      <span
                        key={step.step}
                        className={cn('mr-1.5 rounded-sm border px-1 text-[9px]', ROLE_STYLE[step.role].tag)}
                        title={`Step ${step.step}${step.variable ? ` · ${step.variable}` : ''}`}
                      >
                        {ROLE_STYLE[step.role].label}
                      </span>
                    ))}
                    <SourceLineText text={text} />
                  </span>
                </div>
              )
            })}
          </div>
        ) : null}
      </div>
    </div>
  )
}
