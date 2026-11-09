import { useState, useEffect, useRef } from 'react'
import {
  FileCode2,
  AlertCircle,
  Loader2,
  Copy,
  Check,
  Maximize2,
  Minimize2,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { SurgicalDiffView } from '@/components/dashboard/surgical-diff-view'
import type { TaintStep } from '@/types/sentra'

interface SourceViewerProps {
  filePath: string
  targetLine?: number
  taintSteps?: TaintStep[]
  fallbackSnippet?: string
}

export function SourceViewer({
  filePath,
  targetLine,
  taintSteps = [],
  fallbackSnippet,
}: SourceViewerProps) {
  const [content, setContent] = useState<string | null>(null)
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState<boolean>(false)
  const [isExpanded, setIsExpanded] = useState<boolean>(false)
  const activeLineRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    let active = true
    setLoading(true)
    setError(null)

    async function fetchFile() {
      try {
        const res = await fetch(`/api/file-content?path=${encodeURIComponent(filePath)}`)
        const data = await res.json()
        if (!active) return

        if (res.ok && data.ok) {
          setContent(data.content)
        } else {
          setError(data.error || 'File not available on local host')
        }
      } catch (err: any) {
        if (active) setError(err.message || 'Failed to fetch source file')
      } finally {
        if (active) setLoading(false)
      }
    }

    if (filePath) {
      fetchFile()
    } else {
      setLoading(false)
    }

    return () => {
      active = false
    }
  }, [filePath])

  // Scroll to target line when loaded
  useEffect(() => {
    if (!loading && activeLineRef.current) {
      activeLineRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  }, [loading, content, targetLine])

  function handleCopy() {
    if (content || fallbackSnippet) {
      navigator.clipboard.writeText(content || fallbackSnippet || '')
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  // Create a line lookup for taint step tags
  const taintLineMap = new Map<number, TaintStep>()
  for (const step of taintSteps) {
    taintLineMap.set(step.line, step)
  }

  const lines = content ? content.split('\n') : []

  return (
    <div className="border border-zinc-800 rounded-lg bg-zinc-950 flex flex-col overflow-hidden shadow-inner">
      {/* File Header Bar */}
      <div className="flex items-center justify-between px-3 py-2 bg-zinc-900/80 border-b border-zinc-800 text-xs">
        <div className="flex items-center gap-2 min-w-0">
          <FileCode2 className="size-4 text-primary shrink-0" />
          <span className="font-mono text-zinc-300 truncate" title={filePath}>
            {filePath}
          </span>
          {targetLine && (
            <Badge variant="outline" className="text-[10px] font-mono py-0 text-zinc-400 border-zinc-700">
              Line {targetLine}
            </Badge>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          <Button
            variant="ghost"
            size="sm"
            onClick={handleCopy}
            className="h-6 px-2 text-[11px] text-zinc-400 hover:text-zinc-200"
          >
            {copied ? <Check className="size-3 text-primary mr-1" /> : <Copy className="size-3 mr-1" />}
            {copied ? 'Copied' : 'Copy'}
          </Button>

          <Button
            variant="ghost"
            size="sm"
            onClick={() => setIsExpanded((v) => !v)}
            className="h-6 w-6 p-0 text-zinc-400 hover:text-zinc-200"
            title={isExpanded ? 'Collapse' : 'Expand'}
          >
            {isExpanded ? <Minimize2 className="size-3" /> : <Maximize2 className="size-3" />}
          </Button>
        </div>
      </div>

      {/* Code Viewer Body */}
      <div className={`${isExpanded ? 'max-h-[600px]' : 'max-h-[300px]'} overflow-y-auto font-mono text-xs p-2 leading-relaxed select-text`}>
        {loading ? (
          <div className="flex items-center justify-center p-8 text-zinc-500 gap-2">
            <Loader2 className="size-4 animate-spin" />
            <span>Loading file source...</span>
          </div>
        ) : content ? (
          <div className="flex flex-col">
            {lines.map((lineText, idx) => {
              const lineNum = idx + 1
              const taint = taintLineMap.get(lineNum)
              const isTarget = lineNum === targetLine

              let bgClass = ''
              let tagBadge = null

              if (taint) {
                if (taint.role === 'SOURCE') {
                  bgClass = 'bg-amber-950/40 border-l-2 border-amber-500 text-amber-200'
                  tagBadge = <span className="text-[9px] px-1 rounded bg-amber-500/20 text-amber-400 border border-amber-500/40 mr-1.5">SOURCE</span>
                } else if (taint.role === 'SINK') {
                  bgClass = 'bg-rose-950/40 border-l-2 border-rose-500 text-rose-200'
                  tagBadge = <span className="text-[9px] px-1 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 mr-1.5">SINK</span>
                } else if (taint.role === 'SANITIZER') {
                  bgClass = 'bg-emerald-950/40 border-l-2 border-emerald-500 text-emerald-200'
                  tagBadge = <span className="text-[9px] px-1 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 mr-1.5">CLEAN</span>
                } else {
                  bgClass = 'bg-sky-950/30 border-l-2 border-sky-500 text-sky-200'
                  tagBadge = <span className="text-[9px] px-1 rounded bg-sky-500/20 text-sky-400 border border-sky-500/40 mr-1.5">FLOW</span>
                }
              } else if (isTarget) {
                bgClass = 'bg-rose-950/30 border-l-2 border-rose-500'
              }

              return (
                <div
                  key={lineNum}
                  ref={isTarget ? activeLineRef : null}
                  className={`flex items-start gap-3 px-2 py-0.5 hover:bg-zinc-900/60 transition-colors ${bgClass}`}
                >
                  <span className="w-9 text-right text-zinc-600 select-none shrink-0 font-mono text-[11px]">
                    {lineNum}
                  </span>
                  <div className="flex-1 whitespace-pre-wrap break-all text-zinc-300">
                    {tagBadge}
                    {lineText}
                  </div>
                </div>
              )
            })}
          </div>
        ) : (
          /* Fallback if file not on disk */
          <div className="flex flex-col gap-2.5 p-3 text-xs text-zinc-400">
            <div className="flex items-center gap-1.5 text-zinc-400 text-[11px]">
              <AlertCircle className="size-3.5 text-amber-400" />
              <span>{error || 'Target file is in an isolated container/sandbox'} — Verified AST Remediation Diff:</span>
            </div>
            {fallbackSnippet ? (
              <SurgicalDiffView
                diff={fallbackSnippet}
                filePath={filePath}
                title={`Verified Remediation (${filePath.split('/').pop()})`}
              />
            ) : (
              <div className="p-4 text-center text-zinc-600">No snippet preview available.</div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
