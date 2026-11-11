import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { copyText } from '@/lib/clipboard'
import type { AuditLogEntryView } from '@/types/api'

/** Copies a value and reports the real clipboard outcome. */
export function CopyValueButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  async function handleCopy() {
    if (await copyText(value)) {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } else {
      toast.error(`Could not copy ${label}`, { description: 'The clipboard is unavailable here; select the value and copy it manually.' })
    }
  }
  return (
    <button
      type="button"
      onClick={() => void handleCopy()}
      className="inline-flex items-center justify-center size-5 rounded text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800 shrink-0"
      aria-label={`Copy ${label}`}
      title={`Copy ${label}`}
    >
      {copied ? <Check className="size-3 text-emerald-400" /> : <Copy className="size-3" />}
    </button>
  )
}

const OUTCOME_CLASS: Record<AuditLogEntryView['outcome'], string> = {
  success: 'border-emerald-500/40 text-emerald-300',
  failure: 'border-rose-500/40 text-rose-300',
  denied: 'border-amber-500/40 text-amber-300',
}

export function OutcomeBadge({ outcome }: { outcome: AuditLogEntryView['outcome'] }) {
  return (
    <Badge variant="outline" className={`text-[10px] font-mono ${OUTCOME_CLASS[outcome]}`}>
      {outcome}
    </Badge>
  )
}

/** Pretty-printed JSON rendered as text (never as HTML). */
export function JsonBlock({ value }: { value: unknown }) {
  let text: string
  try {
    text = JSON.stringify(value, null, 2) ?? 'null'
  } catch {
    text = String(value)
  }
  return (
    <pre className="max-h-72 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-2.5 text-[11px] font-mono text-zinc-300 whitespace-pre-wrap break-all">
      {text}
    </pre>
  )
}
