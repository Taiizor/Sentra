import { useState, type ReactNode } from 'react'
import { Check, Copy, Terminal } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { copyText } from '@/lib/clipboard'

interface MarkdownViewProps {
  content: string
  className?: string
}

/**
 * Minimal Markdown renderer for scanner rationale and model output.
 *
 * Supported: fenced code blocks, GFM tables (with a delimiter row), headings, blockquotes,
 * ordered/unordered lists, paragraphs, and inline `code`, **bold**, [links](https://…),
 * bare http(s) URLs and CWE identifiers.
 *
 * Safety: everything is rendered through React text nodes (no raw HTML is ever injected), and
 * only absolute http(s) URLs become links (opened with rel="noopener noreferrer").
 */
export function MarkdownView({ content, className = '' }: MarkdownViewProps) {
  if (!content) return null
  const blocks = parseMarkdownBlocks(content)
  return (
    <div className={`space-y-3 text-xs leading-relaxed text-zinc-200 select-text ${className}`}>
      {blocks.map((block, index) => (
        <BlockRenderer key={index} block={block} />
      ))}
    </div>
  )
}

type BlockToken =
  | { type: 'code_block'; lang: string; code: string }
  | { type: 'table'; headers: string[]; rows: string[][] }
  | { type: 'heading'; level: number; text: string }
  | { type: 'blockquote'; text: string }
  | { type: 'list'; ordered: boolean; start: number; items: string[] }
  | { type: 'paragraph'; text: string }

const TABLE_DELIMITER = /^\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?$/
const UNORDERED_ITEM = /^\s*[-*+]\s+/
const ORDERED_ITEM = /^\s*(\d+)[.)]\s+/

function isTableLine(line: string): boolean {
  const trimmed = line.trim()
  return trimmed.startsWith('|') && trimmed.endsWith('|') && trimmed.length > 1
}

function parseMarkdownBlocks(raw: string): BlockToken[] {
  const lines = raw.replace(/\r\n?/g, '\n').split('\n')
  const blocks: BlockToken[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]
    const trimmed = line.trim()

    if (trimmed.startsWith('```')) {
      const lang = trimmed.slice(3).trim()
      const codeLines: string[] = []
      i++
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        codeLines.push(lines[i])
        i++
      }
      i++ // closing fence (or end of input)
      blocks.push({ type: 'code_block', lang, code: codeLines.join('\n') })
      continue
    }

    if (isTableLine(line)) {
      const tableLines: string[] = []
      while (i < lines.length && isTableLine(lines[i])) {
        tableLines.push(lines[i].trim())
        i++
      }
      if (tableLines.length >= 2 && TABLE_DELIMITER.test(tableLines[1])) {
        blocks.push({ type: 'table', headers: parseTableRow(tableLines[0]), rows: tableLines.slice(2).map(parseTableRow) })
      } else {
        blocks.push({ type: 'paragraph', text: tableLines.join(' ') })
      }
      continue
    }

    const heading = line.match(/^(#{1,6})\s+(.*)$/)
    if (heading) {
      blocks.push({ type: 'heading', level: heading[1].length, text: heading[2] })
      i++
      continue
    }

    if (trimmed.startsWith('>')) {
      const quoteLines: string[] = []
      while (i < lines.length && lines[i].trim().startsWith('>')) {
        quoteLines.push(lines[i].trim().replace(/^>\s?/, ''))
        i++
      }
      blocks.push({ type: 'blockquote', text: quoteLines.join(' ') })
      continue
    }

    if (UNORDERED_ITEM.test(line)) {
      const items: string[] = []
      while (i < lines.length && UNORDERED_ITEM.test(lines[i])) {
        items.push(lines[i].replace(UNORDERED_ITEM, '').trim())
        i++
      }
      blocks.push({ type: 'list', ordered: false, start: 1, items })
      continue
    }

    const ordered = line.match(ORDERED_ITEM)
    if (ordered) {
      const items: string[] = []
      while (i < lines.length && ORDERED_ITEM.test(lines[i])) {
        items.push(lines[i].replace(ORDERED_ITEM, '').trim())
        i++
      }
      blocks.push({ type: 'list', ordered: true, start: Number.parseInt(ordered[1], 10), items })
      continue
    }

    if (trimmed.length > 0) {
      const paragraph: string[] = [trimmed]
      i++
      while (
        i < lines.length &&
        lines[i].trim().length > 0 &&
        !lines[i].trim().startsWith('```') &&
        !isTableLine(lines[i]) &&
        !/^#{1,6}\s/.test(lines[i]) &&
        !lines[i].trim().startsWith('>') &&
        !UNORDERED_ITEM.test(lines[i]) &&
        !ORDERED_ITEM.test(lines[i])
      ) {
        paragraph.push(lines[i].trim())
        i++
      }
      blocks.push({ type: 'paragraph', text: paragraph.join(' ') })
      continue
    }

    i++
  }

  return blocks
}

function parseTableRow(line: string): string[] {
  return line
    .replace(/^\|/, '')
    .replace(/\|$/, '')
    .split('|')
    .map((cell) => cell.trim())
}

function BlockRenderer({ block }: { block: BlockToken }) {
  switch (block.type) {
    case 'code_block':
      return <CodeBlock lang={block.lang} code={block.code} />

    case 'table':
      return (
        <div className="my-2.5 overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-950/70">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/80">
                {block.headers.map((header, index) => (
                  <th key={index} className="px-3.5 py-2 font-semibold text-zinc-300 text-[11px] whitespace-nowrap">
                    <InlineFormattedText text={header} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 font-mono text-[11px]">
              {block.rows.map((row, rowIndex) => (
                <tr key={rowIndex} className="even:bg-zinc-900/20">
                  {row.map((cell, cellIndex) => (
                    <td key={cellIndex} className="px-3.5 py-2 text-zinc-300 align-top">
                      <InlineFormattedText text={cell} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )

    case 'heading':
      if (block.level === 1) {
        return (
          <h1 className="text-base font-bold text-zinc-100 mt-4 mb-1.5 pb-1 border-b border-zinc-800">
            <InlineFormattedText text={block.text} />
          </h1>
        )
      }
      if (block.level === 2) {
        return (
          <h2 className="text-sm font-bold text-zinc-100 mt-3.5 mb-1.5">
            <InlineFormattedText text={block.text} />
          </h2>
        )
      }
      return (
        <h3 className="text-xs font-bold text-zinc-200 mt-2.5 mb-1">
          <InlineFormattedText text={block.text} />
        </h3>
      )

    case 'blockquote':
      return (
        <blockquote className="my-2 border-l-2 border-primary/50 bg-primary/5 px-3 py-2 rounded-r-lg text-zinc-300 text-xs leading-relaxed">
          <InlineFormattedText text={block.text} />
        </blockquote>
      )

    case 'list':
      if (block.ordered) {
        return (
          <ol start={block.start} className="my-1.5 space-y-1 pl-5 list-decimal marker:text-zinc-500 marker:font-mono">
            {block.items.map((item, index) => (
              <li key={index} className="text-xs text-zinc-300 pl-1">
                <InlineFormattedText text={item} />
              </li>
            ))}
          </ol>
        )
      }
      return (
        <ul className="my-1.5 space-y-1 pl-1">
          {block.items.map((item, index) => (
            <li key={index} className="flex items-start gap-2 text-xs text-zinc-300">
              <span className="size-1.5 rounded-full bg-primary/70 shrink-0 mt-1.5" />
              <span className="flex-1 min-w-0">
                <InlineFormattedText text={item} />
              </span>
            </li>
          ))}
        </ul>
      )

    case 'paragraph':
      return (
        <p className="text-xs text-zinc-300 leading-relaxed break-words">
          <InlineFormattedText text={block.text} />
        </p>
      )
  }
}

function CodeBlock({ lang, code }: { lang: string; code: string }) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    const ok = await copyText(code)
    if (ok) {
      setCopied(true)
      toast.success('Code copied to clipboard')
      window.setTimeout(() => setCopied(false), 2000)
    } else {
      toast.error('Copy failed', { description: 'The clipboard is not available here. Select the code and copy it manually.' })
    }
  }

  return (
    <div className="my-2.5 rounded-xl border border-zinc-800 bg-zinc-950 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 bg-zinc-900/90 border-b border-zinc-800 text-[11px]">
        <div className="flex items-center gap-1.5 text-zinc-400">
          <Terminal className="size-3 text-primary" />
          <span className="font-mono text-zinc-300 font-semibold">{lang || 'text'}</span>
        </div>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={handleCopy}
          className="h-6 px-2 text-[11px] text-zinc-400 hover:text-zinc-100"
        >
          {copied ? <Check className="size-3 text-primary mr-1" /> : <Copy className="size-3 mr-1" />}
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
      <div className="p-3 font-mono text-xs overflow-x-auto leading-relaxed text-zinc-200">
        <pre className="whitespace-pre">{code}</pre>
      </div>
    </div>
  )
}

/** Returns the URL only when it is an absolute http(s) URL. */
function safeHttpUrl(raw: string): string | null {
  try {
    const url = new URL(raw)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : null
  } catch {
    return null
  }
}

function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="text-primary underline underline-offset-2 break-all hover:text-primary/80">
      {children}
    </a>
  )
}

const INLINE_TOKEN = /(`[^`]+`|\*\*[^*]+\*\*|\[[^\]\n]+\]\([^()\s]+\)|\bhttps?:\/\/[^\s<>()]+|\bCWE-\d+\b)/g

/** Inline formatting for `code`, **bold**, [label](url), bare http(s) URLs and CWE ids. */
export function InlineFormattedText({ text }: { text: string }) {
  if (!text) return null

  const parts: ReactNode[] = []
  let lastIndex = 0
  for (const match of text.matchAll(INLINE_TOKEN)) {
    const token = match[0]
    const index = match.index ?? 0
    if (index > lastIndex) parts.push(text.slice(lastIndex, index))
    lastIndex = index + token.length

    if (token.startsWith('`')) {
      parts.push(
        <code key={index} className="px-1.5 py-0.5 rounded-md bg-zinc-900 border border-zinc-700 font-mono text-[11px] text-emerald-400">
          {token.slice(1, -1)}
        </code>,
      )
    } else if (token.startsWith('**')) {
      parts.push(
        <strong key={index} className="font-bold text-zinc-100">
          {token.slice(2, -2)}
        </strong>,
      )
    } else if (token.startsWith('[')) {
      const split = token.indexOf('](')
      const label = token.slice(1, split)
      const href = safeHttpUrl(token.slice(split + 2, -1))
      parts.push(href ? <ExternalLink key={index} href={href}>{label}</ExternalLink> : token)
    } else if (token.startsWith('http')) {
      // Keep trailing sentence punctuation outside the link.
      const trailing = token.match(/[.,;:!?'"]+$/)?.[0] ?? ''
      const urlText = trailing ? token.slice(0, -trailing.length) : token
      const href = safeHttpUrl(urlText)
      parts.push(href ? <ExternalLink key={index} href={href}>{urlText}</ExternalLink> : urlText)
      if (trailing) parts.push(trailing)
    } else {
      parts.push(
        <span
          key={index}
          className="inline-flex items-center px-1.5 py-0.5 leading-none rounded font-mono text-[10px] font-semibold bg-primary/10 border border-primary/30 text-primary mx-0.5"
        >
          {token}
        </span>,
      )
    }
  }
  if (lastIndex < text.length) parts.push(text.slice(lastIndex))
  return <>{parts}</>
}
