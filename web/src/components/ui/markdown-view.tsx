import React, { useState } from 'react'
import { Copy, Check, Terminal } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { toast } from 'sonner'
import { copyText } from '@/lib/clipboard'

interface MarkdownViewProps {
  content: string
  className?: string
}

/**
 * Enterprise Markdown View for Sentra
 * Parses GFM tables, fenced code blocks, inline code, headings, lists, blockquotes,
 * and security-specific tokens (CWEs, taint roles, severity levels).
 */
export function MarkdownView({ content, className = '' }: MarkdownViewProps) {
  if (!content) return null

  // Split into block tokens (code blocks, tables, headings, paragraphs, lists, blockquotes)
  const blocks = parseMarkdownBlocks(content)

  return (
    <div className={`space-y-3 text-xs leading-relaxed text-zinc-200 select-text ${className}`}>
      {blocks.map((block, idx) => (
        <BlockRenderer key={idx} block={block} />
      ))}
    </div>
  )
}

type BlockToken =
  | { type: 'code_block'; lang: string; code: string }
  | { type: 'table'; headers: string[]; rows: string[][] }
  | { type: 'heading'; level: number; text: string }
  | { type: 'blockquote'; text: string }
  | { type: 'list'; ordered: boolean; items: string[] }
  | { type: 'paragraph'; text: string }

function parseMarkdownBlocks(raw: string): BlockToken[] {
  const lines = raw.replace(/\r\n/g, '\n').split('\n')
  const blocks: BlockToken[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]

    // 1. Fenced Code Block
    if (line.trim().startsWith('```')) {
      const lang = line.trim().slice(3).trim()
      const codeLines: string[] = []
      i++
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        codeLines.push(lines[i])
        i++
      }
      i++ // Skip closing ```
      blocks.push({
        type: 'code_block',
        lang: lang || 'text',
        code: codeLines.join('\n'),
      })
      continue
    }

    // 2. GFM Table
    if (line.trim().startsWith('|') && line.trim().endsWith('|')) {
      const tableLines: string[] = []
      while (i < lines.length && lines[i].trim().startsWith('|') && lines[i].trim().endsWith('|')) {
        tableLines.push(lines[i].trim())
        i++
      }

      if (tableLines.length >= 2) {
        const headerRow = parseTableRow(tableLines[0])
        // Filter out delimiter line (e.g., |---|---|)
        const dataRows = tableLines
          .slice(1)
          .filter((l) => !l.replace(/[|\s-:]/g, '').length) // delimiter check
        const actualDataRows = tableLines.slice(1).filter((l) => {
          const stripped = l.replace(/[|\s-:]/g, '')
          return stripped.length > 0
        })

        blocks.push({
          type: 'table',
          headers: headerRow,
          rows: actualDataRows.map(parseTableRow),
        })
        continue
      }
    }

    // 3. Headings
    const headingMatch = line.match(/^(#{1,6})\s+(.*)$/)
    if (headingMatch) {
      blocks.push({
        type: 'heading',
        level: headingMatch[1].length,
        text: headingMatch[2],
      })
      i++
      continue
    }

    // 4. Blockquote
    if (line.trim().startsWith('>')) {
      const quoteLines: string[] = []
      while (i < lines.length && lines[i].trim().startsWith('>')) {
        quoteLines.push(lines[i].trim().replace(/^>\s?/, ''))
        i++
      }
      blocks.push({
        type: 'blockquote',
        text: quoteLines.join(' '),
      })
      continue
    }

    // 5. Unordered List
    if (/^\s*[-*+]\s+/.test(line)) {
      const listItems: string[] = []
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
        listItems.push(lines[i].replace(/^\s*[-*+]\s+/, '').trim())
        i++
      }
      blocks.push({
        type: 'list',
        ordered: false,
        items: listItems,
      })
      continue
    }

    // 6. Ordered List
    if (/^\s*\d+\.\s+/.test(line)) {
      const listItems: string[] = []
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        listItems.push(lines[i].replace(/^\s*\d+\.\s+/, '').trim())
        i++
      }
      blocks.push({
        type: 'list',
        ordered: true,
        items: listItems,
      })
      continue
    }

    // 7. Regular Paragraph
    if (line.trim().length > 0) {
      const pLines: string[] = [line.trim()]
      i++
      while (
        i < lines.length &&
        lines[i].trim().length > 0 &&
        !lines[i].trim().startsWith('```') &&
        !lines[i].trim().startsWith('|') &&
        !lines[i].trim().startsWith('#') &&
        !lines[i].trim().startsWith('>') &&
        !/^\s*[-*+]\s+/.test(lines[i]) &&
        !/^\s*\d+\.\s+/.test(lines[i])
      ) {
        pLines.push(lines[i].trim())
        i++
      }
      blocks.push({
        type: 'paragraph',
        text: pLines.join(' '),
      })
      continue
    }

    i++
  }

  return blocks
}

function parseTableRow(line: string): string[] {
  // Strip leading and trailing '|' and split
  const trimmed = line.replace(/^\|/, '').replace(/\|$/, '')
  return trimmed.split('|').map((c) => c.trim())
}

function BlockRenderer({ block }: { block: BlockToken }) {
  switch (block.type) {
    case 'code_block':
      return <CodeBlock lang={block.lang} code={block.code} />

    case 'table':
      return (
        <div className="my-2.5 overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-950/70 shadow-sm">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/80">
                {block.headers.map((h, idx) => (
                  <th
                    key={idx}
                    className="px-3.5 py-2 font-semibold text-zinc-300 tracking-wider text-[11px] uppercase whitespace-nowrap"
                  >
                    <InlineFormattedText text={h} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-850/60 font-mono text-[11px]">
              {block.rows.map((row, rIdx) => (
                <tr
                  key={rIdx}
                  className="hover:bg-zinc-900/50 transition-colors odd:bg-transparent even:bg-zinc-900/20"
                >
                  {row.map((cell, cIdx) => (
                    <td key={cIdx} className="px-3.5 py-2 text-zinc-300 align-middle">
                      <TableCellRenderer text={cell} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )

    case 'heading': {
      if (block.level === 1) {
        return (
          <h1 className="text-base font-bold text-zinc-100 mt-4 mb-1.5 pb-1 border-b border-zinc-800">
            <InlineFormattedText text={block.text} />
          </h1>
        )
      }
      if (block.level === 2) {
        return (
          <h2 className="text-sm font-bold text-zinc-100 mt-3.5 mb-1.5 flex items-center gap-1.5">
            <InlineFormattedText text={block.text} />
          </h2>
        )
      }
      return (
        <h3 className="text-xs font-bold text-zinc-200 mt-2.5 mb-1 flex items-center gap-1.5">
          <InlineFormattedText text={block.text} />
        </h3>
      )
    }

    case 'blockquote':
      return (
        <blockquote className="my-2 border-l-2 border-primary/50 bg-primary/5 px-3 py-2 rounded-r-lg text-zinc-300 text-xs leading-relaxed italic">
          <InlineFormattedText text={block.text} />
        </blockquote>
      )

    case 'list':
      return (
        <ul className="my-1.5 space-y-1 pl-1">
          {block.items.map((item, idx) => (
            <li key={idx} className="flex items-start gap-2 text-xs text-zinc-300">
              {block.ordered ? (
                <span className="font-mono text-[10px] size-4 rounded-full bg-zinc-800 text-zinc-400 flex items-center justify-center shrink-0 mt-0.5">
                  {idx + 1}
                </span>
              ) : (
                <span className="size-1.5 rounded-full bg-primary/70 shrink-0 mt-1.5" />
              )}
              <span className="flex-1">
                <InlineFormattedText text={item} />
              </span>
            </li>
          ))}
        </ul>
      )

    case 'paragraph':
      return (
        <p className="text-xs text-zinc-300 leading-relaxed">
          <InlineFormattedText text={block.text} />
        </p>
      )
  }
}

/**
 * Renders Table Cells with Smart Semantic Tagging
 */
function TableCellRenderer({ text }: { text: string }) {
  const upper = text.toUpperCase().trim()

  if (upper === 'SOURCE') {
    return (
      <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-amber-400 text-[10px] py-0 font-bold">
        SOURCE
      </Badge>
    )
  }
  if (upper === 'SINK') {
    return (
      <Badge variant="outline" className="border-rose-500/40 bg-rose-500/10 text-rose-400 text-[10px] py-0 font-bold">
        SINK
      </Badge>
    )
  }
  if (upper === 'PROPAGATION' || upper === 'PROPAGATE' || upper === 'FLOW') {
    return (
      <Badge variant="outline" className="border-sky-500/40 bg-sky-500/10 text-sky-400 text-[10px] py-0 font-bold">
        PROPAGATE
      </Badge>
    )
  }
  if (upper === 'SANITIZER' || upper === 'CLEAN') {
    return (
      <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 text-emerald-400 text-[10px] py-0 font-bold">
        SANITIZER
      </Badge>
    )
  }

  return <InlineFormattedText text={text} />
}

/**
 * Fenced Code Block with Copy & Syntax Styling
 */
function CodeBlock({ lang, code }: { lang: string; code: string }) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    await copyText(code)
    setCopied(true)
    toast.success('Code copied to clipboard')
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="my-2.5 rounded-xl border border-zinc-800 bg-zinc-950 overflow-hidden shadow-md">
      {/* Code Header */}
      <div className="flex items-center justify-between px-3 py-1.5 bg-zinc-900/90 border-b border-zinc-800 text-[11px]">
        <div className="flex items-center gap-1.5 text-zinc-400">
          <Terminal className="size-3 text-primary" />
          <span className="font-mono text-zinc-300 font-semibold uppercase">{lang || 'code'}</span>
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

      {/* Code Content */}
      <div className="p-3 font-mono text-xs overflow-x-auto leading-relaxed text-zinc-200">
        <pre className="whitespace-pre">{code}</pre>
      </div>
    </div>
  )
}

/**
 * Inline text parser for `code`, **bold**, *italic*, and CWE badges
 */
export function InlineFormattedText({ text }: { text: string }) {
  if (!text) return null

  // Regex to split tokens: inline code `...`, bold **...**, CWE badges, and regular text
  const parts: React.ReactNode[] = []
  const tokenRegex = /(`[^`]+`|\*\*[^*]+\*\*|\bCWE-\d+\b)/g

  let lastIndex = 0
  let match: RegExpExecArray | null

  while ((match = tokenRegex.exec(text)) !== null) {
    // Push preceding text
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index))
    }

    const token = match[0]
    if (token.startsWith('`') && token.endsWith('`')) {
      const code = token.slice(1, -1)
      parts.push(
        <code
          key={match.index}
          className="px-1.5 py-0.5 rounded-md bg-zinc-850 border border-zinc-750 font-mono text-[11px] text-emerald-400 font-semibold"
        >
          {code}
        </code>
      )
    } else if (token.startsWith('**') && token.endsWith('**')) {
      const bold = token.slice(2, -2)
      parts.push(
        <strong key={match.index} className="font-bold text-zinc-100">
          {bold}
        </strong>
      )
    } else if (/^CWE-\d+$/.test(token)) {
      parts.push(
        <span
          key={match.index}
          className="inline-flex items-center px-1.5 py-0.2 rounded font-mono text-[10px] font-bold bg-primary/10 border border-primary/30 text-primary mx-0.5"
        >
          {token}
        </span>
      )
    }

    lastIndex = match.index + token.length
  }

  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex))
  }

  return <>{parts}</>
}
