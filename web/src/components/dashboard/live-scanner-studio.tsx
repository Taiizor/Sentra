import { useState } from 'react'
import { Eraser, FileCode2, Loader2, ScanSearch } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { api } from '@/lib/api'
import type { SnippetScanView } from '@/types/api'
import { ErrorAlert, GatedButton, SectionCard, TabHeader } from './console-kit'
import { STUDIO_EXAMPLES } from './studio-examples'
import { StudioResults } from './studio-results'

const FILE_TYPES: { fileName: string; label: string }[] = [
  { fileName: 'snippet.ts', label: 'TypeScript (snippet.ts)' },
  { fileName: 'snippet.js', label: 'JavaScript (snippet.js)' },
  { fileName: 'snippet.py', label: 'Python (snippet.py)' },
  { fileName: 'snippet.rs', label: 'Rust (snippet.rs)' },
  { fileName: 'snippet.go', label: 'Go (snippet.go)' },
  { fileName: 'snippet.java', label: 'Java (snippet.java)' },
  { fileName: 'snippet.php', label: 'PHP (snippet.php)' },
  { fileName: 'snippet.sol', label: 'Solidity (snippet.sol)' },
  { fileName: 'ci.yml', label: 'YAML (ci.yml)' },
  { fileName: 'Dockerfile', label: 'Dockerfile' },
]

const CUSTOM = '__custom__'
const FILE_NAME_PATTERN = /^[A-Za-z0-9._-]{1,100}$/

interface ScanRecord {
  result: SnippetScanView
  code: string
  fileName: string
  scannedAt: string
}

/**
 * Scans pasted code with the Sentra core rules. The file name selects the language rules;
 * results are rendered exactly as the core returned them and are never persisted as findings.
 */
export function LiveScannerStudio() {
  const [code, setCode] = useState('')
  const [fileType, setFileType] = useState<string>('snippet.ts')
  const [customName, setCustomName] = useState('')
  const [exampleId, setExampleId] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [record, setRecord] = useState<ScanRecord | null>(null)

  const fileName = fileType === CUSTOM ? customName.trim() : fileType
  const fileNameValid = FILE_NAME_PATTERN.test(fileName)
  const lineCount = code ? code.split('\n').length : 0
  const blockedReason = !code.trim()
    ? 'Paste or type code to scan'
    : !fileNameValid
      ? 'Enter a file name of 1-100 letters, digits, dots, dashes or underscores'
      : null

  const scan = async () => {
    if (blockedReason) return
    setBusy(true)
    setError(null)
    try {
      const result = await api.snippet.scan({ code, fileName })
      setRecord({ result, code, fileName, scannedAt: new Date().toISOString() })
    } catch (failure) {
      setError(failure)
    } finally {
      setBusy(false)
    }
  }

  const loadExample = (id: string | null) => {
    const example = STUDIO_EXAMPLES.find((candidate) => candidate.id === id)
    if (!example) return
    setExampleId(example.id)
    setCode(example.code)
    setFileType(FILE_TYPES.some((type) => type.fileName === example.fileName) ? example.fileName : CUSTOM)
    if (!FILE_TYPES.some((type) => type.fileName === example.fileName)) setCustomName(example.fileName)
  }

  return (
    <div className="flex flex-col gap-4">
      <TabHeader
        icon={<ScanSearch className="size-4 text-primary" />}
        title="Snippet scanner"
        description="Runs the Sentra core heuristic rules (`sentra scan`) over pasted code. The file name decides which language rules apply. Results are unverified signals and are not added to the findings catalog."
      />

      <SectionCard
        icon={<FileCode2 className="size-4 text-sky-400" />}
        title="Input"
        actions={
          <Select value={exampleId} onValueChange={(value) => loadExample(value)}>
            <SelectTrigger size="sm" className="w-64 text-xs">
              <SelectValue placeholder="Load an example input">
                {(value: string | null) =>
                  value ? `Example input: ${STUDIO_EXAMPLES.find((example) => example.id === value)?.label ?? value}` : 'Load an example input'
                }
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              {STUDIO_EXAMPLES.map((example) => (
                <SelectItem key={example.id} value={example.id}>
                  Example input: {example.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        }
      >
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-[16rem_1fr] sm:items-end">
          <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
            File type (sets the scanned file name)
            <Select value={fileType} onValueChange={(value) => value && setFileType(value)}>
              <SelectTrigger className="w-full text-xs">
                <SelectValue>
                  {(value: string | null) =>
                    value === CUSTOM ? 'Custom file name' : (FILE_TYPES.find((type) => type.fileName === value)?.label ?? value)
                  }
                </SelectValue>
              </SelectTrigger>
              <SelectContent>
                {FILE_TYPES.map((type) => (
                  <SelectItem key={type.fileName} value={type.fileName}>
                    {type.label}
                  </SelectItem>
                ))}
                <SelectSeparator />
                <SelectItem value={CUSTOM}>Custom file name</SelectItem>
              </SelectContent>
            </Select>
          </label>
          {fileType === CUSTOM && (
            <label className="flex flex-col gap-1 text-[11px] text-muted-foreground">
              File name (base name only)
              <Input
                value={customName}
                onChange={(event) => setCustomName(event.target.value)}
                placeholder="e.g. handler.py"
                className="h-8 font-mono text-xs"
                maxLength={100}
                aria-invalid={customName !== '' && !fileNameValid}
              />
            </label>
          )}
        </div>

        <Textarea
          value={code}
          onChange={(event) => {
            setCode(event.target.value)
            setExampleId(null)
          }}
          spellCheck={false}
          placeholder="Paste code to scan…"
          className="min-h-72 resize-y bg-zinc-950 font-mono text-xs leading-relaxed text-zinc-100 [field-sizing:fixed]"
          aria-label="Code to scan"
        />

        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <span className="text-[11px] text-muted-foreground">
            {lineCount} line(s), {code.length.toLocaleString()} characters · scanned as{' '}
            <span className="font-mono text-zinc-300">{fileNameValid ? fileName : 'invalid file name'}</span>
          </span>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={busy || (!code && !record)}
              onClick={() => {
                setCode('')
                setExampleId(null)
                setRecord(null)
                setError(null)
              }}
            >
              <Eraser />
              Clear
            </Button>
            <GatedButton permission="scan:run" blockedReason={blockedReason} size="sm" disabled={busy} onClick={() => void scan()}>
              {busy ? <Loader2 className="animate-spin" /> : <ScanSearch />}
              Scan
            </GatedButton>
          </div>
        </div>
      </SectionCard>

      {error !== null && <ErrorAlert error={error} title="The snippet scan failed" />}

      {record && (
        <SectionCard icon={<ScanSearch className="size-4 text-amber-400" />} title="Scan result">
          <StudioResults
            result={record.result}
            scannedAt={record.scannedAt}
            stale={record.code !== code || record.fileName !== fileName}
          />
        </SectionCard>
      )}
    </div>
  )
}
