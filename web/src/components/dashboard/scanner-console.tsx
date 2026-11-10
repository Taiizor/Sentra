import { useState } from 'react'
import {
  Terminal,
  Play,
  RotateCcw,
  CheckCircle2,
  Lock,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { UserRole } from '@/types/sentra'

interface ScannerConsoleProps {
  currentRole: UserRole
  onTriggerScanAction: (action: string, workspace: string) => void
}

export function ScannerConsole({ currentRole, onTriggerScanAction }: ScannerConsoleProps) {
  const [selectedAction, setSelectedAction] = useState<string>('scan')
  const [workspacePath, setWorkspacePath] = useState<string>('.')
  const [isRunning, setIsRunning] = useState<boolean>(false)
  const [consoleOutput, setConsoleOutput] = useState<string[]>(() => [
    'Sentra Security Terminal v0.1.0 initialized.',
    'Untrusted target execution: DISABLED (FailClosedBackend active).',
    'Ready for deterministic static analysis and dependency auditing.',
  ])

  function handleRun() {
    if (currentRole === 'Viewer') return
    setIsRunning(true)
    setConsoleOutput((prev) => [
      ...prev,
      `\n$ sentra ${selectedAction} --workspace ${workspacePath}`,
      '[*] Initializing boundary check and workspace discovery...',
      '[*] Scanning under fail-closed security policy...',
    ])

    setTimeout(() => {
      let result = ''
      if (selectedAction === 'scan') {
        result = `Sentra SAST scan: completed
Files scanned: 36
Signals found: 42
Untrusted execution: disabled
  [SENTRA-TAINT-001] CRITICAL src/api/search.rs:18 -> db.execute(&query);
      CWE: CWE-89 | SqlInjectionViaTaintFlow
  [SENTRA-TAINT-002] CRITICAL services/worker.ts:48 -> child_process.exec(cmd);
      CWE: CWE-78 | CommandInjectionViaTaintFlow
  [SENTRA-SEC-001] CRITICAL config/cloud_credentials.json:4 -> AKIAIO...[REDACTED]
      CWE: CWE-798 | HardcodedGenericSecret`
      } else if (selectedAction === 'audit') {
        result = `Sentra dependency audit: completed
Lockfiles discovered: Cargo.lock, bun.lock, package-lock.json
Packages audited: 142
Vulnerabilities identified:
  - lodash 4.17.20 -> GHSA-p6mc-m468-83gw (HIGH) in bun.lock
Untrusted execution: disabled`
      } else if (selectedAction === 'codeql') {
        result = `Sentra CodeQL workspace probe: completed
Primary language: rust (191 files)
Detected languages:
  - rust         (191 files)
  - javascript   (3 files)
CodeQL Database Create:
  codeql database create .sentra/codeql-db --language=rust --source-root=${workspacePath}
CodeQL Database Analyze:
  codeql database analyze .sentra/codeql-db --format=sarif-latest --output=.sentra/codeql-results.sarif`
      } else {
        result = `Sentra source snapshot diff: completed
Base: ${workspacePath}/v1
Head: ${workspacePath}/v2
Files evaluated: 48
Deltas: 3 modified, 1 added, 0 deleted
Aggregate digest: sha256:7f83b165...`
      }

      setConsoleOutput((prev) => [...prev, result, '[✓] Action completed successfully.'])
      setIsRunning(false)
      onTriggerScanAction(selectedAction, workspacePath)
    }, 900)
  }

  function handleClear() {
    setConsoleOutput(['Terminal cleared. Ready for next command.'])
  }

  return (
    <Card className="border-border/60 bg-card/40">
      <CardHeader className="py-2.5 px-4 border-b border-border/40">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Terminal className="size-3.5 text-primary" />
            <CardTitle className="text-xs font-medium text-foreground">CLI Analysis Console</CardTitle>
            <Badge variant="outline" className="text-[10px] font-mono px-1.5 py-0">
              Core Dispatch
            </Badge>
          </div>

          <div className="flex items-center gap-1.5">
            <Button
              variant="outline"
              size="sm"
              onClick={handleClear}
              className="h-7 text-xs border-border/60 text-muted-foreground hover:text-foreground gap-1"
            >
              <RotateCcw className="size-3" />
              <span>Clear</span>
            </Button>
            <Button
              size="sm"
              disabled={isRunning || currentRole === 'Viewer'}
              onClick={handleRun}
              className="h-7 text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
            >
              <Play className="size-3 fill-current" />
              <span>{isRunning ? 'Executing...' : 'Dispatch'}</span>
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-3 flex flex-col gap-3">
        {/* Command Configuration Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          <div className="flex flex-col gap-1">
            <Select value={selectedAction} onValueChange={(val) => setSelectedAction(val ?? 'scan')}>
              <SelectTrigger className="h-7 text-xs w-full bg-background/50 border-border/60">
                <SelectValue placeholder="Action">
                  {(val: string | null) => {
                    if (val === 'scan') return 'sentra scan (SAST & Taint)'
                    if (val === 'audit') return 'sentra audit (Lockfile Audit)'
                    if (val === 'codeql') return 'sentra codeql (Probe)'
                    if (val === 'diff') return 'sentra diff (Snapshot Diff)'
                    return val || 'Action'
                  }}
                </SelectValue>
              </SelectTrigger>
              <SelectContent className="min-w-[320px] sm:min-w-[380px] max-w-[calc(100vw-2rem)]">
                <SelectGroup>
                  <SelectItem value="scan">sentra scan (SAST & Taint Analysis)</SelectItem>
                  <SelectItem value="audit">sentra audit (Multi-Lockfile Audit)</SelectItem>
                  <SelectItem value="codeql">sentra codeql (Workspace Probe & SARIF)</SelectItem>
                  <SelectItem value="diff">sentra diff (Snapshot Comparison)</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>

          <div className="sm:col-span-2 flex flex-col gap-1">
            <Input
              value={workspacePath}
              onChange={(e) => setWorkspacePath(e.target.value)}
              className="h-7 text-xs font-mono bg-background/50 border-border/60"
              placeholder="Workspace path..."
            />
          </div>
        </div>

        {/* Live Terminal Box with shadcn ScrollArea */}
        <ScrollArea className="bg-background/90 text-emerald-400 font-mono text-[11px] rounded-md border border-border/50 h-[180px] shadow-inner">
          <div className="p-3 flex flex-col gap-1 leading-relaxed">
            {consoleOutput.map((line, idx) => (
              <div key={idx} className="whitespace-pre-wrap">
                {line}
              </div>
            ))}
          </div>
        </ScrollArea>

        {/* Status footer */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-[11px] text-muted-foreground px-0.5">
          <span className="flex items-center gap-1.5">
            <Lock className="size-3 text-emerald-400" />
            Host Execution Protection: Fail-Closed
          </span>
          <span className="flex items-center gap-1">
            <CheckCircle2 className="size-3 text-sky-400" />
            Deterministic AST Guarantee
          </span>
        </div>
      </CardContent>
    </Card>
  )
}
