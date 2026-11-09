import { useState, useEffect, useRef } from 'react'
import {
  Play,
  Square,
  Terminal,
  CheckCircle2,
  AlertCircle,
  FolderGit2,
  Cpu,
  Layers,
  Database,
  ShieldCheck,
  SearchCode,
  Copy,
  Check,
  Maximize2,
  Download,
  ArrowRight,
  RefreshCw,
} from 'lucide-react'
import { toast } from 'sonner'
import { copyText } from '@/lib/clipboard'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import {
  streamLiveScan,
  validateWorkspacePath,
  transformMatchesToFindings,
  type StreamLogItem,
  type PathValidationResult,
} from '@/lib/api-client'
import type { FindingView, UserRole } from '@/types/sentra'

interface LiveStreamModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  initialWorkspace: string
  currentRole: UserRole
  onScanComplete: (findings: FindingView[], rawResult: any) => void
  onNavigateToFindings: () => void
}

const PRESETS = [
  { label: 'Sentra Root', path: 'E:/MyProject/Mix/GitHub/Sentra' },
  { label: 'Core Tests', path: 'E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/tests' },
  { label: 'Crates Workspace', path: 'E:/MyProject/Mix/GitHub/Sentra/crates' },
  { label: 'Web Dashboard', path: 'E:/MyProject/Mix/GitHub/Sentra/web' },
]

export function LiveStreamModal({
  open,
  onOpenChange,
  initialWorkspace,
  currentRole,
  onScanComplete,
  onNavigateToFindings,
}: LiveStreamModalProps) {
  const [workspace, setWorkspace] = useState(initialWorkspace)
  const [scanType, setScanType] = useState<'all' | 'sast' | 'audit' | 'codeql'>('all')
  const [persist, setPersist] = useState(true)

  // Validation State
  const [validating, setValidating] = useState(false)
  const [pathInfo, setPathInfo] = useState<PathValidationResult | null>(null)

  // Execution State
  const [status, setStatus] = useState<'idle' | 'running' | 'completed' | 'error'>('idle')
  const [currentStage, setCurrentStage] = useState('Ready to scan')
  const [progressPercent, setProgressPercent] = useState(0)
  const [logs, setLogs] = useState<StreamLogItem[]>([])
  const [scanSummary, setScanSummary] = useState<any>(null)
  const [elapsedSeconds, setElapsedSeconds] = useState(0)
  const [copied, setCopied] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)

  const abortRef = useRef<(() => void) | null>(null)
  const logContainerRef = useRef<HTMLDivElement>(null)
  const timerRef = useRef<any>(null)

  useEffect(() => {
    setWorkspace(initialWorkspace)
  }, [initialWorkspace])

  // Validate path on change or open
  useEffect(() => {
    if (open && workspace) {
      validatePath(workspace)
    }
  }, [open, workspace])

  // Timer while running
  useEffect(() => {
    if (status === 'running') {
      const startTime = Date.now()
      timerRef.current = setInterval(() => {
        setElapsedSeconds(Math.floor((Date.now() - startTime) / 1000))
      }, 500)
    } else {
      if (timerRef.current) clearInterval(timerRef.current)
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [status])

  // Auto-scroll log container
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [logs, autoScroll])

  async function validatePath(pathStr: string) {
    setValidating(true)
    try {
      const res = await validateWorkspacePath(pathStr)
      setPathInfo(res)
    } finally {
      setValidating(false)
    }
  }

  function handleStartScan() {
    if (currentRole === 'Viewer') {
      toast.error('Action Denied: Viewer Role', {
        description: 'Viewer role has read-only access. Switch to Operator or Admin to execute scans.',
      })
      return
    }
    setStatus('running')
    setLogs([])
    setProgressPercent(5)
    setCurrentStage('Starting scan worker stream...')
    setElapsedSeconds(0)
    setScanSummary(null)

    const abortFn = streamLiveScan({
      workspace,
      scanType,
      persist,
      onLog: (item) => {
        setLogs((prev) => [...prev, item])
      },
      onProgress: (stage, percent) => {
        setCurrentStage(stage)
        setProgressPercent(percent)
      },
      onComplete: (data) => {
        setStatus('completed')
        setProgressPercent(100)
        setCurrentStage('Scan successfully completed')
        setScanSummary(data)

        if (data.scan && data.scan.matches) {
          const findings = transformMatchesToFindings(data.scan.matches)
          onScanComplete(findings, data)
        }

        toast.success('Live Security Scan Complete', {
          description: `Finished in ${elapsedSeconds}s. SQLite WAL session committed.`,
        })
      },
      onError: (err) => {
        setStatus('error')
        setCurrentStage(`Scan error: ${err.message || 'Unknown error'}`)
        toast.error('Scan Failed', {
          description: err.message || 'Error occurred during streaming.',
        })
      },
    })

    abortRef.current = abortFn
  }

  function handleStopScan() {
    if (abortRef.current) {
      abortRef.current()
      abortRef.current = null
      setStatus('error')
      setCurrentStage('Scan aborted by operator.')
      toast.info('Scan Aborted')
    }
  }

  async function handleCopyLogs() {
    const text = logs.map((l) => `[${l.timestamp.slice(11, 19)}] ${l.text}`).join('\n')
    await copyText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
    toast.success('Logs copied to clipboard')
  }

  function formatLogText(text: string) {
    if (text.startsWith('[SENTRA]')) {
      return <span className="text-cyan-400 font-semibold">{text}</span>
    }
    if (text.startsWith('[STORAGE]')) {
      return <span className="text-purple-400">{text}</span>
    }
    if (text.startsWith('[AUDIT]')) {
      return <span className="text-blue-400">{text}</span>
    }
    if (text.startsWith('[CODEQL]')) {
      return <span className="text-teal-400">{text}</span>
    }
    if (text.startsWith('[SAST]')) {
      return <span className="text-amber-400 font-semibold">{text}</span>
    }
    if (text.startsWith('[DONE]')) {
      return <span className="text-emerald-400 font-bold">{text}</span>
    }
    if (text.startsWith('[ERROR]')) {
      return <span className="text-rose-400 font-bold">{text}</span>
    }
    if (text.includes('[CRITICAL]')) {
      return <span className="text-rose-400">{text}</span>
    }
    if (text.includes('[HIGH]')) {
      return <span className="text-amber-400">{text}</span>
    }
    return <span className="text-zinc-300">{text}</span>
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] flex flex-col p-0 overflow-hidden bg-zinc-950 border-zinc-800 text-zinc-100 shadow-2xl">
        {/* Sticky Header */}
        <DialogHeader className="px-6 py-4 border-b border-zinc-800 bg-zinc-900/50 flex flex-row items-center justify-between">
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-2">
              <Terminal className="size-5 text-primary" />
              <DialogTitle className="text-base font-bold tracking-tight text-zinc-100">
                Live Security Scan Console (Server-Sent Events)
              </DialogTitle>
              <Badge variant="outline" className="text-[10px] font-mono border-primary/30 text-primary">
                sentra.exe core
              </Badge>
            </div>
            <DialogDescription className="text-xs text-zinc-400">
              Direct real-time streaming from the pure-Rust zero-unsafe engine to local SQLite WAL storage.
            </DialogDescription>
          </div>

          <div className="flex items-center gap-2 pr-8">
            {status === 'running' && (
              <Badge variant="secondary" className="text-xs font-mono flex items-center gap-1.5 bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                <span className="size-2 rounded-full bg-emerald-400 animate-pulse" />
                Live: {elapsedSeconds}s
              </Badge>
            )}
            {status === 'completed' && (
              <Badge variant="secondary" className="text-xs font-mono bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                <CheckCircle2 className="size-3 mr-1 inline" /> Completed ({elapsedSeconds}s)
              </Badge>
            )}
          </div>
        </DialogHeader>

        {/* Configuration Section (Visible when idle) */}
        {status === 'idle' && (
          <div className="p-6 flex flex-col gap-5 bg-zinc-900/30 border-b border-zinc-800">
            {/* Target Path Selector */}
            <div className="flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-zinc-200 flex items-center gap-1.5">
                  <FolderGit2 className="size-3.5 text-primary" /> Target Workspace Directory:
                </label>
                <div className="flex items-center gap-1">
                  <span className="text-[11px] text-zinc-400 mr-1">Quick Presets:</span>
                  {PRESETS.map((p) => (
                    <Button
                      key={p.label}
                      variant="outline"
                      size="sm"
                      className="h-6 text-[10px] px-2 bg-zinc-900 border-zinc-800 hover:border-zinc-700 text-zinc-300"
                      onClick={() => setWorkspace(p.path)}
                    >
                      {p.label}
                    </Button>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-2">
                <Input
                  value={workspace}
                  onChange={(e) => setWorkspace(e.target.value)}
                  placeholder="Absolute folder path on host..."
                  className="h-9 text-xs font-mono bg-zinc-950 border-zinc-800 focus-visible:ring-primary/40 text-zinc-200"
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => validatePath(workspace)}
                  disabled={validating}
                  className="h-9 text-xs border-zinc-800 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 shrink-0"
                >
                  <RefreshCw className={`size-3.5 mr-1.5 ${validating ? 'animate-spin' : ''}`} />
                  Validate
                </Button>
              </div>

              {/* Path Info Chips */}
              {pathInfo && (
                <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                  {pathInfo.exists ? (
                    <>
                      <Badge variant="outline" className="text-[11px] text-emerald-400 border-emerald-500/30 bg-emerald-500/5">
                        <CheckCircle2 className="size-3 mr-1 inline" /> Directory Exists ({pathInfo.fileCount} entries)
                      </Badge>
                      {pathInfo.isGitRepo && (
                        <Badge variant="outline" className="text-[11px] text-zinc-300 border-zinc-700">
                          Git Repository
                        </Badge>
                      )}
                      {pathInfo.ecosystems?.rust && (
                        <Badge variant="outline" className="text-[11px] text-amber-400 border-amber-500/30 bg-amber-500/5">
                          Rust / Cargo.lock
                        </Badge>
                      )}
                      {pathInfo.ecosystems?.bun && (
                        <Badge variant="outline" className="text-[11px] text-pink-400 border-pink-500/30 bg-pink-500/5">
                          Bun / bun.lock
                        </Badge>
                      )}
                      {pathInfo.ecosystems?.node && (
                        <Badge variant="outline" className="text-[11px] text-emerald-400 border-emerald-500/30 bg-emerald-500/5">
                          Node.js / package.json
                        </Badge>
                      )}
                    </>
                  ) : (
                    <Badge variant="destructive" className="text-[11px]">
                      <AlertCircle className="size-3 mr-1 inline" /> {pathInfo.error || 'Path not found'}
                    </Badge>
                  )}
                </div>
              )}
            </div>

            {/* Scope Selection */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <button
                type="button"
                onClick={() => setScanType('all')}
                className={`p-3 rounded-lg border text-left flex flex-col gap-1 transition-all ${
                  scanType === 'all'
                    ? 'border-primary bg-primary/10 shadow-sm'
                    : 'border-zinc-800 bg-zinc-950/60 hover:border-zinc-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-zinc-100 flex items-center gap-1.5">
                    <Layers className="size-3.5 text-primary" /> Full Security Suite
                  </span>
                  {scanType === 'all' && <CheckCircle2 className="size-3.5 text-primary" />}
                </div>
                <p className="text-[11px] text-zinc-400">
                  SAST, Semantic Taint Analysis, Lockfile Audit &amp; CodeQL Probe.
                </p>
              </button>

              <button
                type="button"
                onClick={() => setScanType('sast')}
                className={`p-3 rounded-lg border text-left flex flex-col gap-1 transition-all ${
                  scanType === 'sast'
                    ? 'border-primary bg-primary/10 shadow-sm'
                    : 'border-zinc-800 bg-zinc-950/60 hover:border-zinc-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-zinc-100 flex items-center gap-1.5">
                    <Cpu className="size-3.5 text-amber-400" /> Pure-Rust SAST &amp; Taint
                  </span>
                  {scanType === 'sast' && <CheckCircle2 className="size-3.5 text-primary" />}
                </div>
                <p className="text-[11px] text-zinc-400">
                  Zero-unsafe ReDoS-proof AST scanning, secrets &amp; taint data-flows.
                </p>
              </button>

              <button
                type="button"
                onClick={() => setScanType('audit')}
                className={`p-3 rounded-lg border text-left flex flex-col gap-1 transition-all ${
                  scanType === 'audit'
                    ? 'border-primary bg-primary/10 shadow-sm'
                    : 'border-zinc-800 bg-zinc-950/60 hover:border-zinc-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-zinc-100 flex items-center gap-1.5">
                    <ShieldCheck className="size-3.5 text-blue-400" /> Multi-Lockfile Audit
                  </span>
                  {scanType === 'audit' && <CheckCircle2 className="size-3.5 text-primary" />}
                </div>
                <p className="text-[11px] text-zinc-400">
                  Audit Cargo.lock, bun.lock, package-lock.json against OSV database.
                </p>
              </button>
            </div>

            {/* Options */}
            <div className="flex items-center justify-between pt-1">
              <label className="flex items-center gap-2 cursor-pointer text-xs text-zinc-300">
                <input
                  type="checkbox"
                  checked={persist}
                  onChange={(e) => setPersist(e.target.checked)}
                  className="rounded border-zinc-700 bg-zinc-900 text-primary focus:ring-primary/40 size-3.5"
                />
                <span className="flex items-center gap-1">
                  <Database className="size-3.5 text-purple-400 inline" />
                  Persist Session &amp; Audit Trail into SQLite WAL (<code className="font-mono text-[10px] text-zinc-400">sentra.db</code>)
                </span>
              </label>

              <div className="flex items-center gap-3">
                {currentRole === 'Viewer' && (
                  <span className="text-[11px] text-amber-400 font-medium">
                    Viewer mode: Scans disabled
                  </span>
                )}
                <Button
                  onClick={handleStartScan}
                  disabled={!pathInfo?.exists || currentRole === 'Viewer'}
                  className="h-9 px-4 text-xs font-semibold bg-primary text-primary-foreground hover:bg-primary/90 shadow-md disabled:opacity-40"
                  title={currentRole === 'Viewer' ? "Viewer role is read-only. Switch to Operator or Admin to execute scans." : undefined}
                >
                  <Play className="size-3.5 mr-1.5 fill-current" />
                  Start Live Streaming Scan
                </Button>
              </div>
            </div>
          </div>
        )}

        {/* Live Streaming Stage & Log Console (Visible when running or completed) */}
        {status !== 'idle' && (
          <div className="p-6 flex flex-col gap-4 flex-1 overflow-hidden">
            {/* Progress & Stage Banner */}
            <div className="flex flex-col gap-2 p-3.5 rounded-lg border border-zinc-800 bg-zinc-900/60">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-zinc-200 flex items-center gap-2">
                  {status === 'running' && <span className="size-2 rounded-full bg-emerald-400 animate-ping" />}
                  {currentStage}
                </span>
                <span className="font-mono font-bold text-primary">{progressPercent}%</span>
              </div>
              <Progress value={progressPercent} className="h-2 bg-zinc-800" />
            </div>

            {/* Terminal Log Console */}
            <div className="flex flex-col flex-1 rounded-lg border border-zinc-800 bg-zinc-950 overflow-hidden shadow-inner">
              {/* Terminal Title Bar */}
              <div className="px-3 py-2 border-b border-zinc-800/80 bg-zinc-900/80 flex items-center justify-between text-xs text-zinc-400">
                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1.5">
                    <span className="size-2.5 rounded-full bg-rose-500/80 inline-block" />
                    <span className="size-2.5 rounded-full bg-amber-500/80 inline-block" />
                    <span className="size-2.5 rounded-full bg-emerald-500/80 inline-block" />
                  </div>
                  <span className="font-mono text-[11px] text-zinc-300">sentra-stream-worker://stdio</span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setAutoScroll(!autoScroll)}
                    className={`text-[10px] px-2 py-0.5 rounded border ${
                      autoScroll ? 'border-primary/40 text-primary bg-primary/10' : 'border-zinc-700 text-zinc-400'
                    }`}
                  >
                    Auto-scroll: {autoScroll ? 'ON' : 'OFF'}
                  </button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={handleCopyLogs}
                    className="h-6 px-2 text-[10px] text-zinc-400 hover:text-zinc-100"
                  >
                    {copied ? <Check className="size-3 mr-1 text-emerald-400" /> : <Copy className="size-3 mr-1" />}
                    Copy Logs
                  </Button>
                </div>
              </div>

              {/* Monospace Output */}
              <div
                ref={logContainerRef}
                className="p-4 font-mono text-xs overflow-y-auto max-h-[300px] min-h-[220px] flex flex-col gap-1 leading-relaxed selection:bg-primary/30"
              >
                {logs.length === 0 ? (
                  <div className="text-zinc-500 italic py-8 text-center">
                    Connecting to sentra.exe stream...
                  </div>
                ) : (
                  logs.map((log) => (
                    <div key={log.id} className="flex items-start gap-2 break-all">
                      <span className="text-zinc-600 select-none text-[10px] shrink-0 pt-0.5">
                        {log.timestamp.slice(11, 19)}
                      </span>
                      <div className="flex-1">{formatLogText(log.text)}</div>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Summary Banner when Completed */}
            {status === 'completed' && scanSummary && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 rounded-lg border border-emerald-500/30 bg-emerald-500/5">
                <div className="flex flex-col">
                  <span className="text-[10px] text-zinc-400 uppercase font-semibold">Files Scanned</span>
                  <span className="text-base font-bold font-mono text-zinc-100">
                    {scanSummary.scan?.files_scanned || 0}
                  </span>
                </div>
                <div className="flex flex-col">
                  <span className="text-[10px] text-zinc-400 uppercase font-semibold">Signals Detected</span>
                  <span className="text-base font-bold font-mono text-amber-400">
                    {scanSummary.scan?.signals_found || 0}
                  </span>
                </div>
                <div className="flex flex-col">
                  <span className="text-[10px] text-zinc-400 uppercase font-semibold">Audited Packages</span>
                  <span className="text-base font-bold font-mono text-blue-400">
                    {scanSummary.audit?.packages_audited || 0}
                  </span>
                </div>
                <div className="flex flex-col">
                  <span className="text-[10px] text-zinc-400 uppercase font-semibold">SQLite WAL Events</span>
                  <span className="text-base font-bold font-mono text-purple-400">
                    {scanSummary.auditEvents?.length || 0} committed
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Footer Actions */}
        <div className="px-6 py-3.5 border-t border-zinc-800 bg-zinc-900/60 flex items-center justify-between">
          <div className="text-xs text-zinc-400 font-mono">
            {status === 'running' ? 'Scanning active... Fail-closed boundary intact' : 'Zero untrusted execution'}
          </div>

          <div className="flex items-center gap-2">
            {status === 'running' && (
              <Button
                variant="destructive"
                size="sm"
                onClick={handleStopScan}
                className="h-8 text-xs font-semibold shadow-sm"
              >
                <Square className="size-3.5 mr-1.5 fill-current" />
                Abort Scan
              </Button>
            )}

            {status === 'completed' && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setStatus('idle')}
                  className="h-8 text-xs border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-200"
                >
                  Run Another Scan
                </Button>
                <Button
                  size="sm"
                  onClick={() => {
                    onOpenChange(false)
                    onNavigateToFindings()
                  }}
                  className="h-8 text-xs font-bold bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
                >
                  Explore Findings
                  <ArrowRight className="size-3.5 ml-1.5" />
                </Button>
              </>
            )}

            {status === 'idle' && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => onOpenChange(false)}
                className="h-8 text-xs border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-200"
              >
                Close
              </Button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
