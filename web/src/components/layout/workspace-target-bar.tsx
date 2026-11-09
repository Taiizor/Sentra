import { useState, useEffect } from 'react'
import {
  FolderGit2,
  Play,
  RotateCw,
  SearchCode,
  ShieldCheck,
  CheckCircle2,
  Terminal,
  Cpu,
  Layers,
  Sparkles,
  Radio,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

interface WorkspaceTargetBarProps {
  currentWorkspace: string
  onWorkspaceChange: (path: string) => void
  onRunScan: () => void
  onRunAudit: () => void
  onRunCodeQl: () => void
  onOpenLiveStream: () => void
  isScanning: boolean
  isAuditing: boolean
  isCodeQlProbing: boolean
  backendConnected: boolean
  binaryPath: string
}

const PRESETS = [
  { id: 'root', label: 'Root (Sentra)', path: 'E:/MyProject/Mix/GitHub/Sentra' },
  { id: 'tests', label: 'Core Tests', path: 'E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/tests' },
  { id: 'crates', label: 'Crates Workspace', path: 'E:/MyProject/Mix/GitHub/Sentra/crates' },
  { id: 'web', label: 'Web UI', path: 'E:/MyProject/Mix/GitHub/Sentra/web' },
]

export function WorkspaceTargetBar({
  currentWorkspace,
  onWorkspaceChange,
  onRunScan,
  onRunAudit,
  onRunCodeQl,
  onOpenLiveStream,
  isScanning,
  isAuditing,
  isCodeQlProbing,
  backendConnected,
  binaryPath,
}: WorkspaceTargetBarProps) {
  const [inputVal, setInputVal] = useState(currentWorkspace)

  useEffect(() => {
    setInputVal(currentWorkspace)
  }, [currentWorkspace])

  function handleSelectPreset(path: string) {
    setInputVal(path)
    onWorkspaceChange(path)
  }

  function handleCommit() {
    if (inputVal.trim() && inputVal.trim() !== currentWorkspace) {
      onWorkspaceChange(inputVal.trim())
    }
  }

  return (
    <div className="border border-zinc-800 bg-zinc-900/60 rounded-xl p-3.5 backdrop-blur flex flex-col gap-3 shadow-md">
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Left: Target Path & Status */}
        <div className="flex items-center gap-3">
          <div className="size-8 rounded-md bg-primary/10 border border-primary/30 text-primary flex items-center justify-center">
            <FolderGit2 className="size-4" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-zinc-100">Target Workspace on Disk:</span>
              <Badge
                variant={backendConnected ? 'secondary' : 'destructive'}
                className="text-[10px] h-4 font-mono flex items-center gap-1 font-semibold"
              >
                <span
                  className={`size-1.5 rounded-full ${backendConnected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`}
                />
                {backendConnected ? 'Engine: sentra.exe Connected' : 'Engine: Disconnected'}
              </Badge>
            </div>
            <span className="text-[11px] text-zinc-400 font-mono truncate max-w-[500px]">
              {binaryPath ? `Binary: ${binaryPath}` : 'Checking sentra.exe...'}
            </span>
          </div>
        </div>

        {/* Right: Quick Target Presets Pills */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-zinc-400 font-medium mr-1">Target Presets:</span>
          {PRESETS.map((p) => {
            const isSelected = currentWorkspace === p.path
            return (
              <Button
                key={p.id}
                variant={isSelected ? 'default' : 'outline'}
                size="sm"
                className={`h-7 text-xs rounded-lg px-2.5 ${
                  isSelected
                    ? 'font-bold shadow-sm'
                    : 'bg-zinc-950/70 border-zinc-800 hover:border-zinc-700 text-zinc-300'
                }`}
                onClick={() => handleSelectPreset(p.path)}
              >
                {p.label}
              </Button>
            )
          })}
        </div>
      </div>

      {/* Target Directory Path Input Bar & Actions */}
      <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-zinc-800/60">
        <div className="flex-1 min-w-[280px] flex items-center gap-2">
          <Input
            value={inputVal}
            onChange={(e) => setInputVal(e.target.value)}
            onBlur={handleCommit}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleCommit()
            }}
            placeholder="Type any absolute folder path on your computer (e.g. D:/MyProject)..."
            className="h-8 text-xs font-mono bg-zinc-950 border-zinc-800 focus-visible:ring-primary/40 text-zinc-200"
          />
        </div>

        {/* Actions triggering the real sentra.exe binary */}
        <div className="flex items-center gap-2 shrink-0">
          <Button
            size="sm"
            onClick={onOpenLiveStream}
            className="h-8 text-xs font-bold bg-primary text-primary-foreground hover:bg-primary/90 shadow-md flex items-center gap-1.5"
          >
            <Radio className="size-3.5 text-primary-foreground animate-pulse" />
            Live SSE Stream Scan
          </Button>

          <Button
            variant="outline"
            size="sm"
            disabled={isScanning || !backendConnected}
            onClick={onRunScan}
            className="h-8 text-xs font-medium border-zinc-800 bg-zinc-950/80 hover:bg-zinc-800 text-zinc-200"
          >
            <Play className={`size-3.5 mr-1.5 fill-current ${isScanning ? 'animate-spin' : ''}`} />
            {isScanning ? 'Scanning...' : 'Direct SAST'}
          </Button>

          <Button
            variant="outline"
            size="sm"
            disabled={isAuditing || !backendConnected}
            onClick={onRunAudit}
            className="h-8 text-xs font-medium border-zinc-800 bg-zinc-950/80 hover:bg-zinc-800 text-zinc-200"
          >
            <ShieldCheck className={`size-3.5 mr-1.5 ${isAuditing ? 'animate-spin text-primary' : ''}`} />
            {isAuditing ? 'Auditing...' : 'Audit Lockfiles'}
          </Button>

          <Button
            variant="outline"
            size="sm"
            disabled={isCodeQlProbing || !backendConnected}
            onClick={onRunCodeQl}
            className="h-8 text-xs font-medium border-zinc-800 bg-zinc-950/80 hover:bg-zinc-800 text-zinc-200"
          >
            <SearchCode className={`size-3.5 mr-1.5 ${isCodeQlProbing ? 'animate-spin text-primary' : ''}`} />
            {isCodeQlProbing ? 'Probing...' : 'Probe CodeQL'}
          </Button>
        </div>
      </div>
    </div>
  )
}
