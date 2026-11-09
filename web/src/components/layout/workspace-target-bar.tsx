import { useState } from 'react'
import {
  FolderGit2,
  Play,
  RotateCw,
  SearchCode,
  ShieldCheck,
  CheckCircle2,
  Terminal,
  Cpu,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

interface WorkspaceTargetBarProps {
  currentWorkspace: string
  onWorkspaceChange: (path: string) => void
  onRunScan: () => void
  onRunAudit: () => void
  onRunCodeQl: () => void
  isScanning: boolean
  isAuditing: boolean
  isCodeQlProbing: boolean
  backendConnected: boolean
  binaryPath: string
}

export function WorkspaceTargetBar({
  currentWorkspace,
  onWorkspaceChange,
  onRunScan,
  onRunAudit,
  onRunCodeQl,
  isScanning,
  isAuditing,
  isCodeQlProbing,
  backendConnected,
  binaryPath,
}: WorkspaceTargetBarProps) {
  const [inputVal, setInputVal] = useState(currentWorkspace)

  function handlePreset(val: string | null) {
    if (!val) return
    let newPath = val
    if (val === 'root') newPath = 'E:/MyProject/Mix/GitHub/Sentra'
    else if (val === 'tests') newPath = 'E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/tests'
    else if (val === 'crates') newPath = 'E:/MyProject/Mix/GitHub/Sentra/crates'
    setInputVal(newPath)
    onWorkspaceChange(newPath)
  }

  function handleCommit() {
    onWorkspaceChange(inputVal.trim())
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
                className="text-[10px] h-4 font-mono flex items-center gap-1"
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

        {/* Right: Quick Target Presets */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-zinc-400 font-medium">Quick Path Preset:</span>
          <Select onValueChange={handlePreset} defaultValue="root">
            <SelectTrigger className="w-[210px] h-8 text-xs bg-zinc-950/80 border-zinc-800">
              <SelectValue placeholder="Select target preset" />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="root">Sentra Monorepo Root</SelectItem>
                <SelectItem value="tests">Core Tests (Taint &amp; Signals)</SelectItem>
                <SelectItem value="crates">Rust Crates Workspace</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Target Directory Path Input Bar & Actions */}
      <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-zinc-800/60">
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
            disabled={isScanning || !backendConnected}
            onClick={onRunScan}
            className="h-8 text-xs font-semibold bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
          >
            <Play data-icon="inline-start" className={isScanning ? 'animate-spin' : ''} />
            {isScanning ? 'Scanning Disk...' : 'Run Pure-Rust SAST & Taint'}
          </Button>

          <Button
            variant="outline"
            size="sm"
            disabled={isAuditing || !backendConnected}
            onClick={onRunAudit}
            className="h-8 text-xs font-medium border-zinc-800 bg-zinc-950/80 hover:bg-zinc-800 text-zinc-200"
          >
            <ShieldCheck data-icon="inline-start" className={isAuditing ? 'animate-spin' : ''} />
            {isAuditing ? 'Auditing...' : 'Audit Lockfiles'}
          </Button>

          <Button
            variant="outline"
            size="sm"
            disabled={isCodeQlProbing || !backendConnected}
            onClick={onRunCodeQl}
            className="h-8 text-xs font-medium border-zinc-800 bg-zinc-950/80 hover:bg-zinc-800 text-zinc-200"
          >
            <SearchCode data-icon="inline-start" className={isCodeQlProbing ? 'animate-spin' : ''} />
            {isCodeQlProbing ? 'Probing...' : 'Probe CodeQL'}
          </Button>
        </div>
      </div>
    </div>
  )
}
