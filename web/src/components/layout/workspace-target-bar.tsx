import { useState, useEffect } from 'react'
import {
  FolderGit2,
  Play,
  Radio,
  ShieldCheck,
  SearchCode,
  ChevronDown,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import type { UserRole } from '@/types/sentra'

interface WorkspaceTargetBarProps {
  currentRole: UserRole
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
  { id: 'root', label: 'Root (Sentra)', path: '.' },
  { id: 'tests', label: 'Core Tests', path: 'crates/sentra-core/tests' },
  { id: 'crates', label: 'Crates Workspace', path: 'crates' },
  { id: 'web', label: 'Web UI', path: 'web' },
]

export function WorkspaceTargetBar({
  currentRole,
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

  function handleCommit() {
    if (inputVal.trim() && inputVal.trim() !== currentWorkspace) {
      onWorkspaceChange(inputVal.trim())
    }
  }

  const activePreset = PRESETS.find((p) => p.path === currentWorkspace)

  return (
    <div className="border border-zinc-800/80 bg-zinc-900/40 rounded-xl p-2 sm:px-3 sm:py-2 backdrop-blur flex flex-col md:flex-row md:items-center justify-between gap-2.5 shadow-xs">
      {/* Left: Target Preset & Path Selection */}
      <div className="flex items-center gap-2 flex-1 min-w-0">
        <div className="size-7 rounded-lg bg-primary/10 border border-primary/25 text-primary flex items-center justify-center shrink-0">
          <FolderGit2 className="size-3.5" />
        </div>

        {/* Preset Selector Dropdown */}
        <Select
          value={activePreset ? activePreset.id : 'custom'}
          onValueChange={(val) => {
            const match = PRESETS.find((p) => p.id === val)
            if (match) {
              setInputVal(match.path)
              onWorkspaceChange(match.path)
            }
          }}
        >
          <SelectTrigger className="h-7.5 w-[125px] sm:w-[145px] text-xs bg-zinc-950/80 border-zinc-800 text-zinc-200 shrink-0 px-2 font-medium">
            <SelectValue placeholder="Preset">
              {activePreset ? activePreset.label : 'Custom Target'}
            </SelectValue>
          </SelectTrigger>
          <SelectContent>
            {PRESETS.map((p) => (
              <SelectItem key={p.id} value={p.id}>
                {p.label}
              </SelectItem>
            ))}
            {!activePreset && (
              <SelectItem value="custom" disabled>
                Custom Path
              </SelectItem>
            )}
          </SelectContent>
        </Select>

        {/* Editable Path Input */}
        <div className="relative flex-1 min-w-[130px] max-w-[420px]">
          <Input
            value={inputVal}
            onChange={(e) => setInputVal(e.target.value)}
            onBlur={handleCommit}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleCommit()
            }}
            placeholder="Type folder path..."
            className="h-7.5 text-xs font-mono bg-zinc-950/70 border-zinc-800 text-zinc-300 w-full px-2.5 focus-visible:ring-primary/30"
            title={inputVal}
          />
        </div>

        {/* Engine Ready Indicator */}
        <div
          className="hidden xl:flex items-center gap-1.5 text-[11px] font-mono text-zinc-400 bg-zinc-950/60 border border-zinc-800/80 px-2 py-0.5 rounded-md shrink-0 select-none"
          title={binaryPath || 'sentra.exe engine'}
        >
          <span
            className={`size-1.5 rounded-full ${backendConnected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`}
          />
          <span className="text-[10px]">{backendConnected ? 'sentra.exe' : 'Disconnected'}</span>
        </div>
      </div>

      {/* Right: Scan Actions */}
      <div className="flex items-center gap-1.5 sm:gap-2 shrink-0 self-end md:self-auto">
        {currentRole === 'Viewer' ? (
          <Badge variant="outline" className="text-[10px] text-amber-400 border-amber-500/30 font-medium">
            Viewer: Read Only
          </Badge>
        ) : (
          <>
            {/* Primary Action: Live SSE Stream Scan */}
            <Button
              size="sm"
              onClick={onOpenLiveStream}
              className="h-7.5 text-xs font-bold bg-primary text-primary-foreground hover:bg-primary/90 shadow-xs flex items-center gap-1.5 px-3 cursor-pointer"
            >
              <Radio className="size-3 animate-pulse" />
              <span>Live Scan</span>
            </Button>

            {/* Direct SAST Scan */}
            <Button
              variant="outline"
              size="sm"
              disabled={isScanning || !backendConnected}
              onClick={onRunScan}
              className="h-7.5 text-xs font-medium border-zinc-800 bg-zinc-950/80 hover:bg-zinc-800 text-zinc-200 px-2.5 flex items-center gap-1 cursor-pointer"
              title="Run direct native AST & taint analysis"
            >
              <Play className={`size-3 fill-current ${isScanning ? 'animate-spin text-primary' : ''}`} />
              <span>{isScanning ? 'Scanning...' : 'Direct SAST'}</span>
            </Button>

            {/* More Scan Tools Dropdown */}
            <DropdownMenu>
              <DropdownMenuTrigger
                className="inline-flex items-center justify-center h-7.5 text-xs font-medium rounded-md border border-zinc-800 bg-zinc-950/80 hover:bg-zinc-800 text-zinc-300 px-2 gap-1 cursor-pointer transition-colors outline-none"
                title="More audit and discovery tools"
              >
                <span className="hidden sm:inline">Tools</span>
                <ChevronDown className="size-3 text-zinc-400" />
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-56 bg-zinc-950 border border-zinc-800 p-1.5 text-zinc-200">
                <DropdownMenuItem
                  disabled={isAuditing || !backendConnected}
                  onClick={onRunAudit}
                  className="cursor-pointer text-xs flex items-center gap-2 py-1.5"
                >
                  <ShieldCheck className={`size-3.5 text-emerald-400 ${isAuditing ? 'animate-spin' : ''}`} />
                  <span>{isAuditing ? 'Auditing...' : 'Audit Lockfiles (RustSec)'}</span>
                </DropdownMenuItem>
                <DropdownMenuItem
                  disabled={isCodeQlProbing || !backendConnected}
                  onClick={onRunCodeQl}
                  className="cursor-pointer text-xs flex items-center gap-2 py-1.5"
                >
                  <SearchCode className={`size-3.5 text-cyan-400 ${isCodeQlProbing ? 'animate-spin' : ''}`} />
                  <span>{isCodeQlProbing ? 'Probing...' : 'Probe CodeQL Ecosystem'}</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        )}
      </div>
    </div>
  )
}
