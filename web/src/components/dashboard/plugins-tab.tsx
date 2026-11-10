import { useState, useEffect, useMemo } from 'react'
import {
  Blocks,
  Play,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Activity,
  Terminal,
  Cpu,
  ShieldCheck,
  ShieldAlert,
  Clock,
  HardDrive,
  Search,
  RefreshCw,
  ExternalLink,
  FileCode,
  Sparkles,
  Layers,
} from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  fetchDiscoveredPlugins,
  probePluginAdapter,
  runPluginCapability,
} from '@/lib/api-client'
import type {
  DiscoveredPluginView,
  PluginProbeResult,
  PluginExecutionResult,
  UserRole,
} from '@/types/sentra'

interface PluginsTabProps {
  currentWorkspace: string
  currentRole: UserRole
}

const FAMILY_LABELS: Record<string, { label: string; color: string }> = {
  analysis_tool: { label: 'Analysis Tool', color: 'bg-blue-500/15 text-blue-400 border-blue-500/30' },
  ai_provider: { label: 'AI Provider', color: 'bg-purple-500/15 text-purple-400 border-purple-500/30' },
  language_framework: { label: 'Language Framework', color: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' },
  execution_backend: { label: 'Execution Backend', color: 'bg-amber-500/15 text-amber-400 border-amber-500/30' },
  research_system: { label: 'Research System', color: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30' },
  export_import: { label: 'Export/Import', color: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30' },
}

const CAPABILITY_INFO: Record<string, { label: string; desc: string; icon: any }> = {
  dependency_audit: {
    label: 'Dependency Audit',
    desc: 'Audits package manifests and lockfiles against CVEs & RustSec/OSV databases.',
    icon: Layers,
  },
  static_analysis: {
    label: 'Static Analysis',
    desc: 'Performs semantic AST matching, pattern scans, and taint flow tracking.',
    icon: FileCode,
  },
  source_discovery: {
    label: 'Source Discovery',
    desc: 'Maps project structure, entrypoints, and subsystem boundaries safely.',
    icon: Cpu,
  },
  patch_generation: {
    label: 'Patch Generation',
    desc: 'Synthesizes surgical source patches and remediation diffs with AI models.',
    icon: Sparkles,
  },
  fuzz_execution: {
    label: 'Fuzz Execution',
    desc: 'Coverage-guided dynamic fuzzing against compiled boundaries.',
    icon: Activity,
  },
}

export function PluginsTab({ currentWorkspace, currentRole }: PluginsTabProps) {
  const [plugins, setPlugins] = useState<DiscoveredPluginView[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [familyFilter, setFamilyFilter] = useState('ALL')
  const [probeResults, setProbeResults] = useState<Record<string, { loading: boolean; result?: PluginProbeResult; error?: string }>>({})

  // Execution modal state
  const [activeRunPlugin, setActiveRunPlugin] = useState<DiscoveredPluginView | null>(null)
  const [selectedCapability, setSelectedCapability] = useState<string>('')
  const [runArgs, setRunArgs] = useState<string>('')
  const [isExecuting, setIsExecuting] = useState(false)
  const [execResult, setExecResult] = useState<PluginExecutionResult | null>(null)

  // Fetch registered plugins
  async function fetchPlugins() {
    setIsLoading(true)
    try {
      const list = await fetchDiscoveredPlugins()
      setPlugins(list)
    } catch (err: any) {
      console.error('Failed to load plugins:', err)
      toast.error('Failed to load plugins', {
        description: 'Ensure Sentra web API bridge is running (bun run --cwd web dev).',
      })
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchPlugins()
  }, [])

  // Probe a single plugin
  async function handleProbe(plugin: DiscoveredPluginView) {
    setProbeResults((prev) => ({
      ...prev,
      [plugin.id]: { loading: true },
    }))

    try {
      const data = await probePluginAdapter(plugin.id, currentWorkspace)
      if (!data) throw new Error('No probe response from adapter')
      setProbeResults((prev) => ({
        ...prev,
        [plugin.id]: { loading: false, result: data },
      }))

      if (data.applicable) {
        toast.success(`Probe Successful: ${plugin.name}`, {
          description: data.details || 'Adapter is ready and applicable for the current workspace.',
        })
      } else {
        toast.warning(`Adapter Not Applicable: ${plugin.name}`, {
          description: data.details || data.unsupported_reason || 'Adapter reported workspace mismatch.',
        })
      }
    } catch (err: any) {
      setProbeResults((prev) => ({
        ...prev,
        [plugin.id]: { loading: false, error: err.message },
      }))
      toast.error(`Probe Failed: ${plugin.name}`, {
        description: err.message,
      })
    }
  }

  // Open Run Modal
  function openRunModal(plugin: DiscoveredPluginView) {
    setActiveRunPlugin(plugin)
    setSelectedCapability(plugin.capabilities[0] || '')
    setRunArgs('')
    setExecResult(null)
  }

  // Execute Capability
  async function handleExecuteRun() {
    if (!activeRunPlugin || !selectedCapability) return
    if (currentRole === 'Viewer') {
      toast.error('Permission Denied', {
        description: 'Viewers are not authorized to trigger adapter execution.',
      })
      return
    }

    setIsExecuting(true)
    setExecResult(null)

    try {
      const parsedArgs = runArgs
        .trim()
        .split(' ')
        .map((s) => s.trim())
        .filter(Boolean)

      const data = await runPluginCapability(
        activeRunPlugin.id,
        selectedCapability,
        currentWorkspace,
        parsedArgs
      )

      if (!data) throw new Error('No execution output from adapter subprocess')
      setExecResult(data)

      if (data.exit_code === 0) {
        toast.success(`Execution Successful: ${activeRunPlugin.name}`, {
          description: data.summary || `Capability [${selectedCapability}] completed cleanly.`,
        })
      } else {
        toast.error(`Execution Finished with Exit Code ${data.exit_code}`, {
          description: data.summary || (data as any).error || 'Subprocess exited with non-zero status.',
        })
      }
    } catch (err: any) {
      toast.error('Execution Failed', {
        description: err.message,
      })
      setExecResult({
        action: 'run',
        plugin_id: activeRunPlugin.id,
        capability: selectedCapability,
        exit_code: -1,
        summary: err.message,
      })
    } finally {
      setIsExecuting(false)
    }
  }

  // Filtered plugins
  const filteredPlugins = useMemo(() => {
    const q = search.trim().toLowerCase()
    return plugins.filter((p) => {
      const matchQuery =
        !q ||
        p.id.toLowerCase().includes(q) ||
        p.name.toLowerCase().includes(q) ||
        (p.executable_path && p.executable_path.toLowerCase().includes(q)) ||
        p.capabilities.some((c) => c.toLowerCase().includes(q))

      const matchFamily = familyFilter === 'ALL' || p.family === familyFilter
      return matchQuery && matchFamily
    })
  }, [plugins, search, familyFilter])

  // Count unique capabilities
  const totalCapabilities = useMemo(() => {
    const caps = new Set<string>()
    for (const p of plugins) {
      for (const c of p.capabilities) {
        caps.add(c)
      }
    }
    return caps.size
  }, [plugins])

  return (
    <div className="space-y-6">
      {/* Hero / Header Section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-xl border border-border/60 bg-gradient-to-r from-card/80 via-card/50 to-primary/5 backdrop-blur-md">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <Blocks className="size-5" />
            </div>
            <h1 className="text-xl font-bold tracking-tight text-foreground">
              Plugin & Tool Adapter Ecosystem
            </h1>
            <Badge variant="outline" className="border-primary/30 text-primary bg-primary/10 font-mono text-xs">
              ADR-0004
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground max-w-2xl">
            Supervised process-isolated security tools, SAST engines, SCA analyzers, and AI inference providers governed by strict quota bounds and JSON-delimited stdio contracts.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchPlugins}
            disabled={isLoading}
            className="gap-2 border-border/80"
          >
            <RefreshCw className={`size-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>

          <a
            href="https://github.com/Taiizor/Sentra/blob/develop/docs/PLUGINS_GUIDE.md"
            target="_blank"
            rel="noreferrer"
          >
            <Button variant="default" size="sm" className="gap-2">
              <ExternalLink className="size-3.5" />
              Adapter SDK Guide
            </Button>
          </a>
        </div>
      </div>

      {/* Key Metric HUD Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-card/60 border-border/50">
          <CardContent className="p-4 flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
                Discovered Plugins
              </p>
              <p className="text-2xl font-bold text-foreground font-mono">{plugins.length}</p>
            </div>
            <div className="p-3 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Blocks className="size-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/60 border-border/50">
          <CardContent className="p-4 flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
                Active Capabilities
              </p>
              <p className="text-2xl font-bold text-emerald-400 font-mono">{totalCapabilities}</p>
            </div>
            <div className="p-3 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Sparkles className="size-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/60 border-border/50">
          <CardContent className="p-4 flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
                Process Isolation
              </p>
              <p className="text-base font-semibold text-purple-400">Out-of-Process</p>
              <p className="text-[11px] text-muted-foreground">Zero in-process binary load</p>
            </div>
            <div className="p-3 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
              <ShieldCheck className="size-5" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-card/60 border-border/50">
          <CardContent className="p-4 flex items-center justify-between">
            <div className="space-y-1">
              <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
                Network Governance
              </p>
              <p className="text-base font-semibold text-amber-400">Strictly Enforced</p>
              <p className="text-[11px] text-muted-foreground">Bell-LaPadula Egress Policy</p>
            </div>
            <div className="p-3 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <ShieldAlert className="size-5" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
          <Input
            placeholder="Search plugins, capabilities, commands..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9 h-9 bg-card/60 border-border/60"
          />
        </div>

        <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto pb-1 sm:pb-0">
          {['ALL', 'analysis_tool', 'ai_provider', 'language_framework'].map((fam) => (
            <Button
              key={fam}
              variant={familyFilter === fam ? 'default' : 'outline'}
              size="sm"
              onClick={() => setFamilyFilter(fam)}
              className="text-xs h-8 capitalize border-border/70"
            >
              {fam === 'ALL' ? 'All Families' : fam.replace('_', ' ')}
            </Button>
          ))}
        </div>
      </div>

      {/* Plugin Cards Grid */}
      {isLoading ? (
        <div className="flex flex-col items-center justify-center p-12 text-center border border-dashed border-border/60 rounded-xl bg-card/20">
          <RefreshCw className="size-8 text-primary animate-spin mb-3" />
          <p className="text-sm font-medium text-foreground">Discovering registered adapters...</p>
          <p className="text-xs text-muted-foreground">Inspecting manifests in workspace and adapter search paths</p>
        </div>
      ) : filteredPlugins.length === 0 ? (
        <div className="flex flex-col items-center justify-center p-12 text-center border border-dashed border-border/60 rounded-xl bg-card/20">
          <Blocks className="size-10 text-muted-foreground mb-3 opacity-50" />
          <p className="text-sm font-semibold text-foreground">No matching plugins found</p>
          <p className="text-xs text-muted-foreground max-w-sm mt-1">
            Place adapter manifests inside <code className="text-primary font-mono">examples/adapters/</code> or configure search directories.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filteredPlugins.map((plugin) => {
            const fam = FAMILY_LABELS[plugin.family] || {
              label: plugin.family,
              color: 'bg-muted text-muted-foreground border-border',
            }
            const probeState = probeResults[plugin.id]
            const isEgressDenied = plugin.egress_policy.toLowerCase().includes('denied')

            return (
              <Card
                key={plugin.id}
                className="bg-card/70 border-border/70 hover:border-primary/40 transition-colors flex flex-col justify-between"
              >
                <CardHeader className="p-5 pb-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <CardTitle className="text-base font-semibold text-foreground">
                          {plugin.name}
                        </CardTitle>
                        <Badge variant="outline" className={`text-[10px] uppercase font-mono tracking-wider ${fam.color}`}>
                          {fam.label}
                        </Badge>
                        <Badge variant="outline" className="text-[10px] font-mono text-muted-foreground border-border">
                          v{plugin.version}
                        </Badge>
                      </div>
                      <CardDescription className="text-xs font-mono text-muted-foreground truncate max-w-md">
                        {plugin.id}
                      </CardDescription>
                    </div>

                    <div className="shrink-0">
                      <Badge
                        variant="outline"
                        className={`text-xs gap-1 font-mono ${
                          isEgressDenied
                            ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                            : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        }`}
                      >
                        {isEgressDenied ? <ShieldAlert className="size-3" /> : <ShieldCheck className="size-3" />}
                        {plugin.egress_policy}
                      </Badge>
                    </div>
                  </div>
                </CardHeader>

                <CardContent className="p-5 pt-0 space-y-4">
                  {/* Subprocess Execution Details */}
                  <div className="p-2.5 rounded-lg bg-muted/40 border border-border/40 space-y-1.5 font-mono text-xs">
                    <div className="flex items-center justify-between text-muted-foreground">
                      <span className="flex items-center gap-1.5">
                        <Terminal className="size-3.5 text-primary" />
                        Entrypoint:
                      </span>
                      <span className="text-foreground font-semibold">
                        {plugin.executable_path || 'Standard subprocess runner'}
                      </span>
                    </div>

                    {plugin.quotas && (
                      <div className="flex items-center justify-between text-[11px] text-muted-foreground pt-1 border-t border-border/30">
                        <span className="flex items-center gap-1">
                          <HardDrive className="size-3 text-muted-foreground" />
                          Memory Quota: <strong className="text-foreground">{plugin.quotas.max_memory_mib} MiB</strong>
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="size-3 text-muted-foreground" />
                          Timeout: <strong className="text-foreground">{plugin.quotas.max_execution_time_secs}s</strong>
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Declared Capabilities */}
                  <div className="space-y-1.5">
                    <p className="text-xs text-muted-foreground font-medium">Declared Capabilities:</p>
                    <div className="flex flex-wrap gap-1.5">
                      {plugin.capabilities.map((cap) => {
                        const meta = CAPABILITY_INFO[cap]
                        const Icon = meta?.icon || Activity
                        return (
                          <div
                            key={cap}
                            className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-secondary/60 border border-border/50 text-xs text-foreground font-mono"
                            title={meta?.desc || cap}
                          >
                            <Icon className="size-3 text-primary" />
                            <span>{meta?.label || cap}</span>
                          </div>
                        )
                      })}
                    </div>
                  </div>

                  {/* Live Probe Feedback Banner */}
                  {probeState && (
                    <div
                      className={`p-3 rounded-lg border text-xs space-y-1 ${
                        probeState.loading
                          ? 'bg-muted/40 border-border text-muted-foreground'
                          : probeState.result?.applicable
                          ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                          : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                      }`}
                    >
                      <div className="flex items-center gap-1.5 font-semibold">
                        {probeState.loading ? (
                          <>
                            <RefreshCw className="size-3.5 animate-spin" />
                            <span>Running probe handshake with subprocess...</span>
                          </>
                        ) : probeState.result?.applicable ? (
                          <>
                            <CheckCircle2 className="size-3.5 text-emerald-400" />
                            <span>Probe Verified: Applicable for workspace</span>
                          </>
                        ) : (
                          <>
                            <AlertCircle className="size-3.5 text-amber-400" />
                            <span>Probe Notice: Not applicable</span>
                          </>
                        )}
                      </div>

                      {probeState.result && (
                        <p className="text-[11px] text-muted-foreground font-mono">
                          {probeState.result.details || probeState.result.unsupported_reason}
                        </p>
                      )}
                    </div>
                  )}

                  {/* Action Buttons */}
                  <div className="flex items-center justify-end gap-2 pt-2 border-t border-border/40">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleProbe(plugin)}
                      disabled={probeState?.loading}
                      className="gap-1.5 text-xs h-8 border-border/80"
                    >
                      <Activity className={`size-3.5 ${probeState?.loading ? 'animate-spin' : ''}`} />
                      Probe Health
                    </Button>

                    <Button
                      variant="default"
                      size="sm"
                      onClick={() => openRunModal(plugin)}
                      disabled={currentRole === 'Viewer'}
                      className="gap-1.5 text-xs h-8"
                    >
                      <Play className="size-3.5" />
                      Run Capability
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}

      {/* Interactive Execution Dialog */}
      <Dialog open={!!activeRunPlugin} onOpenChange={(open) => !open && setActiveRunPlugin(null)}>
        <DialogContent className="max-w-2xl bg-card border-border shadow-2xl">
          <DialogHeader>
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
                <Play className="size-4" />
              </div>
              <div>
                <DialogTitle className="text-base font-semibold">
                  Execute Adapter Capability
                </DialogTitle>
                <DialogDescription className="text-xs font-mono">
                  {activeRunPlugin?.name} ({activeRunPlugin?.id})
                </DialogDescription>
              </div>
            </div>
          </DialogHeader>

          {activeRunPlugin && (
            <div className="space-y-4 py-2">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-foreground">Select Capability:</label>
                  <Select
                    value={selectedCapability}
                    onValueChange={(val) => {
                      if (val) setSelectedCapability(val)
                    }}
                  >
                    <SelectTrigger className="w-full h-9 text-xs bg-secondary/60 border-border text-foreground font-mono">
                      <SelectValue placeholder="Select Capability">
                        {(val: string | null) => val || selectedCapability || 'Select Capability'}
                      </SelectValue>
                    </SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        {activeRunPlugin.capabilities.map((c) => (
                          <SelectItem key={c} value={c}>
                            {c}
                          </SelectItem>
                        ))}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-foreground">Target Workspace:</label>
                  <Input
                    value={currentWorkspace}
                    readOnly
                    className="h-9 bg-muted/40 font-mono text-xs text-muted-foreground border-border"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-foreground flex items-center justify-between">
                  <span>Custom Arguments (optional):</span>
                  <span className="text-[11px] text-muted-foreground font-normal">Space-separated flags</span>
                </label>
                <Input
                  placeholder="e.g. --all-projects --deep"
                  value={runArgs}
                  onChange={(e) => setRunArgs(e.target.value)}
                  className="h-9 font-mono text-xs bg-secondary/40 border-border"
                />
              </div>

              {/* Terminal Execution Output */}
              {execResult && (
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-foreground flex items-center gap-1.5">
                      <Terminal className="size-3.5 text-primary" />
                      Execution Output:
                    </span>
                    <Badge
                      variant="outline"
                      className={`text-[10px] font-mono ${
                        execResult.exit_code === 0
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                      }`}
                    >
                      Exit Code: {execResult.exit_code}
                    </Badge>
                  </div>

                  <ScrollArea className="h-48 rounded-lg bg-black/80 border border-border/80 p-3 font-mono text-xs text-emerald-400">
                    <pre className="whitespace-pre-wrap break-all leading-relaxed">
                      {JSON.stringify(execResult, null, 2)}
                    </pre>
                  </ScrollArea>

                  {execResult.evidence_refs && execResult.evidence_refs.length > 0 && (
                    <p className="text-[11px] text-muted-foreground font-mono">
                      Recorded Evidence Digests: {execResult.evidence_refs.join(', ')}
                    </p>
                  )}
                </div>
              )}
            </div>
          )}

          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setActiveRunPlugin(null)}
              disabled={isExecuting}
            >
              Close
            </Button>
            <Button
              variant="default"
              size="sm"
              onClick={handleExecuteRun}
              disabled={isExecuting || !selectedCapability}
              className="gap-2"
            >
              <Play className={`size-3.5 ${isExecuting ? 'animate-spin' : ''}`} />
              {isExecuting ? 'Executing in Sandbox...' : 'Run Capability'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
