import { useState, useEffect, useMemo } from 'react'
import {
  Brain,
  ShieldCheck,
  Play,
  RotateCw,
  Search,
  CheckCircle2,
  Clock,
  Layers,
  FileCheck2,
  Sparkles,
  ShieldAlert,
  Flame,
  Coins,
  X,
  FilterX,
  Code2,
  FolderGit2,
} from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Progress } from '@/components/ui/progress'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  fetchCoverageLedger,
  validateLedgerInvariants,
  setAuditProfile,
  runAuditCampaignWave,
  fetchReconTopology,
  runPhase1Reconnaissance,
} from '@/lib/api-client'
import type {
  CampaignLedgerView,
  CoverageLedgerReport,
  CoverageLedgerUnit,
  AuditProfile,
  LedgerStatus,
  ReconTopologyReport,
  Phase1ReconReport,
  UserRole,
} from '@/types/sentra'

interface ResearchTabProps {
  campaigns: CampaignLedgerView[]
  currentRole: UserRole
}

const STATUS_BADGES: Record<
  LedgerStatus,
  { label: string; variant: 'default' | 'secondary' | 'outline' | 'destructive'; color: string }
> = {
  covered: {
    label: 'Covered',
    variant: 'secondary',
    color: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  },
  candidate: {
    label: 'Candidate',
    variant: 'outline',
    color: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  },
  needs_validation: {
    label: 'Needs Validation',
    variant: 'outline',
    color: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  },
  planned: {
    label: 'Planned',
    variant: 'outline',
    color: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
  },
  deferred: {
    label: 'Deferred',
    variant: 'outline',
    color: 'bg-zinc-800 text-zinc-400 border-zinc-700',
  },
  blocked: {
    label: 'Blocked',
    variant: 'destructive',
    color: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
  },
  out_of_scope: {
    label: 'Out of Scope',
    variant: 'outline',
    color: 'bg-zinc-900 text-zinc-500 border-zinc-800',
  },
  not_applicable: {
    label: 'N/A',
    variant: 'outline',
    color: 'bg-zinc-900 text-zinc-500 border-zinc-800',
  },
  in_progress: {
    label: 'Hunting In Progress',
    variant: 'outline',
    color: 'bg-sky-500/15 text-sky-400 border-sky-500/30 animate-pulse',
  },
}

export function ResearchTab({ campaigns: _campaigns, currentRole }: ResearchTabProps) {
  const [report, setReport] = useState<CoverageLedgerReport | null>(null)
  const [_isLoading, setIsLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<'ALL' | LedgerStatus>('ALL')
  const [isValidating, setIsValidating] = useState(false)
  const [selectedUnit, setSelectedUnit] = useState<CoverageLedgerUnit | null>(null)

  // Sub-views: 4D Matrix, Fast Topology, Phase 1 Recon
  const [activeView, setActiveView] = useState<'matrix' | 'topology' | 'recon'>('matrix')
  const [topologyReport, setTopologyReport] = useState<ReconTopologyReport | null>(null)
  const [reconReport, setReconReport] = useState<Phase1ReconReport | null>(null)
  const [isRunningRecon, setIsRunningRecon] = useState(false)
  const [isLoadingTopology, setIsLoadingTopology] = useState(false)

  useEffect(() => {
    loadLedger()
    loadTopology()
  }, [])

  async function loadTopology() {
    setIsLoadingTopology(true)
    const data = await fetchReconTopology()
    if (data) setTopologyReport(data)
    setIsLoadingTopology(false)
  }

  async function handleRunPhase1Recon() {
    if (currentRole === 'Viewer') {
      toast.error('Action Denied: Viewer Role', {
        description: 'Viewer role is read-only. Switch to Operator or Admin to execute reconnaissance engines.',
      })
      return
    }
    setIsRunningRecon(true)
    try {
      const data = await runPhase1Reconnaissance()
      if (data) {
        setReconReport(data)
        toast.success('Phase 1 Reconnaissance Complete (4 Agents Finished)', {
          description: `Synthesized architecture boundary map with ${data.derivedUnitsCount} derived canonical units.`,
        })
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error'
      toast.error('Reconnaissance Error', { description: msg })
    } finally {
      setIsRunningRecon(false)
    }
  }

  async function loadLedger() {
    setIsLoading(true)
    const data = await fetchCoverageLedger()
    if (data) {
      setReport(data)
    }
    setIsLoading(false)
  }

  async function handleProfileChange(newProfile: AuditProfile) {
    if (currentRole === 'Viewer') {
      toast.error('Action Denied: Viewer Role', {
        description: 'Viewer role is read-only. Switch to Operator or Admin to change audit profiles.',
      })
      return
    }
    const success = await setAuditProfile(newProfile)
    if (success) {
      toast.success(`Audit Profile Switched: ${newProfile.toUpperCase()}`, {
        description:
          newProfile === 'quick'
            ? 'Coarsened ledger units with single-wave hunter and deferred critic.'
            : newProfile === 'deep'
              ? 'Multi-wave deep auditing with independent double-verifiers.'
              : 'Standard 6-phase defensive security audit workflow.',
      })
      loadLedger()
    }
  }

  async function handleValidateLedger() {
    setIsValidating(true)
    const result = await validateLedgerInvariants()
    setIsValidating(false)
    if (result && result.valid) {
      toast.success('Ledger Invariants Validated (100% Sound)', {
        description: `Verified ${result.checkedUnits} canonical units across 4 dimensions. Zero violations.`,
      })
    } else {
      toast.error('Ledger Validation Warning', {
        description: `Found ${result?.errorCount || 0} issue(s) in coverage transitions.`,
      })
    }
  }

  async function handleRunWave() {
    if (currentRole === 'Viewer') {
      toast.error('Action Denied: Viewer Role', {
        description: 'Viewer role is read-only. Switch to Operator or Admin to dispatch hunter waves.',
      })
      return
    }
    const res = await runAuditCampaignWave()
    if (res && res.success) {
      toast.success('Hunter Wave Dispatched', {
        description: res.message,
      })
      loadLedger()
    }
  }

  const filteredUnits = useMemo(() => {
    if (!report?.units) return []
    const q = searchTerm.trim().toLowerCase()
    return report.units.filter((u) => {
      const matchSearch =
        !q ||
        u.coverageId.toLowerCase().includes(q) ||
        u.attackClass.toLowerCase().includes(q) ||
        u.subsystem.toLowerCase().includes(q) ||
        u.surface.toLowerCase().includes(q)

      const matchStatus = statusFilter === 'ALL' || u.status === statusFilter
      return matchSearch && matchStatus
    })
  }, [report, searchTerm, statusFilter])

  const coveredPercent = report?.stats
    ? Math.round((report.stats.covered / Math.max(1, report.stats.totalUnits)) * 100)
    : 0

  return (
    <div className="flex flex-col gap-5">
      {/* Sleek Page Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-2 border-b border-border/40">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <Brain className="size-4 text-purple-400" />
            <h2 className="text-base font-semibold tracking-tight text-foreground">
              Autonomous Deep Research & Coverage Ledger
            </h2>
            <Badge variant="outline" className="text-[11px] px-2 py-0 border-purple-500/30 text-purple-400 bg-purple-500/5">
              Cloudflare 6-Phase
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            Deterministic 4D security audit matrix (<span className="font-mono text-foreground/80">Surface × Boundary × Subsystem × Attack Class</span>).
          </p>
        </div>

        {/* Profile Selector & Wave Controls */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {/* Profile Segmented Group */}
          <div className="flex items-center bg-card/80 border border-border/70 rounded-md p-0.5 text-xs">
            <span className="text-[11px] text-muted-foreground font-medium px-2 hidden sm:inline">Profile:</span>
            {(['quick', 'standard', 'deep'] as AuditProfile[]).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => handleProfileChange(p)}
                className={`px-2 py-0.5 rounded text-xs font-medium capitalize transition-colors ${
                  report?.profile === p
                    ? 'bg-primary text-primary-foreground shadow-xs font-semibold'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {p}
              </button>
            ))}
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={handleValidateLedger}
            disabled={isValidating}
            className="h-7 text-xs border-border/80 text-foreground hover:bg-accent font-medium gap-1.5"
          >
            <ShieldCheck className="size-3.5 text-primary" />
            <span>Validate Invariants</span>
          </Button>

          <Button
            size="sm"
            onClick={handleRunWave}
            disabled={currentRole === 'Viewer'}
            className="h-7 text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
          >
            <Play className="size-3" />
            <span>Dispatch Wave 3</span>
          </Button>
        </div>
      </div>

      {/* 3-Way Sub-Navigation Tabs */}
      <div className="flex items-center gap-1.5 bg-card/60 border border-border/60 rounded-lg p-1 w-fit">
        <button
          onClick={() => setActiveView('matrix')}
          className={`h-7 px-3 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 ${
            activeView === 'matrix'
              ? 'bg-primary text-primary-foreground shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent/60'
          }`}
        >
          <Layers className="size-3.5" />
          <span>4D Coverage Ledger</span>
          <span className={`text-[10px] px-1 rounded-full font-mono ${
            activeView === 'matrix' ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-muted text-muted-foreground'
          }`}>
            {report?.units.length || 0}
          </span>
        </button>

        <button
          onClick={() => {
            setActiveView('topology')
            loadTopology()
          }}
          className={`h-7 px-3 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 ${
            activeView === 'topology'
              ? 'bg-primary text-primary-foreground shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent/60'
          }`}
        >
          <FileCheck2 className="size-3.5" />
          <span>Fast Topology Map</span>
          <span className="text-[10px] px-1 rounded-full bg-sky-500/10 text-sky-400 font-mono">
            Zero-LLM
          </span>
        </button>

        <button
          onClick={() => setActiveView('recon')}
          className={`h-7 px-3 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 ${
            activeView === 'recon'
              ? 'bg-primary text-primary-foreground shadow-sm'
              : 'text-muted-foreground hover:text-foreground hover:bg-accent/60'
          }`}
        >
          <Sparkles className="size-3.5" />
          <span>Phase 1 Recon</span>
          <span className="text-[10px] px-1 rounded-full bg-amber-500/10 text-amber-400 font-mono">
            4-Agent
          </span>
        </button>
      </div>

      {/* ================================================================= */}
      {/* VIEW 1: FAST STATIC TOPOLOGY MAP (ZERO-LLM) */}
      {/* ================================================================= */}
      {activeView === 'topology' && (
        <div className="flex flex-col gap-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                <FileCheck2 className="size-3.5 text-sky-400" />
                Deterministic Workspace Static Topology (Zero-LLM Fast Mapper)
              </h3>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                Computed via pure-Rust AST directory traversal in &lt;100ms. Invariant baseline for hunting assignments.
              </p>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={loadTopology}
              disabled={isLoadingTopology}
              className="h-7 text-xs border-border/80 self-start sm:self-auto gap-1.5"
            >
              <RotateCw className={`size-3 ${isLoadingTopology ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </Button>
          </div>

          {/* Subsystems & Trust Boundaries */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {topologyReport?.subsystems.map((sub) => (
              <Card key={sub.name} className="border-border/60 bg-card/40 shadow-xs">
                <CardHeader className="p-3 pb-2">
                  <div className="flex items-center justify-between">
                    <Badge variant="outline" className="text-[10px] font-mono px-1.5 py-0">
                      {sub.language}
                    </Badge>
                    <Badge
                      variant={sub.trustLevel === 'untrusted_input' ? 'destructive' : 'secondary'}
                      className="text-[10px] font-mono uppercase px-1.5 py-0"
                    >
                      {sub.trustLevel.replace('_', ' ')}
                    </Badge>
                  </div>
                  <CardTitle className="text-xs font-bold font-mono text-foreground mt-2">
                    {sub.name}
                  </CardTitle>
                  <CardDescription className="text-[11px] font-mono text-muted-foreground truncate">
                    {sub.path}
                  </CardDescription>
                </CardHeader>
                <CardContent className="p-3 pt-0">
                  <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider block mb-1">
                    Source Controls:
                  </span>
                  <ul className="list-disc list-inside text-[11px] text-muted-foreground space-y-0.5">
                    {sub.controls.map((c, i) => (
                      <li key={i} className="truncate">{c}</li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Entrypoints Table */}
          <Card className="border-border/60 bg-card/40">
            <CardHeader className="py-2.5 px-4 border-b border-border/40">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-medium text-foreground">
                  Identified Entry Surfaces ({topologyReport?.entrypoints.length || 0})
                </CardTitle>
                <span className="text-[11px] font-mono text-muted-foreground">
                  Deterministic Static Inventory
                </span>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border/40 hover:bg-transparent">
                      <TableHead className="text-xs font-medium h-8">Type</TableHead>
                      <TableHead className="text-xs font-medium h-8">Surface</TableHead>
                      <TableHead className="text-xs font-medium h-8">Location</TableHead>
                      <TableHead className="text-xs font-medium h-8">Handler Scope</TableHead>
                      <TableHead className="text-xs font-medium h-8 text-right pr-4">Auth Required</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody className="text-xs font-mono">
                    {topologyReport?.entrypoints.map((ep, i) => (
                      <TableRow key={i} className="border-border/40 hover:bg-muted/30">
                        <TableCell className="py-2">
                          <Badge variant="outline" className="text-[10px] font-mono px-1.5 py-0">
                            {ep.type}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-foreground/90 py-2">{ep.surface}</TableCell>
                        <TableCell className="text-muted-foreground py-2">{ep.path}:{ep.line}</TableCell>
                        <TableCell className="text-sky-400 truncate max-w-[280px] py-2">{ep.handler}</TableCell>
                        <TableCell className="text-right py-2 pr-4">
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                            ep.authRequired
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                              : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          }`}>
                            {ep.authRequired ? 'ENFORCED' : 'UNAUTHENTICATED'}
                          </span>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>

          {/* Testability & Prohibited Actions */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-2">
              <span className="text-xs font-semibold text-foreground uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 className="size-3.5 text-emerald-400" />
                Validated Offline Test Commands
              </span>
              <ul className="space-y-1 text-xs font-mono text-emerald-400/90">
                {topologyReport?.offlineTestCommands.map((cmd, i) => (
                  <li key={i} className="bg-background/60 p-2 rounded border border-border/50">
                    $ {cmd}
                  </li>
                ))}
              </ul>
            </div>
            <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-2">
              <span className="text-xs font-semibold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldAlert className="size-3.5" />
                Permanently Prohibited Actions (Fail-Closed)
              </span>
              <ul className="space-y-1 text-xs text-muted-foreground">
                {topologyReport?.prohibitedActions.map((act, i) => (
                  <li key={i} className="bg-background/60 p-2 rounded border border-border/50 flex items-center gap-2">
                    <span className="text-rose-400 font-bold">✕</span> {act}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* ================================================================= */}
      {/* VIEW 2: 4-AGENT RECONNAISSANCE ENGINE */}
      {/* ================================================================= */}
      {activeView === 'recon' && (
        <div className="flex flex-col gap-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                <Sparkles className="size-3.5 text-amber-400" />
                Cloudflare Phase 1: 4-Agent Autonomous Reconnaissance Engine
              </h3>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                Spawns 4 specialized read-only research agents to build source-grounded trust boundaries and architecture map.
              </p>
            </div>
            <Button
              size="sm"
              onClick={handleRunPhase1Recon}
              disabled={isRunningRecon || currentRole === 'Viewer'}
              className="h-7 text-xs font-medium bg-amber-500 hover:bg-amber-600 text-zinc-950 gap-1.5 self-start sm:self-auto"
            >
              <Sparkles className={`size-3 ${isRunningRecon ? 'animate-spin' : ''}`} />
              <span>{isRunningRecon ? 'Reconnoitering...' : 'Run Phase 1 Recon'}</span>
            </Button>
          </div>

          {/* 4 Agent Output Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {(reconReport?.agents || [
              {
                agentId: '1a_product_stack' as const,
                agentName: 'Agent 1a: Product, Stack & Local Boundaries',
                summary: 'Maps tech stack, frameworks, offline build commands, and comparable open source software without network access.',
                findingsCount: 4,
                sourceRefs: ['crates/sentra-core/Cargo.toml', 'web/package.json'],
              },
              {
                agentId: '1b_principals_controls' as const,
                agentName: 'Agent 1b: Principals, Authority & Tenant Scopes',
                summary: 'Identifies every lower-trust principal, tenant scopes, role hierarchy, and source-visible authorization controls.',
                findingsCount: 6,
                sourceRefs: ['crates/sentra-core/src/tenant.rs', 'web/src/types/sentra.ts'],
              },
              {
                agentId: '1c_surfaces_sinks' as const,
                agentName: 'Agent 1c: Entry Surfaces & Critical Execution Sinks',
                summary: 'Inventories all entrypoints (HTTP, CLI, Webhook, MCP) and follows data transformations to dangerous execution sinks.',
                findingsCount: 11,
                sourceRefs: ['crates/sentra-cli/src/main.rs', 'agents/tools/bash_executor.py'],
              },
              {
                agentId: '1d_sandbox_testability' as const,
                agentName: 'Agent 1d: Sandbox Readiness & Offline Testability',
                summary: 'Validates loopback test isolation, scratch file promotion controls, and OS sandbox enforcement readiness.',
                findingsCount: 5,
                sourceRefs: ['crates/sentra-core/src/backend/fail_closed.rs'],
              },
            ]).map((agent) => (
              <div key={agent.agentId} className="p-3 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-amber-300 flex items-center gap-1.5">
                    <Brain className="size-3.5 text-amber-400" />
                    {agent.agentName}
                  </span>
                  <Badge variant="outline" className="text-[10px] font-mono border-amber-500/30 text-amber-300 px-1.5 py-0">
                    {agent.findingsCount} Facts Mapped
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  {agent.summary}
                </p>
                <div className="flex flex-wrap gap-1 mt-1">
                  {agent.sourceRefs.map((ref, idx) => (
                    <span key={idx} className="text-[10px] font-mono bg-background/60 border border-border/50 text-muted-foreground px-1.5 py-0.5 rounded">
                      {ref}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Synthesized Architecture Boundary Map */}
          {reconReport?.architectureSummaryMd && (
            <Card className="border-border/60 bg-card/40">
              <CardHeader className="py-2.5 px-4 border-b border-border/40 flex flex-row items-center justify-between">
                <div>
                  <CardTitle className="text-xs font-semibold text-foreground">
                    Synthesized Architecture Boundary Map (&lt;1,000 Words Cap)
                  </CardTitle>
                  <CardDescription className="text-[11px] font-mono text-muted-foreground">
                    Saved to .sentra/architecture-recon.md • Mapped to {reconReport.derivedUnitsCount} Canonical Ledger Units
                  </CardDescription>
                </div>
                <Badge variant="outline" className="text-[10px] font-mono text-emerald-400 border-emerald-500/30 bg-emerald-500/10">
                  RECON PHASE 1 COMPLETE
                </Badge>
              </CardHeader>
              <CardContent className="p-4 font-mono text-xs text-muted-foreground leading-relaxed overflow-x-auto whitespace-pre-wrap bg-background/40">
                {reconReport.architectureSummaryMd}
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* ================================================================= */}
      {/* VIEW 3: 4D COVERAGE LEDGER MATRIX */}
      {/* ================================================================= */}
      {activeView === 'matrix' && (
        <>
          {/* KPI Metrics Row */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {/* Total Ledger Units */}
            <Card className="border-border/60 bg-card/40 shadow-xs">
              <CardHeader className="p-3 pb-1 flex flex-row items-center justify-between">
                <CardTitle className="text-xs font-medium text-muted-foreground">Canonical Units</CardTitle>
                <Layers className="size-3.5 text-cyan-400" />
              </CardHeader>
              <CardContent className="p-3 pt-0">
                <div className="text-xl font-bold font-mono text-foreground">
                  {report?.stats.totalUnits || 0}
                </div>
                <p className="text-[10px] text-muted-foreground mt-0.5">
                  Deterministic 4D matrix cells
                </p>
              </CardContent>
            </Card>

            {/* Covered & Verified */}
            <Card className="border-border/60 bg-card/40 shadow-xs">
              <CardHeader className="p-3 pb-1 flex flex-row items-center justify-between">
                <CardTitle className="text-xs font-medium text-muted-foreground">Covered & Verified</CardTitle>
                <CheckCircle2 className="size-3.5 text-emerald-400" />
              </CardHeader>
              <CardContent className="p-3 pt-0">
                <div className="text-xl font-bold font-mono text-emerald-400">
                  {report?.stats.covered || 0}{' '}
                  <span className="text-xs text-muted-foreground font-normal">({coveredPercent}%)</span>
                </div>
                <Progress value={coveredPercent} className="h-1 mt-1.5 bg-muted" />
              </CardContent>
            </Card>

            {/* Candidates Under Verification */}
            <Card className="border-border/60 bg-card/40 shadow-xs">
              <CardHeader className="p-3 pb-1 flex flex-row items-center justify-between">
                <CardTitle className="text-xs font-medium text-muted-foreground">Phase 3 Candidates</CardTitle>
                <Flame className="size-3.5 text-amber-400" />
              </CardHeader>
              <CardContent className="p-3 pt-0">
                <div className="text-xl font-bold font-mono text-amber-400">
                  {report?.stats.candidate || 0}
                </div>
                <p className="text-[10px] text-muted-foreground mt-0.5">
                  Active violation claims
                </p>
              </CardContent>
            </Card>

            {/* Needs Validation Blockers */}
            <Card className="border-border/60 bg-card/40 shadow-xs">
              <CardHeader className="p-3 pb-1 flex flex-row items-center justify-between">
                <CardTitle className="text-xs font-medium text-muted-foreground">Validation Blockers</CardTitle>
                <Clock className="size-3.5 text-purple-400" />
              </CardHeader>
              <CardContent className="p-3 pt-0">
                <div className="text-xl font-bold font-mono text-purple-400">
                  {(report?.stats.needsValidation || 0) + (report?.stats.blocked || 0)}
                </div>
                <p className="text-[10px] text-muted-foreground mt-0.5">
                  Blocked on host observation
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Budget & Agent Reservation Bar */}
          {report?.budget && (
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-3 py-2 rounded-lg border border-border/60 bg-card/40 text-xs">
              <div className="flex items-center gap-2">
                <Coins className="size-3.5 text-amber-400 shrink-0" />
                <span className="font-medium text-foreground">
                  Budget Discipline: {report.budget.spentAgentCalls} / {report.budget.maxAgentCalls} Calls
                </span>
                <span className="text-[11px] text-muted-foreground hidden md:inline">
                  (Mandatory reserve protected before waves)
                </span>
              </div>

              <div className="flex items-center gap-3 text-[11px] font-mono text-muted-foreground">
                <span>
                  Critics: <strong className="text-cyan-400">{report.budget.reservedCritics}</strong>
                </span>
                <span>•</span>
                <span>
                  Verifiers: <strong className="text-emerald-400">{report.budget.reservedVerifiers}</strong>
                </span>
              </div>
            </div>
          )}

          {/* Unified Filter & Search Toolbar */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-card/60 border border-border/60 rounded-lg p-2.5">
            {/* Status Filter Tabs */}
            <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar">
              <button
                type="button"
                onClick={() => setStatusFilter('ALL')}
                className={`h-7 px-2.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 shrink-0 ${
                  statusFilter === 'ALL'
                    ? 'bg-primary text-primary-foreground shadow-sm'
                    : 'text-muted-foreground hover:text-foreground hover:bg-accent/60'
                }`}
              >
                <span>All</span>
                <span className={`text-[10px] px-1 py-0.2 rounded-full font-mono ${
                  statusFilter === 'ALL' ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-muted text-muted-foreground'
                }`}>
                  {report?.units.length || 0}
                </span>
              </button>
              {(['covered', 'candidate', 'needs_validation', 'planned'] as LedgerStatus[]).map((st) => {
                const count = report?.units.filter((u) => u.status === st).length || 0
                const isActive = statusFilter === st
                return (
                  <button
                    key={st}
                    type="button"
                    onClick={() => setStatusFilter(st)}
                    className={`h-7 px-2.5 text-xs font-medium rounded-md transition-all flex items-center gap-1.5 shrink-0 ${
                      isActive
                        ? 'bg-primary text-primary-foreground shadow-sm'
                        : 'text-muted-foreground hover:text-foreground hover:bg-accent/60'
                    }`}
                  >
                    <span>{STATUS_BADGES[st].label}</span>
                    <span className={`text-[10px] px-1 py-0.2 rounded-full font-mono ${
                      isActive ? 'bg-primary-foreground/20 text-primary-foreground' : 'bg-muted text-muted-foreground'
                    }`}>
                      {count}
                    </span>
                  </button>
                )
              })}
            </div>

            {/* Search Input */}
            <div className="relative w-full md:w-72 shrink-0">
              <Search className="size-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
              <Input
                placeholder="Search coverage ID, subsystem..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-8 pr-7 h-7 text-xs bg-background/50 border-border/60 focus-visible:ring-1"
              />
              {searchTerm && (
                <button
                  onClick={() => setSearchTerm('')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground p-0.5 rounded"
                >
                  <X className="size-3" />
                </button>
              )}
            </div>
          </div>

          {/* 4D Coverage Ledger Matrix Table Card */}
          <Card className="border-border/60 bg-card/40">
            <CardHeader className="py-2.5 px-4 border-b border-border/40">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Layers className="size-3.5 text-muted-foreground" />
                  <CardTitle className="text-xs font-medium text-foreground">
                    Canonical 4D Cells
                  </CardTitle>
                  <span className="text-[11px] text-muted-foreground">
                    ({filteredUnits.length} of {report?.units.length || 0})
                  </span>
                </div>
                <span className="text-[11px] text-muted-foreground hidden sm:inline">
                  Click any row to inspect cell invariant
                </span>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {filteredUnits.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
                  <FilterX className="size-8 text-muted-foreground/50 mb-3" />
                  <p className="text-xs font-medium text-foreground">No matching coverage cells</p>
                  <p className="text-[11px] text-muted-foreground mt-1 max-w-sm">
                    No cells matched your query. Adjust search or status filter.
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-4 h-7 text-xs"
                    onClick={() => {
                      setSearchTerm('')
                      setStatusFilter('ALL')
                    }}
                  >
                    Reset Filters
                  </Button>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-border/40 hover:bg-transparent">
                        <TableHead className="text-xs font-medium h-9 pl-4">Coverage Unit ID (4D)</TableHead>
                        <TableHead className="text-xs font-medium h-9">Attack Class</TableHead>
                        <TableHead className="text-xs font-medium h-9">Subsystem</TableHead>
                        <TableHead className="text-xs font-medium h-9">Status</TableHead>
                        <TableHead className="text-xs font-medium h-9">Wave & Agent</TableHead>
                        <TableHead className="text-xs font-medium h-9">Paths</TableHead>
                        <TableHead className="text-xs font-medium h-9 text-right pr-4">Findings</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody className="text-xs font-mono">
                      {filteredUnits.map((unit) => {
                        const badgeInfo = STATUS_BADGES[unit.status] || STATUS_BADGES.planned
                        return (
                          <TableRow
                            key={unit.coverageId}
                            onClick={() => setSelectedUnit(unit)}
                            className="border-border/40 hover:bg-muted/30 cursor-pointer transition-colors"
                          >
                            {/* Canonical Coverage ID */}
                            <TableCell className="font-semibold text-foreground pl-4 py-2.5">
                              <div className="flex items-center gap-1.5">
                                <span className="size-1.5 rounded-full bg-primary shrink-0" />
                                <span className="truncate max-w-[280px]" title={unit.coverageId}>
                                  {unit.coverageId}
                                </span>
                              </div>
                            </TableCell>

                            {/* Attack Class */}
                            <TableCell className="py-2.5">
                              <Badge variant="outline" className="text-[10px] font-sans px-1.5 py-0">
                                {unit.attackClass}
                              </Badge>
                            </TableCell>

                            {/* Subsystem */}
                            <TableCell className="text-muted-foreground py-2.5">
                              {unit.subsystem}
                            </TableCell>

                            {/* Status Badge */}
                            <TableCell className="py-2.5">
                              <span className={`inline-flex items-center px-1.5 py-0.2 rounded text-[10px] font-bold border ${badgeInfo.color}`}>
                                {badgeInfo.label}
                              </span>
                            </TableCell>

                            {/* Wave & Hunter Agent */}
                            <TableCell className="text-muted-foreground py-2.5">
                              {unit.wave > 0 ? (
                                <span>
                                  W{unit.wave} {unit.agentId && <span className="text-muted-foreground/70">({unit.agentId})</span>}
                                </span>
                              ) : (
                                <span className="text-muted-foreground/50">—</span>
                              )}
                            </TableCell>

                            {/* Reviewed Paths */}
                            <TableCell className="text-muted-foreground py-2.5">
                              {unit.reviewedPaths?.length > 0 ? (
                                <span>{unit.reviewedPaths.length} path(s)</span>
                              ) : (
                                <span className="text-muted-foreground/50">0</span>
                              )}
                            </TableCell>

                            {/* Result Fingerprints */}
                            <TableCell className="text-right pr-4 font-bold py-2.5">
                              {unit.resultFingerprints?.length > 0 ? (
                                <span className="text-emerald-400">
                                  {unit.resultFingerprints.length} finding(s)
                                </span>
                              ) : (
                                <span className="text-muted-foreground/50">—</span>
                              )}
                            </TableCell>
                          </TableRow>
                        )
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}

      {/* Selected Unit Inspection Dialog */}
      <Dialog open={!!selectedUnit} onOpenChange={(open) => !open && setSelectedUnit(null)}>
        <DialogContent className="sm:max-w-xl bg-card border-border/80">
          <DialogHeader>
            <div className="flex items-center gap-2">
              <Layers className="size-4 text-primary" />
              <DialogTitle className="text-sm font-semibold font-mono text-foreground">
                {selectedUnit?.coverageId}
              </DialogTitle>
            </div>
            <DialogDescription className="text-xs text-muted-foreground">
              4D Matrix canonical coordinate specification and hunting invariants.
            </DialogDescription>
          </DialogHeader>

          {selectedUnit && (
            <div className="flex flex-col gap-3 py-2 text-xs">
              <div className="grid grid-cols-2 gap-2 p-3 rounded-lg border border-border/60 bg-muted/20">
                <div>
                  <span className="text-[10px] text-muted-foreground font-semibold uppercase">Attack Class</span>
                  <p className="font-medium text-foreground mt-0.5">{selectedUnit.attackClass}</p>
                </div>
                <div>
                  <span className="text-[10px] text-muted-foreground font-semibold uppercase">Subsystem</span>
                  <p className="font-mono text-foreground mt-0.5">{selectedUnit.subsystem}</p>
                </div>
                <div>
                  <span className="text-[10px] text-muted-foreground font-semibold uppercase">Surface</span>
                  <p className="font-mono text-foreground mt-0.5">{selectedUnit.surface}</p>
                </div>
                <div>
                  <span className="text-[10px] text-muted-foreground font-semibold uppercase">Status</span>
                  <p className="mt-0.5">
                    <span className={`inline-flex items-center px-1.5 py-0.2 rounded text-[10px] font-bold border ${STATUS_BADGES[selectedUnit.status]?.color}`}>
                      {STATUS_BADGES[selectedUnit.status]?.label}
                    </span>
                  </p>
                </div>
              </div>

              <div>
                <span className="text-[10px] text-muted-foreground font-semibold uppercase block mb-1.5">
                  Reviewed Paths ({selectedUnit.reviewedPaths?.length || 0}):
                </span>
                {selectedUnit.reviewedPaths?.length > 0 ? (
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {selectedUnit.reviewedPaths.map((p, i) => (
                      <div key={i} className="flex items-center gap-2 font-mono text-[11px] p-1.5 rounded bg-background/60 border border-border/50 text-foreground">
                        <FolderGit2 className="size-3 text-muted-foreground" />
                        <span className="truncate">{p}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-muted-foreground text-[11px] italic">No paths reviewed yet for this unit.</p>
                )}
              </div>

              {selectedUnit.resultFingerprints?.length > 0 && (
                <div>
                  <span className="text-[10px] text-muted-foreground font-semibold uppercase block mb-1.5">
                    Result Fingerprints ({selectedUnit.resultFingerprints.length}):
                  </span>
                  <div className="space-y-1">
                    {selectedUnit.resultFingerprints.map((fp, i) => (
                      <div key={i} className="flex items-center gap-2 font-mono text-[11px] p-1.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                        <Code2 className="size-3" />
                        <span className="truncate">{fp}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
