import { useState, useEffect, useMemo } from 'react'
import {
  Brain,
  ShieldCheck,
  AlertTriangle,
  Coins,
  Play,
  RotateCw,
  Search,
  CheckCircle2,
  Clock,
  ExternalLink,
  Layers,
  FileCheck2,
  Filter,
  Sparkles,
  ChevronRight,
  ShieldAlert,
  Flame,
} from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Progress } from '@/components/ui/progress'
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
} from '@/types/sentra'

interface ResearchTabProps {
  campaigns: CampaignLedgerView[]
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

export function ResearchTab({ campaigns }: ResearchTabProps) {
  const [report, setReport] = useState<CoverageLedgerReport | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<'ALL' | LedgerStatus>('ALL')
  const [isValidating, setIsValidating] = useState(false)
  const [selectedUnit, setSelectedUnit] = useState<CoverageLedgerUnit | null>(null)
  
  // Phase 1 Reconnaissance and Topology States
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
    setIsRunningRecon(true)
    try {
      const data = await runPhase1Reconnaissance()
      if (data) {
        setReconReport(data)
        toast.success('Phase 1 Reconnaissance Complete (4 Agents Finished)', {
          description: `Synthesized architecture boundary map with ${data.derivedUnitsCount} derived canonical units.`,
        })
      }
    } catch (err: any) {
      toast.error('Reconnaissance Error', { description: err.message })
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
    const success = await setAuditProfile(newProfile)
    if (success) {
      toast.success(`Audit Run Profile Switched to ${newProfile.toUpperCase()}`, {
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
      toast.success('Coverage Ledger Invariants Validated (100% Sound)', {
        description: `Verified ${result.checkedUnits} canonical units across 4 dimensions. Zero schema or transition violations.`,
      })
    } else {
      toast.error('Ledger Validation Warning', {
        description: `Found ${result?.errorCount || 0} issue(s) in coverage transitions.`,
      })
    }
  }

  async function handleRunWave() {
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
    return report.units.filter((u) => {
      const matchSearch =
        u.coverageId.toLowerCase().includes(searchTerm.toLowerCase()) ||
        u.attackClass.toLowerCase().includes(searchTerm.toLowerCase()) ||
        u.subsystem.toLowerCase().includes(searchTerm.toLowerCase()) ||
        u.surface.toLowerCase().includes(searchTerm.toLowerCase())

      const matchStatus = statusFilter === 'ALL' || u.status === statusFilter
      return matchSearch && matchStatus
    })
  }, [report, searchTerm, statusFilter])

  const coveredPercent = report?.stats
    ? Math.round((report.stats.covered / Math.max(1, report.stats.totalUnits)) * 100)
    : 0

  return (
    <div className="flex flex-col gap-6">
      {/* Cloudflare Audit Specification Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-800 pb-5">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <div className="size-8 rounded-lg bg-primary/10 border border-primary/20 text-primary flex items-center justify-center font-bold">
              <Brain className="size-4" />
            </div>
            <h2 className="text-lg font-bold text-zinc-100 flex items-center gap-2">
              Autonomous Deep Research &amp; Coverage Ledger
            </h2>
            <Badge variant="outline" className="font-mono text-xs border-primary/30 text-primary">
              Cloudflare 6-Phase Standard
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            Deterministic 4-dimensional security audit matrix (<code className="font-mono">Surface × Boundary × Subsystem × Attack Class</code>).
            Zero false claims: untracked areas remain planned; no single pass implies full safety.
          </p>
        </div>

        {/* Profile Selector & Wave Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Run Profile Group */}
          <div className="flex items-center p-1 rounded-lg border border-zinc-800 bg-zinc-950 text-xs">
            <span className="text-[11px] text-zinc-400 font-semibold px-2">Profile:</span>
            {(['quick', 'standard', 'deep'] as AuditProfile[]).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => handleProfileChange(p)}
                className={`px-2.5 py-1 rounded-md text-xs font-semibold capitalize transition-colors ${
                  report?.profile === p
                    ? 'bg-zinc-800 text-zinc-100 font-bold shadow-xs'
                    : 'text-zinc-400 hover:text-zinc-200'
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
            className="h-8 text-xs border-primary/40 text-primary bg-primary/5 hover:bg-primary/15 font-semibold"
          >
            <ShieldCheck className="size-3.5 mr-1.5" />
            Validate Invariants
          </Button>

          <Button
            size="sm"
            onClick={handleRunWave}
            className="h-8 text-xs font-semibold bg-primary text-primary-foreground hover:bg-primary/90"
          >
            <Play className="size-3 mr-1.5" />
            Dispatch Wave 3
          </Button>
        </div>
      </div>

      {/* 3-Way Sub-Navigation: Matrix, Fast Topology, Phase 1 Recon */}
      <div className="flex flex-wrap items-center gap-2 border-b border-zinc-800 pb-3">
        <Button
          variant={activeView === 'matrix' ? 'default' : 'outline'}
          size="sm"
          className="h-8 text-xs font-semibold rounded-lg"
          onClick={() => setActiveView('matrix')}
        >
          <Layers className="size-3.5 mr-1.5" />
          4D Coverage Ledger ({report?.units.length || 0})
        </Button>
        <Button
          variant={activeView === 'topology' ? 'default' : 'outline'}
          size="sm"
          className="h-8 text-xs font-semibold rounded-lg border-zinc-750"
          onClick={() => {
            setActiveView('topology')
            loadTopology()
          }}
        >
          <FileCheck2 className="size-3.5 mr-1.5 text-sky-400" />
          Fast Topology Map (LLM-Free)
        </Button>
        <Button
          variant={activeView === 'recon' ? 'default' : 'outline'}
          size="sm"
          className="h-8 text-xs font-semibold rounded-lg border-amber-500/40 text-amber-300 hover:bg-amber-500/10"
          onClick={() => setActiveView('recon')}
        >
          <Sparkles className="size-3.5 mr-1.5 text-amber-400" />
          Phase 1: 4-Agent Recon (LLM-Assisted)
        </Button>
      </div>

      {/* ================================================================= */}
      {/* VIEW 1: LLM-FREE FAST TOPOLOGY MAP */}
      {/* ================================================================= */}
      {activeView === 'topology' && (
        <div className="flex flex-col gap-5">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-zinc-100 flex items-center gap-2">
                <FileCheck2 className="size-4 text-sky-400" />
                Deterministic Workspace Static Topology (Zero-LLM Fast Mapper)
              </h3>
              <p className="text-xs text-zinc-400 mt-0.5">
                Computed via pure-Rust AST directory traversal in &lt;100ms. Invariant baseline for hunting assignments.
              </p>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={loadTopology}
              disabled={isLoadingTopology}
              className="h-7 text-xs border-zinc-800 bg-zinc-900"
            >
              <RotateCw className={`size-3 mr-1 ${isLoadingTopology ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          {/* Subsystems & Trust Boundaries */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3.5">
            {topologyReport?.subsystems.map((sub) => (
              <Card key={sub.name} className="border-zinc-800 bg-zinc-950/70 shadow-sm">
                <CardHeader className="pb-2 pt-3 px-4">
                  <div className="flex items-center justify-between">
                    <Badge variant="outline" className="text-[10px] font-mono">
                      {sub.language}
                    </Badge>
                    <Badge
                      variant={sub.trustLevel === 'untrusted_input' ? 'destructive' : 'secondary'}
                      className="text-[10px] font-mono uppercase"
                    >
                      {sub.trustLevel.replace('_', ' ')}
                    </Badge>
                  </div>
                  <CardTitle className="text-xs font-bold font-mono text-zinc-200 mt-2">
                    {sub.name}
                  </CardTitle>
                  <CardDescription className="text-[11px] font-mono text-zinc-400">
                    {sub.path}
                  </CardDescription>
                </CardHeader>
                <CardContent className="px-4 pb-3">
                  <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider block mb-1">
                    Source Controls:
                  </span>
                  <ul className="list-disc list-inside text-[11px] text-zinc-300 space-y-0.5">
                    {sub.controls.map((c, i) => (
                      <li key={i} className="truncate">{c}</li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Entrypoints Table */}
          <Card className="border-zinc-800 bg-zinc-950/60 shadow-md">
            <CardHeader className="py-3 px-5 border-b border-zinc-800">
              <CardTitle className="text-xs font-semibold text-zinc-200 flex items-center justify-between">
                <span>Identified Entry Surfaces &amp; Execution Gates ({topologyReport?.entrypoints.length || 0})</span>
                <span className="text-[11px] font-mono text-zinc-400 font-normal">Deterministic Static Inventory</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader className="bg-zinc-900/60 text-xs">
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead className="text-zinc-400">Type</TableHead>
                    <TableHead className="text-zinc-400">Surface</TableHead>
                    <TableHead className="text-zinc-400">Location</TableHead>
                    <TableHead className="text-zinc-400">Handler Scope</TableHead>
                    <TableHead className="text-zinc-400 text-right">Auth Required</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody className="text-xs font-mono">
                  {topologyReport?.entrypoints.map((ep, i) => (
                    <TableRow key={i} className="hover:bg-zinc-900/40 border-zinc-800/60">
                      <TableCell>
                        <Badge variant="outline" className="text-[10px] font-mono">
                          {ep.type}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-zinc-300">{ep.surface}</TableCell>
                      <TableCell className="text-zinc-400">{ep.path}:{ep.line}</TableCell>
                      <TableCell className="text-primary truncate max-w-[280px]">{ep.handler}</TableCell>
                      <TableCell className="text-right">
                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${ep.authRequired ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'}`}>
                          {ep.authRequired ? 'ENFORCED' : 'UNAUTHENTICATED'}
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* Testability & Prohibited Actions */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/40 flex flex-col gap-2">
              <span className="text-xs font-bold text-zinc-300 uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 className="size-3.5 text-emerald-400" />
                Validated Offline Test Commands
              </span>
              <ul className="space-y-1 text-xs font-mono text-emerald-300/90">
                {topologyReport?.offlineTestCommands.map((cmd, i) => (
                  <li key={i} className="bg-zinc-950 p-2 rounded border border-zinc-800/80">
                    $ {cmd}
                  </li>
                ))}
              </ul>
            </div>
            <div className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/40 flex flex-col gap-2">
              <span className="text-xs font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldAlert className="size-3.5" />
                Permanently Prohibited Actions (Fail-Closed)
              </span>
              <ul className="space-y-1 text-xs text-zinc-400">
                {topologyReport?.prohibitedActions.map((act, i) => (
                  <li key={i} className="bg-zinc-950 p-2 rounded border border-zinc-800/80 flex items-center gap-2">
                    <span className="text-rose-400 font-bold">✕</span> {act}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* ================================================================= */}
      {/* VIEW 2: LLM-ASSISTED PHASE 1 RECONNAISSANCE ENGINE */}
      {/* ================================================================= */}
      {activeView === 'recon' && (
        <div className="flex flex-col gap-5">
          <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-zinc-100 flex items-center gap-2">
                <Sparkles className="size-4 text-amber-400" />
                Cloudflare Phase 1: 4-Agent Autonomous Reconnaissance Engine
              </h3>
              <p className="text-xs text-zinc-400 mt-0.5">
                Spawns 4 specialized read-only research agents to build source-grounded trust boundaries and architecture map.
              </p>
            </div>
            <Button
              size="sm"
              onClick={handleRunPhase1Recon}
              disabled={isRunningRecon}
              className="h-8 text-xs font-semibold bg-amber-500 hover:bg-amber-600 text-zinc-950 shadow-md"
            >
              <Sparkles className={`size-3.5 mr-1.5 ${isRunningRecon ? 'animate-spin' : ''}`} />
              {isRunningRecon ? '4 Agents Reconnoitering...' : 'Run Phase 1 Recon'}
            </Button>
          </div>

          {/* 4 Agent Output Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
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
              <div key={agent.agentId} className="p-4 rounded-xl border border-zinc-800 bg-zinc-950/80 shadow-sm flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-amber-300 flex items-center gap-1.5">
                    <Brain className="size-3.5 text-amber-400" />
                    {agent.agentName}
                  </span>
                  <Badge variant="outline" className="text-[10px] font-mono border-amber-500/30 text-amber-300">
                    {agent.findingsCount} Facts Mapped
                  </Badge>
                </div>
                <p className="text-xs text-zinc-300 leading-relaxed">
                  {agent.summary}
                </p>
                <div className="flex flex-wrap gap-1 mt-1">
                  {agent.sourceRefs.map((ref, idx) => (
                    <span key={idx} className="text-[10px] font-mono bg-zinc-900 border border-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded">
                      {ref}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Synthesized Architecture Boundary Map */}
          {reconReport?.architectureSummaryMd && (
            <Card className="border-zinc-800 bg-zinc-950/80 shadow-md">
              <CardHeader className="py-3 px-5 border-b border-zinc-800 flex flex-row items-center justify-between">
                <div>
                  <CardTitle className="text-xs font-bold text-zinc-200">
                    Synthesized Architecture Boundary Map (&lt;1,000 Words Cap)
                  </CardTitle>
                  <CardDescription className="text-[11px] font-mono text-zinc-400">
                    Saved to docs/architecture-recon.md • Mapped to {reconReport.derivedUnitsCount} Canonical Ledger Units
                  </CardDescription>
                </div>
                <Badge variant="outline" className="text-[10px] font-mono text-emerald-400 border-emerald-500/30 bg-emerald-500/10">
                  RECON PHASE 1 COMPLETE
                </Badge>
              </CardHeader>
              <CardContent className="p-5 font-mono text-xs text-zinc-300 leading-relaxed overflow-x-auto whitespace-pre-wrap bg-zinc-900/50">
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
          {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Ledger Units */}
        <Card className="border-zinc-800 bg-zinc-950/60 shadow-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-zinc-400">Total Canonical Units</CardTitle>
            <Layers className="size-4 text-cyan-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono text-zinc-100">
              {report?.stats.totalUnits || 0}
            </div>
            <p className="text-[11px] text-zinc-400 mt-1">
              Deterministic 4D matrix cells mapped
            </p>
          </CardContent>
        </Card>

        {/* Covered & Verified */}
        <Card className="border-zinc-800 bg-zinc-950/60 shadow-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-zinc-400">Covered &amp; Verified</CardTitle>
            <CheckCircle2 className="size-4 text-emerald-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono text-emerald-400">
              {report?.stats.covered || 0}{' '}
              <span className="text-xs text-zinc-400 font-normal">({coveredPercent}%)</span>
            </div>
            <Progress value={coveredPercent} className="h-1.5 mt-2 bg-zinc-800" />
          </CardContent>
        </Card>

        {/* Candidates Under Verification */}
        <Card className="border-zinc-800 bg-zinc-950/60 shadow-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-zinc-400">Candidates (Phase 3)</CardTitle>
            <Flame className="size-4 text-amber-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono text-amber-400">
              {report?.stats.candidate || 0}
            </div>
            <p className="text-[11px] text-zinc-400 mt-1">
              Active boundary violation claims
            </p>
          </CardContent>
        </Card>

        {/* Needs Validation Blockers */}
        <Card className="border-zinc-800 bg-zinc-950/60 shadow-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-zinc-400">Needs Validation / Blocked</CardTitle>
            <Clock className="size-4 text-purple-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono text-purple-400">
              {(report?.stats.needsValidation || 0) + (report?.stats.blocked || 0)}
            </div>
            <p className="text-[11px] text-zinc-400 mt-1">
              Blocked on runtime or host observation
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Budget & Agent Reservation Bar */}
      {report?.budget && (
        <Card className="border-zinc-800/80 bg-zinc-900/30 shadow-xs">
          <CardContent className="p-4 flex flex-wrap items-center justify-between gap-4 text-xs">
            <div className="flex items-center gap-3">
              <Coins className="size-4 text-amber-400" />
              <div className="flex flex-col">
                <span className="font-semibold text-zinc-200">
                  Agent Call Budget Discipline ({report.budget.spentAgentCalls} / {report.budget.maxAgentCalls} Calls)
                </span>
                <span className="text-[11px] text-zinc-400">
                  Mandatory reserve protected before hunting waves: never scaled away.
                </span>
              </div>
            </div>

            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="text-zinc-400">
                Reserved Critics:{' '}
                <span className="text-cyan-400 font-bold">{report.budget.reservedCritics} Calls</span>
              </span>
              <span>•</span>
              <span className="text-zinc-400">
                Reserved Verifiers:{' '}
                <span className="text-emerald-400 font-bold">{report.budget.reservedVerifiers} Calls</span>
              </span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* 4D Coverage Ledger Matrix Table */}
      <Card className="border-zinc-800 bg-zinc-950/60 shadow-lg overflow-hidden">
        <CardHeader className="px-6 py-4 border-b border-zinc-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="relative w-64">
              <Search className="size-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
              <Input
                placeholder="Search coverage ID, subsystem..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="h-8 pl-8 text-xs bg-zinc-900 border-zinc-800 text-zinc-100 placeholder:text-zinc-500"
              />
            </div>

            {/* Status Filter Badges */}
            <div className="flex items-center gap-1 overflow-x-auto text-xs">
              <button
                type="button"
                onClick={() => setStatusFilter('ALL')}
                className={`px-2 py-1 rounded text-[11px] font-semibold transition-colors ${
                  statusFilter === 'ALL'
                    ? 'bg-zinc-800 text-zinc-100'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                All ({report?.units.length || 0})
              </button>
              {(['covered', 'candidate', 'needs_validation', 'planned'] as LedgerStatus[]).map((st) => (
                <button
                  key={st}
                  type="button"
                  onClick={() => setStatusFilter(st)}
                  className={`px-2 py-1 rounded text-[11px] font-semibold transition-colors ${
                    statusFilter === st
                      ? 'bg-zinc-800 text-zinc-100 font-bold'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  {STATUS_BADGES[st].label} (
                  {report?.units.filter((u) => u.status === st).length || 0})
                </button>
              ))}
            </div>
          </div>

          <span className="text-xs text-zinc-400 font-mono">
            Showing <span className="font-bold text-zinc-200">{filteredUnits.length}</span> of{' '}
            {report?.units.length || 0} Units
          </span>
        </CardHeader>

        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader className="bg-zinc-900/60 text-xs">
                <TableRow className="border-zinc-800/80 hover:bg-transparent">
                  <TableHead className="font-semibold text-zinc-400 pl-6">Coverage Unit ID (4D)</TableHead>
                  <TableHead className="font-semibold text-zinc-400">Attack Class</TableHead>
                  <TableHead className="font-semibold text-zinc-400">Subsystem</TableHead>
                  <TableHead className="font-semibold text-zinc-400">Status</TableHead>
                  <TableHead className="font-semibold text-zinc-400">Wave &amp; Agent</TableHead>
                  <TableHead className="font-semibold text-zinc-400">Reviewed Paths</TableHead>
                  <TableHead className="text-right font-semibold text-zinc-400 pr-6">Findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody className="text-xs divide-y divide-zinc-800/60 font-mono">
                {filteredUnits.map((unit) => {
                  const badgeInfo = STATUS_BADGES[unit.status] || STATUS_BADGES.planned
                  return (
                    <TableRow
                      key={unit.coverageId}
                      onClick={() => setSelectedUnit(unit)}
                      className="hover:bg-zinc-900/50 cursor-pointer transition-colors"
                    >
                      {/* Canonical Coverage ID */}
                      <TableCell className="font-bold text-zinc-200 pl-6">
                        <div className="flex items-center gap-2">
                          <span className="text-primary">•</span>
                          <span className="truncate max-w-[280px]">{unit.coverageId}</span>
                        </div>
                      </TableCell>

                      {/* Attack Class */}
                      <TableCell>
                        <Badge variant="outline" className="text-[11px] border-zinc-700 bg-zinc-900 text-zinc-300 font-sans">
                          {unit.attackClass}
                        </Badge>
                      </TableCell>

                      {/* Subsystem */}
                      <TableCell className="text-zinc-400">
                        {unit.subsystem}
                      </TableCell>

                      {/* Status Badge */}
                      <TableCell>
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold border ${badgeInfo.color}`}
                        >
                          {badgeInfo.label}
                        </span>
                      </TableCell>

                      {/* Wave & Hunter Agent */}
                      <TableCell className="text-zinc-400">
                        {unit.wave > 0 ? (
                          <span>
                            Wave {unit.wave} {unit.agentId && <span className="text-zinc-500">({unit.agentId})</span>}
                          </span>
                        ) : (
                          <span className="text-zinc-600">—</span>
                        )}
                      </TableCell>

                      {/* Reviewed Paths */}
                      <TableCell className="text-zinc-400">
                        {unit.reviewedPaths?.length > 0 ? (
                          <span>{unit.reviewedPaths.length} path(s)</span>
                        ) : (
                          <span className="text-zinc-600">0</span>
                        )}
                      </TableCell>

                      {/* Result Fingerprints */}
                      <TableCell className="text-right pr-6 font-bold">
                        {unit.resultFingerprints?.length > 0 ? (
                          <span className="text-emerald-400">
                            {unit.resultFingerprints.length} finding(s)
                          </span>
                        ) : (
                          <span className="text-zinc-600">—</span>
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
      </>
      )}
    </div>
  )
}
