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
} from '@/lib/api-client'
import type {
  CampaignLedgerView,
  CoverageLedgerReport,
  CoverageLedgerUnit,
  AuditProfile,
  LedgerStatus,
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

  useEffect(() => {
    loadLedger()
  }, [])

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
    </div>
  )
}
