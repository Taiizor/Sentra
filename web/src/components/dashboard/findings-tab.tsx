import { useState, useEffect, useMemo } from 'react'
import { cn } from 'cn'
import {
  GitBranch,
  ShieldCheck,
  Search,
  ChevronRight,
  Eye,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Copy,
  Check,
  Download,
  ChevronLeft,
  CheckCircle2,
  HelpCircle,
  XCircle,
  Layers,
  Code2,
  FileCode2,
  Sparkles,
  ChevronDown,
} from 'lucide-react'
import { toast } from 'sonner'
import { copyText } from '@/lib/clipboard'
import { validateFindingsInvariants } from '@/lib/api-client'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { SourceViewer } from '@/components/dashboard/source-viewer'
import { SurgicalDiffView } from '@/components/dashboard/surgical-diff-view'
import { MarkdownView, InlineFormattedText } from '@/components/ui/markdown-view'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty'
import type { FindingView, Severity, Reachability, UserRole, FindingVerdict } from '@/types/sentra'

interface FindingsTabProps {
  findings: FindingView[]
  currentRole: UserRole
  onProposePatch: (findingId: string) => void
  onOpenAiPatchModal: (finding: FindingView) => void
  selectedFindingId?: string | null
  onSelectFindingId?: (id: string | null) => void
}

type SortField = 'severity' | 'ruleId' | 'title' | 'targetLocation' | 'reachability' | 'verdict'
type SortDir = 'asc' | 'desc'

const SEVERITY_WEIGHT: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Informational: 0,
}

export function FindingsTab({
  findings,
  currentRole,
  onProposePatch: _onProposePatch,
  onOpenAiPatchModal,
  selectedFindingId,
  onSelectFindingId,
}: FindingsTabProps) {
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('ALL')
  const [reachabilityFilter, setReachabilityFilter] = useState<string>('ALL')
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL')
  const [selectedFinding, setSelectedFinding] = useState<FindingView | null>(() => {
    if (selectedFindingId) {
      return findings.find((f) => f.findingId === selectedFindingId) || null
    }
    return null
  })
  const [copiedPath, setCopiedPath] = useState<string | null>(null)
  const [isValidatingSchema, setIsValidatingSchema] = useState(false)

  // Synchronize deep-linked finding ID with selectedFinding state
  useEffect(() => {
    if (selectedFindingId) {
      const match = findings.find((f) => f.findingId === selectedFindingId)
      if (match && selectedFinding?.findingId !== match.findingId) {
        setSelectedFinding(match)
      }
    } else if (selectedFinding !== null && selectedFindingId === null) {
      setSelectedFinding(null)
    }
  }, [selectedFindingId, findings, selectedFinding])

  function handleSelectFinding(f: FindingView | null) {
    setSelectedFinding(f)
    onSelectFindingId?.(f ? f.findingId : null)
  }

  // Pagination & Sorting state
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(15)
  const [sortField, setSortField] = useState<SortField>('severity')
  const [sortDir, setSortDir] = useState<SortDir>('desc')

  // Calculate quick count metrics
  const counts = useMemo(() => {
    return {
      all: findings.length,
      critical: findings.filter((f) => f.severity === 'Critical').length,
      high: findings.filter((f) => f.severity === 'High').length,
      medium: findings.filter((f) => f.severity === 'Medium').length,
      reachable: findings.filter((f) => f.reachability === 'ReachableCallPath').length,
      confirmed: findings.filter((f) => f.verdict === 'confirmed' || (!f.verdict && f.status !== 'Rejected')).length,
      needsValidation: findings.filter((f) => f.verdict === 'needs_validation').length,
      rejected: findings.filter((f) => f.verdict === 'rejected' || f.status === 'Rejected').length,
    }
  }, [findings])

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const matchesSearch =
        f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.ruleId.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.targetLocation.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.cwe.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (f.fingerprint && f.fingerprint.toLowerCase().includes(searchTerm.toLowerCase()))

      const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter
      const matchesReachability = reachabilityFilter === 'ALL' || f.reachability === reachabilityFilter
      
      const effectiveVerdict = f.verdict ?? (f.status === 'Rejected' ? 'rejected' : 'confirmed')
      const matchesVerdict = verdictFilter === 'ALL' || effectiveVerdict === verdictFilter

      return matchesSearch && matchesSeverity && matchesReachability && matchesVerdict
    })
  }, [findings, searchTerm, severityFilter, reachabilityFilter, verdictFilter])

  const sortedFindings = useMemo(() => {
    const list = [...filteredFindings]
    list.sort((a, b) => {
      let cmp = 0
      if (sortField === 'severity') {
        cmp = (SEVERITY_WEIGHT[a.severity] || 0) - (SEVERITY_WEIGHT[b.severity] || 0)
      } else if (sortField === 'ruleId') {
        cmp = a.ruleId.localeCompare(b.ruleId)
      } else if (sortField === 'title') {
        cmp = a.title.localeCompare(b.title)
      } else if (sortField === 'targetLocation') {
        cmp = a.targetLocation.localeCompare(b.targetLocation)
      } else if (sortField === 'reachability') {
        cmp = a.reachability.localeCompare(b.reachability)
      } else if (sortField === 'verdict') {
        const vA = a.verdict ?? (a.status === 'Rejected' ? 'rejected' : 'confirmed')
        const vB = b.verdict ?? (b.status === 'Rejected' ? 'rejected' : 'confirmed')
        cmp = vA.localeCompare(vB)
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
    return list
  }, [filteredFindings, sortField, sortDir])

  // Paginated findings slice
  const totalPages = Math.max(1, Math.ceil(sortedFindings.length / pageSize))
  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * pageSize
    return sortedFindings.slice(start, start + pageSize)
  }, [sortedFindings, currentPage, pageSize])

  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortDir((prev) => (prev === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDir('desc')
    }
    setCurrentPage(1)
  }

  function handleCopyPath(path: string, e: React.MouseEvent) {
    e.stopPropagation()
    copyText(path)
    setCopiedPath(path)
    toast.success('Path copied to clipboard', {
      description: path,
    })
    setTimeout(() => setCopiedPath(null), 2000)
  }

  function handleExportCsv() {
    const header = 'Verdict,Severity,Rule,CWE,Title,File,Line,Reachability,Status\n'
    const rows = sortedFindings
      .map(
        (f) =>
          `"${f.verdict || (f.status === 'Rejected' ? 'rejected' : 'confirmed')}","${f.severity}","${f.ruleId}","${f.cwe}","${f.title.replace(/"/g, '""')}","${f.targetLocation}",${f.startLine},"${f.reachability}","${f.status}"`
      )
      .join('\n')
    const blob = new Blob([header + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `sentra-findings-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
    toast.success('CSV Export Ready', {
      description: `Downloaded ${sortedFindings.length} findings as CSV with Cloudflare Three-Verdict classifications.`,
    })
  }

  function handleExportJson() {
    const jsonStr = JSON.stringify(sortedFindings, null, 2)
    const blob = new Blob([jsonStr], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `sentra-findings-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
    toast.success('JSON Export Ready', {
      description: `Downloaded ${sortedFindings.length} findings as JSON (OASIS SARIF / Cloudflare audit format).`,
    })
  }

  async function handleValidateSchema() {
    setIsValidatingSchema(true)
    try {
      const res = await validateFindingsInvariants(findings)
      if (res && res.invariantsPass) {
        toast.success('Cloudflare Schema Invariants Pass', {
          description: `All ${res.totalFindings} findings strictly comply with Cloudflare Three-Verdict criteria and source-grounding.`,
        })
      } else if (res && !res.invariantsPass) {
        toast.error('Schema Invariants Failed', {
          description: `Found ${res.errors.length} error(s). First: ${res.errors[0]}`,
        })
      } else {
        toast.info('Validation Offline', {
          description: 'Web API bridge is unreachable. Displaying cached verified findings.',
        })
      }
    } catch (err: any) {
      toast.error('Validation Error', { description: err.message })
    } finally {
      setIsValidatingSchema(false)
    }
  }

  function getVerdictBadge(verdict?: FindingVerdict, status?: string) {
    const effectiveVerdict = verdict ?? (status === 'Rejected' ? 'rejected' : 'confirmed')
    switch (effectiveVerdict) {
      case 'confirmed':
        return (
          <Badge variant="destructive" className="text-[10px] font-mono font-bold flex items-center gap-1 bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <CheckCircle2 className="size-3" />
            CONFIRMED
          </Badge>
        )
      case 'needs_validation':
        return (
          <Badge variant="outline" className="text-[10px] font-mono font-bold flex items-center gap-1 bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <HelpCircle className="size-3" />
            NEEDS VALIDATION
          </Badge>
        )
      case 'rejected':
        return (
          <Badge variant="secondary" className="text-[10px] font-mono font-bold flex items-center gap-1 bg-zinc-800 text-zinc-400 border border-zinc-700">
            <XCircle className="size-3" />
            REJECTED
          </Badge>
        )
    }
  }

  function getSeverityBadgeVariant(severity: Severity) {
    switch (severity) {
      case 'Critical':
        return 'destructive'
      case 'High':
        return 'secondary'
      case 'Medium':
        return 'outline'
      default:
        return 'outline'
    }
  }

  function getReachabilityBadge(reachability: Reachability) {
    switch (reachability) {
      case 'ReachableCallPath':
        return (
          <Badge variant="destructive" className="text-[11px] flex items-center gap-1 font-mono font-bold">
            <GitBranch className="size-3" />
            Reachable Flow
          </Badge>
        )
      case 'SinkOnly':
        return (
          <Badge variant="outline" className="text-[11px] font-mono text-zinc-400">
            Sink Only
          </Badge>
        )
      case 'Unreachable':
        return (
          <Badge variant="secondary" className="text-[11px] font-mono">
            Unreachable
          </Badge>
        )
      default:
        return (
          <Badge variant="outline" className="text-[11px] font-mono">
            Inconclusive
          </Badge>
        )
    }
  }

  function renderSortIcon(field: SortField) {
    if (sortField !== field) {
      return <ArrowUpDown className="size-3 text-zinc-500 opacity-60 ml-1 inline-block" />
    }
    return sortDir === 'asc' ? (
      <ArrowUp className="size-3 text-primary ml-1 inline-block" />
    ) : (
      <ArrowDown className="size-3 text-primary ml-1 inline-block" />
    )
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Top Controls: Verdict Tabs & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Left: Verdict Filter Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar py-0.5 max-w-full">
          <Button
            variant={verdictFilter === 'ALL' ? 'default' : 'outline'}
            size="sm"
            className={`h-7.5 text-xs rounded-lg px-3 shrink-0 ${
              verdictFilter === 'ALL'
                ? 'font-bold shadow-xs'
                : 'bg-zinc-950/70 border-zinc-800 text-zinc-400 hover:text-zinc-200'
            }`}
            onClick={() => {
              setVerdictFilter('ALL')
              setCurrentPage(1)
            }}
          >
            All ({counts.all})
          </Button>

          <Button
            variant={verdictFilter === 'confirmed' ? 'destructive' : 'outline'}
            size="sm"
            className={`h-7.5 text-xs rounded-lg px-3 shrink-0 ${
              verdictFilter === 'confirmed'
                ? 'font-bold shadow-xs'
                : 'border-rose-500/30 hover:border-rose-500/60 bg-rose-500/10 text-rose-300'
            }`}
            onClick={() => {
              setVerdictFilter(verdictFilter === 'confirmed' ? 'ALL' : 'confirmed')
              setCurrentPage(1)
            }}
          >
            <CheckCircle2 className="size-3 mr-1.5 text-rose-400" />
            Confirmed ({counts.confirmed})
          </Button>

          <Button
            variant={verdictFilter === 'needs_validation' ? 'secondary' : 'outline'}
            size="sm"
            className={`h-7.5 text-xs rounded-lg px-3 shrink-0 ${
              verdictFilter === 'needs_validation'
                ? 'font-bold shadow-xs'
                : 'border-amber-500/30 hover:border-amber-500/60 bg-amber-500/10 text-amber-300'
            }`}
            onClick={() => {
              setVerdictFilter(verdictFilter === 'needs_validation' ? 'ALL' : 'needs_validation')
              setCurrentPage(1)
            }}
          >
            <HelpCircle className="size-3 mr-1.5 text-amber-400" />
            Needs Validation ({counts.needsValidation})
          </Button>

          <Button
            variant={verdictFilter === 'rejected' ? 'secondary' : 'outline'}
            size="sm"
            className={`h-7.5 text-xs rounded-lg px-3 shrink-0 ${
              verdictFilter === 'rejected'
                ? 'font-bold shadow-xs'
                : 'border-zinc-800 hover:border-zinc-700 bg-zinc-900/60 text-zinc-400'
            }`}
            onClick={() => {
              setVerdictFilter(verdictFilter === 'rejected' ? 'ALL' : 'rejected')
              setCurrentPage(1)
            }}
          >
            <XCircle className="size-3 mr-1.5 text-zinc-400" />
            Rejected ({counts.rejected})
          </Button>
        </div>

        {/* Right: Validate Schema & Consolidated Export */}
        <div className="flex items-center gap-1.5 shrink-0 self-end sm:self-auto">
          <Button
            variant="outline"
            size="sm"
            className="h-7.5 text-xs border-zinc-800 bg-zinc-900/60 text-primary hover:bg-primary/10 px-2.5 cursor-pointer"
            onClick={handleValidateSchema}
            disabled={isValidatingSchema}
          >
            <ShieldCheck className="size-3.5 mr-1" />
            {isValidatingSchema ? 'Validating...' : 'Validate Schema'}
          </Button>

          <DropdownMenu>
            <DropdownMenuTrigger
              className="inline-flex items-center justify-center h-7.5 text-xs font-medium rounded-md border border-zinc-800 bg-zinc-900/60 hover:bg-zinc-800 text-zinc-300 px-2.5 gap-1.5 cursor-pointer transition-colors outline-none"
              title="Export findings as CSV or JSON"
            >
              <Download className="size-3.5" />
              <span>Export</span>
              <ChevronDown className="size-3 text-zinc-400" />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48 bg-zinc-950 border border-zinc-800 p-1.5 text-zinc-200">
              <DropdownMenuItem onClick={handleExportCsv} className="cursor-pointer text-xs flex items-center gap-2 py-1.5">
                <Download className="size-3.5 text-primary" />
                <span>Export as CSV</span>
              </DropdownMenuItem>
              <DropdownMenuItem onClick={handleExportJson} className="cursor-pointer text-xs flex items-center gap-2 py-1.5">
                <FileCode2 className="size-3.5 text-cyan-400" />
                <span>Export as JSON (SARIF)</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Unified Search & Filter Toolbar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-2.5 p-2 sm:px-3 sm:py-2 rounded-xl border border-zinc-800/80 bg-zinc-900/40 shadow-xs">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[200px] max-w-[420px]">
          <Search className="size-3.5 absolute left-2.5 top-2 text-zinc-400" />
          <Input
            placeholder="Search rule ID, CWE, path, or title..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value)
              setCurrentPage(1)
            }}
            className="pl-8 h-7.5 text-xs bg-zinc-950/70 border-zinc-800 text-zinc-100 placeholder:text-zinc-500 focus-visible:ring-primary/30"
          />
        </div>

        {/* Severity, Reachability & Quick Severity Chips */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Severity Dropdown */}
          <Select
            value={severityFilter}
            onValueChange={(val) => {
              setSeverityFilter(val ?? 'ALL')
              setCurrentPage(1)
            }}
          >
            <SelectTrigger className="w-[125px] h-7.5 text-xs bg-zinc-950/80 border-zinc-800 text-zinc-200">
              <SelectValue placeholder="Severity">
                {(val: string | null) => (val === 'ALL' || !val ? 'All Severities' : val)}
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="ALL">All Severities</SelectItem>
                <SelectItem value="Critical">Critical</SelectItem>
                <SelectItem value="High">High</SelectItem>
                <SelectItem value="Medium">Medium</SelectItem>
                <SelectItem value="Low">Low</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>

          {/* Reachability Dropdown */}
          <Select
            value={reachabilityFilter}
            onValueChange={(val) => {
              setReachabilityFilter(val ?? 'ALL')
              setCurrentPage(1)
            }}
          >
            <SelectTrigger className="w-[145px] h-7.5 text-xs bg-zinc-950/80 border-zinc-800 text-zinc-200">
              <SelectValue placeholder="Reachability">
                {(val: string | null) => {
                  if (val === 'ALL' || !val) return 'All Reachability'
                  if (val === 'ReachableCallPath') return 'Reachable Flow'
                  if (val === 'SinkOnly') return 'Sink Only'
                  if (val === 'Unreachable') return 'Unreachable'
                  return val
                }}
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="ALL">All Reachability</SelectItem>
                <SelectItem value="ReachableCallPath">Reachable Flow</SelectItem>
                <SelectItem value="SinkOnly">Sink Only</SelectItem>
                <SelectItem value="Unreachable">Unreachable</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>

          {/* Quick Active Filter Badges */}
          {(severityFilter !== 'ALL' || reachabilityFilter !== 'ALL' || searchTerm.trim()) && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setSeverityFilter('ALL')
                setReachabilityFilter('ALL')
                setSearchTerm('')
                setCurrentPage(1)
              }}
              className="h-7 text-[11px] text-zinc-400 hover:text-zinc-200 px-2"
            >
              Reset Filters
            </Button>
          )}
        </div>
      </div>

      {/* Findings Table Card */}
      <Card className="border-zinc-800/80 bg-zinc-900/40 shadow-xs">
        <CardHeader className="py-2.5 px-4 border-b border-zinc-800/80 bg-zinc-950/40">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <CardTitle className="text-xs font-semibold text-zinc-200">
                Security Findings
              </CardTitle>
              <Badge variant="outline" className="text-[10px] font-mono border-zinc-800 text-zinc-400">
                {sortedFindings.length} Items
              </Badge>
            </div>

            {/* Page Size Selector */}
            <div className="flex items-center gap-2 text-xs text-zinc-400">
              <span className="text-[11px]">Rows:</span>
              <Select
                value={pageSize.toString()}
                onValueChange={(val) => {
                  setPageSize(Number(val) || 15)
                  setCurrentPage(1)
                }}
              >
                <SelectTrigger className="w-[65px] h-7 text-xs bg-zinc-950/80 border-zinc-800">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="5">5</SelectItem>
                    <SelectItem value="10">10</SelectItem>
                    <SelectItem value="15">15</SelectItem>
                    <SelectItem value="25">25</SelectItem>
                    <SelectItem value="50">50</SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {sortedFindings.length === 0 ? (
            <Empty className="py-12">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <ShieldCheck className="size-8 text-primary" />
                </EmptyMedia>
                <EmptyTitle>No Findings Match Active Filters</EmptyTitle>
                <EmptyDescription>
                  Try clearing your search query or clicking &apos;All&apos; in the filter chips above.
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader className="bg-zinc-950/40">
                  <TableRow className="border-zinc-800/80 hover:bg-transparent">
                    <TableHead
                      className="text-xs cursor-pointer select-none text-zinc-300 font-semibold w-[130px]"
                      onClick={() => handleSort('verdict')}
                    >
                      Verdict {renderSortIcon('verdict')}
                    </TableHead>
                    <TableHead
                      className="text-xs cursor-pointer select-none text-zinc-300 font-semibold w-[110px]"
                      onClick={() => handleSort('severity')}
                    >
                      Severity {renderSortIcon('severity')}
                    </TableHead>
                    <TableHead
                      className="text-xs cursor-pointer select-none text-zinc-300 font-semibold w-[160px]"
                      onClick={() => handleSort('ruleId')}
                    >
                      Rule &amp; CWE {renderSortIcon('ruleId')}
                    </TableHead>
                    <TableHead
                      className="text-xs cursor-pointer select-none text-zinc-300 font-semibold"
                      onClick={() => handleSort('title')}
                    >
                      Vulnerability Title {renderSortIcon('title')}
                    </TableHead>
                    <TableHead
                      className="text-xs cursor-pointer select-none text-zinc-300 font-semibold w-[260px]"
                      onClick={() => handleSort('targetLocation')}
                    >
                      Target Location {renderSortIcon('targetLocation')}
                    </TableHead>
                    <TableHead
                      className="text-xs cursor-pointer select-none text-zinc-300 font-semibold w-[140px]"
                      onClick={() => handleSort('reachability')}
                    >
                      Reachability {renderSortIcon('reachability')}
                    </TableHead>
                    <TableHead className="text-xs text-zinc-300 font-semibold w-[90px]">Status</TableHead>
                    <TableHead className="text-xs text-right text-zinc-300 font-semibold w-[100px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {paginatedFindings.map((finding) => (
                    <TableRow
                      key={finding.findingId}
                      className="cursor-pointer hover:bg-zinc-800/40 border-zinc-800/70 transition-colors group"
                      onClick={() => handleSelectFinding(finding)}
                    >
                      <TableCell>
                        {getVerdictBadge(finding.verdict, finding.status)}
                      </TableCell>
                      <TableCell>
                        <Badge variant={getSeverityBadgeVariant(finding.severity)} className="text-[11px] font-bold">
                          {finding.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        <div className="flex flex-col">
                          <span className="font-bold text-zinc-200">{finding.ruleId}</span>
                          <span className="text-[11px] text-zinc-400 font-normal">{finding.cwe}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs font-medium max-w-[280px] text-zinc-100">
                        <div className="truncate group-hover:text-primary transition-colors">{finding.title}</div>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-zinc-400">
                        <div className="flex items-center gap-1.5 group/loc">
                          <span className="truncate max-w-[220px]" title={`${finding.targetLocation}:${finding.startLine}`}>
                            {finding.targetLocation}:{finding.startLine}
                          </span>
                          <button
                            type="button"
                            className="opacity-0 group-hover/loc:opacity-100 transition-opacity p-0.5 hover:text-zinc-100 text-zinc-400"
                            onClick={(e) => handleCopyPath(`${finding.targetLocation}:${finding.startLine}`, e)}
                            title="Copy path to clipboard"
                          >
                            {copiedPath === `${finding.targetLocation}:${finding.startLine}` ? (
                              <Check className="size-3 text-emerald-400" />
                            ) : (
                              <Copy className="size-3" />
                            )}
                          </button>
                        </div>
                      </TableCell>
                      <TableCell>{getReachabilityBadge(finding.reachability)}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[11px] font-mono text-zinc-400 border-zinc-700">
                          {finding.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-7 text-xs px-2 border-primary/30 bg-primary/10 text-primary hover:bg-primary/20"
                            onClick={(e) => {
                              e.stopPropagation()
                              onOpenAiPatchModal(finding)
                            }}
                          >
                            <Sparkles className="size-3 mr-1" />
                            AI Patch
                          </Button>

                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 text-xs px-2 text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800"
                            onClick={(e) => {
                              e.stopPropagation()
                              handleSelectFinding(finding)
                            }}
                          >
                            <Eye className="size-3.5 mr-1" />
                            Inspect
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}

          {/* Pagination Navigation Footer */}
          {sortedFindings.length > 0 && (
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 px-4 sm:px-5 py-3 border-t border-zinc-800/80 bg-zinc-950/30">
              <span className="text-xs text-zinc-400">
                Page <span className="font-semibold text-zinc-200">{currentPage}</span> of{' '}
                <span className="font-semibold text-zinc-200">{totalPages}</span>
              </span>

              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 text-xs bg-zinc-900 border-zinc-800 disabled:opacity-40"
                  disabled={currentPage <= 1}
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                >
                  <ChevronLeft className="size-3.5 mr-1" />
                  Previous
                </Button>

                {/* Quick Page Jump Pills (hidden on mobile, visible on sm:) */}
                <div className="hidden sm:flex items-center gap-1">
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    let p = i + 1
                    if (totalPages > 5 && currentPage > 3) {
                      p = Math.min(totalPages - 4 + i, currentPage - 2 + i)
                    }
                    return (
                      <Button
                        key={p}
                        variant={currentPage === p ? 'default' : 'outline'}
                        size="sm"
                        className={cn(
                          "h-8 w-8 text-xs p-0 font-medium transition-colors",
                          currentPage === p
                            ? "bg-zinc-100 text-zinc-950 font-bold border-zinc-100 shadow-sm hover:bg-white hover:text-black"
                            : "bg-zinc-900 border-zinc-800 text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800"
                        )}
                        onClick={() => setCurrentPage(p)}
                      >
                        {p}
                      </Button>
                    )
                  })}
                </div>

                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 text-xs bg-zinc-900 border-zinc-800 disabled:opacity-40"
                  disabled={currentPage >= totalPages}
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                >
                  Next
                  <ChevronRight className="size-3.5 ml-1" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Finding Inspector Sheet / Drawer */}
      <Sheet open={!!selectedFinding} onOpenChange={(open) => !open && handleSelectFinding(null)}>
        <SheetContent className="w-full sm:max-w-[640px] md:max-w-[720px] lg:max-w-[780px] p-0 bg-zinc-950 border-zinc-800 shadow-2xl flex flex-col h-full">
          {selectedFinding && (
            <div className="flex flex-col h-full min-h-0">
              {/* Sticky Top Header with Safe Close Button Margin */}
              <SheetHeader className="px-4 sm:px-6 py-4 sm:py-5 border-b border-zinc-800/80 bg-zinc-950/95 sticky top-0 z-20 backdrop-blur pr-14 text-left">
                <div className="flex flex-wrap items-center gap-2">
                  {getVerdictBadge(selectedFinding.verdict, selectedFinding.status)}
                  <Badge variant={getSeverityBadgeVariant(selectedFinding.severity)} className="text-xs font-bold uppercase">
                    {selectedFinding.severity}
                  </Badge>
                  <Badge variant="outline" className="font-mono text-xs text-zinc-300 border-zinc-750">
                    {selectedFinding.ruleId}
                  </Badge>
                  <Badge variant="secondary" className="font-mono text-xs text-zinc-300">
                    {selectedFinding.cwe}
                  </Badge>
                  {selectedFinding.reachability === 'ReachableCallPath' && (
                    <Badge variant="destructive" className="text-xs font-mono flex items-center gap-1 font-bold">
                      <GitBranch className="size-3" />
                      Verified Reachable Flow
                    </Badge>
                  )}
                </div>
                <SheetTitle className="text-base sm:text-lg font-bold mt-2 text-zinc-100 leading-snug">
                  {selectedFinding.title}
                </SheetTitle>
                <SheetDescription className="flex flex-wrap items-center gap-2 mt-1 text-xs text-zinc-400 font-mono">
                  <span className="truncate max-w-[260px] sm:max-w-none" title={selectedFinding.targetLocation}>
                    File: {selectedFinding.targetLocation}
                  </span>
                  <span>•</span>
                  <span>Lines: {selectedFinding.startLine}-{selectedFinding.endLine}</span>
                  {selectedFinding.fingerprint && (
                    <>
                      <span>•</span>
                      <span className="text-[11px] text-zinc-500 bg-zinc-900 border border-zinc-800 px-1.5 py-0.5 rounded truncate max-w-[120px] sm:max-w-none">
                        FP: {selectedFinding.fingerprint}
                      </span>
                    </>
                  )}
                </SheetDescription>
              </SheetHeader>

              {/* Scrollable Inspector Body with Generous Padding */}
              <div className="flex-1 overflow-y-auto px-4 sm:px-6 py-4 sm:py-6 flex flex-col gap-6">
                {/* Cloudflare Three-Verdict: Needs Validation Banner & Blockers */}
                {selectedFinding.verdict === 'needs_validation' && (
                  <div className="p-4 rounded-xl border border-amber-500/40 bg-amber-500/10 flex flex-col gap-3">
                    <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs tracking-wider uppercase">
                      <HelpCircle className="size-4 shrink-0" />
                      <span>Decisive Validation Blocked (Phase 4 Incomplete)</span>
                    </div>
                    <p className="text-xs text-amber-200/90 leading-relaxed">
                      This finding is a source-grounded candidate whose confirmation requires live environment access or operational telemetry. Under Cloudflare audit rules, unverified candidates do not receive an arbitrary severity score.
                    </p>
                    {selectedFinding.blockers && selectedFinding.blockers.length > 0 && (
                      <div className="flex flex-col gap-1.5 mt-1 bg-zinc-950/60 p-3 rounded-lg border border-amber-500/20">
                        <span className="text-[11px] font-bold text-amber-300 uppercase tracking-wider">
                          Unresolved Blockers:
                        </span>
                        <ul className="list-disc list-inside text-xs text-zinc-300 space-y-1">
                          {selectedFinding.blockers.map((b, i) => (
                            <li key={i} className="leading-snug">{b}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {selectedFinding.validationPlan && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                        {selectedFinding.validationPlan.local && (
                          <div className="p-2.5 rounded-lg bg-zinc-950/80 border border-zinc-800">
                            <span className="font-bold text-zinc-300 block mb-1">Local Test Plan:</span>
                            <span className="text-zinc-400 text-[11px] leading-relaxed">
                              <InlineFormattedText text={selectedFinding.validationPlan.local} />
                            </span>
                          </div>
                        )}
                        {selectedFinding.validationPlan.deployment && (
                          <div className="p-2.5 rounded-lg bg-zinc-950/80 border border-zinc-800">
                            <span className="font-bold text-zinc-300 block mb-1">Deployment Telemetry Plan:</span>
                            <span className="text-zinc-400 text-[11px] leading-relaxed">
                              <InlineFormattedText text={selectedFinding.validationPlan.deployment} />
                            </span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Cloudflare Three-Verdict: Rejected / Refuted Hypothesis Banner */}
                {selectedFinding.verdict === 'rejected' && (
                  <div className="p-4 rounded-xl border border-zinc-700 bg-zinc-900/60 flex flex-col gap-2.5">
                    <div className="flex items-center gap-2 text-zinc-300 font-semibold text-xs tracking-wider uppercase">
                      <XCircle className="size-4 shrink-0 text-zinc-400" />
                      <span>Refuted Candidate / Disproven Hypothesis</span>
                    </div>
                    <p className="text-xs text-zinc-400 leading-relaxed">
                      This hypothesis was investigated during Phase 3 hunting and decisively disproven by code analysis or local tests. Retained in the audit ledger to eliminate duplicate audit cycles.
                    </p>
                    {selectedFinding.rejectionReason && (
                      <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 text-xs text-zinc-300 leading-relaxed">
                        <span className="font-bold text-primary block mb-1 font-sans">Disproven Rationale:</span>
                        <InlineFormattedText text={selectedFinding.rejectionReason} />
                      </div>
                    )}
                  </div>
                )}

                {/* Live Host Source Code & Taint Flow Viewer */}
                <div className="flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-zinc-300 uppercase tracking-wider flex items-center gap-1.5">
                      <FileCode2 className="size-4 text-primary" />
                      Live Host Source Inspection & Taint Path
                    </span>
                    <Badge variant="outline" className="text-[10px] font-mono text-zinc-400">
                      Line {selectedFinding.startLine || 1}
                    </Badge>
                  </div>
                  <SourceViewer
                    filePath={selectedFinding.targetLocation || ''}
                    targetLine={selectedFinding.startLine}
                    taintSteps={selectedFinding.taintTrace || []}
                    fallbackSnippet={selectedFinding.smallestEffectiveFix}
                  />
                </div>

                {/* Smallest Effective Source Fix (Cloudflare Audit Doctrine) */}
                {selectedFinding.smallestEffectiveFix && (
                  <div className="flex flex-col gap-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-zinc-300 uppercase tracking-wider flex items-center gap-1.5">
                        <Code2 className="size-4 text-emerald-400" />
                        Smallest Effective Source Fix
                      </span>
                      <Badge variant="outline" className="text-[10px] font-mono text-emerald-400 border-emerald-500/30 bg-emerald-500/10">
                        Minimal Diff Surgical Remedy
                      </Badge>
                    </div>
                    <SurgicalDiffView
                      diff={selectedFinding.smallestEffectiveFix}
                      filePath={selectedFinding.targetLocation}
                      title={`Surgical Remedy — ${selectedFinding.targetLocation.split('/').pop()}`}
                    />
                  </div>
                )}

                {/* Audit Trace: Entrypoint ➔ Propagation ➔ Sink */}
                {selectedFinding.auditTrace && selectedFinding.auditTrace.length > 0 && (
                  <div className="flex flex-col gap-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-zinc-300 uppercase tracking-wider flex items-center gap-2">
                        <Layers className="size-4 text-sky-400" />
                        Boundary Audit Trace ({selectedFinding.auditTrace.length} Hops)
                      </span>
                      <Badge variant="outline" className="text-[10px] font-mono text-sky-400 border-sky-500/30">
                        Entrypoint ➔ Propagation ➔ Sink
                      </Badge>
                    </div>

                    <div className="flex flex-col gap-2.5 border border-zinc-800/80 rounded-xl p-3.5 bg-zinc-900/30">
                      {selectedFinding.auditTrace.map((node, idx) => (
                        <div
                          key={idx}
                          className="flex flex-col gap-1.5 p-3 rounded-lg border border-zinc-800 bg-zinc-950/80 shadow-sm"
                        >
                          <div className="flex items-center justify-between text-xs">
                            <div className="flex items-center gap-2">
                              <Badge
                                variant={
                                  node.kind === 'entrypoint'
                                    ? 'default'
                                    : node.kind === 'sink'
                                      ? 'destructive'
                                      : 'secondary'
                                }
                                className="text-[10px] font-mono font-bold uppercase"
                              >
                                {node.kind}
                              </Badge>
                              <span className="font-mono text-zinc-300 text-xs font-semibold">
                                {node.file}:{node.line}
                              </span>
                            </div>
                            <span className="font-mono text-[11px] text-zinc-400 truncate max-w-[220px]">
                              {node.scope}
                            </span>
                          </div>
                          <p className="text-xs text-zinc-300 pl-1 leading-relaxed">
                            {node.description}
                          </p>
                          {idx < selectedFinding.auditTrace!.length - 1 && (
                            <div className="flex justify-center -mb-4 my-1">
                              <ChevronRight className="size-4 text-zinc-500 rotate-90" />
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Root Cause & Intended Behavior */}
                {(selectedFinding.rootCause || selectedFinding.intendedBehavior) && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {selectedFinding.rootCause && (
                      <div className="flex flex-col gap-1.5 p-3.5 rounded-xl border border-zinc-800 bg-zinc-900/50 shadow-sm">
                        <span className="text-[11px] font-semibold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                          <span className="size-1.5 rounded-full bg-rose-500" />
                          Identified Root Cause
                        </span>
                        <div className="text-xs text-zinc-300 leading-relaxed">
                          <InlineFormattedText text={selectedFinding.rootCause} />
                        </div>
                      </div>
                    )}
                    {selectedFinding.intendedBehavior && (
                      <div className="flex flex-col gap-1.5 p-3.5 rounded-xl border border-zinc-800 bg-zinc-900/50 shadow-sm">
                        <span className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
                          <span className="size-1.5 rounded-full bg-emerald-500" />
                          Intended Boundary Invariant
                        </span>
                        <div className="text-xs text-zinc-300 leading-relaxed">
                          <InlineFormattedText text={selectedFinding.intendedBehavior} />
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Vulnerability Analysis Card (Enterprise Markdown Rendered) */}
                <div className="flex flex-col gap-2.5">
                  <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                    Vulnerability Analysis &amp; Impact
                  </span>
                  <div className="bg-zinc-900/80 border border-zinc-800 p-4 rounded-xl shadow-sm">
                    <MarkdownView content={selectedFinding.description} />
                  </div>
                </div>

                {/* Remediation Guidance (Enterprise Markdown Rendered) */}
                {selectedFinding.remediationGuidance && (
                  <div className="flex flex-col gap-2.5">
                    <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                      Remediation Guidance
                    </span>
                    <div className="bg-zinc-900/50 border border-zinc-800/80 p-4 rounded-xl shadow-sm">
                      <MarkdownView content={selectedFinding.remediationGuidance} />
                    </div>
                  </div>
                )}

                {/* Taint Flow Trace (If Present) */}
                {selectedFinding.taintTrace && selectedFinding.taintTrace.length > 0 && (
                  <div className="flex flex-col gap-3">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider flex items-center gap-2">
                        <GitBranch className="size-4 text-primary" />
                        In-Engine Semantic Taint Trace ({selectedFinding.taintTrace.length} Steps)
                      </span>
                      <Badge variant="destructive" className="text-xs font-mono font-bold">
                        Pure-Rust AST Proof
                      </Badge>
                    </div>

                    <div className="flex flex-col gap-3 border border-zinc-800 rounded-xl p-4 bg-zinc-900/40">
                      {selectedFinding.taintTrace.map((step, idx) => (
                        <div
                          key={step.step}
                          className="flex flex-col gap-2 p-3.5 rounded-lg border border-zinc-800/80 bg-zinc-950/80 relative shadow-sm"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-1.5 text-xs">
                            <div className="flex items-center gap-2.5 flex-wrap">
                              <span className="font-mono font-bold size-6 rounded-full bg-primary/20 text-primary border border-primary/30 flex items-center justify-center text-xs">
                                {step.step}
                              </span>
                              <Badge
                                variant="outline"
                                className={`text-[11px] font-mono font-bold ${
                                  step.role === 'SOURCE'
                                    ? 'border-amber-500/40 bg-amber-500/10 text-amber-300'
                                    : step.role === 'SINK'
                                      ? 'border-rose-500/40 bg-rose-500/10 text-rose-300'
                                      : step.role === 'SANITIZER'
                                        ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
                                        : 'border-sky-500/40 bg-sky-500/10 text-sky-300'
                                }`}
                              >
                                {step.role}
                              </Badge>
                              <span className="font-mono text-zinc-400 text-xs">
                                {step.location}:{step.line}
                              </span>
                            </div>
                            <span className="font-mono text-xs font-bold text-primary bg-primary/10 border border-primary/20 px-2 py-0.5 rounded">
                              ${step.variable}
                            </span>
                          </div>

                          <pre className="font-mono text-xs bg-zinc-900/95 border border-zinc-800 p-3 rounded-md mt-1 overflow-x-auto text-zinc-200 leading-relaxed">
                            {step.codeSnippet}
                          </pre>

                          {idx < selectedFinding.taintTrace!.length - 1 && (
                            <div className="flex justify-center -mb-5 my-1.5">
                              <ChevronRight className="size-4 text-zinc-500 rotate-90" />
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Sticky Bottom Actions & Governance Footer */}
              <div className="border-t border-zinc-800/80 px-4 sm:px-6 py-3 sm:py-4 bg-zinc-950/95 backdrop-blur sticky bottom-0 z-20 flex flex-col gap-3 mt-auto">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex flex-col min-w-0">
                    <span className="text-xs font-bold text-zinc-100 flex items-center gap-1.5">
                      <ShieldCheck className="size-3.5 text-primary shrink-0" />
                      Three-Tier Verified Patch Generation
                    </span>
                    <span className="text-[11px] text-zinc-400">
                      Dispatches test synthesis and dual-state regression verification.
                    </span>
                  </div>
                  <Button
                    size="sm"
                    disabled={currentRole === 'Viewer'}
                    onClick={() => {
                      onOpenAiPatchModal(selectedFinding)
                      handleSelectFinding(null)
                    }}
                    className="font-semibold shadow-md bg-primary text-primary-foreground hover:bg-primary/90 shrink-0 flex items-center justify-center gap-1.5 w-full sm:w-auto h-8 text-xs"
                  >
                    <Sparkles className="size-3.5" />
                    Synthesize AI Patch &amp; Tests
                  </Button>
                </div>
                {currentRole === 'Viewer' && (
                  <span className="text-[11px] text-zinc-500 italic">
                    * Viewer role has read-only permissions. Switch to Operator or Admin in the top bar to propose patches.
                  </span>
                )}
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  )
}
