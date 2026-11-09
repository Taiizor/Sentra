import { useState, useMemo } from 'react'
import {
  AlertTriangle,
  GitBranch,
  ShieldCheck,
  Search,
  ExternalLink,
  ChevronRight,
  Eye,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Copy,
  Check,
  Download,
  ChevronLeft,
  Filter,
  Sparkles,
} from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
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
import type { FindingView, Severity, Reachability, UserRole } from '@/types/sentra'

interface FindingsTabProps {
  findings: FindingView[]
  currentRole: UserRole
  onProposePatch: (findingId: string) => void
}

type SortField = 'severity' | 'ruleId' | 'title' | 'targetLocation' | 'reachability'
type SortDir = 'asc' | 'desc'

const SEVERITY_WEIGHT: Record<Severity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Informational: 0,
}

export function FindingsTab({ findings, currentRole, onProposePatch }: FindingsTabProps) {
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('ALL')
  const [reachabilityFilter, setReachabilityFilter] = useState<string>('ALL')
  const [selectedFinding, setSelectedFinding] = useState<FindingView | null>(null)
  const [copiedPath, setCopiedPath] = useState<string | null>(null)

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
    }
  }, [findings])

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const matchesSearch =
        f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.ruleId.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.targetLocation.toLowerCase().includes(searchTerm.toLowerCase()) ||
        f.cwe.toLowerCase().includes(searchTerm.toLowerCase())

      const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter
      const matchesReachability = reachabilityFilter === 'ALL' || f.reachability === reachabilityFilter

      return matchesSearch && matchesSeverity && matchesReachability
    })
  }, [findings, searchTerm, severityFilter, reachabilityFilter])

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
    navigator.clipboard.writeText(path)
    setCopiedPath(path)
    toast.success('Path copied to clipboard', {
      description: path,
    })
    setTimeout(() => setCopiedPath(null), 2000)
  }

  function handleExportCsv() {
    const header = 'Severity,Rule,CWE,Title,File,Line,Reachability,Status\n'
    const rows = sortedFindings
      .map(
        (f) =>
          `"${f.severity}","${f.ruleId}","${f.cwe}","${f.title.replace(/"/g, '""')}","${f.targetLocation}",${f.startLine},"${f.reachability}","${f.status}"`
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
      description: `Downloaded ${sortedFindings.length} findings as CSV.`,
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
      description: `Downloaded ${sortedFindings.length} findings as JSON.`,
    })
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
      {/* Quick Interactive Filter Chips */}
      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant={severityFilter === 'ALL' && reachabilityFilter === 'ALL' ? 'default' : 'outline'}
          size="sm"
          className="h-7 text-xs rounded-full px-3"
          onClick={() => {
            setSeverityFilter('ALL')
            setReachabilityFilter('ALL')
            setCurrentPage(1)
          }}
        >
          All ({counts.all})
        </Button>

        <Button
          variant={severityFilter === 'Critical' ? 'destructive' : 'outline'}
          size="sm"
          className="h-7 text-xs rounded-full px-3 border-rose-500/30 hover:border-rose-500/80"
          onClick={() => {
            setSeverityFilter(severityFilter === 'Critical' ? 'ALL' : 'Critical')
            setCurrentPage(1)
          }}
        >
          <span className="size-1.5 rounded-full bg-rose-400 mr-1.5" />
          Critical ({counts.critical})
        </Button>

        <Button
          variant={severityFilter === 'High' ? 'secondary' : 'outline'}
          size="sm"
          className="h-7 text-xs rounded-full px-3 border-amber-500/30 hover:border-amber-500/80"
          onClick={() => {
            setSeverityFilter(severityFilter === 'High' ? 'ALL' : 'High')
            setCurrentPage(1)
          }}
        >
          <span className="size-1.5 rounded-full bg-amber-400 mr-1.5" />
          High ({counts.high})
        </Button>

        <Button
          variant={severityFilter === 'Medium' ? 'secondary' : 'outline'}
          size="sm"
          className="h-7 text-xs rounded-full px-3 border-sky-500/30 hover:border-sky-500/80"
          onClick={() => {
            setSeverityFilter(severityFilter === 'Medium' ? 'ALL' : 'Medium')
            setCurrentPage(1)
          }}
        >
          <span className="size-1.5 rounded-full bg-sky-400 mr-1.5" />
          Medium ({counts.medium})
        </Button>

        <Button
          variant={reachabilityFilter === 'ReachableCallPath' ? 'default' : 'outline'}
          size="sm"
          className="h-7 text-xs rounded-full px-3 border-primary/40 hover:border-primary"
          onClick={() => {
            setReachabilityFilter(reachabilityFilter === 'ReachableCallPath' ? 'ALL' : 'ReachableCallPath')
            setCurrentPage(1)
          }}
        >
          <GitBranch className="size-3 mr-1 text-primary" />
          Reachable Flows ({counts.reachable})
        </Button>
      </div>

      {/* Search & Filter Controls */}
      <Card className="border-zinc-800 bg-zinc-900/60 shadow-md">
        <CardContent className="pt-4 pb-4">
          <div className="flex flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative flex-1 min-w-[260px]">
              <Search className="size-4 absolute left-3 top-2.5 text-zinc-400" />
              <Input
                placeholder="Instant filter by rule ID, CWE-89, file path, or payload title..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value)
                  setCurrentPage(1)
                }}
                className="pl-9 h-9 text-xs bg-zinc-950/70 border-zinc-800 text-zinc-100 placeholder:text-zinc-500"
              />
            </div>

            {/* Severity Select */}
            <Select
              value={severityFilter}
              onValueChange={(val) => {
                setSeverityFilter(val ?? 'ALL')
                setCurrentPage(1)
              }}
            >
              <SelectTrigger className="w-[140px] h-9 text-xs bg-zinc-950/70 border-zinc-800">
                <SelectValue placeholder="Severity" />
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

            {/* Reachability Select */}
            <Select
              value={reachabilityFilter}
              onValueChange={(val) => {
                setReachabilityFilter(val ?? 'ALL')
                setCurrentPage(1)
              }}
            >
              <SelectTrigger className="w-[170px] h-9 text-xs bg-zinc-950/70 border-zinc-800">
                <SelectValue placeholder="Reachability" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="ALL">All Reachability</SelectItem>
                  <SelectItem value="ReachableCallPath">Reachable Call Path</SelectItem>
                  <SelectItem value="SinkOnly">Sink Only</SelectItem>
                  <SelectItem value="Unreachable">Unreachable</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>

            {/* Export Actions */}
            <div className="flex items-center gap-1.5 ml-auto">
              <Button
                variant="outline"
                size="sm"
                className="h-9 text-xs bg-zinc-950/70 border-zinc-800 hover:text-zinc-100"
                onClick={handleExportCsv}
              >
                <Download className="size-3.5 mr-1" />
                CSV
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-9 text-xs bg-zinc-950/70 border-zinc-800 hover:text-zinc-100"
                onClick={handleExportJson}
              >
                <Download className="size-3.5 mr-1" />
                JSON
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Findings Table Card */}
      <Card className="border-zinc-800 bg-zinc-900/60 shadow-md">
        <CardHeader className="py-3.5 px-5 border-b border-zinc-800/80">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-col">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <span>Normalized Security Findings</span>
                <Badge variant="outline" className="text-[10px] font-mono">
                  Pure-Rust AST &amp; Taint Engine
                </Badge>
              </CardTitle>
              <CardDescription className="text-xs text-zinc-400 mt-0.5">
                Showing {sortedFindings.length === 0 ? 0 : (currentPage - 1) * pageSize + 1}-
                {Math.min(currentPage * pageSize, sortedFindings.length)} of {sortedFindings.length} filtered findings ({findings.length} total across workspace)
              </CardDescription>
            </div>

            {/* Page Size Selector */}
            <div className="flex items-center gap-2 text-xs text-zinc-400">
              <span>Show:</span>
              <Select
                value={pageSize.toString()}
                onValueChange={(val) => {
                  setPageSize(Number(val) || 15)
                  setCurrentPage(1)
                }}
              >
                <SelectTrigger className="w-[75px] h-7 text-xs bg-zinc-950/70 border-zinc-800">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
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
                    <TableHead className="text-xs text-zinc-300 font-semibold w-[100px]">Status</TableHead>
                    <TableHead className="text-xs text-right text-zinc-300 font-semibold w-[100px]">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {paginatedFindings.map((finding) => (
                    <TableRow
                      key={finding.findingId}
                      className="cursor-pointer hover:bg-zinc-800/40 border-zinc-800/70 transition-colors group"
                      onClick={() => setSelectedFinding(finding)}
                    >
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
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 text-xs px-2 text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800"
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedFinding(finding)
                          }}
                        >
                          <Eye className="size-3.5 mr-1" />
                          Inspect
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}

          {/* Pagination Navigation Footer */}
          {sortedFindings.length > 0 && (
            <div className="flex items-center justify-between px-5 py-3 border-t border-zinc-800/80 bg-zinc-950/30">
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

                {/* Quick Page Jump Pills */}
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
                      className="h-8 w-8 text-xs p-0 bg-zinc-900 border-zinc-800"
                      onClick={() => setCurrentPage(p)}
                    >
                      {p}
                    </Button>
                  )
                })}

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
      <Sheet open={!!selectedFinding} onOpenChange={(open) => !open && setSelectedFinding(null)}>
        <SheetContent className="sm:max-w-xl overflow-y-auto bg-zinc-950 border-zinc-800">
          {selectedFinding && (
            <div className="flex flex-col gap-6 py-4">
              <SheetHeader>
                <div className="flex items-center gap-2">
                  <Badge variant={getSeverityBadgeVariant(selectedFinding.severity)}>
                    {selectedFinding.severity}
                  </Badge>
                  <Badge variant="outline" className="font-mono">
                    {selectedFinding.ruleId}
                  </Badge>
                  <Badge variant="secondary" className="font-mono">
                    {selectedFinding.cwe}
                  </Badge>
                </div>
                <SheetTitle className="text-lg font-bold mt-2 text-zinc-100">
                  {selectedFinding.title}
                </SheetTitle>
                <SheetDescription className="text-xs text-zinc-400">
                  Located in {selectedFinding.targetLocation} (Lines {selectedFinding.startLine}-{selectedFinding.endLine})
                </SheetDescription>
              </SheetHeader>

              {/* Description */}
              <div className="flex flex-col gap-2">
                <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                  Vulnerability Analysis
                </span>
                <p className="text-sm bg-zinc-900/80 border border-zinc-800 p-3 rounded-md text-zinc-200">
                  {selectedFinding.description}
                </p>
              </div>

              {/* Taint Flow Trace (If Present) */}
              {selectedFinding.taintTrace && selectedFinding.taintTrace.length > 0 && (
                <div className="flex flex-col gap-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider flex items-center gap-1.5">
                      <GitBranch className="size-3.5 text-primary" />
                      Interprocedural Taint Flow Call Path
                    </span>
                    <Badge variant="destructive" className="text-xs font-mono">
                      {selectedFinding.taintTrace.length} Steps
                    </Badge>
                  </div>

                  <div className="flex flex-col gap-2 border border-zinc-800 rounded-md p-3 bg-zinc-900/50">
                    {selectedFinding.taintTrace.map((step, idx) => (
                      <div
                        key={step.step}
                        className="flex flex-col gap-1 p-2.5 rounded border border-zinc-800/80 bg-zinc-950/70 relative"
                      >
                        <div className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold size-5 rounded-full bg-primary/20 text-primary flex items-center justify-center text-xs">
                              {step.step}
                            </span>
                            <Badge
                              variant={
                                step.role === 'SOURCE'
                                  ? 'destructive'
                                  : step.role === 'SINK'
                                    ? 'destructive'
                                    : 'secondary'
                              }
                              className="text-[10px] font-mono"
                            >
                              {step.role}
                            </Badge>
                            <span className="font-mono text-zinc-400 text-[11px]">
                              {step.location}:{step.line}
                            </span>
                          </div>
                          <span className="font-mono text-xs font-bold text-zinc-200 bg-zinc-800/80 px-1.5 py-0.5 rounded">
                            ${step.variable}
                          </span>
                        </div>
                        <pre className="font-mono text-xs bg-zinc-900/90 border border-zinc-800 p-2 rounded mt-1.5 overflow-x-auto text-zinc-200">
                          {step.codeSnippet}
                        </pre>
                        {idx < selectedFinding.taintTrace!.length - 1 && (
                          <div className="flex justify-center -mb-3.5 my-1">
                            <ChevronRight className="size-4 text-zinc-500 rotate-90" />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Remediation Action */}
              <div className="border-t border-zinc-800 pt-4 flex flex-col gap-3">
                <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">
                  Remediation &amp; Governance
                </span>
                <div className="flex items-center justify-between gap-3 bg-zinc-900/60 p-3 rounded-lg border border-zinc-800">
                  <div className="flex flex-col">
                    <span className="text-xs font-medium text-zinc-100">Three-Tier Verified Patch</span>
                    <span className="text-xs text-zinc-400">
                      Proposes an isolated overlay patch verified with dual-state regression oracles.
                    </span>
                  </div>
                  <Button
                    size="sm"
                    disabled={currentRole === 'Viewer'}
                    onClick={() => {
                      onProposePatch(selectedFinding.findingId)
                      setSelectedFinding(null)
                      toast.success('Patch Candidate Proposed', {
                        description: `Dispatched verification for ${selectedFinding.findingId}.`,
                      })
                    }}
                  >
                    Propose Patch
                  </Button>
                </div>
                {currentRole === 'Viewer' && (
                  <span className="text-xs text-zinc-500 italic">
                    * Viewer role cannot propose patches. Switch to Operator or Admin role in header.
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
