import { useState } from 'react'
import {
  AlertTriangle,
  GitBranch,
  ShieldCheck,
  Search,
  ExternalLink,
  ChevronRight,
  Eye,
} from 'lucide-react'
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

export function FindingsTab({ findings, currentRole, onProposePatch }: FindingsTabProps) {
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('ALL')
  const [reachabilityFilter, setReachabilityFilter] = useState<string>('ALL')
  const [selectedFinding, setSelectedFinding] = useState<FindingView | null>(null)

  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.ruleId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.targetLocation.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.cwe.toLowerCase().includes(searchTerm.toLowerCase())

    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter
    const matchesReachability = reachabilityFilter === 'ALL' || f.reachability === reachabilityFilter

    return matchesSearch && matchesSeverity && matchesReachability
  })

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
          <Badge variant="destructive" className="text-xs flex items-center gap-1">
            <GitBranch className="size-3" />
            Reachable Flow
          </Badge>
        )
      case 'SinkOnly':
        return (
          <Badge variant="outline" className="text-xs">
            Sink Only
          </Badge>
        )
      case 'Unreachable':
        return (
          <Badge variant="secondary" className="text-xs">
            Unreachable
          </Badge>
        )
      default:
        return (
          <Badge variant="outline" className="text-xs">
            Inconclusive
          </Badge>
        )
    }
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Search & Filter Controls */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative flex-1 min-w-[240px]">
              <Search className="size-4 absolute left-3 top-2.5 text-muted-foreground" />
              <Input
                placeholder="Search findings by rule, CWE, title, or file..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-9 h-9 text-xs"
              />
            </div>

            {/* Severity Filter */}
            <Select value={severityFilter} onValueChange={(val) => setSeverityFilter(val ?? 'ALL')}>
              <SelectTrigger className="w-[140px] h-9 text-xs">
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

            {/* Reachability Filter */}
            <Select value={reachabilityFilter} onValueChange={(val) => setReachabilityFilter(val ?? 'ALL')}>
              <SelectTrigger className="w-[170px] h-9 text-xs">
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
          </div>
        </CardContent>
      </Card>

      {/* Findings Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex flex-col">
              <CardTitle className="text-sm font-semibold">Normalized Security Findings</CardTitle>
              <CardDescription className="text-xs">
                Showing {filteredFindings.length} of {findings.length} findings
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {filteredFindings.length === 0 ? (
            <Empty className="py-12">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <ShieldCheck className="size-8 text-primary" />
                </EmptyMedia>
                <EmptyTitle>No Findings Match Filters</EmptyTitle>
                <EmptyDescription>
                  Try clearing your search query or selecting a different severity level.
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Severity</TableHead>
                  <TableHead className="text-xs">Rule & CWE</TableHead>
                  <TableHead className="text-xs">Vulnerability Title</TableHead>
                  <TableHead className="text-xs">Target Location</TableHead>
                  <TableHead className="text-xs">Reachability</TableHead>
                  <TableHead className="text-xs">Status</TableHead>
                  <TableHead className="text-xs text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredFindings.map((finding) => (
                  <TableRow
                    key={finding.findingId}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => setSelectedFinding(finding)}
                  >
                    <TableCell>
                      <Badge variant={getSeverityBadgeVariant(finding.severity)} className="text-xs">
                        {finding.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      <div className="flex flex-col">
                        <span className="font-semibold">{finding.ruleId}</span>
                        <span className="text-muted-foreground">{finding.cwe}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs font-medium max-w-[260px] truncate">
                      {finding.title}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground truncate max-w-[200px]">
                      {finding.targetLocation}:{finding.startLine}
                    </TableCell>
                    <TableCell>{getReachabilityBadge(finding.reachability)}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">
                        {finding.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 text-xs"
                        onClick={(e) => {
                          e.stopPropagation()
                          setSelectedFinding(finding)
                        }}
                      >
                        <Eye data-icon="inline-start" />
                        Inspect
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Finding Inspector Sheet / Drawer */}
      <Sheet open={!!selectedFinding} onOpenChange={(open) => !open && setSelectedFinding(null)}>
        <SheetContent className="sm:max-w-xl overflow-y-auto">
          {selectedFinding && (
            <div className="flex flex-col gap-6 py-4">
              <SheetHeader>
                <div className="flex items-center gap-2">
                  <Badge variant={getSeverityBadgeVariant(selectedFinding.severity)}>
                    {selectedFinding.severity}
                  </Badge>
                  <Badge variant="outline">{selectedFinding.ruleId}</Badge>
                  <Badge variant="secondary">{selectedFinding.cwe}</Badge>
                </div>
                <SheetTitle className="text-lg font-bold mt-2">
                  {selectedFinding.title}
                </SheetTitle>
                <SheetDescription className="text-xs text-muted-foreground">
                  Located in {selectedFinding.targetLocation} (Lines {selectedFinding.startLine}-{selectedFinding.endLine})
                </SheetDescription>
              </SheetHeader>

              {/* Description */}
              <div className="flex flex-col gap-2">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Vulnerability Analysis
                </span>
                <p className="text-sm bg-muted/50 p-3 rounded-md text-foreground">
                  {selectedFinding.description}
                </p>
              </div>

              {/* Taint Flow Trace (If Present) */}
              {selectedFinding.taintTrace && selectedFinding.taintTrace.length > 0 && (
                <div className="flex flex-col gap-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
                      <GitBranch className="size-3.5 text-primary" />
                      Interprocedural Taint Flow Call Path
                    </span>
                    <Badge variant="destructive" className="text-xs">
                      {selectedFinding.taintTrace.length} Steps
                    </Badge>
                  </div>

                  <div className="flex flex-col gap-2 border rounded-md p-3 bg-card">
                    {selectedFinding.taintTrace.map((step, idx) => (
                      <div
                        key={step.step}
                        className="flex flex-col gap-1 p-2 rounded border bg-muted/20 relative"
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
                              className="text-xs font-mono"
                            >
                              {step.role}
                            </Badge>
                            <span className="font-mono text-muted-foreground">
                              {step.location}:{step.line}
                            </span>
                          </div>
                          <span className="font-mono text-xs font-medium text-foreground">
                            ${step.variable}
                          </span>
                        </div>
                        <pre className="font-mono text-xs bg-muted/60 p-2 rounded mt-1 overflow-x-auto text-foreground">
                          {step.codeSnippet}
                        </pre>
                        {idx < selectedFinding.taintTrace!.length - 1 && (
                          <div className="flex justify-center -mb-3 my-1">
                            <ChevronRight className="size-4 text-muted-foreground rotate-90" />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Remediation Action */}
              <div className="border-t pt-4 flex flex-col gap-3">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                  Remediation & Governance
                </span>
                <div className="flex items-center justify-between gap-3 bg-muted/30 p-3 rounded-lg border">
                  <div className="flex flex-col">
                    <span className="text-xs font-medium">Three-Tier Verified Patch</span>
                    <span className="text-xs text-muted-foreground">
                      Proposes an isolated overlay patch verified with dual-state regression oracles.
                    </span>
                  </div>
                  <Button
                    size="sm"
                    disabled={currentRole === 'Viewer'}
                    onClick={() => {
                      onProposePatch(selectedFinding.findingId)
                      setSelectedFinding(null)
                    }}
                  >
                    Propose Patch
                  </Button>
                </div>
                {currentRole === 'Viewer' && (
                  <span className="text-xs text-muted-foreground italic">
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
