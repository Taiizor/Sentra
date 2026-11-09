import {
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Coins,
  History,
  FolderGit2,
} from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import type { DashboardOverview, SessionSummaryView } from '@/types/sentra'

interface OverviewTabProps {
  overview: DashboardOverview
  sessions: SessionSummaryView[]
  onSelectTab: (tab: string) => void
}

export function OverviewTab({ overview, sessions, onSelectTab }: OverviewTabProps) {
  const totalFindings =
    overview.criticalFindings +
    overview.highFindings +
    overview.mediumFindings +
    overview.lowFindings +
    overview.infoFindings

  const criticalPercent = totalFindings ? Math.round((overview.criticalFindings / totalFindings) * 100) : 0
  const highPercent = totalFindings ? Math.round((overview.highFindings / totalFindings) * 100) : 0
  const mediumPercent = totalFindings ? Math.round((overview.mediumFindings / totalFindings) * 100) : 0

  return (
    <div className="flex flex-col gap-6">
      {/* Platform Security Banner */}
      <Alert>
        <ShieldAlert className="size-5 text-primary" />
        <AlertTitle className="text-sm font-semibold">
          Fail-Closed Security Containment Active (Zero Untrusted Execution)
        </AlertTitle>
        <AlertDescription className="text-xs text-muted-foreground mt-1">
          Target builds, fuzzers, and dynamic PoCs are strictly isolated from the operator host.
          Subprocess plugins and LLM providers execute under strict token ceilings and zero egress permissions.
        </AlertDescription>
      </Alert>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Sessions */}
        <Card className="hover:border-primary/50 transition-colors cursor-pointer" onClick={() => onSelectTab('sessions')}>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Total Sessions
            </CardTitle>
            <FolderGit2 className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview.totalSessions}</div>
            <p className="text-xs text-muted-foreground mt-1">
              {overview.activeSessions} active scoped workspace(s)
            </p>
          </CardContent>
        </Card>

        {/* Security Findings */}
        <Card className="hover:border-destructive/50 transition-colors cursor-pointer" onClick={() => onSelectTab('findings')}>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Vulnerability Findings
            </CardTitle>
            <AlertTriangle className="size-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold flex items-center gap-2">
              <span>{totalFindings}</span>
              {overview.criticalFindings > 0 && (
                <Badge variant="destructive" className="text-xs">
                  {overview.criticalFindings} Critical
                </Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              {overview.highFindings} high, {overview.mediumFindings} medium
            </p>
          </CardContent>
        </Card>

        {/* Verified Patches */}
        <Card className="hover:border-primary/50 transition-colors cursor-pointer" onClick={() => onSelectTab('remediation')}>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Verified Patches
            </CardTitle>
            <CheckCircle2 className="size-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview.verifiedPatches}</div>
            <p className="text-xs text-muted-foreground mt-1">
              3-tier invariant verified with regression oracles
            </p>
          </CardContent>
        </Card>

        {/* Spent Budget */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Research Budget Spend
            </CardTitle>
            <Coins className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              ${(overview.totalSpentMicroUsd / 1_000_000).toFixed(4)}
            </div>
            <p className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
              <History className="size-3" />
              {overview.auditEventCount} immutable audit records
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Two Column Layout: Severity Distribution & Active Sessions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Distribution Card */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm font-semibold">Severity Breakdown</CardTitle>
            <CardDescription className="text-xs">
              Normalized SAST, Taint, and Dependency signals
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {/* Critical */}
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium flex items-center gap-1.5">
                  <span className="size-2 rounded-full bg-destructive" />
                  Critical
                </span>
                <span className="text-muted-foreground font-mono">
                  {overview.criticalFindings} ({criticalPercent}%)
                </span>
              </div>
              <Progress value={criticalPercent} className="h-2" />
            </div>

            {/* High */}
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium flex items-center gap-1.5">
                  <span className="size-2 rounded-full bg-amber-500" />
                  High
                </span>
                <span className="text-muted-foreground font-mono">
                  {overview.highFindings} ({highPercent}%)
                </span>
              </div>
              <Progress value={highPercent} className="h-2" />
            </div>

            {/* Medium */}
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium flex items-center gap-1.5">
                  <span className="size-2 rounded-full bg-blue-500" />
                  Medium
                </span>
                <span className="text-muted-foreground font-mono">
                  {overview.mediumFindings} ({mediumPercent}%)
                </span>
              </div>
              <Progress value={mediumPercent} className="h-2" />
            </div>

            {/* Low & Info */}
            <div className="flex flex-col gap-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium flex items-center gap-1.5">
                  <span className="size-2 rounded-full bg-muted-foreground" />
                  Low & Informational
                </span>
                <span className="text-muted-foreground font-mono">
                  {overview.lowFindings + overview.infoFindings} (0%)
                </span>
              </div>
              <Progress value={0} className="h-2" />
            </div>
          </CardContent>
        </Card>

        {/* Recent Workspace Sessions */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm font-semibold">Active Workspace Sessions</CardTitle>
            <CardDescription className="text-xs">
              Bounded local workspace instances with SQLite WAL persistence
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs">Session ID</TableHead>
                  <TableHead className="text-xs">Workspace Root</TableHead>
                  <TableHead className="text-xs">State</TableHead>
                  <TableHead className="text-xs">Tasks</TableHead>
                  <TableHead className="text-xs">Epoch</TableHead>
                  <TableHead className="text-xs">Created At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((session) => (
                  <TableRow key={session.sessionId}>
                    <TableCell className="font-mono text-xs">{session.sessionId}</TableCell>
                    <TableCell className="font-mono text-xs truncate max-w-[220px]">
                      {session.workspaceRoot}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={session.state === 'SCOPED' ? 'secondary' : 'outline'}
                        className="text-xs"
                      >
                        {session.state}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs font-mono">{session.taskCount}</TableCell>
                    <TableCell className="text-xs font-mono">{session.fencingEpoch}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(session.createdAt).toLocaleTimeString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
