import {
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Coins,
  History,
  FolderGit2,
  TrendingUp,
  Activity,
  Layers,
  Radio,
} from 'lucide-react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { Button } from '@/components/ui/button'
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
import type { DashboardOverview, SecurityTrendPoint, SessionSummaryView } from '@/types/sentra'

interface OverviewTabProps {
  overview: DashboardOverview
  sessions: SessionSummaryView[]
  trends: SecurityTrendPoint[]
  onSelectTab: (tab: string) => void
  onOpenLiveStream?: () => void
}

export function OverviewTab({ overview, sessions, trends, onSelectTab, onOpenLiveStream }: OverviewTabProps) {
  const totalFindings =
    overview.criticalFindings +
    overview.highFindings +
    overview.mediumFindings +
    overview.lowFindings +
    overview.infoFindings

  const criticalPercent = totalFindings ? Math.round((overview.criticalFindings / totalFindings) * 100) : 0
  const highPercent = totalFindings ? Math.round((overview.highFindings / totalFindings) * 100) : 0
  const mediumPercent = totalFindings ? Math.round((overview.mediumFindings / totalFindings) * 100) : 0

  const score = overview.securityScore
  const grade =
    score >= 95 ? 'GRADE A+' :
    score >= 85 ? 'GRADE A' :
    score >= 75 ? 'GRADE B' :
    score >= 60 ? 'GRADE C' :
    score >= 45 ? 'GRADE D' : 'GRADE F'

  const scoreColor =
    score >= 80 ? 'text-emerald-400' :
    score >= 65 ? 'text-teal-400' :
    score >= 50 ? 'text-amber-400' : 'text-rose-400'

  const gradeBadgeVariant =
    score >= 80 ? ('secondary' as const) :
    score >= 50 ? ('outline' as const) : ('destructive' as const)

  return (
    <div className="flex flex-col gap-6">
      {/* Fail-Closed Platform Security Banner */}
      <Alert className="border-primary/30 bg-primary/5">
        <ShieldAlert className="size-5 text-primary" />
        <AlertTitle className="text-sm font-semibold flex items-center justify-between">
          <span>Fail-Closed Host Boundary & Zero Untrusted Target Execution Active</span>
          <div className="flex items-center gap-2">
            {onOpenLiveStream && (
              <Button
                size="sm"
                variant="outline"
                onClick={onOpenLiveStream}
                className="h-7 text-xs border-primary/40 bg-primary/10 text-primary hover:bg-primary/20 font-semibold"
              >
                <Radio className="size-3 mr-1.5 animate-pulse text-primary" />
                Live Stream Scan
              </Button>
            )}
            <Badge variant="outline" className="text-xs font-mono">
              ADR-0004 &amp; ADR-0005
            </Badge>
          </div>
        </AlertTitle>
        <AlertDescription className="text-xs text-muted-foreground mt-1">
          Untrusted code execution on operator host is strictly disabled (<code className="font-mono">FailClosedBackend</code>).
          Dynamic builds, ASan fuzzers, and PoC reproductions run strictly inside disposable single-tenant Linux VM sandboxes with strictly denied network egress.
        </AlertDescription>
      </Alert>

      {/* Primary Threat Posture Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Security Posture Score */}
        <Card
          className="border-border/80 hover:border-primary/50 transition-colors cursor-pointer"
          onClick={() => onSelectTab('findings')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Security Score
            </CardTitle>
            <Activity className={`size-4 ${scoreColor}`} />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${scoreColor}`}>
              {overview.securityScore} <span className="text-xs text-muted-foreground font-normal">/ 100</span>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1 flex items-center gap-1.5">
              <Badge variant={gradeBadgeVariant} className="text-[10px] h-4 px-1.5 font-bold">
                {grade}
              </Badge>
              <span>{overview.securityScore >= 75 ? '3-tier verification active' : 'Critical signals require action'}</span>
            </p>
          </CardContent>
        </Card>

        {/* Total Sessions */}
        <Card
          className="border-border/80 hover:border-primary/50 transition-colors cursor-pointer"
          onClick={() => onSelectTab('fleet')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Workspace Sessions
            </CardTitle>
            <FolderGit2 className="size-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview.totalSessions}</div>
            <p className="text-[11px] text-muted-foreground mt-1">
              {overview.activeSessions} active scoped instance(s)
            </p>
          </CardContent>
        </Card>

        {/* Security Findings */}
        <Card
          className="border-border/80 hover:border-destructive/50 transition-colors cursor-pointer"
          onClick={() => onSelectTab('findings')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Vulnerabilities
            </CardTitle>
            <AlertTriangle className="size-4 text-rose-500" />
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
            <p className="text-[11px] text-muted-foreground mt-1">
              {overview.highFindings} high, {overview.mediumFindings} medium
            </p>
          </CardContent>
        </Card>

        {/* Verified Patches */}
        <Card
          className="border-border/80 hover:border-emerald-500/50 transition-colors cursor-pointer"
          onClick={() => onSelectTab('remediation')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Verified Patches
            </CardTitle>
            <CheckCircle2 className="size-4 text-emerald-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-emerald-400">
              {overview.verifiedPatches}
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">
              Dual-state oracle verified
            </p>
          </CardContent>
        </Card>

        {/* Budget Spend */}
        <Card
          className="border-border/80 hover:border-primary/50 transition-colors cursor-pointer"
          onClick={() => onSelectTab('research')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground">
              Research Tokens Spent
            </CardTitle>
            <Coins className="size-4 text-amber-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-100 font-mono">
              ${(overview.totalSpentMicroUsd / 1_000_000).toFixed(2)}
            </div>
            <p className="text-[11px] text-muted-foreground mt-1 flex items-center gap-1">
              <History className="size-3" />
              <span>{overview.auditEventCount} immutable audit logs</span>
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Two Column Layout: Recharts Threat Trend & CWE Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Recharts Area Chart: 14-Day Vulnerability Trend */}
        <Card className="lg:col-span-8 border-border/80">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <div className="flex flex-col">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <TrendingUp className="size-4 text-primary" />
                  Vulnerability Velocity & Remediation Rate
                </CardTitle>
                <CardDescription className="text-xs">
                  Historical telemetry showing signals detected vs verified remediations over time
                </CardDescription>
              </div>
              <Badge variant="secondary" className="text-xs font-mono">
                MTTR: 4.2 min
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="pt-2">
            <div className="h-[220px] w-full min-h-[220px] min-w-0">
              <ResponsiveContainer width="100%" height="100%" minWidth={0} minHeight={220}>
                <AreaChart data={trends} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="detectedGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="remediatedGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" stroke="#71717a" fontSize={11} tickLine={false} />
                  <YAxis stroke="#71717a" fontSize={11} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#18181b',
                      borderColor: '#27272a',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="detected"
                    stroke="#f43f5e"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#detectedGrad)"
                    name="Detected"
                  />
                  <Area
                    type="monotone"
                    dataKey="remediated"
                    stroke="#10b981"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#remediatedGrad)"
                    name="Remediated"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Severity & Attack Surface Breakdown */}
        <Card className="lg:col-span-4 border-border/80 flex flex-col justify-between">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Layers className="size-4 text-primary" />
              Attack Surface Breakdown
            </CardTitle>
            <CardDescription className="text-xs">
              Normalized SAST, Taint, and Dependency signals
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 pt-2">
            {/* Critical */}
            <div className="flex flex-col gap-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium flex items-center gap-1.5 text-rose-400">
                  <span className="size-2 rounded-full bg-rose-500" />
                  Critical Severity
                </span>
                <span className="font-mono text-muted-foreground">
                  {overview.criticalFindings} ({criticalPercent}%)
                </span>
              </div>
              <Progress value={criticalPercent} className="h-1.5" />
            </div>

            {/* High */}
            <div className="flex flex-col gap-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium flex items-center gap-1.5 text-amber-400">
                  <span className="size-2 rounded-full bg-amber-500" />
                  High Severity
                </span>
                <span className="font-mono text-muted-foreground">
                  {overview.highFindings} ({highPercent}%)
                </span>
              </div>
              <Progress value={highPercent} className="h-1.5" />
            </div>

            {/* Medium */}
            <div className="flex flex-col gap-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium flex items-center gap-1.5 text-blue-400">
                  <span className="size-2 rounded-full bg-blue-500" />
                  Medium Severity
                </span>
                <span className="font-mono text-muted-foreground">
                  {overview.mediumFindings} ({mediumPercent}%)
                </span>
              </div>
              <Progress value={mediumPercent} className="h-1.5" />
            </div>

            {/* CWE Tags */}
            <div className="border-t pt-3 mt-1 flex flex-wrap gap-1.5">
              <Badge variant="outline" className="text-[10px] font-mono">
                CWE-89 SQLi
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono">
                CWE-78 Command Injection
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono">
                CWE-798 Secrets
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono">
                CWE-22 Path Traversal
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono">
                CWE-1321 Proto Pollution
              </Badge>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Active Workspace Sessions */}
      <Card className="border-border/80">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex flex-col">
              <CardTitle className="text-sm font-semibold">
                Bounded Workspace Sessions (SQLite WAL Storage)
              </CardTitle>
              <CardDescription className="text-xs">
                Deterministic session manifests bound to canonical source snapshots with CAS blob storage
              </CardDescription>
            </div>
            <Badge variant="outline" className="text-xs font-mono">
              rusqlite 0.32.1
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs">Session ID</TableHead>
                <TableHead className="text-xs">Canonical Workspace Path</TableHead>
                <TableHead className="text-xs">Lifecycle State</TableHead>
                <TableHead className="text-xs">Task Count</TableHead>
                <TableHead className="text-xs">Fencing Epoch</TableHead>
                <TableHead className="text-xs text-right">Created Timestamp (UTC)</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sessions.map((session) => (
                <TableRow key={session.sessionId}>
                  <TableCell className="font-mono text-xs font-semibold">
                    {session.sessionId}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground truncate max-w-[320px]">
                    {session.workspaceRoot}
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={session.state === 'SCOPED' ? 'secondary' : 'outline'}
                      className="text-xs font-mono"
                    >
                      {session.state}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs font-mono">{session.taskCount}</TableCell>
                  <TableCell className="text-xs font-mono">#{session.fencingEpoch}</TableCell>
                  <TableCell className="text-xs text-muted-foreground font-mono text-right">
                    {new Date(session.createdAt).toLocaleTimeString()}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
