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
} from 'lucide-react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
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

export function OverviewTab({ overview, sessions, trends, onSelectTab }: OverviewTabProps) {
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
    <div className="flex flex-col gap-5">
      {/* Primary Threat Posture Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
        {/* Security Posture Score */}
        <Card
          className="border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900/70 hover:border-primary/40 transition-all cursor-pointer shadow-xs"
          onClick={() => onSelectTab('findings')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-1.5 pt-3.5 px-4">
            <CardTitle className="text-xs font-medium text-zinc-400">
              Security Score
            </CardTitle>
            <Activity className={`size-4 ${scoreColor}`} />
          </CardHeader>
          <CardContent className="px-4 pb-3.5 pt-0">
            <div className={`text-2xl font-bold ${scoreColor}`}>
              {overview.securityScore} <span className="text-xs text-zinc-500 font-normal">/ 100</span>
            </div>
            <div className="text-[11px] text-zinc-400 mt-1 flex items-center gap-1.5">
              <Badge variant={gradeBadgeVariant} className="text-[10px] h-4 px-1.5 font-bold">
                {grade}
              </Badge>
              <span className="truncate">{overview.securityScore >= 75 ? 'Verified Posture' : 'Action Required'}</span>
            </div>
          </CardContent>
        </Card>

        {/* Total Sessions */}
        <Card
          className="border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900/70 hover:border-primary/40 transition-all cursor-pointer shadow-xs"
          onClick={() => onSelectTab('fleet')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-1.5 pt-3.5 px-4">
            <CardTitle className="text-xs font-medium text-zinc-400">
              Workspace Sessions
            </CardTitle>
            <FolderGit2 className="size-4 text-zinc-400" />
          </CardHeader>
          <CardContent className="px-4 pb-3.5 pt-0">
            <div className="text-2xl font-bold text-zinc-100">{overview.totalSessions}</div>
            <p className="text-[11px] text-zinc-400 mt-1 truncate">
              {overview.activeSessions} active scoped instance(s)
            </p>
          </CardContent>
        </Card>

        {/* Security Findings */}
        <Card
          className="border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900/70 hover:border-rose-500/40 transition-all cursor-pointer shadow-xs"
          onClick={() => onSelectTab('findings')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-1.5 pt-3.5 px-4">
            <CardTitle className="text-xs font-medium text-zinc-400">
              Vulnerabilities
            </CardTitle>
            <AlertTriangle className="size-4 text-rose-500" />
          </CardHeader>
          <CardContent className="px-4 pb-3.5 pt-0">
            <div className="text-2xl font-bold flex items-center gap-2">
              <span className="text-zinc-100">{totalFindings}</span>
              {overview.criticalFindings > 0 && (
                <Badge variant="destructive" className="text-[10px] h-4 px-1.5">
                  {overview.criticalFindings} Critical
                </Badge>
              )}
            </div>
            <p className="text-[11px] text-zinc-400 mt-1 truncate">
              {overview.highFindings} high, {overview.mediumFindings} medium
            </p>
          </CardContent>
        </Card>

        {/* Verified Patches */}
        <Card
          className="border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900/70 hover:border-emerald-500/40 transition-all cursor-pointer shadow-xs"
          onClick={() => onSelectTab('remediation')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-1.5 pt-3.5 px-4">
            <CardTitle className="text-xs font-medium text-zinc-400">
              Verified Patches
            </CardTitle>
            <CheckCircle2 className="size-4 text-emerald-400" />
          </CardHeader>
          <CardContent className="px-4 pb-3.5 pt-0">
            <div className="text-2xl font-bold text-emerald-400">
              {overview.verifiedPatches}
            </div>
            <p className="text-[11px] text-zinc-400 mt-1 truncate">
              Dual-state oracle verified
            </p>
          </CardContent>
        </Card>

        {/* Budget Spend */}
        <Card
          className="border-zinc-800/80 bg-zinc-900/40 hover:bg-zinc-900/70 hover:border-amber-500/40 transition-all cursor-pointer shadow-xs"
          onClick={() => onSelectTab('research')}
        >
          <CardHeader className="flex flex-row items-center justify-between pb-1.5 pt-3.5 px-4">
            <CardTitle className="text-xs font-medium text-zinc-400">
              Research Tokens
            </CardTitle>
            <Coins className="size-4 text-amber-400" />
          </CardHeader>
          <CardContent className="px-4 pb-3.5 pt-0">
            <div className="text-2xl font-bold text-zinc-100 font-mono">
              ${(overview.totalSpentMicroUsd / 1_000_000).toFixed(2)}
            </div>
            <p className="text-[11px] text-zinc-400 mt-1 flex items-center gap-1 truncate">
              <History className="size-3 shrink-0" />
              <span>{overview.auditEventCount} immutable audit logs</span>
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Two Column Layout: Recharts Threat Trend & CWE Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Recharts Area Chart: 14-Day Vulnerability Trend */}
        <Card className="lg:col-span-8 border-zinc-800/80 bg-zinc-900/40">
          <CardHeader className="pb-2 pt-4 px-4 sm:px-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex flex-col">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <TrendingUp className="size-4 text-primary" />
                  Vulnerability Velocity &amp; Remediation Rate
                </CardTitle>
                <CardDescription className="text-xs text-zinc-400">
                  Historical telemetry showing signals detected vs verified remediations over time
                </CardDescription>
              </div>
              <Badge variant="secondary" className="text-xs font-mono self-start sm:self-auto">
                MTTR: 4.2 min
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="pt-2 px-3 sm:px-4 pb-4">
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
        <Card className="lg:col-span-4 border-zinc-800/80 bg-zinc-900/40 flex flex-col justify-between">
          <CardHeader className="pb-2 pt-4 px-4 sm:px-5">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Layers className="size-4 text-primary" />
              Attack Surface Breakdown
            </CardTitle>
            <CardDescription className="text-xs text-zinc-400">
              Normalized SAST, Taint, and Dependency signals
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 pt-2 px-4 sm:px-5 pb-4">
            {/* Critical */}
            <div className="flex flex-col gap-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium flex items-center gap-1.5 text-rose-400">
                  <span className="size-2 rounded-full bg-rose-500" />
                  Critical Severity
                </span>
                <span className="font-mono text-zinc-400">
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
                <span className="font-mono text-zinc-400">
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
                <span className="font-mono text-zinc-400">
                  {overview.mediumFindings} ({mediumPercent}%)
                </span>
              </div>
              <Progress value={mediumPercent} className="h-1.5" />
            </div>

            {/* CWE Tags */}
            <div className="border-t border-zinc-800/80 pt-3 mt-1 flex flex-wrap gap-1.5">
              <Badge variant="outline" className="text-[10px] font-mono text-zinc-400 border-zinc-800">
                CWE-89 SQLi
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono text-zinc-400 border-zinc-800">
                CWE-78 Cmd Injection
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono text-zinc-400 border-zinc-800">
                CWE-798 Secrets
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono text-zinc-400 border-zinc-800">
                CWE-22 Traversal
              </Badge>
              <Badge variant="outline" className="text-[10px] font-mono text-zinc-400 border-zinc-800">
                CWE-1321 Proto
              </Badge>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Active Workspace Sessions */}
      <Card className="border-zinc-800/80 bg-zinc-900/40">
        <CardHeader className="pt-4 pb-2 px-4 sm:px-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex flex-col">
              <CardTitle className="text-sm font-semibold">
                Active Workspace Sessions
              </CardTitle>
              <CardDescription className="text-xs text-zinc-400">
                Audit-backed deterministic workspace snapshots with CAS storage
              </CardDescription>
            </div>
            <Badge variant="outline" className="text-[10px] font-mono shrink-0 self-start sm:self-auto text-zinc-400 border-zinc-800">
              WAL Journal
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="px-4 sm:px-5 pb-4">
          <div className="overflow-x-auto">
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
                    <TableCell className="font-mono text-xs font-semibold whitespace-nowrap">
                      {session.sessionId}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-zinc-400 truncate max-w-[320px]">
                      {session.workspaceRoot}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={session.state === 'SCOPED' ? 'secondary' : 'outline'}
                        className="text-[10px] font-mono"
                      >
                        {session.state}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs font-mono">{session.taskCount}</TableCell>
                    <TableCell className="text-xs font-mono">#{session.fencingEpoch}</TableCell>
                    <TableCell className="text-xs text-zinc-400 font-mono text-right">
                      {new Date(session.createdAt).toLocaleTimeString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
