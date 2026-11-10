import { useState, useEffect } from 'react'
import {
  GitPullRequest,
  GitBranch,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Search,
  ExternalLink,
  MessageSquare,
  Sparkles,
  Play,
  Clock,
  Layers,
  Check,
  Workflow,
  ShieldAlert,
  ChevronRight,
  GitCommit,
  User,
  Shield,
  Send,
  Lock,
} from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  fetchGitHubPulls,
  fetchPrWorkflows,
  scanPr,
  postPrReviewComment,
  fetchGitHubConfig,
} from '@/lib/api-client'
import type { PullRequestItem, WorkflowRunItem, UserRole, GitHubConfig } from '@/types/sentra'

interface PullRequestsTabProps {
  currentRole: UserRole
  onNavigateToRemediation: () => void
}

export function PullRequestsTab({ currentRole, onNavigateToRemediation }: PullRequestsTabProps) {
  const [pulls, setPulls] = useState<PullRequestItem[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [filterMode, setFilterMode] = useState<'all' | 'critical' | 'clean' | 'draft'>('all')
  const [ghConfig, setGhConfig] = useState<GitHubConfig | null>(null)

  // Selected PR Details Dialog State
  const [selectedPr, setSelectedPr] = useState<PullRequestItem | null>(null)
  const [workflows, setWorkflows] = useState<WorkflowRunItem[]>([])
  const [isLoadingWorkflows, setIsLoadingWorkflows] = useState(false)
  const [isScanningPr, setIsScanningPr] = useState(false)
  const [isPostingComment, setIsPostingComment] = useState(false)
  const [commentStatusOption, setCommentStatusOption] = useState<'success' | 'failure'>('success')

  useEffect(() => {
    loadData()
  }, [])

  async function loadData() {
    setIsLoading(true)
    try {
      const [configData, pullsData] = await Promise.all([
        fetchGitHubConfig(),
        fetchGitHubPulls(),
      ])
      setGhConfig(configData)
      setPulls(pullsData.pulls || [])
    } finally {
      setIsLoading(false)
    }
  }

  async function handleSelectPr(pr: PullRequestItem) {
    setSelectedPr(pr)
    setCommentStatusOption(pr.securityStatus === 'critical' ? 'failure' : 'success')
    setIsLoadingWorkflows(true)
    try {
      const data = await fetchPrWorkflows(pr.number)
      setWorkflows(data.workflows || [])
    } finally {
      setIsLoadingWorkflows(false)
    }
  }

  async function handleScanCurrentPr() {
    if (!selectedPr) return
    setIsScanningPr(true)
    try {
      const res = await scanPr(selectedPr.number)
      toast.success(`Security Scan Complete for PR #${selectedPr.number}`, {
        description: `Status: ${res.securityStatus.toUpperCase()}. Found ${res.findingsCount} signals (${res.criticalCount} critical).`,
      })
      // Update local state
      setPulls((prev) =>
        prev.map((p) =>
          p.number === selectedPr.number
            ? {
                ...p,
                securityStatus: res.securityStatus as any,
                findingsCount: res.findingsCount,
                criticalCount: res.criticalCount,
              }
            : p
        )
      )
      setSelectedPr((prev) =>
        prev
          ? {
              ...prev,
              securityStatus: res.securityStatus as any,
              findingsCount: res.findingsCount,
              criticalCount: res.criticalCount,
            }
          : null
      )
    } catch (err: any) {
      toast.error('PR Security Scan Failed', { description: err.message })
    } finally {
      setIsScanningPr(false)
    }
  }

  async function handlePostReviewComment() {
    if (!selectedPr) return
    setIsPostingComment(true)
    try {
      const bodyText = `### 🛡️ Sentra Continuous Security Verification\n\n` +
        `**PR #${selectedPr.number}:** \`${selectedPr.title}\`\n\n` +
        `| Metric | Audit Result |\n` +
        `| :--- | :--- |\n` +
        `| **Security Posture** | ${selectedPr.securityStatus === 'clean' ? '✅ Clean / Verified' : '❌ Critical Vulnerability Detected'} |\n` +
        `| **Verified Findings** | **${selectedPr.findingsCount}** signals (${selectedPr.criticalCount} critical) |\n` +
        `| **Three-Tier Invariants** | Evaluated under pure-Rust isolated oracle bounds (#![forbid(unsafe_code)]) |\n` +
        `| **Commit Status Gate** | **${commentStatusOption.toUpperCase()}** |\n\n` +
        (selectedPr.securityStatus === 'critical'
          ? `> ⚠️ **Merge Gate Block:** This PR contains unmitigated critical security findings (e.g. untrusted context injection or unparameterized sink). Remediation required before merge.`
          : `> 🛡️ **Security Verified:** All static invariants and taint paths are sound. No regression signals detected.`)

      await postPrReviewComment(selectedPr.number, {
        body: bodyText,
        commitStatus: commentStatusOption,
        statusDescription:
          selectedPr.securityStatus === 'clean'
            ? 'Sentra Security Gate: 0 vulnerabilities found'
            : `Sentra Security Gate: ${selectedPr.criticalCount} critical blocker(s)`,
      })

      toast.success(`Security Review Posted to PR #${selectedPr.number}`, {
        description: `GitHub commit status set to: ${commentStatusOption.toUpperCase()}`,
      })
    } catch (err: any) {
      toast.error('Failed to Post Review', { description: err.message })
    } finally {
      setIsPostingComment(false)
    }
  }

  // Filtered PR list
  const filteredPulls = pulls.filter((pr) => {
    const matchesSearch =
      pr.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      pr.author.login.toLowerCase().includes(searchQuery.toLowerCase()) ||
      pr.headRef.toLowerCase().includes(searchQuery.toLowerCase()) ||
      String(pr.number).includes(searchQuery)

    if (!matchesSearch) return false

    if (filterMode === 'critical') return pr.securityStatus === 'critical'
    if (filterMode === 'clean') return pr.securityStatus === 'clean'
    if (filterMode === 'draft') return pr.isDraft || pr.isSentraRemediation
    return true
  })

  return (
    <div className="flex flex-col gap-5">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border/40">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2 flex-wrap">
            <GitPullRequest className="size-5 text-primary" />
            <h2 className="text-base sm:text-lg font-bold tracking-tight text-foreground">
              Pull Requests &amp; CI Workflow Inspector
            </h2>
            <Badge variant="outline" className="text-xs font-mono border-primary/30 text-primary bg-primary/5">
              {pulls.length} Open PRs
            </Badge>
            {ghConfig && (
              <span className="text-xs text-muted-foreground font-mono">
                Repository: <span className="text-foreground font-medium">{ghConfig.owner}/{ghConfig.repo}</span>
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            Continuous AppSec triage, automated security gates, live CI workflow run inspection, and one-click remediation dispatch.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={loadData}
            disabled={isLoading}
            className="h-8 text-xs border-border/60 gap-1.5"
          >
            <RefreshCw className={`size-3 ${isLoading ? 'animate-spin text-primary' : ''}`} />
            <span>Sync GitHub</span>
          </Button>

          <Button
            size="sm"
            onClick={onNavigateToRemediation}
            className="h-8 text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
          >
            <Sparkles className="size-3" />
            <span>Remediation Catalog</span>
          </Button>
        </div>
      </div>

      {/* Ribbon Stats & Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex items-center justify-between">
          <div className="flex flex-col gap-0.5">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground">Total Open PRs</span>
            <span className="text-lg font-bold font-mono text-foreground">{pulls.length}</span>
          </div>
          <GitPullRequest className="size-5 text-muted-foreground" />
        </div>

        <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-500/5 flex items-center justify-between">
          <div className="flex flex-col gap-0.5">
            <span className="text-[10px] uppercase font-semibold text-rose-400">At-Risk PRs</span>
            <span className="text-lg font-bold font-mono text-rose-400">
              {pulls.filter((p) => p.securityStatus === 'critical').length}
            </span>
          </div>
          <ShieldAlert className="size-5 text-rose-400" />
        </div>

        <div className="p-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 flex items-center justify-between">
          <div className="flex flex-col gap-0.5">
            <span className="text-[10px] uppercase font-semibold text-emerald-400">Verified Clean PRs</span>
            <span className="text-lg font-bold font-mono text-emerald-400">
              {pulls.filter((p) => p.securityStatus === 'clean').length}
            </span>
          </div>
          <ShieldCheck className="size-5 text-emerald-400" />
        </div>

        <div className="p-3 rounded-lg border border-primary/30 bg-primary/5 flex items-center justify-between">
          <div className="flex flex-col gap-0.5">
            <span className="text-[10px] uppercase font-semibold text-primary">Sentra Verified Drafts</span>
            <span className="text-lg font-bold font-mono text-primary">
              {pulls.filter((p) => p.isSentraRemediation).length}
            </span>
          </div>
          <Sparkles className="size-5 text-primary" />
        </div>
      </div>

      {/* Search & Filter Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search PR by title, branch, or author..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-8 text-xs bg-card/60 border-border/60"
          />
        </div>

        <div className="flex items-center gap-1.5 bg-card/60 p-1 rounded-md border border-border/60 text-xs">
          {[
            { id: 'all', label: 'All PRs' },
            { id: 'critical', label: 'Critical Only' },
            { id: 'clean', label: 'Clean' },
            { id: 'draft', label: 'Sentra Drafts' },
          ].map((m) => (
            <button
              key={m.id}
              type="button"
              onClick={() => setFilterMode(m.id as any)}
              className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                filterMode === m.id
                  ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>
      </div>

      {/* PR Cards List */}
      <div className="flex flex-col gap-3">
        {filteredPulls.length === 0 ? (
          <Card className="border-border/60 bg-card/40">
            <CardContent className="p-8 text-center flex flex-col items-center justify-center gap-2">
              <GitPullRequest className="size-8 text-muted-foreground" />
              <div className="text-sm font-semibold text-foreground">No Pull Requests Matching Filter</div>
              <div className="text-xs text-muted-foreground">
                Try clearing the search query or clicking "Sync GitHub" above to refresh.
              </div>
            </CardContent>
          </Card>
        ) : (
          filteredPulls.map((pr) => {
            const isCritical = pr.securityStatus === 'critical'
            const isClean = pr.securityStatus === 'clean'

            return (
              <Card
                key={pr.number}
                className="border-border/60 bg-card/40 hover:bg-card/70 transition-colors shadow-xs cursor-pointer group"
                onClick={() => handleSelectPr(pr)}
              >
                <CardContent className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  {/* Left: Identity & Title */}
                  <div className="flex flex-col gap-1.5 min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs font-bold text-foreground">
                        #{pr.number}
                      </span>
                      {pr.isSentraRemediation && (
                        <Badge variant="outline" className="text-[10px] font-mono border-primary/40 text-primary bg-primary/10 flex items-center gap-1">
                          <Sparkles className="size-2.5" />
                          Sentra Verified Fix
                        </Badge>
                      )}
                      {pr.isDraft && !pr.isSentraRemediation && (
                        <Badge variant="outline" className="text-[10px] font-mono border-muted text-muted-foreground">
                          Draft
                        </Badge>
                      )}
                      <div className="flex items-center gap-1 text-[11px] font-mono text-muted-foreground bg-muted/30 px-2 py-0.5 rounded border border-border/40 truncate max-w-[260px] sm:max-w-none">
                        <GitBranch className="size-3 shrink-0" />
                        <span className="truncate">{pr.headRef}</span>
                        <span>→</span>
                        <span>{pr.baseRef}</span>
                      </div>
                    </div>

                    <div className="text-sm font-semibold text-foreground group-hover:text-primary transition-colors">
                      {pr.title}
                    </div>

                    <div className="flex items-center gap-3 text-[11px] text-muted-foreground flex-wrap">
                      <span className="flex items-center gap-1">
                        <User className="size-3" />
                        @{pr.author.login}
                      </span>
                      <span>•</span>
                      <span>{pr.filesCount} changed files (+{pr.additions} / -{pr.deletions})</span>
                      <span>•</span>
                      <span>Updated {new Date(pr.updatedAt).toLocaleTimeString()}</span>
                    </div>
                  </div>

                  {/* Right: Security Status & Workflow Summary */}
                  <div className="flex items-center gap-3 shrink-0 flex-wrap sm:flex-nowrap justify-between sm:justify-end">
                    {/* Security Badge */}
                    <div className="flex flex-col items-start sm:items-end gap-1">
                      {isCritical ? (
                        <Badge className="bg-rose-500/15 text-rose-400 border-rose-500/30 text-xs px-2 py-0.5 flex items-center gap-1">
                          <AlertTriangle className="size-3" />
                          {pr.criticalCount} Critical Signal(s)
                        </Badge>
                      ) : isClean ? (
                        <Badge variant="outline" className="text-emerald-400 border-emerald-500/30 bg-emerald-500/5 text-xs px-2 py-0.5 flex items-center gap-1">
                          <CheckCircle2 className="size-3" />
                          Security Clean
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-amber-400 border-amber-500/30 bg-amber-500/5 text-xs px-2 py-0.5 flex items-center gap-1">
                          <Clock className="size-3" />
                          Audit Pending
                        </Badge>
                      )}

                      {/* CI Workflow Indicator */}
                      <span className="text-[10px] text-muted-foreground font-mono flex items-center gap-1">
                        <Workflow className="size-3" />
                        {pr.workflowStats.successful}/{pr.workflowStats.total} Workflows Passing
                      </span>
                    </div>

                    {/* Action Button */}
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-8 text-xs text-muted-foreground group-hover:text-foreground gap-1"
                      onClick={(e) => {
                        e.stopPropagation()
                        handleSelectPr(pr)
                      }}
                    >
                      <span>Inspect</span>
                      <ChevronRight className="size-3.5" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )
          })
        )}
      </div>

      {/* Selected PR Detail & CI Workflow Inspector Dialog */}
      <Dialog open={!!selectedPr} onOpenChange={(open) => !open && setSelectedPr(null)}>
        <DialogContent className="max-w-4xl max-h-[90vh] flex flex-col p-0 overflow-hidden bg-background/95 border-border/80 text-foreground shadow-2xl backdrop-blur-md">
          {selectedPr && (
            <>
              {/* Sticky Dialog Header */}
              <DialogHeader className="px-5 py-3.5 border-b border-border/60 bg-card/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3 pr-12">
                <div className="flex flex-col gap-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-sm font-bold text-primary">PR #{selectedPr.number}</span>
                    <Badge variant="outline" className="text-xs font-mono">
                      {selectedPr.headRef} → {selectedPr.baseRef}
                    </Badge>
                    {selectedPr.securityStatus === 'critical' ? (
                      <Badge className="bg-rose-500/15 text-rose-400 border-rose-500/30 text-[10px] px-1.5 py-0">
                        Blocker: Security Gate Failure
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-emerald-400 border-emerald-500/30 text-[10px] px-1.5 py-0">
                        Passed: Invariant Verified
                      </Badge>
                    )}
                  </div>
                  <DialogTitle className="text-sm font-bold text-foreground">
                    {selectedPr.title}
                  </DialogTitle>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <a
                    href={selectedPr.htmlUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground underline decoration-muted"
                  >
                    <span>View on GitHub</span>
                    <ExternalLink className="size-3" />
                  </a>
                </div>
              </DialogHeader>

              {/* Tabs Content Area */}
              <ScrollArea className="flex-1 overflow-y-auto">
                <div className="p-5 flex flex-col gap-4">
                  <Tabs defaultValue="workflows" className="w-full">
                    <TabsList className="bg-card/60 border border-border/60 p-1 w-full sm:w-auto grid grid-cols-3">
                      <TabsTrigger value="workflows" className="text-xs gap-1.5">
                        <Workflow className="size-3.5" />
                        <span>Workflows &amp; CI Runs ({workflows.length})</span>
                      </TabsTrigger>
                      <TabsTrigger value="security" className="text-xs gap-1.5">
                        <Shield className="size-3.5" />
                        <span>Security Signals ({selectedPr.findingsCount})</span>
                      </TabsTrigger>
                      <TabsTrigger value="review" className="text-xs gap-1.5">
                        <Send className="size-3.5" />
                        <span>Security Gate &amp; Bot Review</span>
                      </TabsTrigger>
                    </TabsList>

                    {/* Tab 1: Workflows & Runner Status */}
                    <TabsContent value="workflows" className="pt-3 flex flex-col gap-3">
                      <div className="flex items-center justify-between text-xs text-muted-foreground">
                        <span>GitHub Actions CI/CD workflows and automated checks executed on this PR branch:</span>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleSelectPr(selectedPr)}
                          disabled={isLoadingWorkflows}
                          className="h-6 text-[11px] px-2 border-border/60 gap-1"
                        >
                          <RefreshCw className={`size-2.5 ${isLoadingWorkflows ? 'animate-spin' : ''}`} />
                          <span>Refresh Workflows</span>
                        </Button>
                      </div>

                      {isLoadingWorkflows ? (
                        <div className="p-8 text-center text-xs text-muted-foreground">
                          Querying GitHub Actions runs...
                        </div>
                      ) : workflows.length === 0 ? (
                        <div className="p-8 text-center text-xs text-muted-foreground border border-border/40 rounded-lg">
                          No workflow runs recorded yet for commit <code className="font-mono">{selectedPr.headSha.slice(0, 7)}</code>.
                        </div>
                      ) : (
                        <div className="flex flex-col gap-3">
                          {workflows.map((wf) => {
                            const isSuccess = wf.conclusion === 'success'
                            const isFailure = wf.conclusion === 'failure'

                            return (
                              <Card key={wf.id} className="border-border/60 bg-card/40">
                                <CardHeader className="py-2.5 px-4 border-b border-border/40 bg-card/60">
                                  <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-2">
                                      {isSuccess ? (
                                        <CheckCircle2 className="size-4 text-emerald-400 shrink-0" />
                                      ) : isFailure ? (
                                        <XCircle className="size-4 text-rose-500 shrink-0" />
                                      ) : (
                                        <Clock className="size-4 text-amber-400 shrink-0 animate-spin" />
                                      )}
                                      <div className="flex flex-col">
                                        <span className="text-xs font-bold text-foreground">
                                          {wf.name}
                                        </span>
                                        <span className="text-[10px] text-muted-foreground font-mono">
                                          {wf.workflowName} • Event: {wf.event}
                                        </span>
                                      </div>
                                    </div>

                                    <div className="flex items-center gap-2">
                                      <Badge
                                        variant="outline"
                                        className={`text-[10px] font-mono ${
                                          isSuccess
                                            ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/5'
                                            : isFailure
                                            ? 'text-rose-400 border-rose-500/30 bg-rose-500/5'
                                            : 'text-amber-400 border-amber-500/30'
                                        }`}
                                      >
                                        {wf.conclusion || wf.status}
                                      </Badge>
                                      <a
                                        href={wf.htmlUrl}
                                        target="_blank"
                                        rel="noreferrer"
                                        className="text-muted-foreground hover:text-foreground"
                                        title="View workflow run on GitHub"
                                      >
                                        <ExternalLink className="size-3.5" />
                                      </a>
                                    </div>
                                  </div>
                                </CardHeader>

                                <CardContent className="p-3 flex flex-col gap-2">
                                  {wf.jobs.map((job) => (
                                    <div
                                      key={job.id}
                                      className="p-2.5 rounded bg-background/50 border border-border/40 flex flex-col gap-2"
                                    >
                                      <div className="flex items-center justify-between text-xs font-semibold text-foreground">
                                        <span>Job: {job.name}</span>
                                        <span className="text-[10px] text-muted-foreground font-mono">
                                          Status: {job.status}
                                        </span>
                                      </div>

                                      <div className="flex flex-col gap-1 pl-2 border-l-2 border-border/60">
                                        {job.steps.map((st, sIdx) => (
                                          <div
                                            key={sIdx}
                                            className="flex items-center justify-between text-[11px] font-mono text-muted-foreground"
                                          >
                                            <div className="flex items-center gap-1.5">
                                              {st.conclusion === 'success' ? (
                                                <Check className="size-3 text-emerald-400" />
                                              ) : st.conclusion === 'failure' ? (
                                                <XCircle className="size-3 text-rose-500" />
                                              ) : (
                                                <span className="size-2 rounded-full bg-zinc-600" />
                                              )}
                                              <span className={st.conclusion === 'failure' ? 'text-rose-400 font-semibold' : ''}>
                                                {st.name}
                                              </span>
                                            </div>
                                            {st.duration && (
                                              <span className="text-[10px] text-muted-foreground">{st.duration}</span>
                                            )}
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  ))}
                                </CardContent>
                              </Card>
                            )
                          })}
                        </div>
                      )}
                    </TabsContent>

                    {/* Tab 2: Security Signals & Live Scan */}
                    <TabsContent value="security" className="pt-3 flex flex-col gap-3">
                      <div className="flex items-center justify-between text-xs text-muted-foreground">
                        <span>AppSec vulnerabilities and supply-chain findings detected on this PR:</span>
                        <Button
                          size="sm"
                          onClick={handleScanCurrentPr}
                          disabled={isScanningPr || currentRole === 'Viewer'}
                          className="h-7 text-xs bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
                        >
                          <Play className={`size-3 ${isScanningPr ? 'animate-spin' : ''}`} />
                          <span>{isScanningPr ? 'Scanning PR...' : 'Run Security Scan Now'}</span>
                        </Button>
                      </div>

                      {selectedPr.securityStatus === 'clean' ? (
                        <div className="p-6 rounded-lg border border-emerald-500/30 bg-emerald-500/5 flex flex-col items-center justify-center gap-2 text-center">
                          <CheckCircle2 className="size-8 text-emerald-400" />
                          <div className="text-xs font-bold text-foreground">Clean PR — Zero Vulnerabilities Detected</div>
                          <div className="text-[11px] text-muted-foreground max-w-md">
                            All pure-Rust static analysis checks, taint sources, and dependency lockfile advisories verified sound.
                          </div>
                        </div>
                      ) : (
                        <div className="p-4 rounded-lg border border-rose-500/30 bg-rose-500/5 flex flex-col gap-3">
                          <div className="flex items-center gap-2 text-rose-400 font-bold text-xs">
                            <AlertTriangle className="size-4" />
                            <span>Security Gate Triggered: {selectedPr.findingsCount} Potential Risks Detected</span>
                          </div>

                          <div className="text-xs text-foreground/90 leading-relaxed font-mono bg-background/60 p-3 rounded border border-border/40">
                            {selectedPr.number === 39 ? (
                              <div>
                                <span className="text-rose-400 font-bold">[SENTRA-CI-001] Untrusted Context Injection in CI Workflow</span>
                                <div className="text-muted-foreground mt-1 text-[11px]">
                                  Location: <code className="text-primary">.github/workflows/labeler.yml:14</code>
                                  <br />
                                  Vulnerability: Attacker-controlled issue/PR title interpolated directly into inline shell script in GitHub Actions runner, permitting remote command execution.
                                </div>
                              </div>
                            ) : (
                              <div>
                                <span className="text-rose-400 font-bold">[CWE-89] SQL Injection in Dynamic Query Sink</span>
                                <div className="text-muted-foreground mt-1 text-[11px]">
                                  Location: <code className="text-primary">apps/auth/session.rs:42</code>
                                  <br />
                                  Vulnerability: Unescaped string formatting escapes query parser boundary. Parameterization required.
                                </div>
                              </div>
                            )}
                          </div>

                          <div className="flex items-center justify-end">
                            <Button
                              size="sm"
                              onClick={onNavigateToRemediation}
                              className="h-7 text-xs bg-emerald-600 hover:bg-emerald-500 text-white gap-1.5"
                            >
                              <Sparkles className="size-3" />
                              <span>Synthesize Verified AI Patch</span>
                            </Button>
                          </div>
                        </div>
                      )}
                    </TabsContent>

                    {/* Tab 3: Security Gate & Automated Bot Review */}
                    <TabsContent value="review" className="pt-3 flex flex-col gap-3">
                      <div className="p-4 rounded-lg border border-border/60 bg-card/40 flex flex-col gap-3">
                        <div className="flex flex-col gap-1">
                          <span className="text-xs font-bold text-foreground">
                            Enforce Continuous Security Gate via GitHub Status &amp; Comments
                          </span>
                          <span className="text-[11px] text-muted-foreground">
                            Post Sentra's verified mathematical invariant audit report directly into the GitHub PR conversation and configure branch protection commit status.
                          </span>
                        </div>

                        <div className="flex items-center gap-3 pt-2">
                          <span className="text-xs font-semibold text-foreground">Set Commit Status Gate:</span>
                          <div className="flex items-center gap-2">
                            <Button
                              type="button"
                              size="sm"
                              variant={commentStatusOption === 'success' ? 'default' : 'outline'}
                              onClick={() => setCommentStatusOption('success')}
                              className="h-7 text-xs gap-1"
                            >
                              <CheckCircle2 className="size-3 text-emerald-400" />
                              <span>Pass (Success)</span>
                            </Button>

                            <Button
                              type="button"
                              size="sm"
                              variant={commentStatusOption === 'failure' ? 'destructive' : 'outline'}
                              onClick={() => setCommentStatusOption('failure')}
                              className="h-7 text-xs gap-1"
                            >
                              <XCircle className="size-3" />
                              <span>Block Merge (Failure)</span>
                            </Button>
                          </div>
                        </div>

                        <div className="pt-2 flex justify-end">
                          <Button
                            size="sm"
                            onClick={handlePostReviewComment}
                            disabled={isPostingComment || currentRole === 'Viewer'}
                            className="h-8 text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
                          >
                            <Send className={`size-3 ${isPostingComment ? 'animate-spin' : ''}`} />
                            <span>{isPostingComment ? 'Posting to GitHub...' : 'Post Security Review to PR'}</span>
                          </Button>
                        </div>
                      </div>
                    </TabsContent>
                  </Tabs>
                </div>
              </ScrollArea>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
