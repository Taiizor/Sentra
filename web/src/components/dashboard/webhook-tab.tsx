import { useState, useEffect } from 'react'
import {
  Webhook,
  ShieldCheck,
  Play,
  Copy,
  Check,
  RefreshCw,
  GitPullRequest,
  FileCode,
  Radio,
  ExternalLink,
  Terminal,
} from 'lucide-react'
import { toast } from 'sonner'
import { copyText } from '@/lib/clipboard'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { fetchWebhookDeliveries, simulateWebhookDispatch } from '@/lib/api-client'
import type { UserRole } from '@/types/sentra'

interface WebhookTabProps {
  currentRole: UserRole
}

const GITHUB_WORKFLOW_YAML = `name: Sentra Continuous Security & Verification CI
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  sentra-security:
    name: Sentra Pure-Rust SAST, Taint & Dependency Audit
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Setup Rust Toolchain
        uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: stable

      - name: Run Sentra Dependency Audit
        run: cargo run --release -p sentra-cli -- audit --json

      - name: Run Sentra SAST & Taint Analysis
        run: cargo run --release -p sentra-cli -- scan --sarif sentra-findings.sarif

      - name: Ingest to GitHub Code Scanning Alerts
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sentra-findings.sarif
          category: sentra-security-engine
`

const GITLAB_CI_YAML = `stages:
  - security-audit

sentra_sast_and_audit:
  stage: security-audit
  image: rust:latest
  script:
    - cargo run --release -p sentra-cli -- scan --sarif sentra-report.sarif
    - cargo run --release -p sentra-cli -- export sarif --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
`

export function WebhookTab({ currentRole }: WebhookTabProps) {
  const [deliveries, setDeliveries] = useState<any[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [isSimulating, setIsSimulating] = useState(false)
  const [activeCiTab, setActiveCiTab] = useState<'github' | 'gitlab'>('github')
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  useEffect(() => {
    loadDeliveries()
  }, [])

  async function loadDeliveries() {
    setIsLoading(true)
    try {
      const data = await fetchWebhookDeliveries()
      setDeliveries(data)
    } finally {
      setIsLoading(false)
    }
  }

  async function handleSimulatePush() {
    setIsSimulating(true)
    try {
      const res = await simulateWebhookDispatch()
      toast.success('Simulated GitHub Webhook Intake Processed', {
        description: `Scanned ${res.delivery?.filesScanned || 0} files. Found ${res.delivery?.findingsDetected || 0} signals.`,
      })
      await loadDeliveries()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Webhook trigger failed.'
      toast.error('Simulation Failed', { description: msg })
    } finally {
      setIsSimulating(false)
    }
  }

  function handleCopy(text: string, key: string, label: string) {
    copyText(text)
    setCopiedKey(key)
    toast.success(`${label} copied to clipboard`)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Sleek Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2 border-b border-border/40">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <Webhook className="size-4 text-violet-400" />
            <h2 className="text-base font-semibold tracking-tight text-foreground">
              CI/CD & Webhook Intake
            </h2>
            <Badge variant="outline" className="text-[11px] px-2 py-0 border-violet-500/30 text-violet-400 bg-violet-500/5">
              Phase 5 Automation
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            HMAC-SHA256 authenticated webhook endpoints for GitHub and GitLab event automation.
          </p>
        </div>

        {/* Action Button */}
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <Button
            size="sm"
            onClick={handleSimulatePush}
            disabled={isSimulating || currentRole === 'Viewer'}
            className="h-8 text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 gap-1.5"
          >
            <Play className={`size-3 fill-current ${isSimulating ? 'animate-spin' : ''}`} />
            <span>{isSimulating ? 'Triggering...' : 'Simulate GitHub Push'}</span>
          </Button>
        </div>
      </div>

      {/* Endpoint & Security Status Ribbon */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {/* Active Listener */}
        <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex items-center justify-between">
          <div className="flex flex-col gap-0.5 min-w-0">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1.5">
              <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Listener Status
            </span>
            <span className="font-mono text-xs font-semibold text-foreground">
              HTTP :3001 Active
            </span>
            <span className="text-[11px] font-mono text-muted-foreground truncate">
              /api/webhook/github
            </span>
          </div>
          <Badge variant="outline" className="text-[10px] font-mono border-emerald-500/30 text-emerald-400 bg-emerald-500/5 shrink-0">
            200 OK
          </Badge>
        </div>

        {/* Signature Verification */}
        <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex items-center justify-between">
          <div className="flex flex-col gap-0.5 min-w-0">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1.5">
              <ShieldCheck className="size-3 text-sky-400" />
              Signature Policy
            </span>
            <span className="font-mono text-xs font-semibold text-foreground">
              HMAC-SHA256
            </span>
            <span className="text-[11px] text-muted-foreground truncate">
              RFC 2104 X-Hub-Signature-256
            </span>
          </div>
          <Badge variant="outline" className="text-[10px] font-mono shrink-0">
            Enforced
          </Badge>
        </div>

        {/* Deliveries Count */}
        <div className="p-3 rounded-lg border border-border/60 bg-card/40 flex items-center justify-between">
          <div className="flex flex-col gap-0.5 min-w-0">
            <span className="text-[10px] uppercase font-semibold text-muted-foreground flex items-center gap-1.5">
              <Radio className="size-3 text-violet-400" />
              Intake History
            </span>
            <span className="font-mono text-xs font-semibold text-foreground">
              {deliveries.length} Deliveries Logged
            </span>
            <span className="text-[11px] text-muted-foreground truncate">
              Automated SAST & Taint Dispatch
            </span>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={loadDeliveries}
            disabled={isLoading}
            className="h-7 text-xs px-2 shrink-0 text-muted-foreground hover:text-foreground"
          >
            <RefreshCw className={`size-3 ${isLoading ? 'animate-spin text-primary' : ''}`} />
          </Button>
        </div>
      </div>

      {/* Deliveries History Card */}
      <Card className="border-border/60 bg-card/40">
        <CardHeader className="py-2.5 px-4 border-b border-border/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Webhook className="size-3.5 text-muted-foreground" />
              <CardTitle className="text-xs font-medium text-foreground">
                Intake Deliveries Ledger
              </CardTitle>
              <span className="text-[11px] text-muted-foreground">
                ({deliveries.length} events)
              </span>
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={loadDeliveries}
              disabled={isLoading}
              className="h-6 text-[11px] px-2 border-border/60 gap-1"
            >
              <RefreshCw className={`size-2.5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </Button>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="border-border/40 hover:bg-transparent">
                  <TableHead className="text-xs font-medium h-9 pl-4">Delivery ID</TableHead>
                  <TableHead className="text-xs font-medium h-9">Provider & Event</TableHead>
                  <TableHead className="text-xs font-medium h-9">Repository & Ref</TableHead>
                  <TableHead className="text-xs font-medium h-9">Sender</TableHead>
                  <TableHead className="text-xs font-medium h-9">Scan Outcome</TableHead>
                  <TableHead className="text-xs font-medium h-9">Status</TableHead>
                  <TableHead className="text-xs font-medium h-9 text-right pr-4">Timestamp</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody className="text-xs">
                {deliveries.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-8 text-xs text-muted-foreground">
                      No webhook deliveries received yet. Click "Simulate GitHub Push" above to trigger a test delivery.
                    </TableCell>
                  </TableRow>
                ) : (
                  deliveries.map((deliv) => (
                    <TableRow key={deliv.deliveryId} className="border-border/40 hover:bg-muted/30">
                      <TableCell className="font-mono text-xs font-semibold text-foreground pl-4 py-2.5">
                        {deliv.deliveryId}
                      </TableCell>
                      <TableCell className="py-2.5">
                        <div className="flex items-center gap-1.5">
                          <Badge variant="outline" className="text-[10px] uppercase font-mono px-1.5 py-0">
                            {deliv.provider}
                          </Badge>
                          <Badge variant="secondary" className="text-[10px] font-mono px-1.5 py-0">
                            {deliv.eventType}
                          </Badge>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-foreground/90 py-2.5">
                        <div className="truncate max-w-[200px]">{deliv.repository}</div>
                        <div className="text-[10px] text-muted-foreground truncate">{deliv.ref}</div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground py-2.5">
                        @{deliv.sender}
                      </TableCell>
                      <TableCell className="py-2.5">
                        <div className="flex items-center gap-1.5">
                          <span className="font-mono text-xs text-foreground/90">
                            {deliv.filesScanned} files
                          </span>
                          {deliv.findingsDetected > 0 ? (
                            <Badge className="bg-rose-500/15 text-rose-400 border-rose-500/30 text-[10px] px-1.5 py-0">
                              {deliv.findingsDetected} signals ({deliv.criticalCount} crit)
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-500/30 px-1.5 py-0">
                              Clean
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="py-2.5">
                        <Badge variant="outline" className="text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border-emerald-500/30 px-1.5 py-0">
                          200 OK
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground text-right pr-4 py-2.5">
                        {new Date(deliv.timestamp).toLocaleTimeString()}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* CI/CD Template Generator Card */}
      <Card className="border-border/60 bg-card/40">
        <CardHeader className="py-2.5 px-4 border-b border-border/40">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <FileCode className="size-3.5 text-muted-foreground" />
              <CardTitle className="text-xs font-medium text-foreground">
                CI/CD Pipeline Configurations
              </CardTitle>
            </div>

            <div className="flex items-center gap-2">
              {/* Tab Selector */}
              <div className="flex items-center bg-background/50 border border-border/60 rounded p-0.5 text-xs">
                <button
                  type="button"
                  onClick={() => setActiveCiTab('github')}
                  className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                    activeCiTab === 'github'
                      ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                >
                  GitHub Actions
                </button>
                <button
                  type="button"
                  onClick={() => setActiveCiTab('gitlab')}
                  className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
                    activeCiTab === 'gitlab'
                      ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                >
                  GitLab CI
                </button>
              </div>

              {/* Copy Button */}
              <Button
                variant="outline"
                size="sm"
                onClick={() =>
                  handleCopy(
                    activeCiTab === 'github' ? GITHUB_WORKFLOW_YAML : GITLAB_CI_YAML,
                    activeCiTab,
                    activeCiTab === 'github' ? 'GitHub Actions YAML' : 'GitLab CI YAML'
                  )
                }
                className="h-6 text-[11px] px-2 border-border/60 gap-1"
              >
                {copiedKey === activeCiTab ? (
                  <Check className="size-2.5 text-emerald-400" />
                ) : (
                  <Copy className="size-2.5" />
                )}
                <span>Copy YAML</span>
              </Button>
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-3">
          <pre className="font-mono text-xs bg-background/60 border border-border/40 rounded-md p-3 overflow-x-auto text-muted-foreground leading-relaxed max-h-[220px]">
            {activeCiTab === 'github' ? GITHUB_WORKFLOW_YAML : GITLAB_CI_YAML}
          </pre>
        </CardContent>
      </Card>
    </div>
  )
}
