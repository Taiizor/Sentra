import { useState, useEffect } from 'react'
import {
  Webhook,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Play,
  Copy,
  Check,
  RefreshCw,
  GitPullRequest,
  GitBranch,
  Terminal,
  ExternalLink,
  Layers,
  FileCode,
  Radio,
} from 'lucide-react'
import { toast } from 'sonner'
import { copyText } from '@/lib/clipboard'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
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

      - name: Setup Rust Toolchain (Zero Unsafe Invariant)
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
    } catch (err: any) {
      toast.error('Simulation Failed', {
        description: err.message || 'Webhook trigger failed.',
      })
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
    <div className="flex flex-col gap-6">
      {/* Phase 5 Header Banner */}
      <Alert className="border-primary/30 bg-primary/5">
        <Webhook className="size-5 text-primary" />
        <AlertTitle className="text-sm font-semibold flex items-center justify-between">
          <span>Continuous Integration Webhook Intake &amp; Hosted Automations</span>
          <Badge variant="outline" className="text-xs font-mono">
            Roadmap Phase 5
          </Badge>
        </AlertTitle>
        <AlertDescription className="text-xs text-muted-foreground mt-1">
          Sentra exposes RFC 2104 HMAC-SHA256 authenticated webhook endpoints for GitHub (<code className="font-mono">/api/webhook/github</code>)
          and GitLab (<code className="font-mono">/api/webhook/gitlab</code>). Incoming pushes and pull requests trigger automated scans,
          calculate reachability, and package Three-Tier verified draft PR proposals.
        </AlertDescription>
      </Alert>

      {/* Webhook Status Card */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card className="border-border/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground flex items-center justify-between">
              <span>Listener Status</span>
              <span className="size-2 rounded-full bg-emerald-400 animate-pulse" />
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-1">
            <span className="text-base font-bold font-mono text-zinc-100">
              HTTP 3001 Active
            </span>
            <span className="text-xs text-muted-foreground truncate">
              /api/webhook/github • /api/webhook/gitlab
            </span>
          </CardContent>
        </Card>

        <Card className="border-border/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground flex items-center justify-between">
              <span>Signature Policy</span>
              <ShieldCheck className="size-4 text-primary" />
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-1">
            <span className="text-base font-bold font-mono text-zinc-100">
              HMAC-SHA256
            </span>
            <span className="text-xs text-muted-foreground">
              X-Hub-Signature-256 verification enabled
            </span>
          </CardContent>
        </Card>

        <Card className="border-border/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground flex items-center justify-between">
              <span>Simulate Webhook Event</span>
              <Radio className="size-4 text-emerald-400" />
            </CardTitle>
          </CardHeader>
          <CardContent className="flex items-center gap-2">
            <Button
              size="sm"
              disabled={isSimulating || currentRole === 'Viewer'}
              onClick={handleSimulatePush}
              className="h-8 text-xs font-semibold bg-primary text-primary-foreground hover:bg-primary/90 w-full"
            >
              <Play className={`size-3.5 mr-1.5 fill-current ${isSimulating ? 'animate-spin' : ''}`} />
              {isSimulating ? 'Triggering...' : 'Simulate GitHub Push'}
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Deliveries History Card */}
      <Card className="border-border/80">
        <CardHeader className="py-4 px-6 border-b border-border/60">
          <div className="flex items-center justify-between">
            <div className="flex flex-col">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <span>Webhook Intake Deliveries Ledger</span>
                <Badge variant="outline" className="text-[10px] font-mono">
                  {deliveries.length} event(s)
                </Badge>
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Audit trail of incoming webhook payloads, signature checks, and automated scan evaluations
              </CardDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={loadDeliveries}
              disabled={isLoading}
              className="h-8 text-xs"
            >
              <RefreshCw className={`size-3.5 mr-1.5 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs">Delivery ID</TableHead>
                <TableHead className="text-xs">Provider &amp; Event</TableHead>
                <TableHead className="text-xs">Target Repo &amp; Ref</TableHead>
                <TableHead className="text-xs">Sender</TableHead>
                <TableHead className="text-xs">Scan Outcome</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs text-right">Received Timestamp</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {deliveries.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-8 text-xs text-muted-foreground">
                    No webhook deliveries received yet. Click "Simulate GitHub Push" above to trigger a test delivery.
                  </TableCell>
                </TableRow>
              ) : (
                deliveries.map((deliv) => (
                  <TableRow key={deliv.deliveryId}>
                    <TableCell className="font-mono text-xs font-bold">
                      {deliv.deliveryId}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <Badge variant="outline" className="text-[10px] uppercase font-mono">
                          {deliv.provider}
                        </Badge>
                        <Badge variant="secondary" className="text-[10px] font-mono">
                          {deliv.eventType}
                        </Badge>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-zinc-300">
                      <div>{deliv.repository}</div>
                      <div className="text-[10px] text-zinc-500">{deliv.ref}</div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      @{deliv.sender}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-zinc-200">
                          {deliv.filesScanned} files
                        </span>
                        {deliv.findingsDetected > 0 ? (
                          <Badge variant="destructive" className="text-[10px] font-bold">
                            {deliv.findingsDetected} signals ({deliv.criticalCount} crit)
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-[10px] text-emerald-400 border-emerald-500/30">
                            Clean
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                        200 OK
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground text-right">
                      {new Date(deliv.timestamp).toLocaleTimeString()}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* CI/CD Template Generator Card */}
      <Card className="border-border/80">
        <CardHeader>
          <div className="flex flex-col">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileCode className="size-4 text-primary" />
              <span>CI/CD Workflow Template Generator</span>
            </CardTitle>
            <CardDescription className="text-xs text-muted-foreground">
              Copy-pasteable GitHub Actions and GitLab CI configurations to integrate Sentra into your repositories
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="github" className="w-full">
            <TabsList className="bg-zinc-900 border border-zinc-800 p-1 rounded-lg">
              <TabsTrigger value="github" className="text-xs">
                GitHub Actions (.github/workflows/sentra.yml)
              </TabsTrigger>
              <TabsTrigger value="gitlab" className="text-xs">
                GitLab CI (.gitlab-ci.yml)
              </TabsTrigger>
            </TabsList>

            <TabsContent value="github" className="pt-3 flex flex-col gap-2">
              <div className="flex items-center justify-between text-xs text-zinc-400">
                <span>Triggers pure-Rust scan and uploads OASIS SARIF v2.1.0 to GitHub Code Scanning:</span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => handleCopy(GITHUB_WORKFLOW_YAML, 'gh-yaml', 'GitHub YAML')}
                  className="h-7 text-xs text-zinc-400 hover:text-zinc-100"
                >
                  {copiedKey === 'gh-yaml' ? <Check className="size-3 mr-1 text-emerald-400" /> : <Copy className="size-3 mr-1" />}
                  Copy Workflow YAML
                </Button>
              </div>
              <pre className="font-mono text-xs bg-zinc-950 border border-zinc-800 rounded-lg p-4 overflow-x-auto text-zinc-300 leading-relaxed max-h-[280px]">
                {GITHUB_WORKFLOW_YAML}
              </pre>
            </TabsContent>

            <TabsContent value="gitlab" className="pt-3 flex flex-col gap-2">
              <div className="flex items-center justify-between text-xs text-zinc-400">
                <span>Executes merge-request checks and produces GitLab SAST reports:</span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => handleCopy(GITLAB_CI_YAML, 'gl-yaml', 'GitLab YAML')}
                  className="h-7 text-xs text-zinc-400 hover:text-zinc-100"
                >
                  {copiedKey === 'gl-yaml' ? <Check className="size-3 mr-1 text-emerald-400" /> : <Copy className="size-3 mr-1" />}
                  Copy GitLab YAML
                </Button>
              </div>
              <pre className="font-mono text-xs bg-zinc-950 border border-zinc-800 rounded-lg p-4 overflow-x-auto text-zinc-300 leading-relaxed max-h-[280px]">
                {GITLAB_CI_YAML}
              </pre>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  )
}
