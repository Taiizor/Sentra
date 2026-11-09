import { useState } from 'react'
import {
  LayoutDashboard,
  AlertTriangle,
  CheckCircle2,
  Brain,
  History,
  Shield,
  FileDown,
} from 'lucide-react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { TooltipProvider } from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'

import { Header } from '@/components/layout/header'
import { OverviewTab } from '@/components/dashboard/overview-tab'
import { FindingsTab } from '@/components/dashboard/findings-tab'
import { RemediationTab } from '@/components/dashboard/remediation-tab'
import { ResearchTab } from '@/components/dashboard/research-tab'
import { AuditTab } from '@/components/dashboard/audit-tab'
import { ScannerConsole } from '@/components/dashboard/scanner-console'

import {
  INITIAL_AUDIT_LOGS,
  INITIAL_CAMPAIGNS,
  INITIAL_FINDINGS,
  INITIAL_OVERVIEW,
  INITIAL_PATCHES,
  INITIAL_SESSIONS,
} from '@/lib/dashboard-store'
import { generateSarifJson } from '@/lib/sarif-export'
import type { TenantId, UserRole } from '@/types/sentra'

export function App() {
  const [currentTenant, setCurrentTenant] = useState<TenantId>('sentra-internal')
  const [currentRole, setCurrentRole] = useState<UserRole>('Operator')
  const [activeTab, setActiveTab] = useState<string>('overview')
  const [isConsoleOpen, setIsConsoleOpen] = useState<boolean>(false)
  const [sarifModalContent, setSarifModalContent] = useState<string | null>(null)

  const [findings, setFindings] = useState(INITIAL_FINDINGS)
  const [patches, setPatches] = useState(INITIAL_PATCHES)
  const [sessions] = useState(INITIAL_SESSIONS)
  const [campaigns] = useState(INITIAL_CAMPAIGNS)
  const [auditLogs, setAuditLogs] = useState(INITIAL_AUDIT_LOGS)
  const [overview, setOverview] = useState(INITIAL_OVERVIEW)

  function handleTenantChange(newTenant: TenantId) {
    setCurrentTenant(newTenant)
    setOverview((prev) => ({
      ...prev,
      tenantId: newTenant,
      workspaceName:
        newTenant === 'sentra-internal'
          ? 'Sentra Security Core'
          : newTenant === 'tenant-alpha'
            ? 'Tenant Alpha (Isolated)'
            : 'Acme Corp Enterprise',
    }))
  }

  function handleExportSarif() {
    const json = generateSarifJson(findings)
    setSarifModalContent(json)
  }

  function handleDownloadSarif() {
    if (!sarifModalContent) return
    const blob = new Blob([sarifModalContent], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `sentra-findings-${currentTenant}.sarif`
    a.click()
    URL.revokeObjectURL(url)
  }

  function handleProposePatch(findingId: string) {
    const finding = findings.find((f) => f.findingId === findingId)
    if (!finding) return

    const newBundleId = `bundle-${Date.now().toString().slice(-4)}`
    const newPatch = {
      bundleId: newBundleId,
      tenantId: currentTenant,
      findingId: finding.findingId,
      title: `Automated Remediation for ${finding.ruleId} (${finding.cwe})`,
      originalTestStatus: 'Failed' as const,
      patchedTestStatus: 'Passed' as const,
      regressionsPass: true,
      isVerified: true,
      attemptCount: 1,
      branchName: `sentra/patch/${finding.ruleId.toLowerCase()}-${newBundleId}`,
      ghPrCommand: `gh pr create --draft --title "[Security] Remediate ${finding.title}" --body "Automated Sentra Three-Tier Verified Patch" --base main --head sentra/patch/${finding.ruleId.toLowerCase()}-${newBundleId}`,
      diff: `--- a/${finding.targetLocation}\n+++ b/${finding.targetLocation}\n@@ -${finding.startLine},3 +${finding.startLine},3 @@\n-// Potentially vulnerable code pattern\n+// Remediated with safe parameterized interface\n`,
      createdAt: new Date().toISOString(),
    }

    setPatches((prev) => [newPatch, ...prev])
    setOverview((prev) => ({
      ...prev,
      verifiedPatches: prev.verifiedPatches + 1,
      auditEventCount: prev.auditEventCount + 1,
    }))

    setAuditLogs((prev) => [
      {
        eventId: `evt-${Date.now().toString().slice(-4)}`,
        tenantId: currentTenant,
        sequenceNumber: prev.length + 1,
        actor: `operator-${currentRole.toLowerCase()}`,
        action: 'patch_proposed_and_verified',
        details: `Three-tier verified patch generated for ${finding.findingId} (${newBundleId})`,
        timestamp: new Date().toISOString(),
      },
      ...prev,
    ])

    setActiveTab('remediation')
  }

  function handleTriggerScanAction(action: string, workspace: string) {
    setAuditLogs((prev) => [
      {
        eventId: `evt-${Date.now().toString().slice(-4)}`,
        tenantId: currentTenant,
        sequenceNumber: prev.length + 1,
        actor: `operator-${currentRole.toLowerCase()}`,
        action: `${action}_executed`,
        details: `Dispatched 'sentra ${action}' on workspace ${workspace}`,
        timestamp: new Date().toISOString(),
      },
      ...prev,
    ])
    setOverview((prev) => ({
      ...prev,
      auditEventCount: prev.auditEventCount + 1,
    }))
  }

  return (
    <TooltipProvider>
      <div className="min-h-screen bg-background text-foreground flex flex-col antialiased">
        {/* Global Header */}
        <Header
          currentTenant={currentTenant}
          onTenantChange={handleTenantChange}
          currentRole={currentRole}
          onRoleChange={setCurrentRole}
          onExportSarif={handleExportSarif}
          onToggleConsole={() => setIsConsoleOpen((v) => !v)}
          isConsoleOpen={isConsoleOpen}
        />

        {/* Main Body */}
        <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 flex flex-col gap-6">
          {/* Collapsible Scanner CLI Console */}
          {isConsoleOpen && (
            <ScannerConsole
              currentRole={currentRole}
              onTriggerScanAction={handleTriggerScanAction}
            />
          )}

          {/* Navigation Tabs */}
          <Tabs value={activeTab} onValueChange={setActiveTab} className="flex flex-col gap-6">
            <div className="border-b pb-1">
              <TabsList className="h-10 bg-muted/60 p-1">
                <TabsTrigger value="overview" className="text-xs flex items-center gap-1.5 px-3">
                  <LayoutDashboard className="size-3.5" />
                  Overview
                </TabsTrigger>
                <TabsTrigger value="findings" className="text-xs flex items-center gap-1.5 px-3">
                  <AlertTriangle className="size-3.5" />
                  Findings
                  <Badge variant="secondary" className="text-[10px] h-4 px-1 ml-1 font-mono">
                    {findings.length}
                  </Badge>
                </TabsTrigger>
                <TabsTrigger value="remediation" className="text-xs flex items-center gap-1.5 px-3">
                  <CheckCircle2 className="size-3.5" />
                  Remediation & Patches
                  <Badge variant="secondary" className="text-[10px] h-4 px-1 ml-1 font-mono">
                    {patches.length}
                  </Badge>
                </TabsTrigger>
                <TabsTrigger value="research" className="text-xs flex items-center gap-1.5 px-3">
                  <Brain className="size-3.5" />
                  Research Campaigns
                </TabsTrigger>
                <TabsTrigger value="audit" className="text-xs flex items-center gap-1.5 px-3">
                  <History className="size-3.5" />
                  Audit Trail
                  <Badge variant="outline" className="text-[10px] h-4 px-1 ml-1 font-mono">
                    {auditLogs.length}
                  </Badge>
                </TabsTrigger>
              </TabsList>
            </div>

            {/* Tab Panes */}
            <TabsContent value="overview">
              <OverviewTab
                overview={overview}
                sessions={sessions}
                onSelectTab={setActiveTab}
              />
            </TabsContent>

            <TabsContent value="findings">
              <FindingsTab
                findings={findings}
                currentRole={currentRole}
                onProposePatch={handleProposePatch}
              />
            </TabsContent>

            <TabsContent value="remediation">
              <RemediationTab patches={patches} currentRole={currentRole} />
            </TabsContent>

            <TabsContent value="research">
              <ResearchTab campaigns={campaigns} />
            </TabsContent>

            <TabsContent value="audit">
              <AuditTab auditLogs={auditLogs} />
            </TabsContent>
          </Tabs>
        </main>

        {/* Footer */}
        <footer className="border-t py-4 px-6 text-xs text-muted-foreground bg-card/30">
          <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Shield className="size-4 text-primary" />
              <span>Sentra Security Platform • RFC 2104 / OASIS SARIF v2.1.0 Compliant</span>
            </div>
            <div className="flex items-center gap-4">
              <span>Fail-Closed Host Boundary</span>
              <span>Zero-Egress Isolation</span>
              <span>Human-in-the-Loop Governance</span>
            </div>
          </div>
        </footer>

        {/* SARIF Export Dialog */}
        <Dialog open={!!sarifModalContent} onOpenChange={(open) => !open && setSarifModalContent(null)}>
          <DialogContent className="sm:max-w-2xl max-h-[85vh] flex flex-col">
            <DialogHeader>
              <DialogTitle className="text-base font-bold flex items-center gap-2">
                <FileDown className="size-4 text-primary" />
                OASIS SARIF v2.1.0 Security Report
              </DialogTitle>
              <DialogDescription className="text-xs">
                Exportable directly to GitHub Advanced Security Code Scanning, GitLab SAST, or VS Code.
              </DialogDescription>
            </DialogHeader>

            <div className="flex-1 overflow-y-auto bg-muted/60 p-3 rounded-md border font-mono text-xs my-2">
              <pre className="whitespace-pre-wrap">{sarifModalContent}</pre>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSarifModalContent(null)}
              >
                Close
              </Button>
              <Button size="sm" onClick={handleDownloadSarif}>
                <FileDown data-icon="inline-start" />
                Download .sarif File
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>
    </TooltipProvider>
  )
}

export default App
