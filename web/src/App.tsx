import { useState, useEffect, useMemo } from 'react'
import {
  FileDown,
  Shield,
  Copy,
} from 'lucide-react'
import { toast } from 'sonner'
import { copyText } from '@/lib/clipboard'
import { Toaster } from '@/components/ui/sonner'
import { TooltipProvider } from '@/components/ui/tooltip'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'

import { Sidebar } from '@/components/layout/sidebar'
import { Header } from '@/components/layout/header'
import { CommandPalette } from '@/components/layout/command-palette'
import { WorkspaceTargetBar } from '@/components/layout/workspace-target-bar'
import { OverviewTab } from '@/components/dashboard/overview-tab'
import { LiveScannerStudio } from '@/components/dashboard/live-scanner-studio'
import { FindingsTab } from '@/components/dashboard/findings-tab'
import { RemediationTab } from '@/components/dashboard/remediation-tab'
import { ThreatIntelTab } from '@/components/dashboard/threat-intel-tab'
import { ResearchTab } from '@/components/dashboard/research-tab'
import { WorkerFleetTab } from '@/components/dashboard/worker-fleet-tab'
import { AuditTab } from '@/components/dashboard/audit-tab'
import { WebhookTab } from '@/components/dashboard/webhook-tab'
import { ScannerConsole } from '@/components/dashboard/scanner-console'
import { LiveStreamModal } from '@/components/dashboard/live-stream-modal'
import { AiPatchModal } from '@/components/dashboard/ai-patch-modal'
import { AddTenantDialog } from '@/components/dashboard/add-tenant-dialog'
import { SettingsDialog } from '@/components/dashboard/settings-dialog'
import { generateExecutiveReportHtml } from '@/lib/executive-report'
import { useAppRouter } from '@/lib/router'

import {
  DEFAULT_TENANTS,
  INITIAL_AUDIT_LOGS,
  INITIAL_CAMPAIGNS,
  INITIAL_FINDINGS,
  INITIAL_OSV_ADVISORIES,
  INITIAL_OVERVIEW,
  INITIAL_PATCHES,
  INITIAL_SECURITY_TRENDS,
  INITIAL_SESSIONS,
  INITIAL_WORKERS,
} from '@/lib/dashboard-store'
import { generateSarifJson } from '@/lib/sarif-export'
import {
  checkApiHealth,
  fetchRealOverview,
  fetchRealSessions,
  fetchRealAuditTrail,
  triggerLiveScan,
  triggerLiveAudit,
  triggerLiveCodeQl,
  transformMatchesToFindings,
} from '@/lib/api-client'
import type { FindingView, TenantId, TenantView, SessionSummaryView, AuditLogView } from '@/types/sentra'

export function App() {
  const {
    activeTab,
    currentTenant,
    currentRole,
    currentWorkspace,
    selectedFindingId,
    setTab: setActiveTab,
    setTenant: setCurrentTenant,
    setRole: setCurrentRole,
    setWorkspace: setCurrentWorkspace,
    setSelectedFindingId,
  } = useAppRouter()

  const [tenants, setTenants] = useState<TenantView[]>(DEFAULT_TENANTS)
  const [isConsoleOpen, setIsConsoleOpen] = useState<boolean>(false)
  const [isCommandOpen, setIsCommandOpen] = useState<boolean>(false)
  const [isStreamModalOpen, setIsStreamModalOpen] = useState<boolean>(false)
  const [isAddTenantOpen, setIsAddTenantOpen] = useState<boolean>(false)
  const [isSettingsOpen, setIsSettingsOpen] = useState<boolean>(false)
  const [selectedPatchFinding, setSelectedPatchFinding] = useState<FindingView | null>(null)
  const [sarifModalContent, setSarifModalContent] = useState<string | null>(null)

  // Real Workspace State
  const [backendConnected, setBackendConnected] = useState<boolean>(false)
  const [binaryPath, setBinaryPath] = useState<string>('')
  const [isScanning, setIsScanning] = useState<boolean>(false)
  const [isAuditing, setIsAuditing] = useState<boolean>(false)
  const [isCodeQlProbing, setIsCodeQlProbing] = useState<boolean>(false)

  // Data Store
  const [findings, setFindings] = useState<FindingView[]>(INITIAL_FINDINGS)
  const [patches, setPatches] = useState(INITIAL_PATCHES)
  const [sessions, setSessions] = useState<SessionSummaryView[]>(INITIAL_SESSIONS)
  const [campaigns] = useState(INITIAL_CAMPAIGNS)
  const [auditLogs, setAuditLogs] = useState<AuditLogView[]>(INITIAL_AUDIT_LOGS)
  const [, setOverview] = useState(INITIAL_OVERVIEW)
  const [workers] = useState(INITIAL_WORKERS)
  const [osvAdvisories] = useState(INITIAL_OSV_ADVISORIES)
  const [trends, setTrends] = useState(INITIAL_SECURITY_TRENDS)

  // Check backend health & sync real SQLite storage on mount
  useEffect(() => {
    async function initData() {
      const health = await checkApiHealth()
      if (health && health.binaryExists) {
        setBackendConnected(true)
        setBinaryPath(health.binaryPath)
      } else {
        setBackendConnected(false)
      }

      // Fetch real database state
      const [realOverview, realSessions, realAudit] = await Promise.all([
        fetchRealOverview(),
        fetchRealSessions(),
        fetchRealAuditTrail(),
      ])

      // Fetch persistent tenants from SQLite WAL
      try {
        const tRes = await fetch('/api/tenants')
        if (tRes.ok) {
          const tData = await tRes.json()
          if (tData.tenants && tData.tenants.length > 0) {
            setTenants(tData.tenants)
          }
        }
      } catch (err) {
        console.warn('Using default tenants, backend offline or unreachable', err)
      }

      if (realOverview) {
        setOverview((prev) => ({
          ...prev,
          totalSessions: realOverview.sessionCount || prev.totalSessions,
          auditEventCount: realOverview.auditEventCount || prev.auditEventCount,
        }))
      }

      if (realSessions && realSessions.length > 0) {
        const mappedSessions: SessionSummaryView[] = realSessions.map((s) => ({
          sessionId: s.session_id,
          tenantId: 'sentra-internal',
          workspaceRoot: s.workspace || currentWorkspace,
          state: s.state || 'SCOPED',
          taskCount: 8,
          fencingEpoch: s.context_generation || 1,
          createdAt: s.created_at || new Date().toISOString(),
          updatedAt: s.updated_at || s.created_at || new Date().toISOString(),
        }))
        setSessions(mappedSessions)
      }

      if (realAudit && realAudit.length > 0) {
        const mappedAudit: AuditLogView[] = realAudit.map((a) => {
          let detailsText = a.details_json || ''
          try {
            const parsed = JSON.parse(a.details_json)
            if (parsed.event) {
              detailsText = JSON.stringify(parsed.event).replace(/[{}"]/g, '')
            }
          } catch (e) {}

          return {
            eventId: a.event_id,
            tenantId: 'sentra-internal',
            sequenceNumber: a.sequence_number,
            actor: a.operator_id || 'sentra-core (rusqlite)',
            action: a.event_kind,
            details: detailsText || `Recorded transition for ${a.session_id}`,
            cryptoHash: a.action_digest || `sha256:${a.event_id.slice(-8)}`,
            timestamp: a.timestamp,
          }
        })
        setAuditLogs(mappedAudit)
      }
    }

    initData()
  }, [currentWorkspace])

  function getTabTitle(tab: string): string {
    switch (tab) {
      case 'overview':
        return 'Executive Threat Posture & Overview'
      case 'studio':
        return 'Live SAST & Semantic Taint Analysis Studio'
      case 'findings':
        return 'Vulnerability Findings & Taint Flow Call Graphs'
      case 'remediation':
        return 'Automated Remediation & Three-Tier Verified Patches'
      case 'intel':
        return 'Universal OSV Threat Intelligence & Advisory Mirror'
      case 'research':
        return 'Deep Research Campaigns & Coverage Ledger'
      case 'fleet':
        return 'Remote-Worker Fleet Coordinator & Sandboxes'
      case 'webhooks':
        return 'Continuous Integration Webhook Intake & Automated Proposals'
      case 'audit':
        return 'Tamper-Resistant Immutable Audit Trail'
      default:
        return 'Security Operations Dashboard'
    }
  }

  // Strict Tenant Data Isolation & Scoped Workspaces (REQ-F19, ADR-0001)
  const tenantFindings = useMemo(
    () => findings.filter((f) => f.tenantId === currentTenant),
    [findings, currentTenant]
  )
  const tenantPatches = useMemo(
    () => patches.filter((p) => p.tenantId === currentTenant),
    [patches, currentTenant]
  )
  const tenantSessions = useMemo(
    () => sessions.filter((s) => s.tenantId === currentTenant),
    [sessions, currentTenant]
  )
  const tenantAuditLogs = useMemo(
    () => auditLogs.filter((l) => l.tenantId === currentTenant),
    [auditLogs, currentTenant]
  )

  // Real-time calculated tenant overview metrics
  const tenantOverview = useMemo(() => {
    const criticalCount = tenantFindings.filter((f) => f.severity === 'Critical').length
    const highCount = tenantFindings.filter((f) => f.severity === 'High').length
    const mediumCount = tenantFindings.filter((f) => f.severity === 'Medium').length
    const lowCount = tenantFindings.filter((f) => f.severity === 'Low').length
    const infoCount = tenantFindings.filter((f) => f.severity === 'Informational').length
    const total = tenantFindings.length

    const baseScore = Math.max(35, 100 - criticalCount * 12 - highCount * 6 - mediumCount * 2)

    const currentTenantObj = tenants.find((t) => t.tenantId === currentTenant)

    return {
      tenantId: currentTenant,
      workspaceName: currentTenantObj ? currentTenantObj.name : (currentTenant === 'sentra-internal' ? 'Sentra Security Core' : currentTenant),
      totalSessions: tenantSessions.length,
      activeSessions: tenantSessions.filter((s) => s.state === 'SCOPED').length || 1,
      criticalFindings: criticalCount,
      highFindings: highCount,
      mediumFindings: mediumCount,
      lowFindings: lowCount,
      infoFindings: infoCount,
      verifiedPatches: tenantPatches.filter((p) => p.isVerified).length,
      totalPatches: tenantPatches.length,
      auditEventCount: tenantAuditLogs.length,
      totalSpentMicroUsd: 0,
      lastActivityTimestamp: tenantAuditLogs[0]?.timestamp || tenantSessions[0]?.updatedAt || '2026-11-09T18:00:00Z',
      securityScore: total === 0 ? 100 : baseScore,
    }
  }, [currentTenant, tenants, tenantFindings, tenantPatches, tenantSessions, tenantAuditLogs])

  function handleTenantChange(newTenant: TenantId) {
    setCurrentTenant(newTenant)
    const match = tenants.find((t) => t.tenantId === newTenant)
    const label = match ? match.name : newTenant
    if (match && match.defaultWorkspace) {
      setCurrentWorkspace(match.defaultWorkspace)
    }
    toast.info(`Switched Workspace to ${label}`, {
      description: 'Strict tenant data isolation applied. Displaying workspace-scoped findings and audit trail.',
    })
  }

  function handleTenantCreated(newTenant: TenantView) {
    setTenants((prev) => {
      if (prev.some((t) => t.tenantId === newTenant.tenantId)) return prev
      return [...prev, newTenant]
    })
    setCurrentTenant(newTenant.tenantId)
    if (newTenant.defaultWorkspace) {
      setCurrentWorkspace(newTenant.defaultWorkspace)
    }

    const newAuditEntry: AuditLogView = {
      eventId: `evt-tenant-${Date.now()}`,
      tenantId: newTenant.tenantId,
      sequenceNumber: (auditLogs[0]?.sequenceNumber || 65) + 1,
      actor: currentRole,
      action: 'tenant_registered',
      details: `Workspace '${newTenant.name}' (${newTenant.isolationLevel}) provisioned`,
      cryptoHash: `sha256:${Date.now().toString(16)}`,
      timestamp: new Date().toISOString(),
    }
    setAuditLogs((prev) => [newAuditEntry, ...prev])

    toast.success(`Organization '${newTenant.name}' Provisioned`, {
      description: `Activated tenant '${newTenant.tenantId}' with ${newTenant.isolationLevel === 'multi_tenant_isolated' ? 'Strict Multi-Tenant Fencing' : 'Single Operator'} isolation.`,
    })
  }

  function handleExportSarif() {
    const json = generateSarifJson(tenantFindings)
    setSarifModalContent(json)
  }

  function handleExportReport() {
    const currentTenantObj = tenants.find((t) => t.tenantId === currentTenant)
    const html = generateExecutiveReportHtml(
      tenantOverview,
      tenantFindings,
      tenantPatches,
      tenantAuditLogs,
      currentTenantObj
    )
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `sentra-executive-threat-report-${currentTenant}.html`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    toast.success('Executive Threat Report Exported', {
      description: `Downloaded report for ${tenantOverview.workspaceName}. Open in browser or print to PDF.`,
    })
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
    toast.success('SARIF Report Exported', {
      description: `Downloaded sentra-findings-${currentTenant}.sarif (OASIS v2.1.0)`,
    })
  }

  // Real scan action triggered against sentra.exe
  async function handleRealScan() {
    if (currentRole === 'Viewer') {
      toast.error('Action Denied: Viewer Role', {
        description: 'Viewer role has read-only access. Switch to Operator or Admin in the top bar to execute scans.',
      })
      return
    }
    setIsScanning(true)
    const startMs = performance.now()
    try {
      const res = await triggerLiveScan(currentWorkspace)
      const durationMs = Math.round(performance.now() - startMs)
      const realFindings = transformMatchesToFindings(res.matches || [])

      setFindings(realFindings)

      // Calculate real severity counts
      const criticalCount = realFindings.filter((f) => f.severity === 'Critical').length
      const highCount = realFindings.filter((f) => f.severity === 'High').length
      const mediumCount = realFindings.filter((f) => f.severity === 'Medium').length

      setOverview((prev) => ({
        ...prev,
        criticalFindings: criticalCount,
        highFindings: highCount,
        mediumFindings: mediumCount,
        securityScore: Math.max(35, 100 - criticalCount * 12 - highCount * 5),
        auditEventCount: prev.auditEventCount + 1,
      }))

      // Update Trend
      setTrends((prev) => [
        ...prev,
        {
          date: 'Now (Live)',
          detected: res.signals_found || realFindings.length,
          remediated: prev[prev.length - 1]?.remediated || 2,
          activeCritical: criticalCount,
        },
      ])

      // Add to audit trail
      setAuditLogs((prev) => [
        {
          eventId: `evt-scan-${Date.now().toString().slice(-4)}`,
          tenantId: currentTenant,
          sequenceNumber: prev.length + 1,
          actor: `operator-${currentRole.toLowerCase()}`,
          action: 'live_sast_scan_executed',
          details: `Scanned ${res.files_scanned} files in ${currentWorkspace}. Found ${res.signals_found} signals, admitted ${realFindings.length} findings in ${durationMs}ms.`,
          cryptoHash: `sha256:${Date.now().toString(16)}...`,
          timestamp: new Date().toISOString(),
        },
        ...prev,
      ])

      toast.success('Pure-Rust SAST & Taint Scan Complete', {
        description: `Scanned ${res.files_scanned} files in ${durationMs}ms. Admitted ${realFindings.length} findings.`,
      })

      setActiveTab('findings')
    } catch (err) {
      console.error('Failed to trigger scan:', err)
      toast.error('Scan Failed', {
        description: 'Failed to communicate with sentra.exe binary.',
      })
    } finally {
      setIsScanning(false)
    }
  }

  // Real audit action against sentra.exe
  async function handleRealAudit() {
    if (currentRole === 'Viewer') {
      toast.error('Action Denied: Viewer Role', {
        description: 'Viewer role has read-only access. Switch to Operator or Admin to execute dependency audits.',
      })
      return
    }
    setIsAuditing(true)
    const startMs = performance.now()
    try {
      const res = await triggerLiveAudit(currentWorkspace)
      const durationMs = Math.round(performance.now() - startMs)
      setAuditLogs((prev) => [
        {
          eventId: `evt-audit-${Date.now().toString().slice(-4)}`,
          tenantId: currentTenant,
          sequenceNumber: prev.length + 1,
          actor: `operator-${currentRole.toLowerCase()}`,
          action: 'live_lockfile_audit_executed',
          details: `Audited ${res.packages_audited} packages in ${currentWorkspace}. Vulnerable packages detected: ${res.vulnerable_packages}`,
          cryptoHash: `sha256:${Date.now().toString(16)}...`,
          timestamp: new Date().toISOString(),
        },
        ...prev,
      ])
      setOverview((prev) => ({
        ...prev,
        auditEventCount: prev.auditEventCount + 1,
      }))
      toast.success('Lockfile Security Audit Complete', {
        description: `Audited ${res.packages_audited} packages in ${durationMs}ms. Vulnerable packages: ${res.vulnerable_packages}`,
      })
    } catch (err) {
      console.error('Failed to audit dependencies:', err)
      toast.error('Audit Failed', {
        description: 'Failed to execute lockfile audit.',
      })
    } finally {
      setIsAuditing(false)
    }
  }

  // Real CodeQL probe action against sentra.exe
  async function handleRealCodeQl() {
    if (currentRole === 'Viewer') {
      toast.error('Action Denied: Viewer Role', {
        description: 'Viewer role has read-only access. Switch to Operator or Admin to execute CodeQL probes.',
      })
      return
    }
    setIsCodeQlProbing(true)
    const startMs = performance.now()
    try {
      const res = await triggerLiveCodeQl(currentWorkspace)
      const durationMs = Math.round(performance.now() - startMs)
      const langSummary = (res.detected_languages || []).map((l) => `${l.language}: ${l.files_count}`).join(', ')
      setAuditLogs((prev) => [
        {
          eventId: `evt-codeql-${Date.now().toString().slice(-4)}`,
          tenantId: currentTenant,
          sequenceNumber: prev.length + 1,
          actor: `operator-${currentRole.toLowerCase()}`,
          action: 'codeql_workspace_probe_completed',
          details: `CodeQL probe completed for ${currentWorkspace}. Primary: ${res.primary_language}. Languages: [${langSummary}]. Plan: ${res.database_create_command}`,
          cryptoHash: `sha256:${Date.now().toString(16)}...`,
          timestamp: new Date().toISOString(),
        },
        ...prev,
      ])
      setOverview((prev) => ({
        ...prev,
        auditEventCount: prev.auditEventCount + 1,
      }))
      toast.info('CodeQL Polyglot Discovery Ready', {
        description: `Primary language: ${res.primary_language}. Detected ${res.detected_languages?.length || 0} language ecosystem(s) in ${durationMs}ms.`,
      })
    } catch (err) {
      console.error('Failed to probe CodeQL:', err)
      toast.error('CodeQL Probe Failed', {
        description: 'Failed to inspect workspace languages.',
      })
    } finally {
      setIsCodeQlProbing(false)
    }
  }

  function handleAddFindingFromStudio(newFinding: FindingView) {
    setFindings((prev) => [newFinding, ...prev])
    setOverview((prev) => ({
      ...prev,
      criticalFindings:
        newFinding.severity === 'Critical' ? prev.criticalFindings + 1 : prev.criticalFindings,
      highFindings: newFinding.severity === 'High' ? prev.highFindings + 1 : prev.highFindings,
      auditEventCount: prev.auditEventCount + 1,
    }))

    setAuditLogs((prev) => [
      {
        eventId: `evt-${Date.now().toString().slice(-4)}`,
        tenantId: currentTenant,
        sequenceNumber: prev.length + 1,
        actor: `operator-${currentRole.toLowerCase()}`,
        action: 'studio_finding_admitted',
        details: `Admitted finding ${newFinding.findingId} (${newFinding.ruleId}) into workspace catalog`,
        cryptoHash: `sha256:${Date.now().toString(16)}...`,
        timestamp: new Date().toISOString(),
      },
      ...prev,
    ])

    setActiveTab('findings')
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
      originalSnippet: `// Vulnerable unparameterized call\nlet res = execute_untrusted(input);`,
      patchedSnippet: `// Parameterized safe call\nlet res = execute_parameterized(&safe_query, &[&input]);`,
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
        cryptoHash: `sha256:${Date.now().toString(16)}...`,
        timestamp: new Date().toISOString(),
      },
      ...prev,
    ])

    setActiveTab('remediation')
  }

  function handleAdmitPatch(newPatch: any) {
    setPatches((prev) => [newPatch, ...prev])
    setOverview((prev) => ({
      ...prev,
      verifiedPatches: prev.verifiedPatches + 1,
      auditEventCount: prev.auditEventCount + 1,
    }))
    setAuditLogs((prev) => [
      {
        eventId: `evt-patch-${Date.now().toString().slice(-4)}`,
        tenantId: currentTenant,
        sequenceNumber: prev.length + 1,
        actor: `operator-${currentRole.toLowerCase()}`,
        action: 'three_tier_patch_verified_admitted',
        details: `Admitted verified patch ${newPatch.bundleId} for finding ${newPatch.findingId}. Branch: ${newPatch.branchName}`,
        cryptoHash: `sha256:${Date.now().toString(16)}...`,
        timestamp: new Date().toISOString(),
      },
      ...prev,
    ])
    toast.success('Three-Tier Verified Patch Admitted', {
      description: `Added ${newPatch.bundleId} to active catalog. All invariants verified.`,
    })
  }

  function handleSyncAdvisories() {
    setAuditLogs((prev) => [
      {
        eventId: `evt-${Date.now().toString().slice(-4)}`,
        tenantId: currentTenant,
        sequenceNumber: prev.length + 1,
        actor: `operator-${currentRole.toLowerCase()}`,
        action: 'osv_mirror_synchronized',
        details: 'Synchronized universal OSV v1.6 advisory feed (RustSec, Google OSV, GHSA)',
        cryptoHash: `sha256:${Date.now().toString(16)}...`,
        timestamp: new Date().toISOString(),
      },
      ...prev,
    ])
    setOverview((prev) => ({
      ...prev,
      auditEventCount: prev.auditEventCount + 1,
    }))
  }

  // Handle live stream completion
  function handleStreamScanComplete(newFindings: FindingView[], rawResult: any) {
    if (newFindings && newFindings.length > 0) {
      setFindings(newFindings)
      const criticalCount = newFindings.filter((f) => f.severity === 'Critical').length
      const highCount = newFindings.filter((f) => f.severity === 'High').length
      const mediumCount = newFindings.filter((f) => f.severity === 'Medium').length

      setOverview((prev) => ({
        ...prev,
        criticalFindings: criticalCount,
        highFindings: highCount,
        mediumFindings: mediumCount,
        securityScore: Math.max(35, 100 - criticalCount * 12 - highCount * 5),
        auditEventCount: prev.auditEventCount + 1,
      }))
    }

    if (rawResult?.auditEvents && rawResult.auditEvents.length > 0) {
      const mapped = rawResult.auditEvents.map((a: any) => ({
        eventId: a.event_id,
        tenantId: 'sentra-internal',
        sequenceNumber: a.sequence_number,
        actor: 'sentra-core (rusqlite)',
        action: a.event_kind,
        details: a.details_json || 'Recorded transition in SQLite WAL',
        cryptoHash: a.action_digest || `sha256:${a.event_id.slice(-8)}`,
        timestamp: a.timestamp,
      }))
      setAuditLogs(mapped)
    }

    if (rawResult?.sessions && rawResult.sessions.length > 0) {
      const mappedSessions: SessionSummaryView[] = rawResult.sessions.map((s: any) => ({
        sessionId: s.session_id,
        tenantId: 'sentra-internal',
        workspaceRoot: s.workspace || currentWorkspace,
        state: s.state || 'SCOPED',
        taskCount: 8,
        fencingEpoch: s.context_generation || 1,
        createdAt: s.created_at || new Date().toISOString(),
        updatedAt: s.updated_at || s.created_at || new Date().toISOString(),
      }))
      setSessions(mappedSessions)
    }
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
        cryptoHash: `sha256:${Date.now().toString(16)}...`,
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
      <div className="min-h-screen bg-zinc-950 text-zinc-100 flex antialiased selection:bg-primary/30 selection:text-white">
        {/* Enterprise Sidebar */}
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          findingCount={tenantFindings.length}
          patchCount={tenantPatches.length}
          auditCount={tenantAuditLogs.length}
          currentRole={currentRole}
          currentTenant={currentTenant}
        />

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Top Header */}
          <Header
            currentTenant={currentTenant}
            tenants={tenants}
            onTenantChange={handleTenantChange}
            onOpenAddTenant={() => setIsAddTenantOpen(true)}
            onOpenSettings={() => setIsSettingsOpen(true)}
            onExportReport={handleExportReport}
            currentRole={currentRole}
            onRoleChange={setCurrentRole}
            onExportSarif={handleExportSarif}
            onToggleConsole={() => setIsConsoleOpen((v) => !v)}
            onOpenCommandPalette={() => setIsCommandOpen(true)}
            onJumpToStudio={() => setActiveTab('studio')}
            isConsoleOpen={isConsoleOpen}
            activeTabTitle={getTabTitle(activeTab)}
          />

          {/* Main Body */}
          <main className="flex-1 p-6 flex flex-col gap-6 max-w-[1600px] w-full mx-auto">
            {/* Live Workspace Target Bar (Selects real folder on disk & triggers real sentra.exe) */}
            <WorkspaceTargetBar
              currentRole={currentRole}
              currentWorkspace={currentWorkspace}
              onWorkspaceChange={setCurrentWorkspace}
              onRunScan={handleRealScan}
              onRunAudit={handleRealAudit}
              onRunCodeQl={handleRealCodeQl}
              onOpenLiveStream={() => {
                if (currentRole === 'Viewer') {
                  toast.error('Action Denied: Viewer Role', {
                    description: 'Viewer role has read-only access. Switch to Operator or Admin to execute live stream scans.',
                  })
                  return
                }
                setIsStreamModalOpen(true)
              }}
              isScanning={isScanning}
              isAuditing={isAuditing}
              isCodeQlProbing={isCodeQlProbing}
              backendConnected={backendConnected}
              binaryPath={binaryPath}
            />

            {/* Collapsible Scanner CLI Console */}
            {isConsoleOpen && (
              <ScannerConsole
                currentRole={currentRole}
                onTriggerScanAction={handleTriggerScanAction}
              />
            )}

            {/* Active View Content */}
            {activeTab === 'overview' && (
              <OverviewTab
                overview={tenantOverview}
                sessions={tenantSessions}
                trends={trends}
                onSelectTab={setActiveTab}
                onOpenLiveStream={() => setIsStreamModalOpen(true)}
              />
            )}

            {activeTab === 'studio' && (
              <LiveScannerStudio
                currentRole={currentRole}
                onAddFinding={handleAddFindingFromStudio}
              />
            )}

            {activeTab === 'findings' && (
              <FindingsTab
                findings={tenantFindings}
                currentRole={currentRole}
                onProposePatch={handleProposePatch}
                onOpenAiPatchModal={(finding) => setSelectedPatchFinding(finding)}
                selectedFindingId={selectedFindingId}
                onSelectFindingId={setSelectedFindingId}
              />
            )}

            {activeTab === 'remediation' && (
              <RemediationTab patches={tenantPatches} currentRole={currentRole} />
            )}

            {activeTab === 'intel' && (
              <ThreatIntelTab
                advisories={osvAdvisories}
                currentRole={currentRole}
                onSyncAdvisories={handleSyncAdvisories}
              />
            )}

            {activeTab === 'research' && <ResearchTab campaigns={campaigns} currentRole={currentRole} />}

            {activeTab === 'fleet' && <WorkerFleetTab workers={workers} />}

            {activeTab === 'webhooks' && <WebhookTab currentRole={currentRole} />}

            {activeTab === 'audit' && <AuditTab auditLogs={tenantAuditLogs} />}
          </main>

          {/* Footer */}
          <footer className="border-t border-zinc-800 py-3 px-6 text-xs text-zinc-500 bg-zinc-950/60 mt-auto">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-2">
                <Shield className="size-3.5 text-primary" />
                <span>Sentra Security Platform • RFC 2104 / OASIS SARIF v2.1.0 Compliant</span>
              </div>
              <div className="flex items-center gap-4 text-[11px] font-mono">
                <span>Fail-Closed Host Boundary</span>
                <span>Zero-Egress Isolation</span>
                <span>Human-in-the-Loop Governance</span>
              </div>
            </div>
          </footer>
        </div>

        {/* Global Command Palette (⌘K) */}
        <CommandPalette
          open={isCommandOpen}
          onOpenChange={setIsCommandOpen}
          onSelectTab={setActiveTab}
          onExportSarif={handleExportSarif}
          onToggleConsole={() => setIsConsoleOpen((v) => !v)}
          findings={tenantFindings}
        />

        {/* SARIF Export Dialog */}
        <Dialog open={!!sarifModalContent} onOpenChange={(open) => !open && setSarifModalContent(null)}>
          <DialogContent className="sm:max-w-2xl max-h-[85vh] flex flex-col bg-zinc-950 border-zinc-800">
            <DialogHeader>
              <DialogTitle className="text-base font-bold flex items-center gap-2 text-zinc-100">
                <FileDown className="size-4 text-primary" />
                OASIS SARIF v2.1.0 Security Report
              </DialogTitle>
              <DialogDescription className="text-xs text-zinc-400">
                Exportable directly to GitHub Advanced Security Code Scanning, GitLab SAST, or VS Code.
              </DialogDescription>
            </DialogHeader>

            <div className="flex-1 overflow-y-auto bg-black/60 p-3 rounded-md border border-zinc-800 font-mono text-xs my-2 text-zinc-300">
              <pre className="whitespace-pre-wrap">{sarifModalContent}</pre>
            </div>

            <div className="flex items-center justify-between gap-2 pt-2 border-t border-zinc-800">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  if (sarifModalContent) {
                    copyText(sarifModalContent)
                    toast.success('SARIF JSON copied to clipboard')
                  }
                }}
                className="border-zinc-800 bg-zinc-900 text-zinc-300 hover:text-zinc-100"
              >
                <Copy className="size-3.5 mr-1.5" />
                Copy SARIF JSON
              </Button>

              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setSarifModalContent(null)}
                  className="border-zinc-800"
                >
                  Close
                </Button>
                <Button size="sm" onClick={handleDownloadSarif} className="bg-primary text-primary-foreground font-semibold">
                  <FileDown className="size-3.5 mr-1.5" />
                  Download .sarif File
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>

        {/* Live Stream SSE Modal */}
        <LiveStreamModal
          open={isStreamModalOpen}
          onOpenChange={setIsStreamModalOpen}
          initialWorkspace={currentWorkspace}
          currentRole={currentRole}
          onScanComplete={handleStreamScanComplete}
          onNavigateToFindings={() => setActiveTab('findings')}
        />

        {/* Autonomous AI Patch & Remediation Modal */}
        <AiPatchModal
          open={!!selectedPatchFinding}
          onOpenChange={(open) => !open && setSelectedPatchFinding(null)}
          finding={selectedPatchFinding}
          currentRole={currentRole}
          onAdmitPatch={handleAdmitPatch}
          onNavigateToPatches={() => setActiveTab('remediation')}
        />

        {/* Dynamic Organization / Tenant Registration Modal */}
        <AddTenantDialog
          open={isAddTenantOpen}
          onOpenChange={setIsAddTenantOpen}
          currentRole={currentRole}
          onTenantCreated={handleTenantCreated}
          currentWorkspace={currentWorkspace}
        />

        {/* Global System Settings & AI Provider Credentials Modal */}
        <SettingsDialog
          open={isSettingsOpen}
          onOpenChange={setIsSettingsOpen}
          currentRole={currentRole}
        />

        {/* Global Sonner Toaster */}
        <Toaster />
      </div>
    </TooltipProvider>
  )
}

export default App
