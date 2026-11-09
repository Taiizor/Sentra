export type TenantId = 'sentra-internal' | 'tenant-alpha' | 'acme-corp'

export type UserRole = 'Viewer' | 'Operator' | 'SecurityAdmin'

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'

export type Confidence = 'High' | 'Medium' | 'Low'

export type Reachability =
  | 'ReachableCallPath'
  | 'SinkOnly'
  | 'Unreachable'
  | 'Inconclusive'

export type FindingStatus =
  | 'Candidate'
  | 'Validated'
  | 'Rejected'
  | 'VerifiedRemediated'

export interface TaintStep {
  step: number
  role: 'SOURCE' | 'PROPAGATION' | 'SANITIZER' | 'SINK'
  location: string
  line: number
  codeSnippet: string
  variable: string
}

export interface FindingView {
  findingId: string
  tenantId: TenantId
  ruleId: string
  cwe: string
  title: string
  severity: Severity
  confidence: Confidence
  reachability: Reachability
  status: FindingStatus
  targetLocation: string
  startLine: number
  endLine: number
  description: string
  taintTrace?: TaintStep[]
  createdAt: string
}

export interface PatchBundleView {
  bundleId: string
  tenantId: TenantId
  findingId: string
  title: string
  originalTestStatus: 'Failed' | 'Passed'
  patchedTestStatus: 'Failed' | 'Passed'
  regressionsPass: boolean
  isVerified: boolean
  attemptCount: number
  diff: string
  branchName: string
  ghPrCommand: string
  createdAt: string
}

export interface SessionSummaryView {
  sessionId: string
  tenantId: TenantId
  workspaceRoot: string
  state: 'SCOPED' | 'IN_PROGRESS' | 'COMPLETED' | 'FAILED'
  fencingEpoch: number
  taskCount: number
  createdAt: string
  updatedAt: string
}

export interface CampaignLedgerView {
  campaignId: string
  tenantId: TenantId
  title: string
  maxBudgetMicroUsd: number
  spentBudgetMicroUsd: number
  status: 'ACTIVE' | 'CONCLUDED' | 'PAUSED'
  taskCount: number
  coveredRegions: number
  skippedRegions: number
}

export interface AuditLogView {
  eventId: string
  tenantId: TenantId
  sequenceNumber: number
  actor: string
  action: string
  details: string
  timestamp: string
}

export interface DashboardOverview {
  tenantId: TenantId
  workspaceName: string
  totalSessions: number
  activeSessions: number
  criticalFindings: number
  highFindings: number
  mediumFindings: number
  lowFindings: number
  infoFindings: number
  verifiedPatches: number
  totalSpentMicroUsd: number
  auditEventCount: number
  lastActivityTimestamp: string
}
