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
  cvssScore: number
  remediationGuidance: string
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
  originalSnippet: string
  patchedSnippet: string
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
  targetArchitecture: string
  fuzzEngine: string
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
  cryptoHash: string
  timestamp: string
}

export interface WorkerNodeView {
  workerId: string
  hostname: string
  architecture: 'x86_64-linux' | 'x86_64-windows'
  state: 'AVAILABLE' | 'LEASED' | 'QUARANTINED' | 'RESETTING'
  tenantLease: TenantId | null
  cpuUsagePercent: number
  memoryUsageMb: number
  egressPolicy: 'StrictlyDenied'
  activeJob: string | null
}

export interface OsvAdvisoryView {
  id: string
  package: string
  ecosystem: 'crates.io' | 'npm' | 'PyPI' | 'Go'
  vulnerability: string
  affectedRange: string
  fixedVersion: string
  severity: Severity
  publishedAt: string
}

export interface SecurityTrendPoint {
  date: string
  detected: number
  remediated: number
  activeCritical: number
}

export interface DashboardOverview {
  tenantId: TenantId
  workspaceName: string
  securityScore: number
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
