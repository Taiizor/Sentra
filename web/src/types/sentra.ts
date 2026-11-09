export type TenantId = string

export interface TenantView {
  tenantId: TenantId
  name: string
  description?: string
  defaultWorkspace?: string
  isolationLevel: 'single_operator' | 'multi_tenant_isolated'
  createdAt: string
}

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

export type FindingVerdict = 'confirmed' | 'needs_validation' | 'rejected'

export interface FindingTraceNode {
  kind: 'entrypoint' | 'propagation' | 'sink'
  file: string
  line: number
  scope: string
  description: string
}

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
  verdict?: FindingVerdict
  rootCause?: string
  intendedBehavior?: string
  smallestEffectiveFix?: string
  unresolvedBlocker?: string
  blockers?: string[]
  validationPlan?: {
    local?: string
    deployment?: string
  }
  rejectionReason?: string
  fingerprint?: string
  auditTrace?: FindingTraceNode[]
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
  targetLocation?: string
  backupPath?: string
  isAppliedToDisk?: boolean
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

export type LedgerStatus =
  | 'planned'
  | 'candidate'
  | 'covered'
  | 'needs_validation'
  | 'deferred'
  | 'blocked'
  | 'out_of_scope'
  | 'not_applicable'
  | 'in_progress'

export type AuditProfile = 'quick' | 'standard' | 'deep'

export interface CoverageLedgerUnit {
  coverageId: string
  surface: string
  boundary: string
  subsystem: string
  attackClass: string
  status: LedgerStatus
  wave: number
  agentId?: string
  reviewedPaths: string[]
  localChecks: string[]
  resultFingerprints: string[]
  unresolved?: string
}

export interface CoverageLedgerReport {
  repoName: string
  targetRef: string
  profile: AuditProfile
  budget: {
    maxAgentCalls: number
    spentAgentCalls: number
    reservedCritics: number
    reservedVerifiers: number
  }
  stats: {
    totalUnits: number
    covered: number
    candidate: number
    needsValidation: number
    planned: number
    deferred: number
    blocked: number
    outOfScope: number
  }
  units: CoverageLedgerUnit[]
  invariantsPass: boolean
  validationOutput?: string
}

export interface ReconTopologyEntrypoint {
  type: 'http_route' | 'cli_command' | 'grpc_service' | 'queue_consumer' | 'model_tool'
  path: string
  line: number
  handler: string
  surface: string
  authRequired: boolean
}

export interface ReconSubsystemBoundary {
  name: string
  path: string
  language: string
  trustLevel: 'untrusted_input' | 'internal_service' | 'isolated_storage' | 'high_privilege'
  controls: string[]
}

export interface ReconTopologyReport {
  repoName: string
  languages: { name: string; percentage: number; files: number }[]
  frameworks: string[]
  subsystems: ReconSubsystemBoundary[]
  entrypoints: ReconTopologyEntrypoint[]
  offlineTestCommands: string[]
  prohibitedActions: string[]
  missingTools: string[]
  timestamp: string
}

export interface Phase1ReconAgentOutput {
  agentId: '1a_product_stack' | '1b_principals_controls' | '1c_surfaces_sinks' | '1d_sandbox_testability'
  agentName: string
  summary: string
  findingsCount: number
  sourceRefs: string[]
}

export interface Phase1ReconReport {
  repoName: string
  agents: Phase1ReconAgentOutput[]
  architectureSummaryMd: string
  derivedUnitsCount: number
  timestamp: string
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
