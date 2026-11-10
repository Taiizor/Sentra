/**
 * Shared HTTP contract between the Bun bridge (web/server) and the React console (web/src).
 * Both sides import these types, so a DTO change is a compile-time change on both ends.
 *
 * Ground rules encoded here:
 * - Every value originates from a real source (core CLI JSON, core SQLite read-only views,
 *   the bridge's own persisted records, GitHub, OSV, configured model providers) or is
 *   explicitly `null` / an empty list / an "unavailable" status.
 * - Scanner and model output are candidates. Nothing in this contract can express
 *   "verified" for a patch: `verificationStatus` is always 'not_run' until an isolated
 *   verifier exists.
 */

// ───────────────────────────── shared primitives ─────────────────────────────

export type Role = 'viewer' | 'operator' | 'admin'
export type RoleLabel = 'Viewer' | 'Operator' | 'SecurityAdmin'

export type Permission =
  | 'read'
  | 'scan:run'
  | 'finding:triage'
  | 'intel:query'
  | 'plugin:probe'
  | 'plugin:run'
  | 'prompt:generate'
  | 'ai:generate'
  | 'ai:test'
  | 'patch:apply'
  | 'research:write'
  | 'research:run'
  | 'console:run'
  | 'github:read'
  | 'github:scan'
  | 'github:comment'
  | 'github:status'
  | 'github:create-pr'
  | 'tenant:create'
  | 'settings:write'
  | 'audit:verify'

/**
 * The single source of the role matrix: the minimum role holding each permission. The bridge
 * derives its enforcement table from this map (web/server/permissions.ts); the console uses it
 * only to explain why an action is unavailable.
 */
export const PERMISSION_MIN_ROLE: Readonly<Record<Permission, Role>> = {
  read: 'viewer',
  'github:read': 'viewer',
  'audit:verify': 'viewer',
  'scan:run': 'operator',
  'finding:triage': 'operator',
  'intel:query': 'operator',
  'plugin:probe': 'operator',
  'prompt:generate': 'operator',
  'ai:generate': 'operator',
  'research:write': 'operator',
  'research:run': 'operator',
  'console:run': 'operator',
  'github:scan': 'operator',
  'ai:test': 'admin',
  'plugin:run': 'admin',
  'patch:apply': 'admin',
  'github:comment': 'admin',
  'github:status': 'admin',
  'github:create-pr': 'admin',
  'tenant:create': 'admin',
  'settings:write': 'admin',
}

export const ROLE_LABELS: Readonly<Record<Role, RoleLabel>> = {
  viewer: 'Viewer',
  operator: 'Operator',
  admin: 'SecurityAdmin',
}

/** e.g. "Requires SecurityAdmin (permission: patch:apply)". */
export function permissionHint(permission: Permission): string {
  return `Requires ${ROLE_LABELS[PERMISSION_MIN_ROLE[permission]]} (permission: ${permission})`
}

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational' | 'Unknown'
export const SEVERITIES: readonly Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational', 'Unknown']

export interface ApiErrorBody {
  error: { code: string; message: string; details?: unknown }
}

// ───────────────────────────── auth & system ─────────────────────────────

export interface LoginRequest {
  token: string
}

export interface SessionInfo {
  authenticated: true
  role: Role
  roleLabel: RoleLabel
  principal: string
  via: 'session' | 'bearer'
  permissions: Permission[]
  expiresAt: string | null
}

export interface HealthResponse {
  status: 'ok'
  coreAvailable: boolean
}

export interface HostInfo {
  hostname: string
  platform: string
  release: string
  arch: string
  cpuModel: string | null
  cpuCount: number
  loadAverage: number[] | null
  totalMemoryBytes: number
  freeMemoryBytes: number
  uptimeSeconds: number
  processRssBytes: number
  bunVersion: string
  cliQueued: number
  sampledAt: string
}

export interface ToolAvailability {
  name: string
  available: boolean
  path: string | null
}

export interface SystemStatus {
  mode: 'production' | 'development'
  core: { binaryPath: string; present: boolean; version: string | null; error: string | null }
  dataDir: string
  host: HostInfo
  tools: ToolAvailability[]
  integrations: {
    githubCredentialSource: GitHubCredentialSource | null
    osvEnabled: boolean
    aiDefaultProvider: ProviderId | null
    aiReadyProviders: ProviderId[]
    githubWebhookSecretConfigured: boolean
    gitlabWebhookTokenConfigured: boolean
  }
  auth: { configuredGrants: number; generatedLocalToken: boolean; bindHost: string; loopbackOnly: boolean }
  /** The core has no persisted remote-worker registry; this is reported, never simulated. */
  remoteWorkers: { registry: 'not_available'; note: string }
}

// ───────────────────────────── tenants & core store ─────────────────────────────

export type IsolationLevel = 'single_operator' | 'multi_tenant_isolated'

export interface RepositoryRef {
  owner: string
  repo: string
  source: 'configured' | 'git_remote'
}

export interface CoreStoreState {
  initialized: boolean
  error: string | null
}

export interface TenantView {
  tenantId: string
  name: string
  description: string
  /** Absolute, canonical workspace root registered by an admin. */
  workspace: string
  workspaceExists: boolean
  /** Declared label only; isolation is not enforced by this console. */
  isolationLevel: IsolationLevel
  githubRepository: RepositoryRef | null
  gitHead: { branch: string | null; sha: string | null } | null
  createdAt: string
  createdBy: string
  coreStore: CoreStoreState
}

export interface CreateTenantRequest {
  tenantId: string
  name: string
  description?: string
  workspace: string
  isolationLevel: IsolationLevel
  /** `owner/repo`; optional, otherwise detected from the workspace's git remote. */
  githubRepository?: string
}

export interface UpdateTenantRequest {
  name?: string
  description?: string
  githubRepository?: string | null
}

export interface CoreSessionView {
  initialized: boolean
  sessionId: string | null
  state: string | null
  mode: string | null
  classificationFloor: string | null
  contextGeneration: number | null
  createdAt: string | null
  updatedAt: string | null
  budgetLimitMicroUsd: number | null
  budgetUsedMicroUsd: number | null
  error: string | null
}

export interface CoreTaskView {
  taskId: string
  sequenceNumber: number
  title: string
  state: string
  createdAt: string
  updatedAt: string
  completedAt: string | null
}

export interface CoreAuditEventView {
  eventId: string
  sessionId: string
  sequenceNumber: number
  eventKind: string
  classification: string
  timestamp: string
  actionDigest: string | null
  operatorId: string | null
  policyId: string | null
  /** The `event` object of the core envelope, or the whole details object when absent. */
  event: unknown
  /** True when the row does not carry the core's versioned envelope (e.g. legacy bridge writes). */
  nonCoreEnvelope: boolean
}

export interface CoreAuditView {
  session: CoreSessionView
  events: CoreAuditEventView[]
  totalEvents: number
  tasks: CoreTaskView[]
  totalTasks: number
}

export interface ResearchSessionsView {
  session: CoreSessionView
  tasks: CoreTaskView[]
  budgetReservations: {
    reservationId: string
    modelId: string
    reservedMicroUsd: number
    actualMicroUsd: number | null
    state: string
    reservedAt: string
    settledAt: string | null
  }[]
  approvals: {
    requestId: string
    actionName: string
    state: string
    classification: string
    displaySummary: string
    createdAt: string
    expiresAt: string
  }[]
}

// ───────────────────────────── scans & findings ─────────────────────────────

export type ScanKind = 'sast' | 'dependency' | 'codeql' | 'all'
export type ScanTrigger = 'operator' | 'webhook' | 'pull_request'
export type ScanStatus = 'running' | 'completed' | 'failed'

export interface LockfileView {
  /** Workspace-relative path with forward slashes. */
  path: string
  kind: string
  ecosystem: string | null
  packages: number
  parseError: string | null
}

export interface DependencyPackageView {
  name: string
  version: string
  ecosystem: string | null
  lockfile: string
}

export interface DependencyInventoryView {
  lockfiles: LockfileView[]
  packages: DependencyPackageView[]
  totalPackages: number
  /** True when the core hit an inventory limit and the list is incomplete. */
  truncated: boolean
  generatedAt: string
}

export interface CodeqlProbeView {
  primaryLanguage: string | null
  detectedLanguages: { language: string; filesCount: number }[]
  /** Suggested commands only — CodeQL is never executed by Sentra. */
  suggestedCreateCommand: string | null
  suggestedAnalyzeCommand: string | null
  codeqlInstalled: boolean
}

export interface ScanRunSummary {
  sast: { filesScanned: number; signalsFound: number; bySeverity: Record<Severity, number> } | null
  dependency: {
    lockfiles: LockfileView[]
    packagesAudited: number
    vulnerablePackages: number
    vulnerabilities: number
    advisorySource: 'osv.dev'
    queriedAt: string
  } | null
  /** Set when the dependency stage was skipped (e.g. OSV lookups disabled by policy). */
  dependencySkippedReason: string | null
  codeql: CodeqlProbeView | null
  newFindings: number
  resolvedFindings: number
  stillOpen: number
  stageErrors: { stage: string; message: string }[]
}

export interface ScanRunView {
  runId: string
  tenantId: string
  workspace: string
  kind: ScanKind
  trigger: ScanTrigger
  status: ScanStatus
  startedAt: string
  finishedAt: string | null
  actor: string
  filesScanned: number | null
  signalsFound: number | null
  packagesAudited: number | null
  vulnerablePackages: number | null
  gitHead: string | null
  error: string | null
  summary: ScanRunSummary | null
}

export interface StartScanRequest {
  kind: ScanKind
}

/** Events streamed by POST /api/tenants/:id/scans when `Accept: text/event-stream`. */
export type ScanStreamEvent =
  | { type: 'run'; run: ScanRunView }
  | { type: 'stage'; stage: 'sast' | 'dependency' | 'codeql' | 'persist'; status: 'started' | 'completed' | 'failed' | 'skipped'; message: string }
  | { type: 'log'; stream: 'stdout' | 'stderr' | 'bridge'; text: string; ts: string }
  | { type: 'complete'; run: ScanRunView }
  /** `status` is the HTTP status the same failure would have had as a JSON response (500 when unexpected). */
  | { type: 'error'; status: number; code: string; message: string }

export type FindingSource = 'sast' | 'dependency'
export type FindingState = 'open' | 'resolved'
export type TriageVerdict = 'confirmed' | 'needs_validation' | 'rejected'

export interface TaintStepView {
  step: number
  role: 'SOURCE' | 'PROPAGATION' | 'SANITIZER' | 'SINK'
  line: number | null
  variable: string | null
  code: string | null
}

export interface DependencyFindingDetails {
  packageName: string
  packageVersion: string
  ecosystem: string
  lockfile: string
  advisoryId: string
  aliases: string[]
  summary: string | null
  details: string | null
  /**
   * `fixed` events of the affected range(s) that contain `packageVersion`, merged across the
   * advisory and its aliases. Empty when that range has no published fix. When the ranges could
   * not be evaluated for the installed version, `fixedVersionsNote` says how the list was built.
   */
  fixedVersions: string[]
  /** Null when `fixedVersions` was filtered for the installed version; otherwise the caveat. */
  fixedVersionsNote: string | null
  references: { type: string; url: string }[]
  published: string | null
  modified: string | null
  severitySource: 'database_specific' | 'cvss_v3' | 'cvss_v2' | 'none'
  cvssVector: string | null
  cvssScore: number | null
}

export interface FindingView {
  findingId: string
  tenantId: string
  source: FindingSource
  ruleId: string
  ruleName: string
  cwe: string | null
  severity: Severity
  category: string | null
  filePath: string | null
  line: number | null
  snippet: string | null
  rationale: string | null
  taintTrace: TaintStepView[] | null
  dependency: DependencyFindingDetails | null
  state: FindingState
  firstSeenAt: string
  lastSeenAt: string
  firstSeenRun: string
  lastSeenRun: string
  resolvedAt: string | null
  triage: { verdict: TriageVerdict; reason: string; by: string; at: string } | null
}

export interface TriageRequest {
  verdict: TriageVerdict
  reason: string
}

export interface FileContentView {
  path: string
  sizeBytes: number
  lineCount: number
  content: string
  truncated: boolean
  language: string | null
}

export interface OverviewView {
  tenant: TenantView
  lastRun: ScanRunView | null
  /** Finish time of the newest completed run of any kind (including CodeQL language probes). */
  lastCompletedRunAt: string | null
  /** Finish time of the newest completed run that produced SAST or dependency results. */
  lastResultRunAt: string | null
  openFindings: {
    /** Open findings not triaged as rejected; `bySeverity` and `bySource` add up to this. */
    total: number
    bySeverity: Record<Severity, number>
    bySource: Record<FindingSource, number>
    /**
     * Every open finding by triage verdict. `rejected` counts open findings triaged as rejected,
     * which are excluded from `total`, so untriaged + confirmed + needs_validation = total.
     */
    byTriage: { untriaged: number; confirmed: number; needs_validation: number; rejected: number }
  }
  resolvedFindings: number
  patches: { proposed: number; applied: number; rolledBack: number; pullRequests: number }
  core: CoreSessionView & { taskCount: number | null; auditEventCount: number | null }
  /** Operator audit entries recorded for this tenant only (global entries such as logins are not counted). */
  operatorAuditEntries: number
  /**
   * Null until a completed run produced SAST or dependency results (a CodeQL probe or a
   * dependency stage skipped by policy does not count). The formula is part of the payload.
   */
  riskScore: { value: number; formula: string } | null
}

export interface TrendPoint {
  date: string
  scans: number
  newFindings: number
  resolvedFindings: number
  openAtEndOfDay: number
  openCriticalAtEndOfDay: number
}

export interface SastMatchView {
  ruleId: string
  ruleName: string
  cwe: string | null
  severity: Severity
  category: string | null
  filePath: string
  line: number
  snippet: string | null
  rationale: string | null
}

export interface SnippetScanRequest {
  code: string
  /** File name used for rule selection, e.g. `snippet.rs`, `handler.py`, `ci.yml`. */
  fileName: string
}

export interface SnippetScanView {
  fileName: string
  filesScanned: number
  signalsFound: number
  matches: SastMatchView[]
}

// ───────────────────────────── patches (model-generated candidates) ─────────────────────────────

export type PatchState = 'proposed' | 'applied' | 'rolled_back'

export interface PatchBundleView {
  bundleId: string
  tenantId: string
  findingId: string
  createdAt: string
  createdBy: string
  provider: ProviderId
  model: string
  title: string
  targetPath: string
  diff: string
  rootCause: string | null
  rationale: string | null
  originalSnippet: string | null
  patchedSnippet: string | null
  testCode: string | null
  branchName: string | null
  commitMessage: string | null
  /** Result of a real dry-run apply of `diff` against the current workspace file. */
  appliesCleanly: boolean
  applyCheckDetail: string | null
  /** No isolated verifier exists yet; patches are never reported as verified. */
  verificationStatus: 'not_run'
  state: PatchState
  appliedAt: string | null
  appliedBy: string | null
  rolledBackAt: string | null
  rolledBackBy: string | null
  pullRequest: { number: number; url: string } | null
}

export interface GeneratePatchRequest {
  provider?: ProviderId
}

export interface CreatePullRequestRequest {
  baseBranch?: string
}

export interface CreatePullRequestResponse {
  number: number
  url: string
  branch: string
  baseBranch: string
  baseSha: string
  commitSha: string
}

// ───────────────────────────── threat intelligence (OSV) ─────────────────────────────

export interface IntelStatusView {
  osvEnabled: boolean
  changedBy: string | null
  changedAt: string | null
  endpoint: string
  cachedAdvisories: number
  lastQueryAt: string | null
  privacyNote: string
}

export interface IntelSettingsRequest {
  osvEnabled: boolean
}

export interface OsvQueryRequest {
  package: string
  ecosystem: string
  version?: string
}

export interface OsvAffectedView {
  ecosystem: string
  package: string
  ranges: { type: string; introduced: string | null; fixed: string | null; lastAffected: string | null }[]
  versions: string[]
}

export interface OsvVulnerabilityView {
  id: string
  summary: string | null
  details: string | null
  aliases: string[]
  severity: Severity
  severitySource: DependencyFindingDetails['severitySource']
  cvssVector: string | null
  cvssScore: number | null
  published: string | null
  modified: string | null
  withdrawn: string | null
  affected: OsvAffectedView[]
  references: { type: string; url: string }[]
  /** Fixes for the queried version (see DependencyFindingDetails.fixedVersions). */
  fixedVersions: string[]
  /** Null when `fixedVersions` was filtered for the queried version; otherwise the caveat. */
  fixedVersionsNote: string | null
  cwes: string[]
}

export interface OsvQueryResponse {
  package: string
  ecosystem: string
  version: string | null
  vulnerabilities: OsvVulnerabilityView[]
  queriedAt: string
}

// ───────────────────────────── AI provider settings ─────────────────────────────

export type ProviderId = 'anthropic' | 'openai' | 'gemini' | 'deepseek' | 'xai' | 'openrouter' | 'opencode' | 'local'

export interface ProviderStatusView {
  id: ProviderId
  label: string
  model: string | null
  endpoint: string
  usesCustomEndpoint: boolean
  requiresKey: boolean
  keyConfigured: boolean
  maskedKey: string | null
  keyUpdatedAt: string | null
  ready: boolean
  customEndpointAllowed: boolean
  loopbackOnly: boolean
}

export interface AiSettingsView {
  defaultProvider: ProviderId | null
  providers: ProviderStatusView[]
  updatedAt: string | null
  updatedBy: string | null
}

export interface UpdateProviderRequest {
  model?: string | null
  endpoint?: string | null
  apiKey?: string
  clearKey?: boolean
}

export interface SetDefaultProviderRequest {
  provider: ProviderId | null
}

export interface ListModelsResponse {
  provider: ProviderId
  models: string[]
  latencyMs: number
}

// ───────────────────────────── GitHub ─────────────────────────────

export type GitHubCredentialSource = 'stored_pat' | 'env_token' | 'gh_cli'

export interface GitHubCredentialView {
  source: GitHubCredentialSource | null
  storedTokenConfigured: boolean
  storedTokenUpdatedAt: string | null
}

export interface GitHubStatusView {
  credential: GitHubCredentialView
  viewer: { login: string; scopes: string | null } | null
  viewerError: string | null
  /**
   * Why `viewerError` is set: no credential source, a stored token that could not be decrypted,
   * or a failed GitHub /user check with an available credential. Null when there is no error.
   */
  viewerErrorKind: 'no_credential' | 'credential_unreadable' | 'check_failed' | null
  repository: RepositoryRef | null
  repositoryInfo: {
    fullName: string
    private: boolean
    defaultBranch: string
    htmlUrl: string
    permissions: Record<string, boolean> | null
  } | null
  repositoryError: string | null
}

export interface SetRepositoryRequest {
  /** `owner/repo`, or null to fall back to git-remote detection. */
  repository: string | null
}

export interface SetGitHubTokenRequest {
  token: string
}

export type PrSecurityStatus = 'not_scanned' | 'stale' | 'clean' | 'warnings' | 'critical' | 'failed'

export interface PrSecurityView {
  status: PrSecurityStatus
  scannedHeadSha: string | null
  scannedAt: string | null
  scannedBy: string | null
  signalsFound: number | null
  criticalCount: number | null
  highCount: number | null
  filesScanned: number | null
  filesConsidered: number | null
}

export interface PullRequestView {
  number: number
  title: string
  state: 'open'
  isDraft: boolean
  author: { login: string; avatarUrl: string | null }
  headRef: string
  headSha: string
  baseRef: string
  htmlUrl: string
  createdAt: string
  updatedAt: string
  filesCount: number
  additions: number
  deletions: number
  checks: { total: number; successful: number; failed: number; inProgress: number; rollupState: string | null }
  isSentraBranch: boolean
  security: PrSecurityView
}

export interface PullRequestListView {
  repository: { owner: string; repo: string }
  pulls: PullRequestView[]
  fetchedAt: string
}

export interface WorkflowStepView {
  number: number
  name: string
  status: string
  conclusion: string | null
  startedAt: string | null
  completedAt: string | null
  durationSeconds: number | null
}

export interface WorkflowJobView {
  id: number
  name: string
  status: string
  conclusion: string | null
  htmlUrl: string | null
  startedAt: string | null
  completedAt: string | null
  steps: WorkflowStepView[]
}

export interface WorkflowRunView {
  id: number
  name: string
  workflowPath: string
  event: string
  status: string
  conclusion: string | null
  htmlUrl: string
  headSha: string
  headBranch: string | null
  runNumber: number
  runAttempt: number
  createdAt: string
  runStartedAt: string | null
  updatedAt: string
  jobs: WorkflowJobView[]
}

export interface PullRequestWorkflowsView {
  prNumber: number
  headSha: string
  runs: WorkflowRunView[]
}

export interface PrScanResultView {
  prNumber: number
  headSha: string
  status: Exclude<PrSecurityStatus, 'not_scanned' | 'stale'>
  filesConsidered: number
  filesScanned: number
  skipped: { path: string; reason: string }[]
  matches: SastMatchView[]
  signalsFound: number
  criticalCount: number
  highCount: number
  scannedAt: string
  scannedBy: string
  error: string | null
}

export interface PrCommentRequest {
  body: string
}

export interface PrCommentResponse {
  id: number
  url: string
}

export interface PrStatusRequest {
  state: 'success' | 'failure' | 'pending' | 'error'
  description: string
}

export interface PrStatusResponse {
  sha: string
  state: PrStatusRequest['state']
}

// ───────────────────────────── webhooks ─────────────────────────────

export type WebhookDeliveryStatus = 'rejected' | 'duplicate' | 'ignored' | 'accepted' | 'scanned' | 'failed'

export interface WebhookDeliveryView {
  provider: 'github' | 'gitlab'
  deliveryId: string
  eventType: string
  receivedAt: string
  repository: string | null
  ref: string | null
  afterSha: string | null
  sender: string | null
  signatureValid: boolean
  status: WebhookDeliveryStatus
  detail: string | null
  tenantId: string | null
  runId: string | null
}

export interface WebhookConfigView {
  github: { path: '/api/webhook/github'; secretConfigured: boolean }
  gitlab: { path: '/api/webhook/gitlab'; tokenConfigured: boolean }
  bindHost: string
  /** Deliveries that failed authentication are counted in memory only (never persisted). */
  rejectedSinceStart: number
  lastRejectedAt: string | null
  note: string
}

// ───────────────────────────── research ─────────────────────────────

export type CoverageStatus =
  | 'planned'
  | 'candidate'
  | 'covered'
  | 'needs_validation'
  | 'deferred'
  | 'blocked'
  | 'out_of_scope'

export interface CoverageUnitView {
  coverageId: string
  surface: string
  boundary: string
  subsystem: string
  attackClass: string
  status: CoverageStatus
  wave: number
  owner: string | null
  reviewedPaths: string[]
  localChecks: string[]
  resultFingerprints: string[]
  unresolved: string | null
  createdAt: string
  updatedAt: string
  updatedBy: string
}

export interface UpsertCoverageUnitRequest {
  surface: string
  boundary: string
  subsystem: string
  attackClass: string
  status: CoverageStatus
  wave: number
  owner?: string | null
  reviewedPaths: string[]
  localChecks: string[]
  resultFingerprints: string[]
  unresolved?: string | null
}

export interface CoverageValidationView {
  valid: boolean
  checkedUnits: number
  errors: { coverageId: string; rule: string; message: string }[]
  validatedAt: string
}

export interface TopologyReportView {
  reportId: string
  tenantId: string
  workspace: string
  createdAt: string
  createdBy: string
  languages: { language: string; filesCount: number }[]
  primaryLanguage: string | null
  manifests: { path: string; kind: string; ecosystem: string | null }[]
  frameworks: { name: string; version: string | null; manifest: string }[]
  subsystems: { name: string; path: string; kind: string }[]
  /** Heuristic: files that look like entry points, with the evidence that matched. */
  entrypoints: { path: string; kind: string; evidence: string }[]
  lockfiles: LockfileView[]
  packagesTotal: number
  tools: ToolAvailability[]
  notes: string[]
}

export type ReconWorkflow = 'scout' | 'threat-model'

export interface ModelReconRequest {
  workflow: ReconWorkflow
  provider?: ProviderId
}

export interface ModelReconReportView {
  reportId: string
  tenantId: string
  createdAt: string
  createdBy: string
  provider: ProviderId
  model: string
  workflow: ReconWorkflow
  topologyReportId: string | null
  output: string
  inputTokens: number | null
  outputTokens: number | null
  latencyMs: number
  /** Always shown with the report: model output is an unverified candidate. */
  disclaimer: string
}

// ───────────────────────────── plugins, skills, prompts, console, diff ─────────────────────────────

export interface PluginView {
  id: string
  name: string
  version: string
  family: string
  manifestPath: string
  executablePath: string | null
  capabilities: string[]
  /** Declared by the manifest; not enforced by an isolation profile. */
  declaredEgressPolicy: string
  declaredQuotas: { maxMemoryMib: number; maxExecutionTimeSecs: number } | null
}

export interface PluginsView {
  pluginDir: string | null
  configured: boolean
  plugins: PluginView[]
  note: string
}

export interface PluginProbeRequest {
  tenantId: string
}

export interface PluginProbeView {
  pluginId: string
  name: string | null
  applicable: boolean
  details: string
  unsupportedReason: string | null
  capabilities: string[]
}

export interface PluginRunRequest {
  tenantId: string
  capability: string
  args?: Record<string, unknown>
}

export interface PluginRunView {
  pluginId: string
  capability: string
  taskId: string | null
  exitCode: number
  summary: string
  /** Adapter-reported references; not admitted evidence. */
  reportedEvidenceRefs: string[]
  stdout: string
  stderr: string
}

export interface SkillSummaryView {
  id: string
  name: string
  category: string
  description: string
  tags: string[]
}

export interface SkillDetailView extends SkillSummaryView {
  content: string
}

export type PromptWorkflow = 'scout' | 'threat-model' | 'api-bola' | 'patch-remediation' | 'skill-audit' | 'verify'

export interface PromptRequest {
  workflow: PromptWorkflow
  skills?: string[]
}

export interface PromptView {
  workflow: PromptWorkflow
  name: string
  role: string
  scope: string
  skills: string[]
  systemPrompt: string
  userPrompt: string
  compositePrompt: string
  expectedSchema: string | null
  /** The core fills some context fields from fixed templates; surfaced so operators can edit them. */
  templateWarning: string
}

export type ConsoleCommand = 'version' | 'status' | 'scan' | 'codeql' | 'inventory' | 'skills' | 'plugins'

export interface ConsoleRunRequest {
  command: ConsoleCommand
}

export interface ConsoleRunView {
  command: ConsoleCommand
  argv: string[]
  exitCode: number
  stdout: string
  stderr: string
  durationMs: number
  timedOut: boolean
}

export interface DiffRequest {
  /** Absolute directories; each must lie inside a registered tenant workspace. */
  base: string
  head: string
}

export interface DiffDeltaView {
  path: string
  fromPath: string | null
  kind: 'added' | 'modified' | 'deleted' | 'renamed' | 'unchanged' | string
  role: string | null
  baseDigest: string | null
  headDigest: string | null
  baseSize: number | null
  headSize: number | null
}

export interface DiffView {
  baseAggregateDigest: string
  headAggregateDigest: string
  summary: {
    totalFilesBase: number
    totalFilesHead: number
    addedFiles: number
    modifiedFiles: number
    deletedFiles: number
    renamedFiles: number
    unchangedFiles: number
    rustFilesChanged: number
    netBytesDelta: number
  }
  deltas: DiffDeltaView[]
}

// ───────────────────────────── audit ─────────────────────────────

export interface AuditLogEntryView {
  seq: number
  ts: string
  actor: string
  role: string
  action: string
  tenantId: string | null
  target: string | null
  outcome: 'success' | 'failure' | 'denied'
  details: Record<string, unknown>
  prevHash: string
  hash: string
}

export interface AuditLogPage {
  entries: AuditLogEntryView[]
  total: number
  nextBefore: number | null
}

export interface AuditVerificationView {
  valid: boolean
  checkedEntries: number
  firstInvalidSeq: number | null
  reason: string | null
  headHash: string
  /** Sequence number recorded by the MAC-protected head checkpoint; null when none exists yet. */
  checkpointSeq: number | null
  /** What verification can and cannot detect (e.g. removal of the newest entries). */
  limitation: string
  verifiedAt: string
}
