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

/**
 * Version of the HTTP contract in this file. The bridge reports it in /api/health and /api/system,
 * and the console compares it with its own copy: in development Vite hot-reloads the UI while the
 * bridge keeps running older code, and the console then shows a "restart the bridge" banner instead
 * of failing on fields the old bridge does not send.
 *
 * Bump it whenever a response shape changes incompatibly (a field is removed, renamed, or changes
 * type, or a new field is required by the UI). Version 1 is the contract before this constant
 * existed; such bridges do not report a version at all.
 * - 2: HostInfo.freeMemoryBytes replaced by availableMemoryBytes and memorySource; HostInfo adds
 *   osName, nativeArch, archEmulated, runtimePath and runtimePathNote; ToolAvailability adds the
 *   search source, resolved target, binary header, usage and shadowed matches; SystemStatus adds
 *   apiContractVersion, toolSearch and core.binary; HealthResponse adds apiContractVersion.
 * - 3: ExecutableSource adds 'configured' and 'environment'; ToolAvailability adds selection,
 *   configuredPath, configuredPathProblem, pathConfigurable and pathHint; PUT and DELETE
 *   /api/system/tools/:name set and clear a console-configured tool path (SetToolPathRequest,
 *   SetToolPathResponse).
 * - 4: PluginsView adds directory, directorySource, directoryExists, diagnostics, hasErrors and
 *   hint (pluginDir stays as a deprecated alias of directory). Without SENTRA_PLUGIN_DIR the bridge
 *   now uses the core's platform default plugin directory, so configured can be true while
 *   SENTRA_PLUGIN_DIR is unset.
 * - 5: CodeQL results. FindingSource adds 'codeql'; FindingView adds origin and codeql;
 *   OverviewView.openFindings.bySource adds codeql; ScanRunSummary adds codeqlAnalysis;
 *   codeql is no longer a console-configurable tool (it is executed when CodeQL host analysis is
 *   enabled; SENTRA_CODEQL_BIN pins it) and its row uses selection 'environment' for that
 *   variable; GET/PUT /api/settings/codeql, POST /api/tenants/:id/codeql/import and
 *   POST /api/tenants/:id/codeql/github-sync are new; CodeqlAnalysisView.outcome and
 *   OverviewView.openFindings.codeqlByOrigin report a failed analysis and the per-origin counts.
 */
export const API_CONTRACT_VERSION = 5

export interface HealthResponse {
  status: 'ok'
  coreAvailable: boolean
  /** API_CONTRACT_VERSION of the running bridge; absent on bridges older than version 2. */
  apiContractVersion: number
}

/** CPU architecture names (Node/Bun `os.arch()` vocabulary). */
export type CpuArch = 'x64' | 'arm64' | 'ia32' | 'arm' | 'riscv64' | 'ppc64' | 's390x' | 'loong64' | 'unknown'

export interface HostInfo {
  hostname: string
  platform: string
  /** Kernel release from os.release(): the Darwin version on macOS, "10.0.<build>" on Windows. */
  release: string
  /** Friendly OS name: Windows product name, macOS product name and version, Linux PRETTY_NAME. */
  osName: string | null
  /** Architecture of the bridge process (os.arch()); differs from nativeArch under emulation. */
  arch: string
  /** Native hardware architecture of the host OS; null when it could not be determined. */
  nativeArch: CpuArch | null
  /** True when the process architecture differs from nativeArch and runs under emulation. */
  archEmulated: boolean | null
  cpuModel: string | null
  cpuCount: number
  /** Null on Windows, which has no load average. */
  loadAverage: number[] | null
  totalMemoryBytes: number
  /** Memory available to new work without swapping (not just free pages); see memorySource. */
  availableMemoryBytes: number
  /** os: os.freemem() (Windows: available physical memory); proc_meminfo: MemAvailable; vm_stat: macOS page statistics. */
  memorySource: 'os' | 'proc_meminfo' | 'vm_stat'
  uptimeSeconds: number
  processRssBytes: number
  bunVersion: string
  /**
   * Bun executable running the bridge: the located install that is the same file as the running
   * executable (so the temporary bun-node shim of `bun run` is resolved away), else process.execPath.
   */
  runtimePath: string
  /** Set when runtimePath could not be tied to an install (an unmatched bun-node shim); explains why. */
  runtimePathNote: string | null
  cliQueued: number
  sampledAt: string
}

/**
 * Where a reported executable came from: a directory of the bridge's automatic search order
 * (process_path, persisted_system_path, persisted_user_path, well_known), a path an admin set in
 * the console (configured; reporting only, never run), or a path the host operator pinned with an
 * environment variable (environment; SENTRA_GH_BIN for gh, SENTRA_CODEQL_BIN for codeql).
 */
export type ExecutableSource =
  | 'process_path'
  | 'persisted_system_path'
  | 'persisted_user_path'
  | 'well_known'
  | 'configured'
  | 'environment'
export type BinaryFormat = 'pe' | 'elf' | 'macho' | 'macho_universal' | 'script' | 'unknown'
export type BinaryCompatibility = 'native' | 'emulated' | 'compatible_32bit' | 'incompatible' | 'script' | 'unknown'

/** Executable header facts read from the file (the file is never executed). */
export interface BinaryInfo {
  format: BinaryFormat
  /** Architectures in the file (several for a macOS universal binary); empty for scripts/unknown. */
  architectures: CpuArch[]
  compatibility: BinaryCompatibility
  /** e.g. "x64 binary runs under Windows on Arm emulation", "#!/usr/bin/env python3", "App Execution Alias (not readable)". */
  note: string | null
}

/** executed: the bridge runs it; runtime: it runs the bridge; presence_only: only its presence is reported; not_used: not used by the bridge. */
export type ToolUsage = 'executed' | 'runtime' | 'presence_only' | 'not_used'

/**
 * How a tool row's path was chosen: automatic detection, a path an admin set in the console, or
 * an environment variable set by the host operator (SENTRA_GH_BIN for gh, SENTRA_CODEQL_BIN for
 * codeql).
 */
export type ToolPathSelection = 'automatic' | 'configured' | 'environment'

export interface ToolAvailability {
  name: string
  available: boolean
  /** Absolute path of the first match in search order (symlinks NOT resolved here; see resolvedPath). */
  path: string | null
  /**
   * The file `path` leads to, when different from path: the target after resolving symlinks, or the
   * executable named by a Scoop shim's `.shim` file (see resolvedVia). Null when no component of
   * path is a link, even if its canonical form differs (a Windows 8.3 short name, a subst or mapped
   * drive, letter case).
   */
  resolvedPath: string | null
  /** How resolvedPath was obtained: a symlink or junction, or a Scoop shim; null when resolvedPath is null. */
  resolvedVia: 'link' | 'scoop_shim' | null
  source: ExecutableSource | null
  /** True when the match is visible on the bridge process's own PATH (what its subprocesses inherit). */
  onProcessPath: boolean
  binary: BinaryInfo | null
  usage: ToolUsage
  usageNote: string
  /**
   * Further matches later in the search order (max 4), absolute paths; the same file reached through
   * another directory (merged /usr, symlinked bin directories) is not repeated. For bun: the other
   * installs, i.e. matches that are not the running executable. For a configured or environment
   * row: copies found by the automatic search that are not the selected file.
   */
  shadowed: string[]
  /** How `path` was chosen (see ToolPathSelection). A broken configured path falls back to 'automatic'. */
  selection: ToolPathSelection
  /** Path an admin set in the console for this tool (a file or the folder holding it); null when none is set. */
  configuredPath: string | null
  /**
   * Why the configured path (or SENTRA_GH_BIN for gh) cannot be used right now, e.g. the file was
   * removed. The row then reports what automatic detection finds (for SENTRA_GH_BIN: nothing).
   */
  configuredPathProblem: string | null
  /**
   * True when an admin may set this tool's path in the console (PUT /api/system/tools/:name).
   * False for tools the bridge runs (gh, codeql) or that run the bridge (bun): a path entered in
   * the web console never becomes a program the bridge runs.
   */
  pathConfigurable: boolean
  /**
   * For a tool whose path cannot be set in the console: how it can be set instead (and, for codeql,
   * that a path stored in the console by an older bridge is ignored); null otherwise.
   */
  pathHint: string | null
}

/** Body of PUT /api/system/tools/:name (permission settings:write). */
export interface SetToolPathRequest {
  /**
   * Absolute path to the executable or to the folder that contains it. The bridge never runs it;
   * it only checks that it exists and can run on the bridge host.
   */
  path: string
}

/** Response of PUT and DELETE /api/system/tools/:name. */
export interface SetToolPathResponse {
  /** The tool's row after the change, as GET /api/system reports it. */
  tool: ToolAvailability
  /** Non-blocking remark about an accepted path (e.g. the file name does not look like the tool); null otherwise. */
  warning: string | null
}

/** The executable search snapshot behind SystemStatus.tools. */
export interface ToolSearchStatus {
  /**
   * True when the persisted (registry / /etc) PATH was read for this snapshot, also when only part
   * of it was (persistedPathError then names the sources that failed).
   */
  persistedPathRead: boolean
  persistedPathError: string | null
  /**
   * Distinct absolute directories in the search order. Removed: empty, relative and duplicate
   * entries, Bun shim directories, and on Windows UNC (\\server\share) and device (\\?\, \\.\)
   * paths, which are never touched because listing them would authenticate to a remote host. This
   * covers standard install locations under such a path (an APPDATA redirected to a share) too.
   */
  searchedDirectories: number
  /** PATH entries skipped because they are UNC or device paths (Windows only; 0 elsewhere). */
  skippedNetworkEntries: number
  refreshedAt: string
}

export interface SystemStatus {
  /** API_CONTRACT_VERSION of the running bridge; absent on bridges older than version 2. */
  apiContractVersion: number
  mode: 'production' | 'development'
  core: {
    binaryPath: string
    present: boolean
    version: string | null
    error: string | null
    /** Header of the sentra binary; null when it is missing. */
    binary: BinaryInfo | null
  }
  dataDir: string
  host: HostInfo
  tools: ToolAvailability[]
  toolSearch: ToolSearchStatus
  integrations: {
    githubCredentialSource: GitHubCredentialSource | null
    osvEnabled: boolean
    aiDefaultProvider: ProviderId | null
    aiReadyProviders: ProviderId[]
    githubWebhookSecretConfigured: boolean
    gitlabWebhookTokenConfigured: boolean
  }
  auth: {
    /** Grants from SENTRA_WEB_TOKENS only; the generated local admin token is reported by generatedLocalToken. */
    configuredGrants: number
    generatedLocalToken: boolean
    bindHost: string
    loopbackOnly: boolean
  }
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
  /** Suggested commands printed by the language probe; the probe itself never runs CodeQL. */
  suggestedCreateCommand: string | null
  suggestedAnalyzeCommand: string | null
  codeqlInstalled: boolean
}

// ───────────────────────────── CodeQL ─────────────────────────────

/**
 * How a CodeQL finding reached the bridge: host_analysis (Sentra ran `sentra codeql analyze` on the
 * bridge host, build mode none), sarif_import (a CodeQL SARIF file produced elsewhere and uploaded
 * by an operator) or github_code_scanning (open alerts of tool CodeQL read from the GitHub code
 * scanning API for the tenant's repository). Each origin is reconciled on its own.
 */
export type FindingOrigin = 'host_analysis' | 'sarif_import' | 'github_code_scanning'
export const FINDING_ORIGINS: readonly FindingOrigin[] = ['host_analysis', 'sarif_import', 'github_code_scanning']

export type CodeqlSuite = 'code-scanning' | 'security-extended'

/** Why CodeQL host analysis did not run in a scan (or would not run now). */
export type CodeqlSkipReason =
  | 'disabled'
  | 'terms_not_accepted'
  | 'launcher_unavailable'
  | 'core_unavailable'
  | 'analysis_busy'
  | 'packs_missing'
  | 'languages_need_build'
  | 'no_languages'

/** Per-language outcome reported by `sentra codeql analyze` / `sentra codeql import`. */
export interface CodeqlLanguageResultView {
  language: string
  status: 'analyzed' | 'skipped' | 'failed'
  reason: string | null
  results: number
  durationMs: number | null
}

/** Outcome of the CodeQL stage of a scan (ScanRunSummary.codeqlAnalysis). */
/** What a scan's CodeQL host analysis did: analyzed at least one language, did not analyze any (skipReason says why), or failed. */
export type CodeqlAnalysisOutcome = 'analyzed' | 'skipped' | 'failed'

export interface CodeqlAnalysisView {
  /**
   * Absent in runs stored before this field existed; derive it from attempted, skipReason and the
   * scan's stageErrors (see codeqlOutcome in the console).
   */
  outcome?: CodeqlAnalysisOutcome
  /** True when `sentra codeql analyze` was started for this run (also when it then failed). */
  attempted: boolean
  /** Set when host analysis did not run (or reported no analyzed language); null when it analyzed at least one language. */
  skipReason: CodeqlSkipReason | null
  /** Why, in words, including what to change. */
  message: string
  codeqlVersion: string | null
  suite: CodeqlSuite | null
  packDownloadAllowed: boolean
  languages: CodeqlLanguageResultView[]
  resultsTotal: number
  /** Results dropped because their path was absolute or left the workspace. */
  resultsOutsideWorkspace: number
  /** True when --max-results cut the result list; open host-analysis findings are then not resolved. */
  truncated: boolean
  warnings: string[]
  durationMs: number | null
}

/** Stored per CodeQL finding (FindingView.codeql). */
export interface CodeqlFindingDetails {
  origin: FindingOrigin
  language: string | null
  /** CVSS-like `security-severity` from the query metadata (0.0-10.0); null when absent. */
  securitySeverity: number | null
  /** `problem.severity` of the query (error, warning, recommendation, note). */
  problemSeverity: string | null
  precision: string | null
  cwes: string[]
  tags: string[]
  helpUri: string | null
  startLine: number | null
  endLine: number | null
  startColumn: number | null
  endColumn: number | null
  /** Tool that produced the result (name and version as reported). */
  toolName: string | null
  toolVersion: string | null
  /** GitHub code scanning only: owner/repo, alert number and web URL of the alert. */
  repository: string | null
  alertNumber: number | null
  alertUrl: string | null
  /** How the stored identity was derived. */
  fingerprintSource: 'sarif_partial_fingerprint' | 'cli_digest' | 'github_alert_number'
}

/** Bridge setting `codeql_analysis`: CodeQL host analysis, off by default. */
export interface CodeqlSettings {
  enabled: boolean
  termsAcceptedBy: string | null
  termsAcceptedAt: string | null
  allowPackDownload: boolean
  suite: CodeqlSuite
  timeoutMinutes: number
  threads: number
  ramMb: number | null
}

export interface CodeqlLauncherView {
  available: boolean
  /** The file `sentra codeql analyze --codeql` would receive; null when none qualifies. */
  path: string | null
  /** environment: SENTRA_CODEQL_BIN; otherwise the search source of the automatic choice. */
  source: 'environment' | 'process_path' | 'persisted_system_path' | 'persisted_user_path' | null
  /** Why no launcher qualifies, or why the pinned one cannot be used. */
  problem: string | null
  /** LICENSE.md next to the launcher (the CodeQL terms shipped with the distribution), when it exists. */
  licenseFile: string | null
}

/** GET/PUT /api/settings/codeql. */
export interface CodeqlSettingsView {
  settings: CodeqlSettings
  updatedAt: string | null
  updatedBy: string | null
  bounds: {
    timeoutMinutes: { min: number; max: number }
    threads: { min: number; max: number }
    ramMb: { min: number; max: number }
  }
  launcher: CodeqlLauncherView
  /** Explicit pack cache passed as --pack-cache (inside the bridge data directory). */
  packCache: string
  /** Null when a scan's CodeQL stage would start host analysis now; otherwise why not. */
  skipReason: CodeqlSkipReason | null
  skipMessage: string | null
  /** The analysis running on this bridge (at most one at a time), if any. */
  running: { tenantId: string; startedAt: string } | null
  terms: { summary: string[]; location: string; referenceUrl: string }
  isolationNote: string
}

export interface UpdateCodeqlSettingsRequest {
  enabled?: boolean
  /** Required (true) in the same request that sets enabled: true. */
  acceptTerms?: boolean
  allowPackDownload?: boolean
  suite?: CodeqlSuite
  timeoutMinutes?: number
  threads?: number
  ramMb?: number | null
}

/** Response of POST /api/tenants/:id/codeql/import and /codeql/github-sync. */
export interface CodeqlIngestView {
  origin: Exclude<FindingOrigin, 'host_analysis'>
  tenantId: string
  receivedAt: string
  /** sarif_import: the SARIF tool; github_code_scanning: the repository read. */
  sourceTool: { name: string; version: string | null } | null
  repository: string | null
  resultsTotal: number
  resultsOutsideWorkspace: number
  truncated: boolean
  languages: CodeqlLanguageResultView[]
  warnings: string[]
  findings: { created: number; reopened: number; stillOpen: number; resolved: number }
  /** What was reconciled and what was not resolved, in words. */
  note: string
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
  /** CodeQL host analysis outcome of the codeql stage; null when the stage did not run (absent on runs stored before contract 5). */
  codeqlAnalysis: CodeqlAnalysisView | null
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

export type FindingSource = 'sast' | 'dependency' | 'codeql'
export const FINDING_SOURCES: readonly FindingSource[] = ['sast', 'dependency', 'codeql']
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
  /** CodeQL findings only: how the result reached the bridge; null for SAST and dependency findings. */
  origin: FindingOrigin | null
  /** CodeQL findings only. */
  codeql: CodeqlFindingDetails | null
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
     * Open CodeQL findings per origin; they add up to bySource.codeql. Every origin is stored and
     * counted on its own, so one CodeQL result reported by host analysis, a SARIF import and
     * GitHub code scanning counts once per origin.
     */
    codeqlByOrigin: Record<FindingOrigin, number>
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

/**
 * Where the plugin directory in use comes from: SENTRA_PLUGIN_DIR in the bridge environment, the
 * core's platform default (used only while SENTRA_PLUGIN_DIR is unset), or none.
 */
export type PluginDirectorySource = 'environment' | 'platform_default' | 'none'

export type PluginDiagnosticSeverity = 'error' | 'warning' | 'info'

/**
 * One discovery diagnostic. Diagnostics from `sentra plugin list` are passed through unchanged
 * (the core reports 'error' for a skipped entry and 'warning' for a loaded entry with a problem);
 * the bridge adds its own about the directory itself (codes starting with plugin_dir_) and about
 * listing entries it ignored (plugin_entry_ignored).
 */
export interface PluginDiagnosticView {
  severity: PluginDiagnosticSeverity
  /** Stable machine-readable code, for example manifest_invalid_json or duplicate_plugin_id. */
  code: string
  message: string
  /** Directory or manifest the diagnostic is about, as reported; null when it names none. */
  path: string | null
}

export interface PluginsView {
  /** Plugin directory in use; null when there is none (directorySource 'none'). */
  directory: string | null
  directorySource: PluginDirectorySource
  /** Whether the directory exists, checked on every listing (the bridge never creates it). */
  directoryExists: boolean
  /** @deprecated Same value as `directory`; kept for API clients written against contract 3. */
  pluginDir: string | null
  /** True when a plugin directory is in use (directory is not null), even if it does not exist yet. */
  configured: boolean
  plugins: PluginView[]
  diagnostics: PluginDiagnosticView[]
  /** True when an entry was skipped (core has_errors) or a diagnostic has severity 'error'. */
  hasErrors: boolean
  /** What the host operator can do next; null when nothing is needed. */
  hint: string | null
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
