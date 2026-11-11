import type {
  AiSettingsView,
  CodeqlIngestView,
  CodeqlSettingsView,
  FindingOrigin,
  UpdateCodeqlSettingsRequest,
  AuditLogPage,
  AuditVerificationView,
  ConsoleCommand,
  ConsoleRunView,
  CoreAuditView,
  CoverageUnitView,
  CoverageValidationView,
  CreatePullRequestRequest,
  CreatePullRequestResponse,
  CreateTenantRequest,
  DependencyInventoryView,
  DiffRequest,
  DiffView,
  FileContentView,
  FindingSource,
  FindingState,
  FindingView,
  GeneratePatchRequest,
  GitHubCredentialView,
  GitHubStatusView,
  HealthResponse,
  HostInfo,
  IntelStatusView,
  ListModelsResponse,
  ModelReconReportView,
  ModelReconRequest,
  OsvQueryRequest,
  OsvQueryResponse,
  OverviewView,
  PatchBundleView,
  PluginProbeView,
  PluginRunRequest,
  PluginRunView,
  PluginsView,
  PrCommentResponse,
  PrScanResultView,
  PrStatusRequest,
  PrStatusResponse,
  PromptRequest,
  PromptView,
  ProviderId,
  PullRequestListView,
  PullRequestWorkflowsView,
  ResearchSessionsView,
  ScanKind,
  ScanRunView,
  ScanStreamEvent,
  SessionInfo,
  SetToolPathRequest,
  SetToolPathResponse,
  Severity,
  SkillDetailView,
  SkillSummaryView,
  SnippetScanRequest,
  SnippetScanView,
  SystemStatus,
  TenantView,
  TopologyReportView,
  TrendPoint,
  TriageRequest,
  UpdateProviderRequest,
  UpdateTenantRequest,
  UpsertCoverageUnitRequest,
  WebhookConfigView,
  WebhookDeliveryView,
} from '@/types/api'

/**
 * Typed client for the Sentra bridge. Every function maps 1:1 to a server route; there are
 * no fallbacks, defaults or fabricated values here — failures surface as ApiError.
 */

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly details: unknown

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
  }
}

/** Fired on window when the server answers 401 so the shell can show the sign-in screen. */
export const UNAUTHENTICATED_EVENT = 'sentra:unauthenticated'

const CSRF_HEADERS = { 'X-Sentra-Client': 'console' }

interface RequestOptions {
  signal?: AbortSignal
  /** Do not broadcast 401 (used by the session probe and login itself). */
  quiet401?: boolean
}

async function parseError(res: Response): Promise<ApiError> {
  let code = `http_${res.status}`
  let message = `Request failed with HTTP ${res.status}`
  let details: unknown
  try {
    const body = (await res.json()) as { error?: { code?: string; message?: string; details?: unknown } }
    if (body?.error?.code) code = body.error.code
    if (body?.error?.message) message = body.error.message
    details = body?.error?.details
  } catch {
    // non-JSON error body
  }
  return new ApiError(res.status, code, message, details)
}

async function request<T>(method: string, path: string, body?: unknown, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (method !== 'GET' && method !== 'HEAD') Object.assign(headers, CSRF_HEADERS)
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  let res: Response
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: 'same-origin',
      signal: options.signal,
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new ApiError(0, 'network_error', 'The Sentra bridge is unreachable. Is `bun run server.ts` running?')
  }
  if (!res.ok) {
    const error = await parseError(res)
    if (res.status === 401 && !options.quiet401) window.dispatchEvent(new CustomEvent(UNAUTHENTICATED_EVENT))
    throw error
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

/**
 * POSTs a JSON document that is already text (a SARIF file read in the browser), without parsing
 * and re-serialising it.
 */
async function postJsonText<T>(path: string, text: string): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', ...CSRF_HEADERS },
      body: text,
      credentials: 'same-origin',
    })
  } catch {
    throw new ApiError(0, 'network_error', 'The Sentra bridge is unreachable.')
  }
  if (!res.ok) {
    const error = await parseError(res)
    if (res.status === 401) window.dispatchEvent(new CustomEvent(UNAUTHENTICATED_EVENT))
    throw error
  }
  return (await res.json()) as T
}

const get = <T>(path: string, options?: RequestOptions) => request<T>('GET', path, undefined, options)
const post = <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>('POST', path, body ?? {}, options)
const put = <T>(path: string, body: unknown, options?: RequestOptions) => request<T>('PUT', path, body, options)
const del = <T>(path: string, options?: RequestOptions) => request<T>('DELETE', path, undefined, options)

const t = (tenantId: string) => `/api/tenants/${encodeURIComponent(tenantId)}`

function query(params: Record<string, string | number | null | undefined>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== null && value !== undefined && value !== '') search.set(key, String(value))
  }
  const text = search.toString()
  return text ? `?${text}` : ''
}

/**
 * Starts a scan and streams its progress. Resolves with the final run (or rejects with the
 * server's error). Aborting the signal stops the stream and the server kills the core process.
 */
async function streamScan(
  tenantId: string,
  kind: ScanKind,
  onEvent: (event: ScanStreamEvent) => void,
  signal?: AbortSignal,
): Promise<ScanRunView> {
  let res: Response
  try {
    res = await fetch(`${t(tenantId)}/scans`, {
      method: 'POST',
      headers: { Accept: 'text/event-stream', 'Content-Type': 'application/json', ...CSRF_HEADERS },
      body: JSON.stringify({ kind }),
      credentials: 'same-origin',
      signal,
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new ApiError(0, 'network_error', 'The Sentra bridge is unreachable.')
  }
  if (!res.ok || !res.body) {
    const error = await parseError(res)
    if (res.status === 401) window.dispatchEvent(new CustomEvent(UNAUTHENTICATED_EVENT))
    throw error
  }
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let finalRun: ScanRunView | null = null
  let streamError: ApiError | null = null
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const frames = buffer.split('\n\n')
    buffer = frames.pop() ?? ''
    for (const frame of frames) {
      const dataLines = frame
        .split('\n')
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).trimStart())
      if (dataLines.length === 0) continue
      let event: ScanStreamEvent
      try {
        event = JSON.parse(dataLines.join('\n')) as ScanStreamEvent
      } catch {
        continue
      }
      onEvent(event)
      if (event.type === 'complete') finalRun = event.run
      if (event.type === 'error') {
        // Older bridges sent no status; treat that as an unexpected server error.
        streamError = new ApiError(typeof event.status === 'number' ? event.status : 500, event.code, event.message)
      }
    }
  }
  if (finalRun) return finalRun
  throw streamError ?? new ApiError(500, 'stream_incomplete', 'The scan stream ended without a result')
}

export const api = {
  health: () => get<HealthResponse>('/api/health', { quiet401: true }),

  auth: {
    login: (token: string) => post<SessionInfo>('/api/auth/login', { token }, { quiet401: true }),
    logout: () => post<{ ok: true }>('/api/auth/logout'),
    session: (signal?: AbortSignal) => get<SessionInfo>('/api/auth/session', { quiet401: true, signal }),
  },

  system: {
    status: (signal?: AbortSignal) => get<SystemStatus>('/api/system', { signal }),
    host: (signal?: AbortSignal) => get<HostInfo>('/api/system/host', { signal }),
    /**
     * Sets the path the bridge reports for a tool (an absolute path to the executable or to the
     * directory that contains it). The bridge validates it and never runs the file; gh and bun are
     * not settable here.
     */
    setToolPath: (tool: string, path: string) =>
      put<SetToolPathResponse>(`/api/system/tools/${encodeURIComponent(tool)}`, { path } satisfies SetToolPathRequest),
    /** Removes the path set in the console; the tool is located automatically again. */
    clearToolPath: (tool: string) => del<SetToolPathResponse>(`/api/system/tools/${encodeURIComponent(tool)}`),
  },

  tenants: {
    list: (signal?: AbortSignal) => get<{ tenants: TenantView[] }>('/api/tenants', { signal }),
    get: (tenantId: string, refresh = false) => get<TenantView>(`${t(tenantId)}${refresh ? '?refresh=1' : ''}`),
    create: (body: CreateTenantRequest) => post<TenantView>('/api/tenants', body),
    update: (tenantId: string, body: UpdateTenantRequest) => put<TenantView>(t(tenantId), body),
    remove: (tenantId: string) => del<{ ok: true; coreStoreRetained: string }>(t(tenantId)),
    overview: (tenantId: string, signal?: AbortSignal) => get<OverviewView>(`${t(tenantId)}/overview`, { signal }),
    trends: (tenantId: string, days: number, signal?: AbortSignal) =>
      get<{ points: TrendPoint[] }>(`${t(tenantId)}/trends${query({ days })}`, { signal }),
    core: (tenantId: string, limit = 200, signal?: AbortSignal) => get<CoreAuditView>(`${t(tenantId)}/core${query({ limit })}`, { signal }),
    researchSessions: (tenantId: string, signal?: AbortSignal) =>
      get<ResearchSessionsView>(`${t(tenantId)}/research/sessions`, { signal }),
  },

  scans: {
    list: (tenantId: string, limit = 50, signal?: AbortSignal) =>
      get<{ runs: ScanRunView[] }>(`${t(tenantId)}/scans${query({ limit })}`, { signal }),
    get: (tenantId: string, runId: string) => get<ScanRunView>(`${t(tenantId)}/scans/${encodeURIComponent(runId)}`),
    /** Runs to completion without streaming. */
    start: (tenantId: string, kind: ScanKind) => post<ScanRunView>(`${t(tenantId)}/scans`, { kind }),
    stream: streamScan,
  },

  findings: {
    list: (
      tenantId: string,
      filter: { state?: FindingState | 'all'; source?: FindingSource; origin?: FindingOrigin; severity?: Severity } = {},
      signal?: AbortSignal,
    ) => get<{ findings: FindingView[] }>(`${t(tenantId)}/findings${query(filter)}`, { signal }),
    get: (tenantId: string, findingId: string, signal?: AbortSignal) =>
      get<FindingView>(`${t(tenantId)}/findings/${encodeURIComponent(findingId)}`, { signal }),
    triage: (tenantId: string, findingId: string, body: TriageRequest) =>
      post<FindingView>(`${t(tenantId)}/findings/${encodeURIComponent(findingId)}/triage`, body),
    file: (tenantId: string, path: string, signal?: AbortSignal) =>
      get<FileContentView>(`${t(tenantId)}/files${query({ path })}`, { signal }),
    /** SARIF 2.1.0 document generated from the tenant's open findings. */
    sarif: (tenantId: string) => get<Record<string, unknown>>(`${t(tenantId)}/export/sarif`),
  },

  dependencies: (tenantId: string, signal?: AbortSignal) => get<DependencyInventoryView>(`${t(tenantId)}/dependencies`, { signal }),

  codeql: {
    settings: (signal?: AbortSignal) => get<CodeqlSettingsView>('/api/settings/codeql', { signal }),
    /** Enabling requires acceptTerms: true in the same request. */
    updateSettings: (body: UpdateCodeqlSettingsRequest) => put<CodeqlSettingsView>('/api/settings/codeql', body),
    /** Uploads a CodeQL SARIF document (the file's text, at most 64 MiB). */
    importSarif: (tenantId: string, sarifText: string) => postJsonText<CodeqlIngestView>(`${t(tenantId)}/codeql/import`, sarifText),
    /** Reads open GitHub code scanning alerts of tool CodeQL for the workspace's repository (read-only on GitHub). */
    githubSync: (tenantId: string) => post<CodeqlIngestView>(`${t(tenantId)}/codeql/github-sync`),
  },

  intel: {
    status: (signal?: AbortSignal) => get<IntelStatusView>('/api/intel/status', { signal }),
    setOsvEnabled: (osvEnabled: boolean) => put<IntelStatusView>('/api/settings/intel', { osvEnabled }),
    query: (body: OsvQueryRequest) => post<OsvQueryResponse>('/api/intel/osv/query', body),
  },

  snippet: {
    scan: (body: SnippetScanRequest) => post<SnippetScanView>('/api/scan/snippet', body),
  },

  console: {
    run: (tenantId: string, command: ConsoleCommand) => post<ConsoleRunView>(`${t(tenantId)}/console`, { command }),
  },

  diff: (tenantId: string, body: DiffRequest) => post<DiffView>(`${t(tenantId)}/diff`, body),

  patches: {
    generate: (tenantId: string, findingId: string, body: GeneratePatchRequest = {}) =>
      post<PatchBundleView>(`${t(tenantId)}/findings/${encodeURIComponent(findingId)}/patches`, body),
    list: (tenantId: string, signal?: AbortSignal) => get<{ patches: PatchBundleView[] }>(`${t(tenantId)}/patches`, { signal }),
    apply: (tenantId: string, bundleId: string) => post<PatchBundleView>(`${t(tenantId)}/patches/${encodeURIComponent(bundleId)}/apply`),
    rollback: (tenantId: string, bundleId: string) =>
      post<PatchBundleView>(`${t(tenantId)}/patches/${encodeURIComponent(bundleId)}/rollback`),
    pullRequest: (tenantId: string, bundleId: string, body: CreatePullRequestRequest = {}) =>
      post<CreatePullRequestResponse>(`${t(tenantId)}/patches/${encodeURIComponent(bundleId)}/pull-request`, body),
  },

  ai: {
    settings: (signal?: AbortSignal) => get<AiSettingsView>('/api/settings/ai', { signal }),
    updateProvider: (provider: ProviderId, body: UpdateProviderRequest) =>
      put<AiSettingsView>(`/api/settings/ai/providers/${provider}`, body),
    setDefault: (provider: ProviderId | null) => put<AiSettingsView>('/api/settings/ai/default', { provider }),
    listModels: (provider: ProviderId) => post<ListModelsResponse>(`/api/settings/ai/providers/${provider}/models`),
  },

  skills: {
    list: (signal?: AbortSignal) => get<{ skills: SkillSummaryView[] }>('/api/skills', { signal }),
    get: (skillId: string, signal?: AbortSignal) => get<SkillDetailView>(`/api/skills/${encodeURIComponent(skillId)}`, { signal }),
  },

  prompts: {
    generate: (tenantId: string, body: PromptRequest) => post<PromptView>(`${t(tenantId)}/prompts`, body),
  },

  github: {
    status: (tenantId: string, signal?: AbortSignal) => get<GitHubStatusView>(`${t(tenantId)}/github`, { signal }),
    setRepository: (tenantId: string, repository: string | null) =>
      put<GitHubStatusView>(`${t(tenantId)}/github/repository`, { repository }),
    setToken: (token: string) => put<GitHubCredentialView>('/api/settings/github/token', { token }),
    clearToken: () => del<GitHubCredentialView>('/api/settings/github/token'),
    /** `refresh` bypasses the bridge's 30-second pull-request cache. */
    pulls: (tenantId: string, signal?: AbortSignal, refresh = false) =>
      get<PullRequestListView>(`${t(tenantId)}/github/pulls${refresh ? '?refresh=1' : ''}`, { signal }),
    workflows: (tenantId: string, prNumber: number, signal?: AbortSignal) =>
      get<PullRequestWorkflowsView>(`${t(tenantId)}/github/pulls/${prNumber}/workflows`, { signal }),
    latestScan: (tenantId: string, prNumber: number, signal?: AbortSignal) =>
      get<{ scan: PrScanResultView | null }>(`${t(tenantId)}/github/pulls/${prNumber}/scan`, { signal }),
    scan: (tenantId: string, prNumber: number) => post<PrScanResultView>(`${t(tenantId)}/github/pulls/${prNumber}/scan`),
    comment: (tenantId: string, prNumber: number, body: string) =>
      post<PrCommentResponse>(`${t(tenantId)}/github/pulls/${prNumber}/comment`, { body }),
    commitStatus: (tenantId: string, prNumber: number, body: PrStatusRequest) =>
      post<PrStatusResponse>(`${t(tenantId)}/github/pulls/${prNumber}/status`, body),
  },

  webhooks: {
    deliveries: (limit = 100, signal?: AbortSignal) =>
      get<{ deliveries: WebhookDeliveryView[] }>(`/api/webhooks/deliveries${query({ limit })}`, { signal }),
    config: (signal?: AbortSignal) => get<WebhookConfigView>('/api/webhooks/config', { signal }),
  },

  research: {
    coverage: (tenantId: string, signal?: AbortSignal) => get<{ units: CoverageUnitView[] }>(`${t(tenantId)}/coverage`, { signal }),
    upsertUnit: (tenantId: string, coverageId: string, body: UpsertCoverageUnitRequest) =>
      put<CoverageUnitView>(`${t(tenantId)}/coverage/${encodeURIComponent(coverageId)}`, body),
    deleteUnit: (tenantId: string, coverageId: string) => del<{ ok: true }>(`${t(tenantId)}/coverage/${encodeURIComponent(coverageId)}`),
    validate: (tenantId: string) => post<CoverageValidationView>(`${t(tenantId)}/coverage/validate`),
    topology: (tenantId: string, signal?: AbortSignal) =>
      get<{ report: TopologyReportView | null }>(`${t(tenantId)}/recon/topology`, { signal }),
    runTopology: (tenantId: string) => post<TopologyReportView>(`${t(tenantId)}/recon/topology`),
    modelReports: (tenantId: string, signal?: AbortSignal) =>
      get<{ reports: ModelReconReportView[] }>(`${t(tenantId)}/recon/model`, { signal }),
    runModelRecon: (tenantId: string, body: ModelReconRequest) => post<ModelReconReportView>(`${t(tenantId)}/recon/model`, body),
  },

  plugins: {
    /** `refresh` lists again instead of reusing a listing the bridge completed in the last 15 seconds. */
    list: (signal?: AbortSignal, options: { refresh?: boolean } = {}) =>
      get<PluginsView>(`/api/plugins${query({ refresh: options.refresh ? 1 : null })}`, { signal }),
    probe: (pluginId: string, tenantId: string) => post<PluginProbeView>(`/api/plugins/${encodeURIComponent(pluginId)}/probe`, { tenantId }),
    run: (pluginId: string, body: PluginRunRequest) => post<PluginRunView>(`/api/plugins/${encodeURIComponent(pluginId)}/run`, body),
  },

  audit: {
    log: (params: { tenant?: string | null; limit?: number; before?: number | null } = {}, signal?: AbortSignal) =>
      get<AuditLogPage>(`/api/audit-log${query({ tenant: params.tenant, limit: params.limit, before: params.before })}`, { signal }),
    verify: () => post<AuditVerificationView>('/api/audit-log/verify'),
  },
}

/** Human-readable message for any thrown value. */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message
  if (error instanceof Error) return error.message
  return String(error)
}
