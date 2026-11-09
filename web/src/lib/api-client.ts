import type { FindingView, Severity, Reachability, FindingStatus } from '@/types/sentra'

export interface RealScanMatch {
  category: string
  cwe: string
  file_path: string
  line_number: number
  rationale: string
  rule_id: string
  rule_name: string
  severity: string
  snippet: string
}

export interface RealScanResponse {
  schema_version: number
  command: string
  files_scanned: number
  signals_found: number
  matches: RealScanMatch[]
  untrusted_execution: boolean
}

export interface RealAuditResponse {
  schema_version: number
  command: string
  session_id: string
  task_id: string
  packages_audited: number
  vulnerable_packages: number
  is_stale: boolean
  findings: any[]
}

export interface RealCodeQlResponse {
  schema_version: number
  command: string
  mode: string
  workspace: string
  primary_language: string
  detected_languages: { language: string; files_count: number }[]
  database_create_command: string
  database_analyze_command: string
}

export interface RealDiffResponse {
  schema_version: number
  command: string
  base_aggregate_digest: string
  head_aggregate_digest: string
  summary: {
    total_files_base: number
    total_files_head: number
    added_files: number
    modified_files: number
    deleted_files: number
    renamed_files: number
    unchanged_files: number
    rust_files_changed: number
    net_bytes_delta: number
  }
  deltas: any[]
}

export interface PathValidationResult {
  exists: boolean
  isDirectory?: boolean
  resolvedPath?: string
  isGitRepo?: boolean
  fileCount?: number
  ecosystems?: {
    rust: boolean
    node: boolean
    bun: boolean
    pnpm: boolean
    yarn: boolean
  }
  error?: string
}

export interface StreamLogItem {
  id: string
  text: string
  stream: 'stdout' | 'stderr'
  timestamp: string
}

export const API_BASE = '/api'

export async function checkApiHealth(): Promise<{ status: string; binaryPath: string; binaryExists: boolean; defaultStorage: string; repoRoot: string } | null> {
  try {
    const res = await fetch(`${API_BASE}/health`)
    if (!res.ok) return null
    return await res.json()
  } catch (err) {
    return null
  }
}

export async function fetchRealOverview(): Promise<{ sessionCount: number; auditEventCount: number; latestSession: any; defaultStorage: string; repoRoot: string } | null> {
  try {
    const res = await fetch(`${API_BASE}/overview`)
    if (!res.ok) return null
    return await res.json()
  } catch (err) {
    return null
  }
}

export async function fetchRealSessions(): Promise<any[]> {
  try {
    const res = await fetch(`${API_BASE}/sessions`)
    if (!res.ok) return []
    const data = await res.json()
    return data.sessions || []
  } catch (err) {
    return []
  }
}

export async function fetchRealAuditTrail(): Promise<any[]> {
  try {
    const res = await fetch(`${API_BASE}/audit-trail`)
    if (!res.ok) return []
    const data = await res.json()
    return data.events || []
  } catch (err) {
    return []
  }
}

export async function validateWorkspacePath(targetPath: string): Promise<PathValidationResult> {
  try {
    const res = await fetch(`${API_BASE}/validate-path`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: targetPath }),
    })
    return await res.json()
  } catch (err: any) {
    return { exists: false, error: err.message || 'Validation request failed' }
  }
}

export async function triggerLiveScan(workspace: string): Promise<RealScanResponse> {
  const res = await fetch(`${API_BASE}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ workspace }),
  })
  if (!res.ok) throw new Error(`Scan failed with HTTP ${res.status}`)
  return await res.json()
}

export async function triggerLiveAudit(workspace: string, database?: string): Promise<RealAuditResponse> {
  const res = await fetch(`${API_BASE}/audit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ workspace, database }),
  })
  if (!res.ok) throw new Error(`Audit failed with HTTP ${res.status}`)
  return await res.json()
}

export async function triggerLiveCodeQl(workspace: string): Promise<RealCodeQlResponse> {
  const res = await fetch(`${API_BASE}/codeql`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ workspace }),
  })
  if (!res.ok) throw new Error(`CodeQL probe failed with HTTP ${res.status}`)
  return await res.json()
}

export async function triggerLiveDiff(base: string, head: string): Promise<RealDiffResponse> {
  const res = await fetch(`${API_BASE}/diff`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ base, head }),
  })
  if (!res.ok) throw new Error(`Diff failed with HTTP ${res.status}`)
  return await res.json()
}

export async function triggerScanSnippet(code: string, language: string): Promise<RealScanResponse> {
  const res = await fetch(`${API_BASE}/scan-snippet`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, language }),
  })
  if (!res.ok) throw new Error(`Snippet scan failed with HTTP ${res.status}`)
  return await res.json()
}

export async function generateAiPatch(
  finding: FindingView,
  providerConfig?: {
    provider?: 'local' | 'openai' | 'anthropic' | 'gemini' | 'deepseek' | 'xai' | 'openrouter' | 'opencode'
    endpoint?: string
    apiKey?: string
    model?: string
  }
): Promise<any> {
  const res = await fetch(`${API_BASE}/ai/generate-patch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ finding, providerConfig }),
  })
  if (!res.ok) throw new Error(`AI Patch generation failed with HTTP ${res.status}`)
  return await res.json()
}

export async function applyPatchToWorkspace(params: {
  patchId: string
  diff: string
  targetLocation: string
  workspace?: string
}): Promise<{
  success: boolean
  patchId: string
  targetLocation: string
  resolvedPath: string
  backupPath: string
  alreadyPatched: boolean
  message: string
}> {
  const res = await fetch(`${API_BASE}/patch/apply`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.error || `Patch application failed with HTTP ${res.status}`)
  }
  return await res.json()
}

export async function rollbackPatch(params: {
  patchId: string
  backupPath: string
  targetLocation: string
  workspace?: string
}): Promise<{
  success: boolean
  patchId: string
  targetLocation: string
  restoredFrom: string
  message: string
}> {
  const res = await fetch(`${API_BASE}/patch/rollback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.error || `Rollback failed with HTTP ${res.status}`)
  }
  return await res.json()
}

export async function fetchWebhookDeliveries(): Promise<any[]> {
  try {
    const res = await fetch(`${API_BASE}/webhook/deliveries`)
    if (!res.ok) return []
    const data = await res.json()
    return data.deliveries || []
  } catch {
    return []
  }
}

export async function simulateWebhookDispatch(): Promise<any> {
  const res = await fetch(`${API_BASE}/webhook/test-dispatch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  })
  if (!res.ok) throw new Error(`Webhook simulation failed with HTTP ${res.status}`)
  return await res.json()
}

/**
 * Robust Server-Sent Events (SSE) Stream Reader with chunk buffering
 */
export function streamLiveScan(options: {
  workspace: string
  scanType?: 'all' | 'sast' | 'audit' | 'codeql'
  persist?: boolean
  onLog: (item: StreamLogItem) => void
  onProgress: (stage: string, percent: number) => void
  onComplete: (data: any) => void
  onError: (err: any) => void
}): () => void {
  const controller = new AbortController()
  const params = new URLSearchParams({
    workspace: options.workspace,
    scanType: options.scanType || 'all',
    persist: options.persist !== false ? 'true' : 'false',
  })

  async function execute() {
    try {
      const response = await fetch(`${API_BASE}/scan-stream?${params.toString()}`, {
        signal: controller.signal,
      })

      if (!response.ok || !response.body) {
        throw new Error(`SSE stream failed with HTTP ${response.status}`)
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      let logIndex = 0

      while (true) {
        const { value, done } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const events = buffer.split('\n\n')
        buffer = events.pop() || ''

        for (const rawEvent of events) {
          if (!rawEvent.trim()) continue
          const lines = rawEvent.split('\n')
          let eventType = 'message'
          let eventData = ''

          for (const line of lines) {
            if (line.startsWith('event: ')) {
              eventType = line.replace('event: ', '').trim()
            } else if (line.startsWith('data: ')) {
              eventData = line.replace('data: ', '').trim()
            }
          }

          if (!eventData) continue

          try {
            const parsed = JSON.parse(eventData)
            if (eventType === 'log') {
              logIndex++
              options.onLog({
                id: `log-${logIndex}-${Date.now()}`,
                text: parsed.text || '',
                stream: parsed.stream || 'stdout',
                timestamp: parsed.timestamp || new Date().toISOString(),
              })
            } else if (eventType === 'progress') {
              options.onProgress(parsed.stage || 'Processing...', parsed.percent || 0)
            } else if (eventType === 'complete') {
              options.onComplete(parsed)
            } else if (eventType === 'error') {
              options.onError(parsed)
            }
          } catch (jsonErr) {
            console.error('Failed to parse SSE payload:', eventData, jsonErr)
          }
        }
      }
    } catch (err: any) {
      if (controller.signal.aborted) {
        options.onLog({
          id: `abort-${Date.now()}`,
          text: '[SENTRA] Scan aborted by operator.',
          stream: 'stderr',
          timestamp: new Date().toISOString(),
        })
      } else {
        options.onError(err)
      }
    }
  }

  execute()

  return () => {
    controller.abort()
  }
}

export function transformMatchesToFindings(matches: RealScanMatch[]): FindingView[] {
  return matches.map((m, idx) => {
    const isTaint = m.rule_id.startsWith('SENTRA-TAINT-')
    const severity: Severity =
      m.severity === 'CRITICAL'
        ? 'Critical'
        : m.severity === 'HIGH'
          ? 'High'
          : m.severity === 'MEDIUM'
            ? 'Medium'
            : 'Low'

    const reachability: Reachability = isTaint ? 'ReachableCallPath' : 'SinkOnly'

    // Extract taint steps if present in rationale Markdown table
    let taintTrace = undefined
    if (isTaint && m.rationale.includes('In-Engine Taint Data-Flow Path')) {
      const lines = m.rationale.split('\n')
      const tableRows = lines.filter((l) => l.trim().startsWith('|') && !l.includes('---') && !l.includes('Role'))
      if (tableRows.length > 0) {
        taintTrace = tableRows.map((row, stepIdx) => {
          const parts = row.split('|').map((s) => s.trim())
          const roleRaw = parts[2] || ''
          const role = roleRaw.includes('SOURCE')
            ? ('SOURCE' as const)
            : roleRaw.includes('PROPAGATE')
              ? ('PROPAGATION' as const)
              : roleRaw.includes('SINK')
                ? ('SINK' as const)
                : ('SANITIZER' as const)
          const line = parseInt(parts[3] || `${m.line_number}`, 10) || m.line_number
          const variable = (parts[4] || '').replace(/`/g, '')
          const codeSnippet = (parts[5] || '').replace(/`/g, '')

          return {
            step: stepIdx + 1,
            role,
            location: m.file_path,
            line,
            codeSnippet: codeSnippet || m.snippet,
            variable: variable || 'expr',
          }
        })
      }
    }

    return {
      findingId: `fnd-real-${idx + 1}-${m.rule_id.toLowerCase()}`,
      tenantId: 'sentra-internal',
      ruleId: m.rule_id,
      cwe: m.cwe,
      title: `${m.rule_name.replace(/([A-Z])/g, ' $1').trim()} (${m.rule_id})`,
      severity,
      confidence: 'High',
      reachability,
      status: 'Candidate' as FindingStatus,
      targetLocation: m.file_path,
      startLine: m.line_number,
      endLine: m.line_number,
      cvssScore: severity === 'Critical' ? 9.5 : severity === 'High' ? 7.8 : 5.0,
      remediationGuidance: isTaint
        ? 'Parameterize database inputs or avoid dynamic shell interpolation.'
        : 'Store secrets in environment variables or key vaults instead of source code.',
      description: m.rationale,
      taintTrace,
      createdAt: new Date().toISOString(),
    }
  })
}

// =========================================================================
// Cloudflare Coverage Ledger & Audit Campaign Client Functions
// =========================================================================

export async function fetchCoverageLedger(): Promise<import('@/types/sentra').CoverageLedgerReport | null> {
  try {
    const res = await fetch(`${API_BASE}/audit/coverage-ledger`)
    if (!res.ok) return null
    return await res.json()
  } catch (err) {
    console.error('Failed to fetch coverage ledger:', err)
    return null
  }
}

export async function validateLedgerInvariants(): Promise<{ valid: boolean; checkedUnits: number; errorCount: number; errors: string[] } | null> {
  try {
    const res = await fetch(`${API_BASE}/audit/validate-ledger`, { method: 'POST' })
    if (!res.ok) return null
    return await res.json()
  } catch (err) {
    console.error('Failed to validate ledger invariants:', err)
    return null
  }
}

export async function setAuditProfile(profile: 'quick' | 'standard' | 'deep'): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/audit/set-profile`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile }),
    })
    return res.ok
  } catch (err) {
    return false
  }
}

export async function runAuditCampaignWave(): Promise<{ success: boolean; promotedCount: number; message: string } | null> {
  try {
    const res = await fetch(`${API_BASE}/audit/run-campaign`, { method: 'POST' })
    if (!res.ok) return null
    return await res.json()
  } catch (err) {
    return null
  }
}

export async function validateFindingsInvariants(
  findings: FindingView[]
): Promise<{ invariantsPass: boolean; totalFindings: number; errors: string[]; output: string } | null> {
  try {
    const res = await fetch(`${API_BASE}/audit/validate-findings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ findings }),
    })
    if (!res.ok) return null
    return await res.json()
  } catch (err) {
    console.error('Failed to validate findings invariants:', err)
    return null
  }
}

export async function fetchReconTopology(): Promise<import('@/types/sentra').ReconTopologyReport | null> {
  try {
    const res = await fetch(`${API_BASE}/audit/recon-topology`)
    if (!res.ok) return null
    return await res.json()
  } catch (err) {
    console.error('Failed to fetch recon topology:', err)
    return null
  }
}

export async function runPhase1Reconnaissance(): Promise<import('@/types/sentra').Phase1ReconReport | null> {
  try {
    const res = await fetch(`${API_BASE}/audit/run-reconnaissance`, { method: 'POST' })
    if (!res.ok) return null
    return await res.json()
  } catch (err) {
    console.error('Failed to run reconnaissance:', err)
    return null
  }
}
