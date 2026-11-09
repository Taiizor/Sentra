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
