import { api, errorMessage } from '@/lib/api'
import {
  SEVERITIES,
  type AuditLogEntryView,
  type CoreSessionView,
  type FindingView,
  type OverviewView,
  type PatchBundleView,
  type SessionInfo,
  type Severity,
  type SystemStatus,
  type TenantView,
} from '@/types/api'
import { CODEQL_PER_ORIGIN_NOTE, codeqlOriginBreakdown } from '@/components/dashboard/findings-format'

/**
 * Builds a self-contained HTML report from data read from the bridge at generation time.
 * Every interpolated value is HTML-escaped; links are emitted only for http(s) URLs. The report
 * states what the data is (unvalidated candidates, unverified model output) and makes no
 * compliance, verification or signing claims.
 */

const AUDIT_EXCERPT_LIMIT = 50
const FINDINGS_ROW_LIMIT = 1000

export interface ExecutiveReportData {
  generatedAt: string
  generatedBy: Pick<SessionInfo, 'principal' | 'roleLabel' | 'via'>
  tenant: TenantView
  overview: OverviewView
  openFindings: FindingView[]
  patches: PatchBundleView[]
  audit: { entries: AuditLogEntryView[]; total: number }
  system: SystemStatus | null
  systemError: string | null
}

export async function collectExecutiveReportData(tenant: TenantView, session: SessionInfo): Promise<ExecutiveReportData> {
  const systemPromise = api.system.status().then(
    (status) => ({ status, error: null as string | null }),
    (failure: unknown) => ({ status: null, error: errorMessage(failure) }),
  )
  const [overview, findings, patches, audit, system] = await Promise.all([
    api.tenants.overview(tenant.tenantId),
    api.findings.list(tenant.tenantId, { state: 'open' }),
    api.patches.list(tenant.tenantId),
    api.audit.log({ tenant: tenant.tenantId, limit: AUDIT_EXCERPT_LIMIT }),
    systemPromise,
  ])
  return {
    generatedAt: new Date().toISOString(),
    generatedBy: { principal: session.principal, roleLabel: session.roleLabel, via: session.via },
    tenant: overview.tenant,
    overview,
    openFindings: findings.findings,
    patches: patches.patches,
    audit: { entries: audit.entries, total: audit.total },
    system: system.status,
    systemError: system.error,
  }
}

export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function safeHttpUrl(raw: string | null | undefined): string | null {
  if (!raw) return null
  try {
    const url = new URL(raw)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : null
  } catch {
    return null
  }
}

function link(raw: string | null | undefined, label: string): string {
  const url = safeHttpUrl(raw)
  return url ? `<a href="${escapeHtml(url)}" rel="noopener noreferrer">${escapeHtml(label)}</a>` : escapeHtml(label)
}

function text(value: string | number | null | undefined, fallback = '—'): string {
  if (value === null || value === undefined || value === '') return `<span class="muted">${escapeHtml(fallback)}</span>`
  return escapeHtml(value)
}

function formatTime(iso: string | null | undefined): string {
  if (!iso) return '<span class="muted">—</span>'
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? escapeHtml(iso) : escapeHtml(date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z'))
}

function formatMicroUsd(value: number | null): string {
  if (value === null) return '<span class="muted">—</span>'
  return escapeHtml(`$${(value / 1_000_000).toFixed(4)}`)
}

const SEVERITY_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4, Unknown: 5 }

function findingLocation(finding: FindingView): string {
  if (finding.source === 'dependency' && finding.dependency) {
    const dep = finding.dependency
    return `${escapeHtml(`${dep.packageName}@${dep.packageVersion}`)} <span class="muted">(${escapeHtml(dep.ecosystem)} · ${escapeHtml(dep.lockfile)})</span>`
  }
  if (!finding.filePath) return '<span class="muted">—</span>'
  return `<code>${escapeHtml(finding.line !== null ? `${finding.filePath}:${finding.line}` : finding.filePath)}</code>`
}

function findingRule(finding: FindingView): string {
  if (finding.source === 'dependency' && finding.dependency) {
    const advisory = finding.dependency.advisoryId
    const reference = finding.dependency.references.find((ref) => safeHttpUrl(ref.url))
    return `${reference ? link(reference.url, advisory) : escapeHtml(advisory)}${
      finding.dependency.summary ? `<div class="muted">${escapeHtml(finding.dependency.summary)}</div>` : ''
    }`
  }
  return `<code>${escapeHtml(finding.ruleId)}</code><div class="muted">${escapeHtml(finding.ruleName)}${
    finding.cwe ? ` · ${escapeHtml(finding.cwe)}` : ''
  }</div>`
}

function triageLabel(finding: FindingView): string {
  if (!finding.triage) return '<span class="muted">untriaged</span>'
  return `${escapeHtml(finding.triage.verdict.replace('_', ' '))} <span class="muted">by ${escapeHtml(finding.triage.by)}</span>`
}

function coreSessionRows(core: CoreSessionView & { taskCount: number | null; auditEventCount: number | null }): string {
  if (!core.initialized) {
    return `<tr><th>State</th><td>Not initialized${core.error ? ` <span class="muted">(${escapeHtml(core.error)})</span>` : ''}</td></tr>`
  }
  return [
    ['Session', text(core.sessionId)],
    ['State', text(core.state)],
    ['Mode', text(core.mode)],
    ['Classification floor', text(core.classificationFloor)],
    ['Context generation', text(core.contextGeneration)],
    ['Budget used / limit', `${formatMicroUsd(core.budgetUsedMicroUsd)} / ${formatMicroUsd(core.budgetLimitMicroUsd)}`],
    ['Core tasks', text(core.taskCount)],
    ['Core audit events', text(core.auditEventCount)],
    ['Created', formatTime(core.createdAt)],
    ['Updated', formatTime(core.updatedAt)],
  ]
    .map(([label, value]) => `<tr><th>${escapeHtml(label)}</th><td>${value}</td></tr>`)
    .join('')
}

/**
 * Splits open findings the way the bridge counts them: findings triaged as rejected stay open
 * (the scanner still reports them) but are excluded from `OverviewView.openFindings.total`.
 */
export function splitOpenFindings(findings: FindingView[]): { counted: FindingView[]; rejected: FindingView[] } {
  const counted: FindingView[] = []
  const rejected: FindingView[] = []
  for (const finding of findings) (finding.triage?.verdict === 'rejected' ? rejected : counted).push(finding)
  return { counted, rejected }
}

const SOURCE_LABEL: Record<string, string> = { sast: 'SAST', dependency: 'Dependency', codeql: 'CodeQL' }
const ORIGIN_LABEL: Record<string, string> = { host_analysis: 'host analysis', sarif_import: 'SARIF import', github_code_scanning: 'GitHub code scanning' }

/** "SAST", "Dependency" or "CodeQL (SARIF import)"; unknown values are shown as they are. */
function sourceLabel(finding: FindingView): string {
  const source = SOURCE_LABEL[finding.source] ?? String(finding.source)
  return finding.source === 'codeql' && finding.origin ? `${source} (${ORIGIN_LABEL[finding.origin] ?? finding.origin})` : source
}

function findingRow(finding: FindingView): string {
  return `<tr>
  <td><span class="sev sev-${escapeHtml(finding.severity.toLowerCase())}">${escapeHtml(finding.severity)}</span></td>
  <td>${escapeHtml(sourceLabel(finding))}</td>
  <td>${findingRule(finding)}</td>
  <td>${findingLocation(finding)}</td>
  <td>${triageLabel(finding)}<div class="muted">first seen ${formatTime(finding.firstSeenAt)}</div></td>
</tr>`
}

export function renderExecutiveReportHtml(data: ExecutiveReportData): string {
  const { tenant, overview } = data
  const open = overview.openFindings
  const bySeverity = (a: FindingView, b: FindingView) =>
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.ruleId.localeCompare(b.ruleId)
  const split = splitOpenFindings(data.openFindings)
  const findings = [...split.counted].sort(bySeverity)
  const rejectedFindings = [...split.rejected].sort(bySeverity)
  const shownFindings = findings.slice(0, FINDINGS_ROW_LIMIT)
  const shownRejected = rejectedFindings.slice(0, FINDINGS_ROW_LIMIT)
  const lastRun = overview.lastRun
  const coreVersion = data.system?.core.version ?? null

  const severityRows = SEVERITIES.map(
    (severity) => `<tr><th>${escapeHtml(severity)}</th><td class="num">${escapeHtml(open.bySeverity[severity] ?? 0)}</td></tr>`,
  ).join('')

  const findingRows =
    shownFindings.length === 0
      ? `<tr><td colspan="5" class="muted">${
          overview.lastResultRunAt
            ? rejectedFindings.length > 0
              ? 'Every open finding is triaged as rejected (listed below). This does not mean the workspace is free of vulnerabilities: the scanners are heuristic.'
              : 'No open findings were recorded by the scans that ran. This does not mean the workspace is free of vulnerabilities: the scanners are heuristic.'
            : 'No completed scan with SAST, dependency or CodeQL host-analysis results exists for this workspace, so there is no finding data.'
        }</td></tr>`
      : shownFindings.map(findingRow).join('')

  const rejectedSection =
    rejectedFindings.length === 0
      ? ''
      : `<h2>Open findings triaged as rejected (${escapeHtml(rejectedFindings.length)})</h2>
<p class="muted">The scanner still reports these, but an operator triaged them as rejected. They are excluded from the open total and the severity counts above.</p>
${rejectedFindings.length > shownRejected.length ? `<p class="muted">Showing the first ${escapeHtml(shownRejected.length)} findings ordered by severity.</p>` : ''}
<table>
  <thead><tr><th>Severity</th><th>Source</th><th>Rule / advisory</th><th>Location</th><th>Triage</th></tr></thead>
  <tbody>${shownRejected.map(findingRow).join('')}</tbody>
</table>`

  const patchRows =
    data.patches.length === 0
      ? '<tr><td colspan="6" class="muted">No patch candidates have been generated for this workspace.</td></tr>'
      : data.patches
          .map(
            (patch) => `<tr>
  <td>${escapeHtml(patch.title)}<div class="muted"><code>${escapeHtml(patch.targetPath)}</code></div></td>
  <td>${escapeHtml(patch.provider)} <span class="muted">${escapeHtml(patch.model)}</span></td>
  <td>${escapeHtml(patch.state.replace('_', ' '))}${patch.appliedAt ? `<div class="muted">applied ${formatTime(patch.appliedAt)} by ${escapeHtml(patch.appliedBy ?? '—')}</div>` : ''}</td>
  <td>${patch.appliesCleanly ? 'yes' : 'no'}${patch.applyCheckDetail ? `<div class="muted">${escapeHtml(patch.applyCheckDetail)}</div>` : ''}</td>
  <td>Not run</td>
  <td>${patch.pullRequest ? link(patch.pullRequest.url, `#${patch.pullRequest.number}`) : '<span class="muted">—</span>'}</td>
</tr>`,
          )
          .join('')

  const auditRows =
    data.audit.entries.length === 0
      ? '<tr><td colspan="6" class="muted">No operator audit entries are recorded for this workspace.</td></tr>'
      : data.audit.entries
          .map(
            (entry) => `<tr>
  <td class="num">${escapeHtml(entry.seq)}</td>
  <td>${formatTime(entry.ts)}</td>
  <td>${escapeHtml(entry.actor)} <span class="muted">${escapeHtml(entry.role)}</span></td>
  <td><code>${escapeHtml(entry.action)}</code></td>
  <td>${text(entry.target)}</td>
  <td><span class="outcome outcome-${escapeHtml(entry.outcome)}">${escapeHtml(entry.outcome)}</span></td>
</tr>`,
          )
          .join('')

  const gitHead = tenant.gitHead
    ? `${text(tenant.gitHead.branch, 'detached HEAD')} @ <code>${text(tenant.gitHead.sha ? tenant.gitHead.sha.slice(0, 12) : null)}</code>`
    : '<span class="muted">No git metadata</span>'

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentra report · ${escapeHtml(tenant.name)}</title>
<style>
  :root { color-scheme: light; }
  body { font: 13px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: #18181b; background: #fff; margin: 0; padding: 32px; }
  main { max-width: 1080px; margin: 0 auto; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  h2 { font-size: 16px; margin: 28px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #e4e4e7; }
  .muted { color: #71717a; }
  .notice { border: 1px solid #f59e0b; background: #fffbeb; padding: 10px 14px; border-radius: 6px; margin: 16px 0; }
  table { border-collapse: collapse; width: 100%; margin: 6px 0; }
  th, td { text-align: left; vertical-align: top; padding: 5px 8px; border-bottom: 1px solid #f4f4f5; }
  thead th { background: #fafafa; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: #52525b; }
  table.kv th { width: 220px; color: #52525b; font-weight: 500; }
  .num { text-align: right; font-variant-numeric: tabular-nums; }
  code { font: 12px ui-monospace, SFMono-Regular, Consolas, monospace; word-break: break-all; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }
  .sev { font-weight: 600; }
  .sev-critical { color: #be123c; } .sev-high { color: #c2410c; } .sev-medium { color: #a16207; }
  .sev-low { color: #0369a1; } .sev-informational, .sev-unknown { color: #52525b; }
  .outcome-success { color: #15803d; } .outcome-failure { color: #be123c; } .outcome-denied { color: #a16207; }
  ul { margin: 6px 0; padding-left: 20px; }
  footer { margin-top: 32px; font-size: 11px; color: #71717a; }
</style>
</head>
<body>
<main>
<h1>Sentra security review report</h1>
<div class="muted">${escapeHtml(tenant.name)} · <code>${escapeHtml(tenant.tenantId)}</code> · generated ${formatTime(data.generatedAt)}</div>

<div class="notice">
  <strong>How to read this report.</strong> Findings are <strong>unvalidated candidates</strong> reported by Sentra's heuristic,
  line-based SAST rules, by OSV.dev advisory matches against lockfile versions and by CodeQL (run on the bridge host with build
  mode none, imported from a SARIF file, or read from GitHub code scanning). They have not been independently verified
  and may include false positives; the absence of a finding is not evidence of absence of a vulnerability. Patches are
  model-generated candidates; no patch has been verified (verification: not run). This document is not a compliance attestation.
</div>

<h2>Workspace</h2>
<table class="kv">
  <tr><th>Tenant</th><td>${escapeHtml(tenant.name)} <code>${escapeHtml(tenant.tenantId)}</code></td></tr>
  <tr><th>Description</th><td>${text(tenant.description)}</td></tr>
  <tr><th>Workspace path</th><td><code>${escapeHtml(tenant.workspace)}</code>${tenant.workspaceExists ? '' : ' <span class="sev-critical">(directory not found on the bridge host)</span>'}</td></tr>
  <tr><th>Git</th><td>${gitHead}</td></tr>
  <tr><th>GitHub repository</th><td>${
    tenant.githubRepository
      ? `${escapeHtml(`${tenant.githubRepository.owner}/${tenant.githubRepository.repo}`)} <span class="muted">(${escapeHtml(tenant.githubRepository.source === 'configured' ? 'configured' : 'from git remote')})</span>`
      : '<span class="muted">Not configured</span>'
  }</td></tr>
  <tr><th>Isolation level</th><td>${escapeHtml(tenant.isolationLevel)} <span class="muted">(declared label; not enforced by the console)</span></td></tr>
  <tr><th>Registered</th><td>${formatTime(tenant.createdAt)} by ${escapeHtml(tenant.createdBy)}</td></tr>
</table>

<h2>Summary</h2>
<div class="grid">
  <table class="kv">
    <tr><th>Open candidate findings</th><td class="num">${escapeHtml(open.total)}</td></tr>
    <tr><th>From SAST rules</th><td class="num">${escapeHtml(open.bySource.sast ?? 0)}</td></tr>
    <tr><th>From dependency advisories</th><td class="num">${escapeHtml(open.bySource.dependency ?? 0)}</td></tr>
    <tr><th>From CodeQL (host analysis, SARIF import, GitHub code scanning)${(open.bySource.codeql ?? 0) > 0 ? `<div class="muted">${escapeHtml(codeqlOriginBreakdown(open.codeqlByOrigin))}. ${escapeHtml(CODEQL_PER_ORIGIN_NOTE)}</div>` : ''}</th><td class="num">${escapeHtml(open.bySource.codeql ?? 0)}</td></tr>
    <tr><th>Resolved (no longer reported)</th><td class="num">${escapeHtml(overview.resolvedFindings)}</td></tr>
  </table>
  <table class="kv">${severityRows}</table>
  <table class="kv">
    <tr><th>Untriaged</th><td class="num">${escapeHtml(open.byTriage.untriaged)}</td></tr>
    <tr><th>Triaged: confirmed</th><td class="num">${escapeHtml(open.byTriage.confirmed)}</td></tr>
    <tr><th>Triaged: needs validation</th><td class="num">${escapeHtml(open.byTriage.needs_validation)}</td></tr>
    <tr><th>Triaged: rejected <span class="muted">(excluded from the open total)</span></th><td class="num">${escapeHtml(open.byTriage.rejected)}</td></tr>
  </table>
</div>
<table class="kv">
  <tr><th>Last scan with results</th><td>${formatTime(overview.lastResultRunAt)} <div class="muted">Newest completed run that produced SAST, dependency or CodeQL host-analysis results (SARIF imports and GitHub syncs are not runs)</div></td></tr>
  <tr><th>Last completed run (any kind)</th><td>${formatTime(overview.lastCompletedRunAt)}</td></tr>
  <tr><th>Latest run</th><td>${
    lastRun
      ? `${escapeHtml(lastRun.kind)} · ${escapeHtml(lastRun.status)} · started ${formatTime(lastRun.startedAt)} by ${escapeHtml(lastRun.actor)} (${escapeHtml(lastRun.trigger)})${
          lastRun.error ? `<div class="sev-critical">${escapeHtml(lastRun.error)}</div>` : ''
        }`
      : '<span class="muted">No scan has run</span>'
  }</td></tr>
  <tr><th>Heuristic risk score</th><td>${
    overview.riskScore
      ? `${escapeHtml(overview.riskScore.value)} <div class="muted">Formula: <code>${escapeHtml(overview.riskScore.formula)}</code></div>`
      : '<span class="muted">Not computed: no completed run with SAST, dependency or CodeQL host-analysis results</span>'
  }</td></tr>
  <tr><th>Patch candidates</th><td>${escapeHtml(overview.patches.proposed)} proposed · ${escapeHtml(overview.patches.applied)} applied · ${escapeHtml(overview.patches.rolledBack)} rolled back · ${escapeHtml(overview.patches.pullRequests)} pull requests</td></tr>
</table>

<h2>Open candidate findings (${escapeHtml(findings.length)})</h2>
${findings.length > shownFindings.length ? `<p class="muted">Showing the first ${escapeHtml(shownFindings.length)} findings ordered by severity.</p>` : ''}
<table>
  <thead><tr><th>Severity</th><th>Source</th><th>Rule / advisory</th><th>Location</th><th>Triage</th></tr></thead>
  <tbody>${findingRows}</tbody>
</table>
${rejectedSection}

<h2>Patch candidates (${escapeHtml(data.patches.length)})</h2>
<table>
  <thead><tr><th>Patch</th><th>Model</th><th>State</th><th>Applies cleanly (dry run)</th><th>Verification</th><th>Pull request</th></tr></thead>
  <tbody>${patchRows}</tbody>
</table>

<h2>Core session</h2>
<table class="kv">${coreSessionRows(overview.core)}</table>

<h2>Operator audit log excerpt</h2>
<p class="muted">The ${escapeHtml(data.audit.entries.length)} most recent of ${escapeHtml(data.audit.total)} console audit entries for this workspace.
This report does not include a chain verification result; use "Verify chain" in the console's Audit trail view.</p>
<table>
  <thead><tr><th>Seq</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Target</th><th>Outcome</th></tr></thead>
  <tbody>${auditRows}</tbody>
</table>

<h2>Provenance</h2>
<table class="kv">
  <tr><th>Generated at</th><td>${formatTime(data.generatedAt)}</td></tr>
  <tr><th>Generated by</th><td>${escapeHtml(data.generatedBy.principal)} (${escapeHtml(data.generatedBy.roleLabel)}, signed in via ${escapeHtml(data.generatedBy.via)})</td></tr>
  <tr><th>Console bridge</th><td>${data.system ? escapeHtml(`${data.system.mode} mode`) : `<span class="muted">status unavailable${data.systemError ? `: ${escapeHtml(data.systemError)}` : ''}</span>`}</td></tr>
  <tr><th>Sentra core version</th><td>${
    coreVersion ? escapeHtml(coreVersion) : `<span class="muted">unavailable${data.system?.core.error ? `: ${escapeHtml(data.system.core.error)}` : ''}</span>`
  }</td></tr>
  <tr><th>Data sources</th><td><ul>
    <li><code>GET /api/tenants/${escapeHtml(tenant.tenantId)}/overview</code> — counts, last run, core session</li>
    <li><code>GET /api/tenants/${escapeHtml(tenant.tenantId)}/findings?state=open</code> — open candidate findings</li>
    <li><code>GET /api/tenants/${escapeHtml(tenant.tenantId)}/patches</code> — patch candidates</li>
    <li><code>GET /api/audit-log?tenant=${escapeHtml(tenant.tenantId)}&amp;limit=${AUDIT_EXCERPT_LIMIT}</code> — operator audit excerpt</li>
    <li><code>GET /api/system</code> — bridge mode and core version</li>
  </ul></td></tr>
</table>
<footer>All values were read from the Sentra console bridge when this file was generated; nothing was estimated or filled in.</footer>
</main>
</body>
</html>
`
}
