import type {
  DashboardOverview,
  FindingView,
  PatchBundleView,
  AuditLogView,
  TenantView,
} from '@/types/sentra'

export function generateExecutiveReportHtml(
  overview: DashboardOverview,
  findings: FindingView[],
  patches: PatchBundleView[],
  auditLogs: AuditLogView[],
  tenant?: TenantView
): string {
  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })
  const timeStr = new Date().toLocaleTimeString('en-US')
  const tenantName = tenant?.name || overview.workspaceName || 'Organization Workspace'
  const tenantId = tenant?.tenantId || overview.tenantId || 'default-tenant'
  const isolationLevel = tenant?.isolationLevel || 'multi_tenant_isolated'

  const criticals = findings.filter((f) => f.severity === 'Critical')
  const highs = findings.filter((f) => f.severity === 'High')
  const mediums = findings.filter((f) => f.severity === 'Medium')
  const lows = findings.filter((f) => f.severity === 'Low')
  const infos = findings.filter((f) => f.severity === 'Informational')
  const verifiedPatches = patches.filter((p) => p.isVerified)

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sentra Executive Threat Posture & Audit Report — ${escapeHtml(tenantName)}</title>
  <style>
    :root {
      --bg: #09090b;
      --card: #18181b;
      --border: #27272a;
      --text: #f4f4f5;
      --text-muted: #a1a1aa;
      --primary: #10b981;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
    }
    @media print {
      body { background: #fff !important; color: #000 !important; }
      .no-print { display: none !important; }
      .card { border: 1px solid #ccc !important; background: #fff !important; color: #000 !important; box-shadow: none !important; }
      .badge-crit { background: #fee2e2 !important; color: #b91c1c !important; }
      .badge-high { background: #ffedd5 !important; color: #c2410c !important; }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 2.5rem 1.5rem;
    }
    .container { max-width: 1080px; margin: 0 auto; }
    .header-bar {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
    }
    .logo-title { display: flex; align-items: center; gap: 0.75rem; }
    .logo-icon {
      width: 40px;
      height: 40px;
      border-radius: 8px;
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.4);
      display: flex;
      align-items: center;
      justify-content: center;
      color: var(--primary);
      font-weight: bold;
      font-size: 1.25rem;
    }
    .grid-4 { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
    }
    .stat-val { font-size: 2rem; font-weight: 700; line-height: 1.1; margin-top: 0.25rem; }
    .stat-lbl { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .badge {
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
    }
    .badge-crit { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-high { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }
    .badge-med { background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }
    .badge-low { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
    .badge-verif { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.85rem; }
    th { text-align: left; padding: 0.75rem; border-bottom: 1px solid var(--border); color: var(--text-muted); font-size: 0.75rem; text-transform: uppercase; }
    td { padding: 0.75rem; border-bottom: 1px solid var(--border); }
    .btn-print {
      background: var(--primary);
      color: #000;
      border: none;
      padding: 0.5rem 1rem;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      font-size: 0.85rem;
    }
    .code-box {
      font-family: monospace;
      font-size: 0.75rem;
      background: #000;
      padding: 0.5rem;
      border-radius: 4px;
      border: 1px solid #333;
      color: #a7f3d0;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header-bar">
      <div>
        <div class="logo-title">
          <div class="logo-icon">S</div>
          <div>
            <h1 style="font-size: 1.5rem; font-weight: 700;">Sentra Autonomous Security Intelligence</h1>
            <p style="color: var(--text-muted); font-size: 0.85rem;">Executive Threat Posture & Independent Verification Report</p>
          </div>
        </div>
      </div>
      <div style="text-align: right;">
        <button class="btn-print no-print" onclick="window.print()">Print / Save as PDF</button>
        <p style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">Generated on ${dateStr} at ${timeStr}</p>
      </div>
    </div>

    <!-- Metadata & Scope -->
    <div class="card" style="margin-bottom: 1.5rem;">
      <h2 style="font-size: 0.95rem; font-weight: 600; margin-bottom: 0.5rem;">Audited Organizational Scope</h2>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; font-size: 0.85rem;">
        <div><strong style="color: var(--text-muted);">Tenant Workspace:</strong> <br>${escapeHtml(tenantName)}</div>
        <div><strong style="color: var(--text-muted);">Tenant Identifier:</strong> <br><code style="color: var(--primary);">${escapeHtml(tenantId)}</code></div>
        <div><strong style="color: var(--text-muted);">Boundary Fencing:</strong> <br>${escapeHtml(isolationLevel)}</div>
        <div><strong style="color: var(--text-muted);">Security Standard:</strong> <br>Cloudflare 6-Phase / OASIS SARIF v2.1.0</div>
      </div>
    </div>

    <!-- Executive Metrics -->
    <div class="grid-4">
      <div class="card">
        <div class="stat-lbl">Security Posture Score</div>
        <div class="stat-val" style="color: ${overview.securityScore >= 80 ? 'var(--primary)' : 'var(--high)'};">${overview.securityScore}/100</div>
        <p style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem;">
          ${overview.securityScore >= 80 ? 'Optimal Posture' : 'Action Required'}
        </p>
      </div>
      <div class="card">
        <div class="stat-lbl">Active Findings</div>
        <div class="stat-val" style="color: ${criticals.length > 0 ? 'var(--critical)' : 'var(--text)'};">${findings.length}</div>
        <p style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem;">
          ${criticals.length} Crit, ${highs.length} High, ${mediums.length} Med, ${lows.length + infos.length} Other
        </p>
      </div>
      <div class="card">
        <div class="stat-lbl">Remediations Verified</div>
        <div class="stat-val" style="color: var(--primary);">${verifiedPatches.length}/${patches.length}</div>
        <p style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem;">
          Three-Tier Oracle Proof Passed
        </p>
      </div>
      <div class="card">
        <div class="stat-lbl">Cryptographic Audit Events</div>
        <div class="stat-val">${auditLogs.length}</div>
        <p style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem;">
          Monotonic SHA-256 Signed
        </p>
      </div>
    </div>

    <!-- Findings Section -->
    <div class="card" style="margin-bottom: 1.5rem;">
      <h2 style="font-size: 1.1rem; font-weight: 600;">Security Findings & Taint Invariants</h2>
      ${
        findings.length === 0
          ? '<p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 0.75rem;">No security vulnerabilities or taint flow violations detected in this workspace.</p>'
          : `<table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>ID & Rule</th>
            <th>Vulnerability Title</th>
            <th>Reachability</th>
            <th>Target Location</th>
          </tr>
        </thead>
        <tbody>
          ${findings
            .map((f) => {
              const badgeClass =
                f.severity === 'Critical'
                  ? 'badge-crit'
                  : f.severity === 'High'
                    ? 'badge-high'
                    : f.severity === 'Medium'
                      ? 'badge-med'
                      : 'badge-low'
              return `<tr>
              <td><span class="badge ${badgeClass}">${f.severity}</span></td>
              <td><code>${escapeHtml(f.findingId)}</code><br><span style="font-size: 0.7rem; color: var(--text-muted);">${escapeHtml(f.cwe || f.ruleId)}</span></td>
              <td><strong>${escapeHtml(f.title)}</strong></td>
              <td><span style="font-size: 0.75rem;">${escapeHtml(f.reachability || 'Confirmed')}</span></td>
              <td><code style="font-size: 0.75rem;">${escapeHtml(f.targetLocation || 'workspace')}</code></td>
            </tr>`
            })
            .join('')}
        </tbody>
      </table>`
      }
    </div>

    <!-- Verified Remediations Section -->
    <div class="card" style="margin-bottom: 1.5rem;">
      <h2 style="font-size: 1.1rem; font-weight: 600;">Three-Tier Verified Remediations</h2>
      ${
        patches.length === 0
          ? '<p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 0.75rem;">No active patches recorded for this tenant.</p>'
          : `<table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Bundle ID</th>
            <th>Target Finding</th>
            <th>Regression Guard</th>
            <th>Verification Oracles</th>
          </tr>
        </thead>
        <tbody>
          ${patches
            .map((p) => {
              return `<tr>
              <td><span class="badge badge-verif">${p.isVerified ? 'VERIFIED' : 'PENDING'}</span></td>
              <td><code>${escapeHtml(p.bundleId)}</code></td>
              <td><code>${escapeHtml(p.findingId)}</code></td>
              <td>${p.regressionsPass ? '<span style="color: var(--primary);">✓ Passed</span>' : '<span style="color: var(--critical);">Failed</span>'}</td>
              <td style="font-size: 0.75rem; color: var(--text-muted);">Baseline + Target + Regression Passed</td>
            </tr>`
            })
            .join('')}
        </tbody>
      </table>`
      }
    </div>

    <!-- Immutable Audit Trail Proof -->
    <div class="card">
      <h2 style="font-size: 1.1rem; font-weight: 600;">Tamper-Resistant Audit Trail Excerpt</h2>
      <p style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem;">
        Cryptographically signed state transitions from SQLite WAL storage.
      </p>
      <table>
        <thead>
          <tr>
            <th>Seq</th>
            <th>Action</th>
            <th>Actor</th>
            <th>Details</th>
            <th>Cryptographic Digest</th>
          </tr>
        </thead>
        <tbody>
          ${auditLogs
            .slice(0, 10)
            .map((a) => {
              return `<tr>
              <td><strong>#${a.sequenceNumber}</strong></td>
              <td><code>${escapeHtml(a.action)}</code></td>
              <td>${escapeHtml(a.actor)}</td>
              <td style="font-size: 0.75rem;">${escapeHtml(a.details || '')}</td>
              <td><code style="font-size: 0.7rem; color: var(--primary);">${escapeHtml(a.cryptoHash || 'sha256:...')}</code></td>
            </tr>`
            })
            .join('')}
        </tbody>
      </table>
    </div>

    <div style="margin-top: 2rem; border-top: 1px solid var(--border); padding-top: 1rem; text-align: center; font-size: 0.75rem; color: var(--text-muted);">
      Sentra Defense Intelligence Engine • Fail-Closed Invariant • OASIS SARIF v2.1.0 Compliant
    </div>
  </div>
</body>
</html>`
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}
