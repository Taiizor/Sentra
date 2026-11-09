import type {
  AuditLogView,
  CampaignLedgerView,
  DashboardOverview,
  FindingView,
  PatchBundleView,
  SessionSummaryView,
  TenantId,
  UserRole,
} from '@/types/sentra'

export interface DashboardState {
  currentTenant: TenantId
  currentRole: UserRole
  overview: DashboardOverview
  sessions: SessionSummaryView[]
  findings: FindingView[]
  patches: PatchBundleView[]
  campaigns: CampaignLedgerView[]
  auditLogs: AuditLogView[]
}

export const INITIAL_FINDINGS: FindingView[] = [
  {
    findingId: 'fnd-8910-sql-injection',
    tenantId: 'sentra-internal',
    ruleId: 'SENTRA-TAINT-001',
    cwe: 'CWE-89',
    title: 'SQL Injection via Multi-Hop Untrusted Taint Flow',
    severity: 'Critical',
    confidence: 'High',
    reachability: 'ReachableCallPath',
    status: 'Candidate',
    targetLocation: 'src/api/search.rs',
    startLine: 12,
    endLine: 18,
    description:
      'Untrusted data originating from HTTP request body flows through intermediate variables without sanitization into a raw SQL query execution sink.',
    taintTrace: [
      {
        step: 1,
        role: 'SOURCE',
        location: 'src/api/search.rs',
        line: 12,
        variable: 'req.body.search_term',
        codeSnippet: 'let user_input = req.body.search_term;',
      },
      {
        step: 2,
        role: 'PROPAGATION',
        location: 'src/api/search.rs',
        line: 14,
        variable: 'intermediate',
        codeSnippet: 'let intermediate = format!("term_{}", user_input);',
      },
      {
        step: 3,
        role: 'PROPAGATION',
        location: 'src/api/search.rs',
        line: 16,
        variable: 'query',
        codeSnippet: 'let query = format!("SELECT * FROM products WHERE desc LIKE \'%{}%\'", intermediate);',
      },
      {
        step: 4,
        role: 'SINK',
        location: 'src/api/search.rs',
        line: 18,
        variable: 'db.execute(&query)',
        codeSnippet: 'db.execute(&query);',
      },
    ],
    createdAt: '2026-11-09T03:15:00Z',
  },
  {
    findingId: 'fnd-7801-command-injection',
    tenantId: 'sentra-internal',
    ruleId: 'SENTRA-TAINT-002',
    cwe: 'CWE-78',
    title: 'Command Injection via CLI Arguments in Shell Wrapper',
    severity: 'Critical',
    confidence: 'High',
    reachability: 'ReachableCallPath',
    status: 'Candidate',
    targetLocation: 'services/worker.ts',
    startLine: 45,
    endLine: 48,
    description:
      'Command-line argument is concatenated directly into a child_process.exec call without shell escaping or command allowlisting.',
    taintTrace: [
      {
        step: 1,
        role: 'SOURCE',
        location: 'services/worker.ts',
        line: 45,
        variable: 'process.argv[2]',
        codeSnippet: 'const target = process.argv[2];',
      },
      {
        step: 2,
        role: 'PROPAGATION',
        location: 'services/worker.ts',
        line: 46,
        variable: 'cmd',
        codeSnippet: 'const cmd = `ping -c 1 ${target}`;',
      },
      {
        step: 3,
        role: 'SINK',
        location: 'services/worker.ts',
        line: 48,
        variable: 'exec(cmd)',
        codeSnippet: 'child_process.exec(cmd, callback);',
      },
    ],
    createdAt: '2026-11-09T03:18:22Z',
  },
  {
    findingId: 'fnd-001-aws-key',
    tenantId: 'sentra-internal',
    ruleId: 'SENTRA-SEC-001',
    cwe: 'CWE-798',
    title: 'Hardcoded AWS Access Key ID Detected',
    severity: 'Critical',
    confidence: 'High',
    reachability: 'SinkOnly',
    status: 'Validated',
    targetLocation: 'config/cloud_credentials.json',
    startLine: 4,
    endLine: 4,
    description: 'High-entropy credential matching standard AWS Access Key ID format (AKIA...) embedded in plaintext configuration.',
    createdAt: '2026-11-09T02:40:11Z',
  },
  {
    findingId: 'fnd-022-path-traversal',
    tenantId: 'sentra-internal',
    ruleId: 'SENTRA-TAINT-004',
    cwe: 'CWE-22',
    title: 'Path Traversal via Route Parameter',
    severity: 'High',
    confidence: 'High',
    reachability: 'ReachableCallPath',
    status: 'Candidate',
    targetLocation: 'src/routes/download.ts',
    startLine: 28,
    endLine: 31,
    description: 'User-controlled route parameter passed to fs.readFile without path.resolve containment check or base directory boundary validation.',
    taintTrace: [
      {
        step: 1,
        role: 'SOURCE',
        location: 'src/routes/download.ts',
        line: 28,
        variable: 'req.params.filepath',
        codeSnippet: 'const file = req.params.filepath;',
      },
      {
        step: 2,
        role: 'PROPAGATION',
        location: 'src/routes/download.ts',
        line: 29,
        variable: 'resolved',
        codeSnippet: 'const resolved = path.join("/var/data", file);',
      },
      {
        step: 3,
        role: 'SINK',
        location: 'src/routes/download.ts',
        line: 31,
        variable: 'fs.readFile',
        codeSnippet: 'fs.readFile(resolved, "utf8");',
      },
    ],
    createdAt: '2026-11-09T03:22:04Z',
  },
  {
    findingId: 'fnd-119-naked-unsafe',
    tenantId: 'sentra-internal',
    ruleId: 'SENTRA-SAST-004',
    cwe: 'CWE-119',
    title: 'Naked Rust Unsafe Block Without SAFETY Rationale',
    severity: 'Medium',
    confidence: 'High',
    reachability: 'SinkOnly',
    status: 'Validated',
    targetLocation: 'crates/sentra-core/src/ffi.rs',
    startLine: 88,
    endLine: 92,
    description: 'An unsafe block was declared without preceding // SAFETY: comment explaining the invariants that make this pointer dereference sound.',
    createdAt: '2026-11-09T01:55:40Z',
  },
  {
    findingId: 'fnd-dep-lodash-proto',
    tenantId: 'sentra-internal',
    ruleId: 'GHSA-p6mc-m468-83gw',
    cwe: 'CWE-1321',
    title: 'Prototype Pollution in lodash (bun.lock / package-lock.json)',
    severity: 'High',
    confidence: 'High',
    reachability: 'ReachableCallPath',
    status: 'Candidate',
    targetLocation: 'package.json (lodash 4.17.20)',
    startLine: 24,
    endLine: 24,
    description: 'Versions of lodash prior to 4.17.21 are vulnerable to Prototype Pollution via zipObjectDeep and merge functions.',
    createdAt: '2026-11-09T02:10:00Z',
  },
]

export const INITIAL_PATCHES: PatchBundleView[] = [
  {
    bundleId: 'bundle-001-sql-fix',
    tenantId: 'sentra-internal',
    findingId: 'fnd-8910-sql-injection',
    title: 'Parametrized Query Binding for Search API (SENTRA-TAINT-001)',
    originalTestStatus: 'Failed',
    patchedTestStatus: 'Passed',
    regressionsPass: true,
    isVerified: true,
    attemptCount: 1,
    branchName: 'sentra/patch/cwe-89-sql-injection-fnd-8910',
    ghPrCommand:
      'gh pr create --draft --title "[Security] Remediate SQL Injection in search.rs (CWE-89)" --body "Automated Sentra Three-Tier Verified Patch" --base main --head sentra/patch/cwe-89-sql-injection-fnd-8910',
    diff: `--- a/src/api/search.rs
+++ b/src/api/search.rs
@@ -14,5 +14,5 @@
-    let query = format!("SELECT * FROM products WHERE desc LIKE '%{}%'", intermediate);
-    db.execute(&query);
+    let query = "SELECT * FROM products WHERE desc LIKE ?";
+    db.execute_with_params(query, &[&intermediate]);`,
    createdAt: '2026-11-09T03:30:12Z',
  },
  {
    bundleId: 'bundle-002-lodash-upgrade',
    tenantId: 'sentra-internal',
    findingId: 'fnd-dep-lodash-proto',
    title: 'Dependency Upgrade: lodash 4.17.20 -> 4.17.21',
    originalTestStatus: 'Failed',
    patchedTestStatus: 'Passed',
    regressionsPass: true,
    isVerified: true,
    attemptCount: 1,
    branchName: 'sentra/patch/ghsa-p6mc-lodash-upgrade',
    ghPrCommand:
      'gh pr create --draft --title "[Security] Upgrade lodash to 4.17.21 (GHSA-p6mc-m468-83gw)" --body "Automated dependency remediation verified by Sentra" --base main --head sentra/patch/ghsa-p6mc-lodash-upgrade',
    diff: `--- a/package.json
+++ b/package.json
@@ -24,3 +24,3 @@
-    "lodash": "4.17.20"
+    "lodash": "4.17.21"`,
    createdAt: '2026-11-09T02:35:00Z',
  },
]

export const INITIAL_SESSIONS: SessionSummaryView[] = [
  {
    sessionId: 'sess-53454ff5-0001',
    tenantId: 'sentra-internal',
    workspaceRoot: 'E:/MyProject/Mix/GitHub/Sentra',
    state: 'SCOPED',
    fencingEpoch: 1,
    taskCount: 8,
    createdAt: '2026-11-09T01:00:00Z',
    updatedAt: '2026-11-09T04:15:00Z',
  },
  {
    sessionId: 'sess-53454ff5-0002',
    tenantId: 'sentra-internal',
    workspaceRoot: 'E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core',
    state: 'COMPLETED',
    fencingEpoch: 1,
    taskCount: 14,
    createdAt: '2026-11-08T22:41:48Z',
    updatedAt: '2026-11-08T23:10:00Z',
  },
]

export const INITIAL_CAMPAIGNS: CampaignLedgerView[] = [
  {
    campaignId: 'cmp-research-cwe-416',
    tenantId: 'sentra-internal',
    title: 'Deep Research: Memory Safety & Use-After-Free Exploration (CWE-416)',
    maxBudgetMicroUsd: 5000000,
    spentBudgetMicroUsd: 1240000,
    status: 'ACTIVE',
    taskCount: 6,
    coveredRegions: 42,
    skippedRegions: 3,
  },
  {
    campaignId: 'cmp-fuzz-delta-min',
    tenantId: 'sentra-internal',
    title: 'OSS-CRS Linux User-Space Crash Minimization Campaign',
    maxBudgetMicroUsd: 3000000,
    spentBudgetMicroUsd: 890000,
    status: 'CONCLUDED',
    taskCount: 9,
    coveredRegions: 28,
    skippedRegions: 0,
  },
]

export const INITIAL_AUDIT_LOGS: AuditLogView[] = [
  {
    eventId: 'evt-001',
    tenantId: 'sentra-internal',
    sequenceNumber: 1,
    actor: 'operator-alice',
    action: 'tenant_registered',
    details: "Workspace 'Sentra Production' registered with IsolationLevel::MultiTenantIsolated",
    timestamp: '2026-11-09T01:00:00Z',
  },
  {
    eventId: 'evt-002',
    tenantId: 'sentra-internal',
    sequenceNumber: 2,
    actor: 'system-scanner',
    action: 'sast_scan_completed',
    details: 'Pure-Rust scan completed across 36 files. 42 signals evaluated, 6 canonical findings admitted.',
    timestamp: '2026-11-09T02:10:15Z',
  },
  {
    eventId: 'evt-003',
    tenantId: 'sentra-internal',
    sequenceNumber: 3,
    actor: 'taint-engine',
    action: 'taint_flow_detected',
    details: 'SENTRA-TAINT-001 identified multi-hop SQL injection from req.body to db.execute',
    timestamp: '2026-11-09T03:15:02Z',
  },
  {
    eventId: 'evt-004',
    tenantId: 'sentra-internal',
    sequenceNumber: 4,
    actor: 'verifier-oracle',
    action: 'patch_verified',
    details: 'Three-tier verification invariant satisfied for bundle-001-sql-fix (Baseline: Failed, Patched: Passed, Regressions: Passed)',
    timestamp: '2026-11-09T03:30:15Z',
  },
  {
    eventId: 'evt-005',
    tenantId: 'sentra-internal',
    sequenceNumber: 5,
    actor: 'human-admission',
    action: 'draft_pr_authorized',
    details: 'Operator authorized creation of draft PR sentra/patch/cwe-89-sql-injection-fnd-8910',
    timestamp: '2026-11-09T03:40:00Z',
  },
]

export const INITIAL_OVERVIEW: DashboardOverview = {
  tenantId: 'sentra-internal',
  workspaceName: 'Sentra Security Core',
  totalSessions: 2,
  activeSessions: 1,
  criticalFindings: 3,
  highFindings: 2,
  mediumFindings: 1,
  lowFindings: 0,
  infoFindings: 0,
  verifiedPatches: 2,
  totalSpentMicroUsd: 2130000,
  auditEventCount: 5,
  lastActivityTimestamp: '2026-11-09T03:40:00Z',
}
