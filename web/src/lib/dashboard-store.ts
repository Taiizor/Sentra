import type {
  AuditLogView,
  CampaignLedgerView,
  DashboardOverview,
  FindingView,
  OsvAdvisoryView,
  PatchBundleView,
  SecurityTrendPoint,
  SessionSummaryView,
  TenantId,
  UserRole,
  WorkerNodeView,
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
  workers: WorkerNodeView[]
  osvAdvisories: OsvAdvisoryView[]
  trends: SecurityTrendPoint[]
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
    cvssScore: 9.8,
    remediationGuidance:
      'Use parameterized queries or prepared statement interfaces with bound parameters instead of string formatting.',
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
    cvssScore: 9.6,
    remediationGuidance:
      'Avoid invoking shell commands with interpolated user input. Use execFile or child_process.spawn with an array of arguments.',
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
    cvssScore: 9.1,
    remediationGuidance:
      'Remove credentials from source code immediately. Rotate the exposed key in AWS IAM and load secrets via IAM instance roles or secrets manager.',
    description:
      'High-entropy credential matching standard AWS Access Key ID format (AKIA...) embedded in plaintext configuration.',
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
    cvssScore: 7.5,
    remediationGuidance:
      'Verify that resolved file paths start with the expected directory boundary using path.resolve and startsWith check before opening.',
    description:
      'User-controlled route parameter passed to fs.readFile without path.resolve containment check or base directory boundary validation.',
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
    cvssScore: 5.3,
    remediationGuidance:
      'Document memory invariants with a // SAFETY: comment explaining why pointer alignments, lifetimes, and bounds are guaranteed sound.',
    description:
      'An unsafe block was declared without preceding // SAFETY: comment explaining the invariants that make this pointer dereference sound.',
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
    cvssScore: 7.4,
    remediationGuidance:
      'Upgrade lodash to version 4.17.21 or later across all lockfiles.',
    description:
      'Versions of lodash prior to 4.17.21 are vulnerable to Prototype Pollution via zipObjectDeep and merge functions.',
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
    originalSnippet: `let query = format!("SELECT * FROM products WHERE desc LIKE '%{}%'", intermediate);
db.execute(&query);`,
    patchedSnippet: `let query = "SELECT * FROM products WHERE desc LIKE ?";
db.execute_with_params(query, &[&intermediate]);`,
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
    originalSnippet: `"lodash": "4.17.20"`,
    patchedSnippet: `"lodash": "4.17.21"`,
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
    title: 'Memory Safety & Use-After-Free Exploration (CWE-416)',
    targetArchitecture: 'Linux x86_64 ELF',
    fuzzEngine: 'libFuzzer + ASan',
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
    title: 'OSS-CRS Linux User-Space Crash Delta Minimization',
    targetArchitecture: 'Linux x86_64 ELF',
    fuzzEngine: 'AddressSanitizer + UBSan',
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
    cryptoHash: 'sha256:7f83b165...e92a',
    timestamp: '2026-11-09T01:00:00Z',
  },
  {
    eventId: 'evt-002',
    tenantId: 'sentra-internal',
    sequenceNumber: 2,
    actor: 'system-scanner',
    action: 'sast_scan_completed',
    details: 'Pure-Rust scan completed across 36 files. 42 signals evaluated, 6 canonical findings admitted.',
    cryptoHash: 'sha256:4c2199b0...128f',
    timestamp: '2026-11-09T02:10:15Z',
  },
  {
    eventId: 'evt-003',
    tenantId: 'sentra-internal',
    sequenceNumber: 3,
    actor: 'taint-engine',
    action: 'taint_flow_detected',
    details: 'SENTRA-TAINT-001 identified multi-hop SQL injection from req.body to db.execute',
    cryptoHash: 'sha256:a13cd882...661c',
    timestamp: '2026-11-09T03:15:02Z',
  },
  {
    eventId: 'evt-004',
    tenantId: 'sentra-internal',
    sequenceNumber: 4,
    actor: 'verifier-oracle',
    action: 'patch_verified',
    details: 'Three-tier verification invariant satisfied for bundle-001-sql-fix (Baseline: Failed, Patched: Passed, Regressions: Passed)',
    cryptoHash: 'sha256:f09231ca...34ab',
    timestamp: '2026-11-09T03:30:15Z',
  },
  {
    eventId: 'evt-005',
    tenantId: 'sentra-internal',
    sequenceNumber: 5,
    actor: 'human-admission',
    action: 'draft_pr_authorized',
    details: 'Operator authorized creation of draft PR sentra/patch/cwe-89-sql-injection-fnd-8910',
    cryptoHash: 'sha256:55ef8821...99bc',
    timestamp: '2026-11-09T03:40:00Z',
  },
]

export const INITIAL_WORKERS: WorkerNodeView[] = [
  {
    workerId: 'worker-node-hyperv-01',
    hostname: 'hyperv-runner-az1',
    architecture: 'x86_64-linux',
    state: 'LEASED',
    tenantLease: 'sentra-internal',
    cpuUsagePercent: 34,
    memoryUsageMb: 820,
    egressPolicy: 'StrictlyDenied',
    activeJob: 'cmp-research-cwe-416 (ASan Fuzzing)',
  },
  {
    workerId: 'worker-node-docker-02',
    hostname: 'docker-isolated-worker-02',
    architecture: 'x86_64-linux',
    state: 'AVAILABLE',
    tenantLease: null,
    cpuUsagePercent: 3,
    memoryUsageMb: 140,
    egressPolicy: 'StrictlyDenied',
    activeJob: null,
  },
  {
    workerId: 'worker-node-quarantine-03',
    hostname: 'hyperv-runner-az3',
    architecture: 'x86_64-linux',
    state: 'QUARANTINED',
    tenantLease: 'tenant-alpha',
    cpuUsagePercent: 0,
    memoryUsageMb: 64,
    egressPolicy: 'StrictlyDenied',
    activeJob: 'Pending sanitization and reset',
  },
]

export const INITIAL_OSV_ADVISORIES: OsvAdvisoryView[] = [
  {
    id: 'GHSA-p6mc-m468-83gw',
    package: 'lodash',
    ecosystem: 'npm',
    vulnerability: 'Prototype Pollution in lodash',
    affectedRange: '< 4.17.21',
    fixedVersion: '4.17.21',
    severity: 'High',
    publishedAt: '2021-05-18T18:00:00Z',
  },
  {
    id: 'RUSTSEC-2021-0145',
    package: 'atty',
    ecosystem: 'crates.io',
    vulnerability: 'Potential unaligned read in atty on Windows',
    affectedRange: '< 0.2.14',
    fixedVersion: '0.2.14',
    severity: 'Medium',
    publishedAt: '2021-12-04T12:00:00Z',
  },
  {
    id: 'GHSA-qw6h-v559-w396',
    package: 'express',
    ecosystem: 'npm',
    vulnerability: 'Path Traversal via serve-static in express',
    affectedRange: '< 4.19.2',
    fixedVersion: '4.19.2',
    severity: 'High',
    publishedAt: '2024-03-20T10:00:00Z',
  },
  {
    id: 'GHSA-wf5p-g6vw-rhxx',
    package: 'axios',
    ecosystem: 'npm',
    vulnerability: 'Server-Side Request Forgery (SSRF) bypass in axios',
    affectedRange: '< 1.7.4',
    fixedVersion: '1.7.4',
    severity: 'High',
    publishedAt: '2024-08-12T14:00:00Z',
  },
  {
    id: 'PYSEC-2023-142',
    package: 'urllib3',
    ecosystem: 'PyPI',
    vulnerability: 'Cookie leakage on cross-origin redirects',
    affectedRange: '< 2.0.7',
    fixedVersion: '2.0.7',
    severity: 'Medium',
    publishedAt: '2023-10-17T16:00:00Z',
  },
]

export const INITIAL_SECURITY_TRENDS: SecurityTrendPoint[] = [
  { date: '11/01', detected: 4, remediated: 1, activeCritical: 1 },
  { date: '11/03', detected: 7, remediated: 3, activeCritical: 2 },
  { date: '11/05', detected: 5, remediated: 4, activeCritical: 1 },
  { date: '11/07', detected: 9, remediated: 6, activeCritical: 3 },
  { date: '11/08', detected: 6, remediated: 5, activeCritical: 2 },
  { date: '11/09', detected: 6, remediated: 2, activeCritical: 3 },
]

export const INITIAL_OVERVIEW: DashboardOverview = {
  tenantId: 'sentra-internal',
  workspaceName: 'Sentra Security Core',
  securityScore: 88,
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
