# Phase 6 — Increment 7.0: Dashboard Core Services API, Multi-Tenant Session Isolation & Role-Based Access Controls (RBAC)

**Status:** Implementation Complete  
**Date:** 2026-11-08  
**Author:** Sentra Core Engineering Team  
**Scope:** Core Engine Platform Layer (`crates/sentra-core`), Access Controls, Multi-Tenant Boundary  
**Requirement References:** `F-19`, `ADR-0001`, `ADR-0003`, `ADR-0005`, `ROADMAP.md § Phase 6 Acceptance Criteria`  

---

## 1. Executive Summary

Phase 6 Increment 7.0 establishes the enterprise platform services foundation for Sentra, delivering the dashboard application services layer, multi-tenant session isolation boundary, and granular role-based access control (RBAC) engine.

In accordance with Phase 6 acceptance criteria (*"dashboard parity with core use cases; tested access controls; measured tenant/worker separation before any multi-tenant claim"*), this implementation introduces:

1. **Dashboard Core Use Case Parity (`F-19`):** Strongly-typed view models and query services providing complete parity for core developer and security workflows:
   - High-level posture and budget overview (`DashboardOverview`).
   - Session lifecycle state tracking and fencing generation introspection (`SessionSummaryView`).
   - Normalized findings explorer with reachability and confidence lattices (`FindingView`).
   - Patch candidate verification bundles with three-tier invariant checks (`PatchBundleView`).
   - Research campaign exploration and monetary budget ledgers (`CampaignLedgerView`).
   - Tamper-resistant timeline history (`AuditLogView`).
2. **Multi-Tenant Session & Data Isolation Boundary:**
   - Strongly-typed, validated `TenantId` (1–64 ASCII alphanumeric, hyphens, underscores).
   - Deterministic test fixture constructors (`TenantId::deterministic`).
   - `IsolationLevel` modes (`SingleOperator` vs `MultiTenantIsolated`).
   - `TenantContext` enforcing fail-closed cross-tenant fencing (`assert_tenant_isolation`) with `DashboardErrorKind::CrossTenantAccessDenied`. Cross-tenant reads and mutations are rejected at the core domain boundary without data leakage.
3. **Role-Based Access Control (RBAC):**
   - Three canonical enterprise roles: `Viewer` (read-only observer), `Operator` (active engineer/reviewer), and `SecurityAdmin` (security lead/administrator).
   - Explicit permission matrix mapping roles to `DashboardAction` operations (`ViewOverview`, `ViewSessions`, `ViewFindings`, `ViewPatchBundles`, `ViewAuditTrail`, `TriggerScan`, `ProposePatch`, `GrantApproval`, `ConfigurePolicy`).
   - Default-deny authorization engine (`enforce_rbac`) failing closed with `DashboardErrorKind::UnauthorizedRole` on any unauthorized attempt.
4. **Tamper-Resistant Audit Trail Timelines:**
   - Every dashboard state mutation, scan trigger, patch proposal, policy update, or approval grant automatically appends an immutable, monotonically sequenced audit log (`AuditLogView`).
   - Per-tenant audit trail timeline fencing ensures actors only inspect their own organizational history.
5. **Fail-Closed Execution Invariant:**
   - Target execution remains strictly disabled and fail-closed (`FailClosedBackend`). All analysis, diffs, and aggregations run purely in safe Rust under `#![forbid(unsafe_code)]`.

---

## 2. Architectural Design

```
+-----------------------------------------------------------------------------------+
|                           Enterprise Dashboard API                               |
|       (CLI / REST / MCP Frontends via Shared Application Services - ADR-0003)     |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
|                        TenantContext & Isolation Boundary                         |
|   - TenantId: validated alphanumeric slug / UUID (max 64 chars)                   |
|   - IsolationLevel: SingleOperator | MultiTenantIsolated                          |
|   - assert_tenant_isolation(context, target_tenant) -> CrossTenantAccessDenied    |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
|                         Role-Based Access Control (RBAC)                          |
|   - UserRole: Viewer | Operator | SecurityAdmin                                   |
|   - DashboardAction: 9 granular permissions                                       |
|   - enforce_rbac(role, action) -> UnauthorizedRole                                |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
|                                 DashboardService                                  |
|   - get_overview(&ctx, role) -> DashboardOverview                                 |
|   - list_sessions(&ctx, role) -> Vec<SessionSummaryView>                          |
|   - list_findings(&ctx, role, filter) -> Vec<FindingView>                         |
|   - get_patch_bundle(&ctx, role, id) -> PatchBundleView                           |
|   - trigger_scan(&mut ctx, role, target) -> session_id                            |
|   - propose_patch(&mut ctx, role, finding_id, diff) -> bundle_id                  |
|   - grant_approval(&mut ctx, role, ticket, justification) -> ()                   |
|   - configure_policy(&mut ctx, role, key, val) -> ()                              |
|   - get_audit_trail(&ctx, role) -> Vec<AuditLogView>                              |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
|                        Tamper-Resistant Audit Trail Log                           |
|   - Monotonic sequence numbers per tenant (1, 2, 3...)                            |
|   - Actor identity bound to context user_id                                       |
|   - RFC 3339 immutable UTC timestamp                                             |
+-----------------------------------------------------------------------------------+
```

---

## 3. Module Breakdown

### 3.1 `crates/sentra-core/src/dashboard/error.rs`
- Defines `DashboardErrorKind`:
  - `UnauthorizedRole`: Caller lacks required role for the requested action.
  - `CrossTenantAccessDenied`: Caller tenant context does not match target resource.
  - `TenantNotFound`: Tenant identifier was not found.
  - `SessionNotFound`: Session identifier was not found.
  - `PolicyDenied`: Denied by platform policy engine.
  - `InvalidQuery`: Malformed query parameters, empty diffs, or invalid identifier formatting.
- Implements `DashboardError` with constructors and `std::error::Error`.

### 3.2 `crates/sentra-core/src/dashboard/tenant.rs`
- Implements `TenantId`:
  - Validates character set (`[a-zA-Z0-9_-]`) and length (`1..=64`).
  - Rejects empty, whitespace, and path traversal strings (`acme/corp`, `../escape`).
  - Provides deterministic fixture constructor `TenantId::deterministic(index: u64)`.
- Implements `IsolationLevel`:
  - `SingleOperator`: Permissive cross-tenant boundary for local single-developer workflows.
  - `MultiTenantIsolated`: Strictly enforced fencing.
- Implements `TenantContext`:
  - Carries `tenant_id`, `user_id`, and `isolation_level`.
  - Implements `assert_tenant_isolation(&self, target_tenant: &TenantId)` which fails closed with `CrossTenantAccessDenied` when tenant IDs do not match in `MultiTenantIsolated` mode.

### 3.3 `crates/sentra-core/src/dashboard/rbac.rs`
- Implements `UserRole`:
  - `Viewer`: Read-only. Allowed actions: `ViewOverview`, `ViewSessions`, `ViewFindings`, `ViewPatchBundles`, `ViewAuditTrail`.
  - `Operator`: Active reviewer. Allowed actions: all Viewer actions + `TriggerScan`, `ProposePatch`.
  - `SecurityAdmin`: Enterprise administrator. Allowed all 9 actions, including `GrantApproval` and `ConfigurePolicy`.
- Implements `enforce_rbac(role: UserRole, action: DashboardAction) -> Result<(), DashboardError>`.

### 3.4 `crates/sentra-core/src/dashboard/view.rs`
- Implements core view DTOs with full `serde::{Serialize, Deserialize}` support:
  - `DashboardOverview`: Tenant ID, workspace name, total sessions, active sessions, finding breakdown by severity, verified patch count, total spend, audit event count, and latest activity timestamp.
  - `SessionSummaryView`: Session ID, tenant ID, workspace root, lifecycle state, fencing epoch, task count, created/updated timestamps.
  - `FindingView`: Finding ID, tenant ID, title, severity, confidence, reachability, status, target location, created timestamp.
  - `PatchBundleView`: Bundle ID, tenant ID, finding ID, original/patched test statuses, regression pass boolean, verification status, attempt count.
  - `CampaignLedgerView`: Campaign ID, tenant ID, title, max budget, spent budget, status, task count.
  - `AuditLogView`: Event ID, tenant ID, monotonic sequence number, actor, action, details, timestamp.

### 3.5 `crates/sentra-core/src/dashboard/service.rs`
- Implements `DashboardService` as the coordinating application layer.
- All mutations enforce RBAC, verify tenant isolation, and record an immutable audit entry with monotonic sequence numbering.

---

## 4. Verification Suite

The integration test suite in `crates/sentra-core/tests/dashboard_tests.rs` covers 6 comprehensive test scenarios:

1. `test_tenant_id_validation_and_fencing`:
   - Validates alphanumeric slugs, hyphens, underscores, deterministic fixture generation.
   - Tests fail-closed rejection of empty strings, excess lengths (>64 chars), path traversal characters, and whitespace.
   - Validates `assert_tenant_isolation` in `SingleOperator` vs `MultiTenantIsolated` modes.
2. `test_rbac_permission_matrix`:
   - Exhaustively iterates over all 9 `DashboardAction` variants for `Viewer`, `Operator`, and `SecurityAdmin`.
   - Confirms default-deny `UnauthorizedRole` on every unauthorized action.
3. `test_dashboard_overview_parity_and_aggregations`:
   - Sets up multi-tenant workspace with sessions (active/completed), findings across all 5 severities, verified/unverified patches, and budget ledgers.
   - Validates that `get_overview` computes exact aggregated statistics and tracks latest activity.
4. `test_multi_tenant_isolation_boundary`:
   - Sets up Tenant A and Tenant B.
   - Confirms Tenant A never sees Tenant B sessions or findings.
   - Confirms Tenant A attempting to access Tenant B patch bundle fails with `CrossTenantAccessDenied`.
   - Confirms Tenant A attempting to write a finding under Tenant B fails closed.
5. `test_dashboard_mutations_and_rbac_enforcement`:
   - Tests scan triggering, patch proposal, human approval granting, and policy configuration.
   - Confirms `Viewer` cannot trigger scan or propose patch.
   - Confirms `Operator` cannot grant approval or configure policy.
   - Confirms `SecurityAdmin` can execute all sensitive mutations.
6. `test_tamper_resistant_audit_trail_parity`:
   - Tests that mutations append monotonically sequenced records (`1, 2, 3, 4`).
   - Verifies actors, timestamps, action labels, and tenant scoping.

---

## 5. Security & Isolation Matrix

| Capability / Boundary | Enforcement Mechanism | Security Guarantee |
|---|---|---|
| Tenant Isolation | `TenantContext::assert_tenant_isolation` | Zero cross-tenant data leakage; fails closed with `CrossTenantAccessDenied` |
| Role-Based Access Control | `enforce_rbac` | Default-deny; viewers cannot mutate, operators cannot approve |
| Human Approval Boundary | `DashboardAction::GrantApproval` restricted to `SecurityAdmin` | Autonomous or unauthorized agents cannot self-grant approval |
| Audit Trail Tamper Resistance | `AuditLogView` append-only with monotonic sequence numbering | Comprehensive non-repudiation and forensic auditability |
| Target Code Execution | `FailClosedBackend` | Untrusted target code execution remains 100% disabled |
