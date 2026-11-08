# Phase 6 — Increment 7.1: Supported-Target Adapter Matrix, Remote-Worker Fleet Management & Multi-User Hosting Security Audit

**Status:** Implementation Complete  
**Date:** 2026-11-08  
**Author:** Sentra Core Engineering Team  
**Scope:** Core Engine Fleet Management (`crates/sentra-core/src/fleet`), Target Matrix, Enterprise Audit  
**Requirement References:** `F-19`, `ADR-0004`, `EXTENSIONS.md § Adapter families`, `ROADMAP.md § Phase 6 Acceptance Criteria`  

---

## 1. Executive Summary

Phase 6 Increment 7.1 completes the platform extensibility, remote worker fleet containment, and multi-user hosting readiness requirements of the Sentra platform roadmap.

In accordance with Phase 6 acceptance criteria (*"per-adapter supported-target matrix; independent security assessment before multi-user hosting; measured tenant/worker separation before any multi-tenant claim"*), this implementation delivers:

1. **Per-Adapter Supported-Target Matrix (`EXTENSIONS.md § Adapter families`):**
   - Implements the canonical 7-tuple target specification:
     $$\langle \text{host}, \text{worker\_arch}, \text{target\_language}, \text{framework\_version\_range}, \text{tool\_version}, \text{action}, \text{evidence\_method} \rangle$$
   - **Wildcard Prohibition:** In strict compliance with the platform roadmap, any wildcard character (`*`, `%`, `all`, `any`) in target capability declarations fails closed with `FleetErrorKind::WildcardProhibited`.
   - **Discovery vs. Dynamic Separation:** Enforces that `DiscoveryOnly` actions cannot claim dynamic execution evidence methods (`AsanCrashArtifact`, `DualStateTestDiff`).
   - **Reference Platform Matrix:** Registers Sentra's verified built-in adapters (Rust Advisory Lockfile Auditor, Rust Diff Analyzer, Linux C/C++ Fuzzing Engine, Disposable Patch Verifier, and Ghidra Binary Analysis Candidate).
2. **Remote-Worker Fleet Management & Measured Separation (`ADR-0004`):**
   - Implements `WorkerFleetManager` and `RemoteWorkerNode` managing disposable remote worker execution nodes.
   - Enforces exclusive single-tenant worker leasing: a worker leased to Tenant A cannot be leased, observed, or commanded by Tenant B (`FleetErrorKind::CrossTenantWorkerAccessDenied`).
   - **Mandatory Quarantine-and-Reset Lifecycle:** Releasing a worker immediately transitions its state to `Quarantined`. Workers cannot be re-leased until an explicit `sanitize_and_reset_worker` boundary purge wipes memory and ephemeral disks.
   - **Keepalive Heartbeat Monitoring:** Tracks worker health timestamps and reaps stale/unresponsive nodes into `Quarantined` (`reap_stale_heartbeats`) to prevent split-brain execution.
3. **Multi-User Hosting Security Assessment (`MultiUserSecurityAudit`):**
   - Automates the 5 mandatory enterprise hosting security gates:
     1. *Tenant Isolation Gate:* Validates fail-closed cross-tenant fencing (`CrossTenantAccessDenied`).
     2. *Worker Egress Containment Gate:* Enforces `EgressPolicy::StrictlyDenied` across all fleet nodes.
     3. *Zero Cross-Tenant Worker Reuse Gate:* Validates quarantine containment before sanitization.
     4. *Zero Secret Inheritance Gate:* Asserts disposable VM containment with zero host credential leakage.
     5. *Immutable Audit Trail Gate:* Verifies append-only monotonic audit timelines.
   - Generates an authoritative `MultiUserAuditReport` with `AuditStatus::Approved` or `AuditStatus::Blocked`.

---

## 2. Architecture & Data Flow

```
+-----------------------------------------------------------------------------------+
|                        Supported-Target Adapter Matrix                            |
|  - SupportedTargetTuple: (Host, WorkerArch, Language, FwRange, Tool, Action, Ev) |
|  - Wildcards (*, %, all, any) STRICTLY PROHIBITED -> WildcardProhibited          |
|  - SupportMatrix::reference_platform_matrix()                                     |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
|                           WorkerFleetManager                                      |
|  - lease_worker(&ctx, arch) -> (RemoteWorkerId, LeaseId)                          |
|  - verify_worker_access(&ctx, worker_id, lease_id)                                |
|    * Cross-tenant access -> CrossTenantWorkerAccessDenied                         |
|  - release_and_quarantine_worker(&ctx, worker_id, lease_id)                       |
|    * Transition -> WorkerState::Quarantined (CANNOT be re-leased!)               |
|  - sanitize_and_reset_worker(worker_id)                                           |
|    * Memory wipe + ephemeral disk purge -> WorkerState::Ready                     |
|  - reap_stale_heartbeats(now, timeout)                                            |
+-----------------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------------+
|                      MultiUserSecurityAudit (5-Gate Assessment)                   |
|  1. Tenant Isolation Gate                                                         |
|  2. Worker Network Egress Containment (StrictlyDenied)                            |
|  3. Zero Cross-Tenant Worker Reuse (Quarantine before reset)                      |
|  4. Zero Secret Inheritance (Disposable VM containment)                           |
|  5. Immutable Audit Trail Compliance                                              |
|  => MultiUserAuditReport { overall_status: Approved | Blocked }                   |
+-----------------------------------------------------------------------------------+
```

---

## 3. Module Breakdown

### 3.1 `crates/sentra-core/src/fleet/error.rs`
- Defines `FleetErrorKind` and `FleetError`:
  - `WorkerNotFound`: Worker identifier does not exist.
  - `WorkerBusy`: All matching workers leased or capacity exhausted.
  - `CrossTenantWorkerAccessDenied`: Unauthorized cross-tenant worker interaction.
  - `UnsupportedTargetTuple`: Requested target profile not backed by an adapter.
  - `WildcardProhibited`: Wildcard detected in target capability declaration.
  - `HeartbeatExpired`: Keepalive timeout exceeded.
  - `WorkerQuarantined`: Worker is quarantined pending sanitary reset.
  - `SecurityAuditFailed`: Hosting readiness gate blocked.
  - `InvalidInput`: Malformed identifier or configuration.

### 3.2 `crates/sentra-core/src/fleet/matrix.rs`
- Implements `HostPlatform` (`WindowsX64`, `LinuxX86_64`, `MacOsArm64`).
- Implements `TargetLanguage` (`Rust`, `CCpp`, `BinaryX86_64`, `SarifReport`, `LockfileManifest`).
- Implements `AdapterActionCapability` (`DiscoveryOnly`, `StaticAnalysis`, `ReproductionFuzzing`, `PatchVerification`).
- Implements `EvidenceMethod` (`AuditLogProof`, `StaticAstProof`, `AsanCrashArtifact`, `DualStateTestDiff`, `DisassemblyArtifact`).
- Implements `SupportedTargetTuple` with strict wildcard validation.
- Implements `SupportMatrix` registry with built-in `reference_platform_matrix()`.

### 3.3 `crates/sentra-core/src/fleet/worker.rs`
- Implements strongly-typed `RemoteWorkerId`.
- Implements `WorkerState` (`Provisioning`, `Ready`, `Leased`, `Quarantined`, `Terminated`).
- Implements `RemoteWorkerNode` with `ContainmentLevel::DisposableVm`, `WorkerResourceCaps`, and `EgressPolicy::StrictlyDenied`.

### 3.4 `crates/sentra-core/src/fleet/manager.rs`
- Implements `WorkerFleetManager`:
  - `lease_worker`: Exclusive allocation bound to `TenantId`.
  - `verify_worker_access`: Fails closed on cross-tenant mismatch.
  - `release_and_quarantine_worker`: Immediate quarantine on lease termination.
  - `sanitize_and_reset_worker`: Sanitary disposable VM reset restoring `Ready` status.
  - `reap_stale_heartbeats`: Identifies and isolates unresponsive nodes.

### 3.5 `crates/sentra-core/src/fleet/audit.rs`
- Implements `MultiUserSecurityAudit` and `MultiUserAuditReport`.
- Evaluates the 5 mandatory multi-user hosting gates before enterprise deployment.

---

## 4. Verification Evidence

The integration test suite in `crates/sentra-core/tests/fleet_tests.rs` covers 6 comprehensive scenarios:
1. `test_supported_target_matrix_wildcard_rejection`: Rejects `*`, `%`, `all`, `any`, empty strings, and discovery-only dynamic evidence.
2. `test_reference_platform_matrix_queries`: Queries reference matrix for Rust, C/C++, Ghidra binary analysis, and verifies unknown compiler rejection.
3. `test_remote_worker_registration_and_exclusive_leasing`: Validates exclusive leasing to Tenant A and fail-closed rejection of Tenant B.
4. `test_cross_tenant_worker_isolation_and_sanitization`: Proves released workers cannot be leased until `sanitize_and_reset_worker` is executed.
5. `test_worker_heartbeat_monitoring_and_stale_reaping`: Proves unresponsive workers are quarantined automatically.
6. `test_multi_user_hosting_security_audit_gates`: Validates full 5-gate pass on compliant fleet, and immediate failure on egress-violating rogue worker.
