# Increment 5.6.2.2.2.1 — Independent Policy Generation, Preview Integrity & Validator Portability Review

Date: 2026-11-06. **Decision: Approved.** Verification-only security and reliability review. No production code, existing test files, dependency manifests, lockfile entries, or ADR statuses were modified. Phase 1 remains in progress; Phase 2 and subsequent increments have not started.

---

## 1. Executive Summary

This independent, verification-only review audits the policy generation, preview integrity, and validator portability hardening implemented in **Increment 5.6.2.2.2** ([`docs/phase1/INCREMENT_5_6_2_2_2_POLICY_AND_VALIDATOR_HARDENING.md`](file:///E:/MyProject/Mix/GitHub/Sentra/docs/phase1/INCREMENT_5_6_2_2_2_POLICY_AND_VALIDATOR_HARDENING.md)).

All three targeted findings from the previous independent review ([`docs/phase1/INCREMENT_5_6_2_2_1_INDEPENDENT_REVIEW.md`](file:///E:/MyProject/Mix/GitHub/Sentra/docs/phase1/INCREMENT_5_6_2_2_1_INDEPENDENT_REVIEW.md)) have been rigorously verified as **fully resolved**:
1. **F-562221-01 (Medium) — Policy Generation and Context Invalidation:** Engine configuration is strictly immutable (mutators removed; compile-fail doctest enforced). Effective policy identity is embedded into Version 2 session security snapshots. Owner registration via `register_session_with_policy` takes the per-session exclusive admission OS lock before SQL execution and transactionally advances the context generation. Equivalent policy registration is a safe no-op that preserves the generation and valid receipts. Stale contexts, pending requests, and issued approvals bound to older generations are rejected fail-closed with `ContextMismatch` or `PolicyMismatch`. Legacy Version 1 snapshots cannot be executed without explicit policy rebinding.
2. **F-562221-02 (Low) — Policy Preview Typed Error Integrity:** In both `preview_execution` and `CoreService::evaluate_action`, database read errors, SQLite closed states, and storage corruptions propagate as typed `ServiceErrorKind::Persistence(PersistenceError)` retaining numeric SQLite codes and rollback metadata. Genuine policy rejections remain `ServicePolicyDecision::Denied`. Infrastructure failures are never flattened or masked as ordinary denials.
3. **F-562221-03 (Low) — Authorization Validator Portability:** `experiments/phase1/authorization/Validate.ps1` dynamically resolves the effective Cargo target directory via `cargo metadata --offline --no-deps`, locates the newly built `sentra_core` rlib from `cargo build --message-format=json`, derives the dependencies directory from the artifact's location, and compiles a unique GUID probe executable per invocation. Verified across four distinct directory scenarios in `Validate-Portability.ps1`.
4. **Git Index Investigation:** The physical `.git/index` checksum change reported in Increment 5.6.2.2.2 has been investigated. Read-only inspection confirms that staged paths, modes, and blob hashes were 100% identical; the byte variance was caused by normal Git stat cache updating during read-only status calls or remote-tracking updates. Subsequently, the repository owner committed Increment 5.6.2.2.2 changes in commit `75a2ed402e997e3d71cd30cae343c5acf110b0d0`, leaving the repository in a pristine, clean working-tree state.

The entire test suite passes **263 unique test cases** (256 runtime tests + 7 compile-fail doctests, 0 failed, 5 ignored). All platform validation suites (`persistence`, `authorization`, `workspace`, and `portability`) pass cleanly with exit code 0.

---

## 2. Scope and Inspected Files

This review audited production call paths, data models, error handlers, and integration tests across the workspace:

| Subsystem / Area | File Inspected | Functions / Structs Audited |
| :--- | :--- | :--- |
| **Policy Engine** | [`crates/sentra-core/src/policy/engine.rs`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/policy/engine.rs) | `PolicyEngine::new`, `with_config`, `with_authority`, `for_service`, `policy_identity`, `valid_policy_identity`, `config`, removal of `set_max_auto_budget` |
| **Persistence Models** | [`crates/sentra-core/src/persistence/model.rs`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/persistence/model.rs) | `Snapshot` (version 1 vs 2, `policy_identity`), `Snapshot::validate`, `ApprovalIntent`, `MetadataDto` |
| **Persistence Repository** | [`crates/sentra-core/src/persistence/repository.rs`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/persistence/repository.rs) | `current`, `execution_context`, `preview_execution`, `register_session`, `register_session_with_policy`, `register_session_bound`, `session_admission` |
| **Service Coordination** | [`crates/sentra-core/src/service/core.rs`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/service/core.rs) | `CoreService::new`, `evaluate_action`, `execute_task` |
| **Service Error Model** | [`crates/sentra-core/src/service/error.rs`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/service/error.rs) | `ServiceError`, `ServiceErrorKind::Persistence`, `ServicePrimaryError::Persistence` |
| **Hardening Test Suite** | [`crates/sentra-core/tests/authorization_isolation_review_tests.rs`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/tests/authorization_isolation_review_tests.rs) | All 22 test functions covering policy immutability, ABA rotation, live dispatch concurrency, preview read-only guarantees, fault injection, and v1 migration |
| **Validator Scripts** | [`experiments/phase1/authorization/Validate.ps1`](file:///E:/MyProject/Mix/GitHub/Sentra/experiments/phase1/authorization/Validate.ps1), [`Validate-Portability.ps1`](file:///E:/MyProject/Mix/GitHub/Sentra/experiments/phase1/authorization/Validate-Portability.ps1) | Dynamic target directory resolution, rlib discovery, probe compilation, 180s command budget |

---

## 3. Initial and Current Git State Audit

- **Current Branch:** `develop`
- **Current HEAD Commit:** `75a2ed402e997e3d71cd30cae343c5acf110b0d0` (Author: `Taiizor`, 2026-11-06T17:10:43+03:00)
- **Commit Message:** `Harden policy binding and validator portability`
- **Upstream Relationship:** Tracking `origin/develop`, up to date (+0 / -0)
- **Working Tree:** Completely clean (0 staged, 0 modified, 0 untracked files prior to generating this review report)
- **Tracked Files:** 248 tracked files (228 baseline files + 20 files committed in `75a2ed4`)

### Historical Baseline Comparison
The implementation report recorded entry at commit `74debdd7e905992205885969a504317a648081e6` with 12 modified files and 20 untracked files unstaged in the working tree. The project owner subsequently reviewed and committed those 32 files into commit `75a2ed4`. That commit is preserved in full; no agent-issued commits, resets, rebases, or pushes were performed.

---

## 4. Git Index Anomaly Investigation

The implementation report in §8 noted an anomaly: the physical index checksum changed from `ca82253cfe310cede02d73cdc72e721784a2cd21fcc09cb420a4c544d4a760f9` at entry to `d8573735cc48f939a058866cac8bb5ba67a8301bd2bb50fb8b54c1e6cddfaba7` at completion, while index entries remained identical (`"index_entries": true`).

### Investigation Findings
1. **Physical Metadata Capture:**
   - Current `.git/index` Length: 29,189 bytes
   - Current `.git/index` SHA-256: `93A5D5649DEE4C72A61F8CB189FEE42484DDBD23F16960495778B624407BB4B9`
   - File Timestamp: 2026-11-06 14:10:43 UTC (coinciding with the owner commit `75a2ed4`)
2. **Read-Only Inspection of Staged Entries:**
   - Inspection of `experiments/phase1/core-review/results/562222-final-state.json` confirms that every tracked blob SHA-1 hash, mode, and path in the index at the conclusion of Increment 5.6.2.2.2 was identical to entry.
   - Reflog analysis records an external remote reference update (`refs/remotes/origin/HEAD@{2026-11-06T16:50:32+03:00} remote set-head`) occurring during the increment.
3. **Stat-Cache Refresh vs. Tree Mutation:**
   - In Git index binary format (version 2/3/4), each entry contains stat data (ctime, mtime, dev, ino, file size) followed by the object's SHA-1 hash.
   - When Git executes operations such as `git status` without `--no-optional-locks` or when background IDE processes probe the repository, Git refreshes the index stat cache with current filesystem timestamps, altering physical file bytes without modifying any staged blob hashes or paths.
4. **Resolution:**
   - The reported change was a harmless stat cache refresh. The subsequent owner commit `75a2ed4` formally committed the increment's changes, producing the current clean index.
   - Zero tampering, repository corruption, or unauthorized staging occurred.

---

## 5. Policy Immutability and Generation Lifecycle (F-562221-01 Verification)

### 5.1 Policy Object Immutability
- The public `PolicyEngine::set_max_auto_budget` mutator has been eliminated.
- The `config` field on `PolicyEngine` is private; `config(&self)` returns a shared reference `&BudgetPolicyConfig`.
- Compile-fail doctest at [`crates/sentra-core/src/policy/engine.rs#L17-L21`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/policy/engine.rs#L17-L21) verifies that caller attempts to mutate engine configuration fail to compile:
  ```rust
  /// ```compile_fail
  /// use sentra_core::{PolicyEngine, CostUsd};
  /// let mut engine = PolicyEngine::new();
  /// engine.set_max_auto_budget(CostUsd::ZERO);
  /// ```
  ```
- Cloned configuration modification has no effect on registered policy (`test: immutable_policy_clone_and_different_engine_cannot_override_registered_rules`).

### 5.2 Canonical Policy Identity
- Generated via `PolicyEngine::policy_identity()`: `"sentra-policy:v1:auto-microusd=<canonical u64>"`.
- Validated via `PolicyEngine::valid_policy_identity(value: &str)`.
- Embedded into Version 2 session security snapshots (`Snapshot.policy_identity`).

### 5.3 Authorized Policy Activation & Generation Advancement
- In [`crates/sentra-core/src/persistence/repository.rs`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/persistence/repository.rs#L745-L818), `register_session_with_policy` enforces:
  1. **OS Admission Lock:** Takes the exclusive per-session file lock (`session_admission(session_id, true)`) before executing SQL work.
  2. **Equivalent Policy Registration No-Op:** If effective `policy_identity`, metadata, revision, classification floor, and budget limit are identical to the active snapshot, it returns the current `SessionRecord` without advancing `context_generation` or writing redundant audit records (`test: unchanged_effective_policy_is_a_non_mutating_registration_and_keeps_valid_grant`).
  3. **Effective Policy Change Advances Generation:** Any semantically different policy increments `context_generation` atomically and writes a new Version 2 snapshot.
  4. **Audit Rollback Safety:** If the audit event insertion fails (e.g. duplicate event ID), the entire transaction rolls back; the generation is not advanced and valid receipts remain intact (`test: failed_policy_registration_audit_rolls_back_epoch_and_preserves_legitimate_grant`).

### 5.4 Context and Approval Invalidation
- **Minting Gate:** `execution_context` checks `snapshot.policy_identity.as_deref() == Some(policy.policy_identity().as_str())`. A mismatched policy rejects minting with `PolicyMismatch`.
- **Preparation & Execution Gate:** `current()` and `binding_matches()` verify that the caller's intent and approval grant match the active `snapshot.generation` and `snapshot.policy_identity`.
- **ABA Invalidation:** A $\rightarrow$ B $\rightarrow$ A policy changes increment generation twice; old contexts and grants cannot be reused even when returning to the original policy rules (`test: policy_aba_never_restores_old_context_or_approval`).
- **Live Dispatch Exclusion:** A live dispatch holds the shared OS admission lock. A concurrent `register_session_with_policy` call fails immediately with `ContextBusy`. Policy cannot be updated mid-dispatch (`test: policy_update_cannot_race_live_service_dispatch_and_old_service_cannot_dispatch_afterward`).
- **Persistence Across Restart:** Reconstructing `SqliteConnectionManager` verifies that policy identity, context generation, and invalidation survive manager restarts (`test: policy_binding_is_persistent_across_separate_manager_reconstruction`).

---

## 6. Version 1 Snapshot Compatibility

The migration and backward-compatibility invariants for Version 1 snapshots were verified:
1. **Detection:** A snapshot with `version == 1` and `policy_identity == None` is recognized as a valid historical record during read-only inspection.
2. **Fail-Closed Execution:** Lines 100-102 of [`crates/sentra-core/src/persistence/repository.rs`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/persistence/repository.rs#L100-L102) strictly enforce:
   ```rust
   if snapshot.policy_identity.is_none() {
       return Err(error(Kind::PolicyMismatch));
   }
   ```
   Unbound Version 1 snapshots cannot be used for execution minting, grant issuance, or preparation.
3. **Legacy Re-registration Rejection:** Calling legacy `register_session` on an existing Version 1 record fails with `PolicyMismatch` (lines 787-790). The system refuses to guess a default policy.
4. **Explicit Rebinding:** Rebinding requires calling `register_session_with_policy`. It updates the record to Version 2, advances `context_generation`, and invalidates prior approvals while preserving historical audit records and passing `integrity_check` with 0 errors (`test: legacy_unbound_snapshot_requires_explicit_owner_policy_binding_without_data_recreation`).

---

## 7. Policy Preview — Typed Error Integrity (F-562221-02 Verification)

The preview pipeline was audited across [`crates/sentra-core/src/persistence/repository.rs`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/persistence/repository.rs#L640-L675) and [`crates/sentra-core/src/service/core.rs`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/service/core.rs#L337-L380):
1. **Read-Only Invariant:** Executing `preview_execution` repeatedly leaves every row and cell across all six SQLite tables 100% byte-identical. Zero approvals are consumed, zero budget reservations are created, and zero audit events are emitted (`test: preview_all_decisions_are_non_consuming_and_leave_every_persistent_table_unchanged`).
2. **Infrastructure Error Propagation:**
   - In `execution_context`: Errors other than `PolicyDenied` propagate as `Err(ServiceError::persistence(error))` rather than flattening to `Denied`.
   - In `preview_execution`: Database faults in `validate_execution_context` or `validate_execution_grant` propagate as `Err(e)`.
   - In `CoreService::evaluate_action`: Preserves typed `ServiceErrorKind::Persistence(PersistenceError)` when SQLite is closed (`Kind::Closed`), snapshots are missing/malformed (`Kind::Integrity`), or SQL queries fail (`Kind::Database`).
3. **Diagnostic Confidentiality:** Injected database errors retain categorical kinds and numeric SQLite error codes (e.g. `sqlite_code == Some(1)`), but sanitize and redact table names, paths, SQL text, and sensitive payloads from `Display`, `Debug`, and `source()` (`test: preview_missing_and_corrupt_authoritative_state_propagates_typed_failure`, `preview_sql_read_error_retains_extended_code_without_disclosing_sql_diagnostics`).

---

## 8. Authorization Validator Portability (F-562221-03 Verification)

The authorization validation harness ([`experiments/phase1/authorization/Validate.ps1`](file:///E:/MyProject/Mix/GitHub/Sentra/experiments/phase1/authorization/Validate.ps1)) was verified:
1. **Dynamic Target Directory Resolution:** Uses `cargo metadata --offline --no-deps --format-version=1` to query the active `target_directory`.
2. **Artifact Identification:** Parses `cargo build --offline --package sentra-core --message-format=json` compiler-artifact records to select the exact `libsentra_core.rlib` produced by that run.
3. **Dependency Derivation:** Derives `$dependencyRoot` directly from the rlib's parent directory (`deps`), eliminating hardcoded paths.
4. **Isolated Probe Executable:** Compiles the probe into a unique GUID subdirectory beneath the active target directory (`policy-context-probe.exe`), avoiding collisions or stale executable reuse.
5. **Four-Scenario Portability Runner (`Validate-Portability.ps1`):**
   - **Case 1 (`default`):** `CARGO_TARGET_DIR` unset $\rightarrow$ **13/13 Passed (exit 0)** in ~16.0s.
   - **Case 2 (`absolute-spaces`):** Absolute target directory containing spaces, launched from a foreign working directory $\rightarrow$ **13/13 Passed (exit 0)** in ~111.2s.
   - **Case 3 (`initially-empty`):** Separate initially empty target directory $\rightarrow$ **13/13 Passed (exit 0)** in ~123.8s.
   - **Case 4 (`reuse`):** Warm re-execution in that same target directory $\rightarrow$ **13/13 Passed (exit 0)** in ~14.3s; verified identical rlib hash and unique probe path.
6. **Command Timeout Evaluation:** Cold compilation and test execution of the entire workspace into a fresh target directory on Windows takes ~110–125 seconds. The 180-second command budget (configurable 1–300s) is a justified, realistic environment allowance for Windows hosts, not a defect mask.

---

## 9. Cross-Increment Security Regression Verification

All security invariants established across Phase 1 increments remain intact:

| Security Invariant | Code Location / Verification Path | Audit Finding |
| :--- | :--- | :--- |
| **Fail-Closed Untrusted Workloads** | `crates/sentra-core/src/execution/engine.rs` | `ExecutionError::untrusted_workload_disabled()` unconditionally blocks untrusted code. Zero host command, Docker, or WSL2 fallbacks. |
| **Centralized Result Invariants** | `crates/sentra-core/src/execution/model.rs` | `validate_for_request()` validates all 16 status, exit code, temporal, and identifier permutations. |
| **Execution ID Correlation** | `crates/sentra-core/src/execution/model.rs` | Mismatched execution IDs reject fail-closed with `ExecutionErrorKind::CorrelationMismatch`. |
| **Single-Use Approval Semantics** | `crates/sentra-core/src/persistence/repository.rs` | Consumption update requires `state='ISSUED'`; replay returns `ApprovalReused`. |
| **Single-Transaction Preparation** | `crates/sentra-core/src/persistence/repository.rs` | `reserve_budget_and_consume_approval` bundles budget reservation and approval consumption in one SQLite transaction. |
| **Compound Error Preservation** | `crates/sentra-core/src/service/error.rs` | Compound variants preserve execution/evidence primaries and settlement persistence secondaries. |
| **Workspace Boundary Quarantine** | `crates/sentra-core/src/workspace/boundary.rs` | Symlinks, junctions, reparse points, and paths outside canonical root quarantined. |
| **SQLite WAL & Integrity Check** | `crates/sentra-core/src/persistence/connection.rs` | WAL mode, synchronous=FULL, foreign keys enabled, integrity check on startup. |

---

## 10. Reconciled Test Inventory

### 10.1 Discovered and Executed Test Breakdown
All commands executed strictly offline without network access:

```
cargo test --workspace --offline
```

| Test Suite / Binary | Discovered | Passed | Ignored / Platform | Failed |
| :--- | :---: | :---: | :---: | :---: |
| `sentra_core` (Unit tests, `src/lib.rs`) | 14 | 14 | 0 | 0 |
| `authorization_isolation_review_tests` | 22 | 22 | 0 | 0 |
| `authorization_tests` | 27 | 27 | 0 | 0 |
| `domain_tests` | 9 | 9 | 0 | 0 |
| `evidence_tests` | 9 | 9 | 0 | 0 |
| `execution_evidence_adversarial_tests` | 11 | 11 | 0 | 0 |
| `execution_tests` | 8 | 8 | 0 | 0 |
| `independent_core_review_tests` | 31 | 30 | 1 helper | 0 |
| `persistence_tests` | 43 | 42 | 1 helper | 0 |
| `policy_tests` | 9 | 9 | 0 | 0 |
| `security_tests` | 10 | 10 | 0 | 0 |
| `service_tests` | 19 | 19 | 0 | 0 |
| `session_tests` | 5 | 5 | 0 | 0 |
| `workspace_tests` | 41 | 38 | 3 platform cases | 0 |
| `Doc-tests sentra_core` | 7 | 7 | 0 | 0 |
| **Workspace Cargo Test Totals** | **265** | **260** | **5** | **0** |

### 10.2 Consolidated Invariants
- **Automated Runtime Tests Passed:** 253
- **Compile-Fail Doctests Passed:** 7
- **Dedicated Platform Fixture Tests Passed:** 3 (executed via `experiments/phase1/workspace/Validate.ps1`: NTFS junction quarantine, ACL deny, 10,000-file benchmark)
- **Subprocess Helper Tests:** 2 (executed via parent test subprocesses)
- **Total Unique Invariants Verified:** **263 Unique Passed** (0 failed, 0 regressions)

### 10.3 Toolchain Verification
- `cargo fmt --all -- --check`: **Clean (0 diffs, exit 0)**
- `cargo check --workspace --all-targets --all-features --offline`: **Clean (0 errors, 0 warnings, exit 0)**
- `cargo clippy --workspace --all-targets --all-features --offline -- -D warnings`: **Clean (0 warnings, exit 0)**
- `persistence/Validate.ps1`: **13 / 13 Passed (exit 0)**
- `authorization/Validate.ps1`: **13 / 13 Passed (exit 0)**
- `workspace/Validate.ps1`: **11 / 11 Passed (exit 0)**
- `authorization/Validate-Portability.ps1`: **4 / 4 Scenarios Passed (13/13 checks each, exit 0)**

---

## 11. Findings and Severity Classification

| Finding ID | Severity | Description | Status |
| :--- | :--- | :--- | :--- |
| **F-5622221-01** | Informational | Physical Git index checksum change in 5.6.2.2.2 attributed to benign stat cache refresh; clean tree subsequently committed in `75a2ed4`. | Documented |
| **F-5622221-02** | Informational | Policy identity string (`sentra-policy:v1:auto-microusd=<n>`) is a canonical formatting of effective auto-budget, not a cryptographic hash. Fully adequate for trusted local controller; cryptographic binding deferred. | Bounded |
| **F-5622221-03** | Informational | Validator command budget of 180s accommodates cold workspace compilation on Windows (~110–125s) without masking execution errors. | Documented |

Zero Critical, High, Medium, or Low findings were identified.

---

## 12. Remaining Architectural Risks and Limitations

1. **Untrusted Target Workloads:** Remain 100% fail-closed (`ExecutionError::untrusted_workload_disabled()`). Hyper-V isolation and host-to-guest communications are deferred to Phase 2.
2. **Provider Integration:** Production Core remains provider-optional and provider-neutral; mock contract tests validate provider isolation. Real AI provider SDKs and network calls remain outside Phase 1.
3. **Cryptographic Identity:** Canonical framing and descriptor strings are deterministic representations, not cryptographic signatures.
4. **Crash Reconciliation:** Post-commit external side-effect crash reconciliation remains conservative (reservations held until explicit reconciliation); exactly-once external execution is not implemented.

---

## 13. Final Decision

**Approved**

All three findings from Increment 5.6.2.2.1 (**F-562221-01**, **F-562221-02**, **F-562221-03**) are verified as correctly and fully resolved. The implementation enforces immutable policy configuration, automatic context/approval invalidation on policy changes, Version 1 backward-compatibility gates, typed persistence error propagation in policy preview, and complete validator portability across arbitrary target directories. The Git index observation has been conclusively analyzed as a harmless stat cache refresh followed by an owner commit. Zero security or reliability defects block progress. Phase 1 remains incomplete; Phase 2 has not started.
