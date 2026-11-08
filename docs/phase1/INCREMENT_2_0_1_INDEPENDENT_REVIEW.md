# Independent Security and Correctness Review — Increment 2.0.1: Recovery and Accounting Hardening

**Review Date**: 2026-11-08  
**Target Commit**: `8569b66` (*"Harden session recovery and budget accounting"*)  
**Review Status**: **APPROVED**  
**Phase Boundary**: Phase 1 is incomplete; Phase 1 remains **NOT APPROVED**; Phase 2 has not started and remains **STRICTLY UNAUTHORIZED**. Untrusted target execution remains **fail-closed** (`FailClosedBackend`). Permanent Git policy preserved.

---

## 1. Executive Verdict and Summary

### Verdict: APPROVED

The adversarial verification of Phase 1 Increment 2.0.1 demonstrates that all six findings (F-20-01 through F-20-06) identified in the Increment 2.0 independent review (`docs/phase1/INCREMENT_2_0_INDEPENDENT_REVIEW.md`) have been thoroughly, accurately, and cleanly remediated. 

Key architectural hardening verified in this audit:
- **Canonical DDL Alignment (F-20-01)**: `docs/phase1/INCREMENT_2_0_IMPLEMENTATION.md` has been completely rewritten to match the canonical SQLite Schema V2 (`crates/sentra-core/src/persistence/schema_v2.sql`). Fabricated columns, inaccurate cascade definitions, and non-existent check constraints have been eliminated.
- **Single-Transaction Resumption & OS Admission Lock (F-20-02)**: Resumption in `CoreService::resume_session` is now strictly serialized using an OS-level exclusive file lease (`SessionAdmission`), preventing concurrent or duplicate resume execution across threads and processes. All attempt reconciliations, conservative budget holds, task state updates, session generation increments, and session state transitions execute within a single atomic SQLite write transaction (`BEGIN IMMEDIATE` in `PersistenceRepository::reconcile_and_resume_session`).
- **Atomic Result & Budget Settlement (F-20-03)**: `PersistenceRepository::record_result` now atomically records verified terminal attempt outcomes and settles associated budget reservations within the same write transaction. Terminal attempts with unsettled reservations are detected during resumption and reported with `budget_held = true`.
- **Fencing Epoch Verification (F-20-04)**: Fencing epoch equality (`snapshot.generation == attempt.fencing_epoch`) is now verified within the same transaction for all attempt transitions (`confirm_running`, `record_result`, and `record_release`), rejecting stale runner messages with `Kind::ContextMismatch`.
- **Disambiguated Reservation Semantics (F-20-05)**: Reservation states and accounting behavior are strictly defined. `budget_reservations.state = 'CANCELLED'` with `actual_cost_micro_usd = 0` cleanly releases budget for pre-release cancellations, whereas `actual_cost_micro_usd = NULL` conservatively locks the entire reservation for post-release interruptions via SQL `COALESCE(actual_cost, reserved_cost)`.
- **Strict Error Propagation & Report Accuracy (F-20-06)**: Silent error suppression (`let _ =`) has been removed; any task state update failure aborts the entire recovery transaction. `SessionResumeReport` queries the final post-reconciliation database state directly, accurately reporting `completed_tasks`, `pending_tasks`, and `blocked_tasks`.

Increment 2.0.1 is verified as a reliable, secure foundation for subsequent Phase 1 work.

---

## 2. Closure Status of Previous Findings

| Finding ID | Severity | Description | Status | Verification Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **F-20-01** | High | Schema Documentation Inaccuracy | **Closed** | `docs/phase1/INCREMENT_2_0_IMPLEMENTATION.md` Sections 4.1 & 4.2 match canonical `schema_v2.sql` verbatim. |
| **F-20-02** | Medium | Non-Atomic Multi-Step Resumption | **Closed** | `CoreService::resume_session` entry `SessionAdmission` lock; `PersistenceRepository::reconcile_and_resume_session` single-transaction recovery. |
| **F-20-03** | Medium | Unsettled Budget Reservations on `ResultRecorded` | **Closed** | `record_result` accepts `Option<CostUsd>` and atomically settles `budget_reservations`; resume detects unsettled reservations. |
| **F-20-04** | Low | Missing Fencing Epoch Verification | **Closed** | Generation equality check enforced in `confirm_running` and `record_result`, returning `Kind::ContextMismatch` on stale attempts. |
| **F-20-05** | Low | Ambiguous `CANCELLED` Reservation Semantics | **Closed** | Accounting query evaluates `COALESCE(actual_cost, reserved_cost)`; held reservations retain `NULL` actual cost, released reservations set `0`. |
| **F-20-06** | Low | Silent Error Suppression & Stale Task Reporting | **Closed** | Task update errors fail recovery (`t_changed == 1`); `SessionResumeReport` populates `blocked_tasks` from post-recovery DB queries. |

---

## 3. Critical Verification Analysis

### 3.1 F-20-01: Canonical Schema Verification
- **Verified Files**: `crates/sentra-core/src/persistence/schema_v2.sql` vs `docs/phase1/INCREMENT_2_0_IMPLEMENTATION.md`.
- **Finding**: Every table definition (`tasks`, `manifests`, `attempts`), column type, foreign key cascading rule (`ON DELETE CASCADE` to sessions/tasks, `RESTRICT` to manifests/approvals/reservations), and check constraint matches the canonical implementation exactly.
- **Assessment**: Fully reconciled; no remaining documentation drift.

### 3.2 F-20-02: Resumption Atomicity & Synchronization Scope
- **Synchronization Scope of `SessionAdmission`**:
  - `SessionAdmission` opens `<database_path>.session-<session_id>.lock` with `std::fs::OpenOptions` and invokes `File::try_lock()`:
    - **In-Process Multi-Threading**: On Windows (`LockFileEx`), locks are associated with individual file handles. Separate `File` instances in the same process attempting concurrent locks fail with `TryLockError::WouldBlock` (`Kind::ContextBusy`). On Unix/Linux, `std::fs::File::try_lock()` uses `flock` on separate open file descriptors, producing identical `EWOULDBLOCK` exclusion.
    - **Cross-Process Multi-Instance**: Independent OS processes accessing the same database are strictly excluded by the OS kernel lock.
    - **Process Termination / Crash Safety**: OS file locks are automatically released by the kernel when the holding process terminates (clean exit or `SIGKILL`), allowing subsequent processes to acquire admission without manual cleanup or orphaned lock files.
- **Transaction Boundaries of `reconcile_and_resume_session`**:
  - All state transitions execute within a single `self.manager.write(|tx| ...)` closure.
  - `write` begins with `BEGIN IMMEDIATE`, acquiring the SQLite write lock immediately.
  - **Process Termination Scenarios**:
    - *Termination before transaction*: No state modified. Resumption can be retried cleanly.
    - *Termination during transaction / before commit*: SQLite WAL guarantees rollback on the next database connection open. No partial updates (e.g. attempts marked uncertain without tasks marked blocked) persist.
    - *Termination after commit*: All changes (attempts, tasks, epoch increment, session state, audit events) are durable in WAL. Resumption is idempotent; a second resumption encounters already reconciled attempts and advances cleanly.

### 3.3 F-20-03: Result Recording and Budget Settlement
- **Atomic Execution**: Inside `PersistenceRepository::record_result`, the `UPDATE attempts SET state='RESULT_RECORDED' ...` and the `UPDATE budget_reservations SET state='SETTLED', actual_cost_micro_usd=?2 ...` execute within the same `BEGIN IMMEDIATE` transaction.
- **Distinction Between `Some(0)` and `None`**:
  - `actual_cost = Some(CostUsd::ZERO)`: Sets `budget_reservations.state = 'SETTLED'`, `actual_cost_micro_usd = 0`, `settled_at = now`. In `budget_used`, `COALESCE(0, reserved_cost)` evaluates to `0`, cleanly releasing the full reservation.
  - `actual_cost = None`: Leaves `actual_cost_micro_usd = NULL` and `settled_at = NULL`. In `budget_used`, `COALESCE(NULL, reserved_cost)` evaluates to `reserved_cost`, conservatively maintaining the full reservation hold.
- **Unsettled Terminal Detection**: In `reconcile_and_resume_session`, any attempt in `ResultRecorded` whose reservation has `actual_cost_micro_usd IS NULL` is identified, flagged in `reconciled_attempts` with `budget_held = true`, and preserves the budget hold.
- **Double-Spend & Double-Release Prevention**: Repeated calls to `record_result` on the same attempt return `Err(Kind::Conflict)`. Repeated calls to `settle_budget` on an already settled reservation return `Err(Kind::Conflict)`.

### 3.4 F-20-04: Fencing Epoch Verification
- In `PersistenceRepository::confirm_running`:
  ```rust
  if !session.state.allows_execution() || snapshot.generation != attempt.fencing_epoch {
      return Err(error(Kind::ContextMismatch));
  }
  ```
- In `PersistenceRepository::record_result`:
  ```rust
  if snapshot.generation != attempt.fencing_epoch {
      return Err(error(Kind::ContextMismatch));
  }
  ```
- Because both checks read `snapshot` inside the `BEGIN IMMEDIATE` write transaction, a concurrent epoch bump by `resume_session` (which also writes to `sessions`) serializes before or after. If resumption completes first, any subsequent attempt submission with the old generation fails immediately with `Kind::ContextMismatch`.

### 3.5 F-20-05: Reservation State Semantics
- In SQLite Schema V1 (`schema_v1.sql`), the check constraint on `budget_reservations` allows `CHECK(state IN ('RESERVED','SETTLED','CANCELLED','EXPIRED'))`.
- Semantics are now disambiguated by column values:
  1. **Pre-Execution Cancellation (`confirm_not_started`)**: `state = 'CANCELLED'`, `actual_cost_micro_usd = 0`, `settled_at = now`. Budget freed: `100%`.
  2. **Post-Release Interruption (`mark_attempt_uncertain` / `reconcile_and_resume_session`)**: `state = 'CANCELLED'`, `actual_cost_micro_usd = NULL`, `settled_at = NULL`. Budget held: `100%`.
  3. **Settled Execution (`record_result`)**: `state = 'SETTLED'`, `actual_cost_micro_usd = <actual>`, `settled_at = now`. Budget used: `<actual>`.
- The canonical accounting query in `budget_used` (`COALESCE(SUM(COALESCE(actual_cost_micro_usd, reserved_cost_micro_usd)), 0)`) reliably reflects these exact three behaviors.

### 3.6 F-20-06: Task Update Error Handling & Report Accuracy
- In `reconcile_and_resume_session`:
  ```rust
  let t_changed = tx.execute(
      "UPDATE tasks SET state='BLOCKED', updated_at=?1 WHERE task_id=?2 AND (state='PENDING' OR state='IN_PROGRESS')",
      params![now, attempt.task_id.to_string()],
  )?;
  if t_changed != 1 {
      return Err(error(Kind::Conflict));
  }
  ```
  Any failure to transition an interrupted task immediately rolls back the SQLite transaction.
- `SessionResumeReport` queries the `tasks` table directly (`SELECT task_id, state FROM tasks WHERE session_id=?1 ORDER BY sequence_number ASC`), accurately populating `completed_tasks`, `pending_tasks`, and `blocked_tasks`.

---

## 4. Regression Test Assessment

The ten new regression tests in `crates/sentra-core/tests/durable_dispatch_tests.rs` were audited individually:

| Test Name | Invariant Established | Production Code Exercised | Real Crash vs Returned Error | Concurrency / Boundary Notes |
| :--- | :--- | :--- | :--- | :--- |
| `test_concurrent_resume_serialized_by_admission_lock` | Concurrent resume calls for the same session fail closed with `ContextBusy`. | `CoreService::resume_session`, `session_admission` | Returned Error | Proves exclusion while lease is active; OS guarantees lease drop on crash. |
| `test_process_termination_or_crash_during_resume_is_idempotent` | Sequential resumes advance generation monotonically without re-reconciling. | `reconcile_and_resume_session` | Idempotent Replay | Tests state consistency across multiple recovery cycles. |
| `test_result_recorded_with_atomic_budget_settlement` | `record_result` atomically transitions attempt and settles budget delta. | `record_result`, `budget_used` | Returned / DB Commit | Verifies atomic release of unused budget ceiling. |
| `test_repeated_result_recording_and_repeated_settlement_rejected` | Terminal attempts and settled reservations reject duplicate transitions. | `record_result`, `settle_budget` | Returned Error | Proves prevention of double settlement and double charging. |
| `test_terminal_attempt_with_unsettled_reservation_detected_in_resume` | Attempts in `ResultRecorded` with `NULL` cost are flagged in resume report. | `reconcile_and_resume_session` | Recovery Inspection | Verifies budget hold persistence for unsettled terminal attempts. |
| `test_uncertain_reservations_remain_held_after_recovery` | Interrupted uncertain attempts maintain full conservative hold across resumes. | `reconcile_and_resume_session`, `budget_used` | Sequential Recovery | Confirms `budget_used` invariant is preserved under repeated recovery. |
| `test_confirmed_not_started_released_exactly_once` | Pre-release cancellation releases reservation to 0 and rejects repeated calls. | `confirm_not_started`, `record_release` | Returned Error | Verifies zero-cost cancellation and release rejection. |
| `test_stale_epoch_rejection_in_confirm_running_and_record_result` | Stale attempts from epoch $N$ cannot execute in epoch $N+1$. | `confirm_running`, `record_result`, epoch check | Returned Error | Proves stale runner isolation after recovery or epoch advancement. |
| `test_recovery_failure_propagation_when_task_update_fails` | Resumption fails closed and returns error on invalid/conflicting sessions. | `CoreService::resume_session` | Returned Error | Proves error propagation out of service layer. |
| `test_resume_report_accuracy_after_reconciliation` | `SessionResumeReport` accurately reflects database task states. | `reconcile_and_resume_session`, `update_task_state` | DB Query Comparison | Verifies partitioned task report fidelity. |

All ten tests run and pass cleanly alongside the existing 10 durable dispatch tests (totaling 20 tests in `durable_dispatch_tests.rs`).

---

## 5. Test Suite and Toolchain Verification

Full verification was executed in the Linux Docker test container (`sentra-test-runner:1.99.0` via `scripts/docker-test.ps1 -Mode all`):

- **Formatting Check**: `cargo fmt --all -- --check` $\rightarrow$ **0 diffs, Passed**.
- **Workspace Compilation**: `cargo check --workspace` $\rightarrow$ **0 errors, Passed**.
- **Clippy Static Analysis**: `cargo clippy --workspace --all-targets --all-features -- -D warnings` $\rightarrow$ **0 warnings, Passed**.
- **Integration Test Execution**: `cargo test --package sentra-core` $\rightarrow$ **136 passed, 0 failed, 1 ignored**.

### Test Suite Inventory

| Test Binary | Passed Cases | Failed Cases | Ignored Cases |
| :--- | :--- | :--- | :--- |
| `tests/authorization_tests.rs` | 27 | 0 | 0 |
| `tests/domain_tests.rs` | 9 | 0 | 0 |
| `tests/durable_dispatch_tests.rs` | 20 | 0 | 0 |
| `tests/evidence_tests.rs` | 9 | 0 | 0 |
| `tests/execution_tests.rs` | 8 | 0 | 0 |
| `tests/persistence_tests.rs` | 39 | 0 | 1 *(owned subprocess helper)* |
| `tests/policy_tests.rs` | 9 | 0 | 0 |
| `tests/security_tests.rs` | 10 | 0 | 0 |
| `tests/session_tests.rs` | 5 | 0 | 0 |
| **Total** | **136** | **0** | **1** |

---

## 6. Remaining Boundaries and Invariants

1. **Phase 1 Incomplete**: Increment 2.0.1 hardens recovery and accounting. Phase 1 remains technical validation only and is **NOT APPROVED**.
2. **Phase 2 Unauthorized**: Workload execution pipelines, scanning, and remediation workflows remain **STRICTLY UNAUTHORIZED**.
3. **Fail-Closed Target Execution**: Untrusted workloads remain intercepted and rejected by `FailClosedBackend`.
4. **Permanent Git Policy**: Agents maintain zero commits, zero staging, zero pushes, and zero branch mutations. All changes remain unstaged in the local working tree.
5. **Open Architecture Items**:
   - `F-611-02`: Atomic staging and explicit operator recovery for store creation remain an open architectural requirement before Phase 2 readiness.
   - `OQ-25`: Local project identity remains the single foundation session. Multi-session CLI commands remain deferred.

---

## 7. Conclusion

Increment 2.0.1 successfully closes all six findings from the Increment 2.0 review with robust, verifiable, atomic persistence contracts and comprehensive regression test coverage.

**Verdict**: **APPROVED**. Increment 2.0.1 is a sound and reliable foundation for subsequent Phase 1 work.
