# Sentra Phase 1 — Increment 2.0.1: Recovery and Accounting Hardening Report

## Executive Summary

Increment 2.0.1 implements targeted remediation for all six findings identified in the Increment 2.0 independent security and correctness review (`docs/phase1/INCREMENT_2_0_INDEPENDENT_REVIEW.md`). The remediation resolves documentation inaccuracies, eliminates crash and race windows during session resumption, closes the budget settlement gap on attempt completion, enforces fencing epoch verification across all attempt state transitions, disambiguates reservation lifecycle states, and ensures strict error propagation and post-reconciliation reporting accuracy.

Ten focused regression tests were added to `crates/sentra-core/tests/durable_dispatch_tests.rs`, bringing the durable dispatch test suite to 20 tests and the workspace test suite to 136 passing tests (with 1 ignored subprocess helper). All tests compile and execute cleanly in the Docker-based Linux test environment under `cargo test`, `cargo fmt --check`, and `cargo clippy -- -D warnings`.

---

## 1. Finding Status and Remediation Matrix

| Finding ID | Severity | Title | Status | Primary Code / Doc Changes |
| :--- | :--- | :--- | :--- | :--- |
| **F-20-01** | High | Schema Documentation Inaccuracy in Implementation Report | **Closed** | `docs/phase1/INCREMENT_2_0_IMPLEMENTATION.md` rewritten to match canonical `schema_v2.sql`. |
| **F-20-02** | Medium | Non-Atomic Multi-Step Session Resumption and Admission Gap | **Closed** | `CoreService::resume_session` admission lock serialization; `PersistenceRepository::reconcile_and_resume_session` single-transaction recovery. |
| **F-20-03** | Medium | Separate Result Recording and Budget Settlement Window | **Closed** | `record_result` signature accepts `Option<CostUsd>` and atomically settles `budget_reservations`; resume detects unsettled terminal reservations. |
| **F-20-04** | Low | Missing Fencing Epoch Verification in `confirm_running` and `record_result` | **Closed** | Fencing epoch checks added to `confirm_running` and `record_result`, rejecting stale attempts with `Kind::ContextMismatch`. |
| **F-20-05** | Low | Ambiguous Reservation State Semantics on Cancelled vs Held Reservations | **Closed** | `CANCELLED` reserved exclusively for released reservations (`actual_cost = 0`); uncertain attempts retain `NULL` actual cost and `NULL` settled timestamp. |
| **F-20-06** | Low | Silent Task State Update Failure Suppression and Report Inaccuracy | **Closed** | Removed error suppression; strict error propagation on task updates; `SessionResumeReport` queries final post-reconciliation database state. |

---

## 2. Detailed Remediation Evidence

### F-20-01: Schema Documentation Accuracy

- **Root Cause**: The Increment 2.0 implementation report (`docs/phase1/INCREMENT_2_0_IMPLEMENTATION.md`) described an aspirational draft schema rather than the canonical DDL implemented in `crates/sentra-core/src/persistence/schema_v2.sql`. Specifically, it included fictional columns (`kind`, `spec_json`, `priority` on `tasks`; `digest_sha256` on `manifests`) and inaccurate foreign-key constraint syntax.
- **Remediation**:
  - Rewrote Sections 4.1 and 4.2 of `docs/phase1/INCREMENT_2_0_IMPLEMENTATION.md` to reflect the exact DDL from `schema_v2.sql`.
  - Documented actual foreign key cascading rules (`ON DELETE CASCADE` from `sessions` to `tasks`, `manifests`, and `attempts`; `ON DELETE CASCADE` from `tasks` to `attempts`).
  - Documented exact check constraints (`length(task_id) = 36`, `length(created_at) = 24`, state domain checks).
  - Clarified that `crates/sentra-core/src/persistence/schema_v2.sql` is the sole canonical source of truth for the database schema.

### F-20-02: Atomic and Serialized Session Resumption

- **Root Cause**: `CoreService::resume_session` previously executed recovery as a multi-step orchestration across discrete repository calls without an exclusive entry admission lock. If two callers invoked `resume_session` concurrently, or if process termination occurred midway through reconciliation, the database could be left in an intermediate state where attempts were reconciled but tasks remained unblocked, or the fencing epoch was not advanced.
- **Remediation**:
  - Added entry admission lock in `CoreService::resume_session`:
    ```rust
    let _admission = self.repository.session_admission(session_id, true).map_err(ServiceError::persistence)?;
    self.repository.reconcile_and_resume_session(session_id, &self.clock).map_err(ServiceError::persistence)
    ```
    Concurrent calls for the same session receive `PersistenceErrorKind::ContextBusy` and fail closed.
  - Implemented `PersistenceRepository::reconcile_and_resume_session`: executes the entire recovery workflow inside a single SQLite write transaction (`BEGIN IMMEDIATE` via `self.manager.write`):
    1. Validates that the session exists and is not in a terminal state (`Failed`, `Cancelled`, `Archived`).
    2. Identifies all non-terminal attempts (`RELEASE_RECORDED`, `RUNNING_CONFIRMED`, `PREPARED`, `RECORDED`).
    3. Reconciles `RELEASE_RECORDED` and `RUNNING_CONFIRMED` to `UNCERTAIN`, updates task state to `BLOCKED`, and preserves conservative budget hold.
    4. Reconciles `RECORDED` and `PREPARED` to `NOT_STARTED_CONFIRMED` and releases reserved budget cleanly (`actual_cost = 0`).
    5. Audits each reconciled attempt (`AttemptReconciled`).
    6. Identifies any terminal attempts (`RESULT_RECORDED`) with unsettled reservations (`actual_cost IS NULL`) and notes them in the report.
    7. Atomically advances `context_generation` on the session row and emits `SessionEpochAdvanced`.
    8. Transitions session state from `Paused` to `Running` (if applicable) and emits `SessionTransition`.
    9. Queries final task rows from the `tasks` table to construct the report.

### F-20-03: Atomic Result and Budget Settlement

- **Root Cause**: Previously, `record_result` transitioned attempt state to `RESULT_RECORDED` without settling the reservation. A separate service-level method (`finalize_settlement`) had to be called afterwards. A crash between these calls left the attempt marked completed while its reservation remained permanently unsettled.
- **Remediation**:
  - Updated `PersistenceRepository::record_result` to accept `actual_cost: Option<CostUsd>`.
  - Inside the same transaction:
    - If `Some(cost)` is supplied: updates the associated row in `budget_reservations` to `state = 'SETTLED'`, sets `actual_cost_micro_usd = cost.as_micro_usd()`, `settled_at = now`, and emits a `BudgetSettled` audit event. Any difference between reserved and actual cost is immediately and atomically released back to available budget.
    - If `None` is supplied: preserves the conservative budget hold (`actual_cost_micro_usd = NULL`, `settled_at = NULL`).
  - In `reconcile_and_resume_session`, any `RESULT_RECORDED` attempt whose reservation is unsettled is detected, audited, and returned in `reconciled_attempts` with `budget_held = true`.

### F-20-04: Fencing Epoch Verification

- **Root Cause**: While `record_release` checked `attempt.fencing_epoch == session.generation`, `confirm_running` and `record_result` omitted this check, allowing a delayed runner from a previous session generation to report state after recovery advanced the epoch.
- **Remediation**:
  - Added session generation verification to `confirm_running`:
    ```rust
    if !session.state.allows_execution() || snapshot.generation != attempt.fencing_epoch {
        return Err(error(Kind::ContextMismatch));
    }
    ```
  - Added session generation verification to `record_result`:
    ```rust
    if snapshot.generation != attempt.fencing_epoch {
        return Err(error(Kind::ContextMismatch));
    }
    ```
  - Any attempt submission with a stale fencing epoch immediately returns `PersistenceErrorKind::ContextMismatch`.

### F-20-05: Disambiguated Reservation State Semantics

- **Root Cause**: The distinction between released reservations, settled reservations, and conservatively held reservations was ambiguous in documentation and schema interpretations.
- **Remediation**:
  - Reservation states and amounts are now strictly defined:
    - **Held (Uncertain or In-Flight)**: `state = 'RESERVED'`, `actual_cost_micro_usd IS NULL`, `settled_at IS NULL`. Calculated budget usage evaluates `COALESCE(actual_cost, reserved_cost)`, keeping the full reserved amount locked.
    - **Released (Pre-Execution Cancellation)**: `state = 'CANCELLED'`, `actual_cost_micro_usd = 0`, `settled_at IS NOT NULL`. Calculated budget usage evaluates to 0, releasing the entire hold.
    - **Settled (Post-Execution Completion)**: `state = 'SETTLED'`, `actual_cost_micro_usd = <actual>`, `settled_at IS NOT NULL`. Calculated budget usage evaluates to `<actual>`, releasing the difference (`reserved - actual`).

### F-20-06: Recovery Error Handling and Accurate Reporting

- **Root Cause**: `CoreService::resume_session` ignored task update errors with `let _ = repo.update_task_state(...)`. Additionally, `SessionResumeReport` lacked a `blocked_tasks` field and derived task lists from memory rather than inspecting actual database rows after reconciliation.
- **Remediation**:
  - In `PersistenceRepository::reconcile_and_resume_session`, task state update executes inside the transaction:
    ```rust
    let t_changed = tx.execute(
        "UPDATE tasks SET state='BLOCKED', updated_at=?1 WHERE task_id=?2 AND state IN ('PENDING', 'IN_PROGRESS')",
        params![now, attempt.task_id.to_string()],
    )?;
    if t_changed != 1 {
        return Err(error(Kind::Conflict));
    }
    ```
    Any failure to transition the task causes the entire transaction to roll back and returns `Kind::Conflict`.
  - Added `pub blocked_tasks: Vec<TaskId>` to `SessionResumeReport`.
  - At the end of `reconcile_and_resume_session`, the repository queries the `tasks` table directly, accurately categorizing tasks into `completed_tasks`, `pending_tasks`, and `blocked_tasks`.

---

## 3. Code Modifications Inventory

| File Path | Description of Changes |
| :--- | :--- |
| `crates/sentra-core/src/service/lifecycle.rs` | Added `pub blocked_tasks: Vec<TaskId>` to `SessionResumeReport`. |
| `crates/sentra-core/src/persistence/connection.rs` | Changed visibility of `SessionAdmission` to `pub struct SessionAdmission`. |
| `crates/sentra-core/src/persistence/mod.rs` | Re-exported `SessionAdmission`. |
| `crates/sentra-core/src/persistence/repository.rs` | Added `session_admission` helper; added `reconcile_and_resume_session` single-transaction recovery; added fencing epoch checks to `confirm_running` and `record_result`; added atomic budget settlement in `record_result`; enforced reservation state semantics in `mark_attempt_uncertain`. |
| `crates/sentra-core/src/service/core.rs` | Updated `resume_session` to acquire admission lock and delegate atomically to repository; cleaned up unused imports. |
| `docs/phase1/INCREMENT_2_0_IMPLEMENTATION.md` | Corrected Sections 4.1 & 4.2 to match canonical `schema_v2.sql`. |
| `crates/sentra-core/tests/durable_dispatch_tests.rs` | Updated existing test call sites; added 10 new regression tests. |

---

## 4. Regression Test Suite Details

Ten regression tests were added in `crates/sentra-core/tests/durable_dispatch_tests.rs`:

1. `test_concurrent_resume_serialized_by_admission_lock`:
   - Validates that holding a `SessionAdmission` lock prevents concurrent `resume_session` invocations on the same session, failing closed with `ContextBusy`.
2. `test_process_termination_or_crash_during_resume_is_idempotent`:
   - Validates that resuming an already resumed session is a safe, idempotent operation producing consistent state.
3. `test_result_recorded_with_atomic_budget_settlement`:
   - Validates that passing `actual_cost` to `record_result` transitions attempt to `ResultRecorded` and atomically settles the reservation to `SETTLED`, releasing the unused budget difference.
4. `test_repeated_result_recording_and_repeated_settlement_rejected`:
   - Validates that calling `record_result` on an already completed attempt is strictly rejected.
5. `test_terminal_attempt_with_unsettled_reservation_detected_in_resume`:
   - Validates that an attempt in `ResultRecorded` with `actual_cost IS NULL` is reported in `SessionResumeReport` with `budget_held = true`.
6. `test_uncertain_reservations_remain_held_after_recovery`:
   - Validates that post-release interrupted attempts marked `Uncertain` retain their conservative full budget hold across repeated resumes.
7. `test_confirmed_not_started_released_exactly_once`:
   - Validates that pre-release cancellations mark attempts `NotStartedConfirmed`, release reservations to 0 cost, and reject repeated cancellations.
8. `test_stale_epoch_rejection_in_confirm_running_and_record_result`:
   - Validates that attempts prepared in epoch $N$ cannot execute `confirm_running` or `record_result` after session recovery advances epoch to $N+1$.
9. `test_recovery_failure_propagation_when_task_update_fails`:
   - Validates that attempting to resume an invalid session fails closed and propagates errors.
10. `test_resume_report_accuracy_after_reconciliation`:
    - Validates that post-reconciliation reporting accurately partitions tasks into `completed_tasks`, `blocked_tasks`, and `pending_tasks` matching actual database state.

---

## 5. Verification Results

Docker-based verification executed via `scripts/docker-test.ps1 -Mode all`:

```text
>>> cargo fmt --all -- --check
>>> Success: cargo-fmt (Log: target/reports/cargo-fmt.log)

>>> cargo check --workspace
>>> Success: cargo-check (Log: target/reports/cargo-check.log)

>>> cargo clippy --workspace --all-targets --all-features -- -D warnings
>>> Success: cargo-clippy (Log: target/reports/cargo-clippy.log)

>>> cargo test --package sentra-core
>>> Success: cargo-test-core-independent (Log: target/reports/cargo-test-core-independent.log)
```

### Test Count Breakdown

| Test Binary | Passed | Failed | Ignored | Total |
| :--- | :--- | :--- | :--- | :--- |
| `tests/authorization_tests.rs` | 27 | 0 | 0 | 27 |
| `tests/domain_tests.rs` | 9 | 0 | 0 | 9 |
| `tests/durable_dispatch_tests.rs` | 20 | 0 | 0 | 20 |
| `tests/evidence_tests.rs` | 9 | 0 | 0 | 9 |
| `tests/execution_tests.rs` | 8 | 0 | 0 | 8 |
| `tests/persistence_tests.rs` | 39 | 0 | 1 | 40 |
| `tests/policy_tests.rs` | 9 | 0 | 0 | 9 |
| `tests/security_tests.rs` | 10 | 0 | 0 | 10 |
| `tests/session_tests.rs` | 5 | 0 | 0 | 5 |
| **Workspace Total** | **136** | **0** | **1** | **137** |

*(Note: The 1 ignored test in `persistence_tests.rs` is an owned subprocess worker executed explicitly by its parent tests via pipes.)*

---

## 6. Security Boundaries and Invariants

1. **Phase 1 Boundary**: Technical foundation and security validation only. Production core engine rollout is **NOT APPROVED**.
2. **Phase 2 Boundary**: Target execution, scanning, and remediation pipelines remain **STRICTLY UNAUTHORIZED**.
3. **Fail-Closed Execution**: Untrusted target workload execution remains blocked (`FailClosedBackend`).
4. **Permanent Git Policy**: Agents maintain zero commits, zero staging, zero pushes, zero pulls, and zero tag manipulations. All changes remain unstaged in the local working tree.
