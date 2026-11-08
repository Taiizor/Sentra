# Independent Security and Correctness Review — Increment 2.0

Date: 2026-11-08. Status: **Approved with Conditions**. Phase 1 is incomplete. Phase 2 has not started and remains strictly unauthorized. Untrusted target execution remains fail-closed. Permanent Git policy preserved.

---

## 1. Executive Verdict and Summary

### Verdict: APPROVED WITH CONDITIONS

The implementation of Phase 1 Increment 2.0 (Docker Test Infrastructure and Durable Persistence Foundation) demonstrates sound core foundations:
- **Docker Test Infrastructure**: Cleanly separates build artifacts from the Windows host filesystem using named volume overlays (`sentra_cargo_target`, `sentra_cargo_cache`), preventing antivirus (Kaspersky) locking and false positives on the host while enforcing read-only source mounting (`:ro`).
- **SQLite Schema V2 & Transactional Migration**: Provides durable tables (`tasks`, `manifests`, `attempts`) with strict foreign keys, check constraints, and down-level older-writer rejection (`NewerSchema`) within an atomic transaction.
- **Durable Dispatch Outbox State Machine**: Successfully establishes forward state progression (`Recorded` $\rightarrow$ `Prepared` $\rightarrow$ `ReleaseRecorded` $\rightarrow$ `RunningConfirmed` $\rightarrow$ `ResultRecorded`), backed by strict fencing epoch validation on release (`record_release`).
- **Conservative Budget Settlement**: Disrupted operations post-release are marked `Uncertain` with conservative budget retention (holding full reservation via `actual_cost_micro_usd = NULL` and SQLite `COALESCE`), preventing budget overruns.

However, an adversarial audit revealed **six findings** (1 High, 2 Medium, 3 Low). The most notable is a significant documentation-to-DDL discrepancy in the implementation report, as well as non-atomic orchestration in `CoreService::resume_session`. Increment 2.0 is **safe to serve as a foundation for subsequent Phase 1 work**, subject to the conditions documented herein.

---

## 2. Review Findings

| Finding ID | Severity | Affected Component | Summary |
| --- | --- | --- | --- |
| **F-20-01** | **High** | `docs/phase1/INCREMENT_2_0_IMPLEMENTATION.md` | **Documentation & Implementation Mismatch in Schema V2 DDL**: Implementation report describes fabricated columns, non-existent check constraints, and `RESTRICT` cascade rules that contradict canonical `schema_v2.sql`. |
| **F-20-02** | **Medium** | `crates/sentra-core/src/service/core.rs` | **Non-Atomic `resume_session` Lacks Entry Admission Lock**: Resumption runs across multiple independent transactions without holding `session_admission` at entry; races and partial-recovery failure windows exist. |
| **F-20-03** | **Medium** | `crates/sentra-core/src/persistence/repository.rs` | **Unsettled Budget Reservations on `ResultRecorded`**: `record_result` does not settle the budget reservation, leaking unfinalized reservations if `reconcile_final_budget` is not explicitly called before a crash. |
| **F-20-04** | **Low** | `crates/sentra-core/src/persistence/repository.rs` | **Missing Fencing Epoch Check in `confirm_running` and `record_result`**: Only `record_release` validates `snapshot.generation == attempt.fencing_epoch`; subsequent transitions validate state string but omit the epoch equality check. |
| **F-20-05** | **Low** | `crates/sentra-core/src/persistence/repository.rs` | **Semantic Ambiguity of `CANCELLED` Reservation State**: `CANCELLED` is used for both released reservations (`actual_cost = 0`) and held reservations (`actual_cost = NULL`), creating potential confusion for external queries. |
| **F-20-06** | **Low** | `crates/sentra-core/src/service/core.rs` | **Silent Error Suppression on Task State Update & Stale Report Sequence**: `let _ = update_task_state` swallows errors during resumption, and `pending_tasks` is computed prior to reconciling attempts. |

---

### Detailed Findings

#### F-20-01: Documentation and Implementation Mismatch in Schema V2 DDL (High Severity)
- **Affected Artifact**: [docs/phase1/INCREMENT_2_0_IMPLEMENTATION.md](INCREMENT_2_0_IMPLEMENTATION.md) Section 4.1.
- **Analysis**:
  The implementation report `INCREMENT_2_0_IMPLEMENTATION.md` purports to present the Schema V2 DDL, but includes multiple fabricated definitions that do not match the canonical code in [crates/sentra-core/src/persistence/schema_v2.sql](../../crates/sentra-core/src/persistence/schema_v2.sql):
  1. `tasks` table: Documented as containing `kind`, `spec_json`, and `priority`. In reality, `tasks` contains `sequence_number`, `title`, and `completed_at`, with no `kind`, `spec_json`, or `priority` columns.
  2. `tasks.state`: Documented as `CHECK(state IN ('CREATED', 'PENDING', 'DISPATCHED', 'RUNNING', ...))`. In reality, it is `CHECK(state IN ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'FAILED', 'CANCELLED', 'BLOCKED'))`.
  3. `manifests` table: Documented as containing `task_id` and `digest_sha256` (64 chars). In reality, it contains `content_digest` (length > 0) and has no `task_id` foreign key.
  4. `attempts` table: Documented with columns `worker_id`, `worker_token_hash`, `outcome_status`, `error_message`, `result_digest`. In reality, the columns are `fencing_epoch`, `execution_id`, `action_name`, `action_digest`, `terminal_outcome`, `terminal_details_json`.
  5. Cascading Behavior: Documented as `ON DELETE RESTRICT` for `session_id`. In reality, `schema_v2.sql` specifies `FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE`.
  6. Timestamp Constraints: Documented as `substr(created_at, 24, 1) = 'Z'`. In reality, `schema_v2.sql` uses `CHECK(length(created_at) = 24)` without the substring operator.
- **Exploit / Failure Scenario**: Documentation-audit divergence. Any subsequent engineer, security auditor, or migration designer relying on the implementation report will design against non-existent schema contracts and false cascade assumptions.
- **Required Remediation**: Update `INCREMENT_2_0_IMPLEMENTATION.md` to reflect the exact DDL from `schema_v2.sql`.

---

#### F-20-02: Non-Atomic Session Resumption Lacks Entry Admission Lock (Medium Severity)
- **Affected Artifact**: [`CoreService::resume_session`](../../crates/sentra-core/src/service/core.rs#L317-L444).
- **Analysis**:
  `CoreService::resume_session` orchestrates resumption across multiple independent transactions:
  1. `list_tasks(session_id)` (Transaction 1)
  2. `list_attempts_for_session(session_id)` (Transaction 2)
  3. Loop over attempts:
     - `mark_attempt_uncertain(...)` / `confirm_not_started(...)` (Independent Transaction per attempt)
     - `update_task_state(...)` (Independent Transaction per task)
  4. `advance_session_epoch(...)` (Final Transaction, acquiring exclusive admission lock)
  5. `transition_session(...)` (Optional Transaction if Paused)
  
  Crucially, `resume_session` **does not acquire `session_admission(session_id, true)` at entry**.
- **Exploit / Failure Scenario**:
  - *Scenario 1 (Crash Window)*: If the process is terminated after reconciling attempt 1 of 3, but before `advance_session_epoch`, attempt 1 is marked `Uncertain` under epoch $N$, while the session remains at epoch $N$. A subsequent worker action on attempt 2 or 3 can proceed under epoch $N$ before resumption is retried.
  - *Scenario 2 (Concurrent Resumption Race)*: Two processes calling `resume_session` concurrently both read the same active attempt list. The winner commits state change; the loser's subsequent `WHERE state = ...` returns 0 modified rows, failing abruptly with `ServiceError::Persistence(Conflict)` instead of serializing cleanly.
  - *Scenario 3 (Live Worker Blocking Advance)*: If an active worker holds an open `PreparedExecution` (holding a shared lock on `.session-<id>.lock`), step 3 (`advance_session_epoch`) calls `session_admission(..., true)` which returns `ContextBusy`. Resumption fails with `ContextBusy`, leaving all earlier attempt state transitions committed under the old un-advanced generation!
- **Required Remediation**:
  1. Acquire `session_admission(session_id, true)` at the very beginning of `resume_session`.
  2. Wrap the entire reconciliation (attempt updates, task updates, epoch increment, session transition) in a single SQLite transaction, or define an explicit `RECOVERING` session state.

---

#### F-20-03: Unsettled Budget Reservations on `ResultRecorded` (Medium Severity)
- **Affected Artifact**: [`record_result`](../../crates/sentra-core/src/persistence/repository.rs#L1559-L1619).
- **Analysis**:
  `record_result` commits the outcome to `attempts` (`state = 'RESULT_RECORDED'`, `terminal_outcome`, `settled_at`), but **does not touch `budget_reservations`**.
  The reservation remains in state `RESERVED` with `actual_cost_micro_usd = NULL`.
  Because `budget_used` computes:
  ```sql
  SELECT COALESCE(SUM(COALESCE(actual_cost_micro_usd,reserved_cost_micro_usd)),0) FROM budget_reservations WHERE session_id=?1
  ```
  The full `reserved_cost_micro_usd` continues to be held against the session budget indefinitely.
- **Exploit / Failure Scenario**:
  If the application crashes or fails after `record_result` before an explicit call to `authority.reconcile_final_budget`, the attempt is in `ResultRecorded`. On restart, `resume_session` ignores `ResultRecorded` attempts:
  ```rust
  AttemptState::ResultRecorded | AttemptState::Uncertain | AttemptState::NotStartedConfirmed => {
      // Terminal attempt states are already reconciled
  }
  ```
  The reservation is never finalized, and the unused delta between actual spend and reserved ceiling is permanently locked, artificially exhausting the session budget.
- **Required Remediation**:
  Allow `record_result` to accept an optional actual cost and settle the associated reservation within the same transaction, or have `resume_session` detect terminal attempts whose reservation is still `actual_cost_micro_usd IS NULL`.

---

#### F-20-04: Missing Fencing Epoch Check in `confirm_running` and `record_result` (Low Severity)
- **Affected Artifact**: [`confirm_running`](../../crates/sentra-core/src/persistence/repository.rs#L1511-L1555), [`record_result`](../../crates/sentra-core/src/persistence/repository.rs#L1559-L1619).
- **Analysis**:
  In `record_release`, the repository explicitly verifies:
  ```rust
  if !session.state.allows_execution() || snapshot.generation != attempt.fencing_epoch {
      return Err(error(Kind::ContextMismatch));
  }
  ```
  However, `confirm_running` and `record_result` read the snapshot but omit the `snapshot.generation != attempt.fencing_epoch` check.
- **Exploit / Failure Scenario**:
  Both functions rely on optimistic state matching (`WHERE (state='RUNNING_CONFIRMED' OR state='RELEASE_RECORDED')`). If an attempt was NOT reconciled during an epoch bump, a delayed worker message could confirm execution or record results under a newer generation.
- **Required Remediation**:
  Add `if snapshot.generation != attempt.fencing_epoch { return Err(error(Kind::ContextMismatch)); }` to both methods for defense-in-depth.

---

#### F-20-05: Semantic Ambiguity of `CANCELLED` Reservation State (Low Severity)
- **Affected Artifact**: [`mark_attempt_uncertain`](../../crates/sentra-core/src/persistence/repository.rs#L1647) vs [`confirm_not_started`](../../crates/sentra-core/src/persistence/repository.rs#L1706).
- **Analysis**:
  Both methods set `budget_reservations.state = 'CANCELLED'`:
  - `confirm_not_started`: `state = 'CANCELLED'`, `actual_cost_micro_usd = 0` (funds released).
  - `mark_attempt_uncertain`: `state = 'CANCELLED'`, `actual_cost_micro_usd = NULL` (full funds held).
- **Exploit / Failure Scenario**:
  Any query or external report inspecting `state = 'CANCELLED'` without checking `actual_cost_micro_usd IS NULL` will misinterpret held uncertain reservations as free/cancelled reservations.
- **Required Remediation**:
  Document this invariant explicitly in the database dictionary, or introduce a distinct state (e.g. `'UNCERTAIN_HOLD'`).

---

#### F-20-06: Silent Error Suppression on Task State Update & Stale Report Sequence (Low Severity)
- **Affected Artifact**: [`CoreService::resume_session`](../../crates/sentra-core/src/service/core.rs#L359-L369).
- **Analysis**:
  1. `let _ = self.repository.update_task_state(...)` silently discards errors during task blocking.
  2. `pending_tasks` is collected from `list_tasks` at line 334, *before* attempts are reconciled. Any task transitioned to `Blocked` during attempt reconciliation is still reported in `report.pending_tasks`.
- **Exploit / Failure Scenario**:
  If task state update fails, the task remains `InProgress` or `Pending` without warning. Callers receiving `SessionResumeReport` receive a stale snapshot of `pending_tasks`.
- **Required Remediation**:
  Propagate errors from `update_task_state` (or record failure in the report), and collect `pending_tasks` / `blocked_tasks` after attempt reconciliation.

---

## 3. Verified Invariants and Supporting Tests

The following critical security and correctness invariants were verified by direct code inspection and automated test execution:

| Invariant | Supporting Tests | Analysis |
| --- | --- | --- |
| **Strict Forward State Machine** | `test_durable_dispatch_full_lifecycle`, `test_task_lifecycle_and_invariants` | Illegal backward or skip transitions (e.g. `Recorded` $\rightarrow$ `RunningConfirmed`) are rejected by check constraints and repository validation. |
| **Fencing Epoch Invalidation on Release** | `test_fencing_epoch_invalidation_prevents_stale_release` | Advancing session epoch causes stale `record_release` to fail closed with `ContextMismatch`. |
| **Conservative Budget Hold on Interruption** | `test_post_release_interruption_marks_uncertain_and_holds_budget` | Interrupted attempts transition to `Uncertain`; `actual_cost = NULL` keeps the full reservation active in `budget_used`. |
| **Clean Budget Release on Cancellation** | `test_pre_release_cancellation_confirms_not_started_and_releases_budget` | Unreleased attempts transition to `NotStartedConfirmed`; `actual_cost = 0` cleanly deducts reserved spend from `budget_used`. |
| **Terminal Session Protection** | `test_terminal_session_cannot_be_resumed` | Attempting to resume `Completed` or `Cancelled` sessions fails closed with `InvalidStateTransition`. |
| **Down-Level Older Writer Rejection** | `test_older_writer_rejected_on_newer_schema` | Databases with `user_version > 2` fail closed with `NewerSchema`, preventing down-level corruption. |
| **V1-to-V2 Data Preservation** | `test_schema_v1_to_v2_transactional_migration_preserves_data` | Existing sessions, snapshots, audits, and approvals from V1 survive migration intact. |
| **Docker Host Volume Isolation** | Inspection of `scripts/docker-test.ps1` | Host repository mounted `:ro`; build binaries isolated in `sentra_cargo_target` named volume. |

---

## 4. Missing Test Coverage

The existing 10 tests in `crates/sentra-core/tests/durable_dispatch_tests.rs` cover the primary happy paths and logical transitions. However, the following adversarial edge-case tests are missing:

1. **Real Process Kill (`kill -9`) During Dispatch**:
   - *Missing Invariant*: Hard process termination between `ReleaseRecorded` and external worker start, or between worker acknowledgment and `RunningConfirmed`, must leave the SQLite database recoverable and restartable.
2. **Concurrent `resume_session` Invocations**:
   - *Missing Invariant*: Two simultaneous processes calling `resume_session(session_id)` must either serialize cleanly or fail with a typed admission error without leaving half-reconciled states.
3. **Mid-Resumption Interruption**:
   - *Missing Invariant*: Crashing after `mark_attempt_uncertain` but before `advance_session_epoch` must be safely resolvable by a subsequent `resume_session` call.
4. **Fencing Invalidation on `confirm_running` and `record_result`**:
   - *Missing Invariant*: Stale attempts from older epochs must be rejected if presented to `confirm_running` or `record_result`.
5. **Partial Migration Failure Rollback**:
   - *Missing Invariant*: A failure occurring halfway through `schema_v2.sql` must roll back completely to V1 without leaving orphan tables.

---

## 5. Explicitly Unverified Guarantees

The following properties are **NOT established** by Increment 2.0 and must not be claimed:
- **No Exactly-Once External Execution**: Sentra guarantees *at-most-once* release before recording, but cannot guarantee that an external worker did not partially execute if interrupted post-release (`Uncertain` boundary).
- **No Automatic Retries**: Sentra deliberately does not auto-retry `Uncertain` attempts; human operator review is required.
- **No True Antivirus Immunity for Virtual Storage**: While host repository files are protected from Kaspersky, files inside Docker Desktop's WSL2 virtual disk (`vhdx`) remain subject to host antivirus inspection if configured to scan virtual disks.
- **No Cryptographic Content Tamper-Proofing**: Content digests in manifests and attempts use non-cryptographic placeholders / length checks pending the Blocked SHA-256 dependency decision.
- **No Power-Loss Durability**: Power-loss fsync durability on NTFS remains unvalidated.

---

## 6. Readiness for Subsequent Phase 1 Increments

### Conclusion: SAFE WITH CONDITIONS

Increment 2.0 is **safe to serve as the persistence and test foundation** for the next Phase 1 increment, provided that:
1. **Condition 1 (Documentation)**: `docs/phase1/INCREMENT_2_0_IMPLEMENTATION.md` is updated to reconcile F-20-01, replacing the inaccurate DDL description with the canonical `schema_v2.sql` schema.
2. **Condition 2 (Concurrency Boundary)**: Multi-process worker dispatch is not enabled until F-20-02 (entry admission lock for `resume_session`) is remediated.
3. **Condition 3 (Budget Accounting)**: Any task execution engine built on top of `record_result` must explicitly call `authority.reconcile_final_budget` to avoid leaking reservation capacity (F-20-03).
4. **Phase Boundary Reaffirmation**: **Phase 1 remains NOT APPROVED; Phase 2 is STRICTLY UNAUTHORIZED; untrusted target execution remains fail-closed.**
