# Increment 2.3 — Result Admission and Settlement

Date: 2026-11-08. Status: **Implemented and empirically verified via Docker container & Windows host**, ready for owner review. Phase 1 is incomplete. Phase 2 has not started and remains unauthorized. Untrusted target execution remains fail-closed. Permanent Git policy preserved.

---

## 1. Executive Summary

Continuing the product-focused Phase 1 roadmap ([DEVELOPMENT_DIRECTION_REVIEW.md](../../DEVELOPMENT_DIRECTION_REVIEW.md), [ROADMAP.md](../../ROADMAP.md)), Increment 2.3 implements **Result Admission and Settlement** (`RM-3`, `F-14`, `R1–R7`).

Following the completion of Increment 2.0 (Schema V2 and continuation state machine), Increment 2.1 (Input manifests and SHA-256 content hashing), and Increment 2.2 (Bounded evidence storage and CAS `BlobStore`), Increment 2.3 bridges execution attempts with authoritative task state and budget settlement:

1. **Atomic Result and Task Progression**:
   - Enhanced `Repository::record_result` to atomically advance the associated task in the `tasks` table within the same write transaction:
     - `AttemptOutcome::Completed` $\rightarrow$ `TaskState::Completed` (with `completed_at` timestamp).
     - `AttemptOutcome::Failed | AttemptOutcome::TimedOut` $\rightarrow$ `TaskState::Failed` (with `completed_at` timestamp).
     - `AttemptOutcome::Cancelled` $\rightarrow$ `TaskState::Cancelled` (with `completed_at` timestamp).
   - Atomic budget settlement is preserved (`F-20-03` / `F-20-05`), settling the reservation to `SETTLED` or releasing unused amounts.
2. **Authoritative State Transition Invariants**:
   - At the persistence layer (`Repository::record_result`), an attempt can only transition to `ResultRecorded` from active execution states (`RunningConfirmed` or `ReleaseRecorded`). Any call on an already terminal attempt fails closed with `Kind::Conflict`, preserving the strict state machine transitions certified by Increment 2.0.1.
3. **Service-Level Result Admission Protocol (`CoreService::admit_task_result`)**:
   - Structured request parameters via `AdmitResultRequest<'a>` with strict typed validation (`SessionId`, `AttemptId`, `AttemptOutcome`, `exit_code`, `ResourceUsage`, `evidence_envelopes`, `actual_cost`).
   - Verifies session non-terminal state (`InvalidState` on terminal sessions).
   - Verifies all emitted evidence envelopes structurally via `EvidenceVerifier`.
   - Persists evidence envelopes to the configured `BlobStore` (from Increment 2.2) and aggregates content-addressed digests (`BlobId`).
   - Encodes exit codes, resource metrics, and evidence digests into canonical `terminal_details_json`.
4. **Replay Determinism and Duplicate No-Op**:
   - `CoreService::admit_task_result` inspects existing attempt state before mutating storage or audit trails.
   - When an attempt has already achieved `ResultRecorded`:
     - If the submitted outcome, exit code, details, and actual cost match the recorded result exactly, the call succeeds idempotently as a duplicate no-op (`Ok(attempt)`), with **zero** secondary budget deduction and **zero** duplicate audit logs.
     - If any attribute conflicts (e.g. conflicting outcome, modified exit code, or differing actual cost), the admission fails closed with `ServiceErrorKind::InvalidState`.
5. **Comprehensive Integration Testing & Dual Platform Verification**:
   - Authored 13 dedicated integration tests in `crates/sentra-core/tests/result_admission_tests.rs`.
   - Verified 100% pass rate in the isolated Linux Docker container (all 12 suites, 168 tests passed, 0 clippy warnings under `-D warnings`, 0 formatting errors).
   - Verified 100% pass rate on the Windows 11 host (all 13 `result_admission_tests` pass, all workspace tests pass).

---

## 2. Requirements & Traceability Matrix

| Identifier | Source Requirement | Implementation Deliverable | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **RM-3** | Evidence Admission & Retention | `BlobStore` publication, digest linking in `terminal_details_json`, quota enforcement | `test_admit_task_result_core_service_integration_with_blobs` |
| **F-14** | Atomic Result and Settlement | Atomic `attempts` + `tasks` + `budget_reservations` + audit in single SQLite transaction | `test_record_result_atomic_transition_and_task_completion` |
| **R1** | Task Completion Transition | Attempt `Completed` $\rightarrow$ Task `Completed` + `completed_at` | `test_record_result_atomic_transition_and_task_completion` |
| **R2** | Task Failure Transition | Attempt `Failed` or `TimedOut` $\rightarrow$ Task `Failed` + `completed_at` | `test_record_result_atomic_transition_on_failure_and_timeout` |
| **R3** | Task Cancellation Transition | Attempt `Cancelled` $\rightarrow$ Task `Cancelled` + `completed_at` | `test_record_result_atomic_transition_on_cancellation` |
| **R4** | Replay Determinism | Identical result re-submission succeeds idempotently without double billing or duplicate audit | `test_admit_task_result_exact_duplicate_is_idempotent_no_op`, `test_admit_task_result_replay_determinism` |
| **R5** | Conflict Rejection | Conflicting outcome, exit code, or cost strictly rejected | `test_admit_task_result_conflicting_outcome_denied`, `test_admit_task_result_conflicting_details_denied`, `test_admit_task_result_conflicting_cost_denied` |
| **R6** | Attempt Precondition Check | `record_result` fails closed on `Uncertain` or `NotStartedConfirmed` attempts | `test_record_result_on_uncertain_attempt_denied_with_conflict`, `test_record_result_on_not_started_confirmed_denied_with_conflict` |
| **R7** | Terminal Session Guard | Terminal session rejects result admission fail-closed | `test_admit_task_result_terminal_session_fails_closed` |

---

## 3. Implementation Details

### 3.1 Repository Atomic Task & Result Transition (`crates/sentra-core/src/persistence/repository.rs`)

`Repository::record_result` executes within an exclusive SQLite write transaction (`self.manager.write`):
1. Verifies attempt exists and is in `RunningConfirmed` or `ReleaseRecorded`.
2. Validates fencing epoch equality against active session `context_generation` (`Kind::ContextMismatch`).
3. Updates `attempts`: sets `state = 'RESULT_RECORDED'`, `terminal_outcome`, `terminal_details_json`, `settled_at`.
4. Atomically settles associated budget reservation:
   - Sets reservation `state = 'SETTLED'`, `actual_cost_micro_usd = actual_cost`, and `settled_at`.
   - Emits authoritative `BudgetSettled` audit event.
5. Updates parent task in `tasks` table:
   - If outcome is `Completed` $\rightarrow$ `state = 'COMPLETED'`, `completed_at = now`.
   - If outcome is `Failed` or `TimedOut` $\rightarrow$ `state = 'FAILED'`, `completed_at = now`.
   - If outcome is `Cancelled` $\rightarrow$ `state = 'CANCELLED'`, `completed_at = now`.
   - Sets `updated_at = now`.
6. Emits authoritative `AttemptResultRecorded` audit event.

### 3.2 Service-Level Admission Protocol (`crates/sentra-core/src/service/core.rs`)

`CoreService::admit_task_result` accepts `AdmitResultRequest<'a>`:
1. **Session Gate**: Asserts session exists and is not terminal.
2. **Admission Lease**: Acquires `session_admission(session_id, false)` for cross-process serialisation.
3. **Replay Determinism Check**:
   - Queries `get_attempt(req.attempt_id)`.
   - If already in `ResultRecorded`:
     - Asserts `terminal_outcome == req.outcome` (fails with `InvalidState` on mismatch).
     - Asserts recorded exit code matches `req.exit_code` (fails with `InvalidState` on mismatch).
     - Asserts recorded reservation actual cost matches `req.actual_cost` (fails with `InvalidState` on mismatch).
     - Returns `Ok(existing_attempt)` immediately without touching storage or audit log.
4. **Evidence Ingestion**:
   - For each envelope, performs structural bounds verification via `evidence_verifier`.
   - If `BlobStore` is configured, stages and commits envelope to CAS storage via `store.put_evidence_envelope`.
   - Collects `BlobId` content digests.
5. **Details Packaging & Persistence**:
   - Constructs JSON payload containing exit code, resource usage, and `evidence_digests`.
   - Calls `repository.record_result(...)`.

---

## 4. Test Suite Matrix (`crates/sentra-core/tests/result_admission_tests.rs`)

| Test Function | Invariant Established |
| :--- | :--- |
| `test_record_result_atomic_transition_and_task_completion` | ResultRecorded transitions attempt, settles budget reservation, updates task to `COMPLETED`, sets `completed_at`, emits audit. |
| `test_record_result_atomic_transition_on_failure_and_timeout` | Outcomes `Failed` and `TimedOut` transition task state to `FAILED` with `completed_at`. |
| `test_record_result_atomic_transition_on_cancellation` | Outcome `Cancelled` transitions task state to `CANCELLED` and marks reservation `CANCELLED`. |
| `test_admit_task_result_exact_duplicate_is_idempotent_no_op` | Duplicate admission returns identical attempt record, zero secondary budget spend, zero new audit rows. |
| `test_admit_task_result_conflicting_outcome_denied` | Attempting to replay an attempt with conflicting terminal outcome fails closed with `InvalidState`. |
| `test_admit_task_result_conflicting_details_denied` | Attempting to replay an attempt with differing exit code fails closed with `InvalidState`. |
| `test_admit_task_result_conflicting_cost_denied` | Attempting to replay an attempt with differing actual cost fails closed with `InvalidState`. |
| `test_record_result_terminal_attempt_denied_with_conflict` | Low-level repository rejects duplicate transitions on already terminal attempts with `Kind::Conflict`. |
| `test_record_result_on_uncertain_attempt_denied_with_conflict` | Direct `record_result` on `UNCERTAIN` attempt is rejected with `Kind::Conflict`. |
| `test_record_result_on_not_started_confirmed_denied_with_conflict` | Direct `record_result` on `NOT_STARTED_CONFIRMED` attempt is rejected with `Kind::Conflict`. |
| `test_admit_task_result_core_service_integration_with_blobs` | Full service admission writes evidence to `FileSystemCasBlobStore`, links blob digests into attempt details, settles budget. |
| `test_admit_task_result_replay_determinism` | Repeated `admit_task_result` calls via `CoreService` produce identical timestamps, outcomes, and identifiers. |
| `test_admit_task_result_terminal_session_fails_closed` | Result admission on cancelled or terminal session fails closed with `InvalidState`. |

---

## 5. Verification Results

### 5.1 Docker Linux Container (`scripts/docker-test.ps1 -Mode all`)

```text
>>> Executing: cargo fmt --all -- --check
>>> Success: cargo-fmt (Log: target/reports/cargo-fmt.log)

>>> Executing: cargo check --workspace
>>> Success: cargo-check (Log: target/reports/cargo-check.log)

>>> Executing: cargo clippy --workspace --all-targets --all-features  -- -D warnings
>>> Success: cargo-clippy (Log: target/reports/cargo-clippy.log)

>>> Executing: cargo test --package sentra-core --test domain_tests --test policy_tests --test session_tests --test evidence_tests --test execution_tests --test security_tests --test authorization_tests --test persistence_tests --test durable_dispatch_tests --test manifest_tests --test storage_tests --test result_admission_tests
>>> Success: cargo-test-core-independent (Log: target/reports/cargo-test-core-independent.log)
```
- Total test suites in Docker: 12
- Total tests passed in Docker: 168 (0 failures, 0 ignored, 0 clippy warnings under `-D warnings`)

### 5.2 Windows 11 Host

- `cargo test --package sentra-core --test result_admission_tests`: 13 passed in 0.30s.
- `cargo test --workspace`: All suites passed (unit tests, integration tests, doctests).
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: 0 warnings, clean.
- `cargo fmt --all -- --check`: Clean formatting.

---

## 6. Preserved Repository Boundaries & Invariants

1. **Phase Boundary:** Phase 1 remains **NOT APPROVED**; Phase 2 remains **STRICTLY UNAUTHORIZED**.
2. **Untrusted Target Execution:** Remains strictly **FAIL-CLOSED** via `FailClosedBackend`. No target workload or scanner execution is enabled.
3. **Permanent Git Policy:** Maintained without exception. No agent commits, amends, pushes, pulls, fetches, resets, rebases, or branch changes. All work remains unstaged in the local working tree.
4. **Historical Evidence Preservation:** All historical experiment scripts, raw logs, validation reports, and independent reviews under `experiments/phase1/` and `docs/phase1/` are preserved unmodified.
