# Sentra Phase 1 — Increment 5.6.2: Core Service Authorization, Budget Ordering & Settlement Reliability Hardening Report

## 1. Executive Summary & Phase Boundary Assertions

Increment 5.6.2 implements targeted security and reliability hardening for the Core Engine Service layer (`sentra_core::service`), resolving all three findings identified during the independent Increment 5.6.1 review:
- **F-561-01** (High Severity): Missing mandatory policy evaluation and classification-floor enforcement in `CoreService::execute_task()`.
- **F-561-02** (Medium Severity): Single-use approval grant consumption before budget reservation, causing unnecessary grant burning on budget exhaustion.
- **F-561-03** (Medium Severity): Silently ignored budget settlement failures in execution and evidence verification failure handlers.

### 1.1 Strict Boundary Assertions
1. **Phase 1 Boundary Preserved**: Phase 1 remains active; Phase 2 has **NOT** started. Untrusted target workloads remain strictly fail-closed (`ExecutionError::untrusted_workload_disabled()`). Dedicated Hyper-V VM isolation and host-to-guest communication pathways remain unvalidated and disabled.
2. **Zero Insecure Fallbacks**: No host process execution (`std::process::Command`), Windows `CreateProcessW`, Docker daemon, or WSL2 fallback execution paths exist in production or synthetic backends.
3. **Offline Cargo Operation**: All compilation, linting, and testing operations were executed strictly offline using the pre-existing Cargo cache. Zero external dependencies were fetched or added.
4. **Permanent Git Policy**: Zero commits, pushes, tags, stashes, rebases, or branch mutations were performed. All modifications remain unstaged in the working tree.

---

## 2. Base Git State & Working Tree Audit

- **Branch**: `develop`
- **Initial HEAD Commit**: `c4ab5e7 Document core service security review` (Author: `Taiizor`, 2026-11-06T01:58:34+03:00)
- **Modified Production Files**:
  - `crates/sentra-core/src/persistence/error.rs`: Added `PersistenceError::from_kind` helper.
  - `crates/sentra-core/src/persistence/mod.rs`: Re-exported `PrepareExecutionRequest`.
  - `crates/sentra-core/src/persistence/model.rs`: Added `Clone, Debug, PartialEq` to `ApprovalIntent`.
  - `crates/sentra-core/src/persistence/repository.rs`: Added `PrepareExecutionRequest`, atomic `reserve_budget_and_consume_approval()`, and `budget_used()` accessor.
  - `crates/sentra-core/src/policy/approval.rs`: Added `ApprovalBroker::set_session_context()` to enable authoritative session context synchronization.
  - `crates/sentra-core/src/policy/engine.rs`: Added `PolicyEngine::register_session_context()` delegating to broker context registration.
  - `crates/sentra-core/src/service/core.rs`: Enforced classification-floor assertions, synchronized session context, invoked mandatory policy evaluation, bound atomic budget reservation and approval consumption, and handled compound settlement errors.
  - `crates/sentra-core/src/service/error.rs`: Added compound error kinds `ExecutionWithSettlementFailure` and `EvidenceWithSettlementFailure`, `secondary_error` field, constructors, and predicates.
  - `crates/sentra-core/tests/service_tests.rs`: Added 6 new integration tests verifying F-561-01, F-561-02, and F-561-03 remediations (expanding service test suite from 13 to 19 tests).

---

## 3. Targeted Security Findings Remediation

### 3.1 F-561-01: Mandatory Policy Evaluation & Classification-Floor Enforcement

#### Defect Analysis
In Increment 5.6, `CoreService::execute_task()` bypassed direct `PolicyEngine::evaluate()` invocation and classification floor assertions, checking only `req.action.is_sensitive() || req.scope.is_untrusted()`. Consequently:
1. Actions requested with a security classification strictly lower than the session floor (`req.classification < session.classification_floor`) were not rejected at dispatch.
2. Actions not recognized by the policy engine (e.g. malformed or malicious custom actions) bypassed default-deny rules if an approval grant was supplied or if marked non-sensitive.
3. Information flow violations (such as Bell-LaPadula write-downs) were not evaluated at the dispatch boundary.

#### Remediation Architecture
1. **Classification Floor Assertion**: At the top of `CoreService::execute_task()`, the request classification is strictly checked against the authoritative persistent floor:
   ```rust
   if req.classification < session.classification_floor {
       return Err(ServiceError::policy_denied(format!(
           "Requested classification ({:?}) is below the session classification floor ({:?})",
           req.classification, session.classification_floor
       )));
   }
   ```
2. **Context Synchronization**: In order for `PolicyEngine` to validate dynamic session rules, `PolicyEngine::register_session_context()` and `ApprovalBroker::set_session_context()` were introduced, syncing the authoritative session metadata, revision, and classification floor before evaluation:
   ```rust
   let _ = self.policy_engine.register_session_context(
       &session.metadata,
       &session.target_revision,
       session.classification_floor,
   );
   ```
3. **Mandatory Policy Evaluation**: `CoreService::execute_task()` calls `self.policy_engine.evaluate()` unconditionally before any budget reservation or execution dispatch:
   ```rust
   let policy_decision = self.policy_engine.evaluate(
       &session.metadata,
       req.classification,
       &req.action,
       None,
       &self.clock,
   );
   match policy_decision {
       PolicyDecision::Denied { reason } => {
           return Err(ServiceError::policy_denied(reason.to_string()));
       }
       PolicyDecision::NeedsApproval { request, .. } => {
           if req.grant.is_none() {
               return Err(ServiceError::policy_denied(format!(
                   "Action '{}' requires an approval grant: {}",
                   req.action.action_name(),
                   request.explanation
               )));
           }
       }
       PolicyDecision::Granted => {
           let requires_approval = req.action.is_sensitive() || req.scope.is_untrusted();
           if requires_approval && req.grant.is_none() {
               return Err(ServiceError::policy_denied(format!(
                   "Action '{}' requires an approval grant",
                   req.action.action_name()
               )));
           }
       }
   }
   ```

#### Verification Evidence
- `test_execute_task_enforces_classification_floor_rejection`: Rejects requests where `classification < session.classification_floor`.
- `test_execute_task_enforces_policy_engine_denial_for_unknown_operation`: Rejects unregistered actions with `ServiceErrorKind::PolicyDenied`.
- `test_execute_task_enforces_policy_denial_on_information_flow_violation`: Rejects Bell-LaPadula write-downs (e.g. exporting Secret data to Public destination) even if an approval grant is provided.

---

### 3.2 F-561-02: Atomic Budget Reservation & Single-Use Approval Consumption

#### Defect Analysis
In Increment 5.6, approval consumption occurred in SQLite transaction 1 (`consume_approval`), while budget reservation occurred in SQLite transaction 2 (`reserve_budget`). If transaction 2 failed due to budget exhaustion (`BudgetExceeded`), transaction 1 had already permanently committed `state='CONSUMED'` in the database. The operator's single-use approval grant was permanently burned without any task execution taking place.

#### Remediation Architecture
1. **Atomic Request Representation (`PrepareExecutionRequest`)**:
   Encapsulates all reservation parameters and optional approval grant/intent:
   ```rust
   #[derive(Clone, Debug)]
   pub struct PrepareExecutionRequest<'a> {
       pub reservation_id: Identifier,
       pub session_id: SessionId,
       pub model_id: &'a str,
       pub amount: CostUsd,
       pub grant_and_intent: Option<(&'a PersistentApprovalGrant, &'a ApprovalIntent<'a>)>,
       pub reservation_event: EventId,
       pub consumption_event: EventId,
   }
   ```
2. **Single SQLite Write Transaction (`reserve_budget_and_consume_approval`)**:
   Executed inside `self.manager.write(|tx| ...)`:
   - **Step 1: In-Transaction Approval Validation**: Validates grant seal, stored hash digest, session identity, context generation, target revision, action parameters, expiration time, and `ISSUED` state.
   - **Step 2: Session & Budget Limit Validation**: Reads active session snapshot; verifies session is not in terminal state; verifies cumulative spend + reserved amount does not exceed `budget_limit_micro_usd`.
   - **Step 3: Budget Reservation Execution**: Inserts row into `budget_reservations` with status `RESERVED` and emits `BudgetReserved` audit event.
   - **Step 4: Approval Consumption Execution**: If an approval grant is present, atomically executes `UPDATE approval_requests SET state='CONSUMED' WHERE ...` and emits `ApprovalConsumed` audit event.
   - **Atomicity & Rollback Guarantees**: If budget check fails at Step 2 (`BudgetExceeded`), SQLite rolls back the entire transaction. The approval grant remains `ISSUED` and unconsumed, available for a subsequent attempt once the session budget is replenished. If approval validation fails at Step 1 (`ApprovalReused`, `ContextMismatch`), no budget is reserved.

#### Verification Evidence
- `test_budget_exhaustion_does_not_consume_valid_approval_grant`: Verifies that attempting to execute a task requiring an approval grant when session budget is exhausted returns `ServiceErrorKind::BudgetExceeded`, and the approval grant remains valid and consumable in a subsequent execution.
- `test_invalid_approval_grant_leaves_no_budget_reservation`: Verifies that if approval consumption fails, no budget reservation is committed to persistence.

---

### 3.3 F-561-03: Settlement Reliability & Compound Error Propagation

#### Defect Analysis
In Increment 5.6, when execution dispatch or evidence verification failed, `CoreService::execute_task()` invoked `self.repository.settle_budget()`, but silently discarded settlement failures using `let _ = ...`. This created a silent persistence failure mode where database corruptions or locks during settlement were invisible to the caller.

#### Remediation Architecture
1. **Compound Error Representation (`ServiceErrorKind`)**:
   Introduced explicit compound error variants:
   - `ServiceErrorKind::ExecutionWithSettlementFailure`: Execution failed AND subsequent budget settlement failed.
   - `ServiceErrorKind::EvidenceWithSettlementFailure`: Evidence verification failed AND subsequent budget settlement failed.
2. **Secondary Error Preservation (`ServiceError`)**:
   Added `pub secondary_error: Option<String>` to `ServiceError`, along with dedicated constructors:
   ```rust
   pub fn execution_with_settlement_failure(
       primary: impl Into<String>,
       secondary: impl Into<String>,
   ) -> Self
   pub fn evidence_with_settlement_failure(
       primary: impl Into<String>,
       secondary: impl Into<String>,
   ) -> Self
   ```
3. **Helper Predicates & Introspection**:
   - `err.is_execution()`: Returns `true` for standard execution failures or compound execution failures.
   - `err.is_evidence()`: Returns `true` for standard evidence failures or compound evidence failures.
   - `err.has_settlement_failure()`: Returns `true` if a secondary settlement failure occurred.
   - `err.secondary_error()`: Returns an `Option<&str>` for the secondary error message.
4. **Pipeline Error Handling**:
   In `CoreService::execute_task()`, when settling budget after dispatch failure or evidence verification failure, if `settle_budget` returns `Err(settle_err)`, `CoreService` returns the compound error, preserving full forensic visibility of both errors while maintaining conservative budget reservation in persistence.

#### Verification Evidence
- `test_service_error_compound_settlement_failure_contracts`: Validates constructor contracts, error formatting, predicate behavior (`is_execution`, `is_evidence`, `has_settlement_failure`), and secondary error retrieval.

---

## 4. Audit Event Consistency & Crash Invariants

### 4.1 Single-Transaction Audit Invariant
Both `BudgetReserved` and `ApprovalConsumed` audit records are written within the same SQLite transaction:
- If the transaction commits, both audit events are recorded sequentially with authoritative audit sequence numbers.
- If the transaction aborts (due to power failure, process termination, constraint violation, or budget exhaustion), SQLite WAL rollback discards both rows simultaneously. Zero orphan `ApprovalConsumed` or `BudgetReserved` records can be created.

### 4.2 Conservative Budget Accounting Invariant
Under any failure condition (execution failure, timeout, cancellation, or settlement failure), the budget allocation remains bounded:
- In `ExecutionWithSettlementFailure` or `EvidenceWithSettlementFailure`, the reservation remains in `RESERVED` status in the database, ensuring cumulative budget calculations (`budget_used`) treat unconfirmed reservations as spent until an explicit reconciliation or recovery pass.

---

## 5. Cross-Increment Regression Verification

| Subsystem / Phase 1 Increment | Key Invariants Verified | Status |
| :--- | :--- | :--- |
| **Increment 5.2 / 5.2.1**: Domain, Session, Policy | 9-state session lifecycle, Bell-LaPadula information flow, fixed-point `CostUsd`, sequential IDs | **Passed (100%)** |
| **Increment 5.3 / 5.3.1 / 5.3.2**: Workspace Boundaries & Approval Binding | Canonical root verification, symlink/junction quarantine, exact-operation binding, parameter tamper resistance | **Passed (100%)** |
| **Increment 5.4 / 5.4.1 / 5.4.2 / 5.4.3**: SQLite Persistence Foundation | WAL mode, synchronous=FULL, foreign keys, rollback retry, in-place quarantine, `SettlementStatus` | **Passed (100%)** |
| **Increment 5.5 / 5.5.1**: Execution Engine & Verifier | Fail-closed untrusted target execution, synthetic fixture isolation, 50 MiB envelope bounds | **Passed (100%)** |
| **Increment 5.6 / 5.6.1**: Core Service & Invariant Validation | Result validation (F-551-01), correlation check (F-551-05), service harness | **Passed (100%)** |
| **Increment 5.6.2**: Authorization, Budget & Settlement Hardening | Policy evaluation at execution boundary (F-561-01), atomic budget/approval (F-561-02), compound settlement errors (F-561-03) | **Passed (100%)** |

---

## 6. Exact Test Inventory & Verification Evidence

### 6.1 Toolchain Commands Executed
All operations were executed offline without fetching dependencies:

1. **Rustfmt Check**:
   ```
   cargo fmt --all -- --check
   ```
   *Result*: Clean (exit 0, 0 diffs).

2. **Cargo Compilation Check**:
   ```
   cargo check --workspace --all-targets --all-features --offline
   ```
   *Result*: Clean (exit 0, 0 errors, 0 warnings).

3. **Clippy Lint Verification**:
   ```
   cargo clippy --workspace --all-targets --all-features --offline -- -D warnings
   ```
   *Result*: Clean (exit 0, 0 warnings across all targets and features).

4. **Automated Workspace Test Suite**:
   ```
   cargo test --workspace --offline
   ```
   *Result*: All **222 automated tests** passed (217 runtime tests + 5 compile-fail doctests, 4 ignored, 0 failed).

### 6.2 Test Suite Reconciliation
| Test Binary / Suite | Test Count | Passed | Ignored | Failed |
| :--- | :--- | :--- | :--- | :--- |
| `sentra_core` (unit tests in `src/lib.rs`) | 14 | 14 | 0 | 0 |
| `authorization_tests.rs` | 27 | 27 | 0 | 0 |
| `domain_tests.rs` | 9 | 9 | 0 | 0 |
| `evidence_tests.rs` | 11 | 11 | 0 | 0 |
| `execution_tests.rs` | 8 | 8 | 0 | 0 |
| `persistence_tests.rs` | 43 | 42 | 1 (cross-process test in `Validate.ps1`) | 0 |
| `policy_tests.rs` | 35 | 35 | 0 | 0 |
| `security_tests.rs` | 10 | 10 | 0 | 0 |
| `service_tests.rs` | 19 | 19 (was 13, +6 new tests) | 0 | 0 |
| `session_tests.rs` | 5 | 5 | 0 | 0 |
| `workspace_tests.rs` | 40 | 37 | 3 (dedicated fixtures in `Validate.ps1`) | 0 |
| `Doc-tests sentra_core` | 5 | 5 | 0 | 0 |
| **Total Automated Workspace Tests** | **226** | **222** | **4** | **0** |

### 6.3 Dedicated PowerShell Validation Suites
All three platform validation scripts executed and passed with 100% success:

1. **Persistence Validation (`experiments/phase1/persistence/Validate.ps1`)**:
   - Total Checks: **13 / 13 Passed** (exit 0).
   - Validates WAL checkpoints, foreign-key checks, crash recovery, and multi-process concurrency.
   - Result artifact: `experiments/phase1/persistence/results/1793920705809.json`.

2. **Authorization Validation (`experiments/phase1/authorization/Validate.ps1`)**:
   - Total Checks: **13 / 13 Passed** (exit 0).
   - Validates grant binding regressions, A-to-B probe, concurrent winner races, and receipt privacy.
   - Result artifact: `experiments/phase1/authorization/results/1793920732438.json`.

3. **Workspace Validation (`experiments/phase1/workspace/Validate.ps1`)**:
   - Total Checks: **11 / 11 Passed** (exit 0).
   - Validates 10,000-file traversal benchmark, Windows NTFS junction quarantine, and ACL deny fixtures.
   - Result artifact: `experiments/phase1/workspace/results/1793920760476.json`.

---

## 7. Remaining Risks & Phase Boundary Confirmation

1. **Phase 2 Status**: Phase 2 remains **NOT authorized**. Untrusted target code execution remains permanently disabled fail-closed (`ExecutionError::untrusted_workload_disabled()`).
2. **Dedicated Isolation**: VM-level Hyper-V worker isolation, worker-to-host gRPC/vsock communication, and guest filesystem boundaries are deferred to Phase 2.
3. **Repository Status**: All changes remain unstaged in the local working tree. No Git commits, tags, pushes, pulls, or branch modifications were executed, adhering strictly to the permanent Git policy.
