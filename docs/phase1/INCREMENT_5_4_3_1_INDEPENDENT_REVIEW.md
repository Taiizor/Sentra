# Independent Persistence Regression & Security Review — Increment 5.4.3.1

Date: 2026-11-06. **Verification-only independent security and regression review complete.**
Zero production code modifications, Cargo manifest changes, or dependency downloads were performed. All pre-existing working-tree changes and external commits were preserved.

---

## 1. Executive Summary & Review Verdict

This independent review evaluated the Increment 5.4.3 persistence security remediations against the original findings **F-542-01** (Ambiguous Budget Settlement Status) and **F-542-04** (Missing Runtime Foreign-Key Integrity Validation) identified during the Increment 5.4.2.1 audit.

### Final Readiness Recommendation: **Approved**

- **Critical Findings:** **0**
- **High Findings:** **0**
- **Medium Findings:** **0**
- **Low Findings:** **0**
- **Informational Findings:** **2** (INF-5431-01: Multi-process snapshot window between integrity checks; INF-5431-02: Indefinite retention of unfinalized `UncertainPartial` reservations)

### Disposition of Prior Findings:
1. **F-542-01 (Budget Settlement Ambiguity):** **Resolved & Closed.** The conflating `cancellation_confirmed: bool` parameter in `PersistentApprovalAuthority::settle_budget` has been completely eliminated. It is replaced by the explicit domain enum `SettlementStatus` (`Completed(CostUsd)`, `CancelledWithUsage(CostUsd)`, `CancelledUncertain`, `UncertainPartial`). Successful task completion records verified actual usage without ambiguous cancellation semantics, and conservative upper-bound retention is strictly preserved for uncertain states.
2. **F-542-04 (Missing Foreign-Key Check):** **Resolved & Closed.** `SqliteConnectionManager::integrity_check` now verifies both physical b-tree consistency (`PRAGMA integrity_check(10)`) and relational integrity (`PRAGMA foreign_key_check`). Detected violations return `PersistenceErrorKind::ForeignKeyViolation` and permanently halt the connection manager fail-closed via `must_halt()`. Pre-existing foreign key violations are rejected fail-closed during `open()` and `migration::initialize()`.

---

## 2. Scope and Methodology

The review conducted both exhaustive static source code analysis and empirical test execution across all crates in the workspace:
- **Static Analysis:** Inspected `crates/sentra-core/src/persistence/` (`model.rs`, `repository.rs`, `connection.rs`, `error.rs`, `migration.rs`, `mod.rs`) and `crates/sentra-core/src/persistence/schema_v1.sql`.
- **Dynamic Test Verification:** Executed `cargo fmt`, `cargo check`, `cargo clippy`, `cargo test`, and the three standalone PowerShell validation suites (`experiments/phase1/persistence/Validate.ps1`, `experiments/phase1/authorization/Validate.ps1`, `experiments/phase1/workspace/Validate.ps1`).
- **Invariant Analysis:** Verified all 10 budget settlement invariants and all 10 SQLite integrity invariants under nominal, concurrent, corrupted, and process-failure conditions.

---

## 3. Budget Settlement Review (Remediation of F-542-01)

### 3.1. Analysis of `SettlementStatus` Variants
In `crates/sentra-core/src/persistence/model.rs`, `SettlementStatus` is defined as:
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementStatus {
    Completed(CostUsd),
    CancelledWithUsage(CostUsd),
    CancelledUncertain,
    UncertainPartial,
}
```

Each variant was evaluated against the domain and database state machine:

1. **`Completed(CostUsd)`:**
   - **Transition:** Sets `state = 'SETTLED'`, `actual_cost_micro_usd = Some(cost)`, `settled_at = Some(now)`.
   - **Schema Compliance:** Satisfies `CHECK(state != 'SETTLED' OR (actual_cost_micro_usd IS NOT NULL AND settled_at IS NOT NULL))` in `schema_v1.sql`.
   - **Accounting:** `budget_used` SQL query evaluates `COALESCE(actual_cost_micro_usd, reserved_cost_micro_usd)`. Because `cost <= reserved`, the difference (`reserved - cost`) is immediately released.
   - **Verdict:** Validated. Successful completion no longer requires misrepresenting status as cancelled.

2. **`CancelledWithUsage(CostUsd)`:**
   - **Transition:** Sets `state = 'CANCELLED'`, `actual_cost_micro_usd = Some(cost)`, `settled_at = Some(now)`.
   - **Accounting:** Because actual usage is verified, `budget_used` evaluates to `cost`, releasing the unconsumed difference (`reserved - cost`).
   - **Verdict:** Validated. Confirmed cancellation with verified spend records accurate final usage.

3. **`CancelledUncertain`:**
   - **Transition:** Sets `state = 'CANCELLED'`, `actual_cost_micro_usd = None`, `settled_at = None`.
   - **Accounting:** `actual_cost_micro_usd` remains `NULL`. The SQL `COALESCE(actual, reserved)` expression evaluates to `reserved`.
   - **Verdict:** Validated. Zero unconsumed budget is released; the entire upper bound remains committed.

4. **`UncertainPartial`:**
   - **Transition:** Sets `state = old_state` (retains `'RESERVED'`), `actual_cost_micro_usd = None`, `settled_at = None`.
   - **Accounting:** `actual_cost_micro_usd` remains `NULL`. The full upper bound remains committed.
   - **Verdict:** Validated. Partial unconfirmed spend never releases budget.

### 3.2. Verification of 10 Budget Settlement Invariants

| # | Invariant | Audit Analysis & Verification | Status |
| --- | --- | --- | --- |
| 1 | **Accurate confirmed usage recording** | Unused reservation difference is released only when `status.actual_cost()` returns `Some(cost)`. For uncertain states, `actual_cost()` returns `None` and full reservation remains charged. | **Verified** |
| 2 | **Conservative reservation ceiling** | `CancelledUncertain` and `UncertainPartial` preserve `actual = NULL`, holding the full upper-bound `reserved` against session budget. | **Verified** |
| 3 | **No silent discard of actual usage** | `Completed(cost)` maps directly to `final_actual = Some(cost)`. Eliminates the old bug where `cancellation_confirmed: false` erased `actual`. | **Verified** |
| 4 | **Usage exceeding reservation fails safely** | Evaluated at line 525 of `repository.rs`: `if cost > reserved { return Err(model::invalid()); }`. Also enforced by database CHECK constraint `CHECK(actual_cost_micro_usd <= reserved_cost_micro_usd)`. No negative availability or overflow. | **Verified** |
| 5 | **Repeated settlement rejection** | Line 516 checks `if old_actual.is_some() { return Err(error(Kind::Conflict)); }`. Once settled, any subsequent attempt fails closed with `Conflict`. | **Verified** |
| 6 | **Concurrent settlement consistency** | All settlements run inside `manager.write(|tx| ...)`, which serializes transactions under mutex and executes `BEGIN IMMEDIATE`. Racing transactions see `old_actual.is_some()` on fresh WAL snapshot and fail with `Conflict`. | **Verified** |
| 7 | **Atomic settlement and audit** | The `UPDATE budget_reservations` and `INSERT INTO audit_events` statements occur in the same `ManagedTransaction`. Transaction abort rolls back both changes simultaneously. | **Verified** |
| 8 | **Safe failure on invalid/overflowing amounts** | `CostUsd` is fixed-point micro-dollars (cannot be NaN, negative, or infinite). `model::integer(u64)` ensures values fit in positive signed 64-bit integers. | **Verified** |
| 9 | **Accurate audit details distinguishing status** | Audit payload writes structured JSON: `{"reservation_id": id, "status": status_str, "final_usage_known": bool}`. Event kind is `BudgetSettled` or `BudgetUsageUnknown`. | **Verified** |
| 10 | **Core domain invariants intact** | Approval issuance, single-use consumption, session generation checks, and budget thresholds remain fully functional across all test suites. | **Verified** |

### 3.3. Lifecycle and Finalization of `UncertainPartial`
A critical area of inquiry was the lifecycle of `UncertainPartial`:
- **State Transition:** When `settle_budget` is called with `UncertainPartial`, the row's `actual_cost_micro_usd` remains `NULL`, and `state` remains `'RESERVED'`.
- **Eventual Finalization:** Because `actual_cost_micro_usd` remains `NULL`, line 516 (`if old_actual.is_some()`) evaluates to `false`. Therefore, the reservation remains open to a subsequent `settle_budget` call when the controller or worker delivers a final verdict (`Completed`, `CancelledWithUsage`, or `CancelledUncertain`).
- **Crash & Restart Invariant:** Across process restarts or connection closes, `actual_cost_micro_usd` on disk is `NULL`. Reopening the database and querying `budget_used()` evaluates `COALESCE(NULL, reserved_cost_micro_usd)`. The upper bound cannot accidentally be released or leaked across process restarts.
- **Repeated Calls:** Repeated calls to `UncertainPartial` write an audit event and keep `actual = NULL`. They cannot alter accounting.

---

## 4. SQLite Integrity Review (Remediation of F-542-04)

### 4.1. Architecture of Dual Integrity Checks
In `crates/sentra-core/src/persistence/connection.rs`, `integrity_report` executes:
1. `PRAGMA integrity_check(10)`: Captures physical page and b-tree corruption.
2. `PRAGMA foreign_key_check`: Captures relational constraint violations.

Structured types in `persistence::connection`:
```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignKeyViolation {
    pub table: String,
    pub rowid: i64,
    pub parent: String,
    pub fkid: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegrityReport {
    pub integrity_ok: bool,
    pub foreign_key_violations: Vec<ForeignKeyViolation>,
}
```

### 4.2. Verification of 10 SQLite Integrity Invariants

| # | Invariant | Audit Analysis & Verification | Status |
| --- | --- | --- | --- |
| 1 | **Physical integrity check fail-closed** | `PRAGMA integrity_check(10)` output is compared against `["ok"]`. Any other output sets `integrity_ok = false` and returns `Err(Kind::Integrity)`. | **Verified** |
| 2 | **Foreign-key check execution** | `PRAGMA foreign_key_check` executes and collects all violation rows. Non-empty results return `Err(Kind::ForeignKeyViolation)`. | **Verified** |
| 3 | **Multiple violations reported** | All returned rows are collected into `Vec<ForeignKeyViolation>`. Test `detailed_integrity_check_reports_structured_fk_violations` confirmed multiple violations across different tables are accurately reported without truncation. | **Verified** |
| 4 | **Query failure fail-closed** | SQL prepare/query errors map via `PersistenceError::sql` and fail closed. `integrity_check()` sets `state.halted = true` on any error. | **Verified** |
| 5 | **Manager halts on violation** | `PersistenceError::must_halt()` includes `ForeignKeyViolation`. `state.halted = true` is set. Subsequent `write()`, `settings()`, and `checkpoint()` calls return `Err(Kind::Halted)`. | **Verified** |
| 6 | **Open and migration reject corrupted DB** | `open()` calls `integrity(&connection)?` before reading schema metadata. `migration::initialize()` calls `PRAGMA foreign_key_check` post-migration. Both reject pre-existing violations fail closed. | **Verified** |
| 7 | **Structured report redaction** | `ForeignKeyViolation` exposes only `(table, rowid, parent, fkid)`. No cell data, secrets, or identifiers are logged or leaked. | **Verified** |
| 8 | **No automatic destructive repair** | Statements are read-only. No `REINDEX`, `VACUUM`, or deletion is performed. In-place quarantine preserves `.db`, `-wal`, `-shm`, and `-journal` intact. | **Verified** |
| 9 | **Consistency of checks** | Physical and FK checks execute under `state.lock()`, serializing local operations. Multi-process WAL snapshot behavior was analyzed (see INF-5431-01). | **Verified** |
| 10 | **WAL, rollback, and recovery unchanged** | All WAL durability, crash recovery, and bounded retry invariants verified without regressions. | **Verified** |

---

## 5. Cross-Increment Regression Review

All security invariants established in earlier increments were re-verified:

1. **Approval Grant Binding (5.3.1 / 5.4.2):**
   - In-memory and persistent grants remain bound to `(SessionId, ContextGeneration, TargetRevision, ActionName, CanonicalActionDigest, Classification, ReceiptToken)`.
   - Cross-action A-to-B attacks, cross-session consumption, revision tampering, and replay attempts remain rejected.
   - All 27 authorization regression tests in `tests/authorization_tests.rs` pass.
2. **Atomic Single-Use Grant Consumption (5.2.1 / 5.4.2):**
   - `UPDATE approval_requests SET state = 'CONSUMED' WHERE state = 'ISSUED' AND ...` enforces `changes() == 1`.
   - Concurrent and cross-process tests prove exactly one consumer succeeds; racing consumers receive `Conflict` or `ApprovalReused`.
3. **Explicit Statement Rollback & Error Latch (5.4.2):**
   - Any SQL error latches `ManagedTransaction::failure`. Callers catching errors cannot commit partial work.
4. **Bounded `SQLITE_BUSY_SNAPSHOT` Retry (5.4.2):**
   - Error 517 triggers full transaction restart with fresh snapshot reads and jittered exponential backoff (10–250 ms), capped at 5 attempts.
5. **Crash Durability & In-Place Quarantine (5.4.2):**
   - Subprocess crash tests verify committed rows survive uncorrupted while uncommitted transactions roll back cleanly.
6. **Workspace Containment (5.3):**
   - Reparse point, symlink, and NTFS junction quarantine remains completely unaffected.

---

## 6. Findings Classification Table

| ID | Module / File | Code Path | Severity | Type | Description & Remediation | Blocks Next Step? |
| --- | --- | --- | --- | --- | --- | --- |
| **F-542-01** | `persistence/repository.rs` | `settle_budget` | **Medium** | Design | **Prior finding: Ambiguous settlement parameter.** Resolved via `SettlementStatus` enum in Increment 5.4.3. | **Closed** |
| **F-542-04** | `persistence/connection.rs` | `integrity_check` | **Low** | Observability | **Prior finding: Runtime integrity check omitted foreign keys.** Resolved via `PRAGMA foreign_key_check` and `ForeignKeyViolation` in Increment 5.4.3. | **Closed** |
| **INF-5431-01** | `persistence/connection.rs` | `integrity_report` (lines 247, 258) | **Informational** | Concurrency Limitation | **Multi-process snapshot window between checks:** `PRAGMA integrity_check(10)` and `PRAGMA foreign_key_check` execute as two separate statements outside an explicit read transaction. While local operations are synchronized under `Mutex<State>`, an independent external process writing to the WAL between the two checks could cause them to observe slightly different WAL snapshots. **Remediation:** In future multi-process controller milestones, enclose dual integrity checks in `BEGIN DEFERRED` if snapshot-pinned consistency across external writers is required. | **No** |
| **INF-5431-02** | `persistence/repository.rs` | `settle_budget` (line 533) | **Informational** | Operational Boundary | **Indefinite retention of unfinalized reservations:** If an external worker reports `UncertainPartial` and subsequently crashes without ever reporting a terminal outcome (`Completed` or `Cancelled`), the reservation remains in `RESERVED` state indefinitely, holding the upper bound. This is fail-safe (prevents budget overspend), but requires session-level lease expiry in future orchestration increments. | **No** |

---

## 7. Test Inventory & Reconciliation

### 7.1. Detailed Test Categorization

| Target / Binary | Test Suite Module | Runtime Tests | Compile-Fail Doctests | Ignored Tests | Notes |
| --- | --- | --- | --- | --- | --- |
| `src/lib.rs` | Policy, Workspace, Model, Transaction, Migration | 14 | 0 | 0 | Core unit tests |
| `tests/authorization_tests.rs` | Authorization integration | 27 | 0 | 0 | In-memory grant binding & concurrency |
| `tests/domain_tests.rs` | Domain models | 9 | 0 | 0 | Identifiers, timestamps, classifications |
| `tests/policy_tests.rs` | Policy engine | 9 | 0 | 0 | Rules, classifications, budget limits |
| `tests/security_tests.rs` | Security hardening | 10 | 0 | 0 | Action digest, Bell-LaPadula, UUID |
| `tests/session_tests.rs` | State machine | 5 | 0 | 0 | 9x9 matrix and lifecycle invariants |
| `tests/workspace_tests.rs` | Workspace containment | 37 | 0 | 3 | Default suite (3 fixtures ignored) |
| `tests/persistence_tests.rs` | SQLite persistence | 42 | 0 | 1 | 37 baseline + 5 new Increment 5.4.3 tests; 1 ignored helper |
| `Doc-tests sentra_core` | Compile-fail documentation | 0 | 5 | 0 | Broker & persistence private API invariants |
| **Default `cargo test` Total** | — | **153** | **5** | **4** | Clean exit 0 |
| `workspace/Validate.ps1` Fixtures | Junction, deny-ACL, 10k-files | 3 | 0 | 0 | Run by PowerShell fixture runner |
| **Total Unique Test Suite** | — | **156** | **5** | — | **161 Total Unique Tests** |

### 7.2. Exact Command Execution Results

1. `cargo fmt --all -- --check`: **Exit 0** (clean, no diff)
2. `cargo check --workspace --all-targets --all-features --offline`: **Exit 0** (clean, dev profile)
3. `cargo clippy --workspace --all-targets --all-features --offline -- -D warnings`: **Exit 0** (zero warnings)
4. `cargo test --workspace --offline`: **Exit 0** (153 runtime passed + 5 doctests passed, 4 ignored)
5. `pwsh -NoProfile -File experiments/phase1/persistence/Validate.ps1`: **Exit 0** (13 passed, 0 failed)
6. `pwsh -NoProfile -File experiments/phase1/authorization/Validate.ps1`: **Exit 0** (13 passed, 0 failed)
7. `pwsh -NoProfile -File experiments/phase1/workspace/Validate.ps1`: **Exit 0** (11 passed, 0 failed, 10,000 files benchmarked)

---

## 8. Blocked and Not Tested Items

In compliance with factual reporting rules, the following items remain outside Phase 1 validation scope:
- **Physical Power-Loss Fault Injection:** Simulating OS crash during fsync or mid-commit page writes requires kernel-level fault injection drivers not permitted in Phase 1.
- **ARM64 Native Persistence Validation:** The MSVC host lacks the ARM64 Rust toolchain; testing is strictly validated on x86_64 MSVC.
- **Multi-Process External Controller Orchestration:** While multi-process SQLite concurrency was validated with owned child processes, full daemon-worker orchestration is a Phase 2 objective.

---

## 9. Final Recommendation

### **Recommendation: Approved**

Increment 5.4.3 correctly remediates findings F-542-01 and F-542-04 without introducing regressions. The Core Engine SQLite persistence foundation preserves all security, authorization, isolation, and fail-closed invariants under exhaustive testing.

Sentra Core Engine Foundation is technically verified and ready to proceed to the next increment.
