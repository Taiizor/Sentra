# Persistence Security Findings Remediation — Increment 5.4.3

Date: 2026-11-06. **Persistence security findings remediation complete. Narrowly scoped hardening increment.**
All code modifications were strictly targeted to findings F-542-01 and F-542-04 identified during the independent Increment 5.4.2.1 security audit. Zero new external dependencies, downloads, Cargo manifest changes, or Git mutations were performed.

---

## 1. Executive Summary & Audit Resolution

Increment 5.4.3 resolves the two actionable findings identified in the Increment 5.4.2.1 independent persistence security review:

1. **F-542-01 (Medium Severity — Ambiguous Budget Settlement Status):** Replaced the conflating boolean parameter `cancellation_confirmed: bool` in `PersistentApprovalAuthority::settle_budget` with an explicit domain enum `SettlementStatus`. This resolves the design flaw where successful task completion discarded verified actual usage unless mislabeled as cancelled.
2. **F-542-04 (Low Severity — Missing Runtime Foreign-Key Integrity Validation):** Extended `SqliteConnectionManager::integrity_check()` to execute both `PRAGMA integrity_check(10)` and `PRAGMA foreign_key_check`. Introduced typed violation models (`ForeignKeyViolation`, `IntegrityReport`), added `detailed_integrity_check()` for structured reporting, and introduced `PersistenceErrorKind::ForeignKeyViolation`, which immediately halts the connection manager fail-closed.

All other findings from Increment 5.4.2.1 (F-542-02: lockfile metadata offline flag; F-542-03: process-local quarantine boundary; F-542-05: FNV-1a migration checksum; F-542-06: ephemeral in-memory seal; F-542-07: single-connection read serialization) were assessed as acceptable operational boundaries and documented limitations.

---

## 2. Remediation of Finding F-542-01: Explicit Budget Settlement Status

### 2.1. The Ambiguity & Design Defect
In Increment 5.4.2, the method signature for reconciling budget reservations was:
```rust
// Old signature (Increment 5.4.2):
pub fn settle_budget(
    &self,
    id: Identifier,
    actual: Option<CostUsd>,
    cancellation_confirmed: bool,
    event: EventId,
    clock: &impl Clock,
) -> Result<BudgetRecord, PersistenceError>
```
The internal logic evaluated `let final_actual = if cancellation_confirmed { actual } else { None };`. This created an ambiguous and unsafe design:
- A caller completing a task successfully had to pass `cancellation_confirmed: true` just to ensure `actual` was recorded, semantic nonsense for a non-cancelled task.
- Passing `cancellation_confirmed: false` for a completed task silently discarded `actual`, treating the final usage as unknown.

### 2.2. Architectural Resolution: `SettlementStatus`
In `crates/sentra-core/src/persistence/model.rs`, an explicit domain enum was introduced and re-exported in `persistence::mod`:

```rust
/// Explicit settlement outcome for a budget reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementStatus {
    /// Confirmed successful completion with verified final actual usage.
    /// Unused reservation difference is released from `budget_used`.
    Completed(CostUsd),
    /// Confirmed cancellation with verified final actual usage.
    /// Unused reservation difference is released from `budget_used`.
    CancelledWithUsage(CostUsd),
    /// Confirmed cancellation where final usage could not be verified.
    /// The full upper-bound reservation is retained in `budget_used`.
    CancelledUncertain,
    /// Uncertain completion or unconfirmed partial usage.
    /// Reservation remains active in `RESERVED` state and full upper bound is retained in `budget_used`.
    UncertainPartial,
}

impl SettlementStatus {
    /// Returns the verified actual cost, if final usage is known.
    pub fn actual_cost(&self) -> Option<CostUsd> {
        match self {
            Self::Completed(cost) | Self::CancelledWithUsage(cost) => Some(*cost),
            Self::CancelledUncertain | Self::UncertainPartial => None,
        }
    }

    /// Whether this status represents a confirmed cancellation.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::CancelledWithUsage(_) | Self::CancelledUncertain)
    }

    /// Whether this status confirms completion or cancellation.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::UncertainPartial)
    }
}
```

### 2.3. Settlement Accounting Matrix
`PersistentApprovalAuthority::settle_budget` now requires `SettlementStatus`:

| `SettlementStatus` Variant | SQL `state` | `actual_cost_micro_usd` | `settled_at` | `budget_used` Impact | Audit Event Kind & Status |
| --- | --- | --- | --- | --- | --- |
| `Completed(cost)` | `'SETTLED'` | `Some(cost)` | `Some(now)` | Releases `reserved - cost` immediately | `BudgetSettled` (`"status":"COMPLETED"`) |
| `CancelledWithUsage(cost)` | `'CANCELLED'` | `Some(cost)` | `Some(now)` | Releases `reserved - cost` immediately | `BudgetSettled` (`"status":"CANCELLED_WITH_USAGE"`) |
| `CancelledUncertain` | `'CANCELLED'` | `NULL` | `NULL` | Retains full upper-bound `reserved` | `BudgetUsageUnknown` (`"status":"CANCELLED_UNCERTAIN"`) |
| `UncertainPartial` | `old_state` (`'RESERVED'`) | `NULL` | `NULL` | Retains full upper-bound `reserved` | `BudgetUsageUnknown` (`"status":"UNCERTAIN_PARTIAL"`) |

### 2.4. Invariants Enforced
- **Cap Invariant:** `cost <= reserved`. Supplying an actual cost greater than reserved immediately returns `PersistenceErrorKind::InvalidValue`.
- **Single Settlement Invariant:** Once a reservation is settled (`actual_cost_micro_usd IS NOT NULL`), subsequent settlement attempts return `PersistenceErrorKind::Conflict`.
- **Structured Audit Evidence:** Audit event details include structured fields: `{"reservation_id": id, "status": status_str, "final_usage_known": bool}`.

---

## 3. Remediation of Finding F-542-04: Runtime Foreign-Key Integrity Validation

### 3.1. The Observability Defect
In Increment 5.4.2, `SqliteConnectionManager::integrity_check()` only executed `PRAGMA integrity_check(10)`. While foreign keys were enforced at runtime (`PRAGMA foreign_keys = ON`) and checked during migration initialization, runtime checks omitted `PRAGMA foreign_key_check`. A database corrupted externally (e.g. by another tool with foreign keys disabled) would report "ok" on physical page checks despite relational corruption.

### 3.2. Architectural Resolution
1. **Typed Relational Models:** Added `ForeignKeyViolation` and `IntegrityReport` to `persistence::connection`:
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

   impl IntegrityReport {
       pub fn is_valid(&self) -> bool {
           self.integrity_ok && self.foreign_key_violations.is_empty()
       }
   }
   ```
2. **Dual Integrity Validation:**
   - `SqliteConnectionManager::integrity_check(&self) -> Result<(), PersistenceError>` executes both:
     1. `PRAGMA integrity_check(10)`: If values $\neq$ `["ok"]`, returns `Err(Kind::Integrity)`.
     2. `PRAGMA foreign_key_check`: If non-empty, returns `Err(PersistenceError { kind: Kind::ForeignKeyViolation, sqlite_code: Some(violations.len() as i32), .. })`.
   - `SqliteConnectionManager::detailed_integrity_check(&self) -> Result<IntegrityReport, PersistenceError>` provides complete inspection details for diagnostic tools.
3. **Fail-Closed Halting:**
   - Added `PersistenceErrorKind::ForeignKeyViolation` to `PersistenceErrorKind`.
   - Updated `PersistenceError::must_halt()` to return `true` for `Kind::ForeignKeyViolation`:
     ```rust
     pub(super) fn must_halt(&self) -> bool {
         matches!(
             self.kind,
             PersistenceErrorKind::Integrity
                 | PersistenceErrorKind::RollbackFailed
                 | PersistenceErrorKind::ForeignKeyViolation
         )
     }
     ```
   - Any foreign key failure sets `state.halted = true`, immediately blocking subsequent transactions, settings queries, and writes.
4. **Early Rejection on Database Open:**
   - `SqliteConnectionManager::open(&path, clock)` executes `integrity(&connection)?` upon opening existing files, rejecting any file with pre-existing foreign key violations before applying any operations.
   - `migration::initialize()` returns `Kind::ForeignKeyViolation` if post-migration validation discovers any foreign key inconsistency.

---

## 4. Test Suite and Verification Evidence

### 4.1. New Automated Tests Added
Five new integration tests were added in `crates/sentra-core/tests/persistence_tests.rs`:

1. `budget_settlement_status_completed_releases_difference_and_finalizes`:
   - Verifies `SettlementStatus::Completed(6)` against a 10 micro USD reservation.
   - Asserts state becomes `"SETTLED"`, `actual` is `Some(6)`, and `budget_used` drops from 10 to 6.
   - Asserts repeated settlement fails with `Kind::Conflict`.
   - Verifies audit event contains `"status":"COMPLETED"` and `"final_usage_known":true`.
2. `budget_settlement_status_cancelled_with_usage_and_helpers`:
   - Verifies `SettlementStatus::CancelledWithUsage(5)` against a 15 micro USD reservation.
   - Asserts state becomes `"CANCELLED"`, `actual` is `Some(5)`, and `budget_used` drops to 5.
   - Verifies all helper methods (`actual_cost()`, `is_cancelled()`, `is_terminal()`) across all 4 enum variants.
3. `runtime_integrity_check_detects_foreign_key_violations_and_halts_manager`:
   - Directly injects an orphan row into `audit_events` referencing a non-existent `session_id` using raw connection with `foreign_keys = OFF`.
   - Asserts `manager.integrity_check()` returns `Err(Kind::ForeignKeyViolation)` with `sqlite_code: Some(1)`.
   - Asserts manager transitions to halted state; subsequent writes fail closed with `Kind::Halted`.
4. `detailed_integrity_check_reports_structured_fk_violations`:
   - Injects two foreign key violations across different tables (`budget_reservations` and `session_security_snapshots`).
   - Asserts `manager.detailed_integrity_check()` returns structured report with 2 violations naming offending tables, rowids, and parent tables.
   - Asserts `report.is_valid() == false` and the manager is halted.
5. `open_database_with_existing_foreign_key_violation_fails_closed`:
   - Corrupts an existing database file by inserting an orphan audit event with FK disabled, then closes the connection.
   - Calls `SqliteConnectionManager::open(&path, &clock)`.
   - Asserts opening fails closed with `PersistenceErrorKind::ForeignKeyViolation`.

### 4.2. Exact Test Inventory

| Test Target / Binary | Category | Increment 5.4.2 | Increment 5.4.3 | Delta | Notes |
| --- | --- | --- | --- | --- | --- |
| `src/lib.rs` | Unit tests | 14 | 14 | 0 | Policy, workspace, transaction, model unit tests |
| `tests/authorization_tests.rs` | Integration | 27 | 27 | 0 | Grant binding and single-use regressions |
| `tests/domain_tests.rs` | Unit / Integration | 9 | 9 | 0 | Identifiers, timestamps, classifications |
| `tests/policy_tests.rs` | Integration | 9 | 9 | 0 | Policy engine decisions and limits |
| `tests/security_tests.rs` | Security hardening | 10 | 10 | 0 | Bell-LaPadula flows, concurrency, digest |
| `tests/session_tests.rs` | State machine | 5 | 5 | 0 | 9x9 matrix and lifecycle transitions |
| `tests/workspace_tests.rs` | Boundary isolation | 37 | 37 | 0 | 3 fixture tests ignored in default run |
| `tests/persistence_tests.rs` | SQLite persistence | 37 | 42 | **+5** | +2 budget settlement, +3 FK integrity tests |
| `Doc-tests sentra_core` | Compile-fail | 5 | 5 | 0 | 2 broker + 3 persistence mod compile-fail |
| **Default `cargo test` Total** | — | **153** | **158** | **+5** | Clean exit 0, 4 ignored |
| `workspace/Validate.ps1` Fixtures | Fixture / Benchmark | 3 | 3 | 0 | Junction, deny-ACL, 10,000-file benchmark |
| **Total Unique Test Suite** | — | **156** | **161** | **+5** | **Zero double-counting** |

### 4.3. Validation Script Outcomes
- `experiments/phase1/persistence/Validate.ps1`: **13 Passed, 0 Failed, Exit 0**
- `experiments/phase1/authorization/Validate.ps1`: **13 Passed, 0 Failed, Exit 0**
- `experiments/phase1/workspace/Validate.ps1`: **11 Passed, 0 Failed, Exit 0**

---

## 5. Scope & Git Policy Compliance

- **Zero Git Operations:** No commits, tags, pushes, pulls, fetches, resets, rebases, or branch changes were made. All working-tree modifications remain unstaged.
- **Dependency Isolation:** No new packages were added. Cargo operates strictly offline.
- **Phase Boundary:** Phase 1 remains in progress. Phase 2 has NOT started.
- **Production Readiness Status:** Increment 5.4.3 completes the persistence hardening remediation. The SQLite persistence foundation is sound, verified, and ready for higher-level Core Engine integration.
