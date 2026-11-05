# Independent SQLite Persistence Security & Reliability Audit — Increment 5.4.2.1

Date: 2026-11-05. **Independent security and reliability audit complete. Verification-only increment.**
No production code modifications, Cargo manifest changes, or dependency downloads were performed. All existing working-tree state and external commits were preserved.

---

## 1. Executive Summary & Audit Outcome

This audit independently inspected the completed Increment 5.4.2 SQLite persistence foundation to determine whether the implementation actually preserves the approved persistence architecture and security invariants under realistic failure, concurrency, and recovery conditions.

### Final Readiness Recommendation: **Conditionally approved — targeted remediation required**

- **Critical Findings:** **0**
- **High Findings:** **0**
- **Medium Findings:** **1** (F-542-01: Ambiguous parameter semantics in `settle_budget`)
- **Low Findings:** **3** (F-542-02: Missing cross-platform `syn 2` in lockfile; F-542-03: Process-local quarantine boundary; F-542-04: Runtime `integrity_check` omits foreign key check)
- **Informational Findings:** **3** (F-542-05: Non-cryptographic FNV-1a migration checksum; F-542-06: Ephemeral in-memory repository seal; F-542-07: Single-connection read serialization)

### Core Invariants Verified
1. **Atomic Authorization Binding:** Persistent approval grants are strictly bound to `(SessionId, ContextGeneration, TargetRevision, CanonicalActionDigest, ActionName, Classification, ReceiptToken)`. Cross-action (A-to-B), cross-session, cross-generation, cross-revision, and replay consumption attempts fail closed.
2. **Atomic Single-Use Consumption:** Consuming an approval grant and appending its audit event executes in a single SQLite transaction with `changes() == 1` enforcement. Live cross-process testing confirmed that two racing processes cannot double-spend a grant.
3. **Explicit Statement Rollback & Error Latch:** Every SQL statement failure triggers explicit `ROLLBACK`. The `ManagedTransaction` error latch prevents committing partial writes if an internal caller catches an error.
4. **Bounded `SQLITE_BUSY_SNAPSHOT` Restart:** Error 517 triggers full transaction rollback, jittered exponential backoff (10–250 ms), and a complete restart with fresh reads, bounded to 5 attempts.
5. **Crash Durability & In-Place Quarantine:** Real subprocess termination tests verified that committed states survive while uncommitted transactions roll back cleanly. Corrupt databases fail closed and preserve `.db`, `-wal`, `-shm`, and `-journal` files in place without dangerous multi-file renames.
6. **Test Suite Integrity:** The claim of **156 unique tests** (151 runtime + 5 compile-fail doctests) was verified mathematically without double-counting.

---

## 2. Repository and Git Safety Inspection

- **Current Branch:** `develop`
- **Current HEAD:** `24ae03b1e8acd8fae6527e4cd68f91fe32b30f8a` (`Add SQLite persistence foundation`)
- **Upstream Status:** `origin/develop` (synced, 0 ahead, 0 behind)
- **Working Tree:** Clean prior to audit report generation.
- **Git Policy Compliance:** Zero commits, tags, pushes, pulls, fetches, resets, rebases, or staging operations were issued. All operations ran strictly read-only and offline.

---

## 3. Dependency and Native Build Audit

### 3.1. Resolved Dependency Tree
Inspection of `crates/sentra-core/Cargo.toml` and `Cargo.lock` verified that exactly three direct dependencies were added:
```toml
rusqlite = { version = "=0.32.1", default-features = false, features = ["bundled"] }
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = "=1.0.154"
```

For the active Windows target (`x86_64-pc-windows-msvc`), Cargo resolves exactly **29 external packages**:
- SQLite FFI: `rusqlite 0.32.1`, `libsqlite3-sys 0.30.1`
- Utilities: `bitflags 2.13.2`, `fallible-iterator 0.3.0`, `fallible-streaming-iterator 0.1.9`, `hashlink 0.9.1`, `smallvec 1.16.4`, `hashbrown 0.14.5`, `ahash 0.8.12`, `cfg-if 1.0.5`, `once_cell 1.21.4`, `zerocopy 0.8.63`
- Serialization: `serde 1.0.229`, `serde_core 1.0.229`, `serde_derive 1.0.229`, `serde_json 1.0.154`, `itoa 1.0.18`, `memchr 2.8.3`, `zmij 1.0.23`
- Proc Macro: `proc-macro2 1.0.107`, `quote 1.0.47`, `syn 3.0.9`, `unicode-ident 1.0.27`
- Build-time: `cc 1.10.0`, `find-msvc-tools 0.1.15`, `shlex 2.0.1`, `pkg-config 0.3.34`, `vcpkg 0.2.15`, `version_check 0.9.5`

### 3.2. Actual Bundled SQLite Runtime Version
- The actual compiled SQLite C runtime version reported by `rusqlite::version()` and asserted in `connection_fresh_pragmas_schema_integrity_and_clean_shutdown` is **SQLite 3.46.0**.
- This corrects the initial conservative estimate of 3.45.3 documented during Increment 5.4.1 planning.
- The C source `libsqlite3-sys-0.30.1/sqlite3/sqlite3.c` is compiled statically using the host MSVC `cl.exe` (v14.52.37025). No external `sqlite3.dll` is required or linked.

### 3.3. Feature Configuration & Extension Loading
- `default-features = false` successfully disables unwanted default features (e.g. `rusqlite-macros`, `time`, `uuid`).
- SQLite extension loading is verified disabled and unauthorized: native testing of `SELECT load_extension('...')` returns `not authorized`.

### 3.4. Unsafe FFI Boundary & `#![forbid(unsafe_code)]`
- The `sentra-core` crate enforces `#![forbid(unsafe_code)]` at its root. Zero unsafe blocks exist in the crate.
- `rusqlite` encapsulates FFI calls to `sqlite3.c` internally. The compiler-enforced prohibition applies strictly to Sentra source code; memory safety of SQLite engine internals relies on the upstream C amalgamation and `rusqlite` wrappers.

---

## 4. Connection and PRAGMA Configuration Audit

### 4.1. Verified Connection PRAGMAs
Every connection opened via `SqliteConnectionManager::open` executes the following PRAGMA sequence and reads back the effective values:

| PRAGMA / Setting | Value | Verification Method | Enforcement Scope |
| --- | --- | --- | --- |
| `foreign_keys` | `ON` (1) | Read back via `PRAGMA foreign_keys` | Connection-scoped; re-applied on open |
| `journal_mode` | `wal` | Read back via `PRAGMA journal_mode` | Database-scoped; verified on open |
| `synchronous` | `FULL` (2) | Read back via `PRAGMA synchronous` | Connection-scoped; re-applied on open |
| `busy_timeout` | `5000` ms | Read back via `PRAGMA busy_timeout` | Connection-scoped; re-applied on open |
| `wal_autocheckpoint` | `1000` pages | Read back via `PRAGMA wal_autocheckpoint`| Connection-scoped; re-applied on open |
| `trusted_schema` | `OFF` (0) | Read back via `PRAGMA trusted_schema` | Connection-scoped; re-applied on open |
| `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE` | `true` | Verified via `set_db_config` return | Connection-scoped |
| `SQLITE_DBCONFIG_DEFENSIVE` | `true` | Verified via `set_db_config` return | Connection-scoped |

If any setting fails to match expected values, `verify_settings` immediately returns `PersistenceErrorKind::PragmaMismatch`.

### 4.2. Concurrency & Connection Ownership
- `SqliteConnectionManager` holds a single `Mutex<State>` containing `Option<Connection>`.
- Raw connections are **never exported**. All database interactions occur through `manager.write(|tx| ...)`.
- Mutex poisoning triggers fail-closed behavior (`PersistenceErrorKind::Poisoned`).
- When `shutdown()` is called:
  1. `PRAGMA wal_checkpoint(TRUNCATE)` is executed under the mutex.
  2. If the checkpoint is blocked (`busy=true` or `log_frames > 0`), it returns `PersistenceErrorKind::CheckpointBusy`, leaving the connection intact for caller retry.
  3. If checkpoint succeeds, the connection is closed. If close fails, the connection is restored and `CloseFailed` is returned.

### 4.3. Filesystem Path Validation
`validated_path` strictly validates the target database path on Windows:
- Must be an absolute disk drive path (`Prefix::Disk` or `Prefix::VerbatimDisk`). UNC paths, device paths (`\\.\`), drive-relative paths (`C:foo`), and relative paths are rejected.
- Paths containing `..`, control characters, reserved DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`), or invalid characters are rejected.
- All parent directory components are verified to be ordinary directories and pinned using Windows attribute handles (`OpenOptions::access_mode(0x80)`).
- Canonicalized parent path is re-checked against UNC prefixes to prevent symlink/junction redirection.
- Existing database and sidecar files (`-wal`, `-shm`, `-journal`) must be ordinary files, not symlinks or reparse points.
- If the database exists, `user_version`, `application_id`, and `sqlite_master` objects are inspected before executing journal-mode writes; opening an existing non-Sentra database returns `SchemaMetadata` without modifying it.

---

## 5. Transaction and Bounded Retry Audit

### 5.1. Explicit Rollback & The Error Latch
- Every managed transaction begins with `BEGIN IMMEDIATE`.
- Statement failures abort the transaction via `ManagedTransaction::abort()`, which executes an explicit `ROLLBACK`.
- If SQLite has already aborted the transaction (e.g. after `SQLITE_FULL` or certain I/O errors), `is_autocommit()` is checked so an already-completed rollback is not misreported as a rollback failure.
- If explicit `ROLLBACK` fails, `Kind::RollbackFailed` is returned and `state.halted` is set to `true`, permanently halting the connection.
- **The Error Latch:** Once an error occurs, `self.failure` is latched. Any subsequent attempt to execute statements or commit returns the latched error immediately. A transaction cannot be committed after an earlier statement error, even if the caller catches the error.

### 5.2. `SQLITE_BUSY_SNAPSHOT` vs Ordinary `SQLITE_BUSY`
- Both `SQLITE_BUSY` (code 5) and `SQLITE_BUSY_SNAPSHOT` (code 517) are classified as contention errors via `error.is_contention()`.
- The retry loop (`transaction::retry`) enforces:
  - Maximum **5 total attempts** (0..4 retries).
  - Jittered exponential backoff: $10 \times 2^{\min(\text{attempt}, 4)}$ ms + deterministic ticket jitter, capped at 250 ms.
  - On each retry, the **entire transaction is restarted**, acquiring a fresh `BEGIN IMMEDIATE` lock and re-reading all session, approval, sequence, and budget state from the fresh WAL snapshot.
  - Non-contention errors (constraint violations, invalid inputs, rollback failures) fail immediately without retrying.
- **Side Effect Containment:** Closures passed to `manager.write` perform only SQL queries and clock reads. Compile-fail test `persistence (line 32)` verifies that closures cannot capture or execute external side effects.

---

## 6. Persistent Authorization Security Audit

### 6.1. Comprehensive Binding Matrix
The authorization pipeline was audited against all potential bypass vectors:

| Bypass Vector | Code Path & Defense | Audit Finding / Verdict |
| --- | --- | --- |
| **A-to-B Grant Bypass** | `binding_matches` verifies `row.action_digest == intent.action.action_digest()`. SQL `UPDATE ... WHERE action_digest = ?2`. | **Blocked.** Mismatch returns `ContextMismatch`. Original grant remains unconsumed. |
| **Cross-Session Consumption** | `row.session == intent.session.session_id`. SQL `UPDATE ... WHERE session_id = ?4`. | **Blocked.** Rejects with `ContextMismatch`. |
| **Cross-Generation Consumption** | `row.generation == snapshot.generation`. SQL `UPDATE ... WHERE context_generation = ?5`. | **Blocked.** Re-registering context increments generation, invalidating old grants. |
| **Target Revision Mismatch** | `row.revision == snapshot.revision`. SQL `UPDATE ... WHERE target_revision = ?6`. | **Blocked.** ABA revision changes reject consumption. |
| **Action Type / Name Mismatch** | `row.action_name == intent.action.action_name()`. SQL `UPDATE ... WHERE action_name = ?7`. | **Blocked.** `ContextMismatch`. |
| **Caller-Forged Grant** | `PersistentApprovalGrant` has private fields, no `Deserialize`. `Arc::ptr_eq(&self.seal, &grant.seal)` verifies repository provenance. | **Blocked.** Unissued proposals or foreign grants reject with `InvalidApproval`. |
| **Replay / Double Spending** | SQL `UPDATE ... WHERE state = 'ISSUED'`. Checks `changed == 1`. Subsequent attempts see `state = 'CONSUMED'`. | **Blocked.** Returns `ApprovalReused`. |
| **Expired Grant Consumption** | In-Rust `validate_time(&row, &now)` and SQL `WHERE expires_at > ?1`. RFC 3339 lexicographical comparison. | **Blocked.** Returns `ApprovalExpired`. |
| **Cross-Process Race** | Two independent OS processes race on `consume_approval` via SQLite file locking. | **Blocked.** Exactly 1 succeeds, 1 receives `ApprovalReused`. Verified via live pipe test. |

### 6.2. Transactional Atomicity of Consumption and Audit
In `consume_approval`:
1. `UPDATE approval_requests SET state = 'CONSUMED' ... WHERE state = 'ISSUED'`
2. Verify `changed == 1`.
3. `INSERT INTO audit_events(...)` with event kind `ApprovalConsumed`.
4. `COMMIT` the transaction.
If step 2 fails, step 3 is never reached and transaction rolls back. If step 3 fails (e.g. duplicate event ID), step 1 rolls back. If commit fails, all changes roll back. The audit record cannot claim an action that did not commit.

---

## 7. Audit Trail and Budget Persistence Audit

### 7.1. Monotonic Sequence Allocation
- In `audit()`: `sequence = COALESCE(MAX(sequence_number), 0) + 1` inside the serialized `BEGIN IMMEDIATE` write transaction.
- The `audit_events` table enforces `UNIQUE(session_id, sequence_number)`.
- If two transactions race for the same session, SQLite serialization ensures strictly ascending sequence numbers.
- If a transaction rolls back, the allocated sequence number rolls back with it, preventing gaps in committed history.

### 7.2. Diagnostic Redaction
- `AuditRecord`, `SessionRecord`, `PersistentApprovalGrant`, `ConsumptionRecord`, and `BudgetRecord` implement custom `Debug` macros outputting `[redacted]`.
- Path strings, tokens, and payloads are not disclosed in standard debug formats.

### 7.3. Budget Accounting & Reservation
- Budget limit is stored as fixed-point `CostUsd` (micro-dollars, `u64` bounded to `i64::MAX`).
- `budget_used(tx, session)` computes:
  ```sql
  SELECT COALESCE(SUM(COALESCE(actual_cost_micro_usd, reserved_cost_micro_usd)), 0)
  FROM budget_reservations WHERE session_id = ?1
  ```
  Unsettled reservations count at their full upper-bound reservation.
- `reserve_budget` checks `budget_used + amount <= limit`. Checked addition prevents integer overflow.
- **Unconfirmed Cancellation:** If cancellation is unconfirmed, the full reservation bound is retained.
- **Confirmed Cancellation:** If confirmed without known usage, state transitions to `CANCELLED`, but `actual_cost_micro_usd` remains NULL, preserving the upper-bound hold against overspend.

---

## 8. WAL Lifecycle and Recovery Audit

### 8.1. Crash Durability & Recovery
- Three native process termination tests (`recovery_real_process_termination_preserves_committed_and_discards_uncommitted`, `migration_real_process_interruption_leaves_fresh_database_recoverable`, and `subprocess_race_worker_helper`) verified real OS process crash recovery:
  - Transactions committed prior to `kill()` survive reopen and pass `PRAGMA integrity_check`.
  - Transactions active/uncommitted at `kill()` are discarded cleanly by SQLite WAL recovery.

### 8.2. In-Place Quarantine Policy
- `SqliteConnectionManager::quarantine_in_place()` permanently halts the manager (`state.halted = true`) and closes the connection.
- In compliance with Phase 1 safety constraints, **no files are moved, renamed, or deleted**. All 4 recovery artifacts (`.db`, `-wal`, `-shm`, `-journal`) are preserved in place.
- Subsequent calls to `manager.write()` or `manager.settings()` fail closed with `PersistenceErrorKind::Halted`.

---

## 9. Migration Engine Audit

### 9.1. Deterministic DDL & Object Validation
- Embedded migration `schema_v1.sql` creates exactly 6 tables: `schema_migrations`, `sessions`, `session_security_snapshots`, `audit_events`, `approval_requests`, `budget_reservations`.
- Line endings are normalized to LF (`canonical_sql`), ensuring identical checksums on CRLF Windows checkouts.
- During initialization, the migration runner applies the DDL to an in-memory template and extracts all expected schema objects (`sqlite_master`). It compares the target database's objects against the template: any unexpected table, index, or column schema drift causes initialization to fail closed with `PersistenceErrorKind::SchemaMetadata`.
- Migration DDL, migration audit row, `PRAGMA user_version = 1`, and `PRAGMA application_id = 0x53454E54` commit together within a single transaction.

---

## 10. Test and Validation Coverage Review

### 10.1. Exact Test Counts Verification
A thorough inventory across all test targets confirmed the exact composition of the test suite:

| Target | Test File / Module | Tests Passed | Tests Ignored | Notes |
| --- | --- | --- | --- | --- |
| `src/lib.rs` (core) | Unit tests (workspace/policy) | 4 | 0 | In-crate unit tests |
| `src/lib.rs` (persistence) | Unit tests (persistence) | 10 | 0 | Model, transaction, migration, connection unit tests |
| `tests/authorization_tests.rs` | Authorization integration | 27 | 0 | In-memory grant binding regressions |
| `tests/domain_tests.rs` | Domain models | 9 | 0 | Identifiers, timestamps, classifications |
| `tests/policy_tests.rs` | Policy engine | 9 | 0 | Policy rules, defaults, budget thresholds |
| `tests/security_tests.rs` | Security hardening | 10 | 0 | Action digest, Bell-LaPadula flow, concurrency |
| `tests/session_tests.rs` | Session state machine | 5 | 0 | 9x9 transition matrix, audit invariants |
| `tests/workspace_tests.rs` | Workspace boundary | 37 | 3 | Normal suite; 3 fixture tests ignored in default run |
| `tests/persistence_tests.rs` | Persistence integration | 37 | 1 | 1 ignored entry is the subprocess helper |
| `Doc-tests sentra_core` | Compile-fail documentation | 5 | 0 | 2 approval broker + 3 persistence mod compile-fail |
| **Default `cargo test` Total** | — | **148 runtime + 5 doctests = 153** | **4** | Clean exit 0 |
| **Workspace Fixture Tests** | `workspace/Validate.ps1` | **3** | 0 | Junction, deny-ACL, 10,000-file benchmark |
| **Total Unique Test Suite** | — | **151 runtime + 5 doctests = 156** | — | **Zero double-counting** |

### 10.2. Subprocess Worker Accounting
- `persistence_tests.rs::owned_persistence_process_worker` is marked `#[ignore]` because it is a subprocess helper executable.
- It is executed directly by three parent integration tests using explicit child process spawning and stdio pipes:
  1. `approval_cross_process_exactly_one_consumes_and_audit_is_atomic`
  2. `recovery_real_process_termination_preserves_committed_and_discards_uncommitted`
  3. `migration_real_process_interruption_leaves_fresh_database_recoverable`
- It is an actively exercised test component, not an omitted scenario.

---

## 11. Findings Classification Table

| ID | Module / File | Code Path | Severity | Type | Description & Remediation | Blocks 5.4.3? |
| --- | --- | --- | --- | --- | --- | --- |
| **F-542-01** | `persistence/repository.rs` | `settle_budget` (lines 501, 514) | **Medium** | Design Weakness | **Ambiguous parameter semantics in `settle_budget`:** The parameter `cancellation_confirmed: bool` conflates terminal completion confirmation with cancellation. Passing `cancellation_confirmed = false` for a normal completed task causes `final_actual` to be discarded as unconfirmed. **Remediation:** Refactor parameter to an explicit settlement status enum (`SettlementStatus::Completed(CostUsd)`, `SettlementStatus::Cancelled(Option<CostUsd>)`, `SettlementStatus::UnconfirmedPartial`) in Increment 5.4.3. | **No (Remediation in 5.4.3)** |
| **F-542-02** | `Cargo.lock` | `zerocopy-derive` entry | **Low** | Tooling / Build | **Unfiltered `cargo metadata` fails offline:** `Cargo.lock` contains `zerocopy-derive 0.8.63` depending on uncached `syn 2.0.119`. While unused on Windows x64 MSVC (`--filter-platform` passes), generic offline metadata calls fail. **Remediation:** Document mandatory `--filter-platform x86_64-pc-windows-msvc` flag or prune unused dependencies in future manifest maintenance. | **No** |
| **F-542-03** | `persistence/connection.rs` | `quarantine_in_place` (line 495) | **Low** | Operational Boundary | **Process-local quarantine halt:** `quarantine_in_place` halts the local connection manager, but cannot signal or halt independent external processes accessing the same database file. **Remediation:** Document that multi-process deployments require external controller process supervision upon quarantine. | **No** |
| **F-542-04** | `persistence/connection.rs` | `integrity_check` (line 385) | **Low** | Observability | **Runtime integrity check omits foreign key verification:** `manager.integrity_check()` runs `PRAGMA integrity_check(10)` but omits `PRAGMA foreign_key_check`. (Foreign keys are checked during migration initialization). **Remediation:** Add `PRAGMA foreign_key_check` to `manager.integrity_check()`. | **No** |
| **F-542-05** | `persistence/migration.rs` | `checksum_for` (line 23) | **Informational** | Documented Limitation | **Non-cryptographic FNV-1a migration checksum:** FNV-1a detects accidental source drift only, not cryptographic tampering. Documented and expected. | **No** |
| **F-542-06** | `persistence/repository.rs` | `seal: Arc<()>` (line 28) | **Informational** | Intentional Invariant | **In-memory grant seal resets on restart:** In-memory `PersistentApprovalGrant` allocations cannot be consumed across process restarts without calling `recover_issued_grant`. This is an intentional security feature. | **No** |
| **F-542-07** | `persistence/connection.rs` | `SqliteConnectionManager` (line 70) | **Informational** | Architecture Trade-Off | **Single connection serializes read operations:** `Mutex<Option<Connection>>` serializes reads and writes. Acceptable for Phase 1 single-operator CLI; read connection pool can be added in future phases. | **No** |

---

## 12. Reproduction Commands

To reproduce the complete validation and audit suite offline from PowerShell on Windows 11:

```powershell
# 1. Code formatting check
cargo fmt --all -- --check

# 2. Offline workspace check
cargo check --workspace --offline

# 3. Strict Clippy warnings check
cargo clippy --workspace --all-targets --all-features --offline -- -D warnings

# 4. Workspace test suite (148 runtime + 5 compile-fail doctests)
cargo test --workspace --offline

# 5. Dedicated persistence integration suite
cargo test --package sentra-core --test persistence_tests --offline

# 6. Target-filtered metadata verification
cargo metadata --offline --format-version=1 --filter-platform x86_64-pc-windows-msvc

# 7. Complete automated persistence validation runner
pwsh -NoProfile -File experiments/phase1/persistence/Validate.ps1

# 8. Regression check on authorization suite
pwsh -NoProfile -File experiments/phase1/authorization/Validate.ps1

# 9. Regression check on workspace boundary suite (including 10,000-file scale)
pwsh -NoProfile -File experiments/phase1/workspace/Validate.ps1
```

---

## 13. Final Readiness Recommendation & Increment 5.4.3 Action Plan

### Decision: **Conditionally approved — targeted remediation required**

The Increment 5.4.2 SQLite persistence implementation is sound, robust, and mathematically verified against all specified security invariants. It is approved to proceed to **Increment 5.4.3** with the following targeted remediations:

1. **Remediation R-01 (Addressing F-542-01):** In Increment 5.4.3, refactor `PersistentApprovalAuthority::settle_budget` to replace the ambiguous `cancellation_confirmed: bool` parameter with an explicit enum representing completion status, preventing caller confusion during task dispatch integration.
2. **Remediation R-02 (Addressing F-542-04):** In Increment 5.4.3, enhance `SqliteConnectionManager::integrity_check` to execute `PRAGMA foreign_key_check` alongside `PRAGMA integrity_check(10)`.
