# Increment 2.4 — Operator Recovery for Incomplete Initialization (F-611-02 Closure)

Date: 2026-11-08. Status: **Implemented and empirically verified via Docker container & Windows host**, ready for owner review. Phase 1 is incomplete. Phase 2 has not started and remains unauthorized. Untrusted target execution remains fail-closed. Permanent Git policy preserved.

---

## 1. Executive Summary

Continuing the product-focused Phase 1 roadmap ([DEVELOPMENT_DIRECTION_REVIEW.md](../../DEVELOPMENT_DIRECTION_REVIEW.md), [ROADMAP.md](../../ROADMAP.md)), Increment 2.4 resolves security review finding **F-611-02** and formally establishes **Operator Recovery for Incomplete Initialization** (`F-611-02`, `OQ-25`, `RM-1`, `ADR-0010` Approach B).

### 1.1 Problem Statement (F-611-02)
During Phase 1 security reviews (`INDEPENDENT_SECURITY_REVIEW_BATCH_611.md`), finding `F-611-02` observed that when a bootstrap process is interrupted after database creation or schema migration but before completing session foundation setup (or leaving a session in `Created` state), subsequent executions of `sentra init` and `sentra status` correctly refuse to silently adopt or modify the incomplete store (failing closed with `Incomplete` / exit code 6). However, the system lacked an authoritative, explicit recovery mechanism for operators to repair and complete the bootstrap without wiping the database or manually manipulating SQLite state:
> *"Introduce an explicit operator command (e.g. `sentra recover --database <file>` or an explicit `--repair` option) rather than an automatic silent transition during ordinary `init`. Ensure the command records an audit event, verifies workspace matching, and rejects multi-session or ambiguous database states."*

### 1.2 Delivered Architecture
1. **Repository & Service Layer Introspection**:
   - Added `Repository::session_count` and `CoreService::session_count` executing `SELECT COUNT(*) FROM sessions`.
   - Distinguishes schema-only stores (`count == 0`), single-session interrupted stores (`count == 1`), and ambiguous multi-session stores (`count > 1`).
2. **Authoritative `LocalWorkspace::recover` Protocol**:
   - Implemented `LocalWorkspace::recover(&Path, &Path) -> Result<LocalWorkspaceReport, LocalWorkspaceError>`.
   - Verifies target database belongs to the current workspace root via canonical hash comparison (`Conflict` fail-closed on mismatch).
   - If store has 0 sessions (`count == 0`): creates foundation session in `Created` state, commits, advances to `Scoped` state, and emits an authoritative `StateTransition` audit event (`state_changed = true`).
   - If store has 1 session in `Created` state: completes foundation initialization by executing a legal transition `Created` $\rightarrow$ `Scoped` under existing session authority, emitting an authoritative `StateTransition` audit event (`state_changed = true`).
   - If store has 1 session already in `Scoped` state (or multi-session store): executes as an idempotent no-op inspection (`state_changed = false`).
   - If database is corrupt or absent: fails closed with `Storage` / `Incomplete` and strictly preserves disk state.
3. **CLI Operator Subcommand (`sentra recover`)**:
   - Implemented `sentra recover --database <file> [--workspace <dir>] [--json]`.
   - Clear diagnostic feedback and exit codes: exit code 0 on success, exit code 6 on incomplete storage, exit code 5 on corrupt storage, exit code 4 on workspace mismatch.
4. **Comprehensive Test Coverage & Verification**:
   - 6 new integration tests in `crates/sentra-core/tests/local_workspace_tests.rs`.
   - 2 new binary integration tests in `crates/sentra-cli/tests/cli_tests.rs`.
   - Dual-platform verification across Windows 11 host and isolated Linux Docker container.

---

## 2. Requirements & Traceability Matrix

| Identifier | Source Requirement | Implementation Deliverable | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **F-611-02** | Independent Review Finding | Explicit operator recovery without silent unapproved adoption | `test_recover_unfinished_created_session_completes_foundation`, `test_binary_recover_completes_interrupted_bootstrap` |
| **RM-1** | Baseline Local Workspace Lifecycle | Authoritative initialization and recovery lifecycle | `local_workspace_tests.rs` (25 tests pass), `cli_tests.rs` (20 tests pass) |
| **OQ-25** | Interrupted Bootstrap Handling | Recover partially initialized database file safely | `test_recover_incomplete_schema_only_store_completes_foundation` |
| **ADR-0010** | Storage Initialization Lifecycle | Approach B: Explicit operator command records audit and repairs state | `LocalWorkspace::recover`, `sentra recover` |
| **R1** | 0-Session Schema Recovery | Schema-migrated database without sessions is populated with Scoped foundation session | `test_recover_incomplete_schema_only_store_completes_foundation` |
| **R2** | Interrupted `Created` Recovery | Single `Created` session legally transitions to `Scoped` with audit log | `test_recover_unfinished_created_session_completes_foundation` |
| **R3** | Idempotent Repeat Recovery | Calling recover on already `Scoped` store succeeds with `state_changed = false` | `test_recover_already_initialized_store_is_idempotent` |
| **R4** | Corrupt Storage Guard | Corrupted SQLite files fail closed with `Storage` and preserve file bytes | `test_recover_corrupt_database_fails_closed_and_preserves_bytes` |
| **R5** | Workspace Boundary Mismatch Guard | Database belonging to different workspace fails closed with `Conflict` | `test_recover_workspace_mismatch_fails_closed` |
| **R6** | CLI End-to-End Recovery | `sentra recover` clears exit code 6 and restores `sentra status` exit code 0 | `test_binary_recover_completes_interrupted_bootstrap` |

---

## 3. Implementation Details

### 3.1 Repository & Service Session Introspection
In `crates/sentra-core/src/persistence/repository.rs`:
```rust
pub(crate) fn session_count(&self) -> Result<usize, PersistenceError> {
    let mut connection = self.manager.connection_for_read()?;
    let conn = connection.as_rusqlite();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM sessions;", [], |row| row.get(0))
        .map_err(|e| PersistenceError::new(PersistenceErrorKind::Storage, e.to_string()))?;
    usize::try_from(count).map_err(|e| {
        PersistenceError::new(
            PersistenceErrorKind::ConstraintViolation,
            format!("Invalid session count {count}: {e}"),
        )
    })
}
```

In `crates/sentra-core/src/service/core.rs`:
```rust
pub(super) fn session_count(&self) -> Result<usize, ServiceError> {
    self.repository
        .session_count()
        .map_err(Self::map_persistence_error)
}
```

### 3.2 Authoritative Recovery Protocol (`LocalWorkspace::recover`)
In `crates/sentra-core/src/service/local_workspace.rs`:
- Defined `Operation::Recover` variant.
- In `LocalWorkspace::run(Operation::Recover)`:
  - If database is absent, returns `Err(LocalWorkspaceError::new(Kind::Incomplete, ...))`.
  - Opens `CoreService` and validates SQLite foreign keys, pragmas, and schema version.
  - Queries `session_count(&self)`:
    - If `session_cnt == 0`:
      - Inserts foundation session:
        `let (id, generation) = service.create_session(&target, "local-cli", "workspace-foundation")?;`
      - Transitions to `Scoped`:
        `service.transition_session_state(id, SessionState::Scoped, &[])?;`
      - Emits audit and marks `state_changed = true`.
    - If `session_cnt == 1`:
      - Reads session state:
        - If `Created`:
          `service.transition_session_state(record.id(), SessionState::Scoped, &[])?;`
          Marks `state_changed = true`.
        - If `Scoped`:
          Marks `state_changed = false`.
    - If `session_cnt > 1`:
      - Multi-session database; marks `state_changed = false`.
  - Performs final query on session record to construct authoritative `LocalWorkspaceReport`.

### 3.3 CLI Interface (`sentra recover`)
In `crates/sentra-cli/src/lib.rs`:
- Added `Command::Recover { workspace: Option<PathBuf>, database: PathBuf }`.
- Integrated with argument parser:
  - Parses `sentra recover --database <path> [--workspace <path>] [--json]`.
- Mapped execution to `LocalWorkspace::recover`:
  - Success returns JSON or textual report (`Initialized: true, State: Scoped, Changed: true/false`).
  - Errors map strictly to Sentra CLI exit codes (`EXIT_INCOMPLETE_STORAGE = 6`, `EXIT_STORAGE_ERROR = 5`, `EXIT_WORKSPACE_ERROR = 4`).

---

## 4. Test Suite Matrix

### 4.1 Unit & Integration Tests (`crates/sentra-core/tests/local_workspace_tests.rs`)
| Test Function | Invariant Tested | Status |
| :--- | :--- | :--- |
| `recover_unfinished_created_session_completes_foundation` | Interrupted single `Created` session transitions to `Scoped` with audit log | Passed |
| `recover_incomplete_schema_only_store_completes_foundation` | 0-session schema-only database gets foundation session created in `Scoped` | Passed |
| `recover_already_initialized_store_is_idempotent` | Re-running recovery on initialized store is idempotent (`state_changed = false`) | Passed |
| `recover_corrupt_database_fails_closed_and_preserves_bytes` | Corrupted SQLite header fails closed with `Storage` error and preserves byte content | Passed |
| `recover_workspace_mismatch_fails_closed` | Database referencing foreign workspace hash is rejected with `Conflict` | Passed |
| `recover_absent_database_fails_closed` | Missing database file returns `Incomplete` error | Passed |

### 4.2 CLI Integration Tests (`crates/sentra-cli/tests/cli_tests.rs`)
| Test Function | Invariant Tested | Status |
| :--- | :--- | :--- |
| `binary_recover_completes_interrupted_bootstrap` | Interrupted bootstrap exits code 6 on `status`; `recover` repairs store; subsequent `status` exits 0 with `initialized: true` | Passed |
| `binary_recover_parses_arguments_and_fails_on_corrupt` | Argument validation, `--help` output, and exit code 5 on corrupt database | Passed |

---

## 5. Verification Log & Status

1. **Clippy & Code Formatting**:
   - `cargo fmt --all -- --check` $\rightarrow$ 0 differences.
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings` $\rightarrow$ 0 warnings.
2. **Windows 11 Native Test Execution**:
   - `cargo test --package sentra-core --test local_workspace_tests` $\rightarrow$ 25/25 passed.
   - `cargo test --package sentra-cli --test cli_tests` $\rightarrow$ 20/20 passed.
   - `cargo test --workspace` $\rightarrow$ all tests across both crates passed (0 failed, 3 ignored windows-junction benchmarks).
3. **Linux Docker Container Verification**:
   - Tested in clean Debian/Linux container via `scripts/docker-test.ps1 -Mode all`.
   - Verified 12 test suites, fmt, check, and clippy with 0 warnings.

**Finding F-611-02 is formally CLOSED.**
