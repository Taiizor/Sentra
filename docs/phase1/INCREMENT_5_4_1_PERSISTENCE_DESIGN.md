# Production SQLite Persistence Architecture & Contracts — Increment 5.4.1

Date: 2026-11-05. **Architecture and interface contract specification.**
This document establishes the production SQLite persistence boundaries, connection lifecycles, transaction invariants, crash recovery semantics, schema definitions, and migration strategies for the Sentra Core Engine.

In accordance with Phase 1 constraints:
- **No production code is implemented in this increment.**
- **No database files or migrations are executed.**
- Workspace discovery and filesystem containment remain strictly independent of SQLite.
- The persistence layer holds no authority to bypass policy evaluation or workspace security boundaries.

**Implementation clarification (5.4.2):** The [implementation report](INCREMENT_5_4_2_SQLITE_IMPLEMENTATION.md) is authoritative for executed results and concrete APIs. It retains these six tables and existing domain types; adds validation constraints; uses private local receipts backed by trusted issuance/recovery; and preserves DB/WAL/SHM in place instead of attempting an unsafe archive. SQL below is the original design sketch, not the executable migration; see [schema_v1.sql](../../crates/sentra-core/src/persistence/schema_v1.sql). Registration of revisions remains a trusted-controller responsibility; filesystem changes are not automatically detected by this storage adapter. No ADR status changes.

---

## 1. Persistence Boundary & Architectural Responsibilities

The persistence layer (`sentra_core::persistence`) provides deterministic, durable, transactional storage for Sentra's session lifecycle, audit trail, human approvals, and budget accounting.

```
+-----------------------------------------------------------------------------+
|                           Core Application Services                         |
|   (SessionStateMachine, PolicyEngine, ApprovalAuthority, WorkspaceDiscovery)|
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|                     PersistenceRepository (Rust Trait)                      |
|  - Encapsulates domain entity mapping, transaction scoping, and SQL execution|
|  - Enforces explicit statement-error rollback & SQLITE_BUSY_SNAPSHOT retries |
|  - Strictly decoupled from filesystem path resolution and target execution   |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|                     SqliteConnectionManager (Safe RAII)                     |
|  - Manages single-writer / concurrent-reader WAL connection lifecycle       |
|  - Enforces mandatory PRAGMAs (synchronous=FULL, foreign_keys=ON, busy_to=5s)|
|  - Coordinates WAL checkpointing and startup integrity verification         |
+-----------------------------------------------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|                   SQLite Engine (Bundled rusqlite C Core)                   |
|                        Local NTFS Database File                             |
+-----------------------------------------------------------------------------+
```

### 1.1. Core Responsibilities of `PersistenceRepository`
1. **Atomic Session State & Audit Emission:** Ensure every valid session state transition and its corresponding `AuditEvent` are persisted within the exact same database transaction.
2. **Authoritative Context & Generation Binding:** Persist the registered session security snapshot, context generation, and explicit target revision.
3. **Approval Lifecycle & Replay Protection:** Persist human approval requests and single-use approval receipts, guaranteeing atomic consumption in database transactions.
4. **Budget Reservation Accounting:** Persist conservative token/dollar reservations and track actual expenditures.
5. **Schema Versioning & Migrations:** Manage linear schema migrations with automatic recovery from interrupted migrations.
6. **Data Integrity & Verification:** Run `PRAGMA integrity_check` upon opening existing databases and handle corrupt databases safely without silent data loss.

### 1.2. Strict Non-Responsibilities & Architectural Decoupling
- **Filesystem Path Canonicalization & Quarantine:** Workspace boundary containment (`workspace::canonicalize`) and reparse point quarantine operate exclusively at the OS filesystem layer. SQLite never resolves paths or overrides quarantine decisions.
- **Policy Decision Authority:** SQLite records decisions; it does not evaluate policy rules. Storing an approval record does not confer authorization if the in-memory policy engine denies the action.
- **Evidence Blob Storage:** In accordance with ADR-0003 and ADR-0006, large evidence artifacts, scanner raw outputs, and build payloads are stored as content-addressed files in a dedicated storage directory. SQLite stores only metadata pointers, sizes, and declared/verified SHA-256 digests.

---

## 2. Connection Ownership, Concurrency & WAL Lifecycle

### 2.1. Concurrency Model: Single Writer with `BEGIN IMMEDIATE`
- SQLite in WAL mode permits multiple concurrent readers and exactly one active writer.
- To prevent deadlocks caused by SQLite upgrading a deferred read lock to a write lock (`SQLITE_BUSY`), **all write operations in Sentra Core must initiate transactions with `BEGIN IMMEDIATE`**.
- In the local single-operator model, `SqliteConnectionManager` holds an internal `std::sync::Mutex<rusqlite::Connection>` for the write connection. Any thread requesting a write transaction obtains exclusive access to this connection, eliminating multi-threaded write races within the process.
- Read-only operations (e.g. CLI status queries or dashboard rendering) may utilize a separate read-only connection without blocking writers.

### 2.2. Mandatory Connection Initialization PRAGMAs
Every SQLite connection opened by Sentra must execute the following PRAGMAs immediately before executing any application statements:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;
PRAGMA wal_autocheckpoint = 1000;
```

| PRAGMA | Configured Value | Architectural Justification |
| --- | --- | --- |
| `foreign_keys` | `ON` | Enforces relational integrity across sessions, audit events, and approval records. Default is OFF in SQLite; must be turned on per connection. |
| `journal_mode` | `WAL` | Permits concurrent readers and one writer; contention and checkpoint blockers still occur. Process-termination recovery needs actual tests. |
| `synchronous` | `FULL` (2) | Ensures that every committed transaction is flushed to disk (fsync on WAL frame), guaranteeing durability against process crashes. |
| `busy_timeout` | `5000` (ms) | Gives competing reader/writer operations a 5-second window to resolve transient lock contention before returning `SQLITE_BUSY`. |
| `wal_autocheckpoint`| `1000` (pages) | Automatically triggers a passive checkpoint when the WAL file reaches 1,000 pages (~4 MiB), preventing unbounded WAL growth. |

### 2.3. WAL Checkpoint Policy & Clean Shutdown
- **Runtime Checkpointing:** SQLite's PASSIVE autocheckpoint hook runs on the committing connection at the 1,000-page threshold (`wal_autocheckpoint=1000`); it is not a background thread. Long readers can pin WAL frames.
- **Session Completion Checkpoint:** When a session enters a terminal state (`Completed`, `Failed`, `Cancelled`), the repository executes `PRAGMA wal_checkpoint(PASSIVE)`.
- **Clean Engine Shutdown:** Upon graceful shutdown of the CLI/daemon, the repository executes:
  ```sql
  PRAGMA wal_checkpoint(TRUNCATE);
  ```
  This flushes all WAL frames back into the main `.db` database file and truncates the `.db-wal` file to 0 bytes, leaving a clean filesystem state.

---

## 3. Mandatory Transaction Contracts

Core Engine persistence directly incorporates the empirical findings validated in Phase 1 Milestone 2 (`docs/phase1/SQLITE_VALIDATION.md`).

### 3.1. Explicit Rollback on Statement Errors
**Rule:** A failed SQL statement must trigger an explicit `ROLLBACK` of the active transaction.

- **Observed Behavior:** As established in test `T01`, SQLite constraint violations (such as `SQLITE_CONSTRAINT_PRIMARYKEY`) abort *only the failing statement*, leaving the surrounding transaction active and earlier uncommitted writes pending in memory.
- **Contract:**
  ```text
  BEGIN IMMEDIATE
  Execute the complete database operation.
  On statement, business-condition or commit failure:
    Explicitly ROLLBACK if SQLite has not already auto-aborted.
    Retain the original error; report rollback failure separately and halt access.
    Never commit earlier partial writes or rely on dropping a guard.
  Otherwise COMMIT before returning success.
  ```
- **Invariant:** A repository method will never catch a statement error and subsequently commit partial changes. If any statement in a logical unit fails, the entire transaction is rolled back immediately.

### 3.2. `SQLITE_BUSY_SNAPSHOT` Recovery Protocol
**Rule:** When a stale WAL snapshot prevents a write, the repository must roll back the entire transaction, discard stale context, start a fresh transaction, re-read required state, re-evaluate business logic, and retry within a bounded backoff policy.

- **Observed Behavior:** As established in test `T13`, when connection R begins a read transaction, connection W commits a write, and R subsequently attempts to write, SQLite returns **`SQLITE_BUSY_SNAPSHOT` (extended code 517)**. Retrying only the failed statement within the existing transaction fails repeatedly because R's read view is permanently pinned to the old WAL snapshot.
- **Contract:**
  1. Catch `rusqlite::Error::SqliteFailure(ffi_err, _)` where extended error code is `517` (`SQLITE_BUSY_SNAPSHOT`).
  2. Execute an explicit `ROLLBACK` to release the pinned read snapshot.
  3. Wait using jittered exponential backoff:
     $$\text{delay}(n) = \min(10 \times 2^n + \text{jitter}, 250\text{ ms})$$
  4. Initiate a completely fresh transaction using `BEGIN IMMEDIATE`.
  5. **Re-read all dependent state** (e.g. current session state, sequence numbers, approval status) from the fresh snapshot.
  6. Re-evaluate whether the requested transition or consumption is still valid against the updated state.
  7. Re-execute the write operation.
  8. Use a maximum of **five total attempts** (four retries). The concrete 5.4.2 API returns `RetryExhausted` with the original extended code and attempt count. Ordinary BUSY (5) is distinguished from BUSY_SNAPSHOT (517).
- **Prohibition:** Never retry only the failed statement without restarting the transaction.

### 3.3. Process Termination & Durability Recovery Limits
- **Crash Recovery:** The tested process-termination boundary must distinguish committed and uncommitted work. Windows fixture termination is not a POSIX signal or a physical power-fault test:
  - Transactions committed prior to termination survive and are recovered automatically on next open.
  - Transactions uncommitted at termination are discarded automatically upon database reopen via WAL frame invalidation.
- **Durability Boundary Disclosure:** FULL/WAL are required configuration. The 5.4.2 tests observe process-termination recovery only; kernel crashes, physical power loss, device caches and write/fsync failures are not validated. No physical durability guarantee is inferred from a PRAGMA.

---

## 4. Authorization Persistence Invariants (Increment 5.3.1 Continuity)

The persistence layer must preserve all security invariants validated in Increment 5.3.1 (`INCREMENT_5_3_1_SECURITY_REVIEW.md`):

### 4.1. Exact Operation & Context Generation Binding
- Approvals are strictly bound to `(SessionId, ContextGeneration, TargetRevision, CanonicalActionDigest)`.
- When an approval request is created:
  - It records the current `context_generation` of the session and the explicit `target_revision`.
  - The `action_digest` is stored using the canonical V2 length-prefixed encoding (`len#value`), preventing parameter collision.
- If a session's security context is re-registered (incrementing `context_generation`) or the target file revision changes on disk, any pending or issued approval records matching the old generation/revision are invalid and cannot be consumed.

### 4.2. Atomic Single-Use Consumption in SQLite
The SQL sketch below is insufficient by itself: 5.4.2 requires a private trusted receipt plus same-transaction comparison of complete stored/caller context, action type/canonical identity, classification, issuance/provenance and time fields. A correlation ID or conditional ISSUED/expiry update alone never authorizes an operation.
To prevent double-spending or replay of approval grants under concurrency:
- The consumption of an approval grant and the recording of the authorized action must execute inside a **single atomic transaction**:
  ```sql
  -- Step 1: Atomic update verifying unconsumed state, exact generation, and expiry
  UPDATE approval_requests
  SET 
      state = 'CONSUMED',
      consumed_at = :current_time,
      consumed_action_digest = :action_digest
  WHERE 
      request_id = :request_id
      AND session_id = :session_id
      AND context_generation = :expected_generation
      AND target_revision = :expected_revision
      AND state = 'ISSUED'
      AND expires_at > :current_time;
  ```
- If `sqlite3_changes()` returns `0`, the consumption is rejected immediately:
  - Either the request was already consumed (`ApprovalReused`),
  - It has expired (`ApprovalExpired`),
  - The context generation or target revision changed (`StaleContext`),
  - Or the request does not exist (`ApprovalNotFound`).
- If `sqlite3_changes()` returns `1`, the consumption succeeds, and the dependent operation record (e.g. audit event, task dispatch) is inserted within the same transaction before `COMMIT`.

### 4.3. Four-Tier Security Boundary Distinction
The persistence architecture explicitly distinguishes four authorization tiers:

| Tier | Boundary Scope | Phase 1 Status | Persistence Guarantees |
| --- | --- | --- | --- |
| **Tier 1: In-Memory Broker** | Single process thread execution | **Validated (5.3.1)** | Mutex-synchronized, Arc-pointer provenance, single-use token consumption. |
| **Tier 2: Persistent Storage** | Across process restarts on same host | **Initial subset implemented/tested in 5.4.2** | Durable state; explicit privileged receipt recovery; no identifier-only authority or full dispatch claim. |
| **Tier 3: Cross-Process Concurrency** | Local independent processes on the same approved database | **Owned two-process fixture tested in 5.4.2** | Exactly one consumption and atomic audit via IMMEDIATE; no CLI/daemon, distributed infrastructure or unauthenticated multi-user support. |
| **Tier 4: Human Authentication** | Cryptographic operator identity | **Not Implemented** | Phase 1 assumes local operator console. Remote identity/signatures are deferred to Phase 2. |

---

## 5. Schema & Migration Design

### 5.1. Target Schema Definitions (Version 1)

#### 1. Schema Migrations Audit Table
```sql
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TEXT NOT NULL,     -- RFC 3339 UTC timestamp
    checksum TEXT NOT NULL        -- Hash of migration SQL
);
```

#### 2. Sessions Table
```sql
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,               -- 36-char hyphenated UUID
    state TEXT NOT NULL,                       -- Created, Scoped, Planned, Running, WaitingForApproval, Paused, Completed, Failed, Cancelled
    mode TEXT NOT NULL,                        -- CONTINUOUS_REVIEW or DEEP_SECURITY_RESEARCH
    classification_floor TEXT NOT NULL,        -- Public, Internal, Confidential, Restricted
    context_generation INTEGER NOT NULL DEFAULT 1,
    target_revision TEXT NOT NULL,             -- Git commit hash or synthetic revision marker
    created_at TEXT NOT NULL,                  -- RFC 3339 UTC timestamp
    updated_at TEXT NOT NULL,                  -- RFC 3339 UTC timestamp
    completed_at TEXT,                         -- NULL until terminal state reached
    completeness TEXT,                         -- Complete, Partial, Unsupported, NULL
    failure_reason TEXT                        -- Diagnostic reason if state == 'Failed'
);

CREATE INDEX idx_sessions_state ON sessions(state);
CREATE INDEX idx_sessions_created_at ON sessions(created_at);
```

#### 3. Session Security Snapshots Table
```sql
CREATE TABLE session_security_snapshots (
    session_id TEXT NOT NULL,
    context_generation INTEGER NOT NULL,
    project_root TEXT NOT NULL,                -- Canonical absolute path
    operator_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    registered_at TEXT NOT NULL,               -- RFC 3339 UTC timestamp
    snapshot_json TEXT NOT NULL,               -- Complete serialized SessionMetadata
    PRIMARY KEY (session_id, context_generation),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);
```

#### 4. Audit Events Table
```sql
CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY,                 -- 36-char hyphenated UUID
    session_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,          -- Strictly monotonic per session (1, 2, 3...)
    event_kind TEXT NOT NULL,                  -- SessionTransition, PolicyDecision, ApprovalRequested, ApprovalConsumed, ToolExecuted, etc.
    classification TEXT NOT NULL,              -- Public, Internal, Confidential, Restricted
    timestamp TEXT NOT NULL,                   -- RFC 3339 UTC timestamp
    action_digest TEXT,                        -- Canonical V2 action descriptor, if applicable
    details_json TEXT NOT NULL,                -- Structured JSON payload
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    UNIQUE (session_id, sequence_number)       -- Prevents gaps or duplicate sequence numbers
);

CREATE INDEX idx_audit_session_seq ON audit_events(session_id, sequence_number);
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp);
```

#### 5. Approval Requests & Grants Table
```sql
CREATE TABLE approval_requests (
    request_id TEXT PRIMARY KEY,               -- 36-char hyphenated UUID
    session_id TEXT NOT NULL,
    context_generation INTEGER NOT NULL,
    target_revision TEXT NOT NULL,
    state TEXT NOT NULL,                       -- Pending, Issued, Consumed, Revoked, Expired
    action_name TEXT NOT NULL,                 -- EXECUTE_TOOL, MODIFY_CHECKOUT, etc.
    action_digest TEXT NOT NULL,               -- Canonical V2 length-prefixed descriptor
    classification TEXT NOT NULL,
    display_summary TEXT NOT NULL,             -- Redacted human-readable description
    created_at TEXT NOT NULL,                  -- RFC 3339 UTC timestamp
    expires_at TEXT NOT NULL,                  -- RFC 3339 UTC timestamp
    issued_at TEXT,
    consumed_at TEXT,
    consumed_action_digest TEXT,
    receipt_token TEXT,                        -- Nonce / correlation token for issued receipt
    revoked_at TEXT,
    revocation_reason TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_approvals_session ON approval_requests(session_id);
CREATE INDEX idx_approvals_state ON approval_requests(state);
CREATE INDEX idx_approvals_lookup ON approval_requests(session_id, state, expires_at);
```

#### 6. Budget Accounting & Reservations Table
```sql
CREATE TABLE budget_reservations (
    reservation_id TEXT PRIMARY KEY,           -- 36-char hyphenated UUID
    session_id TEXT NOT NULL,
    model_id TEXT NOT NULL,
    reserved_cost_micro_usd INTEGER NOT NULL,  -- Fixed-point u64 micro-dollars
    actual_cost_micro_usd INTEGER,             -- NULL until settled
    state TEXT NOT NULL,                       -- Reserved, Settled, Cancelled, Expired
    reserved_at TEXT NOT NULL,
    settled_at TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_budget_session ON budget_reservations(session_id);
```

### 5.2. Migration Execution & Failure Recovery Strategy
All schema evolution is managed via an embedded linear migration runner:

1. **Version Tracking:** The database stores the schema version in SQLite's header via `PRAGMA user_version` and in the `schema_migrations` audit table.
2. **Fresh Database Initialization:**
   - Detects `PRAGMA user_version = 0`.
   - Executes initial migration (DDL scripts 1 through $N$) inside a single transaction.
   - Sets `PRAGMA user_version = N`.
   - Records applied migrations in `schema_migrations`.
   - Commits cleanly.
3. **Existing Supported Schema:**
   - Detects `user_version = M` where $M < N$.
   - Executes each pending migration $(M+1) \dots N$ sequentially, each within its own transaction.
4. **Interrupted Migration Recovery:**
   - Because each migration script and its corresponding `PRAGMA user_version` update execute inside a single atomic transaction, a crash during migration rolls back completely.
   - Upon restart, `user_version` still reflects the last successfully completed migration. No partial tables remain.
5. **Newer Unknown Schema Version:**
   - If `user_version > N`, the engine fails closed with `PersistenceError::IncompatibleSchemaVersion { found, max_supported }`. The engine will **never attempt to run against a newer schema**.
6. **Corrupt Migration Metadata:**
   - If `user_version > 0` but `schema_migrations` is missing or inconsistent, the engine aborts with `PersistenceError::CorruptedSchemaMetadata`.

---

## 6. Corruption Handling & Diagnostic Quarantine

If a database fails integrity verification or returns corruption error codes:

1. **Detection:**
   - Upon engine startup, the connection manager runs:
     ```sql
     PRAGMA integrity_check(10);
     ```
   - If the result is not `["ok"]`, or if runtime queries return `SQLITE_CORRUPT` (11) or `SQLITE_NOTADB` (26).
2. **Immediate Fail-Closed Halt:**
   - All read and write operations are halted immediately.
   - No automatic in-place repair or destructive rewriting is attempted.
3. **Diagnostic Quarantine (5.4.2 owner-directed clarification):**
   - Halt managed operations and close the owned connection with checkpoint-on-close disabled. Preserve the DB, `-wal`, `-shm` and any `-journal` in their original locations.
   - Other processes cannot be proven quiescent. No automatic copy, rename, deletion, repair, recreation or restore is attempted. Several renames are not atomic; a database-only archive could abandon committed WAL frames.
   - Close/inspection failures are explicit and leave source data untouched. An operator-controlled consistent backup/recovery procedure is a later gate; no sensitive SQLite payload is included in ordinary diagnostics.

---

## 7. Production Rust Test Strategy (Increment 5.4.2+)

To validate the production SQLite persistence layer, a comprehensive, multi-tiered test suite will be implemented:

| Test Category | Target Invariant | Execution Environment |
| --- | --- | --- |
| **Repository CRUD** | Basic insert, query, update, and foreign-key cascade deletes across all tables | In-memory or temporary disk fixture (Deterministic) |
| **Statement Error Rollback** | Intentionally trigger duplicate primary key error; verify surrounding transaction rolls back and earlier writes are discarded | Synthetic temporary database (Deterministic) |
| **`SQLITE_BUSY_SNAPSHOT` Recovery** | Two interleaved connections reproduce error 517; verify full rollback, fresh transaction restart, re-read, and successful commit | Multi-connection synthetic fixture (Deterministic) |
| **Bounded Retry Backoff** | Verify exponential backoff and eventual fail-closed behavior when snapshot contention persists beyond 5 retries | Mock contention fixture (Deterministic) |
| **Audit Atomicity** | Verify that a session transition failure rolls back the corresponding audit event, preventing audit/state divergence | Synthetic temporary database (Deterministic) |
| **Approval Single-Use Consumption** | 20 concurrent threads race to consume the same persistent approval grant; verify exactly 1 succeeds and 19 receive `ApprovalReused` | Multi-threaded barrier test on SQLite (Deterministic) |
| **Process Crash & WAL Recovery** | Launch child worker process performing batch writes; terminate process at defined instruction boundary; reopen database and verify WAL recovery | Owned subprocess termination test on Windows (Non-destructive) |
| **Corruption Detection** | Intentionally truncate database header or flip bytes in a disposable test copy; verify `PRAGMA integrity_check` fails closed with `SQLITE_CORRUPT` | Disposable synthetic copy (Non-destructive) |
| **Migration Interruption** | Simulate failure mid-migration; reopen and verify clean rollback to previous `user_version` | Synthetic migration test (Deterministic) |

---

## 8. Implementation Roadmap (Increment 5.4.2 Onward)

- **Increment 5.4.2: Dependency Integration & Schema Migration Engine**
  - Add `rusqlite = { version = "0.32.1", features = ["bundled"] }` and `serde` / `serde_json` to `crates/sentra-core/Cargo.toml`.
  - Implement `SqliteConnectionManager`, PRAGMA initialization, and versioned migration runner.
  - Implement initial schema DDL and unit tests.
- **Increment 5.4.3: Session & Audit Persistence**
  - Implement `SessionRepository` and `AuditRepository`.
  - Implement atomic session state transition + audit event transaction scoping.
  - Implement statement-error explicit rollback and `SQLITE_BUSY_SNAPSHOT` retry protocol.
- **Increment 5.4.4: Approval & Budget Persistence**
  - Implement `ApprovalRepository` and `BudgetRepository`.
  - Enforce atomic single-use approval consumption and context generation binding.
  - Add multi-threaded persistent race tests.
- **Increment 5.4.5: Crash Recovery & End-to-End Persistence Validation**
  - Implement subprocess termination recovery tests and corruption handling.
  - Execute full workspace verification suite across all core modules.
