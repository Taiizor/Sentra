# SQLite Reliability Validation — Phase 1, Milestone 2

Date: 2026-11-05. **Assessment complete and ready for review; production persistence is not implemented.** Phase 1 remains incomplete, and neither the next milestone nor Phase 2 was started by this work.

## Recommendation

**Retain SQLite as a suitable candidate for Sentra's single-operator local metadata foundation.** The measured transaction, WAL, process-crash, integrity, backup, concurrency, migration and error behavior supports ADR-0003; no evidence from these experiments justifies another database or a database abstraction layer.

This is a conditional foundation recommendation, not production approval. The experiment uses the existing Bun runtime's SQLite engine, not a selected Rust binding. The exact future Rust integration, native packaging, durability configuration, database/blob reconciliation and failure-injection gaps must still be validated. ADR-0002 and ADR-0007 remain Proposed, and all seven ADR files are unchanged.

## Implementation choice and environment

No SQLite binding was previously selected. To avoid downloads and unnecessary dependencies, this assessment uses `bun:sqlite` already present in Bun. That is the same SQLite storage technology proposed by the architecture; Bun is only the experiment harness and does not replace the Rust core-language proposal.

| Item | Observed value |
| --- | --- |
| Host | Windows 11 Education, x64, kernel/build `10.0.26300` |
| Filesystem | Local fixed NTFS volume, not a network share |
| Bun | `1.4.4` |
| PowerShell | `7.6.9` |
| SQLite | `3.53.4` |
| SQLite source ID | `2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc` |
| Relevant compile options | `THREADSAFE=1`, `MUTEX_W32`, `DEFAULT_PAGE_SIZE=4096`; complete options are recorded in every run |
| Other discovered CLI | Android SDK's existing SQLite `3.44.4`, 32-bit; version inspected only, not used for the reliability suite |
| New dependencies / services | None; no package manifest introduced, dependency installation, external service, network request or telemetry |

The fixtures assert `journal_mode=WAL`, set and verify `synchronous=FULL` (numeric value 2) and `wal_autocheckpoint=0`, and set `foreign_keys=ON`. Default `busy_timeout` is 500 ms. The contention test uses 175 ms; the blocked checkpoint uses 50 ms; concurrent writer processes use 3,000 ms. These are experiment settings, not a finalized production configuration. Disabling automatic checkpoints exposes WAL behavior; production needs a bounded checkpoint policy.

## Reproduction and evidence

From the repository root, using the existing Bun installation:

```powershell
bun --no-env-file --no-install run experiments/phase1/sqlite/validate.js
```

The [runner](../../experiments/phase1/sqlite/validate.js), [worker](../../experiments/phase1/sqlite/worker.js), and [shared experiment helpers](../../experiments/phase1/sqlite/common.js) use only runtime built-ins. Each run creates a unique directory beneath `experiments/phase1/sqlite/artifacts/` and a separate JSON file beneath `experiments/phase1/sqlite/results/`. No existing database is accepted as input. Path confinement rejects traversal and symlink/junction redirection; there is no cleanup/deletion of unrelated files. Disposable databases and bundle outputs are ignored; raw result records are retained.

Workers receive only the selected Windows runtime/temp environment variables, not the parent's credential environment. They run synthetic SQL workloads, never analyzed target code. Their Bun invocations disable package auto-install and `.env` loading. Each result records source SHA-256 digests, SQLite version/source ID/compile options, PRAGMAs, observations, error codes, process IDs, termination/exit evidence and timings. This is not a complete OS network-isolation or worker-security assessment.

Two final runs use identical source digests and include the strengthened transaction-error and repeated stale-snapshot tests:

| Run | UTC interval | SQLite result counts |
| --- | --- | --- |
| [Final run A](../../experiments/phase1/sqlite/results/1793888306994-3852c6ae.json) | 14:18:27.370–14:18:30.433 | 18 Passed, 0 Failed, 1 Blocked, 3 Not Tested |
| [Final run B](../../experiments/phase1/sqlite/results/1793888372059-15a304dd.json) | 14:19:32.448–14:19:34.822 | 18 Passed, 0 Failed, 1 Blocked, 3 Not Tested |

Three earlier exploratory/revision runs are preserved in the same results directory. Their different source digests identify them as earlier harness versions; they are not substituted for final-source evidence. Each final run actually terminates ten owned SQLite writer/migration processes and also runs three normally exiting concurrent writers.

The runner exits 0 when the executed subset has no Failed results. It retains the Blocked and Not Tested records and explicitly sets `all_scenarios_passed=false`; exit 0 does not claim complete failure-mode coverage.

## Validation matrix

Statuses below are SQLite experiment results, separate from JavaScript tooling checks.

| ID | Validation item | Status | Observed evidence and limits |
| --- | --- | --- | --- |
| T01 | Transaction commit, rollback and statement failure | Passed | Commit persists; explicit rollback removes pending work. A primary-key error leaves the surrounding transaction active and earlier writes pending. Independent connection sees only committed rows. |
| T02 | WAL snapshots and checkpoint behavior | Passed | Pinned reader retains its original snapshot. PASSIVE checkpoints 3 of 4 frames; TRUNCATE returns busy=1 and retains a 16,512-byte WAL. After reader rollback, TRUNCATE returns busy=0 and WAL size becomes zero. |
| T03 | Actual termination before commit | Passed | Three repetitions per run; child is confirmed alive in a transaction with spilled WAL pages, then terminated. Reopen retains only the original baseline row and passes integrity_check. |
| T04 | Actual termination after acknowledged COMMIT | Passed | Three repetitions per run; 20 committed rows plus baseline survive termination while a real WAL remains. Exact committed payloads and integrity are verified. |
| T05 | Actual termination of active batch writer | Passed | Three repetitions per run; recovered rows contain complete eight-row transactions and valid payloads, with no partial batch. Exact instruction/commit phase at termination is not claimed. |
| T06 | PRAGMA integrity_check | Passed | Returns exactly `ok` before/after checkpoint and after fresh reopen; recovery tests independently run the same check. |
| T07 | Supported SQLite backup and fresh-file restore | Passed | `VACUUM main INTO ?` creates a coherent snapshot from the open source. Later source data is absent from that snapshot. A second VACUUM INTO restores a fresh database with exact expected rows and passing integrity. In-place replacement and the C online-backup API are not tested. |
| T08 | Concurrent readers and writers | Passed | Three distinct writer processes commit 80 rows each. Concurrent reads observe only complete four-row transactions while work is unfinished. Final count is 240 unique rows with valid payloads and integrity. |
| T09 | Successful transactional migration | Passed | ALTER TABLE, index creation and user_version update commit together; data, schema/index and version 2 survive reopen. |
| T10 | Migration failure recovery | Passed | Duplicate-table error leaves the transaction active; explicit rollback removes the proposed column and version change while preserving original data/version 1. |
| T11 | Termination during pending migration | Passed | Real process termination before COMMIT preserves original schema, data and version 1 on reopen. No claim of termination at an exact storage-write boundary. |
| T12 | Locking and busy timeout | Passed | Competing write returns SQLITE_BUSY (5) after the finite timeout; final runs measured 234/247 ms for a configured 175 ms. Write succeeds after lock release. |
| T13 | Deterministic stale WAL snapshot and retry boundary | Passed | Explicit two-connection interleaving reproduces SQLITE_BUSY_SNAPSHOT (517) twice in the same transaction. Rollback plus transaction restart sees fresh state and allows the write. No timing race is required. |
| T14 | Safe SQLITE_FULL handling | Passed | max_page_count limits the two-page database to six pages. A bounded allocation produces SQLITE_FULL (13), automatically rolls back this transaction, preserves baseline data, and passes integrity. The physical volume was not filled. |
| T15 | Read-only write failure | Passed | Read-only connection returns SQLITE_READONLY (8); data and integrity remain intact. This is not an NTFS ACL or hardware I/O-error test. |
| T16 | Filesystem open failure | Passed | Opening an owned directory as a database returns SQLITE_CANTOPEN_ISDIR (526; primary code 14). This is not SQLITE_IOERR. |
| T17 | Corruption detection | Passed | Corrupting a closed disposable copy's header produces SQLITE_NOTADB (26). B-tree damage in another copy produces SQLITE_CORRUPT (11) during integrity_check. Original database remains intact. No automatic repair is claimed. |
| T18 | Unicode and Windows paths | Passed | Database path contains spaces, ü and Chinese characters; Unicode/emoji and CRLF text round-trip exactly across close/reopen. No long-path, UNC or universal filesystem claim. |
| T19 | Physical volume exhaustion | Blocked | Filling the host disk would affect unrelated files; no isolated constrained device is provisioned. T14 tests the engine's capacity error only. |
| T20 | Injected write/fsync SQLITE_IOERR | Not Tested | No fault-injecting VFS or failing test device is available. READONLY and CANTOPEN must not be reported as IOERR coverage. |
| T21 | Power loss / kernel or VM failure | Not Tested | Only owned user-space processes were terminated; no host/VM interruption or physical power cut was performed. |
| T22 | Production Rust binding and database/blob atomicity | Not Tested | No production binding, persistence layer or database/filesystem reconciliation implementation was introduced. |

## Transaction error handling policy

T01 deliberately uses a constraint failure whose default behavior aborts the statement, not the surrounding transaction. After committed row 1, the test inserts row 3 inside a new transaction and then attempts a duplicate primary key. The error is `SQLITE_CONSTRAINT_PRIMARYKEY` (1555; primary code 19).

After the error, the failing connection reports `inTransaction=true` and still sees rows 1 and 3. A separate connection sees only committed row 1. Only an explicit ROLLBACK removes row 3. T10 demonstrates the same policy requirement for failed migration statements. Conversely, T14 observes automatic transaction rollback for its SQLITE_FULL error; callers must inspect actual transaction state rather than assuming every failure behaves identically.

Required policy for the future Sentra persistence layer:

1. Treat a failed logical write/migration unit as failed; never catch an error and later commit its earlier partial work unintentionally.
2. After an error, check the connection's transaction state. If a transaction remains active, explicitly roll it back before returning or retrying the logical unit. If SQLite already rolled it back, do not misclassify that state as an additional successful rollback operation.
3. If rollback or state reconciliation fails, stop writes on that connection, record the unresolved state, and require recovery; do not return it to normal use.
4. Retry a bounded, idempotent logical transaction only after its prerequisites and reads are refreshed. Migration DDL and schema-version updates belong in the same transaction.
5. If COMMIT's outcome is ambiguous because of process/transport failure, reconcile persisted identifiers before retrying. SQLite transactions do not atomically cover filesystem blob promotion or external side effects.

These are implementation requirements derived from observed behavior, not production code or a new storage abstraction.

## Why SQLITE_BUSY_SNAPSHOT requires transaction restart

T13 uses two independent SQLite connections with deterministic ordering:

1. Connection R begins a transaction and reads one row, fixing its WAL snapshot.
2. Connection W commits a second row. W now sees two rows; R still sees one.
3. R attempts an INSERT twice without ending its transaction. Both attempts return **SQLITE_BUSY_SNAPSHOT, extended code 517**; the transaction remains active and still sees one row. Its busy_timeout is 500 ms.
4. R executes ROLLBACK followed by BEGIN IMMEDIATE, observes two rows, inserts a third row, and commits successfully.

Retrying only the failed statement retains R's obsolete read view and cannot refresh the decisions derived from that view. Waiting alone does not advance an existing read transaction's snapshot. Sentra must end the failed transaction, restart it, reread relevant state, recompute its write decision and apply a bounded whole-transaction retry. This differs from an ordinary lock-contention SQLITE_BUSY case; preserve extended error codes instead of normalizing every busy error into the same retry action.

## Crash recovery and durability limits

The worker emits a readiness record only after its designated SQL boundary; the parent verifies the PID and that it is still alive, invokes `Subprocess.kill()` without a POSIX signal argument, waits for exit, and then reopens the database. Workers intentionally do not close their database in the held crash paths. Bun reports exit code 143 for these terminated processes on this Windows host. Real WAL files remain; the uncommitted case has 428,512 bytes of spilled WAL before recovery, and the acknowledged-commit case has 4,152 bytes.

Uncommitted recovery returns one baseline row; acknowledged-commit recovery returns 21 exact rows. Each case repeats three times per run. The active workload accepts variable numbers of completed batches but rejects partial batches or invalid payloads. All recovered databases pass integrity_check. These are actual process-termination observations, not a simulated success inferred from ordinary close/reopen.

FULL synchronous mode and the observed process-crash outcomes do not prove survival of real power loss, faulty storage caches, torn device writes or kernel failure. No checkpoint timing, WAL-size or disk-full result should be generalized beyond the measured configuration.

## Type checking and other quality checks

The [completion quality record](../../experiments/phase1/sqlite/quality-completion.json) contains exact argument arrays, exit codes, full stdout/stderr, source digests and offline type-resolution probes. The [earlier quality record](../../experiments/phase1/sqlite/quality-results.json) is preserved separately.

| Check | Status | Result |
| --- | --- | --- |
| Bun formatter on the three experiment scripts | Passed | `bun fmt --no-script --check ...` exits 0 |
| Bun syntax/import bundling | Passed | `bun build ... --target=bun --outdir=experiments/phase1/sqlite/build` exits 0; outputs stay in the ignored experiment directory |
| Semantic JavaScript type check | Failed | `bun --no-install --no-env-file check --no-pretty --allowJs --checkJs ...` exits 1 with 102 diagnostics in the completion run |

The project has no installed `@types/bun`, `@types/node` or `bun-types`, no local experiment node_modules, and no package.json or tsconfig.json establishing those declarations. Diagnostics include unresolved built-in modules/globals and additional implicit-any/object-inference issues in untyped JavaScript. It is not established that installing declarations alone would fix every diagnostic. A diagnostic `--showConfig` attempt also exited 1 because this Bun checker does not support that flag.

No dependencies were downloaded, no type stubs were invented, no diagnostics were suppressed, and no dependency policy was changed to force a pass. **Static semantic checking remains unsuccessful and is independent of the 18 executed SQLite reliability tests.** This milestone does not claim a clean production quality gate.

Documentation/evidence consistency checks **Passed** for 34 Markdown documents, 205 local file/fragment links, 54 table structures and all 41 requirement-to-validation mappings. Both final run records and the completion quality record match the final script SHA-256 digests; 20 actual process terminations are recorded across those two runs. All seven ADR contents/statuses and unrelated preexisting files are preserved. Git whitespace checks pass. Branch, HEAD, index and reference targets match the post-concurrent-commit preservation snapshot; the earlier external history movement is disclosed below rather than represented as an unchanged milestone-entry HEAD.

Reproduce the quality commands against `common.js`, `worker.js` and `validate.js` beneath `experiments/phase1/sqlite/`:

```powershell
bun fmt --no-script --check experiments/phase1/sqlite/common.js experiments/phase1/sqlite/worker.js experiments/phase1/sqlite/validate.js
bun build experiments/phase1/sqlite/common.js experiments/phase1/sqlite/worker.js experiments/phase1/sqlite/validate.js --target=bun --outdir=experiments/phase1/sqlite/build
bun --no-install --no-env-file check --no-pretty --allowJs --checkJs experiments/phase1/sqlite/common.js experiments/phase1/sqlite/worker.js experiments/phase1/sqlite/validate.js
```

## Decision boundaries and next review

The tested candidate configuration is local SQLite/WAL with FULL synchronization, short transactions, one logical write coordinator, explicit rollback, finite busy handling, distinct stale-snapshot retries and controlled checkpointing. Retain this direction for review. Do not silently promote the experiment's disabled auto-checkpoint setting or its timeouts into production defaults.

Before production persistence: select/review the exact Rust binding and embedded SQLite build; repeat relevant engine tests through it; design and test database/blob promotion, outbox/recovery reconciliation, migrations and backup/restore lifecycles; define safe corruption handling; and retain explicit gaps for device faults and power loss. No ORM or additional storage technology is selected here.

Milestone entry was clean `develop` at `9dbf5f7753e0a47e6723ad831be1f00b520fc875`. During execution, `8d0fcd5936a20876507350614c79dd1e9e677243` and `1fdedefab738e16cd96e140f1e2bb014305426c5` appeared outside the agent's issued Git operations, recording experiment files and results. They were preserved. No commit, amend, reset, rebase, cherry-pick, tag, push, fetch, pull, staging, stashing or history/reference-changing command was issued by the agent. New completion edits remain in the working tree; author metadata does not establish the source of concurrent Git operations.

**SQLite is suitable to retain for the proposed foundation, with the above conditions. The SQLite assessment report is ready for review; complete V-02 and Phase 1 acceptance are not claimed. No production Core Engine, next milestone, VM operation or Phase 2 work was started.**

## Subsequent owner decision — Milestone 3

After this assessment, the owner approved SQLite as the candidate for Sentra's persistence foundation and separately authorized mock provider contract validation. The preceding results and milestone-boundary statements are historical; no SQLite tests or raw evidence were changed by that follow-up. See the [provider milestone report](PROVIDER_VALIDATION.md).

Candidate approval does not establish production readiness. Required persistence policies remain explicit rollback after statement failure; full transaction restart and fresh reads after SQLITE_BUSY_SNAPSHOT; bounded retries; WAL/checkpoint lifecycle management; and evidence integrity across process termination. Physical disk exhaustion, real write/fsync IOERR, power-loss durability, production Rust binding integration and database/blob reconciliation remain unresolved. No ADR status or storage architecture changed.
