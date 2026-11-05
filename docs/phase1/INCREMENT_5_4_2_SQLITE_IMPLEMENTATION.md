# Increment 5.4.2 — SQLite Persistence Foundation

Date: 2026-11-05. **Implemented and tested on Windows x64/MSVC; foundation ready for review. This is not production-readiness certification or Phase 1 completion.** The owner authorized this increment; Increment 5.4.3 and Phase 2 have not started. All seven ADRs retain their existing status (0002 and 0007 Proposed).

## Scope and implementation

The [persistence module](../../crates/sentra-core/src/persistence/mod.rs) adds a concrete local adapter. It does not replace the existing in-memory broker, session state machine or workspace boundary, grant permission to open target content, or dispatch any operation. A committed consumption record is a storage result, not an execution capability.

| Component | Implemented boundary |
| --- | --- |
| `connection.rs` | Explicit local database selection, serialized owned connection, verified settings, integrity checks, checkpoint/shutdown and in-place quarantine |
| `transaction.rs` | Private managed statements/queries, error latch, explicit rollback, separate rollback failure, whole-operation retry |
| `migration.rs`, `schema_v1.sql` | Atomic version 1 migration, migration history/fingerprint and exact schema-object validation |
| `model.rs` | Validated storage DTOs, existing domain IDs/timestamps/costs, redacted projections and private receipts |
| `repository.rs` | Sessions/security snapshots, atomic approval/audit transitions and conservative budget reservations |
| `policy/engine.rs` | Existing operation validation and no-write-down rules extracted into one shared crate-private check; no separate permissive policy path |
| `tests/persistence_tests.rs`, `tests/support/persistence.rs` | Owned synthetic databases, deterministic barriers/pipes, real independent-process fixtures and cleanup |
| `experiments/phase1/persistence/Validate.ps1` | Offline commands, input fingerprints, feature graph, resolved licenses, raw outputs and repeated process races |

No production SQL callback, raw connection, long-lived read handle or provider implementation is exported. Typed repository methods return only after their transaction commits. Bootstrap code retains `PersistentApprovalAuthority` and the connection manager; model/target/request handlers must receive neither. As in the existing broker design, the bootstrap factory is a privileged application-composition boundary, not protection against malicious code already executing in the controller process.

## Dependencies and native build evidence

Exactly three direct dependencies are pinned in [Cargo.toml](../../crates/sentra-core/Cargo.toml): `rusqlite =0.32.1` with `bundled` and no default features, `serde =1.0.229` with `derive`, and `serde_json =1.0.154`. JSON is used only for versioned security snapshots and inert structured audit payloads. No ORM, async runtime, transport, `uuid`, `chrono`, `sha2` or custom cryptographic hash is added. `#![forbid(unsafe_code)]` remains in Sentra; it does not constrain dependency-internal FFI/unsafe code or C.

The initial [recorded build](../../experiments/phase1/persistence/results/1793909666845.json) compiled the included `sqlite3/sqlite3.c` using `D:/Program Files/Microsoft Visual Studio/2026/Insiders/VC/Tools/MSVC/14.52.37025/bin/HostX64/x64/cl.exe` and the static archive step through `lib.exe`, targeting `x86_64-pc-windows-msvc`. Native build exit: 0 (68,615 ms). The final [validation run](../../experiments/phase1/persistence/results/1793911046516.json) builds the final sources offline, records exact commands/output and confirms unchanged source inputs. Rust/Cargo are 1.99.0; actual PowerShell is 7.6.9. The runtime query and test report **SQLite 3.46.0**, correcting 5.4.1's 3.45.3 estimate. Earlier Bun SQLite 3.53.4 results remain separate historical engine evidence.

`Cargo.lock` contains 31 external packages, including unused optional/platform resolution entries `syn 2.0.119` and `zerocopy-derive 0.8.63`. Unfiltered `cargo metadata --offline --format-version=1` **Failed** (101): Cargo refused retrieval of uncached `syn 2.0.119`. No download occurred. Metadata with `--filter-platform x86_64-pc-windows-msvc` **Passed**, resolving the actual graph of 29 external packages below. This is an explicit platform limitation, not a workaround permitting downloads or a claim that every platform's metadata is available offline.

| Resolved Windows package | Version | Manifest license expression |
| --- | --- | --- |
| ahash | 0.8.12 | MIT OR Apache-2.0 |
| bitflags | 2.13.2 | MIT OR Apache-2.0 |
| cc (build) | 1.10.0 | MIT OR Apache-2.0 |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 |
| fallible-iterator | 0.3.0 | MIT/Apache-2.0 |
| fallible-streaming-iterator | 0.1.9 | MIT/Apache-2.0 |
| find-msvc-tools (build) | 0.1.15 | MIT OR Apache-2.0 |
| hashbrown | 0.14.5 | MIT OR Apache-2.0 |
| hashlink | 0.9.1 | MIT OR Apache-2.0 |
| itoa | 1.0.18 | MIT OR Apache-2.0 |
| libsqlite3-sys | 0.30.1 | MIT (wrapper); bundled SQLite carries its public-domain notice |
| memchr | 2.8.3 | Unlicense OR MIT |
| once_cell | 1.21.4 | MIT OR Apache-2.0 |
| pkg-config (build) | 0.3.34 | MIT OR Apache-2.0 |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 |
| quote | 1.0.47 | MIT OR Apache-2.0 |
| rusqlite | 0.32.1 | MIT |
| serde | 1.0.229 | MIT OR Apache-2.0 |
| serde_core | 1.0.229 | MIT OR Apache-2.0 |
| serde_derive (proc macro) | 1.0.229 | MIT OR Apache-2.0 |
| serde_json | 1.0.154 | MIT OR Apache-2.0 |
| shlex (build) | 2.0.1 | MIT OR Apache-2.0 |
| smallvec | 1.16.4 | MIT OR Apache-2.0 |
| syn | 3.0.9 | MIT OR Apache-2.0 |
| unicode-ident | 1.0.27 | (MIT OR Apache-2.0) AND Unicode-3.0 |
| vcpkg (build) | 0.2.15 | MIT/Apache-2.0 |
| version_check (build) | 0.9.5 | MIT/Apache-2.0 |
| zerocopy | 0.8.63 | BSD-2-Clause OR Apache-2.0 OR MIT |
| zmij | 1.0.23 | MIT |

The raw `cargo tree --offline -e features` is the complete selected feature graph. `pkg-config` and `vcpkg` are compiled Rust build dependencies; the bundled path uses MSVC rather than an external SQLite installation. Bindings are pre-generated. Upstream C compilation flags, including its `-W0` default, are recorded; warning-free Rust Clippy is not an independent C warning/static-analysis certification. The bundled C has additional features (including compiled extension-loading support); the managed connection does not enable extension loading or expose its API. A native test confirms SQL `load_extension` is not authorized. These manifest/local-source license observations are an inventory, not completed distribution/notices review, fresh advisory analysis or legal certification. Sentra itself still has no selected license; ADR-0007 remains Proposed.

## Connection lifecycle, paths and settings

One `Arc`-shared manager owns one `Mutex`-serialized connection, opened with READ_WRITE, NO_MUTEX and NOFOLLOW; CREATE is added only for a missing explicitly selected file. There is no pool. All repository reads use short fresh managed transactions on that same connection, simplifying initial ownership at the cost of read concurrency. Locks are released before retry backoff. Shutdown covers its checkpoint and close under the same mutex, preventing a managed write between them.

The parent must already exist on an operator-approved local filesystem. Relative, parent-traversal, UNC/device, drive-relative, ADS, reserved-device, inaccessible and statically indirect paths are rejected. The filesystem-canonical parent's prefix is checked again before opening SQLite, so a drive spelling that canonicalizes to UNC cannot bypass the initial prefix check; actual mapped-provider behavior remains Not Tested. Each existing recovery-set member must be an ordinary file. Parent directories are inspected and pinned by Windows attribute handles; those handles live until the last manager clone is dropped. Unicode/whitespace paths work. Windows verbatim paths interpret separators differently: a native test exposed a mixed-spelling ambiguity during development, and normal components containing separator characters are now rejected instead of passed to SQLite. Ordinary drive paths and std-canonical native verbatim paths are supported; ambiguous spellings fail closed.

These checks do not prove safe handle-relative VFS access, prevent all hostile sidecar/ancestor races, identify every mapped remote provider, or replace OS ACLs. The database directory is trusted controller storage, never a target workspace or a directory writable by an untrusted worker. An approved local filesystem/encrypted volume and operator permissions remain prerequisites. No race-free isolation, UNC support or cross-platform validation is claimed.

| Setting | Effective value verified after initialization | Scope |
| --- | --- | --- |
| foreign_keys | 1 / ON | Connection; reapply on every open |
| journal_mode | wal | Persistent database mode; still verify on every open |
| synchronous | 2 / FULL | Connection; no physical power-loss proof |
| busy_timeout | 5000 ms | Connection; each contended attempt may wait this long |
| wal_autocheckpoint | 1000 pages | Connection's committing-thread PASSIVE hook, not a background worker |
| trusted_schema | 0 / OFF | Additional connection hardening, verified |

Safe `DbConfig` also enables DEFENSIVE and NO_CKPT_ON_CLOSE, checking the returned effective booleans. Startup runs `integrity_check(10)`, rejects foreign/newer databases before journal-mode writes, applies/reads back settings, then migrates/validates. A supported database with inconsistent history is rejected without recreation; no failed initialization reports success. Actual changes to five connection settings in a private native test are rejected by the verifier. The managed connection itself rejects an orphan FK insert (extended code 787).

## Transactions and retry protocol

Every managed write begins IMMEDIATE. Statement, preparation, row conversion, query and commit errors abort the active transaction explicitly; an error latch prevents committing earlier work even if an internal caller catches an error. Business-condition errors also roll back. SQLite FULL/IOERR can already auto-abort: `is_autocommit()` is checked so a completed automatic rollback is not misreported as a second rollback failure. Ordinary error handling does not rely on `Drop`; panic cleanup is best effort and a poisoned manager denies subsequent access.

Rollback failure has a separate category/code and retains the original statement code; the manager halts on rollback or integrity failure. The rollback-failure unit case is **explicit fault injection**, not a real write/fsync failure. Non-contention errors are not retried, including ambiguous I/O/commit outcomes.

BUSY (5) and BUSY_SNAPSHOT (517) retain their distinct extended codes. The shared private retry loop performs at most **five total attempts**, four bounded jittered delays within 10–250 ms, and a fresh transaction/complete method body on every attempt. All stored context, current approval state, audit sequence and budget totals are read inside that body. `Clock` is injected and read inside each relevant attempt; there are no new wall-clock authorization calls. A persistent contention failure returns `RetryExhausted`, original code and `attempts=5`; the total operation can exceed 25 seconds because each attempt has the 5000 ms SQLite timeout.

Production IMMEDIATE writes normally avoid stale read-to-write promotion. The native regression deliberately begins its **first** read DEFERRED, commits a conflicting write on another connection, observes actual 517 and full rollback, then uses the shared retry machinery and IMMEDIATE to read the new value and commit. Reads observed `[0,1]`, final value `2`; this is not a fabricated error or a production DEFERRED path. Separate real BEGIN contention with a test-only zero timeout proves five attempts, four backoffs and zero entries into business logic. A 5000 ms timeout test exercises actual ordinary BUSY independently.

No public retryable callback exists. Private closures contain database work and clock reads only; provider calls, host filesystem changes, execution and networking are absent. Compile-fail coverage rejects an external callback attempting a filesystem side effect. This does not make arbitrary future internal closures safe: code review must preserve the boundary.

## Schema and migrations

The [embedded migration](../../crates/sentra-core/src/persistence/schema_v1.sql) creates exactly the six approved tables and their indexes: `schema_migrations`, `sessions`, `session_security_snapshots`, `audit_events`, `approval_requests`, `budget_reservations`. It uses existing domain state/mode names rather than the imaginary mode names in the earlier sketch; no architecture change or extra storage is introduced.

Version 1 DDL, its migration row, `user_version=1` and Sentra `application_id` commit together under IMMEDIATE. Current schema objects (including SQL definitions), description, fingerprint, row count, version and foreign-key consistency are compared against the trusted embedded template; unknown objects, missing history, drift and unknown newer versions fail closed. Trusted migration text and SQL-object comparisons normalize CRLF to LF; a native LF/CRLF template/fingerprint regression confirms Git checkout endings do not create false drift, while other source changes remain detected. A repeated initializer preserves existing supported data. The checksum is named `fnv1a64` and detects accidental migration drift only. It is **not** a cryptographic digest, authenticity check or defense against someone able to rewrite both schema and metadata. No custom SHA-256 was implemented.

Constraints cover FK relationships (including an approval's session/generation snapshot), unique per-session audit sequence, supported state values, nonnegative bounded money, JSON validity, canonical-width times, and required consumed fields. Domain parsing also checks ASCII identifiers before existing parsers, calendar round trips, dates 1970–9999 and integer conversions, avoiding silent truncation or malformed UTF-8 slicing. SQLite INTEGER limits persisted costs/generations/sequences to `i64::MAX`; the wider domain's `u64` values above that are explicitly rejected.

The trusted budget limit is versioned inside `snapshot_json`, retaining the six-table design. New context registration increments persisted generation; old snapshots remain. There are no destructive migrations, automatic repairs, task/outbox/blob schemas or fallback databases. Process interruption during actual embedded DDL leaves a fresh initialization recoverable; a separate invalid-SQL migration test proves explicit rollback of all partial tables/version changes.

## Persistent authorization, audit and budgets

The privileged local authority registers current metadata/revision/floor/budget, issues a PENDING request, explicitly recovers an already issued receipt after reopen, or revokes it. Untrusted metadata alone cannot mint or restore a receipt. Receipts have private fields, no deserializer, a repository-local `Arc` provenance seal, and frozen snapshot/approval data. The stored correlation token is deliberately **not** a secret, bearer credential, random nonce or cryptographic signature. Caller IDs have uniqueness checks; secure production UUID generation remains fail-closed and deferred.

Consumption checks local provenance first and, within one transaction, re-reads the trusted current snapshot and issued record; validates complete metadata, generation, revision, canonical action/type/arguments/target, classification, issued/expiry times and frozen record fields; then performs a fully conditioned ISSUED→CONSUMED update requiring exactly one affected row and appends its audit event. Only the subsequent COMMIT returns success. A mismatch leaves the valid grant and audit log unchanged. Re-registration/ABA, expiry, revocation, replay and terminal sessions deny. The exact prior synthetic A→B probe is covered through the persistent consumption path; the existing policy/broker probe and 27 regressions also continue to pass.

One success under a shared mutex is not the only evidence: separate managers/connections and **two independent owned test processes** each obtain explicit privileged recovery receipts before a pipe barrier, then race on the same database. Exactly one consumes; the other receives ApprovalReused; exactly one consumption audit commits. This tests local cross-process database single-use, not distributed grants, authenticated humans or hostile processes with write access to the database. Trusted bootstrap/OS storage protection remains necessary. No automatic cross-process receipt trust or in-memory grant conversion is introduced.

Audit insertion allocates `MAX(sequence_number)+1` inside the serialized write transaction and relies on UNIQUE(session_id, sequence_number) for collision rejection. Uniqueness alone would not prove monotonic order; the allocator/transaction supplies that rule. Each payload retains current generation, revision, policy/operator references and operation-specific inert details. No append/update/delete SQL interface is exposed to consumers. Duplicate event IDs deliberately injected in tests roll back the preceding session transition, approval consumption, reservation or settlement. Success is not logged or returned before COMMIT. Explicit audit data is classified; ordinary Debug/Display does not reveal paths, tokens or action payloads. There is no cryptographic audit chaining or resistance to a database administrator rewriting history.

Budget reservation recomputes committed spend plus unresolved upper bounds in the same IMMEDIATE transaction before inserting and auditing. Concurrent threads and separate connections cannot exceed the registered limit. Final accounting uses fixed-point micro-dollars only. Unconfirmed cancellation ignores partial usage receipts and retains the full bound; confirmed cancellation with unknown usage also retains it. A delayed unconfirmed partial receipt cannot revert that confirmed CANCELLED state. Only trusted final usage reconciles/releases an unused portion. A zero quoted reservation with unknown final usage stays unknown, not an invented invoice. Invalid/overflowing values and final usage above the reserved upper bound deny; reducing a session limit below held spend/reservations denies.

These are persistence primitives, not an integrated paid-operation dispatcher. Atomic composition of grant consumption, a particular reservation, provider transport, leases/outbox and external side-effect recovery is deferred. No real pricing, token counts, provider termination, filesystem revision acquisition or human identity is inferred. Full S-02/S-06 and end-to-end Phase 1 acceptance remain open.

## WAL lifecycle and conservative recovery

Terminal session transitions attempt PASSIVE **after** the state/audit commit and return its checkpoint result separately; a checkpoint failure cannot replay or undo a committed transition. Explicit clean shutdown attempts TRUNCATE and closes only on successful checkpoint. A pinned reader test observes an actual blocked shutdown, nonempty WAL and recorded checkpoint progress, then releases the reader and succeeds with WAL reduction to zero. Errors never masquerade as clean shutdown. Dropping an unclosed manager does not claim a successful clean shutdown.

Startup `integrity_check(10)` failures and runtime corruption fail closed. There is no automatic repair, deletion, truncation, recreation or restore. `quarantine_in_place` halts all clones of that manager and closes its owned connection with automatic checkpoint-on-close disabled, retaining DB/WAL/SHM/rollback journal in their original locations. Source database and WAL bytes and SHM presence are tested across closure; the set remains recoverable on an explicit test-controlled reopen. SHM is a rebuildable index, not an immutable evidence digest. Existing archive-name artifacts remain untouched.

No sequence of independent renames is called atomic. No multi-file archive/copy routine is implemented: the adapter cannot prove other processes have closed their connections or that a moving recovery set is consistent. It therefore uses the user's required safe fallback, **preserve in place**. Close/inspection errors are surfaced, no source files are deleted, and new operations on the halted manager deny. An unrelated manager/process is not globally stopped by a local halt. A controller must coordinate all owners before any later archive/restore. Real close failures and partial archive movement are not passed based on design arguments.

## Tests and actual results

Final [raw validation](../../experiments/phase1/persistence/results/1793911046516.json): **13 commands/checks Passed, 0 Failed, 0 Blocked**, source hashes unchanged during the run. The earlier [first driver run](../../experiments/phase1/persistence/results/1793909666845.json) has 12 Passed/1 Failed because of the explicitly disclosed unfiltered metadata issue; its real native compile evidence is retained. Intermediate passing runs remain in the results directory. Development failures in path handling and deliberate malformed-fixture setup were corrected and rerun before the final suite; they are not presented as earlier successes.

| Validation group | Actual final result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed, exit 0 |
| `cargo check --workspace --offline` | Passed, exit 0 |
| `cargo clippy --workspace --all-targets --all-features --offline -- -D warnings` | Passed, exit 0; no warning suppression |
| `cargo test --workspace --offline` | Passed: **148 runtime + 5 compile-fail doctests = 153**, 0 Failed; 4 harness-ignored entries explained below |
| New native persistence tests | Passed: **9 unit + 37 integration + 3 compile-fail = 49 unique cases** (included in 153, not added again) |
| Persistent cross-process race | Passed in the suite, focused suite and 3 additional recorded repeats; one success/one replay each |
| Windows-specific native cases | Passed: Unicode/whitespace database paths, static DB/WAL/parent symlinks, UNC/device/drive-relative rejection, actual sharing-denied initialization and MSVC bundled C compilation |
| Real process termination | Passed: committed SCOPED state/audit remain; uncommitted PLANNED state/audit disappear; integrity passes |
| Migration termination | Passed: independent process killed after embedded DDL before commit; fresh supported migration completes with one history row |
| Native statement failures | Passed: caught SQL failure still prevents partial commit; real duplicate audit errors roll back business state |
| Native snapshot/busy handling | Passed: actual 517 rollback/fresh-read retry; actual BUSY timeout; five-attempt termination; non-busy and rollback-failure no-retry |
| Native page-limit FULL | Passed: actual SQLITE_FULL (13) from max_page_count, no partial rows; **not physical disk exhaustion** |
| Corrupt startup and quarantine | Passed: invalid database header rejected without rewriting original bytes; actual DB/WAL/SHM set retained in place and managed operations halted |

One ignored integration entry is the subprocess helper: **three parent tests really launch it**, using pipes; it is not an omitted security test. The other three are existing workspace junction/ACL/10,000-entry fixtures requiring their separate runner. Existing authorization and workspace validators are run separately and their final results are recorded in the validation follow-up below. Do not sum repeated executions as unique tests.

### Existing validator follow-up

- [Authorization validator](../../experiments/phase1/authorization/results/1793910842702.json): **13 checks Passed**, unchanged source inputs, exact three approved direct dependencies, all 27 prior authorization regressions, original standalone A→B probe and the 64/32-round deterministic concurrency cases Passed. Its dependency gate was narrowly updated from the historical zero-dependency rule to verify the three owner-approved exact pins/features. Earlier raw files are unchanged.
- [Workspace validator](../../experiments/phase1/workspace/results/1793910842720.json): **11 checks Passed**, owned internal/external junction and deny-ACL fixtures Passed, cleanup Passed, input hashes unchanged. Its 151 unique runtime cases include the three previously harness-ignored cases; the only remaining ignored entry is the separately parent-executed persistence child helper. The five workspace doctests are recorded by Cargo summaries, not by that driver's runtime-name regex. Combined coverage is **151 runtime + 5 doctests = 156 unique tests**, including the 153 ordinary-suite cases; repeated runs are not new unique cases.
- Three owned scale repeats discover 10,000 entries / 310,000 bytes completely; measured discovery times 10537 / 11009 / 10894 ms, peak process RSS 7,602,176 / 7,917,568 / 7,872,512 bytes. These are current controlled metadata fixture measurements, not production persistence or adversarial containment benchmarks. ACL changes were confined to two disposable fixtures, restored and cleaned; no host security setting was changed.

### Not Tested and Blocked

| Item | Status | Limitation / next owner gate |
| --- | --- | --- |
| Physical disk exhaustion | Not Tested | Core/storage maintainer; page-count FULL is only a safe engine-capacity experiment |
| Actual disk write/fsync IOERR and rollback I/O failure | Not Tested | Storage maintainer; rollback-failure handling has labeled fault injection only |
| Power loss, kernel crash, volatile device cache behavior | Not Tested | Storage/hardware maintainer; FULL is configuration, not observed physical durability |
| Real close failure with outstanding native resources | Not Tested | Core maintainer; public API prevents outstanding raw statements; error path is implemented |
| Multi-file archive rename/copy and partial movement | Not Tested | Not implemented because consistency/quiescence cannot be guaranteed; source set preserved in place |
| Native production backup/restore API, upgrade beyond v1, blob reconciliation | Not Tested | Core maintainer; separate approved increment and crash/restore fixtures required |
| Real human identity, distributed approval, integrated dispatch/reservation/outbox | Not Tested | Security/application maintainer; storage single-use is narrower |
| Hostile concurrent filesystem replacement, mapped providers, network filesystems | Not Tested | Core/security maintainer; trusted approved local storage is a precondition |
| Linux/macOS/ARM64, long-duration production load, advisory freshness | Not Tested | Separate platform/load/license/security review gates; no network database fetched |
| Cryptographic migration/evidence authentication | Blocked | No approved cached hash dependency; no custom implementation; canonical IDs/FNV are non-cryptographic |
| General unfiltered offline Cargo metadata | Blocked after observed Failed command | Unused syn 2.0.119 source unavailable; only the actual Windows-filtered graph is validated |
| Earlier Bun/Node semantic declarations | Not Tested in this increment | Historical separate Failed check remains unresolved; no declarations downloaded |

## Reproduction and traceability

Run from the repository in PowerShell with the same pre-provisioned Windows/MSVC Cargo cache; no install step:

```powershell
./experiments/phase1/persistence/Validate.ps1
cargo fmt --all -- --check
cargo check --workspace --offline
cargo clippy --workspace --all-targets --all-features --offline -- -D warnings
cargo test --workspace --offline
cargo test --package sentra-core --test persistence_tests --offline
./experiments/phase1/authorization/Validate.ps1
./experiments/phase1/workspace/Validate.ps1
cargo metadata --offline --format-version=1 --filter-platform x86_64-pc-windows-msvc
cargo tree --offline -e features
```

The driver records a timestamped JSON file, exact stdout/stderr, status and input SHA-256 fingerprints (PowerShell's existing hashing facility, not a new Sentra crypto implementation). Owned fixtures are under ignored `target/`; child processes are only the compiled repository-controlled test harness. Existing validators keep historical raw files and add new results. No target code, target build scripts, hooks, package managers, remote service or untrusted workload was executed. Only Sentra tests and explicitly approved cached dependency compilation/build scripts ran.

| Requirement / gate | Evidence added; remaining boundary |
| --- | --- |
| F-02 / V-01 | Persisted metadata, security context/revision/budget; actual bundled Rust/C x64 integration; full immutable acquisition and all Rust suitability gates remain open |
| F-14 / V-02 / Q-03 | Native commit/recovery, bounded retries, sessions/audit survive real process termination; no worker/blob/external-side-effect reconciliation yet |
| S-01 / S-02 / V-05 | Private authority receipts, exact durable bindings/replay/expiry, local cross-process single-use; no real human authentication or end-to-end dispatch |
| S-06 | Atomic fixed-point conservative budgets across threads/connections; broader execution/resource quotas and provider pricing remain future work |
| S-09 / Q-04 | Logical audit atomicity and versioned fail-closed migration; no cryptographic tamper proof or administrator resistance |
| S-11 / S-12 / S-14 | Local data-path checks, read-only corruption preservation and explicit errors; filesystem races, encryption, backup/deletion and storage hardware gates remain open |
| S-15 / ADR-0007 | Exact Windows graph/license inventory; no project license selection, release notices certification or live vulnerability lookup |

## Repository preservation

Entry branch: `develop`; HEAD: `7f66ec2f47861566ca76993e74fc49818ee42be5` (`Document SQLite persistence design and audit`), parent `ccf9ba30f69fc2c2729f81bd99055ba671781bcf`. The initial read-only snapshot recorded the manifest as unstaged with no normalized text diff; its text was preserved except for the explicitly approved dependency section. No preexisting unrelated file was discarded. Final Git/source preservation evidence is recorded with the validation follow-up and completion report.

The [final local review](../../experiments/phase1/persistence/results/final-review.json) compares branch/HEAD, all refs, full visible history and staged index entries against the initial snapshot, and hashes all 123 original files. Only the 14 explicitly intended existing files differ; all ADRs, old raw results and unrelated source are unchanged. It also validates local Markdown links/anchors, table widths, all 41 requirement references and seven ADR status records. Upstream remains the local origin/develop at the same HEAD, ahead/behind 0/0; no remote refresh was performed. Changes are left unstaged, with new source/tests/reports/results untracked.

Documentation check: **Passed** for 45 Markdown files, 320 local file/fragment links, 96 table blocks, 41 requirement references and seven ADR status records; 0 failures. Git diff whitespace verification also exits 0. The original index entries, references, branch and history compare equal. These document/state checks are separate from the Rust/SQLite test counts.

No commit, amend, reset, rebase, cherry-pick, tag, fetch, pull, push, checkout, staging, unstaging, stash or history/reference/index modification was issued. No host configuration change or external data transmission was performed. Increment 5.4.2 stops here; no subsequent increment is authorized by this report.
