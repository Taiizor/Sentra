# Phase 1 Remediation — Increment 0.1: Foundational Prerequisite Validation

Date: 2026-11-07. **Technical feasibility and evidence only. Phase 1 remains NOT APPROVED.** No production remediation, schema/migration/API/test/configuration/dependency/lockfile change, ADR acceptance, closure attempt or Phase 2 work occurred.

## 1. Executive summary

**Prerequisites are partially validated; dependent remediation remains blocked.** Controlled C: NTFS experiments support stable observed file identity, collision-safe namespace creation candidates and SQLite transactional migration feasibility. They do not establish a safe production Rust content-handle boundary, durable publication across OS/power failure, an approved offline SHA-256 implementation, or safe upgrade of a store with live legacy writers.

| Prerequisite | Assessment and implementation consequence |
| --- | --- |
| Windows identity | **Passed, restricted observations:** same regular-file ID after rename, independent reader process and hard link; replacement has a different ID while an old alias retains the old object. **Blocked:** stable safe Rust by-handle identity integration. Canonical paths and external ID queries do not secure a later open. |
| No-replace publication | **Passed, restricted observations:** existing-destination rejection and 10/10 two-process races each for managed File.Move without replacement and Rust std hard_link. **Not validated:** production publication protocol, arbitrary failure atomicity, cross-volume behavior and namespace durability. |
| Durability | **Passed, restricted process-termination observations:** three flush/rename/close kill points preserve the expected synthetic bytes/name/ID. **Not Tested:** OS crash, power loss, directory metadata durability, device cache/fsync failure and other filesystems. |
| SHA-256 dependency | **Blocked offline:** sha2 and a suitable safe CNG wrapper are not cached. Recommend evaluating a pinned minimal sha2 configuration first; no version, license/maintenance conclusion, platform certification or dependency approval is invented. |
| SQLite migration | **Passed, engine feasibility:** DDL/history/user_version roll back or commit together, competing migrators re-read under BEGIN IMMEDIATE, WAL reader/checkpoint behavior and a healthy logical snapshot work on SQLite 3.46.0. **Blocked for production upgrades:** exact migrations/legacy binding, preservation and old-writer quiescence are not implemented or fully verified. |
| F-611-02 | Explicit operator recovery remains the recommended initial candidate. ADR-0010 remains Proposed and F-611-02 remains Open before Phase 2 production readiness. No incomplete store was repaired. |

[REMEDIATION_ARCHITECTURE](REMEDIATION_ARCHITECTURE.md), [ADR-0008](../adr/0008-recoverable-local-operations.md), [ADR-0009](../adr/0009-verified-content-and-blob-reconciliation.md) and [ADR-0010](../adr/0010-explicit-initialization-recovery.md) remain proposals with their original statuses. The [gap analysis](PHASE1_GAP_ANALYSIS.md), original acceptance criteria and [NOT APPROVED decision](PHASE1_FINAL_VERIFICATION.md) are unchanged. OQ-25 remains Open; project identity still aliases one foundation SessionId and multiple sessions remain unsupported.

## 2. Environment, scope and Git baseline

| Item | Observed evidence |
| --- | --- |
| Branch / HEAD | develop / 4bd86181289cf452191e17fe52b41eda74ab73e2 |
| Local upstream | origin/develop, 0 ahead / 0 behind; no fetch |
| Entry worktree/index | Clean; 0 staged, modified or untracked; 286 index entries |
| Physical index SHA-256 | 5425d94867efe9e9759a7eb5dc413a93272749be543c6d82ce66ef0c2161428a |
| OS | Microsoft Windows 11 Education, 10.0.26300 / build 26300, x64 process and OS |
| Actual PowerShell / .NET | 7.6.9 / 10.0.14; these are observed versions, not an assumed 7.6.6 |
| Rust / Cargo | rustc 1.99.0 (b940084d7 2026-09-28); cargo 1.99.0 (5f94df478 2026-08-27); x86_64-pc-windows-msvc |
| Bun | 1.4.4; inspection/cleanup harness only, not the SQLite engine used here |
| Tested filesystem | Local fixed C: NTFS; CIM volume serial F2C8CC66. Repository E: is reported NTFS but was not the experiment volume. |
| Experiment root | C:/Users/Taiizor/AppData/Local/Temp/Sentra Prereq-4be22b15f8d941bea9515af9f8ee31ab (called `<probeRoot>` below); created 00:30:44 UTC, removed 00:44:49 UTC |
| Network / configuration | No external service, download, feature/security change, elevation, Docker, WSL2 or Hyper-V invocation |

Before experiments, the complete tracked/untracked inventory, hashes of all 286 tracked files, physical index, staged entries, branch/HEAD/upstream, reference targets and reachable history were captured in memory with read-only Git calls and GIT_OPTIONAL_LOCKS=0. All remained identical after experiments and cleanup, before documentation edits.

Inspection covered the proposed contracts, [connection.rs](../../crates/sentra-core/src/persistence/connection.rs), [migration.rs](../../crates/sentra-core/src/persistence/migration.rs), [transaction.rs](../../crates/sentra-core/src/persistence/transaction.rs), [model.rs](../../crates/sentra-core/src/persistence/model.rs), [schema_v1.sql](../../crates/sentra-core/src/persistence/schema_v1.sql), current manifests/lockfile, local Cargo sources/cache, existing [SQLite validation](SQLITE_VALIDATION.md) and [native persistence report](INCREMENT_5_4_2_SQLITE_IMPLEMENTATION.md). This report does not re-certify those previous suites.

Only owner-controlled synthetic helpers/data ran on the host under the explicit experiment permission. This is not a production host execution backend. No analyzed target, repository build script, package hook or untrusted workload ran. The production fail-closed backend was not changed or invoked.

## 3. Windows file identity findings

### 3.1 Runtime observations

| Case | Actual observation | Meaning and limit |
| --- | --- | --- |
| FS-01 | Regular-file ID 0x00000000000000000024000000080a2e unchanged after rename to a Unicode/spaced name | Name is not object identity. Tested on the same C: volume only. |
| FS-02 | Fresh pwsh/fsutil reader process returns the same ID | Identity observation survives that reader/writer process boundary; not reboot, restore, clone or deletion/reallocation proof. |
| FS-03 | Hard link reports the same ID; attributes Archive, without ReparsePoint | Different canonical names can access one mutable object. Reparse checks alone do not detect hard-link aliasing. |
| FS-04 | Rust std rename replaces the destination: its ID becomes replacement ID 0x00000000000000000042000000063bf2; retained hard link keeps the original ID/content | Same pathname can identify a new object. The old object remained linked, avoiding reliance on ID recycling behavior. |
| FS-08/09 | Junction tag 0xa0000003; file/directory symlink tag 0xa000000c. Rust symlink_metadata reports ReparsePoint for all three | Known fixtures can be quarantined without treating a resolved in-root target as trusted. Unknown tags and malicious replacement races were not exercised. |

IDs were queried using `fsutil.exe file queryfileid <synthetic-path>`. Regular-file queries succeeded without elevation. `fsutil fsinfo volumeinfo C:` failed with command exit 1 / Windows error 5; it was not retried with elevation. Read-only DriveInfo and CIM queries supplied NTFS/serial observations instead. This is not proof that a CIM serial is globally unique or a held-handle volume identifier.

Do not use a pathname, canonical name, bare file ID or serial as authorization. A queried ID is an observation at that instant, not proof that a subsequent read opens that object. ID lifetime/reuse after deletion, restore/clone behavior, cross-volume identity, ReFS/FAT/network storage and Windows ARM64 are Not Tested. Sentra must scope any future identity tuple to a verified live volume/object and protected store activation, rather than assume permanent global uniqueness.

Hard links introduce an additional content-read condition: an untrusted repository may have aliases whose other names are outside the authorized root. Before content acquisition, require an approved link-count/ownership strategy or reject unsupported alias cases. Merely classifying a hard link as a regular file must not grant arbitrary content access. Current metadata-only discovery is not changed by this finding.

### 3.2 Stable Rust and native API availability

The safe stable attribute probe compiled and reported 1040 for directory reparse entries and 1056 for the file symlink. The separate identity compile probe actually failed twice with E0658/windows_by_handle for `MetadataExt::volume_serial_number` and `file_index`; the definitive rerun explicitly captured native exit **1**. The first shell wrapper masked that native exit with its final environment-restoration statement, so its shell exit 0 is **not a successful compilation**.

Cached windows-sys 0.61.2 declares GetFileInformationByHandleEx and FILE_RENAME_INFO, and installed std documentation marks the by-handle metadata methods unstable. These establish API/source availability, not a selected safe Rust implementation. No unsafe FFI, nightly switch or additional dependency was introduced.

**DG-3 remains Blocked.** A reviewed safe retained-handle abstraction (or explicitly justified narrower supported profile) must establish object/volume identity, no-follow containment, hard-link treatment and final-operation correlation. External fsutil/CIM helpers are diagnostic instruments, not the proposed production access boundary. Canonicalize-then-open is not an acceptable fallback.

## 4. No-replace promotion findings

### 4.1 Mechanisms and evidence

| Mechanism | Evidence | Candidate disposition |
| --- | --- | --- |
| Rust std::fs::rename | FS-04 replaces an existing destination; installed std docs also describe replacement | Unsuitable as a no-replace primitive. A prior exists check does not fix its race. |
| .NET File.Move(source,destination,false) | FS-05 existing destination unchanged; FS-06 10/10 barrier-synchronized two-process races have exactly one winner, collision HRESULT -2147024713 (0x800700B7), unchanged losing source | Restricted Windows managed-API experiment. No new .NET subprocess bridge is selected for production Rust. |
| Rust std::fs::hard_link | FS-07 10/10 two-process races have one winner, losing Win32 error 183; destination ID/hash matches winning source. Removing that source name preserves destination bytes/ID. | Safe std no-replace **link creation** candidate for owned immutable CAS bytes; a link-plus-unlink protocol is not one atomic move. Requires further review. |
| MoveFileExW without REPLACE_EXISTING/COPY_ALLOWED; handle rename with ReplaceIfExists=false | Native declarations/flags/union inspected in cached windows-sys | API-level candidates, not directly called or traced here. A safe wrapper, exact flag semantics and handle-based tests are still needed. |

Installed local std hard_link documentation states that an already existing link path errors and currently maps to CreateHardLink on Windows. The live C: tests support that limited behavior. They do not prove all Windows filesystems, crash durability or every failure path.

Each race used two independently started helpers and named readiness/release events; no timing sleeps. Both producers were ready before release. Source files contained distinct 64-KiB synthetic payloads. Assertions checked exactly one success, expected collision code, destination ID and SHA-256 equal to the winner, and untouched losing source. Diagnostic Get-FileHash used an existing host implementation; this does not validate a Rust SHA-256 dependency.

### 4.2 Required collision and failure policy

After a collision, re-open through the approved identity boundary and verify actual digest, length, classification/access and ownership. A matching destination name or Win32 183 is not deduplication proof. The experiments preserved sources/destinations for these collision cases; arbitrary I/O failure, partial copy, cross-volume promotion and adversarial directory replacement were **Not Tested**. Unknown outcomes require preserve-and-reconcile, never a blind second promotion.

Only same-tested-volume operations were attempted. Sentra must reject cross-volume publication until separately validated; no atomic cross-volume or managed move fallback is inferred.

The hard-link option refines ADR-0009's implementation candidates without selecting one: destination link creation is one namespace operation, but stage unlink is separate. A crash may leave both names. Every writable staging handle/alias must be retired before publication; guards and immutable ownership must prevent post-publication mutation. Link count alone is not provenance. A later protocol must reconcile both names, content and pending references before Ready.

**Do not transfer this CAS candidate automatically to SQLite database publication.** Two live database names with potentially separate WAL/SHM naming are not a safe bootstrap strategy without a separately proven protocol. Atomic staging of a database still requires a fully closed/checkpointed recovery set, no-replace publication and alias/open exclusion.

## 5. Filesystem durability findings

FS-10 actually terminated three owned worker processes with Process.Kill after explicit readiness:

| Boundary | Observed after process exit -1 | Claim supported |
| --- | --- | --- |
| After FileStream.Flush(true), before rename | Stage present, destination absent, content durable-fixture and same queried ID | This process-termination fixture retained its flushed data. |
| After rename, handle still open | Destination present, stage absent, expected bytes/ID | Closing the killed process's handles did not undo this observed same-volume rename. |
| After rename and handle close | Same destination/content/ID retained | This completed managed close/name transition survived that process termination. |

These are **three process-crash observations**, not OS-crash or power-loss tests. No device write cache, filesystem journal recovery, directory flush, volume flush, fsync IOERR, physical disk exhaustion or power cut was tested. No claim is made that Flush(true) traced a particular native call or established persistent directory entry ordering.

Installed std File docs say Drop ignores close errors and sync_all attempts synchronization. Consequently the proposed “verified flush/close” contract still needs an achievable, reviewed API/error-handling definition; dropping a File cannot be reported as proof that all deferred errors were checked. File lifetime, share-delete behavior, retained directory handles and object fencing must be specified before production publication.

| Failure class | Status | Required future evidence |
| --- | --- | --- |
| Controlled process termination | Passed under the three stated C: fixtures only | Integrate actual promotion/ref transaction kill points, restart discovery and repeated reconciliation. |
| OS/kernel crash | Not Tested | Separately approved disposable environment and journal/recovery evidence. |
| Physical power loss / device fsync behavior | Not Tested | Controlled hardware/storage setup; successful flush/rename/FULL is insufficient. |
| Directory/volume metadata durability and strong identity | Blocked for the proposed production guarantee | Exact safe API, supported filesystem contract and error/ordering verification. |
| SQLite WAL plus blob publication | Design only / Not Tested | SQL/CAS reconciliation protocol; DB commit does not atomically persist unrelated file operations. |

## 6. Experimental methodology, inventory and raw results

### 6.1 Scope and execution

All explicit experimental sources, databases, sidecars, binaries, PDBs and raw JSON were created in the single dedicated `<probeRoot>`. No Cargo project/manifest/lockfile was generated. Rust compiled a dependency-free harness source apart from the **already approved and already compiled** rusqlite dependency graph, linked read-only from the existing target directory. The harness itself forbids unsafe code. No dependency build script was rerun.

Actual compile command (resolved paths shown by their repository-relative names):

```powershell
rustc --edition=2024 --crate-name prerequisite_sqlite --extern "rusqlite=$repoRoot/target/debug/deps/librusqlite-d6ef7b75ae602769.rlib" -L "dependency=$repoRoot/target/debug/deps" -L "native=$repoRoot/target/debug/build/libsqlite3-sys-932b2007a2b5b5c3/out" -o "$probeRoot/sqlite_probe.exe" "$probeRoot/sqlite_probe.rs"
pwsh -NoProfile -NonInteractive -File "$probeRoot/run.ps1" -ProbeRoot $probeRoot
pwsh -NoProfile -NonInteractive -File "$probeRoot/retry_sql.ps1" -ProbeRoot $probeRoot
pwsh -NoProfile -NonInteractive -File "$probeRoot/final_sql.ps1" -ProbeRoot $probeRoot
& "$probeRoot/sqlite_probe.exe" init "$probeRoot/backup-source.db"
& "$probeRoot/sqlite_probe.exe" backup "$probeRoot/backup-source.db" "$probeRoot/healthy-snapshot.db"
rustc --edition=2024 --emit=metadata -o "$probeRoot/identity_api.rmeta" "$probeRoot/identity_api.rs"
```

The executable was built four times while the disposable harness gained metadata probes, corrected diagnostic handling and the supplemental backup mode; all four compile commands emitted no diagnostics and exited 0. This is not a fresh bundled-C dependency build. The dependency binary fingerprint reports bundled + modern_sqlite; backup feature is absent. Native SQLite observed at runtime is **3.46.0**, source ID **2024-05-23 13:25:27 96c92aba00c8375bc32fafcdf12429c58bd8aabfcadab6683e35bbb9cdebf19e**. This differs from the historical Bun SQLite 3.53.4 experiment; no results are transferred between those engines.

Read-only artifact identity:

| Existing linked artifact | SHA-256 |
| --- | --- |
| target/debug/deps/librusqlite-d6ef7b75ae602769.rlib | cbd1a0b14659ab60cede37280fa65a218f122903b63bcb2d6257071a33bc01f6 |
| target/debug/build/libsqlite3-sys-932b2007a2b5b5c3/out/sqlite3.lib | a5caab53df67bd6344cf16eecfb8c0670d3c77c6b2e615b331fa4d157c73c964 |

The fixtures copy the current six-table v1 DDL but insert **synthetic migration metadata** and minimal schema-level rows (one session, one audit, a 10-micro-dollar RESERVED hold). They are not valid Core authorization/resume snapshots. The disposable v2 adds only a probe table/index/history entry/user_version to test SQLite mechanics, **not a proposed Sentra migration or new production schema**. End-to-end legacy approval/context migration remains Not Tested.

### 6.2 Failures retained and reconciled inventory

| Execution | Exit / actual outcome | Disposition |
| --- | --- | --- |
| Initial full harness | Exit 1; 14 Passed records, 1 Blocked volume-query record, 1 harness failure | FS cases completed. SQL-03 rollback assertions ran, then diagnostic unwrap panicked: modern SqlInputError has no value from sqlite_error(). That case was not counted Passed. Raw failure retained. |
| First SQLite-only retry | Exit 1; 1 Passed record, 1 harness failure | A remaining literal version.db path collided with the initial fixture. The harness refused to replace it. No existing fixture was overwritten; fresh path selection was corrected. |
| Final SQLite-only retry | Exit 0; **11/11 Passed**, no failures | New sql-final-* files; all previously incomplete SQLite cases actually executed. |
| Supplemental healthy snapshot | Exit 0; **1 Passed** additional named case | VACUUM INTO captured committed WAL data and rejected an existing nonempty snapshot without changing it. |
| Stable by-handle API compile | Initial wrapper shell 0 with E0658 diagnostics; rerun native/shell **1**, two E0658 errors | Expected unsupported capability, **Blocked prerequisite**, not a passing compilation. |
| Cleanup | Recursive command rejected before execution by automatic review (“blocked by policy”); confined nonrecursive cleanup exit 0 | Read-only inventory/ownership checked, no elevation or broader deletion attempted. No artifacts remain. |

**Non-overlapping final inventory:** **23 named successful experimental checks** = 11 filesystem checks + 12 SQLite checks; **2 separately identified blocked probes** = volume management query and stable Rust identity compilation. The two failed harness executions remain failures in the chronology, not erased or counted as successful product tests. The initial/retry SQL success records overlap final cases and are not added to the unique count. FS-06/07 contain 10 race rounds each (20 rounds / 40 competing helpers), and FS-10 groups 3 kill boundaries; repetitions/substeps are not extra unique named cases. SQLite has 2 real migration-kill cases, 2 competing migrators and one held writer. Rust doctests, ignored/platform suites and Core regression validators were not run in this increment.

The final result does not report the complete harness as one all-green run: filesystem evidence comes from the initial run, SQLite evidence from the final retry plus backup, with source-level diagnostic-only changes between them. No production code was changed to obtain success.

### 6.3 Cleanup and evidence retention

Read-only inventory found 117 entries, including exactly the three known reparse links and one normal subdirectory; no unknown types. No remaining process command line referenced the experiment root. Nonrecursive cleanup verified the exact dedicated root/marker, unchanged inventory and known link set, unlinked the three links without following them, checked their target canary after every unlink, removed individually verified regular files, then removed empty directories. Root absence was confirmed at 00:44:49.888 UTC. No source data outside that owned temporary tree was deleted.

All raw JSON was read into memory before deletion and is retained in section 16, along with the original failure records. Only the literal temporary-root path in raw records is normalized to `<probeRoot>`; observations/codes/counts are unchanged. Generated source and raw-file hashes are retained there. Reproduction sources are embedded as inert Markdown in section 17; no executable experiment artifact remains in the repository or temporary root.

## 7. SHA-256 dependency comparison and offline availability

Inventory examined all immediate registry source/cache roots under C:/Users/Taiizor/.cargo. No cached sha2, sha256, digest, crypto-common, block-buffer, cpufeatures, ring, OpenSSL, AWS-LC or suitable bcrypt/CNG wrapper was found in the inspected candidates. No resolver/download was attempted to “make it pass.”

| Dimension | sha2 candidate | Safe Windows CNG wrapper alternative |
| --- | --- | --- |
| Technical reason | Preferred evaluation direction: a narrowly configured implementation of exactly SHA-256 consistent with Rust/offline portability goals | Meaningful alternative if OS-provided hashing reduces shipped crypto implementation burden; Windows-specific API/error/interop cost must be justified |
| Provenance/correctness | Package source/version unavailable locally; implementation correctness/provenance and known-answer tests **Not Tested** | Cached generated declarations expose BCryptOpenAlgorithmProvider/CreateHash/HashData/FinishHash; no suitable safe wrapper was established, no CNG hashing test or certification claim |
| License / maintenance | **Not validated**; do not infer a current license, support policy, advisories or maintenance from an unavailable package/name | Raw windows-sys 0.61.2 / windows-link 0.2.1 manifests: MIT OR Apache-2.0, rust-version 1.71, Microsoft windows-rs repository. This does not license/audit an unselected wrapper or prove current maintenance. |
| Dependencies/features | Exact graph/default features/MSRV/architecture code unavailable; must pin/review before approval | Cached raw graph includes windows-sys -> windows-link 0.2.1 with default features false. Necessary feature/API surface and a safe wrapper's graph remain unselected. |
| Unsafe code | Not assessed without source; Sentra forbid(unsafe_code) does not govern dependency internals | Raw Windows FFI is not a safe API for Sentra; do not introduce unsafe calls as a shortcut. Safe wrapper audit required. |
| Windows x64 / ARM64 | Neither candidate built or run here. No ARM64 claim. | Neither safe candidate built/run. Declarations are not target execution evidence. |
| Offline/reproducibility | **Blocked:** source/archive/dependencies absent, no approved exact version | **Blocked:** raw bindings available but selected safe implementation absent; OS servicing is another provenance input |
| Selection | Conditional recommendation to evaluate sha2 first, not approved/installable today | Retain alternative only if measured safety/packaging advantage warrants Windows-specific implementation; no provider chosen |

Cached getrandom 0.4.3 (MIT OR Apache-2.0, edition 2024/MSRV 1.85) provides an identifier-entropy candidate, **not SHA-256**. It is not added or approved. Existing std hash, action_digest and FNV migration drift values are not substitutes. No hand-written cryptography, host command hashing transport, alternative hash algorithm or production .NET bridge is proposed.

### Required candidate acceptance tests

Before production recommendation becomes dependency approval: pin exact cached package/transitive versions and checksums; inspect source/build scripts/assembly/features/licenses; obtain permitted maintenance/advisory/provenance evidence; compile/run offline on x64 MSVC, then assess other targets separately. Test independent known-answer vectors (empty, abc, standard long message, million-a), chunk boundaries 0/1/63/64/65, randomized split equivalence, large streamed input with checked counters, short read/I/O failure/cancellation, same-length corruption and altered manifest bytes.

Two mandatory known-answer constants for later comparison are:

- Empty input: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
- UTF-8 abc: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.

These are **planned test expectations, not candidate results**. Incremental/streaming hashing must process bounded chunks without loading whole files, retain checked byte totals and never finalize a failed/partial write as Ready. Test large-file counters independently of actual disk exhaustion; do not assume a small buffer test covers >4-GiB paths.

Store 32 digest bytes with explicit algorithm/version or serialize strictly as `sha256:<64 lowercase hexadecimal characters>`, with bounded verified byte length and rejection of noncanonical/truncated/unsupported encodings. Recompute over actual immutable bytes at admission/dedup/reconciliation as policy requires. Digest equality detects content mismatch under cryptographic assumptions; it does not establish authorization, provenance or semantic correctness.

## 8. SQLite migration contract

### 8.1 Current implementation and configuration

The actual manager opens local validated paths, enforces NOFOLLOW and defensive mode, disables implicit checkpoint-on-close, validates integrity/FKs, rejects unsupported application/schema metadata, and applies/verifies foreign_keys=ON, journal_mode=WAL, synchronous=FULL, busy_timeout=5000, wal_autocheckpoint=1000 and trusted_schema=OFF. The isolated runtime probe used those same settings and SQLite 3.46.0.

Current migration.rs supports exactly version 1, one matching migration history row and the exact six-table/index definition set. It transactionally creates DDL/history/user_version/application_id and validates FKs through the managed transaction. Its FNV-1a value detects accidental canonical-DDL drift, not malicious modification. New tables cannot simply be added behind its back.

Current managed transactions latch **every** statement failure, explicitly roll back and prevent later commit. BUSY_SNAPSHOT requires complete transaction restart/fresh reads under the existing five-attempt bounded policy; external work must remain outside the closure. Those production mechanisms were inspected, not re-certified by this raw-engine harness.

### 8.2 Precise proposed migration protocol

This contract refines ADR-0008's proposal; exact future DDL/version numbers and implementation still require acceptance.

1. **Ownership and preflight:** the trusted persistence/lifecycle owner alone selects an embedded ordered migration list. Acquire exclusive migration/controller ownership, retire all legacy open writers and active backend admissions, validate path/family/identity, preservation capacity and compatibility. No caller-provided SQL or boolean may trigger upgrade. A new lock cannot retroactively bind old clients that never acquired it.
2. **Preservation:** before destructive open/recovery of uncertain input, preserve the original quiescent DB/WAL/SHM/journal/control family in place or through an approved consistent capture. For a healthy compatible store, an approved SQLite snapshot may preserve committed logical state, coupled with blob reference/retention pins. A live copy of .db alone is insufficient and a logical snapshot is not forensic preservation of every sidecar.
3. **Version authority:** application-owned compiled ordered migration descriptions define supported source/destination versions and expected historical objects/checksums. Database user_version/history must agree; neither alone grants trust. Separate schema version from policy identity/generation, context generation and recovery epoch. Versions never decrement automatically.
4. **Exclusive write transaction:** begin IMMEDIATE, **re-read** application_id, user_version, full migration history and expected schema under that transaction. Reject newer/unknown/intermediate/inconsistent metadata before logical changes. Another migrated process must validate the supported final state and return already-applied, not blindly repeat DDL.
5. **Atomic scope:** execute reviewed deterministic main-database DDL/index/DML and migration-history/version updates in the same transaction. Validate preserved identity, terminal state, snapshots, approval provenance/consumption, budget holds, audit uniqueness/sequences and FK/integrity before commit. A failed statement, data validation, audit or commit requires explicit full rollback, with rollback failure separately typed and the manager halted.
6. **Commit and acknowledgement:** report success only after commit. Reopen/validate the same resulting version if acknowledgement was lost; never infer failure and replay solely from the missing reply. Migration success audit/history must share the commit; a partial progress message is not authority.
7. **WAL lifecycle:** retain foreign_keys ON outside/through the migration connection and preserve WAL/FULL. Do not change journal mode within the migration or suppress FK checks to bypass invalid legacy data. Bound/reject long-lived readers for required checkpoints; report checkpoint busy/failure separately. A committed migration is not rolled back merely because later checkpoint failed.
8. **Backup/rollback:** never reset/delete/recreate a failed store. A rollback before commit is transactional; restoring an earlier backup after commit is an explicit activation/recovery operation with a new activation identity, invalidated old contexts and conservative inherited dispatch uncertainty. Retire the old activation first. No automatic down-migration or restore over live files.
9. **Retries/errors:** distinguish lock contention, incompatible schema, corrupt/incomplete data, FK violation, rollback failure, checkpoint failure and uncertain preservation. Typed errors retain the primary and secondary failures with redacted diagnostics. Fresh reads and complete pure-SQL retries only; no filesystem/network/provider actions inside them. An exhausted/busy migration leaves the original state and returns a typed failure.

### 8.3 Failure decisions and actual evidence

| Situation | Required behavior | Evidence/status |
| --- | --- | --- |
| Migration starts, does not commit | Whole DDL/data/history/version rollback; preserve original; restart validates old supported version | SQL-03 explicit rollback and SQL-04-before_commit actual process kill: v1/history1/no probe table, integrity ok, FK0, hold10/audit1. Passed for synthetic DDL. |
| Commit succeeds, process dies before response | Restart discovers v2/history2/probe table together; idempotent validation, no repeated event or DDL | SQL-04-after_commit exit -1, reopen v2; SQL-02 second migration applied=false. Passed for fixture. |
| Unknown/newer schema | Typed refusal, no silent reset/downgrade; no execution from incompatible state | Current source rejects NewerSchema/SchemaMetadata. **Source-inspected; no new runtime unknown-schema test here.** Physical SQLite/open side effects must not be mislabeled read-only. |
| Corrupt data / invalid snapshot / FK failure | Abort/rollback; preserve complete original family; no permissive defaults or automatic repair | Current integrity/FK/snapshot checks inspected. **New corrupt-data/rollback-IOERR migration runtime cases Not Tested.** |
| Two compatible migrators | One writer at a time; re-read after lock, one application and one validated already-applied result | SQL-05 two actual processes: applied true/false, final v2/history2. Passed. |
| Writer contention | BEGIN IMMEDIATE waits within configured busy policy, then typed busy with no started transaction | SQL-06 code 5 after 5513 ms with busy_timeout=5000. This is observed elapsed time, not a hard real-time bound. |
| Old reader | May retain prior schema snapshot and block TRUNCATE; release permits checkpoint | SQL-07 reader v1/writer v2; checkpoint [1,28,23], then [0,0,0], WAL 0 bytes. Checkpoint subtest busy timeout explicitly reduced to 25 ms. |
| Already-open legacy writer | Upgrade must not proceed without retirement/quiescence; version is not a fence | SQL-08 old connection writes audit row after version2 commit. Passed as a **risk demonstration**, not as a safe upgrade result. |
| Non-transactional/FS maintenance | Must not enter atomic DDL migration; use separate approved recoverable protocol | SQL-09 VACUUM inside transaction errors with code1; explicit rollback. Blob promotion, backup creation, rename/checkpoint/restore are not atomic with migration DDL. |

### 8.4 Backup experiment and legacy compatibility

SQL-10 used **VACUUM main INTO** outside a transaction on a healthy disposable v1 database. Source had **94,792 bytes of WAL** before the snapshot. A read-only open of the snapshot found version1, integrity ok, hold10/audit1. A second VACUUM INTO to that nonempty destination returned SQLite code1 and its bytes stayed identical. This establishes that this supported SQL mechanism can capture committed logical WAL-backed state without enabling rusqlite's backup feature. It does not implement a production backup service, an atomic file-family capture, preservation for a corrupt source, blob consistency or power-loss durability.

Current security snapshots accept version1 without policy identity as historical data, and version2 only with a valid canonical effective policy identity. There is no independent persisted policy_generation today. Future migration must preserve raw historical provenance and classify missing new bindings **LegacyUnbound**, not fill current policy/input/epoch values. Version1 history cannot become executable authorization; consumed grants remain consumed and unknown budget usage remains held. The same foundation SessionId is retained; multi-session stores are not adopted.

The fixture omits complete Core security snapshots/approvals, so end-to-end legacy-context/approval migration proof is **missing**. SHA-256 availability is not retroactively required to rename the existing FNV history field: any future cryptographic history format is versioned and separately approved.

**Conclusion:** current SQLite configuration supports the tested transactional building blocks. It does not supply migration ownership, upgrade compatibility, safe preservation, fencing or blob/result atomicity automatically. Production upgrade readiness remains conditional/blocked.

## 9. F-611-02 decision readiness

| Driver | Atomic staging A | Explicit operator recovery B |
| --- | --- | --- |
| Evidence gained | Tested managed no-replace and safe Rust hard-link creation are useful namespace observations | Tested SQL rollback, lost-acknowledgement idempotency and healthy WAL snapshot support conservative plan/apply semantics |
| Still missing | Safe Rust handle identity/publication, durable directory ordering, all sidecar/checkpoint/close windows, concurrent bootstrap exclusion and crash recovery of staging | Proven quiescent original-family acquisition, source identity, explicit recovery authorization, compatible legacy-input proof and all recovery kill points |
| Sidecar/alias risk | Several independent renames are not an atomic DB family; CAS hard-link alias publication is not automatically appropriate for mutable SQLite | Preserve DB/WAL/SHM/journal before recovery; healthy VACUUM INTO does not replace original recovery evidence |
| Existing-file protection | Must prove no replacement under collision/race and correct ambiguous-publication recovery | No auto delete/reset/overwrite/adopt; invalid/unowned/corrupt data may stay blocked |
| Operational cost | More complete eventual bootstrap experience, larger publication/cleanup proof obligation | Explicit intervention and conservative blocked states, smaller initial recovery surface |

**Recommendation remains B, explicit operator recovery, not an accepted selection.** Keep detection non-mutating at the domain level, preserve original family before storage-mutating opens, bind an explicit recovery plan to exact identity/epoch/action, and apply only authorized Core lifecycle changes transactionally. Zero-session/identity-less data cannot be invented as continuation. A verifiable Created session may be completed only under the accepted future contract; committed Scoped is rediscovered without another session. No such recovery was implemented or tested here.

F-611-02 stays Open before Phase 2 production readiness. Acceptance, implementation and real Windows interruption/concurrency/preservation tests are still required. OQ-25 stays separately Open; recovery does not imply multi-session support.

## 10. Proposed architecture amendments

These are recorded amendments for review, not silent edits to the three ADRs or a new accepted architecture.

| Area / proposal affected | Proposed clarification from evidence | Gate |
| --- | --- | --- |
| ADR-0009 identity | Diagnostic volume/file IDs are available, but stable Rust safe by-handle methods are unavailable here. Add explicit hard-link/alias treatment and reject unverified content opens. | DG-3 remains Blocked; wrapper/profile selection and adversarial tests required. |
| ADR-0009 publication | Consider safe std hard_link as an owned immutable CAS candidate, with a separate stage-unlink/reconciliation subphase. Do not call it an atomic move or reuse it unreviewed for SQLite. | Independent filesystem review; post-link/pre-unlink crash tests and immutable-writer proof still missing. |
| ADR-0009 durability | Define achievable flush/close/directory publication contract per API/filesystem. Drop/no observed error is not proof of checked close errors or OS/power durability. | No Ready durability promise beyond tested profile until accepted evidence. |
| ADR-0008 fencing | Keep controller/object guards across external mutation; DB epochs alone cannot stop stale filesystem handles or an already released effect. | Stale writer/guard/recovery tests; no automatic uncertain replay. |
| ADR-0008 migration | Mandatory old-writer retirement, in-transaction version re-read and post-commit lost-ack validation; old user_version is not a fence. | Exact migration/legacy/backup strategy acceptance before production upgrade. |
| ADR-0010 recovery | Preserve original recovery family separately from a healthy logical snapshot. A blocking diagnosis is legitimate when preservation/provenance is unavailable. | F-611-02 acceptance/implementation/test gate remains Open. |
| Input/result integrity | Frozen content references still require approved SHA-256 and verified object admission; successful metadata identity observations do not make a path immutable or a digest provenance. | DG-4 blocked; no blob/manifest/result remediation begins. |

No independent provider integration, scope expansion, execution backend or new authorization mechanism is proposed by these findings.

## 11. Prerequisite acceptance criteria and remaining unknowns

| Prerequisite / owner | Required acceptance evidence | Current status |
| --- | --- | --- |
| PF-1 safe identity — Windows/security | Selected safe Rust API, held volume/file identity, no-follow containment, replacement/alias/hard-link/reparse/race/permission fixtures and declared supported-volume scope | Blocked; only diagnostic identities/known reparse fixtures Passed |
| PF-2 no-replace CAS — evidence/platform | Reviewed mechanism, collision verification and immutable ownership; process kills before/after publish/unlink/Ready, concurrent promotion/GC, quota/IOERR behavior | Partially validated namespace candidates; integrated protocol Not Tested |
| PF-3 durability — platform/storage | Exact flush/close/namespace ordering/error contract; process-crash recovery raw evidence; separate OS/power claims only with permitted tests | Process-fixture observations Passed; strong publication contract Blocked; OS/power Not Tested |
| PF-4 crypto — dependency/license/security | Exact approved cached version/graph/features/licenses/provenance, permitted maintenance assessment, offline x64 build and independent streaming/corruption/vector tests | Blocked offline, no candidate test |
| PF-5 migration — persistence/security | Accepted exact ordered DDL/legacy contract, old-writer retirement, preservation, all statement/commit/rollback faults and kill tests on valid Core session/grant/hold fixtures | Engine feasibility Passed; production contract/compatibility implementation and proof missing |
| PF-6 bootstrap recovery — Core/product | Accepted A/B selection, original-family protection, explicit plan authorization and all four bootstrap windows plus repeated recovery | Design recommendation only, F-611-02 Open |

Additional Not Tested areas are cross-volume/cross-filesystem publication and IDs, file-ID reuse, unknown reparse tags, adversarial path/handle races, cross-file snapshot coherence, corruption during migration, physical disk exhaustion/fsync IOERR, OS/power recovery, live-worker cancellation, Linux/macOS/ARM64 and real AI providers. Existing untrusted execution remains fail-closed; no fallback was tested or introduced.

The failed volume query was not escalated; unavailable stable APIs were not replaced by unsafe FFI; missing crypto was not downloaded. These are documented stop gates for their dependent implementation branches. No original acceptance criterion is waived or newly marked satisfied by this report.

## 12. Recommended next increment and independent review gates

**Do not begin blob, manifest, dispatch, result or session remediation from these partial results.** The immediate next authorized work should resolve DG-3/DG-4: choose/audit a safe Windows content/identity/publication abstraction and an exact SHA-256 package, with separately approved provisioning if offline material is missing. This report does not authorize network access or package addition.

The smallest subsequent **production implementation candidate** is PG-01's versioned migration-compatibility foundation, only after ADR-0008/legacy/ownership decisions and exact preservation/old-writer-exclusion contracts are accepted. Begin with disposable valid Core fixtures; keep upgrade of existing operator stores disabled until preservation and quiescence have independent evidence. Do not append recovery tables or weaken current v1 exact-schema checks ad hoc.

PG-02 identity/hash primitives must pass before PG-05 CAS, then PG-03 immutable manifests, PG-04 dispatch, PG-06 results and PG-07 continuation. ADR-0010 acceptance and PG-08 recovery remain separate. Independent Windows filesystem/dependency and migration/security reviews are required before those dependent capabilities are enabled. Exactly-once external execution, physical power-loss durability and dedicated VM containment are not consequences of a passed SQLite test.

## 13. Documentation and Git verification

Only this report and a narrow PROGRESS reference are permitted retained changes. No existing ADR, acceptance requirement, historical report, production/test/API/schema/dependency/configuration or lockfile is altered. No Cargo workspace test/validator was run; those are not claimed as newly passing here. The executable experiments were temporary synthetic programs, not new repository tests.

Final documentation link/heading/fence/status and whitespace checks, full file-hash preservation, physical index and reference/history comparisons are recorded in section 18 after writing. No Git index bytes are restored or rewritten.

## 14. Evidence references

- [Recovery architecture](REMEDIATION_ARCHITECTURE.md), Proposed [ADR-0008](../adr/0008-recoverable-local-operations.md), [ADR-0009](../adr/0009-verified-content-and-blob-reconciliation.md), [ADR-0010](../adr/0010-explicit-initialization-recovery.md).
- [Original requirements](../../REQUIREMENTS.md), [ROADMAP Phase 1](../../ROADMAP.md#phase-1--technical-validation-and-local-foundation), [gap analysis](PHASE1_GAP_ANALYSIS.md), [final rejection](PHASE1_FINAL_VERIFICATION.md), [OPEN_QUESTIONS](../OPEN_QUESTIONS.md).
- Actual [migration](../../crates/sentra-core/src/persistence/migration.rs), [connection](../../crates/sentra-core/src/persistence/connection.rs), [managed transactions](../../crates/sentra-core/src/persistence/transaction.rs), [snapshot model](../../crates/sentra-core/src/persistence/model.rs) and [DDL](../../crates/sentra-core/src/persistence/schema_v1.sql).
- Installed Rust 1.99 primary documentation under C:/Users/Taiizor/.rustup/toolchains/stable-x86_64-pc-windows-msvc/share/doc/rust/html/: std/fs/fn.rename.html, fn.hard_link.html, struct.File.html and std/os/windows/fs/trait.MetadataExt.html. Read locally; no mutable online documentation was consulted.
- Cached rusqlite 0.32.1 src/error.rs (SqlInputError versus sqlite_error accessor), windows-sys 0.61.2 Cargo.toml plus Win32/Storage/FileSystem and Security/Cryptography declarations, windows-link 0.2.1 and getrandom 0.4.3 manifests. Source availability/licensing metadata is not approval.
- Live fsutil/CIM/DriveInfo queries, controlled helper stdout, actual native compilation and process termination, raw outputs/sources below. OS API declarations are distinguished from runtime tracing; hash/cleanup tools are not production crypto/containment implementations.

## 15. Reproduction setup

The following reproduces only synthetic feasibility experiments and must be separately authorized when run. Copy the embedded source blocks in section 17 to a **new** dedicated temporary directory, never over an existing directory. Copy the trusted current schema_v1.sql there without changing it. Create owner.marker with the exact text “Sentra prerequisite synthetic experiments only” and identity.txt containing identity-a. Use local cached build artifacts matching section 6; if unavailable or ambiguous, **stop rather than download/build unrelated dependencies**.

```powershell
$repoRoot = (Get-Location).Path.Replace([char]92,[char]47)
$probeRoot = [IO.Path]::GetTempPath().Replace([char]92,[char]47).TrimEnd('/') + '/Sentra Prereq-' + [Guid]::NewGuid().ToString('N')
# Verify this fresh absolute path is inside the intended temporary base before creation.
# Write the inert appendix sources here; never use an existing directory or database.
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
try {
    $env:TEMP = $probeRoot
    $env:TMP = $probeRoot
    # Run the exact rustc command from section 6 using the resolved repository path.
    # Capture $LASTEXITCODE immediately; a later finally statement must not mask it.
    # Then run run.ps1, not the historical failed/retry files on reused paths.
} finally {
    $env:TEMP = $previousTemp
    $env:TMP = $previousTmp
}
```

The appendix preserves the executed controller source, including its historical FS-00 record of the earlier denied volume query; a new run must query/record its own environment rather than reuse that recorded serial/error. The final Rust source includes the diagnostic fix and supplemental backup mode. On a fresh root it avoids the two historical harness errors. Historical retry scripts only changed fixture/output prefixes as described in section 6; they are not needed for fresh reproduction. Raw experiment-file hashes below identify the original files before cleanup, including normal generated line endings.

Do not use a blanket recursive cleanup copied from a log. Re-inventory the exact owned root without following links, verify marker and known link targets, unlink known indirections while preserving target canary, remove individually verified normal files and finally empty directories. Stop on an unexpected entry, busy helper or type/path change. The actual successful cleanup used Bun fs.unlinkSync and fs.rmdirSync without recursive deletion.

## 16. Retained raw results and hashes

The JSON lines preserve each named record; only the temporary-root token is normalized as stated above. Compiler excerpt is the actual definitive failure, not a successful check.

### Initial run

```json
{"id":"FS-00-volume-management-query","status":"Blocked","data":{"exit_code":1,"win32_error":5,"alternative":"DriveInfo NTFS and CIM serial F2C8CC66; no elevation","command":"fsutil fsinfo volumeinfo C:"}}
{"id":"FS-01-identity-rename","status":"Passed","data":{"after":"0x00000000000000000024000000080a2e","before":"0x00000000000000000024000000080a2e","content":"identity-a"}}
{"id":"FS-02-independent-reader","status":"Passed","data":{"file_id":"0x00000000000000000024000000080a2e","raw":"File ID is 0x00000000000000000024000000080a2e","exit_code":0}}
{"id":"FS-03-hardlink-identity","status":"Passed","data":{"original":"0x00000000000000000024000000080a2e","attributes":"Archive","alias":"0x00000000000000000024000000080a2e"}}
{"id":"FS-04-std-rename-replaces","status":"Passed","data":{"source_exists":false,"replacement_id":"0x00000000000000000042000000063bf2","old_hardlink_id":"0x00000000000000000024000000080a2e","old_id":"0x00000000000000000024000000080a2e","destination_id":"0x00000000000000000042000000063bf2"}}
{"id":"FS-05-no-replace-collision","status":"Passed","data":{"source_preserved":true,"destination_preserved":true,"destination_id":"0x0000000000000000002c000000080da9","hresult":-2147024713,"source_id":"0x00000000000000000017000000080d65"}}
{"id":"FS-06-concurrent-file-move","status":"Passed","data":[{"round":1,"successes":1,"winner":0,"collision_code":-2147024713,"destination_id":"0x00000000000000000011000000080db8","content_preserved":true,"loser_source_preserved":true},{"round":2,"successes":1,"winner":1,"collision_code":-2147024713,"destination_id":"0x00000000000000000024000000080de5","content_preserved":true,"loser_source_preserved":true},{"round":3,"successes":1,"winner":1,"collision_code":-2147024713,"destination_id":"0x0000000000000000000f000000080dfb","content_preserved":true,"loser_source_preserved":true},{"round":4,"successes":1,"winner":0,"collision_code":-2147024713,"destination_id":"0x0000000000000000000f000000080dfd","content_preserved":true,"loser_source_preserved":true},{"round":5,"successes":1,"winner":0,"collision_code":-2147024713,"destination_id":"0x00000000000000000023000000080e0a","content_preserved":true,"loser_source_preserved":true},{"round":6,"successes":1,"winner":1,"collision_code":-2147024713,"destination_id":"0x00000000000000000025000000080e10","content_preserved":true,"loser_source_preserved":true},{"round":7,"successes":1,"winner":0,"collision_code":-2147024713,"destination_id":"0x00000000000000000021000000080e16","content_preserved":true,"loser_source_preserved":true},{"round":8,"successes":1,"winner":0,"collision_code":-2147024713,"destination_id":"0x0000000000000000000e000000080e1a","content_preserved":true,"loser_source_preserved":true},{"round":9,"successes":1,"winner":0,"collision_code":-2147024713,"destination_id":"0x00000000000000000018000000080e1c","content_preserved":true,"loser_source_preserved":true},{"round":10,"successes":1,"winner":0,"collision_code":-2147024713,"destination_id":"0x00000000000000000013000000080e21","content_preserved":true,"loser_source_preserved":true}]}
{"id":"FS-07-concurrent-std-hard-link","status":"Passed","data":[{"round":1,"successes":1,"winner":1,"collision_code":183,"destination_id":"0x00000000000000000010000000080e34","content_preserved":true,"loser_source_preserved":true},{"round":2,"successes":1,"winner":1,"collision_code":183,"destination_id":"0x00000000000000000026000000080e6e","content_preserved":true,"loser_source_preserved":true},{"round":3,"successes":1,"winner":1,"collision_code":183,"destination_id":"0x00000000000000000030000000080e8b","content_preserved":true,"loser_source_preserved":true},{"round":4,"successes":1,"winner":1,"collision_code":183,"destination_id":"0x0000000000000000003f0000000813f5","content_preserved":true,"loser_source_preserved":true},{"round":5,"successes":1,"winner":1,"collision_code":183,"destination_id":"0x000000000000000000220000000813f9","content_preserved":true,"loser_source_preserved":true},{"round":6,"successes":1,"winner":0,"collision_code":183,"destination_id":"0x0000000000000000001c0000000813fa","content_preserved":true,"loser_source_preserved":true},{"round":7,"successes":1,"winner":1,"collision_code":183,"destination_id":"0x0000000000000000002e00000008142e","content_preserved":true,"loser_source_preserved":true},{"round":8,"successes":1,"winner":1,"collision_code":183,"destination_id":"0x0000000000000000001b000000081436","content_preserved":true,"loser_source_preserved":true},{"round":9,"successes":1,"winner":0,"collision_code":183,"destination_id":"0x0000000000000000001500000008146f","content_preserved":true,"loser_source_preserved":true},{"round":10,"successes":1,"winner":0,"collision_code":183,"destination_id":"0x000000000000000000320000000814a4","content_preserved":true,"loser_source_preserved":true}]}
{"id":"FS-08-junction","status":"Passed","data":{"link_type":"Junction","metadata":{"is_symlink":true,"file_attributes":1040,"is_reparse":true},"query_exit":0,"tag":"0xa0000003"}}
{"id":"FS-09-file-symlink","status":"Passed","data":{"metadata":{"is_symlink":true,"file_attributes":1056,"is_reparse":true},"query_exit":0,"tag":"0xa000000c"}}
{"id":"FS-09-directory-symlink","status":"Passed","data":{"metadata":{"is_symlink":true,"file_attributes":1040,"is_reparse":true},"query_exit":0,"tag":"0xa000000c"}}
{"id":"FS-10-process-termination","status":"Passed","data":[{"content":"durable-fixture","file_id":"0x00000000000000000011000000081611","kill_exit":-1,"object_exists":false,"point":"after_flush","stage_exists":true},{"content":"durable-fixture","file_id":"0x0000000000000000001f000000081624","kill_exit":-1,"object_exists":true,"point":"after_rename","stage_exists":false},{"content":"durable-fixture","file_id":"0x0000000000000000001700000008162c","kill_exit":-1,"object_exists":true,"point":"after_close","stage_exists":false}]}
{"id":"SQL-01-effective-config","status":"Passed","data":{"case":"inspect","version":1,"probe_table":0,"history_rows":1,"integrity":"ok","foreign_key_violations":0,"reserved_micro_usd":10,"audit_rows":1}}
{"id":"SQL-01-engine-config-values","status":"Passed","data":{"case":"init","sqlite":"3.46.0","source_id":"2024-05-23 13:25:27 96c92aba00c8375bc32fafcdf12429c58bd8aabfcadab6683e35bbb9cdebf19e","foreign_keys":1,"journal_mode":"wal","synchronous":2,"busy_timeout":5000,"wal_autocheckpoint":1000,"trusted_schema":0}}
{"id":"SQL-02-commit-and-idempotency","status":"Passed","data":{"second":{"case":"migrate","applied":false,"version":2},"first":{"case":"migrate","applied":true,"version":2},"state":{"case":"inspect","version":2,"probe_table":1,"history_rows":2,"integrity":"ok","foreign_key_violations":0,"reserved_micro_usd":10,"audit_rows":1}}}
{"id":"HARNESS-FAILURE","status":"Failed","data":{"position":"Şurada C:\\Users\\Taiizor\\AppData\\Local\\Temp\\Sentra Prereq-4be22b15f8d941bea9515af9f8ee31ab\\run.ps1:11 karakter:61\r\n+ … n Assert([bool]$Ok,[string]$Message) {if (-not $Ok) {throw $Message}}\r\n+                                                        ~~~~~~~~~~~~~~","message":"Rust probe failed: \nthread 'main' (15884) panicked at <probeRoot>/sqlite_probe.rs:87:251:\ncalled `Option::unwrap()` on a `None` value\nnote: run with `RUST_BACKTRACE=1` environment variable to display a backtrace","exception_type":"System.Management.Automation.RuntimeException"}}
```

### First retry (failed)

```json
{"id":"SQL-01-effective-config","status":"Passed","data":{"case":"inspect","version":1,"probe_table":0,"history_rows":1,"integrity":"ok","foreign_key_violations":0,"reserved_micro_usd":10,"audit_rows":1}}
{"id":"HARNESS-FAILURE","status":"Failed","data":{"position":"Şurada C:\\Users\\Taiizor\\AppData\\Local\\Temp\\Sentra Prereq-4be22b15f8d941bea9515af9f8ee31ab\\retry_sql.ps1:11 karakter:61\r\n+ … n Assert([bool]$Ok,[string]$Message) {if (-not $Ok) {throw $Message}}\r\n+                                                        ~~~~~~~~~~~~~~","message":"Rust probe failed: \nthread 'main' (27744) panicked at <probeRoot>/sqlite_probe.rs:24:5:\nassertion failed: !Path::new(p).exists()\nnote: run with `RUST_BACKTRACE=1` environment variable to display a backtrace","exception_type":"System.Management.Automation.RuntimeException"}}
```

### Final SQLite retry

```json
{"id":"SQL-01-effective-config","status":"Passed","data":{"case":"inspect","version":1,"probe_table":0,"history_rows":1,"integrity":"ok","foreign_key_violations":0,"reserved_micro_usd":10,"audit_rows":1}}
{"id":"SQL-01-engine-config-values","status":"Passed","data":{"case":"init","sqlite":"3.46.0","source_id":"2024-05-23 13:25:27 96c92aba00c8375bc32fafcdf12429c58bd8aabfcadab6683e35bbb9cdebf19e","foreign_keys":1,"journal_mode":"wal","synchronous":2,"busy_timeout":5000,"wal_autocheckpoint":1000,"trusted_schema":0}}
{"id":"SQL-02-commit-and-idempotency","status":"Passed","data":{"state":{"case":"inspect","version":2,"probe_table":1,"history_rows":2,"integrity":"ok","foreign_key_violations":0,"reserved_micro_usd":10,"audit_rows":1},"first":{"case":"migrate","applied":true,"version":2},"second":{"case":"migrate","applied":false,"version":2}}}
{"id":"SQL-03-explicit-rollback","status":"Passed","data":{"probe":{"case":"statement_failure","sqlite_code":1,"transaction_still_active":true,"version_before_rollback":2,"version_after_rollback":1,"partial_table_after_rollback":0},"state":{"case":"inspect","version":1,"probe_table":0,"history_rows":1,"integrity":"ok","foreign_key_violations":0,"reserved_micro_usd":10,"audit_rows":1}}}
{"id":"SQL-04-kill-before_commit","status":"Passed","data":{"kill_exit":-1,"state":{"case":"inspect","version":1,"probe_table":0,"history_rows":1,"integrity":"ok","foreign_key_violations":0,"reserved_micro_usd":10,"audit_rows":1}}}
{"id":"SQL-04-kill-after_commit","status":"Passed","data":{"kill_exit":-1,"state":{"case":"inspect","version":2,"probe_table":1,"history_rows":2,"integrity":"ok","foreign_key_violations":0,"reserved_micro_usd":10,"audit_rows":1}}}
{"id":"SQL-05-two-migrators","status":"Passed","data":{"responses":[{"case":"concurrent","applied":true,"version":2},{"case":"concurrent","applied":false,"version":2}],"state":{"case":"inspect","version":2,"probe_table":1,"history_rows":2,"integrity":"ok","foreign_key_violations":0,"reserved_micro_usd":10,"audit_rows":1}}}
{"id":"SQL-06-busy-timeout","status":"Passed","data":{"case":"busy","sqlite_code":5,"elapsed_ms":5513,"transaction_started":false}}
{"id":"SQL-07-reader-checkpoint","status":"Passed","data":{"case":"wal_reader","reader_version_before_release":1,"writer_version":2,"checkpoint_busy":1,"log_frames":28,"checkpointed_frames":23,"checkpoint_after_release":[0,0,0],"wal_bytes_after_release":0}}
{"id":"SQL-08-legacy-open-writer-risk","status":"Passed","data":{"case":"legacy_connection","version":2,"preopened_connection_write_succeeded":true,"audit_rows":2}}
{"id":"SQL-09-vacuum-boundary","status":"Passed","data":{"case":"vacuum_inside_transaction","sqlite_code":1,"explicit_rollback":true}}
```

### Supplemental backup and cleanup

```json
{"case":"init","sqlite":"3.46.0","source_id":"2024-05-23 13:25:27 96c92aba00c8375bc32fafcdf12429c58bd8aabfcadab6683e35bbb9cdebf19e","foreign_keys":1,"journal_mode":"wal","synchronous":2,"busy_timeout":5000,"wal_autocheckpoint":1000,"trusted_schema":0}
{"case":"vacuum_into_snapshot","source_wal_bytes_before":94792,"backup_version":1,"backup_integrity":"ok","reserved_micro_usd":10,"audit_rows":1,"collision_sqlite_code":1,"existing_backup_preserved":true}
{"root":"<probeRoot>","nonrecursive":true,"entriesRemoved":117,"linksRemoved":3,"targetCanaryPreserved":true,"rootRemains":false,"completedUtc":"2026-11-07T00:44:49.888Z"}
```

### Definitive stable-API compiler output

```text
error[E0658]: use of unstable library feature `windows_by_handle`
 --> <probeRoot>/identity_api.rs:2:108
  |
2 | fn main() { let m=std::fs::metadata(std::env::args_os().nth(1).unwrap()).unwrap(); println!("{:?} {:?}", m.volume_serial_number(), m....
  |                                                                                                            ^^^^^^^^^^^^^^^^^^^^
  |
  = note: see issue #63010 <https://github.com/rust-lang/rust/issues/63010> for more information

error[E0658]: use of unstable library feature `windows_by_handle`
 --> <probeRoot>/identity_api.rs:2:134
  |
2 | ...unwrap(); println!("{:?} {:?}", m.volume_serial_number(), m.file_index()); }
  |                                                                ^^^^^^^^^^
  |
  = note: see issue #63010 <https://github.com/rust-lang/rust/issues/63010> for more information

error: aborting due to 2 previous errors

For more information about this error, try `rustc --explain E0658`.
RUSTC_NATIVE_EXIT=1

```

### Experiment file hashes before cleanup

```json
{"File":"sqlite_probe.rs","Sha256":"17a473c0d2c9de0deae2d594fe2d82a14007545854e4ce6772dbede3a6e781ce","Bytes":10201}
{"File":"fs_worker.ps1","Sha256":"ffbd52c3d56af89c084b86b329e36197973253aa36b8593e40ffc859700b5d12","Bytes":2119}
{"File":"run.ps1","Sha256":"8687ce3e614e7e385f838a50d03942efbcdd7ae52a1e1c3fcf60a3f49e7434b5","Bytes":15450}
{"File":"retry_sql.ps1","Sha256":"bab413b560de2288f865930fa89bc0c74195d8c1fe0bf11c1906d4e2daf14134","Bytes":6095}
{"File":"final_sql.ps1","Sha256":"033aa628513206ada19fbebd5dda0fd518ca6a4680a4c752e70ecd3899bc47a2","Bytes":6105}
{"File":"schema_v1.sql","Sha256":"54c53fb3b5b58173c3c6ef697c2e11a8362a48fe61eeb18e7b49dad0e124a1d3","Bytes":4743}
{"File":"raw-results.json","Sha256":"a5775b0e6b5039a6f93e1eba09e22363a4a4ccbca60d6404b19e1406ae65c163","Bytes":11823}
{"File":"sqlite-retry-results.json","Sha256":"b5553daa953f93cda31a31f255157fd9fcd46dc8cccf2361e02e575083e7da90","Bytes":1299}
{"File":"sqlite-final-results.json","Sha256":"40b822415620f2758165105bff8b671e3b787f5d543dc119b489e8b1170d76af","Bytes":4876}
{"File":"sqlite_probe.exe","Sha256":"b3ea790703bd1b3e8e05f8131498a956e7c5ca810d319be07a9d4b0d6a4c1cf3","Bytes":1982976}
```

## 17. Inert reproduction sources

### Rust feasibility harness — sqlite_probe.rs

```rust
#![forbid(unsafe_code)]
use rusqlite::{Connection, config::DbConfig};
use std::{env, io::{self, Write}, path::Path, time::{Duration, Instant}};
const APP: i64 = 0x53454e54;
fn open(p: &str) -> Connection {
    let c=Connection::open(p).unwrap();
    c.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,true).unwrap();
    c.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE,true).unwrap();
    c.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA wal_autocheckpoint=1000;").unwrap();
    c
}
fn n(c:&Connection,q:&str)->i64{c.query_row(q,[],|r|r.get(0)).unwrap()}
fn s(c:&Connection,q:&str)->String{c.query_row(q,[],|r|r.get(0)).unwrap()}
fn code(e:&rusqlite::Error)->i32 {
    match e {
        rusqlite::Error::SqliteFailure(e,_) | rusqlite::Error::SqlInputError{error:e,..}=>e.extended_code,
        _=>-1
    }
}
fn ready(){println!("READY");io::stdout().flush().unwrap();let mut x=String::new();io::stdin().read_line(&mut x).unwrap();}
fn table(c:&Connection)->i64{n(c,"SELECT count(*) FROM sqlite_master WHERE name='prerequisite_probe'")}
fn history(c:&Connection)->i64{n(c,"SELECT count(*) FROM schema_migrations")}
fn init(p:&str){
    assert!(!Path::new(p).exists());
    let mut c=open(p);
    let tx=c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).unwrap();
    tx.execute_batch(include_str!("schema_v1.sql")).unwrap();
    tx.execute("INSERT INTO schema_migrations VALUES(1,'Synthetic schema-only fixture','2026-11-07T00:00:00.000Z','probe-only-not-integrity')",[]).unwrap();
    tx.execute_batch(&format!("PRAGMA user_version=1; PRAGMA application_id={APP};")).unwrap();
    tx.execute("INSERT INTO sessions(session_id,state,mode,classification_floor,target_revision,created_at,updated_at) VALUES('00000000-0000-0000-0000-000000000001','SCOPED','CONTINUOUS_REVIEW','INTERNAL','synthetic','2026-11-07T00:00:00.000Z','2026-11-07T00:00:00.000Z')",[]).unwrap();
    tx.execute("INSERT INTO budget_reservations VALUES('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001','synthetic',10,NULL,'RESERVED','2026-11-07T00:00:00.000Z',NULL)",[]).unwrap();
    tx.execute("INSERT INTO audit_events VALUES('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000001',1,'Seed','INTERNAL','2026-11-07T00:00:00.000Z',NULL,'{}')",[]).unwrap();
    tx.commit().unwrap();
    println!("{{\"case\":\"init\",\"sqlite\":\"{}\",\"source_id\":\"{}\",\"foreign_keys\":{},\"journal_mode\":\"{}\",\"synchronous\":{},\"busy_timeout\":{},\"wal_autocheckpoint\":{},\"trusted_schema\":{}}}",rusqlite::version(),s(&c,"SELECT sqlite_source_id()"),n(&c,"PRAGMA foreign_keys"),s(&c,"PRAGMA journal_mode"),n(&c,"PRAGMA synchronous"),n(&c,"PRAGMA busy_timeout"),n(&c,"PRAGMA wal_autocheckpoint"),n(&c,"PRAGMA trusted_schema"));
}
fn ddl(c:&Connection){
    c.execute_batch("CREATE TABLE prerequisite_probe(id INTEGER PRIMARY KEY, value TEXT NOT NULL); CREATE UNIQUE INDEX prerequisite_probe_value ON prerequisite_probe(value); INSERT INTO prerequisite_probe VALUES(1,'synthetic'); INSERT INTO schema_migrations VALUES(2,'Disposable DDL feasibility probe','2026-11-07T00:00:00.000Z','probe-only-not-integrity'); PRAGMA user_version=2;").unwrap();
}
fn migrate(c:&mut Connection)->bool{
    let tx=c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).unwrap();
    let v=n(&tx,"PRAGMA user_version");
    assert!(v==1 || v==2);
    if v==1 {ddl(&tx);} else {assert_eq!(table(&tx),1);assert_eq!(history(&tx),2);}
    tx.commit().unwrap(); v==1
}
fn inspect(c:&Connection){
    let integrity=s(c,"PRAGMA integrity_check(10)");
    let fk:i64=c.prepare("PRAGMA foreign_key_check").unwrap().query_map([],|_|Ok(())).unwrap().count() as i64;
    let v=n(c,"PRAGMA user_version");
    let t=table(c);let h=history(c);
    let b=n(c,"SELECT sum(reserved_cost_micro_usd) FROM budget_reservations");
    let a=n(c,"SELECT count(*) FROM audit_events");
    assert_eq!(integrity,"ok");assert_eq!(fk,0);assert_eq!(b,10);
    assert!((v==1&&t==0&&h==1)||(v==2&&t==1&&h==2));
    println!("{{\"case\":\"inspect\",\"version\":{v},\"probe_table\":{t},\"history_rows\":{h},\"integrity\":\"{integrity}\",\"foreign_key_violations\":{fk},\"reserved_micro_usd\":{b},\"audit_rows\":{a}}}");
}
fn main(){
    let a:Vec<String>=env::args().collect();let mode=&a[1];let p=&a[2];
    if mode=="metadata" {
        use std::os::windows::fs::MetadataExt;
        let m=std::fs::symlink_metadata(p).unwrap();
        println!("{{\"is_symlink\":{},\"file_attributes\":{},\"is_reparse\":{}}}",m.file_type().is_symlink(),m.file_attributes(),m.file_attributes() & 0x400 != 0);
        return;
    }
    if mode=="rename" {
        match std::fs::rename(p,&a[3]) {
            Ok(())=>println!("{{\"ok\":true,\"os_error\":0}}"),
            Err(e)=>println!("{{\"ok\":false,\"os_error\":{}}}",e.raw_os_error().unwrap_or(-1))
        } return;
    }
    if mode=="link" {
        match std::fs::hard_link(p,&a[3]) {
            Ok(())=>println!("{{\"ok\":true,\"os_error\":0}}"),
            Err(e)=>println!("{{\"ok\":false,\"os_error\":{}}}",e.raw_os_error().unwrap_or(-1))
        } return;
    }
    if mode=="init"{init(p);return;}
    let mut c=open(p);
    match mode.as_str(){
        "inspect"=>inspect(&c),
        "migrate"=>{let applied=migrate(&mut c);println!("{{\"case\":\"migrate\",\"applied\":{applied},\"version\":{}}}",n(&c,"PRAGMA user_version"));},
        "concurrent"=>{ready();let applied=migrate(&mut c);println!("{{\"case\":\"concurrent\",\"applied\":{applied},\"version\":{}}}",n(&c,"PRAGMA user_version"));},
        "before_commit"=>{c.execute_batch("BEGIN IMMEDIATE").unwrap();ddl(&c);ready();c.execute_batch("ROLLBACK").unwrap();},
        "after_commit"=>{assert!(migrate(&mut c));ready();},
        "hold"=>{c.execute_batch("BEGIN IMMEDIATE").unwrap();ready();c.execute_batch("ROLLBACK").unwrap();},
        "failure"=>{
            c.execute_batch("BEGIN IMMEDIATE").unwrap();ddl(&c);
            let e=c.execute_batch("THIS IS NOT SQL").unwrap_err();
            let still_active=!c.is_autocommit();let transient_version=n(&c,"PRAGMA user_version");
            assert!(still_active);assert_eq!(transient_version,2);
            c.execute_batch("ROLLBACK").unwrap();
            assert_eq!(n(&c,"PRAGMA user_version"),1);assert_eq!(table(&c),0);assert_eq!(history(&c),1);
            println!("{{\"case\":\"statement_failure\",\"sqlite_code\":{},\"transaction_still_active\":{still_active},\"version_before_rollback\":{transient_version},\"version_after_rollback\":1,\"partial_table_after_rollback\":0}}",code(&e));
        },
        "busy"=>{
            let start=Instant::now();let e=c.execute_batch("BEGIN IMMEDIATE").unwrap_err();
            assert_eq!(code(&e),5);
            assert!(c.is_autocommit());
            println!("{{\"case\":\"busy\",\"sqlite_code\":5,\"elapsed_ms\":{},\"transaction_started\":false}}",start.elapsed().as_millis());
        },
        "wal"=>{
            c.execute_batch("BEGIN").unwrap();assert_eq!(n(&c,"PRAGMA user_version"),1);
            assert_eq!(n(&c,"SELECT count(*) FROM sessions"),1);
            let mut writer=open(p);assert!(migrate(&mut writer));
            assert_eq!(n(&c,"PRAGMA user_version"),1);
            writer.busy_timeout(Duration::from_millis(25)).unwrap();
            let busy:(i64,i64,i64)=writer.query_row("PRAGMA wal_checkpoint(TRUNCATE)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
            assert_eq!(busy.0,1);c.execute_batch("ROLLBACK").unwrap();
            let done:(i64,i64,i64)=writer.query_row("PRAGMA wal_checkpoint(TRUNCATE)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
            assert_eq!(done,(0,0,0));
            let wal=std::fs::metadata(format!("{p}-wal")).unwrap().len();assert_eq!(wal,0);
            println!("{{\"case\":\"wal_reader\",\"reader_version_before_release\":1,\"writer_version\":2,\"checkpoint_busy\":{},\"log_frames\":{},\"checkpointed_frames\":{},\"checkpoint_after_release\":[0,0,0],\"wal_bytes_after_release\":{wal}}}",busy.0,busy.1,busy.2);
        },
        "legacy"=>{
            assert_eq!(n(&c,"PRAGMA user_version"),1);let mut w=open(p);assert!(migrate(&mut w));
            c.execute("INSERT INTO audit_events VALUES('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000001',2,'LegacyConnectionWrite','INTERNAL','2026-11-07T00:00:00.000Z',NULL,'{}')",[]).unwrap();
            assert_eq!(n(&c,"SELECT count(*) FROM audit_events"),2);
            println!("{{\"case\":\"legacy_connection\",\"version\":2,\"preopened_connection_write_succeeded\":true,\"audit_rows\":2}}");
        },
        "backup"=>{
            let dest=&a[3];assert!(!Path::new(dest).exists());
            let wal_before=std::fs::metadata(format!("{p}-wal")).unwrap().len();assert!(wal_before>0);
            c.execute("VACUUM main INTO ?1",[dest]).unwrap();
            let d=Connection::open_with_flags(dest,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
            assert_eq!(n(&d,"PRAGMA user_version"),1);assert_eq!(s(&d,"PRAGMA integrity_check(10)"),"ok");
            assert_eq!(n(&d,"SELECT sum(reserved_cost_micro_usd) FROM budget_reservations"),10);
            assert_eq!(n(&d,"SELECT count(*) FROM audit_events"),1);
            let before=std::fs::read(dest).unwrap();
            let e=c.execute("VACUUM main INTO ?1",[dest]).unwrap_err();
            assert_eq!(before,std::fs::read(dest).unwrap());
            println!("{{\"case\":\"vacuum_into_snapshot\",\"source_wal_bytes_before\":{wal_before},\"backup_version\":1,\"backup_integrity\":\"ok\",\"reserved_micro_usd\":10,\"audit_rows\":1,\"collision_sqlite_code\":{},\"existing_backup_preserved\":true}}",code(&e));
        },
        "unsupported"=>{
            c.execute_batch("BEGIN IMMEDIATE").unwrap();
            let e=c.execute_batch("VACUUM").unwrap_err();
            assert!(!c.is_autocommit());c.execute_batch("ROLLBACK").unwrap();
            println!("{{\"case\":\"vacuum_inside_transaction\",\"sqlite_code\":{},\"explicit_rollback\":true}}",code(&e));
        },
        _=>panic!("unknown synthetic mode")
    }
}

```

### Process/barrier helper — fs_worker.ps1

```powershell
param([string]$Mode,[string]$Source,[string]$Destination,[string]$ReadyName,[string]$GoName,[string]$Kind,[string]$Point)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($Mode -eq 'Inspect') {
    $raw=@(& fsutil.exe file queryfileid $Source 2>&1) -join "`n"
    $exit=$LASTEXITCODE
    if ($exit -ne 0) { throw "File identity query failed: $exit" }
    $id=[regex]::Match($raw,'0x[0-9A-Fa-f]+').Value
    if (-not $id) { throw 'Missing file identity' }
    [ordered]@{file_id=$id;raw=$raw;exit_code=$exit} | ConvertTo-Json -Compress
    exit 0
}
if ($Mode -eq 'Promote') {
    $ready=[Threading.EventWaitHandle]::OpenExisting($ReadyName)
    $go=[Threading.EventWaitHandle]::OpenExisting($GoName)
    try {
        $ready.Set() | Out-Null
        if (-not $go.WaitOne(30000)) { throw 'Promotion barrier timeout' }
        if ($Kind -eq 'Link') {
            $out=@(& "$PSScriptRoot/sqlite_probe.exe" link $Source $Destination)
            if ($LASTEXITCODE -ne 0) { throw 'Rust link helper failed' }
            ($out -join "`n") | ConvertFrom-Json | ConvertTo-Json -Compress
        } else {
            try {
                [IO.File]::Move($Source,$Destination,$false)
                [ordered]@{ok=$true;hresult=0} | ConvertTo-Json -Compress
            } catch [IO.IOException] {
                [ordered]@{ok=$false;hresult=$_.Exception.GetBaseException().HResult} | ConvertTo-Json -Compress
            }
        }
    } finally {$ready.Dispose();$go.Dispose()}
    exit 0
}
if ($Mode -eq 'Crash') {
    $f=[IO.FileStream]::new($Source,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,([IO.FileShare]::Read -bor [IO.FileShare]::Delete))
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes('durable-fixture')
        $f.Write($bytes,0,$bytes.Length);$f.Flush($true)
        if ($Point -ne 'after_flush') {[IO.File]::Move($Source,$Destination,$false)}
        if ($Point -eq 'after_close') {$f.Dispose()}
        [Console]::WriteLine('READY');[Console]::Out.Flush()
        [Console]::ReadLine() | Out-Null
    } finally {$f.Dispose()}
    exit 0
}
throw 'Unknown synthetic worker mode'

```

### Recorded controller — run.ps1

```powershell
param([Parameter(Mandatory)][string]$ProbeRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$results=[Collections.Generic.List[object]]::new()
$worker="$ProbeRoot/fs_worker.ps1"
$exe="$ProbeRoot/sqlite_probe.exe"
function Add-Result([string]$Id,[string]$Status,[object]$Data) {
    $results.Add([ordered]@{id=$Id;status=$Status;data=$Data})
    Write-Host "$Id $Status"
}
function Assert([bool]$Ok,[string]$Message) {if (-not $Ok) {throw $Message}}
function Hash([string]$P) {(Get-FileHash -LiteralPath $P -Algorithm SHA256).Hash.ToLowerInvariant()}
function File-Id([string]$P) {
    $raw=@(& fsutil.exe file queryfileid $P 2>&1) -join "`n"
    Assert ($LASTEXITCODE -eq 0) 'fsutil file query failed'
    $id=[regex]::Match($raw,'0x[0-9A-Fa-f]+').Value
    Assert ([bool]$id) 'No file ID returned'
    $id
}
function Start-Owned([string]$Program,[string[]]$Arguments) {
    $si=[Diagnostics.ProcessStartInfo]::new()
    $si.FileName=$Program;$si.WorkingDirectory=$ProbeRoot
    $si.UseShellExecute=$false;$si.CreateNoWindow=$true
    $si.RedirectStandardInput=$true;$si.RedirectStandardOutput=$true;$si.RedirectStandardError=$true
    $si.Environment['TEMP']=$ProbeRoot;$si.Environment['TMP']=$ProbeRoot
    foreach($a in $Arguments){$si.ArgumentList.Add($a)}
    $p=[Diagnostics.Process]::new();$p.StartInfo=$si
    Assert ($p.Start()) 'Synthetic helper did not start'
    $p
}
function Finish-Owned([Diagnostics.Process]$P) {
    $out=$P.StandardOutput.ReadToEndAsync()
    $err=$P.StandardError.ReadToEndAsync()
    if (-not $P.WaitForExit(30000)) {$P.Kill($true);$P.WaitForExit();throw 'Owned helper timed out'}
    $o=$out.GetAwaiter().GetResult();$e=$err.GetAwaiter().GetResult()
    Assert ($P.ExitCode -eq 0) ("Owned helper failed: "+$e)
    $o.Trim()
}
function Await-Ready([Diagnostics.Process]$P) {
    $line=$P.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(30)).GetAwaiter().GetResult()
    Assert ($line -eq 'READY') ("Missing readiness barrier: "+$line)
}
function Kill-Owned([Diagnostics.Process]$P) {
    Assert (-not $P.HasExited) 'Owned helper exited before termination'
    $P.Kill();Assert ($P.WaitForExit(30000)) 'Owned helper did not terminate'
    $code=$P.ExitCode
    Assert ($code -ne 0) 'Synthetic crash was a normal exit'
    $code
}
function Rust([string[]]$Arguments) {
    $raw=@(& $exe @Arguments 2>&1) -join "`n"
    Assert ($LASTEXITCODE -eq 0) ("Rust probe failed: "+$raw)
    $raw | ConvertFrom-Json
}
function Fixture([string]$Name) {
    $db="$ProbeRoot/$Name.db"
    $config=Rust @('init',$db)
    Assert ($config.sqlite -eq '3.46.0' -and $config.foreign_keys -eq 1 -and $config.journal_mode -eq 'wal' -and $config.synchronous -eq 2 -and $config.busy_timeout -eq 5000 -and $config.wal_autocheckpoint -eq 1000) 'SQLite config mismatch'
    $db
}
function Promote-Rounds([string]$Kind) {
    $rounds=[Collections.Generic.List[object]]::new()
    foreach($round in 1..10) {
        $name=[Guid]::NewGuid().ToString('N')
        $go=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,"SentraGo$name")
        $ready=@(
            [Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,"SentraReadyA$name"),
            [Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,"SentraReadyB$name")
        )
        $source=@("$ProbeRoot/$Kind-$round-A.tmp","$ProbeRoot/$Kind-$round-B.tmp")
        [IO.File]::WriteAllText($source[0],('A'*65536))
        [IO.File]::WriteAllText($source[1],('B'*65536))
        $ids=@((File-Id $source[0]),(File-Id $source[1]))
        $hashes=@((Hash $source[0]),(Hash $source[1]))
        $destination="$ProbeRoot/$Kind-$round.object"
        $children=@()
        try {
            foreach($i in 0..1) {
                $eventName=if($i -eq 0){"SentraReadyA$name"}else{"SentraReadyB$name"}
                $children+=Start-Owned (Get-Command pwsh.exe).Source @('-NoProfile','-NonInteractive','-File',$worker,'-Mode','Promote','-Source',$source[$i],'-Destination',$destination,'-ReadyName',$eventName,'-GoName',"SentraGo$name",'-Kind',$Kind)
            }
            foreach($e in $ready){Assert ($e.WaitOne(30000)) 'Promotion readiness timeout'}
            $go.Set() | Out-Null
            $responses=@()
            foreach($p in $children){$responses+=((Finish-Owned $p)|ConvertFrom-Json)}
            $winners=@(0..1 | Where-Object {$responses[$_].ok})
            Assert ($winners.Count -eq 1) 'Not exactly one promotion winner'
            $winner=$winners[0];$loser=1-$winner
            Assert ((File-Id $destination) -eq $ids[$winner]) 'Promotion changed file identity'
            Assert ((Hash $destination) -eq $hashes[$winner]) 'Destination content mismatch'
            Assert ((Hash $source[$loser]) -eq $hashes[$loser]) 'Losing source changed'
            if($Kind -eq 'Link'){
                Assert ($responses[$loser].os_error -in @(80,183)) 'Unexpected hard-link collision code'
                Assert ([IO.File]::Exists($source[$winner])) 'Hard-link source missing before unlink'
                [IO.File]::Delete($source[$winner])
                Assert ((File-Id $destination) -eq $ids[$winner]) 'Object disappeared after source unlink'
                $collision=$responses[$loser].os_error
            }else{
                Assert ($responses[$loser].hresult -in @(-2147024816,-2147024713)) 'Unexpected move collision code'
                Assert (-not [IO.File]::Exists($source[$winner])) 'Moved source still exists'
                $collision=$responses[$loser].hresult
            }
            $rounds.Add([ordered]@{round=$round;successes=$winners.Count;winner=$winner;collision_code=$collision;destination_id=$ids[$winner];content_preserved=$true;loser_source_preserved=$true})
        } finally {
            foreach($p in $children){if(-not $p.HasExited){$p.Kill($true);$p.WaitForExit()};$p.Dispose()}
            foreach($e in $ready){$e.Dispose()};$go.Dispose()
        }
    }
    $rounds.ToArray()
}
try {
    Add-Result 'FS-00-volume-management-query' 'Blocked' @{command='fsutil fsinfo volumeinfo C:';exit_code=1;win32_error=5;alternative='DriveInfo NTFS and CIM serial F2C8CC66; no elevation'}
    $original="$ProbeRoot/identity.txt";$renamed="$ProbeRoot/renamed Unicode α space.txt"
    $id=File-Id $original
    [IO.File]::Move($original,$renamed,$false)
    Assert ((File-Id $renamed) -eq $id) 'Rename changed identity'
    Add-Result 'FS-01-identity-rename' 'Passed' @{before=$id;after=(File-Id $renamed);content=[IO.File]::ReadAllText($renamed)}
    $p=Start-Owned (Get-Command pwsh.exe).Source @('-NoProfile','-NonInteractive','-File',$worker,'-Mode','Inspect','-Source',$renamed)
    try {$fresh=(Finish-Owned $p)|ConvertFrom-Json}finally{$p.Dispose()}
    Assert ($fresh.file_id -eq $id) 'Independent reader identity mismatch'
    Add-Result 'FS-02-independent-reader' 'Passed' $fresh
    $alias="$ProbeRoot/hard alias.txt"
    New-Item -ItemType HardLink -Path $alias -Target $renamed | Out-Null
    Assert ((File-Id $alias) -eq $id) 'Hard link identity mismatch'
    Add-Result 'FS-03-hardlink-identity' 'Passed' @{original=$id;alias=(File-Id $alias);attributes=([IO.File]::GetAttributes($alias)).ToString()}
    $replacement="$ProbeRoot/replacement.tmp";[IO.File]::WriteAllText($replacement,'identity-b')
    $newId=File-Id $replacement
    Assert ($newId -ne $id) 'Fixture IDs unexpectedly equal'
    $replace=Rust @('rename',$replacement,$renamed)
    Assert ($replace.ok) 'std rename failed'
    Assert ((File-Id $renamed) -eq $newId -and (File-Id $alias) -eq $id) 'Replacement identity mismatch'
    Assert ([IO.File]::ReadAllText($renamed) -eq 'identity-b' -and [IO.File]::ReadAllText($alias) -eq 'identity-a') 'Replacement content mismatch'
    Add-Result 'FS-04-std-rename-replaces' 'Passed' @{old_id=$id;replacement_id=$newId;destination_id=(File-Id $renamed);old_hardlink_id=(File-Id $alias);source_exists=[IO.File]::Exists($replacement)}
    $collisionSource="$ProbeRoot/collision-source.tmp";$collisionDest="$ProbeRoot/collision-dest.object"
    [IO.File]::WriteAllText($collisionSource,'source')
    [IO.File]::WriteAllText($collisionDest,'existing')
    $sourceId=File-Id $collisionSource;$destId=File-Id $collisionDest;$hr=0
    try{[IO.File]::Move($collisionSource,$collisionDest,$false)}catch [IO.IOException]{$hr=$_.Exception.GetBaseException().HResult}
    Assert ($hr -in @(-2147024816,-2147024713)) 'Existing-destination move unexpectedly succeeded'
    Assert ((File-Id $collisionSource) -eq $sourceId -and (File-Id $collisionDest) -eq $destId) 'Collision changed identity'
    Assert ([IO.File]::ReadAllText($collisionDest) -eq 'existing') 'Collision overwrote data'
    Add-Result 'FS-05-no-replace-collision' 'Passed' @{hresult=$hr;source_id=$sourceId;destination_id=$destId;source_preserved=$true;destination_preserved=$true}
    Add-Result 'FS-06-concurrent-file-move' 'Passed' @(Promote-Rounds 'Move')
    Add-Result 'FS-07-concurrent-std-hard-link' 'Passed' @(Promote-Rounds 'Link')
    $target="$ProbeRoot/link-target";[IO.Directory]::CreateDirectory($target)|Out-Null
    [IO.File]::WriteAllText("$target/canary.txt",'inert')
    $junction="$ProbeRoot/junction"
    New-Item -ItemType Junction -Path $junction -Target $target | Out-Null
    $raw=@(& fsutil.exe reparsepoint query $junction 2>&1) -join "`n";$reparseExit=$LASTEXITCODE
    $meta=Rust @('metadata',$junction)
    Assert ($meta.is_reparse -and $raw -match '0xa0000003' -and $reparseExit -eq 0) 'Junction reparse classification failed'
    Add-Result 'FS-08-junction' 'Passed' @{metadata=$meta;tag='0xa0000003';query_exit=$reparseExit;link_type=(Get-Item -LiteralPath $junction -Force).LinkType}
    foreach($kind in @('file','directory')){
        $link="$ProbeRoot/$kind-symlink"
        try{
            if($kind -eq 'file'){[IO.File]::CreateSymbolicLink($link,"$target/canary.txt")|Out-Null}
            else{[IO.Directory]::CreateSymbolicLink($link,$target)|Out-Null}
        }catch [UnauthorizedAccessException]{
            Add-Result ("FS-09-$kind-symlink") 'Blocked' @{hresult=$_.Exception.GetBaseException().HResult;reason='Current privileges do not permit symlink creation; no configuration change'}
            continue
        }catch [IO.IOException]{
            $base=$_.Exception.GetBaseException()
            if($base.HResult -ne -2147023582){throw}
            Add-Result ("FS-09-$kind-symlink") 'Blocked' @{hresult=$base.HResult;reason='Privilege not held; no elevation or configuration change'}
            continue
        }
        $meta=Rust @('metadata',$link)
        $raw=@(& fsutil.exe reparsepoint query $link 2>&1) -join "`n";$code=$LASTEXITCODE
        Assert ($meta.is_reparse -and $raw -match '0xa000000c' -and $code -eq 0) 'Symlink reparse classification failed'
        Add-Result ("FS-09-$kind-symlink") 'Passed' @{metadata=$meta;tag='0xa000000c';query_exit=$code}
    }
    $crashes=[Collections.Generic.List[object]]::new()
    foreach($point in @('after_flush','after_rename','after_close')){
        $source="$ProbeRoot/$point.stage";$destination="$ProbeRoot/$point.object"
        $p=Start-Owned (Get-Command pwsh.exe).Source @('-NoProfile','-NonInteractive','-File',$worker,'-Mode','Crash','-Source',$source,'-Destination',$destination,'-Point',$point)
        try{
            Await-Ready $p
            $observed=if($point -eq 'after_flush'){$source}else{$destination}
            $before=File-Id $observed;$code=Kill-Owned $p
        }finally{if(-not $p.HasExited){$p.Kill($true);$p.WaitForExit()};$p.Dispose()}
        Assert ((File-Id $observed) -eq $before -and [IO.File]::ReadAllText($observed) -eq 'durable-fixture') 'Process-crash fixture changed'
        Assert ([IO.File]::Exists($source) -eq ($point -eq 'after_flush')) 'Unexpected stage after kill'
        Assert ([IO.File]::Exists($destination) -eq ($point -ne 'after_flush')) 'Unexpected destination after kill'
        $crashes.Add(@{point=$point;kill_exit=$code;file_id=$before;content='durable-fixture';stage_exists=[IO.File]::Exists($source);object_exists=[IO.File]::Exists($destination)})
    }
    Add-Result 'FS-10-process-termination' 'Passed' $crashes.ToArray()
    $db=Fixture 'config'
    Add-Result 'SQL-01-effective-config' 'Passed' (Rust @('inspect',$db))
    $config=Rust @('init',"$ProbeRoot/version.db")
    Add-Result 'SQL-01-engine-config-values' 'Passed' $config
    $db=Fixture 'commit'
    $first=Rust @('migrate',$db);$second=Rust @('migrate',$db)
    Assert ($first.applied -and -not $second.applied) 'Migration repeated'
    Add-Result 'SQL-02-commit-and-idempotency' 'Passed' @{first=$first;second=$second;state=(Rust @('inspect',$db))}
    $db=Fixture 'failure'
    Add-Result 'SQL-03-explicit-rollback' 'Passed' @{probe=(Rust @('failure',$db));state=(Rust @('inspect',$db))}
    foreach($point in @('before_commit','after_commit')){
        $db=Fixture $point;$p=Start-Owned $exe @($point,$db)
        try{Await-Ready $p;$code=Kill-Owned $p}finally{if(-not $p.HasExited){$p.Kill($true);$p.WaitForExit()};$p.Dispose()}
        $state=Rust @('inspect',$db)
        $expected=if($point -eq 'before_commit'){1}else{2}
        Assert ($state.version -eq $expected -and $state.audit_rows -eq 1) 'Interrupted migration violated atomicity'
        Add-Result ("SQL-04-kill-$point") 'Passed' @{kill_exit=$code;state=$state}
    }
    $db=Fixture 'concurrent'
    $children=@()
    try{
        $children+=Start-Owned $exe @('concurrent',$db)
        $children+=Start-Owned $exe @('concurrent',$db)
        foreach($p in $children){Await-Ready $p}
        foreach($p in $children){$p.StandardInput.WriteLine('go');$p.StandardInput.Flush()}
        $responses=@($children|ForEach-Object{(Finish-Owned $_)|ConvertFrom-Json})
        Assert (@($responses|Where-Object{$_.applied}).Count -eq 1) 'Concurrent migration applied twice'
        Add-Result 'SQL-05-two-migrators' 'Passed' @{responses=$responses;state=(Rust @('inspect',$db))}
    }finally{foreach($p in $children){if(-not $p.HasExited){$p.Kill($true);$p.WaitForExit()};$p.Dispose()}}
    $db=Fixture 'busy';$p=Start-Owned $exe @('hold',$db)
    try{Await-Ready $p;$busy=Rust @('busy',$db);$p.StandardInput.WriteLine('release');$p.StandardInput.Flush();$unused=Finish-Owned $p}
    finally{if(-not $p.HasExited){$p.Kill($true);$p.WaitForExit()};$p.Dispose()}
    Add-Result 'SQL-06-busy-timeout' 'Passed' $busy
    $db=Fixture 'wal'
    Add-Result 'SQL-07-reader-checkpoint' 'Passed' (Rust @('wal',$db))
    $db=Fixture 'legacy'
    Add-Result 'SQL-08-legacy-open-writer-risk' 'Passed' (Rust @('legacy',$db))
    $db=Fixture 'unsupported'
    Add-Result 'SQL-09-vacuum-boundary' 'Passed' (Rust @('unsupported',$db))
}catch{
    Add-Result 'HARNESS-FAILURE' 'Failed' @{exception_type=$_.Exception.GetType().FullName;message=$_.Exception.Message;position=$_.InvocationInfo.PositionMessage}
}finally{
    $record=[ordered]@{observed_utc=[DateTimeOffset]::UtcNow.ToString('o');root=$ProbeRoot;cases=$results.ToArray()}
    [IO.File]::WriteAllText("$ProbeRoot/raw-results.json",($record|ConvertTo-Json -Depth 14))
}
$failed=@($results|Where-Object{$_.status -eq 'Failed'}).Count
[ordered]@{cases=$results.Count;passed=@($results|Where-Object{$_.status -eq 'Passed'}).Count;blocked=@($results|Where-Object{$_.status -eq 'Blocked'}).Count;failed=$failed;raw_results="$ProbeRoot/raw-results.json"}|ConvertTo-Json -Compress
if($failed){exit 1}

```

### Negative stable-API probe — identity_api.rs

```rust
use std::os::windows::fs::MetadataExt;
fn main() { let m=std::fs::metadata(std::env::args_os().nth(1).unwrap()).unwrap(); println!("{:?} {:?}", m.volume_serial_number(), m.file_index()); }

```

## 18. Final preservation record

- **Passed — documentation:** read-only Bun check across 68 Markdown files, 609 local links, 107 heading links, fenced blocks and the three unchanged Proposed statuses; zero errors, exit 0. No online link requests or dependency installation.
- **Passed — whitespace:** `git --no-optional-locks -c core.safecrlf=false diff --check`, exit 0. No Cargo fmt/check/clippy/test or repository validator was run or claimed here; only the documented disposable feasibility probes executed.
- **Passed — preservation:** develop / HEAD `4bd86181289cf452191e17fe52b41eda74ab73e2`, origin/develop 0 ahead / 0 behind, 286 index entries unchanged. Physical index SHA-256 `5425d94867efe9e9759a7eb5dc413a93272749be543c6d82ce66ef0c2161428a` and complete staged-entry, reference-target and reachable-history snapshots match entry. All **285 other tracked files** have identical byte hashes, including original criteria, ten ADRs, source/tests/manifests/lockfile/configuration and historical evidence.
- **Final worktree:** 1 modified file (`PROGRESS.md`), 1 untracked file (`docs/phase1/FOUNDATIONAL_PREREQUISITE_VALIDATION.md`), 0 staged files. Only documentation is retained. No Git operation modified history, references, index entries or physical index bytes.
- **Passed — cleanup:** owned temporary root absent after verified nonrecursive cleanup; 117 inventoried entries removed, three links unlinked without following, target canary preserved during link removal, zero remaining referring helper processes before cleanup. No cleanup artifacts remain.
- **Remaining stop gates:** safe production Windows handle/publication/durability strategy, exact approved offline SHA-256 and migration/preservation/legacy-writer evidence. Restricted positive experiments do not close these gates or certify production readiness.

**Phase 1 remains NOT APPROVED. ADR-0008/0009/0010 remain Proposed; F-611-02 and OQ-25 remain Open. No production implementation, closure attempt or Phase 2 work occurred.**

