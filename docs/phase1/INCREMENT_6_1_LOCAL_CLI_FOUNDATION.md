# Increment 6.1 — Local CLI Foundation

Date: 2026-11-06. Status: **Implemented and tested on Windows x64/MSVC**, within the limits below. Phase 1 is incomplete. Increment 6.2 and Phase 2 have not started. This is implementation evidence, not an independent security approval or production-readiness certification.

## Scope and architecture

`sentra-cli` is a Rust edition 2024 workspace member, with binary name `sentra`. It has exactly one dependency: the local `sentra-core = 0.1.0` path package. A fixed standard-library parser is adequate for three commands and avoids a new parser dependency. Typed `Command`/`Invocation` values separate argument handling and rendering from Core domain operations. The binary handles process streams and exit codes only.

The interface-neutral `sentra_core::service::LocalWorkspace` facade owns workspace/storage admission and CoreService composition. It calls the existing `CoreService::create_session`, session projection and budget inspection, using the existing repository, immutable default PolicyEngine and `FailClosedBackend`. CLI code has no SQL, connection, authority, provider, subprocess or execution dispatch access. The binary's `std::process::ExitCode` is not a process-spawning facility.

The existing Core API lacked a durable CLI project registry or idempotent initialization operation. The bounded solution uses a **dedicated database with one foundation session**, whose SessionId also serves as local project identity. There is no new manifest, ProjectId entity, schema migration, lifecycle edge or independent authorization mechanism. Empty/incomplete/multi-session stores are rejected; arbitrary session selection or automatic repair would be unsafe. Multi-session identity and repair remain [OQ-25](../OPEN_QUESTIONS.md).

## Changed files and responsibilities

| Files | Change |
| --- | --- |
| [Cargo.toml](../../Cargo.toml), [Cargo.lock](../../Cargo.lock), [CLI manifest](../../crates/sentra-cli/Cargo.toml) | Workspace membership and local package edge only; external versions/checksums unchanged |
| [CLI library](../../crates/sentra-cli/src/lib.rs), [binary](../../crates/sentra-cli/src/main.rs) | Typed grammar, Core facade calls, stable human/JSON presentation and exit codes |
| [LocalWorkspace service](../../crates/sentra-core/src/service/local_workspace.rs), [service exports](../../crates/sentra-core/src/service/mod.rs), [CoreService](../../crates/sentra-core/src/service/core.rs) | Local lifecycle, redacted summary/error types and private single-session service projection |
| [SQLite manager](../../crates/sentra-core/src/persistence/connection.rs), [repository](../../crates/sentra-core/src/persistence/repository.rs) | Existing-only open, reuse of no-follow OS admission and bounded validated single-session query |
| [Core tests](../../crates/sentra-core/tests/local_workspace_tests.rs), [CLI tests](../../crates/sentra-cli/tests/cli_tests.rs) | 19 + 18 new cases; existing tests are unchanged |
| [CLI validator](../../experiments/phase1/cli/Validate.ps1), [authorization validator](../../experiments/phase1/authorization/Validate.ps1) | Recorded offline checks, actual Cargo artifact discovery, JSON/junction smoke checks; audit three external edges separately from the CLI path edge |
| [README](../../README.md), [architecture](../../ARCHITECTURE.md), [roadmap](../../ROADMAP.md), [security](../../SECURITY.md), [progress](../../PROGRESS.md), [documentation index](../README.md), [execution record](README.md), [validation plan](../VALIDATION.md), [open questions](../OPEN_QUESTIONS.md), this report | Synchronize current implemented scope, instructions, evidence and deferred gates |
| `experiments/phase1/*/results/` | New raw evidence; all previous reports/results preserved |

## Commands and output contract

```text
sentra init --workspace <directory> --database <file> [--json]
sentra status --database <file> [--workspace <directory>] [--json]
sentra session show <session-id> --database <file> [--workspace <directory>] [--json]
sentra --help
sentra --version
```

`init` requires an explicit workspace. `status` and `session show` default to the invocation directory, with no upward search. A database selection is always explicit; relative paths resolve against the invocation directory and remain subject to Core validation. Storage's existing canonical parent must be outside the workspace, on supported protected local storage. Directories are not automatically created. UNC/device paths, traversal and unsafe aliases remain rejected by the existing boundary/SQLite validators. Paths with Unicode and spaces pass.

`init` creates a metadata-only, Internal-classification, Scoped foundation session, with zero budget, generic `local-operator` label and explicit `local:unversioned-metadata-only` revision label. The existing `CONTINUOUS_REVIEW` mode field is stored as metadata; no review workflow starts. The operator label authenticates no human; the revision is neither a Git commit nor a content hash. No Git/configuration, source, hook, manifest or script contents are inspected. There is no scan command or recursive discovery in this increment.

Repeated `init` returns the existing identity with `created=false`, without registering a new context, advancing generation or creating events. `status` returns initialized metadata or an explicit uninitialized selection. `session show` accepts only the selected project's sole persisted session ID; unknown IDs fail. No create/add/resume/cancel/approve/run session commands are implemented.

Success output goes to stdout. Errors go to stderr with empty stdout. `--json` selects a one-line object with `schema_version=1` for both success and errors. Initialized output includes command, initialized/created booleans, project_id/session_id, state, classification_floor, context_generation, created_at, integer budget_limit_micro_usd/budget_used_micro_usd and `untrusted_execution=false`. Uninitialized output has false initialized/created and null IDs. JSON strings are restricted to trusted command constants and validated domain IDs/enum/timestamp alphabets; arbitrary target strings are never interpolated. Human output exposes the same safe projection. Paths, operator/revision strings, approval material and evidence payloads are omitted.

| Exit | Meaning |
| --- | --- |
| 0 | Help/version or successful initialized inspection/initialization |
| 2 | Invalid/unknown/duplicate/missing arguments or invalid session ID |
| 3 | Status selection is uninitialized; ordinary stdout result, not an infrastructure failure |
| 4 | Invalid workspace/storage location or existing-workspace mismatch |
| 5 | Persistence, lock, integrity, checkpoint or Core service failure |
| 6 | Incomplete/ambiguous local store or orphan recovery files |
| 7 | Requested session does not exist in the selected local context |
| 8 | Process output stream failure |

Errors contain stable payload-free codes such as `invalid_workspace`, `workspace_mismatch`, `incomplete_storage` and `storage_or_service_failure`. Core retains typed ServiceError/PersistenceError sources; a separate typed shutdown error is retained if cleanup also fails. CLI output deliberately uses a coarse infrastructure category rather than printing SQLite diagnostics or converting a failure into Denied/uninitialized. Parse errors never echo supplied arguments. The grammar accepts UTF-8, at most 64 arguments, no abbreviations/equals syntax, duplicate options or implicit environment configuration. Option values starting with `-` require an explicit path prefix such as `./`.

## Initialization and storage lifecycle

1. Establish and retain the canonical workspace boundary and existing storage-parent boundary. Use component containment on filesystem-canonical paths, never string prefixes. Reparse roots/ancestors are rejected. Internal links are not opened or traversed; existing discovery quarantine remains unchanged.
2. Acquire a nonblocking, database-wide OS admission lock at `<database>.local-context.lock`, using the SQLite manager's existing no-follow/ordinary-file/parent-pin strategy. Retain the lease through the complete operation and shutdown. Overlapping cooperating CLI operations serialize or return typed ContextBusy; lock files persist and must not be unlinked while active.
3. Check DB and WAL/SHM/journal presence under admission. A missing DB with any associated recovery file fails closed, preserving all files. Missing storage during status/session never creates a DB.
4. Only a genuinely absent DB takes the existing creation path. Existing files use `open_existing`, which omits SQLite's CREATE flag and rejects version-zero/empty files before mandatory WAL initialization. Unrelated/corrupt/newer/inconsistent schemas remain errors; no overwrite/recreate/archive/restore is attempted.
5. Existing six-table migrations, integrity/FK validation and mandatory FK/WAL/FULL/busy-timeout/autocheckpoint settings apply. The bounded repository query reads at most two IDs and requires exactly one validated current snapshot with bound policy identity. Created-only or ambiguous stores are incomplete. Canonical workspace mismatch denies without replacing identity.
6. Required `wal_checkpoint(TRUNCATE)`/shutdown must succeed before the facade returns success. Reader-blocked checkpoint is runtime-tested and returns Persistence/CheckpointBusy. Errors preserve data for reconciliation; no automatic cleanup of a partial store occurs.

The existing create_session registration and Created-to-Scoped transition are separate atomic database transactions, not an atomic filesystem/bootstrap transaction. Interruption can leave an empty valid schema or Created record; these states remain preserved and are reported incomplete. A committed Scoped record remains initialized even if a later checkpoint/terminal-write failure caused the initiating command to fail. Repeating init never silently repairs or rebinds it.

Inspection is **logically read-only**: sessions, snapshots, approvals, budgets and audits are unchanged. It is not byte-for-byte read-only: OS lock creation, SQLite PRAGMAs, WAL recovery and checkpoints can change storage files. Tests compare all domain rows before/after init repetition, status and session inspection. Existing persistent authorization/session admission remains separate; no CLI operation grants execution, data export or approval authority.

## Verification evidence

Actual host: Windows 11 x64, reported OS build `Microsoft Windows 10.0.26300`; **PowerShell 7.6.9** was observed (7.6.6 was not separately rerun). Rust `1.99.0 (b940084d7 2026-09-28)`, Cargo `1.99.0 (5f94df478 2026-08-27)`, host `x86_64-pc-windows-msvc`, LLVM 23.1.1. Existing cached bundled SQLite and approved dependency graph remain unchanged. No dependency download, toolchain install or host configuration change occurred. `forbid(unsafe_code)` applies to both Sentra-owned crates, not transitive dependencies.

The [baseline output](../../experiments/phase1/cli/results/61-baseline-tests.txt) records 253 runtime + 7 doctests passed, 5 ignored before changes. Final raw records retain commands, stdout/stderr, results and input hashes:

- [CLI/quality/inventory/JSON/Windows junction record](../../experiments/phase1/cli/results/61-1793976246791.json): **18/18 checks Passed**, fixture cleanup Passed, source inputs unchanged.
- [Persistence validator](../../experiments/phase1/persistence/results/1793976346316.json): **13/13 checks Passed**, including explicit MSVC target build, 42 persistence cases and three separate cross-process repetitions; inputs unchanged.
- [Authorization validator](../../experiments/phase1/authorization/results/1793976386599.json): **13/13 checks Passed**, 27 grant cases, 64/32 concurrency rounds, original A-to-B denial/matching-once/replay probe; three approved external dependencies verified; inputs unchanged.
- [Workspace validator](../../experiments/phase1/workspace/results/1793976509800.json): **11/11 checks Passed**, junction/access-denied fixtures and three scale repetitions, fixture cleanup Passed; inputs unchanged.

The new CLI validator obtains the executable from this invocation's Cargo JSON artifacts and checks it lies inside Cargo's resolved target directory; it does not hardcode `target/debug/sentra.exe` or reuse a guessed executable. It parses JSON success/error outputs and checks repeated identity, disabled execution and junction rejection. Existing authorization artifact portability logic is unchanged; only its dependency audit distinguishes the newly approved local edge from the original three external edges.

### Reproduction commands

From the repository root, with cached dependencies and the existing MSVC environment:

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --offline
cargo clippy --workspace --all-targets --all-features --offline -- -D warnings
cargo test --workspace --offline
./experiments/phase1/persistence/Validate.ps1
./experiments/phase1/authorization/Validate.ps1
./experiments/phase1/workspace/Validate.ps1
./experiments/phase1/cli/Validate.ps1
```

Every command above actually ran successfully; the exact first four commands are also recorded inside the CLI validator. The new focused suites can be reproduced with:

```powershell
cargo test --offline --package sentra-core --test local_workspace_tests
cargo test --offline --package sentra-cli
```

### Reconciled inventory

| Harness group | Discovered | Ordinary passed | Ordinary ignored |
| --- | ---: | ---: | ---: |
| Existing Core unit tests | 14 | 14 | 0 |
| Authorization isolation review | 22 | 22 | 0 |
| Authorization | 27 | 27 | 0 |
| Domain / evidence / adversarial execution-evidence / execution | 37 | 37 | 0 |
| Independent Core review | 31 | 30 | 1 helper |
| Persistence | 43 | 42 | 1 helper |
| Policy / security / service / session | 43 | 43 | 0 |
| Workspace | 41 | 38 | 3 platform/scale |
| New local workspace | 19 | 19 | 0 |
| New CLI | 18 | 18 | 0 |
| **Runtime subtotal** | **295** | **290** | **5** |
| Compile-fail doctests | 7 | 7 | 0 |
| **All harness entries** | **302** | **297** | **5** |

The workspace validator separately executes the three ignored junction, access-denied and 10,000-file cases: all pass, yielding **300 unique assertion cases passed, 0 failed, 0 blocked** across the suite/platform runs. The other two ignored entries are owned subprocess helpers launched by their parent tests; they are not standalone untested security cases or additional unique passes. Empty CLI unit/doc harnesses add zero. Overlapping validators and focused suites repeat the same IDs and are not additional unique tests. The persistence validator repeats one cross-process parent case three times; authorization repeats two concurrency cases; workspace repeats the same scale case three times. CLI smoke checks add eight binary invocations (including two Windows junction checks), not new Rust case IDs.

| New validation area | Result and boundary |
| --- | --- |
| Parsing/help/version/errors/exits | Passed: fixed grammar, unknown/missing/duplicate/invalid input, redaction, actual executable |
| Identity and logical inspection | Passed: repeated init/status/session retain ID, generation and all domain rows; unknown session/mismatched root deny |
| Initialization failures | Passed: missing root/parent, internal storage, DB-as-directory, unrelated/empty/corrupt/schema-only/Created/multi-session stores fail without replacement |
| Recovery-file handling | Passed: orphan WAL, SHM and journal preserve bytes and prevent new DB; existing SQLite process/WAL regression suite passes |
| Concurrency/checkpoint | Passed: two synchronized init attempts produce exactly one created session/identity; real reader blocks checkpoint, error surfaces and releasing reader permits success |
| Windows indirection/availability | Passed: symlink root/parent/DB rejection, internal-link nontraversal, junction root/storage rejection, exclusive-share DB denial; existing ACL fixtures restored |
| Offline/no target execution | Passed: no production network/process/provider call path, only approved cached graph, inert canaries unchanged and actual local CLI runs with unusable proxies; not OS packet-capture proof |
| Terminal stdout/stderr write failure | Not Tested: exit-8 path inspected, no deterministic failing-console integration fixture |
| Forced process death during the new CLI bootstrap | Not Tested: unfinished states tested directly; previous real SQLite crash tests reran, but do not prove CLI bootstrap kill behavior |
| New CLI alternate-target-directory matrix | Not Tested: actual-artifact selection inspected; previous authorization portability evidence is historical, default target validated here |
| Opaque reparse tags, hostile alias/race/hardlink scenarios, mapped providers | Not Tested: retained existing limitations; no strong filesystem identity claim |
| Linux/macOS/ARM64, PowerShell 7.6.6, physical disk/IOERR/power loss | Not Tested in this increment; no compatibility/durability claim |

No required local Windows fixture was silently skipped. All required offline commands pass. Optional/environmental scenarios above are not counted as successful runtime tests.

## Security and requirement traceability

- **F-01/F-02, partial:** explicit canonical root and durable foundation identity/budget metadata; no immutable source snapshot, content hash, acquisition, language inventory or complete authorization manifest. No target content authority follows from path validation.
- **F-14, partial:** read-only session inspection; no CLI resume/cancellation/recovery or session mutation. Existing conservative settlement/recovery regressions pass.
- **S-01/S-02/S-06/S-07/S-09/S-14, preserved:** default-deny, exact approval/epoch binding, budget ownership, transaction rollback/audits, classification floors, uncertain holds, redaction and fail-closed workload execution remain behind the existing Core service. No new bypass around execute_task exists; the CLI cannot call it.
- **Q-01/Q-02/Q-04, partial:** Windows-only evidence, explicit incomplete/error states, unchanged schema validation. No release-wide requirement or ADR gate is marked complete.

The external dependency inventory remains the exact pinned rusqlite 0.32.1/bundled, serde 1.0.229/derive and serde_json 1.0.154 graph from 5.4.2; the raw dependency-tree record contains the actual feature graph. Cargo.lock only adds the local CLI package and Core edge. No new package license, crypto algorithm, async runtime, transport or unsafe code is introduced. ADR-0002 and ADR-0007 remain Proposed; licensing/distribution remains an owner gate.

## Limitations and deferred work

Local storage and its lock files must be operator-owned and protected by OS access controls/approved volume security. The application does not authenticate users or defend against an administrator rewriting storage, hardlink aliases or noncooperating hostile filesystem races. Canonical paths/retained handles mitigate static indirection; they are not race-free handle-relative isolation. Project IDs use the existing non-cryptographic SessionId generator; no new cross-store uniqueness or authenticity guarantee is claimed.

The CLI deliberately requires explicit external storage, supports one foundation session, and rejects malformed/incomplete selection rather than guessing or migrating project identity. It neither follows internal links nor inventories/quarantines the whole repository during init. No arbitrary source/metadata content is opened. Future content reads, exports, project registry/multi-session lifecycle and repair need their own approved design and tests.

No scanner, real AI/provider, credentials, telemetry, network/remote/Git operation, target execution, host/Docker/WSL2 fallback, VM provisioning/cancellation, streaming evidence, new cryptography, MCP/dashboard or Phase 2 functionality is implemented. Strong filesystem identity, exactly-once external effects/crash reconciliation, full SQLite fault/durability/blob integration and unvalidated platforms remain open.

## Git safety and completion

Entry: clean `develop`, HEAD `822faad9e8521435d7107387ba6af89f8f462f70`, tracking locally recorded `origin/develop` at ahead/behind 0/0; 257 tracked files, zero staged/modified/untracked. Initial physical index SHA-256: `f4584740eb6a77b3f5312bb9321faac362863aacd863c1d9a69899ff795440a2`.

Final state: **16 modified, 15 untracked, 0 staged**, on the same `develop` HEAD and local upstream relationship (0 ahead / 0 behind). Exact paths and comparisons are recorded in the [Git preservation record](../../experiments/phase1/cli/results/61-git-state.json); documentation checks are in the [documentation record](../../experiments/phase1/cli/results/61-documentation.json). HEAD, branch, all reference targets, history, index entries and physical index bytes match entry. All changes remain in the working tree, unstaged. No agent Git mutation, fetch/pull/push, dependency download, external data transfer, untrusted target code/build script execution or host-wide security change occurred. Existing Windows validator ACL operations were limited to owned disposable fixtures and restored during cleanup. Historical reports/raw evidence were preserved.

Increment 6.1 is complete within this documented local foundation scope. **Stop at 6.1; Phase 1 is not complete and Increment 6.2/Phase 2 are not started.**
