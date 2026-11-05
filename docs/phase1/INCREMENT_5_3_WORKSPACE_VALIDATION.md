# Workspace Boundary, Quarantine and Discovery — Increment 5.3

Date: 2026-11-05. **Workspace implementation and filesystem validation are ready for review.** The Windows x64 filesystem suite passes; a separate probe exposes a preexisting approval-context defect. Overall authorization integration is **Blocked** until that defect is corrected. Phase 1 is incomplete. Increment 5.4 and Phase 2 have not started.

## Scope and implementation

The implementation follows the [Core Engine design](CORE_ENGINE_DESIGN.md), [Milestone 4 conditions](MILESTONE_4_REVIEW.md), existing domain types and the prior [5.2.1 review](INCREMENT_5_2_1_SECURITY_REVIEW.md). Earlier reports were checked against actual source. No accepted ADR, session state machine or policy implementation was changed.

| File | Responsibility |
| --- | --- |
| [workspace/mod.rs](../../crates/sentra-core/src/workspace/mod.rs) | Public metadata-only boundary exports and authorization disclaimer |
| [boundary.rs](../../crates/sentra-core/src/workspace/boundary.rs) | WorkspaceRoot, WorkspaceBoundary, retained ResolvedWorkspacePath, canonical component checks and revalidation |
| [platform.rs](../../crates/sentra-core/src/workspace/platform.rs) | Safe Windows metadata opens, syntax/attribute checks, retained ancestors and before/after observations |
| [model.rs](../../crates/sentra-core/src/workspace/model.rs) | Classified inventory, quarantine, resource budgets and explicit incomplete results |
| [error.rs](../../crates/sentra-core/src/workspace/error.rs) | Typed failures with redacted Display/Debug and separately accessible relative context |
| [discovery.rs](../../crates/sentra-core/src/workspace/discovery.rs) | Bounded directory enumeration, opaque Git metadata, name-only Cargo detection and subtree retraction |
| [lib.rs](../../crates/sentra-core/src/lib.rs) | Exposes the workspace module; preserves existing exports and unsafe prohibition |
| [workspace_tests.rs](../../crates/sentra-core/tests/workspace_tests.rs) | Maintainer-controlled Windows fixtures and explicit environment/scale tests |
| [Validate.ps1](../../experiments/phase1/workspace/Validate.ps1) | Offline checks, disposable junction/ACL fixtures, benchmark measurements, source digests and cleanup |

The workspace retains the existing SessionId and SecurityClassification. No new identifier generator, persistence layer, provider, subprocess dispatcher or CLI was introduced. Cargo manifests and lockfile are unchanged; there are zero third-party dependencies. Edition 2024 and `#![forbid(unsafe_code)]` are preserved.

## Boundary invariants and path validation

WorkspaceRoot has one private canonical path and an Arc-owned state containing retained metadata handles for the root and its ancestors. ResolvedWorkspacePath has a private constructor and retains its component handles. An observation from another independently established boundary is rejected even when canonical path and session strings match. Cloning the established boundary preserves its instance identity. This is a lifetime-scoped in-process observation, not a durable filesystem object ID or authorization token.

Root establishment validates syntax and inspects each component without following its final entry before canonicalization. It rejects a non-directory root and indirection in any root ancestor. Relative inputs are interpreted against that established root, never against a changed process working directory. Absolute inputs must use its drive and resolve their root prefix to the same OS-canonical root. Final containment uses Path::strip_prefix components; no string-prefix containment or home-grown lowercasing is used. Windows canonicalization decides ordinary case aliases, including the tested Unicode/case fixture.

The parser rejects every parent component, even `dir/../dir/file`; NUL/control/wildcard characters; invalid encoding; ADS colons; reserved DOS device names, including extension and superscript variants; trailing dot/space aliases; empty input; excessive path length/components; drive-relative and root-relative forms; UNC/device namespaces and unsupported prefixes. Dot components and repeated separators in ordinary paths are accepted subject to actual filesystem checks. Missing/inaccessible entries return typed errors rather than valid future paths.

UNC is rejected before any filesystem lookup. Different drives are rejected before lookup. This is deliberate local-only support, not validated UNC functionality. Validation of an absolute root prefix may inspect its ancestors to establish equivalence; no source bytes from an outside candidate are read. Mapped network drives and arbitrary filesystem providers are not established safe by local-drive syntax alone: callers must select a known local volume. This run used a Fixed NTFS E: volume, confirmed with `[IO.DriveInfo]::new('E:/')`.

Ordinary errors expose operation, category and numeric OS code, with no OS error text or absolute filename. Debug for roots and resolved observations is redacted. Relative metadata records remain sensitive untrusted data; the API performs no logging or export. An explicitly requested canonical-root accessor is a diagnostic view, not a capability grant.

## Windows reparse detection and quarantine

The implementation checks MetadataExt::file_attributes and gives FILE_ATTRIBUTE_REPARSE_POINT precedence over regular file/directory classification. It does not rely on Path::is_symlink. Attribute-only OpenOptionsExt opens use FILE_READ_ATTRIBUTES, FILE_FLAG_OPEN_REPARSE_POINT and FILE_FLAG_BACKUP_SEMANTICS, retaining ancestors while the next component is inspected. Device, unknown, offline and recall-related attribute combinations are unsupported.

The installed Rust 1.99 rustdoc confirms that file_index, volume_serial_number and number_of_links remain nightly-only windows_by_handle APIs; stable metadata does not expose the reparse tag. No nightly feature, unsafe FFI or external crate is enabled. See the versioned [MetadataExt reference](https://doc.rust-lang.org/1.99.0/std/os/windows/fs/trait.MetadataExt.html) and [OpenOptionsExt reference](https://doc.rust-lang.org/1.99.0/std/os/windows/fs/trait.OpenOptionsExt.html), inspected through the installed documentation without a network request.

Consequently Windows symbolic links, junctions, mount points and other tagged indirections are reported as **ReparsePoint**, with Indirection quarantine. Exact junction-versus-symlink tag labeling is not implemented; the conservative unsupported classification is intentional. The SymbolicLink enum variant does not assert that this Windows implementation distinguishes tags. No indirection is accepted because its target would be internal, and no read_link/canonicalization of a quarantined target is attempted. Internal and external junction fixtures both pass.

Quarantine is logical exclusion, not moving or deleting repository entries. Quarantined records are not ResolvedWorkspacePath values and have no conversion to retained handles. Resolving a still-present indirection independently remains rejected. Inventory limits and failed inspection also produce explicit exclusions/incompleteness. Quarantine does not establish a permanent name blacklist or make a future replacement at the same name trusted without fresh resolution.

## Metadata-only discovery and limits

Discovery inspects names, relative paths, ordinary types, file lengths, optional modification times and directory structure. Cargo.toml/Cargo.lock are recognized by name only. Any ASCII case spelling of `.git` is an opaque metadata file/directory: its children, pointer contents, configuration, hooks and credentials are never read. Git is never invoked. Invalid manifest bytes are valid inert name-only fixtures.

**No target file content is read.** max_metadata_content_bytes must be zero; any request to enable content reads is rejected. No shell, Git, package manager, compiler, plugin, import, hook or target build/test is invoked by this module. The separate validation runner launches only the reviewed project toolchain and synthetic test executables.

| Budget | Default | Valid range / semantics |
| --- | --- | --- |
| max_entries | 10,000 | 1–100,000 metadata admission attempts, including failed entries |
| max_depth | 32 | 0–128; root depth zero, zero permits only an empty-root complete result |
| max_file_bytes | 100 MiB | 1–1 TiB ordinary file length; larger entries are quarantined |
| max_total_file_bytes | 100 MiB | 1–1 TiB aggregate retained file lengths; not bytes read |
| max_inventory_bytes | 16 MiB | 1–128 MiB encoded-name budget, including pending ancestor directory buffers |
| max_metadata_content_bytes | 0 | Only zero supported |
| Path representation | 32,768 encoded bytes / 128 components | Hard pre-I/O bounds for each caller input |

Directory buffers and final inventories are bounded. At most one extra directory entry is enumerated to detect entry-count overflow, without resolving it. Counts apply globally across nested directories. Names are sorted within bounded buffers and the final result; an incomplete/mutating directory does not promise a deterministic selected subset. Repeated errors do not create unbounded diagnostics. Name budget consumed by failed/retracted observations is conservatively not refunded.

DiscoveryResult carries inspected_entries, total_file_bytes, inventory_bytes, entries, quarantine and unique incomplete reasons. Entry/depth/total-byte/name-budget exhaustion and inspection failure cannot appear complete. A directory observation that changes retracts its usable subtree; tests distinguish a `dir` component from `directory`. `is_complete` concerns only this metadata inventory, never absence of vulnerabilities or permission to use content. Blocking OS filesystem calls do not have a hard cancellation deadline in this synchronous std-only increment.

## Filesystem races and authority limits

Before/opened-handle/after metadata observations are compared, and retained handles are rechecked after canonicalization. Root ancestors are retained, and directory inventory observations include modification timestamps. Directory child changes are not mistaken for ancestor replacement solely because an unrelated ancestor's modification time changed. A deterministic check/open replacement by a symlink is rejected; existing writer changes and later attribute/directory changes invalidate retained observations. Ordinary rename attempts on retained roots/directories failed in this NTFS fixture.

**These are not race-free filesystem isolation or immutable snapshot guarantees.** Attribute-only handles did not exclude writers on the tested Windows host. Stable std lacks the chosen strong handle-relative open/enumeration and file-ID facilities. Before/after timestamps are observations, not collision-proof identity; ABA, timestamp-preserving replacement, provider behavior and hard-link aliasing are unresolved. Canonicalize/read_dir still operate on paths. A hostile mutation between system calls cannot be proven absent by these tests.

ResolvedWorkspacePath therefore exposes only an untrusted relative name and revalidated metadata, with no absolute-path conversion, AsRef<Path>, File accessor or content-open/read/write/execute method. It must not be reused as permission for later source reads, exports, modifications or execution. Strong object/containment identity must be established at that operation, or the operation must remain unavailable. Boundary establishment/discovery do not call or mutate the policy engine, issue grants, advance sessions, or authorize Restricted data processing. The caller remains responsible for a separate policy decision before metadata processing; the unified service that enforces that sequence is not implemented here.

## Executed checks and reproducibility

From the repository root:

```powershell
pwsh -NoProfile -File experiments/phase1/workspace/Validate.ps1
```

The [final raw record](../../experiments/phase1/workspace/results/1793902387953.json) contains exact command arrays, stdout/stderr, exits, individual outcomes, 35 source/manifest/runner hashes, unchanged-input verification, hardware and fixture cleanup. It records **76 unique tests Passed, 0 Failed, 0 Not Tested** across the workspace and explicit fixture/scale runs. The four deferred validation categories below are separate from that executable-test count. No Windows security scenario in the implemented suite was silently skipped.

| Executed group | Status | Result |
| --- | --- | --- |
| cargo fmt --all -- --check | Passed | No formatting changes required |
| cargo check --offline --workspace | Passed | Windows x64 compilation |
| cargo clippy --offline --workspace --all-targets --all-features -- -D warnings | Passed | Zero warnings |
| cargo test --offline --workspace | Passed | 73 passed; three explicitly ignored environment/scale cases executed separately below |
| Explicit ignored Windows fixture tests | Passed | 2 passed: internal/external junctions and actual permission-denied file/directory |
| Explicit ignored scale test | Passed | 1 unique case executed three times; no ignored cases in each invocation |
| Owned fixture preparation and cleanup | Passed | Junctions and temporary deny ACLs without elevation; original ACLs restored and exact owned tree removed |

The 76 tests comprise 33 preexisting domain/session/policy tests, three new workspace unit tests and 40 new Windows integration cases. Coverage includes roots, absolute/relative/Unicode/spaced/case paths, traversal/ADS/devices/UNC, missing paths, boundary-instance binding, metadata mutations, retained rename observations, all required symlink patterns, opaque Git metadata, limits, inert executable/script canaries, classification preservation and 10,000 files. No target code or target build scripts were executed. This is source/API review plus synthetic canary evidence; no ETW/process monitor or OS-enforced egress audit was performed.

Documentation checks Passed for 40 Markdown files, 275 local file/fragment links, 80 tables, all 41 requirement mappings and seven ADR status records. Eight preexisting trailing-whitespace warnings remain in the unchanged Core Engine design document; they were not silently rewritten as part of this increment. PowerShell parsing, standalone probe rustfmt and Git diff whitespace checks pass. The final record's 35 input hashes match current sources; unrelated original files and all ADR hashes match the entry snapshot. Static source inspection found no subprocess creation, network client, content-read or read_link API in the workspace module. The separate Failed policy probe remains a security finding, not a passing quality check.

Benchmark host: Windows 11 x64, reported build 10.0.26300; PowerShell 7.6.9; Rust/Cargo 1.99.0 and x86_64-pc-windows-msvc; Intel Core i7-11800H; 34,091,286,528 bytes physical RAM; Fixed NTFS E: storage. ARM64, Linux and macOS were not tested. The fixture contains 10,000 text files / 310,000 bytes, two directories, Unicode/spaced names and depths 1–3. max_entries is explicitly 10,002 because directories also consume entry budget.

| Run | Discovery time | Observed test-process peak working set | Status |
| --- | --- | --- | --- |
| 1 | 9,470 ms | 7,565,312 bytes | Passed |
| 2 | 9,574 ms | 7,532,544 bytes | Passed |
| 3 | 9,519 ms | 7,557,120 bytes | Passed |

This meets the 30-second / 512-MiB engineering target on the declared small-text fixture. Timing excludes fixture creation, cleanup, compilation, Git acquisition and models. Memory samples the actual standalone reviewed test process's PeakWorkingSet64 while alive every 25 ms, including setup/discovery/cleanup; it is not Cargo memory or an OS memory quota. The last interval before exit is not an atomic exit-time measurement. No full 100-MiB corpus or other-machine performance claim follows.

The [first raw run](../../experiments/phase1/workspace/results/1793901859226.json) is preserved as Failed: the narrower deny-ACL fixture still permitted metadata access, and benchmark assertions used an incorrect expected byte count and lacked a live memory sample. Actual timing tests exited successfully, but those failed quality checks were not labeled Passed. The [intermediate flat-fixture run](../../experiments/phase1/workspace/results/1793902182023.json) is superseded; the final record adds varied depth/Unicode, corrected case accounting and final source hashes. Earlier writer-exclusion assumptions were removed after real tests contradicted them.

## Separate preexisting approval-context finding

**Failed — S-02 current-operation binding.** Source review found that PolicyEngine::evaluate forwards a grant to ApprovalBroker::verify_and_consume without comparing it to the current action/session/revision. The broker compares the grant to its stored old request, which does not establish permission for the currently evaluated action.

The [synthetic policy probe](../../experiments/phase1/workspace/PolicyContextProbe.rs) creates a Restricted metadata request A, constructs its fixture grant, then evaluates different Restricted metadata action B with that grant. The [raw probe result](../../experiments/phase1/workspace/results/policy-context.json) records exit 1 and `POLICY_CONTEXT_BINDING=Failed: grant for metadata A accepted for metadata B`. No filesystem content, execution, network request or real approval was involved. This probe is deliberately separate from the 76 passing tests; its failure is not waived into the workspace pass count.

Reproduce after the offline build by locating the current `libsentra_core-*.rlib` under target/debug/deps, then:

```powershell
rustc --edition=2024 --crate-name policy_context_probe experiments/phase1/workspace/PolicyContextProbe.rs --extern "sentra_core=<current rlib path>" -L dependency=target/debug/deps -o target/workspace-policy-context-probe.exe
./target/workspace-policy-context-probe.exe
```

The policy files match the increment-entry hashes and were not changed here. Before composed authorization, a focused correction must bind and atomically consume the grant against the current operation context and add mismatch/non-consumption regressions. No earlier review is treated as proof that this integration gate passes. This blocks declaring the combined Core authorization boundary secure; no automatic progression to Increment 5.4 is implied.

## Deferred validation and disposition

| Item | Status | Gate / safe default |
| --- | --- | --- |
| Opaque real reparse tags beyond tested links/junctions | Not Tested | Attribute classifier test passes; all reparse flags remain quarantined without tag promises |
| Strong handle-relative containment, file IDs, adversarial ABA and hard-link aliasing | Not Tested | No content-access capability; separate safe-API/dependency review before such operations |
| Mapped drives, case-sensitive NTFS directories and arbitrary filesystem providers | Not Tested | Known-local volume precondition; no general filesystem/network-isolation claim |
| Linux, macOS and ARM64 | Not Tested | No support claim; runtime metadata strategy is Windows-only |
| Combined current-context approval enforcement | Blocked | Separate probe Failed; existing policy must be corrected before unified dispatch |

The metadata-only implementation is ready for review within these limits. Full V-04/F-01/S-11, immutable snapshots, language discovery, safe content acquisition and composed policy enforcement are not all complete. SQLite production integration, all existing SQLite failure-mode gaps, real providers, VM containment, license selection and Proposed ADR-0002/0007 remain unchanged. No Increment 5.4, execution backend implementation, CLI or Phase 2 work started.

## Repository preservation

Entry was develop at c849a8a7ea71c2bda2b86fd3d5be4f9e3fcd645a with 13 intentional 5.2.1 modified/untracked files. Their contents were preserved. During this increment, external commit 4267b42f2a2d37e7c579523929b5bfd178e8de0e recorded those existing hardening changes; its parent is c849a8a. It was inspected and preserved. Author metadata does not identify the process that performed it.

The agent issued no commit/amend/reset/rebase/cherry-pick/tag/push/fetch/pull/stage/stash/revert operation and changed no Git references or history. Overall entry HEAD/index/reference targets did move externally, so they are not falsely described as unchanged since entry. Final preservation checks compare against the observed external-commit snapshot. Existing user changes, all seven ADRs and unrelated source remain intact; new edits are left in the working tree.

Current-status synchronization updates PROGRESS.md, the root README/ROADMAP/ARCHITECTURE, documentation index, Phase 1 execution record, validation traceability and open questions. These edits distinguish the implemented metadata subset, unresolved strong containment and the preexisting approval defect; they do not alter accepted architecture decisions. New implementation, fixtures, runners and evidence remain confined to the workspace module/tests, this report and the workspace experiment directory.
