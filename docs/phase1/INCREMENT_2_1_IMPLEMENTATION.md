# Increment 2.1 — Input Manifests and Source Content Hashing

Date: 2026-11-08. Status: **Implemented and empirically verified via Docker container & Windows host**, ready for owner review. Phase 1 is incomplete. Phase 2 has not started and remains unauthorized. Untrusted target execution remains fail-closed. Permanent Git policy preserved.

---

## 1. Executive Summary

Continuing the product-focused Phase 1 roadmap ([DEVELOPMENT_DIRECTION_REVIEW.md](../../DEVELOPMENT_DIRECTION_REVIEW.md), [ROADMAP.md](../../ROADMAP.md)), Increment 2.1 implements **Input Manifests and Source Content Hashing** (`REQ-F01/F02`, `DG-4`, `OQ-24`).

This increment establishes:

1. **Audited Cryptographic Hashing Primitive**: Integrated the pure-Rust `sha2` crate (v0.11.1, `default-features = false, features = ["alloc"]`), guaranteeing `#![forbid(unsafe_code)]` compliance across the entire `sentra-core` crate. Verified against official NIST FIPS 180-4 test vectors for both empty, short, and multi-block payloads.
2. **Deterministic Source Snapshot Capture**: Implemented recursive workspace inspection (`capture_source_snapshot`) that freezes authorized source trees into immutable snapshots (`SourceSnapshot`). Features canonical forward-slash path normalization across platforms, automatic source file role classification (`CargoManifest`, `RustSource`, `Documentation`, `Configuration`, etc.), explicit exclusion of internal directories (`.git`, `target`, `.sentra`), strict quarantine of symlinks and Windows reparse points, and deterministic lexicographical sorting by path for stable aggregate content hashing.
3. **Fail-Closed Snapshot Quotas**: Implemented configurable resource limits (`SnapshotLimits`) enforcing strict ceilings on individual file sizes (`max_file_size_bytes`), cumulative workspace bytes (`max_total_bytes`), file counts (`max_files`), and directory nesting depths (`max_depth`). Any violation triggers an immediate, typed fail-closed rejection (`ManifestError`).
4. **Operation Manifest Data Model**: Defined canonical operation manifests (`OperationManifest`), immutably binding a session, task, operation action name, action argument digest, session classification floor, creation timestamp, and optional source snapshot digest.
5. **Core Service & SQLite Persistence Integration**: Integrated snapshot capture (`CoreService::capture_source_snapshot`) and manifest generation (`CoreService::create_operation_manifest`) into the Core Engine pipeline, persisting records into SQLite Schema V2's `manifests` table with indexed content digests and validated compact canonical JSON payloads.
6. **Empirical Verification**: Implemented comprehensive integration test suite (`tests/manifest_tests.rs`). All 14 tests pass on Windows 11 host; all 10 independent suites (140 tests) pass inside the Docker Linux container runner with zero warnings under `cargo clippy --workspace --all-targets --all-features -- -D warnings` and zero formatting errors under `cargo fmt --all -- --check`.

---

## 2. Scope and Invariants

### Preserved Boundaries
- **Phase Boundary**: Phase 1 technical validation only; Phase 2 remains **STRICTLY UNAUTHORIZED**.
- **Execution Boundary**: Untrusted target execution remains **100% fail-closed** via `FailClosedBackend`. No target code is compiled or executed.
- **Permanent Git Policy**: Zero agent commits, pushes, fetches, merges, rebases, cherry-picks, or staging. All changes remain unstaged in the working tree.
- **Platform Integrity**: Preserves Windows 11 host with PowerShell 7 as the primary development platform, while providing Linux Docker validation for platform-independent suites.
- **Unsafe Code Ban**: `#![forbid(unsafe_code)]` strictly preserved; no `unsafe` blocks exist in `sentra-core`.

### Architectural References
- [ROADMAP.md](../../ROADMAP.md): Phase 1 Acceptance Invariant: *"Capture and freeze input manifest with source content hashing before execution"*.
- [DEVELOPMENT_DIRECTION_REVIEW.md](../../DEVELOPMENT_DIRECTION_REVIEW.md): Refocused priorities on durable dispatch, manifest capture, and verification contracts.
- [REMEDIATION_ARCHITECTURE.md](REMEDIATION_ARCHITECTURE.md): Manifest table schema and context generation fencing integration.
- [OPEN_QUESTIONS.md](../OPEN_QUESTIONS.md): OQ-24 (Source capture determinism and path normalization).

---

## 3. Cryptographic Hashing Implementation

Located in [`crates/sentra-core/src/common/crypto.rs`](../../crates/sentra-core/src/common/crypto.rs).

### 3.1 Crate Selection & Auditing
- Crate: `sha2` version `0.11.1` (`default-features = false, features = ["alloc"]`).
- Pure Rust implementation from the `RustCrypto` organization.
- Adheres strictly to `#![forbid(unsafe_code)]`.
- Zero external native dependencies; operates identically on Windows MSVC and Linux ELF.

### 3.2 Hashing Primitives
- `sha256_digest(data: &[u8]) -> String`: Returns 64-character lowercase hex digest.
- `sha256_prefixed(data: &[u8]) -> String`: Returns `sha256:<64-char-hex>` prefixed string, matching Sentra canonical format.
- `sha256_bytes(data: &[u8]) -> [u8; 32]`: Returns raw 32-byte hash array.
- `Sha256Stream`: Streaming hasher supporting incremental `update(&[u8])` and `finalize()`.

### 3.3 NIST FIPS 180-4 Verification
Verified against standard vectors:
- Empty string `""` $\rightarrow$ `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- String `"abc"` $\rightarrow$ `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`.
- Multi-block 448-bit input $\rightarrow$ `248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1`.

---

## 4. Source Snapshot and Capture Architecture

Located in [`crates/sentra-core/src/manifest/`](../../crates/sentra-core/src/manifest/).

### 4.1 Data Models
- **`SourceSnapshot`**:
  - `version: u32`: Schema version (`1`).
  - `session_id: String`: Associated session UUID.
  - `root_label: String`: Canonical workspace root display label.
  - `entries: Vec<SourceSnapshotEntry>`: Lexicographically sorted list of file entries.
  - `total_files: usize`: Total included files count.
  - `total_bytes: u64`: Cumulative file bytes.
  - `aggregate_digest: String`: SHA-256 digest computed over the canonical framed entry stream.
  - `created_at: String`: RFC 3339 UTC timestamp.
- **`SourceSnapshotEntry`**:
  - `path: String`: Canonical forward-slash normalized relative path (e.g. `src/lib.rs`).
  - `size_bytes: u64`: Exact file length.
  - `content_sha256: String`: Lowercase hex SHA-256 content digest.
  - `role: SourceFileRole`: Detected file role (`CargoManifest`, `CargoLock`, `RustSource`, `Documentation`, `Configuration`, `BuildScript`, `TestData`, `Other`).
- **`SnapshotLimits`**:
  - `max_file_size_bytes: u64`: Default 10 MiB.
  - `max_total_bytes: u64`: Default 100 MiB.
  - `max_files: usize`: Default 10,000 files.
  - `max_depth: usize`: Default 32 directory levels.

### 4.2 Containment & Traversal Rules
1. **Workspace Boundary**: Traversal begins strictly at the canonical workspace root validated by `WorkspaceBoundary`.
2. **Reparse Point & Symlink Quarantine**:
   - Symlinks (`is_symlink() == true`) are quarantined and skipped.
   - On Windows, entries with `FILE_ATTRIBUTE_REPARSE_POINT` (0x0400) (junctions, volume mounts) are quarantined and skipped.
3. **Repository Directory Exclusion**: `.git`, `target`, and `.sentra` directories are excluded from snapshot contents to prevent metadata leakage or non-deterministic build artifact ingestion.
4. **Path Normalization**: All relative paths are normalized using `/` forward slashes, ensuring identical aggregate hashes across Windows and Unix platforms.
5. **Aggregate Digest Framing**:
   Entries are sorted by `path` ascending. The aggregate digest is computed by streaming each entry formatted as:
   `ENTRY:{path}:{size_bytes}:{content_sha256}\n`
   into a SHA-256 hasher, prefixed with `sha256:`.

---

## 5. Operation Manifest Architecture

Located in [`crates/sentra-core/src/manifest/model.rs`](../../crates/sentra-core/src/manifest/model.rs).

- **`OperationManifest`**:
  - `version: u32`: Schema version (`1`).
  - `session_id: String`: Session identifier.
  - `task_id: String`: Task identifier.
  - `action_name: String`: High-level action name (e.g. `DISCOVER_METADATA`).
  - `action_digest: String`: Action argument digest.
  - `source_snapshot_digest: Option<String>`: Content digest of the input source snapshot (if bound).
  - `classification: String`: Security classification floor.
  - `created_at: String`: RFC 3339 UTC timestamp.
- Computes its own deterministic content digest via `compute_content_digest()`.

---

## 6. Core Engine and Persistence Integration

### 6.1 Service Methods
Located in [`crates/sentra-core/src/service/core.rs`](../../crates/sentra-core/src/service/core.rs):
- **`CoreService::capture_source_snapshot(session_id, limits)`**:
  1. Validates that the session is non-terminal.
  2. Acquires session admission.
  3. Re-validates `WorkspaceBoundary` against `session.metadata.workspace_root`.
  4. Executes `capture_source_snapshot`.
  5. Serializes to canonical JSON.
  6. Inserts `ManifestRecord` into SQLite `manifests` table (`ManifestKind::SourceSnapshot`).
  7. Returns `(ManifestRecord, SourceSnapshot)`.
- **`CoreService::create_operation_manifest(session_id, task_id, action, source_digest)`**:
  1. Validates that the session is non-terminal.
  2. Constructs `OperationManifest`.
  3. Computes content digest and serializes canonical JSON.
  4. Inserts `ManifestRecord` into SQLite `manifests` table (`ManifestKind::Operation`).
  5. Returns `ManifestRecord`.

---

## 7. Empirical Verification Summary

### 7.1 Test Matrix
| Environment | Test Target | Command | Result |
| :--- | :--- | :--- | :--- |
| **Windows 11 Host** | Unit & Integration | `cargo test --package sentra-core --test manifest_tests` | **14 / 14 passed** (0.07s) |
| **Linux Container** | Integration | `pwsh scripts/docker-test.ps1 -Mode test -Package sentra-core -TestName manifest_tests` | **4 / 4 passed** (0.00s) |
| **Linux Container** | All 10 Independent Suites | `pwsh scripts/docker-test.ps1 -Mode all` | **140 passed** (5.95s) |
| **Linux Container** | Linter | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **0 warnings** |
| **Linux Container** | Formatter | `cargo fmt --all -- --check` | **Clean** |

### 7.2 Integration Tests Detail (`tests/manifest_tests.rs`)
1. `test_sha256_nist_vectors`: NIST test vectors validation.
2. `test_source_snapshot_canonical_json_roundtrip`: Canonical JSON serialization fidelity.
3. `test_operation_manifest_canonical_json_roundtrip`: Operation manifest serialization fidelity.
4. `test_workspace_boundary_fails_closed_on_unsupported_platform`: Linux fail-closed validation.
5. `test_capture_source_snapshot_determinism`: Stable aggregate hash across multiple runs on identical tree.
6. `test_source_snapshot_sensitivity_to_content_change`: 1-byte mutation in source file changes aggregate hash and file hash.
7. `test_source_snapshot_sensitivity_to_file_addition_and_deletion`: File addition changes hash; deletion restores initial hash.
8. `test_source_snapshot_role_detection`: Accurate detection of Cargo manifests, locks, source, and config.
9. `test_path_normalization_uses_forward_slashes_consistently`: Forward-slash verification across all entries.
10. `test_git_directory_excluded_from_snapshot`: Strict `.git` directory exclusion.
11. `test_source_snapshot_file_size_limit_fails_closed`: `FileTooLarge` fail-closed error.
12. `test_source_snapshot_total_bytes_limit_fails_closed`: `TotalBytesExceeded` fail-closed error.
13. `test_source_snapshot_file_count_limit_fails_closed`: `FileCountExceeded` fail-closed error.
14. `test_core_service_capture_and_persist_source_snapshot`: End-to-end `CoreService` capture and SQLite retrieval.
15. `test_operation_manifest_creation_and_persistence`: End-to-end operation manifest creation and SQLite retrieval.
