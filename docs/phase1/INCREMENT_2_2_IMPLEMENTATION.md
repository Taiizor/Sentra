# Increment 2.2 — Bounded Evidence Storage and Content Addressing (CAS)

Date: 2026-11-08. Status: **Implemented and empirically verified via Docker container & Windows host**, ready for owner review. Phase 1 is incomplete. Phase 2 has not started and remains unauthorized. Untrusted target execution remains fail-closed. Permanent Git policy preserved.

---

## 1. Executive Summary

Continuing the product-focused Phase 1 roadmap ([DEVELOPMENT_DIRECTION_REVIEW.md](../../DEVELOPMENT_DIRECTION_REVIEW.md), [ROADMAP.md](../../ROADMAP.md)), Increment 2.2 implements **Bounded Evidence Storage and Content Addressing** (`S-09`, `RM-3`, `DG-3`).

This increment establishes:

1. **`BlobStore` Abstraction & Interface Contract**: Defined the canonical trait ([`traits.rs`](../../crates/sentra-core/src/storage/traits.rs)) specifying atomic content-addressed blob operations (`put`, `put_evidence_envelope`, `get`, `open_reader`, `exists`, `metadata`, `usage`).
2. **Cryptographic Content Addressing (`BlobId`)**: Implemented strongly-typed content identifiers ([`model.rs`](../../crates/sentra-core/src/storage/model.rs)) derived from pure-Rust SHA-256 digests (`sha256:<64-char-hex>`), supporting parsing, validation, serialization, and sub-digest addressing.
3. **Cooperative CAS Publication Lifecycle**: Implemented `FileSystemCasBlobStore` ([`cas.rs`](../../crates/sentra-core/src/storage/cas.rs)) executing the zero-window lifecycle validated in Increment 1.4:
   - Private staging in `<root>/staging/` under unique process/nanosecond identifiers.
   - Synchronous write and cache flush via `sync_all()`.
   - In-handle cryptographic SHA-256 verification before publication.
   - Atomic namespace insertion into `<root>/blobs/<digest>.blob` via `std::fs::hard_link`.
   - Concurrent race de-duplication: Win32 Error 183 / `ErrorKind::AlreadyExists` triggers length validation and succeeds idempotently.
   - Clean staging link unlinking and cooperative read-only attribute application (`set_readonly(true)`).
4. **Storage Quotas and Resource Bounds**: Implemented `StorageLimits` enforcing configurable ceilings on individual blob sizes (`max_blob_size_bytes`, default 50 MiB matching `MAX_EVIDENCE_SIZE_BYTES`), cumulative storage consumption (`max_total_storage_bytes`, default 1 GiB), and blob counts (`max_blob_count`, default 10,000). Violations trigger immediate typed fail-closed errors (`BlobTooLarge`, `TotalStorageExceeded`, `BlobCountExceeded`).
5. **Evidence Envelope Integration**: Integrated `EvidenceEnvelope` persistence with transit digest validation (`declared_sha256` matching computed hash) and structural metadata validation.
6. **Core Engine Service Attachment**: Integrated `BlobStore` into `CoreService` via `with_blob_store`, `store_evidence`, and `get_evidence`, linking evidence verification with persistent storage.
7. **Empirical Verification**: Implemented comprehensive integration test suite ([`tests/storage_tests.rs`](../../crates/sentra-core/tests/storage_tests.rs)). All 14 tests pass on Windows 11 host; all 11 independent suites (154 tests) pass inside the Docker Linux container runner with zero warnings under `cargo clippy --workspace --all-targets --all-features -- -D warnings` and zero formatting errors under `cargo fmt --all -- --check`.

---

## 2. Scope and Invariants

### Preserved Boundaries
- **Phase Boundary**: Phase 1 technical validation only; Phase 2 remains **STRICTLY UNAUTHORIZED**.
- **Execution Boundary**: Untrusted target execution remains **100% fail-closed** via `FailClosedBackend`. No target code is compiled or executed.
- **Permanent Git Policy**: Zero agent commits, pushes, fetches, merges, rebases, cherry-picks, or staging. All changes remain unstaged in the working tree.
- **Threat Model Scope**: As formalized in [FILESYSTEM_CAPABILITY_CONTRACT.md](FILESYSTEM_CAPABILITY_CONTRACT.md), cooperative immutability (`set_readonly`) protects against accidental self-modification by Sentra and cooperative concurrency. Hostile same-user tampering without service boundaries remains documented as unsupported on Windows NTFS.
- **Unsafe Code Prohibition**: `#![forbid(unsafe_code)]` strictly preserved; no `unsafe` blocks exist in `sentra-core`.

### Architectural References
- [ROADMAP.md](../../ROADMAP.md): Phase 1 Acceptance Invariant: *"Persist and resume a session; interrupt at task dispatch, blob promotion, and result commit; show no lost committed events and no repeated sensitive side effects."*
- [REMEDIATION_ARCHITECTURE.md](REMEDIATION_ARCHITECTURE.md): B1–B8 blob lifecycle, content-addressed storage (S-09), and evidence envelope persistence.
- [FILESYSTEM_CAPABILITY_CONTRACT.md](FILESYSTEM_CAPABILITY_CONTRACT.md): Staging, atomic hard-link publication, Error 183 de-duplication, and read-only attribute sequencing.

---

## 3. Storage Architecture and Data Models

Located in [`crates/sentra-core/src/storage/`](../../crates/sentra-core/src/storage/).

### 3.1 Data Models ([`model.rs`](../../crates/sentra-core/src/storage/model.rs))
- **`BlobId`**:
  - Encapsulates `sha256:<64-char-hex>`.
  - Constructors: `from_bytes(&[u8])`, `from_hex_digest(&str)`, and `FromStr` parsing.
  - Implements `Serialize`, `Deserialize`, `Display`, `Debug`, `Hash`, `Ord`.
- **`BlobMetadata`**:
  - `blob_id: BlobId`: Cryptographic identifier.
  - `size_bytes: u64`: Exact file length.
  - `created_at_rfc3339: Option<String>`: Timestamp.
- **`StorageLimits`**:
  - `max_blob_size_bytes: u64`: Default 50 MiB (`MAX_EVIDENCE_SIZE_BYTES`).
  - `max_total_storage_bytes: u64`: Default 1 GiB.
  - `max_blob_count: usize`: Default 10,000 files.
- **`StorageUsage`**:
  - `total_blobs: usize`: Active blob count in CAS directory.
  - `total_bytes: u64`: Cumulative byte volume.

### 3.2 Error Hierarchy ([`error.rs`](../../crates/sentra-core/src/storage/error.rs))
- **`StorageErrorKind`**:
  - `BlobTooLarge`: Staged payload exceeds individual ceiling.
  - `TotalStorageExceeded`: Cumulative storage exceeds configured capacity.
  - `BlobCountExceeded`: Total blob count exceeds limit.
  - `DigestMismatch`: Computed hash does not match declared digest.
  - `NotFound`: Requested blob missing from repository.
  - `CollisionConflict`: Destination file exists but length or content differs.
  - `InvalidPath`: Directory traversal or path escape attempt.
  - `IoError`: Underlying filesystem I/O failure.
  - `ConfigurationError`: Invalid path or metadata bounds.

---

## 4. CAS Publication Lifecycle Implementation

Located in [`crates/sentra-core/src/storage/cas.rs`](../../crates/sentra-core/src/storage/cas.rs).

### 4.1 Publication Steps
1. **Quota Pre-Check**: Verifies `size <= limits.max_blob_size_bytes`.
2. **Digest Computation**: Derives `blob_id = BlobId::from_bytes(data)`.
3. **Idempotent Destination Check**:
   If `<blobs>/<digest>.blob` already exists, verifies file length matches. If valid, returns `Ok(blob_id)` immediately without duplicate writing.
4. **Cumulative Capacity Check**: Verifies `usage().total_bytes + size <= max_total_storage_bytes` and `usage().total_blobs < max_blob_count`.
5. **Private Staging**:
   Allocates `<staging>/stage-{pid}-{seq}-{digest}.tmp`.
   Writes payload with `OpenOptions::new().write(true).create_new(true)`.
   Commits OS buffers with `sync_all()`.
6. **Atomic Hard-Link Namespace Insertion**:
   Executes `std::fs::hard_link(&stage_path, &dest_path)`.
   - On success: new immutable link published.
   - On `AlreadyExists` (race winner collision): verifies existing destination file length; if valid, treats as idempotent publication success.
7. **Staging Cleanup**: Unlinks `stage_path`.
8. **Cooperative Immutability**: Applies `perms.set_readonly(true)` to `dest_path`.

---

## 5. Core Service Integration

Located in [`crates/sentra-core/src/service/core.rs`](../../crates/sentra-core/src/service/core.rs):

- `CoreService::with_blob_store(self, blob_store: Arc<dyn BlobStore>) -> Self`: Fluent builder attaching storage.
- `CoreService::blob_store(&self) -> Option<&Arc<dyn BlobStore>>`: Accessor.
- `CoreService::store_evidence(&self, envelope: &EvidenceEnvelope) -> Result<BlobId, ServiceError>`:
  1. Validates that a `BlobStore` is configured on the service instance.
  2. Runs `evidence_verifier.verify_envelope(envelope)`.
  3. Delegates to `blob_store.put_evidence_envelope(envelope)`.
  4. Returns computed `BlobId`.
- `CoreService::get_evidence(&self, blob_id: &BlobId) -> Result<Vec<u8>, ServiceError>`:
  1. Retrieves raw bytes from attached store.

---

## 6. Empirical Verification Summary

### 6.1 Test Matrix
| Environment | Test Target | Command | Result |
| :--- | :--- | :--- | :--- |
| **Windows 11 Host** | Storage Integration | `cargo test --package sentra-core --test storage_tests` | **14 / 14 passed** (0.08s) |
| **Windows 11 Host** | Manifest Integration | `cargo test --package sentra-core --test manifest_tests` | **14 / 14 passed** (0.07s) |
| **Linux Container** | Storage Integration | `pwsh scripts/docker-test.ps1 -Mode test -Package sentra-core -TestName storage_tests` | **14 / 14 passed** (0.08s) |
| **Linux Container** | All 11 Independent Suites | `pwsh scripts/docker-test.ps1 -Mode all` | **154 passed** (6.12s) |
| **Linux Container** | Linter | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | **0 warnings** |
| **Linux Container** | Formatter | `cargo fmt --all -- --check` | **Clean** |

### 6.2 Integration Tests Detail ([`tests/storage_tests.rs`](../../crates/sentra-core/tests/storage_tests.rs))
1. `test_blob_id_derivation_and_formatting`: Validates `BlobId` hex string formatting, parsing, and rejection of malformed digests.
2. `test_cas_put_get_roundtrip`: Verifies storing and retrieving payloads by content digest.
3. `test_cas_idempotent_deduplication`: Confirms publishing identical content twice produces zero duplicates and retains single blob count.
4. `test_cas_streaming_reader`: Verifies streaming chunked reads via standard `Read` trait.
5. `test_cas_blob_too_large_fails_closed`: Verifies rejection of payloads exceeding configured per-blob ceiling.
6. `test_cas_total_storage_quota_fails_closed`: Verifies cumulative capacity enforcement across multiple blobs.
7. `test_cas_blob_count_quota_fails_closed`: Verifies blob count ceiling rejection.
8. `test_cas_not_found_fails_closed`: Verifies typed `NotFound` error for non-existent digests.
9. `test_cas_put_evidence_envelope_success`: Verifies storing evidence envelope with valid declared SHA-256.
10. `test_cas_put_evidence_envelope_digest_mismatch_fails_closed`: Verifies rejection when declared hash does not match payload.
11. `test_cas_put_evidence_envelope_invalid_metadata_fails_closed`: Verifies rejection of invalid metadata before storage.
12. `test_cas_concurrent_threads_atomic_dedup`: 8 concurrent worker threads racing to publish identical payload; all succeed with single published CAS object.
13. `test_core_service_evidence_storage_integration`: Verifies end-to-end evidence storage and retrieval through `CoreService`.
14. `test_core_service_evidence_storage_unconfigured_fails_closed`: Verifies fail-closed behavior when storage is not configured.
