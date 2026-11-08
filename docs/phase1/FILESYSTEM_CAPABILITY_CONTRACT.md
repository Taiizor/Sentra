# Phase 1 — Increment 1.0: Filesystem Capability Contract

**Date:** 2026-11-08  
**Status:** **Proposed Technical Capability Contract. Phase 1 remains NOT APPROVED. Phase 2 remains unauthorized.**  
**Primary Validation Evidence:** [FILESYSTEM_CAPABILITY_VALIDATION.md](FILESYSTEM_CAPABILITY_VALIDATION.md)  
**Scope:** Defines the exact technical capabilities, primitive boundaries, failure modes, and fail-closed conditions for future Core Engine content-addressed blob storage and recoverable publication. Zero production implementation, zero API changes.

---

## 1. Authority, Purpose and Non-Claims

This contract formalizes the findings of [FILESYSTEM_CAPABILITY_VALIDATION.md](FILESYSTEM_CAPABILITY_VALIDATION.md) into explicit technical requirements for any future Core filesystem provider.

### Core Architecture Invariants:
1. **No Silent Fallback:** The filesystem provider must never silently fall back to weaker primitives (e.g. falling back to destructive `std::fs::rename` if hard links fail, or falling back to unbuffered writes if flush fails).
2. **Explicit Scope Denial:** Capabilities verified on local C: NTFS must NOT be assumed to apply to ReFS, network/SMB shares, FAT32/exFAT, cross-volume publications, or non-Windows operating systems. Any request for an unsupported profile must be rejected before mutation.
3. **No Unsafe Code or Unvetted Dependencies:** All future in-crate implementations must strictly adhere to `#![forbid(unsafe_code)]`. Where an operation requires native Win32 capabilities not exposed by stable Rust `std`, that capability must remain explicitly marked **Blocked** until a vetted, approved abstraction is authorized.

---

## 2. Filesystem Capability Matrix

The following matrix establishes the exact operational primitives, verified behaviors, supported scopes, failure modes, and fail-closed conditions:

| Required Capability | Native Primitive / API | Tested Behavior | Evidence ID | Supported Scope | Failure Mode | Fail-Closed Condition |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- |
| **Atomic No-Replace Publication** | `CreateHardLinkW` / `std::fs::hard_link` | Fails deterministically with Error 183 when destination exists; preserves existing destination bytes and ID; serializes concurrent races with exactly 1 winner. | `EXP-PUB-01`<br>`EXP-PUB-02` | Local single-volume NTFS on Windows 11 x64. | Win32 Error 183 (`ERROR_ALREADY_EXISTS`). | Rejects overwrite. Triggers authorized content comparison; if hash/length differs, reports `CollisionConflict` and preserves existing file. |
| **Cross-Volume Publication Rejection** | `CreateHardLinkW` / `std::fs::hard_link` | Fails deterministically with Error 17 when source and destination reside on different volumes. | `EXP-PUB-03` | Cross-volume (e.g. C: to E:). | Win32 Error 17 (`ERROR_NOT_SAME_DEVICE`). | Returns `CrossVolumeUnsupported`; refuses copy-delete fallback. |
| **In-Place Rename Object Invariance** | `MoveFileExW(..., 0)` | In-place rename within the same volume preserves 64-bit and 128-bit File ID and volume serial identically. | `EXP-ID-01` | Local single-volume NTFS on Windows 11 x64. | Win32 Error 183 if destination exists. | Refuses destination overwrite. |
| **Open-Handle Lockout (TOCTOU Prevention)** | `CreateFileW(..., FILE_SHARE_READ)` | Holding an open read handle with `FILE_SHARE_READ` blocks concurrent write, delete, and rename attempts. | `EXP-ID-07` | Windows NTFS files. | Win32 Error 32 (`ERROR_SHARING_VIOLATION`). | Any concurrent modification attempt fails closed with sharing violation. |
| **Reparse Point / Junction Detection** | `(dwFileAttributes & 0x400) != 0` | Distinguishes junctions and symlinks (`0x00000410`) from ordinary directories (`0x00000010`). | `EXP-ID-05` | Windows NTFS reparse points. | Flag mismatch. | Fails closed with `ReparseQuarantine`; refuses traversal into link target. |
| **Directory Handle Access** | `CreateFileW(..., FILE_FLAG_BACKUP_SEMANTICS)` | Opening directory handle requires `FILE_FLAG_BACKUP_SEMANTICS` (0x02000000); fails with Error 5 without it. | `EXP-ID-06` | Windows directories. | Win32 Error 5 (`ERROR_ACCESS_DENIED`). | Denies handle acquisition if backup semantics flag is omitted. |
| **Staging Path Containment** | Canonical path prefix check (`starts_with`) | Component-based containment check rejects path traversal (`..`) and escaping links. | `EXP-STG-01` | Local storage roots. | Path containment failure. | Throws `PathEscapeDenied`; refuses file creation or deletion outside staging root. |
| **Idempotent Staging Cleanup** | Guarded path deletion (`Remove-Item` / `fs::remove_dir_all`) | Repeated deletion of already-removed staging path completes safely without error. | `EXP-STG-02` | Designated staging directories. | `NotFound` safely handled. | Succeeds idempotently; does not fail if artifact was already cleaned. |
| **Cleanup Containment Guard** | Pre-deletion boundary verification | Refuses to delete paths outside the designated staging boundary. | `EXP-STG-03` | External filesystem paths. | Security boundary exception. | Fails closed; preserves external paths untouched. |
| **File Buffer Flushing** | `FlushFileBuffers` / `File::sync_all` | Commits written bytes and metadata from OS file cache to storage controller. | `EXP-DUR-01` | Open writable file handles. | Flush error / I/O error. | Fails publication with `StorageSyncFailure`; refuses to mark artifact `Ready`. |
| **Direct By-Handle File ID Query** | `GetFileInformationByHandle` / `FileIdInfo` | Native API returns 64-bit and 128-bit IDs; in stable Rust std, methods fail with `E0658`. | Section 2.3 | **BLOCKED IN SAFE RUST.** | Compiler error `E0658`. | **Blocked capability.** Safe in-crate query unavailable until wrapper crate approved. |

---

## 3. Handle-Based Identity & TOCTOU Prevention Contract

### 3.1 Logical Ownership Boundaries
A future storage provider must encapsulate raw handles and file paths in private, non-clonable types with private constructors:

1. `VerifiedStorageRoot`: Represents an established storage root on an explicitly validated local fixed NTFS volume. Retains the canonical root path and volume serial number.
2. `OpenedOwnedObject`: Represents an open file handle held with restricted sharing modes (`FILE_SHARE_READ`, zero write, zero delete). Retains the open handle throughout the validation-to-use window to guarantee TOCTOU immunity.
3. `StagedArtifact`: Represents a private staging file under `<storage>/staging/<write_id>/content.tmp`. Held under exclusive write access until synchronization.
4. `PublicationReceipt`: Immutable proof of successful publication, recording `WriteId`, destination path, byte length, and SHA-256 digest.

### 3.2 Blocked Status for Stable By-Handle ID Inspection
- Because `std::os::windows::fs::MetadataExt::volume_serial_number` and `file_index` are unstable (`windows_by_handle`, issue #63010), in-crate retrieval of raw File IDs in stable `#![forbid(unsafe_code)]` Rust is **BLOCKED**.
- Contractual Rule: Future implementations must NOT use path strings as identity substitutes. Until a safe wrapper is authorized, object verification must rely on open handle retention and atomic namespace primitives (`std::fs::hard_link`), which enforce kernel-level object semantics without requiring user-space inspection of raw MFT indexes.

---

## 4. No-Replace Publication Contract

### 4.1 Primitive Selection
- **Approved Primitive:** `std::fs::hard_link(source, destination)`.
- **Prohibited Primitive:** `std::fs::rename(source, destination)`. The use of `std::fs::rename` for CAS publication is strictly prohibited due to its destructive overwrite behavior (`MOVEFILE_REPLACE_EXISTING`).

### 4.2 Lifecycle State Transitions

```mermaid
stateDiagram-v2
    [*] --> StagingAllocated: Allocate unique <staging>/<uuid>/
    StagingAllocated --> StagedWriting: Create content.tmp exclusively
    StagedWriting --> StagedSynced: FlushFileBuffers() / sync_all()
    StagedSynced --> HashVerified: Verify byte length and cryptographic hash
    HashVerified --> HardLinkAttempt: std::fs::hard_link(content.tmp, <blobs>/<hash>.blob)
    
    HardLinkAttempt --> Published: Success (Atomic namespace insertion)
    HardLinkAttempt --> CollisionDetected: Error 183 (ERROR_ALREADY_EXISTS)
    
    CollisionDetected --> IdempotentDedup: Destination hash & length match
    CollisionDetected --> CollisionConflict: Destination hash/length mismatch or unreadable
    
    Published --> CleanupStaging: StageCleanupPending
    IdempotentDedup --> CleanupStaging: StageCleanupPending
    CollisionConflict --> QuarantineStaging: Preserve staged artifact for investigation
    
    CleanupStaging --> [*]: Guarded idempotent removal of <staging>/<uuid>/
    QuarantineStaging --> [*]: Retain uncommitted stage; surface typed error
```

### 4.3 Collision & Idempotency Rules
1. **Collision is Not an Automatic Failure:** When `hard_link` returns `ErrorKind::AlreadyExists` (Win32 Error 183), the provider must NOT treat this as immediate data loss or silent success.
2. **Authorized Verification:** The provider must inspect the existing destination file under an open handle with `FILE_SHARE_READ`. It must verify:
   - File size matches expected byte count exactly.
   - Cryptographic digest matches expected hash exactly.
3. **Outcome:**
   - If destination matches: The collision is an idempotent deduplication. The provider emits a `PublicationReceipt` and proceeds to cleanup.
   - If destination differs or cannot be read: The provider surfaces a typed `CollisionConflict` error and preserves both the staged artifact and the destination file untouched.

---

## 5. Staging and Cleanup Contract

1. **Unique Isolation:** Staging directories must use cryptographically random UUIDv4 or monotonic non-repeating identifiers under `<storage>/staging/<write_id>/`.
2. **Component Containment:** Before any file creation or deletion, the target path must be canonicalized and checked for strict component containment:
   ```text
   target_path.canonical().starts_with(staging_root.canonical() + "/")
   ```
   If containment fails, the operation must immediately fail closed with a security violation.
3. **Idempotence:** Deletion of staging directories must be idempotent. If a directory is already absent (e.g. from an earlier cleanup attempt or manual operator action), the operation must report success (`AlreadyAbsent`) without error.
4. **No Recursive Delete on Unverified Roots:** The provider must never call recursive deletion on an unverified or parameterized path that has not passed the component containment guard.

---

## 6. Durability Scope and Guarantees

| Scope Level | Supported Guarantee | Required Primitives | Boundary Limits |
| :--- | :--- | :--- | :--- |
| **Level 1: Process-Crash Recoverable** | **SUPPORTED & VERIFIED** | `FlushFileBuffers` on staging file + `CreateHardLinkW` + Staging cleanup. | Protects against process termination (`kill -9`, panic, power cut to process). If process dies before hard link, destination does not exist. If process dies after hard link, destination is fully committed. |
| **Level 2: OS-Crash Recoverable** | **UNVERIFIED** | Directory flush + NTFS metadata journal commit. | Unverified in unprivileged userspace. OS crashes may drop unflushed disk controller cache. |
| **Level 3: Power-Loss Durable** | **UNSUPPORTED / BLOCKED** | Write-through barriers / non-volatile hardware write caches. | Cannot be claimed on consumer hardware or without dedicated power-loss validation fixtures. |

---

## 7. Blocked Capabilities Catalog

The following capabilities are explicitly classified as **Blocked** and must NOT be enabled or claimed by any Phase 1 module:
1. **Direct In-Crate By-Handle File ID Query:** Blocked due to Rust `windows_by_handle` instability (E0658) and `#![forbid(unsafe_code)]`.
2. **Cross-Volume Hard-Link Publication:** Blocked by operating system architecture (Win32 Error 17).
3. **Destructive Replacement Publication:** Blocked by architectural policy (prohibition of `std::fs::rename` for CAS).
4. **ReFS 128-Bit File ID Support:** Blocked by environment scope (tested exclusively on C: NTFS; ReFS unsupported).
5. **Hardware Power-Loss Durability:** Blocked by lack of dedicated power-cut testing hardware and write-cache flush guarantees.

**Phase 1 remains NOT APPROVED. Phase 2 remains unauthorized. Stop after Increment 1.0.**
