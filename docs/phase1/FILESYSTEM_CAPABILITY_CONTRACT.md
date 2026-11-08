# Phase 1 — Increment 1.2: Filesystem Capability Contract

**Date:** 2026-11-08<br>
**Status:** **Revised Technical Capability Contract (Incorporates Increment 1.2 Closures for F-11-01 through F-11-05). Phase 1 remains NOT APPROVED. Phase 2 remains unauthorized.**<br>
**Primary Validation Evidence:**
- [FILESYSTEM_CAPABILITY_VALIDATION.md](FILESYSTEM_CAPABILITY_VALIDATION.md) (Increment 1.0)
- [INCREMENT_1_1_INDEPENDENT_REVIEW.md](INCREMENT_1_1_INDEPENDENT_REVIEW.md) (Increment 1.1)
- [INCREMENT_1_2_FILESYSTEM_SECURITY_CLOSURE.md](INCREMENT_1_2_FILESYSTEM_SECURITY_CLOSURE.md) (Increment 1.2)<br>
**Scope:** Defines the exact technical capabilities, primitive boundaries, failure modes, and fail-closed conditions for future Core Engine content-addressed blob storage and recoverable publication. Zero production implementation, zero API changes.

---

## 1. Authority, Purpose and Non-Claims

This contract formalizes the empirical findings of Increments 1.0, 1.1, and 1.2 into explicit technical requirements for any future Core filesystem provider.

### Core Architecture Invariants:
1. **No Silent Fallback:** The filesystem provider must never silently fall back to weaker primitives (e.g. falling back to destructive `std::fs::rename` if hard links fail, or falling back to unbuffered writes if flush fails).
2. **Explicit Scope Denial:** Capabilities verified on local C: and E: NTFS must NOT be assumed to apply to ReFS, network/SMB shares, FAT32/exFAT, or non-Windows operating systems. Any request for an unsupported profile must be rejected before mutation.
3. **No Unsafe Code or Unvetted Dependencies:** All future in-crate implementations must strictly adhere to `#![forbid(unsafe_code)]`. Where an operation requires native Win32 capabilities not exposed by stable Rust `std`, that capability must remain explicitly marked **Blocked** until a vetted, approved abstraction is authorized.
4. **Zero-Window Content Immutability (F-11-01 / F-11-04):** Creating an atomic namespace directory entry via `hard_link` does NOT make a file immutable. The provider must maintain an unbroken exclusive handle (`share_mode = 0`) from file creation through write, flush, hash verification, and publication, followed by immediate unlinking of the staging alias and application of `FILE_ATTRIBUTE_READONLY`.

---

## 2. Filesystem Capability Matrix

| Required Capability | Native Primitive / API | Tested Behavior | Evidence ID | Supported Scope | Failure Mode | Fail-Closed Condition |
| :--- | :--- | :--- | :---: | :--- | :--- | :--- |
| **Atomic No-Replace CAS Publication** | `CreateHardLinkW` / `std::fs::hard_link` | Fails deterministically with Error 183 when destination exists; preserves existing destination bytes and ID; serializes multi-process races with exactly 1 winner. | `EXP-PUB-01`<br>`EXP-PUB-02`<br>`EXP-PUB-02-MP` | Local single-volume NTFS on Windows 11 x64. | Win32 Error 183 (`ERROR_ALREADY_EXISTS`). | Rejects overwrite. Triggers authorized content comparison; if hash/length differs, reports `CollisionConflict` and preserves existing file. |
| **Zero-Window Content Immutability** | `CreateFileW(0)` + link + attr | Holding exclusive handle (`share_mode=0`) through write, flush, hash, and link eliminates all concurrent tampering windows. | `EXP-MUT-01`<br>`EXP-MUT-08` | Staging to CAS publication. | Sharing violation / attribute error. | Rejects publication if handle exclusivity is broken before publication. |
| **Cross-Volume Publication** | Destination-Volume Staging | Streams copy to destination-volume staging, flushes, hashes, and hard-links within destination volume. | `EXP-CROSS-01` | Cross-volume (e.g. C: to E:). | Win32 Error 17 on direct link. | Refuses direct cross-volume link; mandates destination-volume staging protocol. |
| **Scoped Rename Restriction** | `MoveFileExW` / `std::fs::rename` | Prohibited for CAS publication; permitted exclusively in private staging directories where destination non-existence is verified. | `EXP-PUB-05`<br>`F-11-05` | Private staging directories only. | Overwrite risk. | Fails closed; never permits `rename` to overwrite an existing destination. |
| **Open-Handle Lockout (TOCTOU Prevention)** | `CreateFileW(..., FILE_SHARE_READ)` | Holding an open read handle with `FILE_SHARE_READ` blocks subsequent write, delete, and rename attempts. | `EXP-ID-07`<br>`EXP-MUT-06` | Windows NTFS files. | Win32 Error 32 (`ERROR_SHARING_VIOLATION`). | Any concurrent modification attempt fails closed with sharing violation. |
| **Reparse Point / Junction Detection** | `(dwFileAttributes & 0x400) != 0` | Distinguishes junctions and symlinks (`0x00000410`) from ordinary directories (`0x00000010`). | `EXP-ID-05` | Windows NTFS reparse points. | Flag mismatch. | Fails closed with `ReparseQuarantine`; refuses traversal into link target. |
| **Directory Handle Access** | `CreateFileW(..., FILE_FLAG_BACKUP_SEMANTICS)` | Opening directory handle requires `FILE_FLAG_BACKUP_SEMANTICS` (0x02000000); fails with Error 5 without it. | `EXP-ID-06` | Windows directories. | Win32 Error 5 (`ERROR_ACCESS_DENIED`). | Denies handle acquisition if backup semantics flag is omitted. |
| **Component Path Containment** | `Path::components()` parsing | Parses path components, strips `\\?\`, normalizes case on Windows, verifies parent canonicalization, and checks reparse flags. | `EXP-PATH-01..09` | Local storage roots. | Path containment failure. | Throws `PathEscapeDenied`; refuses file creation or deletion outside staging root. |
| **Idempotent Staging Cleanup** | Guarded path deletion (`fs::remove_dir_all`) | Repeated deletion of already-removed staging path completes safely without error; safe across 7 crash boundaries. | `EXP-STG-02`<br>`EXP-TERM-01..07`| Designated staging directories. | `NotFound` safely handled. | Succeeds idempotently; does not fail if artifact was already cleaned. |
| **File Buffer Flushing** | `FlushFileBuffers` / `File::sync_all` | Commits written bytes and metadata from OS file cache to storage controller. | `EXP-DUR-01` | Open writable file handles. | Flush error / I/O error. | Fails publication with `StorageSyncFailure`; refuses to mark artifact `Ready`. |
| **Direct By-Handle File ID Query** | `GetFileInformationByHandle` / `FileIdInfo` | Native API returns 64-bit and 128-bit IDs; in stable Rust std, methods fail with `E0658`. | Section 2.3 | **BLOCKED IN SAFE RUST.** | Compiler error `E0658`. | **Blocked capability.** Safe in-crate query unavailable until wrapper crate approved. |

---

## 3. Handle-Based Identity & Zero-Window Lifecycle Contract

### 3.1 Logical Ownership Boundaries
A future storage provider must encapsulate raw handles and file paths in private, non-clonable types with private constructors:

1. `VerifiedStorageRoot`: Represents an established storage root on an explicitly validated local fixed NTFS volume. Retains the canonical root path and volume serial number.
2. `ExclusiveStagedArtifact`: Represents an open file handle held under exclusive access (`CREATE_NEW`, `GENERIC_READ | GENERIC_WRITE`, `share_mode = 0`). Held continuously from creation through hash verification and `hard_link` publication.
3. `PublicationReceipt`: Immutable proof of successful publication, recording `WriteId`, destination path, byte length, and SHA-256 digest.
4. `PublishedBlob`: Represents a published CAS object with `FILE_ATTRIBUTE_READONLY` set, having zero lingering staging hard links.

### 3.2 The Zero-Window Handle Lifecycle (Resolution of F-11-01 & F-11-04)
To ensure that a published CAS blob is strictly immutable and cannot be tampered with:
1. **Exclusive Creation:** Staging files must be created under `<storage>/staging/<write_id>/content.tmp` using `OpenOptions::new().read(true).write(true).create_new(true).share_mode(0)`. If the file exists or another process holds it, creation fails closed immediately.
2. **Synchronized Write:** Payload bytes are written. `FlushFileBuffers` (`File::sync_all`) is called on the open exclusive handle.
3. **In-Handle Verification:** Without closing the handle, the writer seeks to offset 0 and reads back the bytes to verify length and compute the cryptographic digest.
4. **Hard-Link Publication Under Exclusive Hold:** While still holding the exclusive handle, `std::fs::hard_link(stage_path, cas_destination_path)` is executed. Windows NTFS permits creating hard links to files with open exclusive handles.
5. **Handle Release & Staging Unlink:** The exclusive handle is closed. The staging link (`content.tmp`) is immediately unlinked.
6. **Read-Only Marking:** `SetFileAttributesW(cas_destination_path, FILE_ATTRIBUTE_READONLY)` is applied to the destination blob.

---

## 4. No-Replace Publication Contract

### 4.1 Primitive Selection (Resolution of F-11-05)
- **Approved CAS Publication Primitive:** `std::fs::hard_link(source, destination)`.
- **Prohibited CAS Publication Primitive:** `std::fs::rename(source, destination)`. The use of `std::fs::rename` for CAS publication is strictly prohibited due to its destructive overwrite behavior (`MOVEFILE_REPLACE_EXISTING`).
- **Scoped Permissibility of Rename:** `std::fs::rename` is permitted strictly within private, single-owner staging directories where the target name is guaranteed non-existent (e.g. rotating an internal temporary part file `<write_id>/upload.part` to `<write_id>/content.tmp`).

### 4.2 Lifecycle State Transitions

```mermaid
stateDiagram-v2
    [*] --> StagingAllocated: Allocate unique <staging>/<uuid>/
    StagingAllocated --> ExclusiveHeld: Create content.tmp (CREATE_NEW, share_mode=0)
    ExclusiveHeld --> SyncedExclusive: Write payload & FlushFileBuffers()
    SyncedExclusive --> VerifiedExclusive: Seek 0, verify length & hash (SAME handle)
    VerifiedExclusive --> HardLinkAttempt: std::fs::hard_link(content.tmp, <blobs>/<hash>.blob)
    
    HardLinkAttempt --> PublishedLinked: Success (Atomic namespace insertion)
    HardLinkAttempt --> CollisionDetected: Error 183 (ERROR_ALREADY_EXISTS)
    
    CollisionDetected --> IdempotentDedup: Destination hash & length match
    CollisionDetected --> CollisionConflict: Destination hash/length mismatch or unreadable
    
    PublishedLinked --> ReleaseExclusive: Close exclusive handle
    IdempotentDedup --> ReleaseExclusive: Close exclusive handle
    CollisionConflict --> QuarantineStaging: Close handle & preserve stage for audit
    
    ReleaseExclusive --> UnlinkStage: Remove-Item <staging>/<uuid>/content.tmp
    UnlinkStage --> ApplyReadOnly: SetFileAttributesW(<blobs>/<hash>.blob, READONLY)
    ApplyReadOnly --> [*]: Emit immutable PublicationReceipt
    QuarantineStaging --> [*]: Retain uncommitted stage; surface typed error
```

### 4.3 Collision & Idempotency Rules
1. **Collision Handling:** When `hard_link` returns `ErrorKind::AlreadyExists` (Win32 Error 183), the provider inspects the existing destination file under an open handle with `FILE_SHARE_READ`.
2. **Authorized Verification:** Verify exact byte length and cryptographic hash.
3. **Deduplication:** If destination matches exactly, the collision is an idempotent deduplication. The provider releases staging and emits a `PublicationReceipt`. If it differs, it fails closed with `CollisionConflict`.

---

## 5. Staging and Cleanup Contract (Resolution of F-11-02)

1. **Unique Isolation:** Staging directories must use cryptographically random UUIDv4 identifiers under `<storage>/staging/<write_id>/`.
2. **Component-Based Path Containment Algorithm:**
   Before any file creation or deletion, path containment must be verified using parsed path components, NOT naive string concatenation:
   - Strip verbatim `\\?\` prefix for component normalization.
   - Decompose both candidate path and staging root into `std::path::Component` sequences.
   - Verify that `candidate_components.len() > root_components.len()`.
   - Compare components prefix-by-prefix using case-insensitive ASCII comparison on Windows.
   - For prospective files that do not yet exist, canonicalize and verify the *parent directory*.
   - Verify that no intermediate directory component has `FILE_ATTRIBUTE_REPARSE_POINT` (`0x400`).
3. **Idempotence Across Crash Boundaries:** Deletion of staging directories must be idempotent. If a directory or file is already absent, the operation reports success (`AlreadyAbsent`) without error.
4. **No Recursive Delete on Unverified Roots:** The provider must never call recursive deletion on an unverified path.

---

## 6. Durability Scope and Guarantees

| Scope Level | Supported Guarantee | Required Primitives | Boundary Limits |
| :--- | :--- | :--- | :--- |
| **Level 1: Process-Crash Recoverable** | **SUPPORTED & VERIFIED** | Zero-Window Exclusive Lifecycle + `CreateHardLinkW` + Staging cleanup. | Verified across 7 process termination boundaries. If process dies before hard link, destination does not exist. If process dies after hard link, destination blob is fully intact and lingering stage is cleaned on recovery. |
| **Level 2: OS-Crash Recoverable** | **UNVERIFIED** | Directory flush + NTFS metadata journal commit. | Unverified in unprivileged userspace. OS crashes may drop unflushed disk controller cache. |
| **Level 3: Power-Loss Durable** | **UNSUPPORTED / BLOCKED** | Write-through barriers / non-volatile hardware write caches. | Cannot be claimed on consumer hardware or without dedicated power-loss validation fixtures. |

---

## 7. Blocked Capabilities Catalog

The following capabilities remain explicitly classified as **Blocked** and must NOT be enabled or claimed by any Phase 1 module:
1. **Direct In-Crate By-Handle File ID Query:** Blocked due to Rust `windows_by_handle` instability (E0658) and `#![forbid(unsafe_code)]`.
2. **Hardware Power-Loss Durability:** Blocked by lack of dedicated power-cut testing hardware and write-cache flush guarantees.
3. **Cryptographic SHA-256 Digest:** Blocked pending project owner dependency decision (Increment 0.2).
4. **ReFS 128-Bit File ID Support:** Blocked by environment scope (tested exclusively on NTFS).

**Phase 1 remains NOT APPROVED. Phase 2 remains unauthorized. Stop after Increment 1.2.**
