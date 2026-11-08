# Phase 1 — Increment 1.1: Independent Filesystem Security & Publication Contract Review

**Date:** 2026-11-08  
**Status:** **Approved with Conditions.** Phase 1 remains **NOT APPROVED**. Phase 2 remains **UNAUTHORIZED**.  
**Reviewed Documents:**
- [`docs/phase1/FILESYSTEM_CAPABILITY_VALIDATION.md`](FILESYSTEM_CAPABILITY_VALIDATION.md)
- [`docs/phase1/FILESYSTEM_CAPABILITY_CONTRACT.md`](FILESYSTEM_CAPABILITY_CONTRACT.md)
- [`PROGRESS.md`](../../PROGRESS.md)
- [`docs/phase1/IMPLEMENTATION_CONTRACTS.md`](IMPLEMENTATION_CONTRACTS.md)
- [`docs/phase1/IMPLEMENTATION_READINESS.md`](IMPLEMENTATION_READINESS.md)
- [`docs/phase1/REMEDIATION_ARCHITECTURE.md`](REMEDIATION_ARCHITECTURE.md)
- [`docs/phase1/PHASE1_GAP_ANALYSIS.md`](PHASE1_GAP_ANALYSIS.md)
- Raw disposable test evidence: `scratch/run_fs_experiments.ps1` and embedded validation JSON.

---

## 1. Executive Summary & Review Decision

### Review Decision: **APPROVED WITH CONDITIONS**

Increment 1.0 successfully demonstrated key Windows 11 x64 / NTFS filesystem primitives:
1. `std::fs::hard_link` (Win32 `CreateHardLinkW`) deterministically rejects destination collisions with Win32 Error 183 (`ERROR_ALREADY_EXISTS`), preserving existing destination content and object identity (**EXP-PUB-01**).
2. Concurrent races to the same destination path are serialized at the NTFS directory index layer with exactly 1 winner and $N-1$ Error 183 collisions (**EXP-PUB-02**).
3. Hard links are strictly single-volume and deterministically reject cross-volume operations with Win32 Error 17 (`ERROR_NOT_SAME_DEVICE`, **EXP-PUB-03**).
4. Standard Rust `std::fs::rename` delegates to `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)` and destructively overwrites pre-existing destination files (**EXP-PUB-05**), correctly disqualifying it for CAS destination publication.
5. In stable Rust 1.99.0 (`x86_64-pc-windows-msvc`), `MetadataExt::volume_serial_number()` and `file_index()` are unstable library features under `windows_by_handle` (issue #63010) and emit `E0658`, correctly substantiating the blocked in-crate File ID query capability.

However, an adversarial security analysis reveals critical vulnerabilities, overstated claims, and missing edge-case verifications in the proposed contract and validation methodology:
- **Critical Vulnerability (F-11-01):** Atomic hard-link namespace creation was conflated with content immutability. Hard links share the underlying MFT record. Open writable handles, lingering staging source aliases, and permissive file attributes leave published "immutable" blobs vulnerable to post-publication mutation.
- **Path Traversal Vulnerability (F-11-02):** The proposed staging path containment check `canonical_path.starts_with(staging_root + '/')` is severely flawed on Windows: `std::fs::canonicalize` returns verbatim paths with `\\?\` prefix and backslashes `\`, causing forward-slash checks to fail; raw string matching ignores Windows case insensitivity and 8.3 aliasing; and `canonicalize()` fails immediately with `NotFound` on non-existent staging paths.
- **Missing Race and Crash Coverage (F-11-03):** Multi-process concurrency, destination reparse-point substitution, and in-flight process termination were not experimentally executed.
- **Pre-Existing Handle Bypass (F-11-04):** Holding `FILE_SHARE_READ` blocks *subsequent* open attempts, but does not invalidate or block *pre-existing* writable handles.
- **Overly Broad Rename Prohibition (F-11-05):** Prohibiting `std::fs::rename` across the entire crate unnecessarily restricts private staging operations where destinations are unique and non-existent.

**Approval is granted solely for the documented research baseline and capability boundaries.** Implementation of any storage provider remains blocked until the conditions specified in Section 8 are addressed in future increments.

---

## 2. Git State & Preservation Baseline

The repository state was inspected at entry and verified to be clean:
- **Branch:** `develop`
- **Reviewed HEAD:** `e1ca3e7d8da5a813291ab32f1987018bc544c7fe`
- **Commit Subject:** `Document filesystem capability validation` (authored by Taiizor on 2026-11-08 18:25:47 +0300).
- **Commit Ancestry:** `8d36d43 → 4bd8618 → d9cca25 → adc3cf2 → ad0b7bb → e1ca3e7`
- **Upstream:** `origin/develop` (0 ahead / 0 behind).
- **Physical Index SHA-256:** `D5966A0E327F1A059FD1B15F00131D78A05DA3D536868F3C89AB07116575B410`
- **Tracked Files in Index:** 291 entries.
- **Working Tree:** Completely clean prior to this review. All modifications during this review are confined to unstaged documentation deliverables.

---

## 3. Detailed Adversarial Evaluation

### 3.1 Hard-Link Publication and Content Immutability

> [!WARNING]
> **Atomic Destination Creation $\neq$ Content Immutability.**  
> A successful hard-link operation merely creates an additional directory entry pointing to the source file's MFT record. It does NOT make the file content immutable.

Adversarial findings:
1. **Open Writable Handles Mutate Published Blobs:** If the staging writer holds an open writable handle to `content.tmp` while creating the hard link, writing to that handle *after* the link is created directly mutates the bytes of `<storage>/blobs/<hash>.blob`.
2. **Lingering Source Aliases:** Hard links share the underlying inode/MFT record. As long as `<storage>/staging/<write_id>/content.tmp` exists, any process or thread that opens that staging path for writing will mutate the published blob. If a publisher crashes after `hard_link` but before staging cleanup, the staging alias lingers indefinitely.
3. **Absence of OS-Enforced Immutability:** On Windows NTFS, file attributes (`FILE_ATTRIBUTE_READONLY`) and DACLs apply to the underlying MFT file record, not individual directory entries. `CreateHardLinkW` does NOT set the read-only attribute or tighten ACLs. Without an explicit, verified transition to read-only (e.g. via `SetFileAttributesW` or restrictive ACLs), any unprivileged process with write access to the directory can open `<storage>/blobs/<hash>.blob` with `FILE_WRITE_DATA` and overwrite or truncate it.

**Requirement:** Before `hard_link` is called:
- All writable handles must be flushed (`FlushFileBuffers`), invalidated, and explicitly closed.
- The file must be reopened in read-only mode with restricted sharing (`FILE_SHARE_READ`, zero write, zero delete).
- The hash must be verified on the *closed and reopened read-only handle*.
- Immediately upon successful hard-linking, the staging link must be unlinked. If unlinking fails or is delayed, the source alias must remain quarantined.
- The published blob must have `FILE_ATTRIBUTE_READONLY` set, and future readers must verify that write permissions are denied.

---

### 3.2 Atomicity and Race Coverage

1. **Destination Collisions:** EXP-PUB-01 proved that `CreateHardLinkW` against an existing destination fails closed with Error 183 without modifying the existing file. This is supported by Win32 NTFS documentation.
2. **Same-Process Concurrency:** EXP-PUB-02 tested 10 PowerShell Runspaces within a single host process, producing 1 winner and 9 Error 183 rejections. This demonstrates thread-level serialization.
3. **Missing Multi-Process Concurrency:** EXP-PUB-02 did NOT test independent OS processes racing for the same destination. While the NTFS directory lock is kernel-wide, multi-process tests are necessary to verify that independent process crashes or unexpected handle closures during a race do not leave dangling directory locks or partial MFT link counts.
4. **Missing Reparse-Point Substitution Race:** No test evaluated the scenario where an adversary substitutes `<storage>/blobs/` with a directory junction or symlink immediately before `hard_link` executes.
5. **Missing In-Flight Process Termination:** EXP-STG-02 tested clean sequential cleanup. No experiment verified recovery when a process is killed (`TerminateProcess` / `SIGKILL`) midway through `CreateHardLinkW` or during staging cleanup.

---

### 3.3 Handle Identity and TOCTOU

1. **Rust Stable Toolchain Verification:**
   Independent compilation on `rustc 1.99.0 (b940084d7 2026-09-28) (x86_64-pc-windows-msvc)` confirmed:
   ```text
   error[E0658]: use of unstable library feature 'windows_by_handle'
    --> <anon>:7:18
     |
   7 |     let _ = meta.file_index();
     |                  ^^^^^^^^^^
     = note: see issue #63010 <https://github.com/rust-lang/rust/issues/63010> for more information
   ```
   The claim that safe in-crate by-handle File ID queries are blocked on stable Rust under `#![forbid(unsafe_code)]` is **100% verified and factual**.
2. **Alternative Stable APIs:** Stable `std::os::windows::fs::OpenOptionsExt` supports `opts.share_mode(FILE_SHARE_READ)` (value `1`), which successfully compiles on stable Rust. However, no stable standard library API exists to extract the MFT 64-bit/128-bit File ID or Volume Serial Number.
3. **Pre-Existing Handle Limitation:** EXP-ID-07 proved that holding a handle with `FILE_SHARE_READ` blocks *subsequent* open attempts with `ERROR_SHARING_VIOLATION` (32). However, Windows sharing modes only evaluate against handles opened *after* the restrictive handle. If a rogue process opened `content.tmp` with `FILE_SHARE_READ | FILE_SHARE_WRITE` *before* Sentra acquired its read-only handle, the rogue process retains write access and can mutate the file concurrently. Sentra must ensure the file was created with exclusive access (`share_mode(0)`) from inception.

---

### 3.4 Staging and Cleanup Logic

> [!CAUTION]
> **Flawed Path Containment Logic:**  
> The proposed contract specifies `canonical_path.starts_with(staging_root + '/')`. This check is vulnerable to multiple failure modes on Windows.

1. **Prefix Separator Mismatch:** On Windows, Rust's `std::fs::canonicalize()` returns verbatim paths starting with `\\?\` and using backslashes `\` (e.g. `\\?\C:\storage\staging\write_id`). Concatenating `/` to the root path creates a prefix like `\\?\C:\storage\staging/`, which **never matches** any valid child path.
2. **Case Insensitivity:** Windows NTFS paths are case-preserving but case-insensitive. A raw string `starts_with` in Rust performs case-sensitive byte comparison. If `staging_root` is `C:\Storage\Staging` and the canonical child path evaluates to `C:\storage\staging\...`, the check falsely fails closed.
3. **Non-Existent Path Failure:** `std::fs::canonicalize` requires the path to exist on disk; if called on a prospective temporary path before creation, it returns `io::ErrorKind::NotFound`.
4. **Reparse-Point Traversal during Recursive Cleanup:** If an adversary creates a directory junction inside `<storage>/staging/<write_id>/sub`, calling `remove_dir_all` without verifying that every directory component lacks `FILE_ATTRIBUTE_REPARSE_POINT` (0x400) risks following the junction and deleting files outside the staging boundary.

**Required Remediation:** Containment checks must use parsed path components (`std::path::Path::components()`), normalize verbatim prefixes (`\\?\`), enforce case-insensitive component comparison on Windows, and verify `(symlink_metadata().file_attributes() & 0x400) == 0` before entering any directory during cleanup.

---

### 3.5 Crash and Durability Claims

The durability claims in Increment 1.0 are categorized below:

| Durability Level | Claim in Increment 1.0 | Actual Review Status | Rationale |
| :--- | :--- | :---: | :--- |
| **File Buffer Flushing** | `FlushFileBuffers` commits data/metadata. | **Verified** | Verified experimentally via EXP-DUR-01. |
| **Atomic Namespace Insertion** | `CreateHardLinkW` is atomic. | **Verified** | Verified experimentally via EXP-PUB-01 and EXP-PUB-02. |
| **Process Crash Recovery** | Staging isolation guarantees crash recovery. | **Plausible, but Unverified** | Overstated as "Experimentally Verified". No crash-injection tests (kill -9 midway) were run in Increment 1.0. |
| **Directory Index Persistence** | `FlushFileBuffers` on directory handle. | **Supported by Docs, Unverified** | Unverified in unprivileged userspace; requires `BACKUP_SEMANTICS`. |
| **NTFS Metadata Journaling** | Filesystem integrity preserved across OS crash. | **Supported by OS Architecture** | Standard NTFS design; does not guarantee user data payload durability without write-through. |
| **OS Crash Recovery** | Unflushed disk controller caches may drop data. | **Unverified / Acknowledged** | Correctly qualified as unverified in Increment 1.0. |
| **Power-Loss Durability** | Power loss may lose uncommitted write cache. | **Blocked / Unsupported** | Correctly qualified as blocked/unsupported in Increment 1.0. |

---

### 3.6 Cross-Volume Publication

EXP-PUB-03 confirmed that `CreateHardLinkW` across volumes (C: to E:) fails with Win32 Error 17 (`ERROR_NOT_SAME_DEVICE`).
- Hard-link publication is strictly limited to single-volume deployments.
- If a future deployment places blob storage and staging on separate drives, hard-link publication is **impossible**.
- Copy-and-replace fallbacks are strictly prohibited because they violate the no-replace CAS invariant.
- Any future cross-volume publication protocol must require:
  1. Staging directory allocated on the *destination volume*.
  2. Byte-for-byte copy into destination-volume staging.
  3. `FlushFileBuffers` on the destination-volume staging file.
  4. Same-volume `hard_link` on the destination volume.

---

### 3.7 API and Contract Scoping: The Rename Prohibition

Increment 1.0 issued a blanket prohibition of `std::fs::rename`:
> *"Prohibited Primitive: `std::fs::rename(source, destination)`. The use of `std::fs::rename` for CAS publication is strictly prohibited due to its destructive overwrite behavior (`MOVEFILE_REPLACE_EXISTING`)."*

While this prohibition is **100% correct for destination publication** (where an existing destination must never be overwritten), extending a blanket ban on `std::fs::rename` across all internal storage operations is overly broad. In private, isolated staging directories where the destination is guaranteed non-existent (e.g. renaming `<write_id>/upload.part` to `<write_id>/content.tmp`), atomic rename is safe and standard practice. The prohibition must be narrowly scoped to **destination publication and CAS promotion**.

---

## 4. Formal Review Findings

### F-11-01 (High): Hard-Link Namespace Creation Does Not Guarantee Content Immutability
- **Affected Contract:** `FILESYSTEM_CAPABILITY_CONTRACT.md` Section 4 & Section 6.
- **Evidence:** `CreateHardLinkW` creates an additional directory entry sharing the MFT record. Open writable handles, lingering staging source links, and absence of `FILE_ATTRIBUTE_READONLY` permit post-publication mutation of the destination blob.
- **Impact:** An attacker or buggy writer holding a handle or modifying the staging alias silently mutates published CAS content without triggering hash mismatch at the publication step.
- **Remediation:** 
  1. Mandate that staging files are opened exclusively (`share_mode(0)`).
  2. Mandate explicit handle flush and close *before* hashing.
  3. Mandate read-only reopening with `FILE_SHARE_READ` for hash validation.
  4. Mandate immediate unlinking of the staging link upon publication.
  5. Mandate setting `FILE_ATTRIBUTE_READONLY` on the published destination.

---

### F-11-02 (Medium): Vulnerable Windows Path Prefix Containment Check
- **Affected Contract:** `FILESYSTEM_CAPABILITY_CONTRACT.md` Section 2 (Row 7) and Section 5 (Rule 2).
- **Evidence:** `canonical_path.starts_with(staging_root + '/')` fails on Windows because `std::fs::canonicalize` emits verbatim paths (`\\?\`) with backslashes `\`. Furthermore, raw string prefix matching is vulnerable to case-sensitivity mismatches and fails with `NotFound` on non-existent paths.
- **Impact:** Valid staging paths will be falsely rejected, or path traversal vulnerabilities could occur if naive string comparisons are implemented.
- **Remediation:** Replace string concatenation with component-wise path containment (`Path::components()`), strip verbatim prefixes safely, enforce case-insensitive component comparison on Windows, and check parent directory canonicalization for non-existent target files.

---

### F-11-03 (Medium): Missing Multi-Process, Reparse Substitution, and Crash Injection Experiments
- **Affected Document:** `FILESYSTEM_CAPABILITY_VALIDATION.md` Section 3 & Section 5.
- **Evidence:** EXP-PUB-02 only tested 10 threads within a single PowerShell process. EXP-STG-02 only tested clean sequential cleanup. No tests evaluated multi-process races, destination reparse-point substitution races, or process kills midway through publication.
- **Impact:** Multi-process edge cases (such as abandoned locks or partial directory updates across independent processes) remain unverified empirically.
- **Remediation:** Before implementing the storage provider, design and execute disposable multi-process race and crash-injection test scripts.

---

### F-11-04 (Low): Pre-Existing Writable Handles Bypass `FILE_SHARE_READ` TOCTOU Lock
- **Affected Contract:** `FILESYSTEM_CAPABILITY_CONTRACT.md` Section 2 (Row 4) & Section 3.1.
- **Evidence:** Windows sharing flags only evaluate against *subsequent* handle opens. If an external handle was opened with write access prior to Sentra opening with `FILE_SHARE_READ`, the prior handle retains write capability.
- **Impact:** Holding `FILE_SHARE_READ` does not retroactively revoke existing writers.
- **Remediation:** The storage engine must create staging files exclusively from inception (`CREATE_NEW`, `share_mode(0)`) so that no external process could have acquired a prior handle.

---

### F-11-05 (Low): Overly Broad Blanket Prohibition of `std::fs::rename`
- **Affected Contract:** `FILESYSTEM_CAPABILITY_CONTRACT.md` Section 4.1 & Section 7 (Item 3).
- **Evidence:** The contract prohibits `std::fs::rename` across the entire storage layer due to `MOVEFILE_REPLACE_EXISTING`.
- **Impact:** Legitimate private staging file rotations (where destination is guaranteed non-existent) are unnecessarily restricted.
- **Remediation:** Clarify that `std::fs::rename` is strictly prohibited for **destination publication and CAS object promotion**, but permitted within private, single-owner staging directories.

---

## 5. Overstated and Unsupported Claims

1. **"Process Crash Recovery: Experimentally Verified" (OVERSTATED):**  
   `FILESYSTEM_CAPABILITY_VALIDATION.md` Section 5 claims process crash recovery is experimentally verified based on EXP-STG-02. However, EXP-STG-02 merely verified sequential idempotent cleanup of an intact directory. No process termination (`TerminateProcess` / kill -9) during active write or link operations was executed in Increment 1.0. This claim must be downgraded to **Plausible by Design, Empirically Unverified in Increment 1.0**.
2. **"Immutable Publication Primitive" (OVERSTATED):**  
   Calling `std::fs::hard_link` an "immutable publication primitive" conflates namespace creation with object immutability. Hard links create directory entries, not immutable files. The claim must be corrected to **Atomic No-Replace Namespace Publication Primitive**.

---

## 6. Updated Filesystem Capability Matrix

| Capability / Primitive | Native Win32 API | Rust Std API | Review Status | Boundary & Conditions |
| :--- | :--- | :--- | :---: | :--- |
| **Atomic No-Replace Publication** | `CreateHardLinkW` | `std::fs::hard_link` | **Verified & Approved** | Local single-volume NTFS. Rejects collision with Error 183. Serializes races. |
| **Content Immutability Enforcement** | `SetFileAttributesW` / ACL | `MetadataExt` | **Requires Hardening (F-11-01)** | Must close writable handles before link; unlink staging source; set read-only attribute. |
| **Destructive Rename Prohibition** | `MoveFileExW(REPLACE)` | `std::fs::rename` | **Approved for CAS (F-11-05)** | Prohibited for CAS publication; permitted in private staging. |
| **By-Handle File ID Query** | `GetFileInformationByHandle` | `windows_by_handle` | **Blocked (E0658)** | Unstable in Rust std. No safe route without approved wrapper crate. |
| **Open-Handle TOCTOU Lock** | `FILE_SHARE_READ` | `OpenOptionsExt` | **Approved with Caution (F-11-04)**| Requires exclusive creation (`share_mode(0)`) from inception. |
| **Reparse Point Detection** | `FILE_ATTRIBUTE_REPARSE_POINT`| `symlink_metadata` | **Verified & Approved** | `0x400` flag identifies junctions/symlinks. |
| **Staging Path Containment** | Component analysis | `Path::components()` | **Requires Remediation (F-11-02)**| String prefix check rejected; must use component-based comparison. |
| **Cross-Volume Publication** | Error 17 | `std::fs::hard_link` | **Unsupported** | Single-volume NTFS only. Cross-volume requires separate destination-volume staging. |
| **File Data & Metadata Sync** | `FlushFileBuffers` | `File::sync_all` | **Verified & Approved** | Flushes data and MFT attributes to device cache. |
| **Power-Loss Durability** | Hardware write-through | `File::sync_all` | **Blocked / Unsupported** | Unverifiable on consumer hardware without power-cut test equipment. |

---

## 7. Production Readiness & Approval Decision

### **Phase 1 Status: NOT APPROVED**
### **Phase 2 Status: UNAUTHORIZED**

- The technical foundation established in Increment 1.0 and reviewed herein demonstrates the feasibility of Windows NTFS no-replace publication via `std::fs::hard_link`.
- However, Phase 1 cannot be approved because:
  1. Production storage provider implementation has not occurred.
  2. Critical vulnerabilities F-11-01 (content immutability) and F-11-02 (path containment) must be resolved in design contracts before implementation.
  3. Safe Rust File ID querying remains **Blocked** (E0658).
  4. Cryptographic SHA-256 hashing remains **Blocked** (Increment 0.2 dependency decision).
  5. Recovery from interrupted bootstrap (F-611-02) and single-session project identity (OQ-25) remain open.
  6. ADR-0008, ADR-0009, and ADR-0010 remain **Proposed**.

---

## 8. Conditions and Stop Criteria for Future Work

Before any production filesystem or blob storage module is implemented:
1. **Condition 1 (Immutability Protocol):** The contract must specify the complete handle lifecycle (exclusive creation $\rightarrow$ write $\rightarrow$ flush $\rightarrow$ close $\rightarrow$ read-only open $\rightarrow$ hash verify $\rightarrow$ hard link $\rightarrow$ staging unlink $\rightarrow$ read-only attribute set).
2. **Condition 2 (Safe Path Containment):** The contract must replace the flawed string prefix check with a verified component-based path containment algorithm tailored for Windows verbatim paths and case insensitivity.
3. **Condition 3 (Multi-Process Race Verification):** Multi-process concurrency and crash-injection tests must be executed to verify crash recovery empirically.
4. **Stop Criteria:** Stop immediately after this review. Do not implement production code, tests, or schema modifications.
