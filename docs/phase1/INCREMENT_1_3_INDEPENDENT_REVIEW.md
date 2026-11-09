# Phase 1 — Increment 1.3: Independent Review of Filesystem Security Closure

**Date:** 2026-11-08  
**Status:** **Approved with Conditions.** Phase 1 remains **NOT APPROVED**. Phase 2 remains **UNAUTHORIZED**.  
**Reviewed Documents & Evidence:**
- [`docs/phase1/INCREMENT_1_2_FILESYSTEM_SECURITY_CLOSURE.md`](INCREMENT_1_2_FILESYSTEM_SECURITY_CLOSURE.md)
- [`docs/phase1/FILESYSTEM_CAPABILITY_CONTRACT.md`](FILESYSTEM_CAPABILITY_CONTRACT.md)
- [`PROGRESS.md`](../../PROGRESS.md)
- [`docs/phase1/INCREMENT_1_1_INDEPENDENT_REVIEW.md`](INCREMENT_1_1_INDEPENDENT_REVIEW.md)
- [`docs/phase1/FILESYSTEM_CAPABILITY_VALIDATION.md`](FILESYSTEM_CAPABILITY_VALIDATION.md)
- Experiment source code and harnesses under `experiments/phase1/filesystem-publication/`:
  - `test_f11_01_mutability.ps1`
  - `test_exclusive_zero_window.ps1`
  - `test_path_containment.rs`
  - `race_worker.rs`
  - `test_independent_process_race.ps1`
  - `termination_worker.ps1`
  - `test_process_termination.ps1`
  - `test_cross_volume_staging.ps1`

---

## 1. Executive Summary & Review Decision

### Review Decision: **APPROVED WITH CONDITIONS**

Increment 1.2 significantly advanced the technical and empirical foundation of Sentra's filesystem publication model:
1. **Multi-Process Concurrency (F-11-03):** The independent process race harness (`test_independent_process_race.ps1` + `race_worker.rs`) demonstrated that NTFS directory locking genuinely serializes concurrent publishers: across 20 independent rounds with 10 concurrent OS processes (200 executions), exactly 1 process won and exactly 9 failed closed with Win32 Error 183 (`ERROR_ALREADY_EXISTS`), preserving destination integrity with zero byte corruption.
2. **Process Termination Recovery (F-11-03):** Forced termination injection (`kill -9`) across 7 distinct lifecycle boundaries in `test_process_termination.ps1` proved deterministic post-crash state: uncommitted staging files are safely reclaimed, while successfully linked destination blobs remain intact.
3. **Component Path Containment (F-11-02):** The Rust probe `test_path_containment.rs` empirically proved the failure modes of naive string prefix checks (verbatim `\\?\` mismatch, separator mismatch, and case-sensitivity failure) and validated a component-based parsing algorithm (`Path::components()`).
4. **Cross-Volume Protocol:** `test_cross_volume_staging.ps1` verified that destination-volume staging followed by same-volume hard-linking enables cross-volume publication without resorting to destructive copy-and-replace fallbacks.
5. **Scoped Rename (F-11-05):** Narrowing the prohibition of `std::fs::rename` strictly to CAS publication while permitting it in private staging resolved F-11-05 appropriately.

### Critical Adversarial Disagreements & Conditions:
However, an adversarial security audit reveals that Increment 1.2's claim of **"Complete Immutability Closure with Zero Race Window" (F-11-01)** is overstated under the documented Windows threat model:
- **Finding F-13-01 (Medium): Unclosed Post-Publish Race Window.** In the proposed 7-step sequence, Step 5 closes the exclusive handle *before* Step 7 sets `FILE_ATTRIBUTE_READONLY`. In the interval between handle closure and attribute setting, the destination blob is completely unlocked and accessible in the filesystem; a concurrent process can open it for write access. Furthermore, once opened, an open write handle continues to write even after `FILE_ATTRIBUTE_READONLY` is set.
- **Finding F-13-02 (Medium): `FILE_ATTRIBUTE_READONLY` is Advisory Against Same-User Adversaries.** In Windows security architecture, `FILE_ATTRIBUTE_READONLY` is a legacy DOS attribute, not an Access Control Entry (ACE). Any process running under the same user token can invoke `SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL)` without administrative elevation. It prevents *accidental* self-modification, but provides zero protection against a hostile process in the same user session.
- **Finding F-13-03 (Low): Component-Based Containment Does Not Prevent TOCTOU Reparse Substitution.** `Path::components()` parses path strings lexically. It does not protect against an active adversary replacing an intermediate directory with a junction/symlink between validation and handle creation.
- **Finding F-13-04 (Low): Cross-Volume Protocol Relies on Unverified Cryptographic Integrity.** The cross-volume staging test verified byte count equality, but did not compute a cryptographic hash because SHA-256 remains an unresolved dependency blocker.

**Phase 1 remains NOT APPROVED. Phase 2 remains UNAUTHORIZED.** Production implementation must not begin until the conditions in Section 8 are addressed.

---

## 2. Git State & Repository Baseline

The repository was verified prior to review:
- **Branch:** `develop`
- **Reviewed HEAD:** `13ee13b467c43e985572b848fcf2e296965966fd` (*"Document filesystem security experiments"*, Taiizor, 2026-11-08 18:40:22 +0300).
- **Commit Ancestry:** `8d36d43 → 4bd8618 → d9cca25 → adc3cf2 → ad0b7bb → e1ca3e7 → 628d558 → 13ee13b`
- **Upstream:** `origin/develop` (0 ahead / 0 behind).
- **Physical Index SHA-256:** `F5B4A7FF5499D3F0986EB759EA3645E1BEF6FA7BBF8D5C833D7CAA912944A732`
- **Index Tracked Entries:** 301.
- **Working Tree:** Completely clean prior to this review. Zero agent Git mutations.

---

## 3. Adversarial Analysis of F-11-01 & "Zero-Window" Immutability

### 3.1 The Post-Closure Race Gap
Increment 1.2 proposed the following sequence:
```text
1. Create staging file (CREATE_NEW, share_mode = 0).
2. Write content and flush.
3. Verify content while exclusive handle remains open.
4. Create hard link to CAS destination while handle remains open.
5. Close exclusive handle.
6. Delete staging name.
7. Set FILE_ATTRIBUTE_READONLY on destination.
```

**Adversarial Examination of the Step 5 $\rightarrow$ Step 7 Transition:**
1. At Step 4, `CreateHardLinkW` creates the destination directory entry pointing to the MFT record. While the exclusive handle (`share_mode = 0`) is held, no process can open either the staging link or the destination link.
2. At Step 5, the exclusive handle is closed. **The exclusive kernel share reservation is completely released at this exact microsecond.**
3. At this moment:
   - The destination file `<blobs>/<hash>.blob` exists and is visible in the directory index.
   - It does **NOT** yet have `FILE_ATTRIBUTE_READONLY` set (that occurs in Step 7).
   - The staging alias `<staging>/<uuid>/content.tmp` is **NOT** yet deleted (that occurs in Step 6).
4. If a concurrent process opens `<blobs>/<hash>.blob` (or `<staging>/<uuid>/content.tmp`) with `GENERIC_WRITE` between Step 5 and Step 7, **the open succeeds**.
5. Crucially, as proven by EXP-MUT-05 in `test_f11_01_mutability.ps1`:
   ```text
   WriteViaOpenHandleBypassesReadOnly: true
   ```
   Windows performs access checks when the handle is opened. Once an adversary acquires an open write handle during the Step 5–Step 7 gap, subsequently applying `FILE_ATTRIBUTE_READONLY` in Step 7 **does not revoke or block writes through that open handle**. The adversary can mutate the blob at any point thereafter.

**Independent Empirical Verification:**
Independent execution confirmed that `SetFileAttributesW(stageFile, FILE_ATTRIBUTE_READONLY)` **can be called while the exclusive handle is still open**.
> **Correction Required:** Step 7 must be moved **before** Step 5! Specifically:
> - Step 4: `CreateHardLinkW`
> - Step 5 (NEW): `SetFileAttributesW(cas_destination, FILE_ATTRIBUTE_READONLY)` *while the exclusive handle is still held*.
> - Step 6: Close exclusive handle.
> - Step 7: Delete staging link.

---

### 3.2 Evaluation of Threat Models

The security claims must be decoupled across distinct threat models:

| Threat Model | Protected by Design? | Evaluation & Vulnerabilities |
| :--- | :---: | :--- |
| **1. Accidental Self-Modification by Sentra** | **YES (Fully Protected)** | Sentra opens blobs read-only and hashes content; `FILE_ATTRIBUTE_READONLY` blocks accidental write opens. |
| **2. Concurrent Cooperative Processes (Same User)** | **PARTIALLY (Conditional)** | Protected if Step 7 is moved before Step 5. If Step 5 closes before attribute setting, a race window exists. |
| **3. Hostile Process (Same User Privileges)** | **NO (VULNERABLE)** | In Windows security, `FILE_ATTRIBUTE_READONLY` is an advisory attribute. Any unprivileged process running under the same user account can invoke `SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL)` and overwrite the blob. It is not an ACL or security boundary. |
| **4. Administrative / Elevated Process** | **NO (VULNERABLE)** | Administrators bypass file permissions via `SeBackupPrivilege` and `SeTakeOwnershipPrivilege`. |

**Conclusion:** Increment 1.2's claim of "content immutability" is valid **only against cooperative/accidental modification**, NOT against a malicious process running with the same user token.

---

### 3.3 Evaluation of Alternative Architectures for True Immutability

Without implementing them, the following alternatives were evaluated:
1. **DACL Hardening (Deny Write ACEs):**
   - Windows allows applying a Discretionary Access Control List (DACL) that explicitly denies `FILE_WRITE_DATA`, `FILE_APPEND_DATA`, and `WRITE_DAC` to the current user.
   - *Limitation:* The Windows Security Reference Monitor automatically grants `WRITE_DAC` to the owner of an object, regardless of the DACL. An unprivileged owner can always reset their own DACL unless ownership is transferred to another principal.
2. **Dedicated Service Architecture:**
   - Run a background storage daemon under a separate service account (`NT SERVICE\SentraBlobService`). Only the service account has write permissions to `<storage>/blobs/`. The user process only has read permissions.
   - *Limitation:* Mandates administrative installation and inter-process communication (IPC). Outside the unprivileged local CLI profile.
3. **Immutable Content Stored in Content-Addressable Archive (Packfiles / SQLite Read-Only):**
   - Store blobs inside append-only, signed packfiles or SQLite databases with WAL checkpoints, verified via Merkle trees.

---

## 4. Adversarial Audit of F-11-02 (Component Path Containment)

The Rust implementation `test_path_containment.rs` successfully passed 9 tests, proving that:
- Case-folding is necessary for Windows path components.
- Stripping `\\?\` verbatim prefixes avoids prefix comparison failure.
- Checking parent canonicalization is required for nonexistent target paths.

**Adversarial Limitation:**
`Path::components()` is a **purely lexical parsing mechanism**. It does NOT provide TOCTOU protection:
- If a directory component is verified to be a normal directory, an adversary with write access to the parent folder can rename that directory and replace it with a NTFS Junction (`reparse point`) between the time `is_strictly_contained()` returns `true` and the time `CreateFileW` is called.
- Therefore, component containment is secure **only within directories where the current user/process has exclusive write permissions and untrusted actors cannot modify directory entries**.
- Full TOCTOU immunity requires handle-based relative opening (`FILE_FLAG_OPEN_REPARSE_POINT`), which remains **Blocked** in safe Rust due to `E0658` and `#![forbid(unsafe_code)]`.

---

## 5. Audit of F-11-03 (Process Races and Crash Injection)

### 5.1 Multi-Process Concurrency Verification
- Inspected `race_worker.rs` and `test_independent_process_race.ps1`.
- The test correctly spawned 10 independent OS processes via `[System.Diagnostics.Process]::Start` in 20 distinct rounds.
- Each round used a fresh directory, preventing cross-round contamination.
- The destination content was strictly validated against the single winner.
- **Finding:** The kernel-level NTFS directory lock reliably serializes atomic `CreateHardLinkW` calls with zero double-writes.

### 5.2 Process Termination Verification
- Inspected `termination_worker.ps1` and `test_process_termination.ps1`.
- Forced termination (`Process::Kill()`) was injected at boundaries 1 through 7.
- Recovery logic safely distinguished uncommitted staging files (Boundaries 1–4) from published blobs (Boundaries 5–7).
- **Limitation:** The recovery logic was executed by the test controller script. Because Phase 1 has no production Core Engine implementation, automated crash recovery remains a design specification rather than an integrated production service feature.

---

## 6. Audit of Cross-Volume Staging Protocol

Inspected `test_cross_volume_staging.ps1`:
- Streamed payload from C: to E: staging.
- Executed same-volume hard link on E:.
- Correctly verified collision rejection with Error 183.
- **Limitation:** Integrity was checked via `(Get-Item $stageFileE).Length -eq $payload.Length`. Byte-count equality is not cryptographic verification. Cryptographic hash verification remains **Blocked** pending SHA-256 dependency selection.

---

## 7. Formal Review Findings

### F-13-01 (Medium): Unclosed Race Window Between Handle Closure and Read-Only Setting
- **Affected Contract:** `FILESYSTEM_CAPABILITY_CONTRACT.md` Section 3.2 & Section 4.2.
- **Evidence:** Step 5 closes the exclusive handle while Step 7 applies `FILE_ATTRIBUTE_READONLY`. In that gap, the destination is unlocked and writable. An open write handle obtained in that gap can continue writing even after Step 7.
- **Impact:** Cooperative or concurrent processes racing to open the new blob can acquire write access.
- **Required Remediation:** Move `SetFileAttributesW(..., FILE_ATTRIBUTE_READONLY)` *before* closing the exclusive handle. Windows permits setting attributes on files with open exclusive handles.

---

### F-13-02 (Medium): Overstated Immutability Against Same-User Adversaries
- **Affected Document:** `INCREMENT_1_2_FILESYSTEM_SECURITY_CLOSURE.md` Section 1 & Section 3.1.
- **Evidence:** Any unprivileged process running under the same user SID can invoke `SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL)` and overwrite published blobs.
- **Impact:** Claiming the blob is "immutable" without qualifying the threat model creates a false sense of cryptographic/OS-enforced security.
- **Required Remediation:** Explicitly qualify the immutability boundary: Sentra guarantees immutability against *accidental modification and cooperative concurrency*, but cannot guarantee immutability against an active hostile process in the same user session without separate service credentials.

---

### F-13-03 (Low): Component-Based Path Containment Does Not Protect Against Directory Swap TOCTOU
- **Affected Contract:** `FILESYSTEM_CAPABILITY_CONTRACT.md` Section 5.
- **Evidence:** `Path::components()` is lexical. Swapping a parent directory with a junction between check and open is possible in shared/untrusted directories.
- **Impact:** Staging containment requires that the staging root directory itself is private and non-writable by untrusted actors.
- **Required Remediation:** Document that path containment guarantees apply only when the staging root resides within a private, access-controlled directory.

---

### F-13-04 (Low): Cross-Volume Integrity Relies on Unchecked Byte Count
- **Affected Document:** `INCREMENT_1_2_FILESYSTEM_SECURITY_CLOSURE.md` Section 4.
- **Evidence:** Cross-volume staging verification checked length equality without computing a cryptographic digest because SHA-256 remains blocked.
- **Impact:** Partial copy corruption is detectable by length, but bit-flips or in-flight mutations are not cryptographically detected.
- **Required Remediation:** Retain SHA-256 as a mandatory gate before enabling production cross-volume staging.

---

## 8. Corrected Filesystem Capability Matrix

| Capability / Primitive | Native Win32 API | Rust Std API | Review Classification | Boundary & Operational Conditions |
| :--- | :--- | :--- | :---: | :--- |
| **No-Replace CAS Publication** | `CreateHardLinkW` | `std::fs::hard_link` | **Verified & Approved** | Single-volume NTFS. Error 183 collision rejection verified in 200 process trials. |
| **Zero-Window Content Immutability** | Exclusive handle + link + attr | `OpenOptionsExt` | **Approved with Conditions (F-13-01, F-13-02)** | Must set ReadOnly *before* closing exclusive handle. Protects against accidental/cooperative changes only. |
| **Multi-Process Concurrency** | NTFS directory lock | `std::fs::hard_link` | **Verified & Approved** | 20 rounds x 10 processes verified. Exactly 1 winner, 9 collisions. |
| **Process Crash Recovery** | Staging isolation + recovery | Standard cleanup | **Verified & Approved** | 7 termination boundaries tested. Reclaims stage; preserves intact destination. |
| **Component Path Containment** | `Path::components()` | `std::path::Component` | **Approved with Conditions (F-13-03)** | Lexical containment verified; requires private staging root to prevent directory swap TOCTOU. |
| **Cross-Volume Publication** | Destination staging + link | Stream copy + link | **Approved with Conditions (F-13-04)** | Protocol verified; cryptographic integrity verification requires SHA-256 resolution. |
| **Scoped Rename Restriction** | `MoveFileExW` | `std::fs::rename` | **Verified & Approved** | Prohibited for CAS publication; permitted in private staging. |
| **By-Handle File ID Query** | `GetFileInformationByHandle` | `windows_by_handle` | **BLOCKED (E0658)** | Unstable in stable Rust std. Prohibited by `#![forbid(unsafe_code)]`. |
| **Power-Loss Hardware Durability** | Hardware write-through | `File::sync_all` | **BLOCKED / UNSUPPORTED** | Unverifiable on consumer SSDs without power-cut test equipment. |
| **Cryptographic SHA-256 Digest** | Hash computation | External crate | **BLOCKED** | Retained dependency blocker from Increment 0.2. |

---

## 9. Production-Readiness & Phase 1 Boundary

### **Phase 1 Status: NOT APPROVED**
### **Phase 2 Status: UNAUTHORIZED**

The technical investigations in Increments 1.0, 1.1, 1.2, and 1.3 have established a rigorous understanding of Windows NTFS filesystem publication primitives. However, Phase 1 closure cannot be approved because:
1. Production storage engine implementation has not begun.
2. Finding F-13-01 (moving attribute setting before handle close) must be incorporated into design contracts.
3. Cryptographic SHA-256 hashing remains **Blocked** (Increment 0.2).
4. Direct by-handle File ID inspection remains **Blocked** (E0658).
5. Interrupted bootstrap recovery (F-611-02) and single-session project identity (OQ-25) remain open.
6. ADR-0008, ADR-0009, and ADR-0010 remain **Proposed**.

---

## 10. Conditions and Stop Criteria for Future Increments

Before any storage provider implementation is authorized:
1. **Condition 1 (Order of Attribute Application):** The storage contract must mandate that `SetFileAttributesW(..., FILE_ATTRIBUTE_READONLY)` is executed *before* the exclusive handle is closed.
2. **Condition 2 (Threat Model Qualification):** The architectural documentation must explicitly define the threat model: publication immutability guarantees apply against accidental modification and cooperative concurrent processes; protection against hostile processes in the same user session requires out-of-process credential isolation.
3. **Condition 3 (Cryptographic Prerequisite):** No content-addressed storage implementation may be admitted without an approved, verified SHA-256 implementation.
4. **Stop Criteria:** Stop immediately after this review. Do not implement production code, tests, or schema modifications.
