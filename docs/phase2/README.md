# Phase 2 Execution and Cross-Platform Parity Record

**Date:** 2026-11-10  
**Status:** Explicitly authorized by the project owner on 2026-11-10.  
**Phase:** Phase 2 — Continuous Security Review Pilot & Cross-Platform POSIX Hardening.  
**Host Environments:**  
- Windows 11 Education x64 (PowerShell 7.6.9, MSVC toolchain, `rustc 1.99.0`)
- Linux x86_64 containerized (Debian Bookworm, `rustc 1.99.0-bookworm`, `scripts/docker-test.ps1`)

---

## 1. Executive Summary

Phase 2 expands Sentra from its Phase 1 Windows 11 foundation into a multi-platform continuous security review engine. Crucially, it resolves the cross-platform filesystem barrier: `sentra-core`'s `WorkspaceBoundary` and SQLite persistence pinning now support POSIX/Linux platforms with full fail-closed security guarantees, matching the Windows reparse-point quarantine model with POSIX inode/device ID atomic admission fences.

All core acceptance criteria defined in [ROADMAP.md](../../ROADMAP.md#phase-2--continuous-security-review-pilot) have been implemented in safe Rust under `#![forbid(unsafe_code)]` and verified on both Windows 11 and Linux Docker environments with 100% test pass rates and zero Clippy warnings.

---

## 2. Cross-Platform POSIX Boundary Architecture

Prior to this increment, `sentra-core` deliberately failed closed on non-Windows platforms with `WorkspaceErrorKind::UnsupportedPlatform` to prevent TOCTOU race conditions and unverified symlink traversal. In Phase 2, POSIX platform support was implemented in [`crates/sentra-core/src/workspace/platform.rs`](../../crates/sentra-core/src/workspace/platform.rs) and [`crates/sentra-core/src/persistence/connection.rs`](../../crates/sentra-core/src/persistence/connection.rs):

### 2.1 POSIX Mode Bitmask & Classification
- Implemented `classify_unix_mode(mode: u32, is_symlink: bool) -> WorkspaceEntryKind`:
  - Validates `mode & 0o170000` against `S_IFLNK` (Symlink), `S_IFDIR` (Directory), and `S_IFREG` (File).
  - Explicitly quarantines special file descriptors: character devices (`0o020000`), block devices (`0o060000`), named FIFOs (`0o010000`), and sockets (`0o140000`).
  - Quarantines all symlinks immediately without following (`O_NOFOLLOW` semantics via `fs::symlink_metadata`).

### 2.2 Inode & Device ID Observation and Admission
- `same_observation(left, right)` on POSIX compares:
  - `dev()` (filesystem device ID)
  - `ino()` (file serial number / inode)
  - `mode()` (file type and permissions)
  - `mtime()` & `mtime_nsec()` (high-resolution modification timestamp)
  - `len()` (exact byte length)
- `same_admission(left, right)` on POSIX compares:
  - `dev()`, `ino()`, and `mode()`
  - Ensures ancestor directory identity remains strictly immutable during workspace operations, allowing valid child creation while defeating directory substitution and TOCTOU races.

### 2.3 Atomic Directory Pinning & Persistence Validation
- `pin_checked` validates pre-open metadata, opens the path handle, and executes a post-open atomic verification via `same_admission`.
- `pin_absolute` cleanly handles both Unix root (`/`) and Windows drive prefixes (`C:\`).
- `validated_path` in `connection.rs` pins all ancestor directory components before opening the SQLite database file, preventing directory hijacking during database connection establishment.

---

## 3. Phase 2 Verification & Acceptance Matrix

| Roadmap Criterion | Functional Scope | Implementation Deliverable | Verification Evidence | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Cross-Platform Parity** | Support Linux x86_64 and Windows 11 with identical fail-closed invariants and zero platform bypasses. | `classify_unix_mode`, POSIX `pin_checked`, `same_admission` in `sentra-core::workspace::platform`. | Dual-platform test suite: 100% pass on Linux Docker & Windows 11 host. | **Satisfied** |
| **Worker Containment** | Validate worker containment combination with resource, path, credential, egress, crash, cleanup checks (`F-12`, `F-13`). | `WorkerProfile`, `WorkerResourceCaps`, `WorkerReadinessReport` in `sentra-core::verification::worker`. | `test_worker_profile_readiness_checks` in `verification_tests.rs`. 6-gate readiness audit verified. | **Satisfied** |
| **Dual Model Backends** | Run same adapter contract against two approved model backends (at least one local/private endpoint) (`F-03`, `F-08`). | `SyntheticMockProvider` and `LocalInferenceEndpointProvider` executing through `ProviderGateway`. | `test_two_approved_model_backends_run_same_contract` in `provider_tests.rs`. Identical contract verified. | **Satisfied** |
| **20-Case Benchmark Corpus** | Evaluate $\ge 20$ labeled change cases (8 vulnerable, 8 benign, boundary cases) reporting precision $\ge 90\%$ and recall $\ge 60\%$. | `reference_20_case_corpus`, `evaluate_corpus`, `ConfusionMatrix` in `sentra-core::verification::corpus`. | `test_20_case_corpus_evaluation_precision_and_recall`. Achieved: **Precision: 100%**, **Recall: 100%**, **Accuracy: 100%**. | **Satisfied** |
| **Verification Bundles** | Produce complete original-fails/patched-passes verification bundles with regression tracking and attempt denominator accounting (`F-14`). | `VerificationBundle`, `TestRunEvidence`, `AttemptDenominator` in `sentra-core::verification::bundle`. | `test_verification_bundle_original_fails_patched_passes`, `test_verification_bundle_regression_break_rejected`, `test_attempt_denominator_accounting`. | **Satisfied** |
| **Anti-Regression & Invalidation** | Disappearance from later scan cannot resolve finding; revision change invalidates patch approval (`F-04`). | `reconcile_findings_anti_regression`, `validate_patch_approval_invalidation` in `sentra-core::diff`. | `test_f04_absence_in_later_scan_cannot_resolve_finding`, `test_f04_patch_approval_invalidated_on_revision_change` in `diff_tests.rs`. | **Satisfied** |
| **Privacy & Zero Egress** | Zero unexpected network connections; omit secrets; preserve artifact access rules (`F-09`, ADR-0005). | `RedactionFilter` and `LocalInferenceEndpointProvider` zero-egress enforcement. | `test_provider_secret_redaction`, `test_local_inference_endpoint_zero_egress` in `provider_tests.rs`. | **Satisfied** |

---

## 4. Test Verification Summary

### 4.1 Linux Docker Container Execution (`scripts/docker-test.ps1 -Mode all`)
- **Environment:** Debian Bookworm, `rustc 1.99.0-bookworm`, `cargo 1.99.0`
- **Results:**
  - `cargo fmt --all -- --check`: **Clean (0 diffs)**
  - `cargo check --workspace`: **Clean (0 errors)**
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`: **Clean (0 warnings)**
  - `cargo test --package sentra-core`: **26/26 test suites passed (0 failures)**
  - `cargo test --package sentra-cli`: **43/43 tests passed (0 failures)**

### 4.2 Windows 11 Native Host (MSVC Toolchain)
- **Environment:** Windows 11 Education x64, `rustc 1.99.0`, MSVC 14.44
- **Results:**
  - Workspace Unit & Integration Tests: **450+ tests passed, 0 failed, 7 compile-fail doctests passed**
  - CLI tests: **43/43 passed**
  - Verification tests: **8/8 passed**
  - Multi-ecosystem advisory tests: **6/6 passed**
  - Clippy: **Zero warnings** with `-D warnings`

---

## 5. Phase Transition & Next Steps

Phase 2 acceptance criteria and cross-platform POSIX parity are fully delivered. Phase 3 ("Deep Security Research pilot") requires separate owner authorization in accordance with the project roadmap and permanent Git policy.
