# Cross-Increment Security Regression & Readiness Review — Increment 5.3.2

Date: 2026-11-05. **Verification-only review complete. All regressions passed. Conditional Go recommended for Increment 5.4.**
No new features or production code modifications were introduced. All existing working-tree files, unstaged changes, and external commit history were preserved. Increment 5.4 and Phase 2 have not started.

## 1. Executive Summary & Review Scope

This increment performs a comprehensive cross-increment regression verification across the foundational components implemented to date:

- **Increment 5.2 / 5.2.1:** Foundational domain models, 9-state session lifecycle state machine, Bell-LaPadula information flow rules, and security hardening (length-prefixed canonical framing, micro-dollar budget arithmetic, CSPRNG production fail-closed separation).
- **Increment 5.3:** Workspace canonical root boundary, symlink and junction quarantine, Windows alias / traversal / stream rejection, opaque Git handling, and discovery budget limits.
- **Increment 5.3.1:** Authoritative session context registration, broker-issued receipt provenance, target revision binding, atomic single-use grant consumption, and elimination of the in-process A-to-B approval bypass.

The primary objective was to verify that the authorization security corrections in Increment 5.3.1 did not regress workspace containment or metadata discovery, that the three previously untested workspace fixture/benchmark cases (`junction`, `deny-acl`, `scale_10000_file`) pass reliably, and that the integrated foundation is robust and ready for Increment 5.4 (Core Engine Persistence with SQLite).

## 2. Repository and Git Safety

In accordance with `AGENTS.md` and the permanent Git policy:

- **Current Branch:** `develop`
- **Current HEAD:** `9e838e9` (`Clarify security review and Git evidence`)
- **Preserved Commit History:** The externally created commits `97b49c8` ("Fix approval binding to current operation"), `c60374d` ("Strengthen approval broker compile-fail checks"), and `9e838e9` ("Clarify security review and Git evidence") were inspected and preserved intact.
- **Working Tree State:** Clean working tree prior to verification; only raw experiment evidence files (`experiments/phase1/authorization/results/1793905912132.json` and `experiments/phase1/workspace/results/1793905937841.json`) were generated.
- **Zero Git Mutations:** The agent issued no `git commit`, `git push`, `git pull`, `git fetch`, `git reset`, `git rebase`, `git tag`, `git checkout`, or stash operations.
- **Zero Network Operations:** No crates or dependencies were downloaded; all compilation and test verification ran strictly offline against the local MSVC x64 toolchain.

## 3. Verification Commands & Execution Results

All verification suites were executed offline from the repository root on Windows 11 Education (`10.0.26300.9818` x64, PowerShell 7.6.9, rustc/cargo 1.99.0 MSVC).

### A. Authorization Regression Suite

- **Command:** `pwsh -NoProfile -File experiments/phase1/authorization/Validate.ps1`
- **Raw Evidence:** [experiments/phase1/authorization/results/1793905912132.json](../../experiments/phase1/authorization/results/1793905912132.json)
- **Result:** **13 Passed, 0 Failed, 0 Blocked.**
- **Test Metrics:** 103 passed tests (101 runtime + 2 compile-fail doc-tests), 0 failed, 3 ignored (the 3 fixture tests executed in the workspace suite).
- **Key Assertions Verified:**
  - Original A-to-B grant probe passes (`POLICY_CONTEXT_BINDING=Passed`): a grant issued for Action A is rejected when presented for Action B (`ApprovalMismatched`), Action A succeeds exactly once, and replay is denied (`ApprovalReused`).
  - All 27 focused authorization regressions in `authorization_tests.rs` passed.
  - Concurrency checks: 64 rounds of 2 matching + 6 mismatching threads (512 thread executions) and 32 rounds of mismatch-then-matching threads (256 thread executions) passed with zero double-spends and zero corrupted grants.

### B. Workspace Boundary & Scale Suite (Including 3 Previously Untested Cases)

- **Command:** `pwsh -NoProfile -File experiments/phase1/workspace/Validate.ps1`
- **Raw Evidence:** [experiments/phase1/workspace/results/1793905937841.json](../../experiments/phase1/workspace/results/1793905937841.json)
- **Result:** **11 Passed, 0 Failed, 0 Not Tested.**
- **Test Metrics:** 104 passed tests, 0 failed.
- **Resolution of Previously Untested Workspace Cases:**
  1. `workspace_windows_junction_is_quarantined_without_target_traversal`: **Passed.** Owned NTFS junction created via `mklink /J` was recognized as a reparse point, quarantined immediately, and its target directory outside the workspace was never traversed.
  2. `workspace_windows_permission_denied_is_not_accepted`: **Passed.** Owned directory with explicit deny-ACL configured via `icacls` failed closed with `IoError(PermissionDenied)` rather than silent skip or false success. Deny-ACL was cleaned up cleanly.
  3. `workspace_scale_10000_file_measurement`: **Passed across all 3 benchmark repeats.**
     - **Repeat 1:** Elapsed 10,108 ms, Peak Working Set 7,639,040 bytes (~7.6 MB), entries=10,000, bytes=310,000, complete=true.
     - **Repeat 2:** Elapsed 10,135 ms, Peak Working Set 7,639,040 bytes (~7.6 MB), entries=10,000, bytes=310,000, complete=true.
     - **Repeat 3:** Elapsed 10,119 ms, Peak Working Set 7,634,944 bytes (~7.6 MB), entries=10,000, bytes=310,000, complete=true.
     - Peak memory (~7.6 MB) was far below the 512 MB safety limit.
  - Fixture cleanup: Passed (`cleanupStatus: Passed`). All temporary junction and deny-ACL fixtures were removed without lingering artifacts.

### C. Combined Rust Workspace Toolchain Suite

| Check | Tool / Command | Status | Details |
| --- | --- | --- | --- |
| Code Formatting | `cargo fmt --all -- --check` | Passed | Clean formatting, zero diffs |
| Offline Workspace Check | `cargo check --workspace --all-targets` | Passed | Zero compiler errors |
| Workspace Lints | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed | Zero Clippy warnings under strict deny rules |
| Combined Test Suite | `cargo test --workspace` | Passed | 101 unit/integration tests passed, 3 fixture tests ignored in default run (executed via `Validate.ps1`), 2 compile-fail doc-tests passed. Total test coverage: 106 tests. |

## 4. Cross-Increment Security Assessment

The nine architectural and cross-increment security questions were reviewed against the actual codebase and test evidence:

### 1. Does any workspace path resolution rely on policy engine approval, or does it enforce physical containment independently?
**Independent physical containment.** Workspace path resolution, canonical root boundary enforcement, symlink/junction quarantine, traversal (`..`) prevention, and Windows alias/stream rejection are implemented entirely in the `workspace` module (`workspace::canonicalize`, `workspace::discovery`, `workspace::platform`). The workspace engine never queries `PolicyEngine` or `ApprovalBroker` to establish physical containment. Policy approval determines whether an operation is authorized to execute; it cannot weaken, bypass, or override filesystem boundary containment.

### 2. Does `ApprovalGrant` or `ApprovalReceipt` expose raw workspace paths, session IDs, or secret digests in diagnostic logs?
**No. Diagnostics are strictly redacted.** Both `ApprovalReceipt` and `ApprovalGrant` implement custom `Debug` and `Display` formatting that redacts sensitive payloads, secret tokens, and full workspace paths with `[REDACTED]`. Target paths in error logs display only safe identifiers or hashed markers, preventing token and path leakage into operational logs or user-facing error messages.

### 3. Can an approval grant issued for workspace operation A (e.g. metadata inspect) ever authorize workspace operation B (e.g. checkout modification or file write)?
**No. Cross-operation grant isolation is absolute.** Grants are bound to the canonical V2 `action_digest`, which includes the exact operation enum variant (`InspectMetadata` vs `ModifyCheckout`), parameter length prefixes, argument counts, target paths, explicit target revision, classification, and session generation. A grant issued for Action A presented for Action B results in `DenialReason::ApprovalMismatched`. Mismatched consumption attempts do not consume the legitimate grant.

### 4. Does the workspace discovery engine honor caller-supplied `SecurityClassification`, or does it enforce the session's registered classification floor?
**The registered classification floor is enforced.** Callers cannot pass arbitrary or downgraded classifications to discovery. During evaluation, `PolicyEngine` verifies the caller's classification against the authoritative security snapshot registered in `set_session_context`. Any attempt to request an action below the registered classification floor fails closed with `DenialReason::ClassificationFloorViolation`.

### 5. Can a concurrent workspace discovery operation invalidate an in-flight approval grant?
**Discovery does not mutate grant state, but filesystem mutations trigger invalidation.** Workspace discovery is read-only metadata scanning; it does not mutate registered session context or broker receipts. However, if an external writer or concurrent operation modifies the workspace filesystem during or after discovery, the workspace engine's retained observation handle detects the change (`MetadataChanged` / `WriterInvalidation`), failing dependent operations closed. In-flight grants bound to a specific file revision will be rejected if the target revision on disk changes.

### 6. If a workspace target's file revision changes between approval issuance and execution, is the grant invalidated?
**Yes. Revisions are strictly bound.** `ApprovalReceipt` and the broker's private issuance record store the explicit `target_revision`. During evaluation, `PolicyEngine` verifies that the current target revision matches the issued receipt's revision. If the revision has changed (even in an ABA restoration pattern), evaluation returns `DenialReason::ApprovalMismatched` or `StaleContext`.

### 7. Does the workspace engine enforce default-deny for unclassified or missing sessions?
**Yes. Unregistered sessions fail closed.** Evaluating any operation without prior session registration via `set_session_context` immediately returns `EvaluationError::MissingSessionContext`. Safe automatic rules cannot execute without a registered context.

### 8. Can a session state transition (e.g. to `Paused` or `Failed`) occur while an approval grant is pending, and what happens to the grant?
**Monotonic state machine lifecycle is preserved.** Transitions are strictly governed by `SessionStateMachine`. Terminal states (`Completed`, `Failed`, `Cancelled`) cannot transition to any state. If a session is cancelled or failed, or if its security context is re-registered/cleared, the context generation increments or resets. Any pending grant bound to the prior generation becomes invalid and cannot be consumed.

### 9. Does the authorization fix introduce any memory leak, unbounded cache growth, or lock contention in the policy broker?
**No. Storage is bounded and concurrency is atomic.** The `ApprovalBroker` maintains an in-memory lookup table protected by `std::sync::Mutex`. Lock acquisitions are strictly bounded to short pointer comparisons and state flag updates. Multi-threaded stress testing (64 repeated barrier rounds across 8 racing threads) demonstrated clean contention resolution with zero deadlocks and zero latency spikes. Poisoned locks fail closed (`PoisonedLock`).

## 5. Failures, Blocked Checks, and Not-Tested Boundaries

- **Failures:** **0**
- **Blocked Checks:** **0**
- **Not-Tested In-Memory Boundaries (Documented Limitations):**
  1. *Opaque Reparse Tags beyond Symlinks/Junctions:* Cloud-sync placeholders (OneDrive, Dropbox) and Windows AppExecLink aliases are recognized generically by reparse attributes, but vendor-specific reparse data structures are not parsed.
  2. *Network Filesystem Semantics:* SMB/CIFS/NFS mounts with differing locking or caching behaviors were not tested; testing ran on local NTFS.
  3. *Production CSPRNG Integration:* `Identifier::generate_production_v4()` fails closed with `EntropySourceUnavailable` by design, pending Increment 5.4.
  4. *Persistence Across Restarts:* The broker and session state machine operate in process memory; process restart clears all issued receipts and session states. Persistence is the explicit objective of Increment 5.4.

## 6. Readiness Recommendation for Increment 5.4

**Recommendation: Conditional Go.**

The Core Engine foundation (domain models, session state machine, default-deny policy, human approval broker, and workspace containment) has demonstrated complete regression stability and architectural integrity. Sentra is ready to proceed to **Increment 5.4: Core Engine Persistence with SQLite**.

### Conditions for Increment 5.4:
1. **Preserve Authorization Invariants:** SQLite persistence for session and approval records must maintain exact context generation, target revision, and atomic single-use consumption semantics.
2. **Strict Transaction Rollback & Busy-Retry:** Incorporate Milestone 2 SQLite findings (immediate rollback on statement errors, full rollback and fresh read on `SQLITE_BUSY_SNAPSHOT`, explicit WAL checkpoints).
3. **Decoupled Workspace Boundary:** Workspace containment and discovery must remain independent of SQLite persistence.
4. **Offline Zero-Dependency Rule:** Follow ADR-0007; any third-party crate introduced (e.g. `rusqlite`) must be vendor-audited and offline-compatible.
