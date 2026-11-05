# Sentra Phase 1 — Increment 5.5.1: Independent Execution & Evidence Security Review

## 1. Executive Summary & Review Scope

This independent security, correctness, and regression audit reviews the **Increment 5.5 (Fail-Closed Execution Engine & Evidence Verifier)** implementation. The audit was conducted strictly as a verification-only increment: zero production code, public APIs, dependencies, or Git references were modified.

### 1.1 Scope of Review
- **Execution Engine & Boundaries**:
  - `crates/sentra-core/src/execution/backend.rs` (`ExecutionBackend`, `FailClosedBackend`, `SyntheticFixtureBackend`)
  - `crates/sentra-core/src/execution/engine.rs` (`ExecutionEngine`)
  - `crates/sentra-core/src/execution/scope.rs` (`ExecutionScope`)
  - `crates/sentra-core/src/execution/model.rs` (`ExecutionRequest`, `ExecutionResult`, `ResourceLimits`, `BackendCapabilities`)
  - `crates/sentra-core/src/execution/error.rs` (`ExecutionError`, `ExecutionErrorKind`)
- **Evidence Verification & Structural Bounds**:
  - `crates/sentra-core/src/evidence/verifier.rs` (`EvidenceVerifier`)
  - `crates/sentra-core/src/evidence/model.rs` (`EvidenceEnvelope`, `EvidenceMetadata`, `EvidenceArtifact`, `IntegrityVerificationStatus`)
  - `crates/sentra-core/src/evidence/error.rs` (`EvidenceVerificationError`, `EvidenceVerificationErrorKind`)
- **Cross-Increment Regression Points**:
  - Interaction with `persistence` (`SettlementStatus`, conservative budget reservation, atomic audit insertion).
  - Interaction with `policy` and `authorization` (approval grant binding, security classification flow).
  - Interaction with `workspace` (root canonicalization, symlink/junction quarantine).
- **Adversarial & Regression Verification Suite**:
  - Existing tests: `tests/execution_tests.rs` (8 tests), `tests/evidence_tests.rs` (9 tests).
  - New verification suite: `tests/execution_evidence_adversarial_tests.rs` (10 tests).

### 1.2 Final Review Decision
**APPROVED**.
The execution foundation and evidence verification contracts strictly preserve fail-closed isolation. Untrusted target execution is completely disabled, zero insecure fallbacks exist, synthetic fixtures are rigorously sandboxed, and evidence bounds and payload redactions are enforced. Five findings were identified (0 Critical, 0 High, 2 Low, 1 Low/Architectural, 2 Informational), none of which compromise the fail-closed boundary or block subsequent work.

---

## 2. Execution Boundary Security Review

### 2.1 Default Fail-Closed Behavior
- **Untrusted Workload Interception**: Verified that every `UntrustedTargetWorkload` request is rejected fail-closed by `FailClosedBackend` with `ExecutionErrorKind::BackendUnavailable` (`ExecutionError::untrusted_workload_disabled()`).
- **Engine Gating**: In `ExecutionEngine::dispatch()`, an untrusted workload is intercepted at Step 2 *before* dispatching to the configured backend whenever the backend lacks validated Hyper-V VM capabilities (`!caps.supports_untrusted || !caps.isolated_vm_available`).
- **Zero Fallback Paths**: Code inspection confirmed that neither `std::process::Command`, Windows API process creation (`CreateProcessW`), Docker CLI/daemon sockets, nor WSL2 interop commands exist in the execution crate.
- **Accurate Capabilities**: `FailClosedBackend` and `SyntheticFixtureBackend` explicitly declare `host_execution: false`, `docker_wsl_execution: false`, and `isolated_vm_available: false`.

### 2.2 Synthetic Fixture Isolation
- **Curated Identifiers Only**: In `SyntheticFixtureBackend::execute`, action dispatch matches only five explicitly hardcoded strings: `"synthetic:noop"`, `"synthetic:success"`, `"synthetic:failure"`, `"synthetic:timeout"`, and `"synthetic:cancelled"`, plus `"synthetic:evidence"`.
- **Injection Resistance**: Adversarial probes testing delimiter injection (`"; rm -rf /"`, `"&& whoami"`), path traversal (`"../synthetic:noop"`), NUL bytes (`"synthetic:noop\0"`), newlines, and case variations were all rejected with `ExecutionErrorKind::InvalidRequest`.
- **Argument Disregard**: The synthetic backend returns simulated in-memory metrics (`duration_millis: 1`, `exit_code: Some(0)`) and completely ignores caller-provided argument vectors, preventing command injection or dynamic evaluation.
- **Scope Tampering Immunity**: Passing an untrusted workload scope with a valid fixture identifier (`tool_id: "synthetic:noop"`) is rejected fail-closed with `BackendUnavailable`.

### 2.3 Timeout and Cancellation Semantics
- **Synchronous In-Memory Stubs**: In Phase 1, `SyntheticFixtureBackend` simulates timeout (`ExecutionStatus::TimedOut`) and cancellation (`ExecutionStatus::Cancelled`) synchronously without spawning background threads or child processes.
- **Conservative Budget Preservation**: Probed integration with persistence: when an execution outcome is `TimedOut` or `Cancelled`, the settlement status maps to `SettlementStatus::CancelledUncertain` or `SettlementStatus::UncertainPartial`. Because `actual_cost()` is `None`, zero unconsumed budget is released, preserving the upper-bound reservation invariant.
- **Late Response Interception**: In Phase 1 synchronous dispatch, race conditions between completion and cancellation cannot occur because no background workers are running. The need for an asynchronous cancellation interface (`cancel(&self, execution_id)`) was noted as an architectural finding for Phase 2 (F-551-02).

### 2.4 Policy and Session Integration
- `ExecutionEngine` functions as an isolated execution coordinator. It does not accept forged authorization tokens or claim policy authority. Full orchestration requiring `PolicyEngine::authorize` and `ApprovalBroker::consume` prior to dispatch will reside in the application service layer (Increment 5.6).

---

## 3. Evidence Verifier Security Review

### 3.1 Size and Memory Safety
- **Ceiling Enforcement**: `MAX_EVIDENCE_SIZE_BYTES` is set to 52,428,800 bytes (50 MiB). In `EvidenceVerifier::verify_structural_bounds()`, payloads exceeding this ceiling are rejected with `EvidenceVerificationErrorKind::OversizedPayload`.
- **Length Matching**: Declared `payload_length_bytes` is checked against actual `payload.len()`. Truncation, padding, or empty payload declarations are rejected fail-closed.
- **Post-Allocation Observation**: `EvidenceEnvelope` takes an already-allocated `Vec<u8>`. For Phase 1 in-memory testing, this is safe, but bounded streaming ingestion is recommended for Phase 2 external artifact ingestion to prevent host OOM before verification (F-551-03).
- **Arithmetic Safety**: `actual_len = envelope.payload.len() as u64` is lossless on 64-bit systems and cannot overflow.

### 3.2 Content Integrity vs. Semantic Authenticity (ADR-0006)
- **Clear Verification Levels**:
  - `IntegrityVerificationStatus::StructuralBoundsVerified`: Admitted when structural bounds, length matching, and media-type formatting pass.
  - `IntegrityVerificationStatus::CryptographicallyVerified`: Reserved strictly for cryptographic hash verification.
- **Offline Cryptographic Gate**: When `declared_sha256` is present, `verify_envelope()` and `verify_transit_integrity()` fail closed with `CryptographicVerificationUnavailable`. A syntactically valid SHA-256 string is **never** accepted as proof of integrity.
- **Zero Weak Fallbacks**: No non-cryptographic hashes (CRC32, FNV, adler) were substituted.

### 3.3 MIME and Metadata Validation
- **Syntax Checks**: Media types must contain `/`, must not exceed 128 characters, and must not contain control characters or whitespace.
- **Policy Allowlist**: `EvidenceVerifier::with_allowed_media_types()` enforces an explicit whitelist.
- **Format vs. Semantic Content**: The verifier validates declared metadata formatting, not the semantic validity or magic numbers of the payload. For example, a payload labeled `application/json` is not parsed as valid JSON at the verification boundary; parser validation remains the responsibility of specific domain consumers.

### 3.4 Sensitive Data Protection
- **`Debug` Redaction**: `EvidenceEnvelope` implements custom `fmt::Debug` that replaces payload bytes with `"[REDACTED]"` and discloses only `payload_len_bytes`.
- **Diagnostic Formatting**: `ExecutionError` and `EvidenceVerificationError` contain safe diagnostic messages and do not leak confidential payload content.

---

## 4. Cross-Increment Regression Review

All previous security guarantees established in Increments 5.2, 5.3, and 5.4 were re-verified:
1. **Persistent Approval Single-Use**: Approval grants cannot be double-spent, replayed, or reused across sessions/targets.
2. **Context Generation Binding**: Grants bound to generation $N$ are rejected if the target revision or context changes.
3. **Workspace Boundary**: Symlink and NTFS junction quarantine remains active; directory traversal attacks fail closed.
4. **SQLite PRAGMAs & Integrity**: Foreign keys (`PRAGMA foreign_key_check`), WAL mode, and startup integrity checks operate without regression.
5. **Budget Settlement (`SettlementStatus`)**: All four variants (`Completed`, `CancelledWithUsage`, `CancelledUncertain`, `UncertainPartial`) function correctly. Uncertain execution retains the conservative reservation ceiling.

---

## 5. Security & Reliability Findings

| Finding ID | Module & Location | Severity | Category | Status |
| :--- | :--- | :---: | :---: | :---: |
| **F-551-01** | `crates/sentra-core/src/execution/engine.rs:79-88` | **Low** | Invariant Logic | Open (Remediate in 5.6) |
| **F-551-02** | `crates/sentra-core/src/execution/backend.rs:19-28` | **Low** | Architecture | Open (Phase 2 Roadmap) |
| **F-551-03** | `crates/sentra-core/src/evidence/model.rs:87-104` | **Low** | Memory Safety | Open (Future Ingestion) |
| **F-551-04** | `crates/sentra-core/src/evidence/model.rs:54-64` | **Informational** | MIME Strictness | Documented |
| **F-551-05** | `crates/sentra-core/src/execution/engine.rs:74-90` | **Informational** | Correlation | Open (Remediate in 5.6) |

### Detailed Finding Descriptions

#### F-551-01: Tautological Post-Execution Invariant Check in `ExecutionEngine::dispatch`
- **Location**: [`crates/sentra-core/src/execution/engine.rs:79-88`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/execution/engine.rs#L79-L88)
- **Description**: The post-execution check:
  ```rust
  if matches!(result.status, ExecutionStatus::TimedOut | ExecutionStatus::Cancelled)
      && result.status.is_success()
  { ... }
  ```
  evaluates to `false` unconditionally because `result.status.is_success()` is defined as `matches!(self, Self::Completed)`. An enum variant cannot be `TimedOut` or `Cancelled` and simultaneously `Completed`.
- **Security Impact**: Low. A contradictory response from a backend (such as `ExecutionStatus::TimedOut` with `exit_code: Some(0)`) bypasses this defense-in-depth check without triggering `BackendFault`. It does not breach isolation because untrusted workloads are intercepted prior to dispatch.
- **Remediation**: Check `result.exit_code == Some(0)` when `result.status` is `TimedOut` or `Cancelled`, or verify `result.status.is_success() && result.exit_code != Some(0)`.

#### F-551-02: Absence of Active Cancellation Interface in `ExecutionBackend` Trait
- **Location**: [`crates/sentra-core/src/execution/backend.rs:19-28`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/execution/backend.rs#L19-L28)
- **Description**: The trait exposes only a blocking `execute(&self, request: &ExecutionRequest)` method. There is no cancellation token or `cancel(&self, execution_id: ExecutionId)` method.
- **Security Impact**: Low in Phase 1 (fixtures are synchronous and simulated). In Phase 2 VM execution, an asynchronous cancellation pathway will be required to force-terminate hung worker VMs.
- **Remediation**: Design cooperative cancellation or out-of-band VM worker termination for Phase 2.

#### F-551-03: Post-Allocation Evidence Payload Size Check
- **Location**: [`crates/sentra-core/src/evidence/model.rs:87-104`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/evidence/model.rs#L87-L104)
- **Description**: `EvidenceEnvelope::new()` takes an already-allocated `Vec<u8>`. The 50 MiB ceiling check in `verify_structural_bounds()` is performed post-allocation.
- **Security Impact**: Low in Phase 1. If untrusted artifact streams are read directly into memory before bound verification, heap exhaustion (OOM) could occur before verification is reached.
- **Remediation**: Implement a bounded streaming constructor (e.g., `EvidenceEnvelope::from_reader(metadata, &mut reader, max_bytes)`) for external artifact ingestion.

#### F-551-04: Strict MIME Whitespace Rejection Precludes Standard Parameters
- **Location**: [`crates/sentra-core/src/evidence/model.rs:54-64`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/evidence/model.rs#L54-L64)
- **Description**: `EvidenceMetadata::validate()` rejects any `media_type` containing whitespace, disallowing valid RFC 2045 parameters like `"application/json; charset=utf-8"`. Furthermore, whitelist matching uses case-sensitive exact string matching.
- **Security Impact**: Informational. Callers must adhere to strict parameterless lowercase MIME types.

#### F-551-05: Missing Execution ID Correlation Check in `ExecutionEngine::dispatch`
- **Location**: [`crates/sentra-core/src/execution/engine.rs:74-90`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/src/execution/engine.rs#L74-L90)
- **Description**: The engine does not verify that `result.execution_id == request.execution_id`.
- **Security Impact**: Informational. A misbehaving backend could return an uncoordinated result.

---

## 6. Test Inventory Reconciliation

All tests were executed and reconciled without double-counting:

| Test Suite / Harness | Executed Tests | Passed | Failed | Ignored | Category / Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `sentra-core` Unit Tests (`src/lib.rs`) | 14 | 14 | 0 | 0 | In-tree persistence, workspace, policy unit tests |
| `authorization_tests.rs` | 27 | 27 | 0 | 0 | Approval grant binding, exact single-use, concurrency |
| `domain_tests.rs` | 9 | 9 | 0 | 0 | UUID v7, timestamps, security classifications |
| `evidence_tests.rs` | 9 | 9 | 0 | 0 | Baseline evidence bounds, length matching, offline crypto |
| `execution_evidence_adversarial_tests.rs` (New) | 10 | 10 | 0 | 0 | Adversarial fixtures, limits, contradictory mock, redactions |
| `execution_tests.rs` | 8 | 8 | 0 | 0 | Baseline execution engine and synthetic fixtures |
| `persistence_tests.rs` | 43 | 42 | 0 | 1 | SQLite WAL, FK checks, retry, rollback (1 subprocess helper) |
| `policy_tests.rs` | 9 | 9 | 0 | 0 | PolicyEngine rules, default-deny, classifications |
| `security_tests.rs` | 10 | 10 | 0 | 0 | Bell-LaPadula flow, fixed-point budget, CSPRNG |
| `session_tests.rs` | 5 | 5 | 0 | 0 | 9-state lifecycle state machine |
| `workspace_tests.rs` | 40 | 37 | 0 | 3 | Canonical root, symlink quarantine (3 fixture cases) |
| `Doc-tests sentra_core` | 5 | 5 | 0 | 0 | Compile-fail architectural invariant doctests |
| **Automated Cargo Workspace Total** | **189** | **184** | **0** | **4** | 180 runtime tests + 5 doctests + 4 ignored |
| Dedicated Windows Platform Fixtures | 3 | 3 | 0 | 0 | Windows junction, deny-ACL, and 10k-file benchmark |
| **Grand Total Unique Invariants** | **188** | **188** | **0** | **0** | **188 unique passing tests across entire repository** |

### Validation Script Outcomes
- `cargo fmt --all -- --check`: Exit 0 (Clean formatting).
- `cargo check --workspace --all-targets --all-features --offline`: Exit 0.
- `cargo clippy --workspace --all-targets --all-features --offline -- -D warnings`: Exit 0 (0 warnings).
- `pwsh -File experiments/phase1/persistence/Validate.ps1`: Exit 0 (13/13 passed).
- `pwsh -File experiments/phase1/authorization/Validate.ps1`: Exit 0 (13/13 passed).
- `pwsh -File experiments/phase1/workspace/Validate.ps1`: Exit 0 (11/11 passed, including 3 platform fixtures).

---

## 7. Status and Phase Boundary Declarations

1. **Phase 1 Status**: Phase 1 remains in progress. Increment 5.5 is approved.
2. **Phase 2 Status**: Phase 2 has **NOT** started. Untrusted target code execution remains permanently disabled fail-closed.
3. **Permanent Git Policy**: Zero commits, pushes, tags, branch creations, or resets were issued. All review artifacts and test files remain unstaged in the working tree.
