# Sentra Phase 1 — Increment 5.2.1: Security Hardening Review

**Review Date:** 2026-11-05  
**Reviewed Crate:** `crates/sentra-core` (v0.1.0)  
**Status:** Complete — All Identified Weaknesses Hardened or Fail-Closed; 33 Tests Passing  

---

## 1. Review Methodology

This security review performed a code-level and invariant-level audit of the Increment 5.2 implementation in `crates/sentra-core`. Each primary target was evaluated against:
1. **Cryptographic Integrity & Canonicalization:** Verification of digest algorithms, collision-resistance, argument/path delimiter injection, and cryptographic claims versus actual in-memory protections.
2. **Identifier Generation & Predictability:** Analysis of UUID version 4 and variant conformance, randomness sources, collision resistance across processes/restarts, and separation of deterministic test fixtures from production entropy.
3. **Concurrency & Atomicity:** Verification of approval grant validation and consumption under simultaneous multithreaded races, evaluating replay prevention and time-of-check to time-of-use (TOCTOU) windows.
4. **Information Flow & Security Classifications:** Verification of Bell-LaPadula simple confidentiality invariants (no write-down), external egress boundaries, and protection against metadata-only bypasses.
5. **Budget Policy & Currency Representation:** Analysis of numeric types, floating-point IEEE-754 bypasses (such as NaN/negative amounts), auto-budget threshold enforcement, and conservative handling of unknown costs.

---

## 2. Source Files and Functions Inspected

| Source File | Components / Functions Inspected | Primary Focus |
|---|---|---|
| `crates/sentra-core/src/domain/id.rs` | `Identifier`, `SessionId`, `new_sequential`, `new_deterministic`, `generate_production_v4` | UUID format, version/variant bits, predictable PRNG vs CSPRNG, process restart collision |
| `crates/sentra-core/src/domain/error.rs` | `DomainError` enum | Typed security errors (`InvalidCost`, `EntropySourceUnavailable`) |
| `crates/sentra-core/src/domain/classification.rs` | `SecurityClassification`, `can_flow_to`, `requires_approval_for_external_egress` | Bell-LaPadula flow lattice, rank ordering, egress permissions |
| `crates/sentra-core/src/policy/action.rs` | `OperationAction`, `action_digest`, `is_sensitive` | Argument injection, path list binding, delimiter collision, canonical formatting |
| `crates/sentra-core/src/policy/approval.rs` | `ApprovalBroker`, `ApprovalRequest`, `ApprovalGrant`, `verify_and_consume` | Concurrency, `Mutex` atomicity, single-use replay prevention, revocation, expiry |
| `crates/sentra-core/src/policy/budget.rs` | `CostUsd`, `BudgetPolicyConfig` | Fixed-point micro-dollar arithmetic, NaN/negative bypass prevention, configuration validation |
| `crates/sentra-core/src/policy/decision.rs` | `PolicyDecision`, `DenialReason` | Typed denial explanations (`ClassificationExceeded`, `BudgetExceeded`) |
| `crates/sentra-core/src/policy/engine.rs` | `PolicyEngine::evaluate` | Default-deny priority, Bell-LaPadula write-down denial, egress approval, auto-budget ceiling |

---

## 3. Findings, Severity, and Evidence

### Finding 1: Delimiter Injection in `action_digest` (High Severity)
- **Evidence:** In `OperationAction::ExecuteTool`, command-line arguments were previously concatenated using `arguments.join(",")`. An argument containing a comma (e.g., `["a,b", "c"]`) produced the exact same digest string (`action:exec:tool:untrusted=true:args=a,b,c`) as separate arguments (`["a", "b,c"]` or `["a", "b", "c"]`).
- **Impact:** An approval granted for an innocent-looking argument string could authorize arbitrary argument injection or parameter confusion.
- **Remediation:** Implemented length-prefixed argument encoding (`len#arg`, e.g., `3#a,b,1#c` vs `1#a,3#b,c`). Delimiter collision is now mathematically impossible.

### Finding 2: Missing Target Path Binding in `ModifyCheckout` (High Severity)
- **Evidence:** `OperationAction::ModifyCheckout` previously only encoded `file_count: usize` in `action_digest`.
- **Impact:** An approval granted to modify 2 documentation files could be reused to modify 2 critical security workflow files (such as `.github/workflows/ci.yml`).
- **Remediation:** Added `target_paths: Vec<String>` to `OperationAction::ModifyCheckout`. The paths are sorted canonically and length-prefixed in `action_digest`, binding the exact set of authorized files to the approval grant.

### Finding 3: IEEE-754 Floating-Point NaN Bypass in Budget Evaluation (High Severity)
- **Evidence:** `estimated_cost_usd` was represented as an `f64`. Under IEEE-754 semantics, `f64::NAN > 1.0` evaluates to `false`.
- **Impact:** If an operation passed `NaN` as the estimated cost, the comparison `*estimated_cost_usd > self.max_auto_budget_usd` evaluated to `false`, causing the engine to automatically approve and execute an unbounded/arbitrary cost operation without human authorization.
- **Remediation:** Replaced raw `f64` with a fixed-point `CostUsd` type storing integer micro-dollars (`u64`, 1 USD = 1,000,000 micro-USD). Any attempt to parse `NaN`, `Infinity`, or negative values fails closed immediately with `DomainError::InvalidCost`.

### Finding 4: Predictable Pseudo-Random UUID Generation in Production Code (Medium Severity)
- **Evidence:** `Identifier::new_sequential` generated IDs using `now_millis ^ salt` and an in-memory atomic counter starting at 1.
- **Impact:** IDs are completely predictable across process runs. Two processes running concurrently or across restarts can generate identical session/approval IDs.
- **Remediation:** Explicitly separated deterministic test fixtures from production generation. Standard library safe code does not expose OS CSPRNG on Windows without external crates or unsafe FFI. Implemented `Identifier::generate_production_v4()` and `SessionId::generate_production()` which explicitly fail closed with `DomainError::EntropySourceUnavailable` until the approved `uuid` / `getrandom` dependency is integrated in Increment 5.4.

### Finding 5: Non-Thread-Safe `ApprovalBroker` Lacked Concurrency Protection (Medium Severity)
- **Evidence:** `ApprovalBroker` stored state in plain `BTreeMap` and `BTreeSet` requiring `&mut self`. If wrapped in an external lock without atomic check-and-consume guarantees, or if request ID consumption was not tracked, race conditions could occur.
- **Impact:** Concurrent workers could race on grant verification or receive misleading `InvalidApprovalGrant` errors instead of `ApprovalReused`.
- **Remediation:** Embedded `std::sync::Mutex` inside `ApprovalBroker`, making the broker and `PolicyEngine` thread-safe (`Send + Sync`). Added `consumed_requests: BTreeSet<ApprovalId>` to ensure that racing threads attempting to reuse a grant atomically receive `DenialReason::ApprovalReused`.

### Finding 6: Cryptographic Overclaim in Documentation (Low Severity)
- **Evidence:** Documentation described `action_digest` as "cryptographically bound to approval grants".
- **Impact:** Overclaiming cryptographic security when the implementation was a formatted canonical string.
- **Remediation:** Updated documentation to accurately state that `action_digest` is a *canonical structured action descriptor*, and authorization integrity is currently enforced by trusted in-memory broker state. Cryptographic hashing via SHA-256 is scheduled for Increment 5.4 under ADR-0006.

---

## 4. Cryptographic Action Digest and Security Properties

| Property | Actual Status |
|---|---|
| **Underlying Representation** | Structured canonical ASCII string (e.g., `action:exec:tool:untrusted=true:args=[3#a,b,1#c]`) |
| **Cryptographic Hash** | None (pure Rust standard library in Increment 5.2; SHA-256 planned for Increment 5.4) |
| **Collision Resistance** | Delimiter-injection free via length-prefixed field encoding (`len#value`) and canonical path sorting |
| **Bound Scope Fields** | Action name, tool ID, untrusted flag, arguments, model ID, micro-USD cost, destination, external flag, destination classification, file count, canonical target paths |
| **Bound Session/Revision** | Explicitly validated by `ApprovalBroker` (`session_id`, `target_revision`, `action_digest`) |
| **Trust Model** | In-memory trusted state in `ApprovalBroker`; not an asymmetric digital signature or MAC |

---

## 5. UUID Production/Test Generation Assessment

- **Version & Variant Conformance:** Verified. Bit manipulation in `Identifier::new_deterministic` correctly sets version 4 (bits 4-7 of byte 6 = `0100`) and variant 1 (bits 6-7 of byte 8 = `10`). Verified by `test_uuid_version_variant_and_production_fail_closed`.
- **Test Generation:** Monotonic sequence counter and deterministic salts (`from_sequence`, `for_test_sequence`) provide reproducible identifiers for test fixtures.
- **Production CSPRNG:** Safe Rust `std` does not provide access to OS CSPRNG (e.g. `BCryptGenRandom` or `ProcessPrng`) without `unsafe` blocks or external crates. In accordance with project policy (no unsafe code, zero third-party dependencies in 5.2), production generation explicitly fails closed returning `Err(DomainError::EntropySourceUnavailable)`. Full production CSPRNG is deferred to Increment 5.4.

---

## 6. Approval Broker Concurrency Guarantees

- **Synchronization Primitive:** Internal `std::sync::Mutex<BrokerInner>` wrapping pending requests, consumed tokens, consumed request IDs, and revoked requests.
- **Single-Use Replay Invariant:** Verified under live concurrency with 20 simultaneous threads racing on a synchronization barrier (`test_concurrent_single_use_approval_consumption_exact_winner`). Exactly 1 thread succeeds; exactly 19 threads receive `DenialReason::ApprovalReused`.
- **Atomicity:** Verification and state mutation occur within a single lock acquisition. Failed validation (such as revision mismatch or expiration) leaves pending requests and consumed tokens completely untouched (`test_failed_validation_does_not_consume_grant`).

---

## 7. Security Classification and Information Flow Assessment

- **Lattice Order:** Explicit numeric ranks: `Public` (10), `Internal` (20), `Confidential` (30), `Restricted` (40).
- **Bell-LaPadula Enforcement:** `can_flow_to` enforces that data cannot flow down to a lower confidentiality level. In `PolicyEngine::evaluate`, attempting to export higher-classification data to a lower-classification destination returns `DenialReason::ClassificationExceeded` (`test_bell_lapadula_flow_enforcement_prevents_write_down`).
- **External Egress Boundary:** External export of `Internal`, `Confidential`, or `Restricted` data unconditionally requires explicit human approval.
- **Restricted Data Protection:** Operations on `Restricted` data (including metadata discovery) unconditionally require human approval.
- **Default-Deny Priority:** Classification checks never grant permission to an unknown or sensitive operation. Unknown operations are rejected immediately regardless of classification (`test_classification_check_never_accidentally_grants_unknown_operation`).

---

## 8. Budget Policy Assessment

- **Currency Type:** `CostUsd` represents monetary values as integer micro-dollars (`u64`, 1 USD = 1,000,000 micro-USD).
- **Bypass Prevention:** Negative amounts, NaN, Infinity, and overflow values are rejected during parsing.
- **Precision:** Fixed-point arithmetic eliminates floating-point representation errors ($0.10 + $0.20 = $0.30 exactly).
- **Threshold Boundary:** Automated approval is granted if `cost <= max_auto_budget`; operations with `cost > max_auto_budget` (even by 1 micro-dollar) trigger `PolicyDecision::NeedsApproval` (`test_budget_threshold_boundary_precision`).
- **Configuration Invariants:** `BudgetPolicyConfig::validate()` enforces that `max_auto_budget` cannot exceed `max_request_ceiling`.

---

## 9. Changes Made

1. **`crates/sentra-core/src/domain/error.rs`**: Added `DomainError::InvalidCost` and `DomainError::EntropySourceUnavailable`.
2. **`crates/sentra-core/src/domain/id.rs`**: Added `version()`, `variant()`, `generate_production_v4()`, `for_test_sequence()`, and typed ID production methods.
3. **`crates/sentra-core/src/policy/budget.rs`**: Created `CostUsd` and `BudgetPolicyConfig` with micro-dollar arithmetic and NaN rejection.
4. **`crates/sentra-core/src/policy/action.rs`**: Added length-prefixed argument encoding in `action_digest`, target path list to `ModifyCheckout`, and micro-dollar formatting for `InvokeProvider`.
5. **`crates/sentra-core/src/policy/decision.rs`**: Updated `BudgetExceeded` to use `CostUsd`.
6. **`crates/sentra-core/src/policy/approval.rs`**: Protected `ApprovalBroker` with internal `std::sync::Mutex`, added `consumed_requests` tracking, made all public broker methods thread-safe (`&self`), and updated `budget_limit` to `CostUsd`.
7. **`crates/sentra-core/src/policy/engine.rs`**: Integrated `BudgetPolicyConfig`, enforced Bell-LaPadula flow rules in `evaluate`, and updated `evaluate(&self, ...)` to take `&self`.
8. **`crates/sentra-core/src/policy/mod.rs` & `lib.rs`**: Re-exported `CostUsd` and `BudgetPolicyConfig`.
9. **`crates/sentra-core/tests/policy_tests.rs`**: Updated existing tests to align with `CostUsd`, `target_paths`, and `&self` engine API.
10. **`crates/sentra-core/tests/security_tests.rs`**: Created 10 targeted regression tests covering all 5 review targets.

---

## 10. Tests Added and Results

A new integration test suite [`security_tests.rs`](file:///E:/MyProject/Mix/GitHub/Sentra/crates/sentra-core/tests/security_tests.rs) was added with 10 targeted tests:

1. `test_action_digest_argument_delimiter_injection_resistance`: Validates length-prefixed argument encoding against separator collision.
2. `test_action_digest_modify_checkout_target_binding_and_canonical_sorting`: Validates target path binding and deterministic order sorting.
3. `test_uuid_version_variant_and_production_fail_closed`: Validates UUID v4 / variant 1 bits and fail-closed production CSPRNG.
4. `test_concurrent_single_use_approval_consumption_exact_winner`: Validates atomic single-use grant consumption under 20 concurrent racing threads.
5. `test_failed_validation_does_not_consume_grant`: Validates that invalid attempts do not consume valid grants.
6. `test_bell_lapadula_flow_enforcement_prevents_write_down`: Validates denial of write-down from Confidential to Public.
7. `test_classification_check_never_accidentally_grants_unknown_operation`: Validates default-deny priority over classification.
8. `test_cost_usd_rejects_nan_infinity_and_negative_amounts`: Validates monetary parsing and NaN/negative bypass prevention.
9. `test_cost_usd_fixed_point_exact_arithmetic`: Validates micro-dollar checked arithmetic and epsilon elimination.
10. `test_budget_threshold_boundary_precision`: Validates exact 1-micro-dollar threshold boundary behavior.

### Total Test Suite Results:
- `domain_tests.rs`: 9 passed
- `policy_tests.rs`: 9 passed
- `security_tests.rs`: 10 passed
- `session_tests.rs`: 5 passed
- **Total:** 33 passed, 0 failed, 0 ignored.
- **Quality Gates:** `cargo fmt --check`, `cargo check --workspace`, and `cargo clippy --workspace --all-targets --all-features -- -D warnings` all pass with 0 errors and 0 warnings.

---

## 11. Remaining Limitations and Deferred Work

1. **SHA-256 Digest Hashing:** `action_digest` produces a canonical descriptor string. Cryptographic SHA-256 hashing is deferred to Increment 5.4 when the approved `sha2` crate is integrated.
2. **OS CSPRNG for UUIDs:** Production UUIDv4 generation currently fails closed with `DomainError::EntropySourceUnavailable`. Integration of the approved `uuid` (with `v4` and `getrandom`) crate is deferred to Increment 5.4.
3. **Persistent Approval Storage:** `ApprovalBroker` is strictly in-memory. Persistence across process restarts is deferred to Increment 5.4 (SQLite repository integration).
4. **Execution Boundaries:** No untrusted execution backend or worker orchestration is implemented in this increment.

---

## 12. Final Security Disposition

**Status: Approved (Increment 5.2.1 Hardening Complete).**  
All identified security weaknesses have been remediated with verified fail-closed semantics and comprehensive regression tests. The codebase maintains zero third-party dependencies, `#![forbid(unsafe_code)]`, and full toolchain compliance. The project is ready to proceed to Increment 5.3 upon user authorization.
