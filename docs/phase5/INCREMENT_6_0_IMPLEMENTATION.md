# Phase 5 — Increment 6.0: Continuous Hosted Integrations — Authenticated Webhook Intake & Delivery Replay Defense

**Implementation Report**  
**Requirement References:** REQ-F18, ADR-0005, THREAT_MODEL T-11, S-10, ROADMAP Phase 5  
**Date:** 2026-11-09  
**Status:** Complete & Empirically Verified (Host Windows 11 MSVC & Linux Docker)

---

## 1. Executive Summary

Increment 6.0 launches **Phase 5 (Continuous Hosted Integrations)**, delivering the foundational webhook ingestion engine, cryptographic event authentication, delivery deduplication ledger, and provider-agnostic event normalization for GitHub and GitLab, satisfying **REQ-F18**, **THREAT_MODEL T-11**, and **S-10**.

The implementation establishes:
1. **Pure Safe-Rust Cryptographic Primitives:** Implements RFC 2104 / RFC 4231 HMAC-SHA256 (`hmac_sha256`, `hmac_sha256_hex`) and constant-time byte comparison (`constant_time_eq`) directly in `crates/sentra-core/src/common/crypto.rs` under `#![forbid(unsafe_code)]` with zero third-party C/C++ dependencies.
2. **Cryptographic Event Authentication:**
   - **GitHub:** Verifies `X-Hub-Signature-256` HMAC-SHA256 signatures over raw request bodies using constant-time comparison.
   - **GitLab:** Verifies `X-Gitlab-Token` webhook secret tokens using constant-time comparison.
3. **Delivery Deduplication & Replay Prevention:**
   - Tracks incoming deliveries via `DeliveryLedger` indexed by unique delivery IDs (`X-GitHub-Delivery`, `X-Gitlab-Event-UUID`).
   - Detects and rejects duplicate or replayed deliveries with `WebhookErrorKind::ReplayDetected`.
   - Enforces configurable timestamp drift tolerance (default 300 seconds / 5 minutes) via `WebhookErrorKind::TimestampDriftDetected`.
4. **Canonical Event Normalization & Fork Isolation:**
   - Normalizes GitHub and GitLab push and pull/merge request events into canonical `WebhookEvent`.
   - Strictly validates 40-character hexadecimal Git commit SHAs (`validate_commit_sha`).
   - Automatically detects untrusted fork events (`is_fork: true`), ensuring fork isolation prior to task authorization.
   - Restricts webhook ingestion to authorized repositories via `allowed_repositories` allowlist.

All code compiles under `#![forbid(unsafe_code)]` with zero Clippy warnings (`-D warnings`) and passes 12/12 new integration tests on Windows 11 MSVC and across 21 test suites in Linux Docker.

---

## 2. Architecture & Design

### 2.1 Cryptographic Primitives (`crates/sentra-core/src/common/crypto.rs`)

To guarantee security against timing attacks and forged signatures without external native dependencies:
- **`hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32]`**: Pure-Rust RFC 2104 / RFC 4231 HMAC-SHA256 implementation leveraging `sha2::Sha256`. Validated against RFC 4231 Test Cases 1, 2, and 3.
- **`constant_time_eq(a: &[u8], b: &[u8]) -> bool`**: Bitwise OR accumulation over XOR byte comparisons ensuring identical execution time regardless of mismatch positions.

```
+-----------------------------------------------------------------------------------+
|                                 HMAC-SHA256                                       |
|                                                                                   |
|  Key (K) ----> [Pad/Hash to 64B] ---> XOR with ipad (0x36) ---> H(K^ipad || M)    |
|                                                                        |          |
|                                  ---> XOR with opad (0x5c) ---> H(K^opad || Inner)|
|                                                                        |          |
|                                                                 Digest (32 bytes) |
+-----------------------------------------------------------------------------------+
```

### 2.2 Event Authentication & Webhook Intake (`crates/sentra-core/src/hosted/`)

The `hosted` module coordinates incoming webhooks through structured stages:

```
[ Incoming Webhook Request ]
             |
             v
[ 1. Cryptographic Authentication ]
   ├── GitHub: verify_github_signature(secret, X-Hub-Signature-256, body)
   └── GitLab: verify_gitlab_token(secret, X-Gitlab-Token)
             | (Fail -> InvalidSignature)
             v
[ 2. Delivery Ledger & Replay Defense ]
   ├── Check delivery ID against DeliveryLedger (ReplayDetected)
   └── Verify timestamp drift <= max_drift_secs (TimestampDriftDetected)
             |
             v
[ 3. Repository Policy Gating ]
   └── Verify repository in allowed_repositories allowlist (PolicyDenied)
             |
             v
[ 4. Payload Normalization ]
   ├── Validate 40-character commit SHAs (validate_commit_sha)
   ├── Detect fork PR origin (head.repo != base.repo -> is_fork: true)
   └── Produce Canonical WebhookEvent (Push / PullRequest / Ping)
```

### 2.3 Domain Models

- **`HostedProvider`**: `GitHub`, `GitLab`.
- **`PushPayload`**: `ref_name`, `before_sha`, `after_sha`, `is_forced`, `commit_count`.
- **`PullRequestPayload`**: `pr_number`, `action` (`Opened`, `Synchronize`, `Closed`, `Reopened`, `Other`), `base_ref`, `base_sha`, `head_ref`, `head_sha`, `is_fork`.
- **`WebhookEvent`**: `event_id`, `provider`, `repository_name`, `repository_url`, `is_fork`, `payload: EventKind`, `received_at: TimestampUtc`.

---

## 3. Verification & Test Evidence

### 3.1 Test Coverage (`crates/sentra-core/tests/hosted_tests.rs`)

12 integration tests verify the end-to-end security and intake invariants:

1. `test_github_push_webhook_authenticated`: Valid push event with authentic HMAC-SHA256 signature accepted.
2. `test_github_forged_signature_rejected`: Tampered body or forged signature fails with `InvalidSignature`.
3. `test_github_missing_signature_rejected`: Missing `X-Hub-Signature-256` header fails with `InvalidSignature`.
4. `test_github_delivery_replay_rejected`: Duplicate delivery ID fails with `ReplayDetected`.
5. `test_github_pull_request_with_fork_detection`: Fork repository PR correctly detected and labeled `is_fork: true`.
6. `test_github_ping_event`: Ping handshake event ingested cleanly.
7. `test_gitlab_push_webhook_authenticated`: Valid GitLab push hook with secret token accepted.
8. `test_gitlab_invalid_token_rejected`: Bad secret token fails with `InvalidSignature`.
9. `test_gitlab_merge_request_fork_detection`: Fork merge request (`source_project_id != target_project_id`) labeled `is_fork: true`.
10. `test_repository_allowlist_enforcement`: Repositories outside allowlist rejected with `PolicyDenied`.
11. `test_malformed_commit_sha_rejected`: Non-hex or invalid-length commit SHA rejected with `InvalidRevision`.
12. `test_timestamp_drift_freshness_window`: Event timestamp older than 300s rejected with `TimestampDriftDetected`.

### 3.2 Dual-Platform Test Results

#### Host Windows 11 (MSVC):
```text
running 12 tests
test test_github_delivery_replay_rejected ... ok
test test_github_forged_signature_rejected ... ok
test test_github_missing_signature_rejected ... ok
test test_github_ping_event ... ok
test test_github_pull_request_with_fork_detection ... ok
test test_github_push_webhook_authenticated ... ok
test test_gitlab_invalid_token_rejected ... ok
test test_gitlab_merge_request_fork_detection ... ok
test test_gitlab_push_webhook_authenticated ... ok
test test_malformed_commit_sha_rejected ... ok
test test_repository_allowlist_enforcement ... ok
test test_timestamp_drift_freshness_window ... ok

test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

#### Linux Docker Container (`scripts/docker-test.ps1 -Mode all`):
- `cargo fmt --all -- --check`: **Success (0 diffs)**
- `cargo check --workspace`: **Success**
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: **Success (0 warnings)**
- `cargo test --package sentra-core` across 21 independent suites: **21/21 suites passed (12/12 in `hosted_tests`)**.

---

## 4. Requirement Traceability Matrix

| Requirement | Implementation Artifact | Verification Result |
|:---|:---|:---|
| **REQ-F18** (Continuous Hosted Integrations) | `crates/sentra-core/src/hosted/` | Webhook intake, event normalization verified |
| **THREAT_MODEL T-11** (Webhook Authentication) | `hosted/verifier.rs` (`verify_github_signature`, `verify_gitlab_token`) | HMAC-SHA256 & constant-time check verified |
| **THREAT_MODEL T-11** (Replay Protection) | `hosted/ledger.rs` (`DeliveryLedger`) | Delivery deduplication and drift window verified |
| **REQ-S10** (Fork Quarantine & Scope) | `hosted/event.rs`, `hosted/intake.rs` (`is_fork`) | Fork PRs detected and isolated |
| **Commit SHA Integrity** | `hosted/event.rs` (`validate_commit_sha`) | 40-hex lowercase SHA validation enforced |

---

## 5. Next Steps

With Increment 6.0 complete:
- **Increment 6.1:** Hosted CI Authorization, Fork Security Boundaries, Stale-Head Invalidation & Approval-Gated PR / Publication Protocol (`F-18`, `T-11`, `S-10`).
