# Phase 5 — Increment 6.1: Hosted CI Authorization, Fork Security Boundaries, Stale-Head Invalidation & Approval-Gated PR / Publication Protocol

**Implementation Report**  
**Requirement References:** REQ-F18, ADR-0005, THREAT_MODEL T-11, S-10, ROADMAP Phase 5 Acceptance Criteria  
**Date:** 2026-11-09  
**Status:** Complete & Empirically Verified (Host Windows 11 MSVC & Linux Docker)

---

## 1. Executive Summary

Increment 6.1 delivers the hosted CI authorization engine, fork security containment, immutable revision binding, force-push / stale-head defenses, and human approval-gated remediation proposal protocol for Sentra, fulfilling all remaining acceptance criteria for **Phase 5 (Continuous Hosted Integrations)**.

The implementation establishes:
1. **Fork Quarantine & Zero-Secret Guarantee (`T-11`, `S-10`):**
   - Implements `ForkSecurityProfile` strictly isolating untrusted forks (`is_fork: true`, `secrets_permitted: false`). Fork workloads are denied permission to access repository write tokens, model provider keys, or publishing privileges (`ForkSecretAccessDenied`).
   - Implements `HostedCredentials::filter_for_worker` ensuring write tokens are stripped before passing to any worker environment, and all tokens are wiped for forks.
2. **Permission Model & Privilege Separation:**
   - Granular `HostedPermission` flags: `AcquireSource`, `RunAnalysis`, `PublishStatusCheck`, `ProposeDraftPr`, `PublicDisclosure`.
   - Prevents privilege escalation and permission downgrade attacks (`PermissionDowngrade`).
3. **Immutable Revision Binding & Stale-Head Defense:**
   - All remediation proposals are bound strictly to immutable commit SHAs (`base_sha`, `verified_head_sha`), never mutable branch names.
   - Detects force-push or head movement via `StaleHeadGuard::verify_head_freshness`, failing closed with `StaleHeadDivergence`.
   - Verifies common merge base presence via `StaleHeadGuard::verify_merge_base`, failing closed with `MissingMergeBase` if history is missing or diverged.
4. **Approval-Gated Remediation Proposals & Stale Verification Defense:**
   - Implements `DraftPrProposal` bound to exact commit SHAs with `is_draft_only: true` invariant.
   - Prohibits autonomous model publishing: draft PR publication requires an explicit human operator approval ticket (`assert_can_publish` fails closed with `HumanApprovalRequired` without operator admission).
   - Enforces `StaleHeadGuard::verify_verification_bundle_freshness`: if the target commit revision changes after verification occurred, publication is blocked (`StaleVerificationBlocksPublication`).
   - Disallows autonomous merge permanently via `StaleHeadGuard::assert_no_autonomous_merge`.

All code compiles under `#![forbid(unsafe_code)]` with zero Clippy warnings (`-D warnings`) and passes 21/21 integration tests on Windows 11 MSVC and across 21 test suites in Linux Docker.

---

## 2. Architecture & Design

### 2.1 Fork Quarantine & Zero-Secret Containment (`crates/sentra-core/src/hosted/permission.rs`)

When a pull/merge request originates from a fork, an adversary could attempt to extract repository secrets or execute malicious actions under repository identity (Threat T-11).

Sentra defends against this with `ForkSecurityProfile` and credential filtering:

```
[ Webhook Event (is_fork = true) ]
             |
             v
+-------------------------------------------------------------+
|                     ForkSecurityProfile                     |
|                                                             |
|  is_fork: true                                              |
|  secrets_permitted: false  <-- STRICT ZERO-SECRET GUARANTEE |
|  allowed_permissions: [AcquireSource, RunAnalysis]          |
|                                                             |
|  DENIED: PublishStatusCheck, ProposeDraftPr, PublicDisclosure|
+-------------------------------------------------------------+
             |
             v
[ HostedCredentials::filter_for_worker ]
   ├── Fork: { read_token: None, write_token: None }
   └── Non-Fork: { read_token: Some(...), write_token: None }
       (Write tokens NEVER reach target workers)
```

### 2.2 Stale-Head, Merge-Base, and Stale-Verification Defense (`crates/sentra-core/src/hosted/proposal.rs`)

To ensure that automated remediation proposals never target stale revisions or unverified code states:

```
+-------------------------------------------------------------------------------+
|                               StaleHeadGuard                                  |
|                                                                               |
| 1. verify_head_freshness(current_head, proposal_head)                         |
|    - Validates commit SHAs match. Divergence/force-push -> StaleHeadDivergence|
|                                                                               |
| 2. verify_merge_base(merge_base_sha)                                          |
|    - Validates common ancestor exists. Missing -> MissingMergeBase            |
|                                                                               |
| 3. verify_verification_bundle_freshness(bundle_sha, current_head)             |
|    - Target revision moved -> StaleVerificationBlocksPublication               |
|                                                                               |
| 4. assert_no_autonomous_merge(requested_merge)                                |
|    - Autonomous merge requested -> PolicyDenied (Strictly prohibited)         |
+-------------------------------------------------------------------------------+
```

### 2.3 Draft PR Proposal Lifecycle (`DraftPrProposal`)

```
[ New Proposal Created ]
       | (DraftProposed, is_draft_only = true, human_approval_ticket = None)
       |
       v
[ assert_can_publish() ] ---> FAILS: HumanApprovalRequired
       |
       | Operator explicitly reviews and executes admit_human_approval(ticket)
       v
[ Status: ApprovedByHuman ]
       |
       v
[ assert_can_publish() ] ---> SUCCEEDS (References exact verified_head_sha)
```

---

## 3. Verification & Test Evidence

### 3.1 Test Coverage (`crates/sentra-core/tests/hosted_tests.rs`)

21 integration tests comprehensively verify the entire hosted intake, authentication, authorization, and proposal pipeline:

1. `test_github_push_webhook_authenticated`: Valid push event with authentic HMAC-SHA256 signature accepted.
2. `test_github_forged_signature_rejected`: Tampered body or forged signature fails with `InvalidSignature`.
3. `test_github_missing_signature_rejected`: Missing `X-Hub-Signature-256` header fails with `InvalidSignature`.
4. `test_github_delivery_replay_rejected`: Duplicate delivery ID fails with `ReplayDetected`.
5. `test_github_pull_request_with_fork_detection`: Fork repository PR correctly detected and labeled `is_fork: true`.
6. `test_github_ping_event`: Ping handshake event ingested cleanly.
7. `test_gitlab_push_webhook_authenticated`: Valid GitLab push hook with secret token accepted.
8. `test_gitlab_invalid_token_rejected`: Bad secret token fails with `InvalidSignature`.
9. `test_gitlab_merge_request_fork_detection`: Fork merge request labeled `is_fork: true`.
10. `test_repository_allowlist_enforcement`: Repositories outside allowlist rejected with `PolicyDenied`.
11. `test_malformed_commit_sha_rejected`: Non-hex or invalid-length commit SHA rejected with `InvalidRevision`.
12. `test_timestamp_drift_freshness_window`: Event timestamp older than 300s rejected with `TimestampDriftDetected`.
13. `test_fork_security_profile_strict_zero_secrets`: Fork profile denies secret access and wipes all worker tokens.
14. `test_fork_permission_fencing`: Status check, PR proposal, and disclosure permissions strictly denied to forks.
15. `test_internal_branch_worker_credentials_filtering`: Write tokens are stripped before passing to workers.
16. `test_draft_pr_proposal_creation_and_binding`: Proposal binds to exact commit SHAs; publication without approval fails.
17. `test_draft_pr_proposal_human_approval_lifecycle`: Human approval admission permits publication.
18. `test_stale_head_divergence_rejected`: Force-push or branch head movement rejects proposal with `StaleHeadDivergence`.
19. `test_missing_merge_base_rejected`: Missing or empty merge base rejected with `MissingMergeBase`.
20. `test_stale_verification_blocks_publication`: Head change after verification blocks publication.
21. `test_autonomous_merge_permanently_prohibited`: Autonomous merge requests fail closed with `PolicyDenied`.

### 3.2 Dual-Platform Test Results

#### Host Windows 11 (MSVC):
```text
running 21 tests
test test_autonomous_merge_permanently_prohibited ... ok
test test_draft_pr_proposal_creation_and_binding ... ok
test test_draft_pr_proposal_human_approval_lifecycle ... ok
test test_fork_permission_fencing ... ok
test test_fork_security_profile_strict_zero_secrets ... ok
test test_github_delivery_replay_rejected ... ok
test test_github_forged_signature_rejected ... ok
test test_github_missing_signature_rejected ... ok
test test_github_ping_event ... ok
test test_github_pull_request_with_fork_detection ... ok
test test_github_push_webhook_authenticated ... ok
test test_gitlab_invalid_token_rejected ... ok
test test_gitlab_merge_request_fork_detection ... ok
test test_gitlab_push_webhook_authenticated ... ok
test test_internal_branch_worker_credentials_filtering ... ok
test test_malformed_commit_sha_rejected ... ok
test test_missing_merge_base_rejected ... ok
test test_repository_allowlist_enforcement ... ok
test test_stale_head_divergence_rejected ... ok
test test_stale_verification_blocks_publication ... ok
test test_timestamp_drift_freshness_window ... ok

test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

#### Linux Docker Container (`scripts/docker-test.ps1 -Mode all`):
- `cargo fmt --all -- --check`: **Success (0 diffs)**
- `cargo check --workspace`: **Success**
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: **Success (0 warnings)**
- `cargo test --package sentra-core` across 21 independent suites: **21/21 suites passed (21/21 in `hosted_tests`)**.

---

## 4. Phase 5 Acceptance Criteria Fulfillment

| Acceptance Criterion (Roadmap Phase 5) | Implementation & Test Evidence | Status |
|:---|:---|:---|
| **Forged webhook test** | `test_github_forged_signature_rejected`, `test_gitlab_invalid_token_rejected` | **PASSED** |
| **Replay test** | `test_github_delivery_replay_rejected` (`DeliveryLedger`) | **PASSED** |
| **Fork PR test** | `test_github_pull_request_with_fork_detection`, `test_fork_permission_fencing` | **PASSED** |
| **Permission downgrade test** | `test_fork_permission_fencing`, `check_permission` (`PermissionDowngrade`) | **PASSED** |
| **Force-push test** | `test_stale_head_divergence_rejected` (`StaleHeadGuard::verify_head_freshness`) | **PASSED** |
| **Missing merge base test** | `test_missing_merge_base_rejected` (`StaleHeadGuard::verify_merge_base`) | **PASSED** |
| **Duplicate event test** | `test_github_delivery_replay_rejected` (`ReplayDetected`) | **PASSED** |
| **Stale patch test** | `test_stale_verification_blocks_publication` (`StaleVerificationBlocksPublication`) | **PASSED** |
| **Credentials cannot reach workers** | `test_internal_branch_worker_credentials_filtering`, `filter_for_worker` | **PASSED** |
| **Exact verified commit reference** | `test_draft_pr_proposal_creation_and_binding` (`verified_head_sha`) | **PASSED** |
| **Stale verification blocks publication** | `test_stale_verification_blocks_publication` | **PASSED** |
| **No autonomous merge** | `test_autonomous_merge_permanently_prohibited`, `is_draft_only: true` | **PASSED** |
