# Phase 3 — Increment 4.0: Deep Research Scout/Analyst Campaign Engine & Coverage Ledger — Implementation Report

**Status:** Completed  
**Date:** 2026-11-08  
**Scope:** Increment 4.0 — Scout/Analyst Role Contracts (`F-04`), Proposer/Verifier Independence & Anti-Collusion (`S-08`, Roadmap Phase 3), Task Fanout & Concurrency Limits (`S-06`), Hypothesis Deduplication (`F-05`), and Coverage Ledger (`F-04`).  
**Host Environment:** Windows 11 (PowerShell 7.6.6) & Linux Docker Container Verification (`scripts/docker-test.ps1`).  

---

## 1. Executive Summary

Increment 4.0 establishes the foundation for Phase 3 ("Deep Security Research pilot") within `sentra-core`:

1. **Scout / Analyst Role Contracts & Capability Boundaries (`F-04`, `S-08`):**
   - Implemented `ResearchRole` (`Scout`, `Analyst`, `Validator`, `PatchAuthor`, `IndependentVerifier`) and `RoleCapability` in `crates/sentra-core/src/research/role.rs`.
   - Enforces least-privilege capability masks: Scouts are restricted to context reading, surface reconnaissance, and reporting coverage gaps; Analysts form hypotheses and request reproduction; Patch Authors propose diffs; only Independent Verifiers can execute dual-state verification.
   - Implemented strict proposer/verifier separation via `assert_patch_verifier_independent`: a patch author is strictly forbidden from verifying or approving their own patch.
   - Implemented anti-collusion barriers via `assert_peer_approval_forbidden`: model-controlled roles (Scouts, Analysts, Validators, Patch Authors) cannot grant execution authority or approve peer work through model messages.

2. **Campaign Orchestrator & Task Fanout Engine (`F-04`, `S-06`):**
   - Implemented `Campaign`, `CampaignLimits`, `CampaignStatus`, `CampaignStopReason`, and `CampaignTask` in `crates/sentra-core/src/research/campaign.rs`.
   - Enforces hierarchical tree depth limits (`max_depth`, default 2), preventing runaway child task spawning.
   - Enforces active concurrency ceilings (`max_concurrent_tasks`, default 4).
   - Enforces strict monetary budget reservations and settlements in micro-USD (`max_budget_micro_usd`), failing closed if a requested reservation exceeds available funds.
   - Implemented secret canary isolation (`secret_canary` per task, verified by `verify_secret_isolation`), ensuring that peer tasks cannot leak, access, or share private credentials across task boundaries.

3. **Hypothesis Deduplication & Canonical Fingerprinting (`F-05`):**
   - Implemented `Hypothesis`, `HypothesisId`, `VulnerabilityCategory`, `HypothesisStatus`, and `HypothesisDeduplicator` in `crates/sentra-core/src/research/hypothesis.rs`.
   - Computes deterministic SHA-256 canonical fingerprints across target file, symbol, line number, and vulnerability category.
   - Fails closed with `ResearchErrorKind::DuplicateHypothesis` when a duplicate hypothesis is proposed, preventing redundant LLM and worker compute expenditure.

4. **Coverage Ledger & Explicit Uncertainty Reporting (`F-04`, Roadmap Phase 3):**
   - Implemented `CoverageLedger`, `CoveredRegion`, `SkippedRegion`, `SkipReason`, and `CoverageSummary` in `crates/sentra-core/src/research/coverage.rs`.
   - Tracks covered lines, symbols, and files alongside explicitly skipped targets with typed justifications (`OutOfScope`, `UnbuildableTarget`, `LanguageUnsupported`, `BudgetExhaustion`, `TimeoutCeiling`, `PolicyExcluded`, `NonDeterministicCrash`).
   - Produces aggregated coverage statistics and uncertainty distributions fulfilling Roadmap transparency obligations.

---

## 2. Verification Evidence

### 2.1 Research Integration Suite (`crates/sentra-core/tests/research_tests.rs`)

1. `test_role_capability_enforcement`: Proves capability boundaries across all 5 roles and asserts fail-closed rejection on unauthorized capabilities.
2. `test_patch_author_cannot_verify_own_patch`: Verifies that self-verification is strictly denied and verifies role requirements for independent verifiers.
3. `test_anti_collusion_peer_approval_forbidden`: Verifies rejection of all peer approval attempts between model-controlled agents.
4. `test_hypothesis_deduplication`: Verifies canonical fingerprinting and duplicate hypothesis rejection.
5. `test_coverage_ledger_recording_and_summary`: Verifies coverage ledger tracking, skip reasons, and summary computation.
6. `test_campaign_task_fanout_limits`: Verifies concurrency ceilings and max tree depth enforcement.
7. `test_campaign_budget_accounting_and_exhaustion`: Verifies budget reservations, settlement, and exhaustion guards.
8. `test_task_secret_isolation_canary_detection`: Proves detection and fail-closed prevention of secret token leakage between tasks.
9. `test_campaign_stop_and_status`: Verifies campaign lifecycle states, stop reasons, and rejection of task spawning after campaign conclusion.
10. `test_research_serde_roundtrip`: Verifies JSON serialization and deserialization roundtrip fidelity.

---

## 3. Dual-Platform Validation

- **Windows 11 MSVC Host:** All 10 research integration tests passed cleanly.
- **Clippy:** Passed `--workspace --all-targets --all-features -- -D warnings` with zero warnings.
- **Formatting:** Passed `cargo fmt --all -- --check`.
- **Linux Docker Container (`scripts/docker-test.ps1 -Mode all`):** 17 independent test suites executed under `#![forbid(unsafe_code)]`.
