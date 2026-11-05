# Approval Grant Binding and Authorization Integrity — Increment 5.3.1

Date: 2026-11-05. **Implemented and tested; the original in-process A-to-B vulnerability is closed.** All required binding/provenance/expiry/replay regressions pass. This is a targeted correction to the existing approval mechanism, not completion of the Core Engine or a claim of end-to-end execution security. Increment 5.4 and Phase 2 have not started.

## Original vulnerability and root causes

The [5.3 review](INCREMENT_5_3_WORKSPACE_VALIDATION.md) and its preserved [Failed probe result](../../experiments/phase1/workspace/results/policy-context.json) showed a grant for Restricted metadata action A authorizing different action B. Source inspection traced the entire lifecycle rather than relying on the earlier 5.2.1 pass count. There is no separate 5.2 report file; its implementation record is the corresponding PROGRESS.md section and the existing domain/session/policy tests.

The defects were:

1. PolicyEngine::evaluate passed only a grant and clock to the broker. The broker compared that grant with an old pending request, not the current action, target, session or revision.
2. ApprovalGrant::new could construct an accepted grant from known request fields and an arbitrary token. There was no trusted issuance record or verified issuance provenance.
3. Public request insertion accepted caller-created records and could overwrite an existing request ID. SessionMetadata was a mutable caller DTO, with no independently registered authoritative security snapshot.
4. policy_digest was reused as target_revision, conflating two identities. A supplied invalid grant could also be ignored when evaluation reached an automatic rule.

The existing Mutex already prevented two simultaneous consumers of the same matching request; atomicity alone did not make its incomplete predicate correct. Length-prefixing arguments in 5.2.1 also did not establish grant provenance or current-operation binding.

## Implementation and trusted lifecycle

| Changed artifact | Correction |
| --- | --- |
| [policy/approval.rs](../../crates/sentra-core/src/policy/approval.rs) | Registered session contexts, explicit target revisions, context generations, broker-issued receipts, immutable stored bindings, atomic full validation/consumption, poisoning denial and privileged authority facade |
| [policy/engine.rs](../../crates/sentra-core/src/policy/engine.rs) | Require registered context; pass current session/classification/action to consumption; validate every supplied receipt; preserve automatic rules only without a presented grant |
| [policy/action.rs](../../crates/sentra-core/src/policy/action.rs) | Version-2 canonical field/list framing and rejection of missing/inconsistent parameters |
| [policy/mod.rs](../../crates/sentra-core/src/policy/mod.rs), [lib.rs](../../crates/sentra-core/src/lib.rs) | Export the authority capability alongside the same existing broker mechanism |
| [policy_tests.rs](../../crates/sentra-core/tests/policy_tests.rs), [security_tests.rs](../../crates/sentra-core/tests/security_tests.rs) | Migrate affected setup/issuance/consume calls while preserving all 19 test intents |
| [authorization_tests.rs](../../crates/sentra-core/tests/authorization_tests.rs) | 27 focused regressions, including the exact A/B case and repeated barrier races |
| [original probe source](../../experiments/phase1/workspace/PolicyContextProbe.rs) | Use real broker issuance; require the precise mismatch denial, matching success and replay rejection |
| [validation runner](../../experiments/phase1/authorization/Validate.ps1) | Offline commands, individual outcomes, source hashes, repeated concurrency and independent probe execution |

No workspace boundary/discovery source or fixture, domain model, session state machine, budget implementation, manifest, dependency, accepted ADR, persistence, provider, execution backend, CLI or sandbox implementation changed. The two old capability/sensitivity fixtures declared a file count inconsistent with their target-path list; their counts were corrected to their actual lists. Malformed operations now deny, and separate negative coverage verifies that rule.

Trusted bootstrap calls PolicyEngine::with_authority(config), returning an evaluator and a separate ApprovalAuthority handle over the **same Arc/Mutex broker state**. Only the trusted controller retains the authority. The evaluator's broker interface cannot register contexts, inject request DTOs, issue grants or revoke them. Two compile-fail documentation tests enforce the missing request-injection/issuance methods. This is capability separation within one approval mechanism, not a second authorization store.

The lifecycle is:

1. The trusted controller registers a SessionMetadata security snapshot, an explicit target revision and a minimum classification using set_session_context. Metadata processing does not automatically register itself. Blank/control-bearing required fields or a zero session identity deny. The owner must supply an already established workspace identity and actual revision; this API performs no filesystem or Git acquisition.
2. Evaluation compares the caller's session identity, workspace, operator, policy identity, mode and creation time with that stored snapshot. Assessment completeness is not an authorization input. Classification below the trusted floor denies. Missing context denies, including for automatic rules.
3. Broker request creation derives the operation identity from OperationAction, binds the registered workspace/revision/session and operation classification, and stores that binding privately. Returned request objects are display copies. Caller modifications cannot replace the stored record or expiry.
4. After obtaining human approval through its trusted control path, the controller calls ApprovalAuthority::issue_grant. It uses the stored request, checks its current context generation, lifetime and state, and records a complete receipt with private Arc-based provenance. Unknown, stale, revoked, duplicate-issued and expired requests deny issuance.
5. Consumption recomputes the expected binding from the current operation and the registered context, verifies exact receipt provenance and all public receipt fields, checks revocation/replay/time, and consumes the request under one Mutex acquisition. Every failure leaves consumption state untouched.
6. Clones of a valid receipt share its one-use identity. Successful use is recorded; all subsequent matching attempts return ApprovalReused. Re-registering a session replaces its private generation, invalidating previous requests/grants even if revision text changes A→B→A.

The public legacy ApprovalGrant::new now creates an **unissued proposal**. It cannot authorize anything, even if every visible field equals a genuine grant. Its retained constructor is not an issuance bypass. Predictable IDs/token strings are correlation labels, not bearer credentials: verification relies on the broker's registered private receipt identity and stored context. Receipts and generation markers remain alive in broker state, so a fresh receipt cannot inherit the provenance of a dropped allocation while that state exists. No cryptographic signature or persistent token is claimed.

## Exact binding and canonical operation identity

The complete authorization binding consists of registered session generation and security fields, workspace identity, explicit revision, current classification and the canonical OperationAction identity. The receipt's actor, issuance timestamp, workspace, classification, revision, token label and IDs must also exactly match its trusted issuance record. Caller metadata is compared, never used as proof of issuance.

action_digest remains a **canonical structured descriptor, not a cryptographic digest**. Version 2 uses a variant tag, UTF-8 byte-length prefixes for every variable string, list counts and individually framed list elements. This includes tool/model/resource identifiers, metadata paths, ordered arguments, untrusted flag, micro-USD cost, export destination/external flag/optional destination class, checkout file count and exact target paths. None uses a distinct fixed marker; classification variants have fixed disjoint names. Checkout path sorting intentionally preserves the previous order-insensitive target-set identity; argument order remains significant. Empty argument lists differ from lists containing empty arguments. No delimiter escaping assumption or partial action-name comparison is used.

Missing names, NUL arguments and inconsistent checkout counts deny before requesting/consuming approval. This is not filesystem canonicalization or permission to execute the action. The v2 encoding and issuance/context API changes require call-site migration; old descriptors/proposals are not imported into the new in-memory broker. No storage migration or cryptographic dependency is introduced.

## Default denial, expiration and concurrency

For approval-required operations, evaluate without a grant returns NeedsApproval for planning; it never grants execution. Direct verify_and_consume(None, ...) returns MissingApprovalGrant. Existing non-sensitive automatic policy rules remain available only with a validated registered context and no presented receipt. Presenting an unknown, stale or forged receipt cannot fall through to an automatic success.

Unknown operations and forbidden information flows retain their existing denial rules. Approval validates a specific operation; it does not override those other policy rules or supply an unavailable execution capability. A broker receipt must not be treated as a substitute for PolicyEngine evaluation and the future dispatch/containment gates.

Expiration uses the existing Clock and TimestampUtc semantics: now at or beyond expiry denies. Issuance/consumption before recorded creation/issuance also deny. No new wall-clock expiry call was added. The preexisting sequential request-ID generator remains a correlation mechanism; production CSPRNG generation and its separate fail-closed limitation were not changed.

Context comparison, private receipt verification, expiry, replay checks and the consumed-state mutation occur under the same Mutex. There is no successful validate-only grant API. Mismatches are checked before replay state, so mismatching attempts cannot consume/invalidate a legitimate grant and produce stable mismatch denials regardless of the winning matching thread. Context replacement/revocation and issuance use that same synchronization boundary. Poisoned state denies instead of proceeding without verification. Broker, authority, engine and receipts remain Send + Sync.

## Regression matrix

Each scenario below exercises actual evaluator and/or broker consumption, not just descriptor equality. The focused test file contains the complete named cases; the raw record lists every executed outcome.

| Required scenario | Status | Evidence |
| --- | --- | --- |
| Exact approved operation/target | Passed | Policy grants once; direct broker and policy replay deny |
| Same session, different action type | Passed | Parameter matrix plus original metadata A/B regression |
| Changed arguments/resource/untrusted flag/cost | Passed | Matrix covers all ExecuteTool/InvokeProvider fields and ordered/delimiter-bearing arguments |
| Changed target path/workspace | Passed | Discovery/checkout/export target matrix and registered workspace rebinding |
| Changed revision | Passed | Trusted revision changes invalidate use and stale issuance, including ABA restoration |
| Different session | Passed | A second registered session with the same workspace cannot consume the grant |
| Modified approval metadata | Passed | Every public receipt field rejects; changed request display cannot change issuance/expiry |
| Unknown grant/request ID | Passed | Unknown IDs deny in evaluator/consumer/issuer paths |
| Forged/caller-created grant | Passed | Known request alone and copied visible receipt fields lack registered provenance |
| Expired grant | Passed | Exact expiry boundary denies issuance, evaluator and broker consumption |
| Previously consumed grant | Passed | Matching replay returns ApprovalReused |
| Missing/malformed security context | Passed | Unconfigured engine, blank/zero required fields and missing required grant deny |
| Two matching concurrent attempts | Passed | Exactly one winner and one replay per barrier round |
| Mismatch before matching attempt | Passed | Mismatches do not consume; legitimate matching action then succeeds once |

Additional coverage includes classification binding/floor, invalid-grant automatic-fallback prevention, poisoned Mutex, cross-broker provenance, caller metadata replacement, capability separation and redacted diagnostics. All 27 focused regressions and the poison test are executed, not ignored.

## Commands, counts and reproducibility

Run from the repository root:

```powershell
pwsh -NoProfile -File experiments/phase1/authorization/Validate.ps1
```

The [final raw result](../../experiments/phase1/authorization/results/1793904967368.json) records all 13 exact command arrays, full stdout/stderr, exits, timeouts, individual tests, aggregate summaries, versions, zero dependencies and 37 input SHA-256 digests. Inputs did not change during execution. The earlier 1793904491573 record is preserved; the final run strengthens the two compile-fail examples with their real method signatures, without changing runtime behavior or counts. Environment: Windows 11 x64, reported build 10.0.26300; PowerShell 7.6.9; installed Rust/Cargo 1.99.0, x86_64-pc-windows-msvc. No dependency/toolchain download, network operation, API key, telemetry or host configuration change occurred.

| Check | Status | Actual outcome |
| --- | --- | --- |
| cargo fmt --all -- --check | Passed | Exit 0 |
| cargo check --offline --workspace --all-targets | Passed | Exit 0 |
| cargo clippy --offline --workspace --all-targets --all-features -- -D warnings | Passed | Exit 0; no warnings |
| cargo test --offline --workspace | Passed | Exit 0; 101 runtime tests + 2 compile-fail doctests Passed, 0 Failed; 3 unrelated fixture/scale cases ignored |
| Focused authorization_tests | Passed | 27 passed, 0 failed/ignored |
| Explicit concurrency repeat | Passed | 2 passed, 0 failed/ignored; 25 unrelated focused cases filtered |
| Original A/B standalone compile/run | Passed | Exit 0 with the exact mismatch/positive/replay output below |
| Probe rustfmt, dependency metadata and library artifact | Passed | Exit 0; metadata contains zero third-party dependencies |

Workspace runtime groups: 4 unit tests, 27 authorization regressions, 9 domain tests, 9 policy tests, 10 prior security tests, 5 session tests and 37 workspace integration tests. All 33 original 5.2/5.2.1 test intents pass after the required approval API migration. The grant-binding suite ran in the workspace command, separately, and in the explicit concurrency repeat.

Documentation verification Passed for 41 Markdown files, 296 local file/fragment links, 83 tables, all 41 requirement mappings and seven consistent ADR status records. Eight existing whitespace warnings remain in the design document; those unrelated lines were preserved. PowerShell parsing and Git diff whitespace checks pass. Final source digests match all 37 recorded inputs; the 95 unrelated original files, including workspace/domain/session/budget code, existing fixture tests, dependencies and ADRs, match their entry digests.

Each concurrency invocation executes 64 rounds with two matching and six mismatching consumers, then 32 rounds of eight mismatches followed by a legitimate consumption and replay. The explicit raw repeat reports:

```text
CONCURRENCY rounds=64 matching_successes=64 matching_replays=64 mismatches=384
CONCURRENCY rounds=32 mismatches=256 legitimate_successes=32
```

The same two tests also executed in the full and focused runs: 288 new barrier rounds across the three commands. The prior 20-thread single-winner test also passes. No sleep or scheduling-order assumption is used.

The original standalone probe now requires trusted setup and a **genuinely issued** grant, asserts the precise A→B mismatch denial, then verifies the matching A succeeds once and replay denies. It cannot pass merely because the engine is unconfigured or the grant unissued:

```text
POLICY_CONTEXT_BINDING=Passed: mismatched metadata action rejected; matching action accepted once; replay rejected
```

The earlier Failed JSON remains unchanged as historical evidence. The runner builds only the reviewed local library and this synthetic probe; no target code, target build script, scanner or real provider is invoked.

## Not tested, blocked items and remaining risks

- **Not Tested in this increment:** the unchanged Windows junction fixture, deny-ACL fixture and 10,000-file scale test are the three explicitly ignored workspace cases. Their actual 5.3 results remain historical; they are not counted Passed here. Workspace source/tests and that runner are unchanged.
- **Not Tested / outside this correction:** remote human authentication/UI integrity, durable or cross-process approvals, external dispatch, filesystem snapshot/containment guarantees and Linux/macOS/ARM64 execution. The trusted controller must authenticate human intent, read the broker's current request and keep ApprovalAuthority out of untrusted request handlers. Actor strings alone do not authenticate a human.
- **Remaining risk:** context registration must use the actual authorized workspace/revision/classification. The broker detects a changed registered context; it cannot observe an unreported filesystem/Git revision change. Exact canonical descriptor equality is not a cryptographic content identity or immutable snapshot. Future side-effect code must correlate dispatch/leases and recheck target state; no such dispatch is implemented here.
- **Remaining limitation:** receipts, generations, requests and replay tombstones are in-memory and retained for the broker lifetime. There is no persistence, import of serialized grants, cross-process token protocol or bounded retention implementation. A fresh unconfigured broker fails closed; old receipt DTOs cannot recreate issuance provenance.
- **Blocked mandatory 5.3.1 acceptance items:** none. The reported defect and required negative cases are tested closed in the current in-process model. Full Phase 1, worker containment, production persistence and provider/privacy/license validation remain incomplete as previously documented.

## Repository and scope preservation

Entry was clean develop at 5c6242f9d957abd226b59a550b3106056ad6998d, whose parent is the preserved 4267b42 hardening commit. No initial user changes were present. During this work, external commit 97b49c8d72c348b45722d1685cf5fcc9d3958697 recorded most of the correction/documentation, followed by c60374deeaa5386b330c42bad5e670816bc64617 recording the compile-fail refinement and final evidence. Their parents are 5c6242f and 97b49c8 respectively. Both were inspected and preserved. Entry HEAD/index/reference targets therefore moved outside the agent's issued operations; they are not represented as unchanged throughout the increment. Final Git guards compare against a read-only snapshot after those external commits, while workspace/domain/session/dependency/ADR digests are compared against entry. The agent leaves its edits unstaged for owner control and does not describe externally committed edits as pending.

The agent issued no commit, amend, reset, rebase, cherry-pick, tag, push, fetch, pull, branch change, staging, unstaging, stash or revert operation and modified no Git history, reference or index. Author metadata alone does not identify the process that performed the external operation. Accepted ADRs and the permanent Git policy are unchanged. Stop is at Increment 5.3.1; no subsequent increment is authorized or started.
