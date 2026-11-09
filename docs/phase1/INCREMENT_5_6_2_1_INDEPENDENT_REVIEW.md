# Increment 5.6.2.1 — Independent Core Service Security Review

Date: 2026-11-06. Reviewed HEAD: `a4362f61750fb90374f13b02f11052ef8adf2c34`. **Final decision: Rejected.** Verification only; no production implementation, fixes, dependency changes or ADR changes.

## 1. Executive summary

The original improvements are real but do not establish the complete authorization/error-handling contract claimed in the [5.6.2 completion report](INCREMENT_5_6_2_CORE_SERVICE_SECURITY_HARDENING.md).

| Original finding | Independently verified remediation | Closure assessment |
| --- | --- | --- |
| F-561-01 | execute_task loads a persisted session, checks its initial classification floor and calls PolicyEngine before preparation/dispatch. Straight-line denials have no budget/approval/backend side effect. | Partial. Public context setters bypass the privileged broker boundary; automatic preparation lacks a context fence; PAUSED sessions execute; the preview can claim Granted for an unrelated receipt. |
| F-561-02 | Reservation, approval consumption and both audit inserts are in one IMMEDIATE transaction. Budget exhaustion, either audit failure and a forced consumption-update error roll back correctly. Thread/connection/process races have one winner. | Partial. The new public method can consume session A's grant while reserving for session B. No-grant preparation cannot carry/recheck the evaluated context. Declared provider action cost and reserved cost can disagree. |
| F-561-03 | Both dispatch-Err and evidence-Err handlers now expose actual secondary settlement failures; successful cleanup produces a standalone primary error and retains unknown usage conservatively. | Original silent-drop paths fixed; full closure rejected. Failed/TimedOut/Cancelled result paths still erase the primary outcome when settlement fails. Error objects/codes become strings and sensitive diagnostic inputs are printed. |

The final independent suite executes **23 security/reliability assertions: 11 Passed, 12 Failed**, plus one filtered child helper exercised by parent tests. Failures are secure-behavior assertions, not tests rewritten to accept vulnerabilities. Three findings are High, seven Medium and two Informational. A separate existing workspace invalidation regression failed in the full run and in **6/20** isolated repetitions; successful validator runs do not cancel those observations.

## 2. Scope, method and inspected files

Inspected actual [Core Service](../../crates/sentra-core/src/service/core.rs), [service errors](../../crates/sentra-core/src/service/error.rs), service configuration/lifecycle/harness, [policy engine](../../crates/sentra-core/src/policy/engine.rs), [broker/authority](../../crates/sentra-core/src/policy/approval.rs), canonical actions/classification/session types, [persistence repository](../../crates/sentra-core/src/persistence/repository.rs), DTOs/schema, connection/managed transaction/retry code, execution engine/backends/result validation, and evidence metadata/verifier/error formatting. Existing service, policy, authorization, persistence, execution/evidence and workspace tests were read and run.

Context includes AGENTS.md and owner/global instructions, [Core Engine design](CORE_ENGINE_DESIGN.md), [5.6 integration](INCREMENT_5_6_CORE_SERVICE_INTEGRATION.md), [5.6.1 review](INCREMENT_5_6_1_INDEPENDENT_REVIEW.md), 5.6.2 report, accepted ADRs 0003–0006, requirements and earlier persistence/authorization records. Historical report conclusions were not treated as implementation evidence.

Evidence labels below mean: **Runtime** = actually executed native synthetic fixture; **Code** = inspected control/data flow; **Not Tested** = no execution proof. Component interleaving is distinguished from an end-to-end CoreService race. Native SQL trigger injection and closing a managed fixture database are test-only operations, not production fault hooks or physical I/O fault simulation.

New artifacts: [independent tests](../../crates/sentra-core/tests/independent_core_review_tests.rs), offline review driver, raw results, this report and PROGRESS.md. Assertions are ignored by ordinary Cargo runs to keep the independent review separate, and **all 23 are explicitly executed** by the recorded review command. A normal workspace pass therefore does not imply they passed.

## 3. Git safety and working-tree preservation

Entry was clean `develop`, tracking local `origin/develop`, at `a4362f61750fb90374f13b02f11052ef8adf2c34` (`Harden core service authorization and budgets`), parent `c4ab5e74c27c28649a06b5fa05e4d186f4dbd14a`. No staged, unstaged or untracked repository files existed at entry. A before-snapshot captured all refs, visible history, staged entries, physical index SHA-256 and all **193 original tracked file hashes**. Original index SHA-256: `f75ed732d543da079bcabacd13335a579277746c05422ccc99ba165fef58224d`.

Only PROGRESS.md may differ among original files; production Rust/SQL, existing tests, manifests, lockfile, previous raw records and all ADRs must remain byte-identical. New review/validator result files remain untracked/unstaged. Read-only Git commands use `--no-optional-locks`; no commit, tag, amend, reset, rebase, cherry-pick, checkout, staging/unstaging, stash, revert, fetch/pull/push or reference modification was issued. Final comparison is recorded in repository review evidence.

Final read-only comparison: branch/HEAD/history/refs/index entries **and physical index bytes unchanged**; all 193 original file hashes match except the intended PROGRESS.md update. Local origin/develop remains at the same HEAD, ahead/behind **0/0**, with no remote refresh. Working tree: **1 modified tracked document, 12 untracked review/result artifacts, 0 staged files**. The two touched Markdown documents pass checks for 78 local file/fragment links, nine table blocks, 41 requirement references and all seven unchanged ADR status records. ADR-0002/0007 remain Proposed. Whitespace diff verification exits 0.

## 4. F-561-01 — Mandatory policy enforcement

**Runtime and Code, verified:** execute_task takes a session ID, not caller-supplied SessionMetadata. It reloads SessionRecord from SQLite, rejects terminal state, rejects requested classification below the initial persisted floor, registers that snapshot, and evaluates the actual typed action with `None` as the **in-memory** grant. Classification Ord/PartialOrd use explicit ranks 10/20/30/40; storage classification parsing checks canonical values. Declaration order/string aliases do not bypass the floor. Unknown/malformed operations and no-write-down violations deny. Unknown/missing sessions deny. Actual observer tests assert zero backend calls and unchanged SQL budget/approval state for denial, missing approval and terminal-session branches.

**Remaining gaps:**

- `PolicyEngine::register_session_context` delegates to a newly public `ApprovalBroker::set_session_context`, which mutates the live trusted map without ApprovalAuthority. Both request-side routes overwrite metadata/revision/floor and rotate generation. Runtime tests lower an authority-installed Restricted floor to Public and obtain Granted. This applies to holders of a shared engine/broker reference; it is not a claim that a remote caller can access CoreService's private field directly.
- Registration, evaluation and SQL preparation have separate lock/transaction boundaries. Registration ignores its returned error in create/evaluate/execute. A poisoned/unavailable broker still causes evaluate to deny, so that ignored error is not itself a permissive fallback. Unconditional replacement, however, can install an older snapshot and is not a monotonic synchronization protocol.
- A registration of identical values changes the Arc generation and invalidates an already issued in-memory receipt. Runtime verified; persistent receipts use different trusted provenance and are not invalidated by this memory-only refresh.
- Only terminal eligibility is checked. PAUSED passes and actually reaches the controlled backend without a resume transition; [the design](CORE_ENGINE_DESIGN.md#valid-state-transition-matrix) describes pause/revoked leases and resume/re-evaluation. Scoped synthetic operation is deliberately exercised by existing tests and is not mislabeled as an unauthorized state merely because it is not Running.
- `evaluate_action` converts NeedsApproval into Granted for **any** Some(persistent grant), without checking that receipt. An A receipt produces Granted for B. execute_task independently rejects such an A-on-B service request, so this is a false authorization preview, not proof of direct service execution with that receipt.

### Context consistency window

**Code-inferred end-to-end schedule; component counterexample Runtime:** A reads generation 1 / revision A / Internal floor. A trusted controller changes SQLite to generation 2 / revision B / Restricted floor. A can reinstall its older memory snapshot, evaluate an otherwise automatic Internal action, then prepare with no grant. That request contains no expected metadata, generation, revision, classification or action. The transaction sees the new SQL record but only tests terminal state/budget and commits. The resulting ExecutionRequest still uses A's old revision.

The test executes the real policy decision, trusted context update and no-grant preparation in this order and demonstrates acceptance. It does **not** force this complete live schedule through execute_task; that timing reproduction is **Not Tested** because no production scheduling hooks were added. For grant-present operations, `current(tx,intent)` instead detects changed generation/revision/floor and fails closed. Context mutation requires a trusted controller/shared broker handle; ordinary source text cannot mutate SQLite authority by itself.

## 5. F-561-02 — Atomicity and authorization consistency

### SQL transaction trace

`reserve_budget_and_consume_approval` uses one `manager.write` / `transaction::attempt` / BEGIN IMMEDIATE:

1. Validate scalar reservation fields and local receipt seal.
2. Inside the transaction read current context/approval, compare frozen snapshot and receipt fields, exact action/type/arguments/paths/classification, state and exclusive expiry.
3. Independently read the reservation session and its fresh budget totals/ceiling.
4. Insert the reservation and BudgetReserved audit.
5. Conditionally change exactly one ISSUED row to CONSUMED using all stored bindings, token and time bounds; insert ApprovalConsumed audit.
6. COMMIT, then return records. No external operation is inside this retry closure.

For an honestly matched request, steps 2–6 are atomic. For a deliberately split request, step 2 validates session A and step 3 validates session B; **nothing equates these identities**. Runtime reproduction leaves A's receipt CONSUMED, A budget 0 and B budget 7. The service currently constructs both IDs consistently; the public primitive still violates its binding contract and must not be relied on by another caller until corrected.

**Runtime, Passed:** insufficient budget retains ISSUED state and no new audit/reservation; exact retry succeeds once. Duplicating either audit event ID rolls back every earlier mutation. An owned trigger rejects the approval transition with actual SQLite code **1811**, after reservation/audit insertion, and all preceding work rolls back. Removing the fixture trigger allows legitimate consumption. Event sequences remain contiguous; failed attempts do not leave successful audit rows. Mismatched operation, generation, revision and expiry do not reserve/consume. Existing legacy provenance/unknown-reference/compile-fail tests also run; no new grant forgery API was introduced for testing.

**Runtime, Passed:** eight matching thread contenders have exactly one consumer; eight additional 40-unit reservations against the remaining 93-unit budget have exactly two successes, total 87. Separate manager connections have one consumer. Two independent owned processes recover their own private receipts, wait on pipes before invoking the **new atomic method**, and produce one Consumed/one ApprovalReused, one reservation and one consumption audit. These are SQLite cross-process results, not just a shared Mutex result.

**Code and existing unit tests:** every managed SQL error explicitly aborts the active transaction and latches failure, even if caught internally. Rollback errors are separate and halt access; existing fault injection is not a real fsync experiment. BUSY/BUSY_SNAPSHOT retries restart the complete database operation, read fresh values and stop after five attempts with 10–250 ms bounded backoff. They do not rerun the earlier in-memory policy evaluation. All grant-present binding checks and budget calculations occur on each attempt; missing automatic-operation context remains missing on every attempt. The real stale-snapshot unit fixture exercises the shared mechanism with a deliberate first DEFERRED read; production preparation uses IMMEDIATE.

Raising a budget through context re-registration rotates persisted generation and requires a new grant. Preserving ISSUED on budget exhaustion is not permission to ignore that context change. An unchanged context can retry after an appropriate existing reservation is reconciled, or with a valid smaller non-provider reservation; the original service test uses the latter.

### Memory versus persistent state

| Boundary / failure | Actual behavior |
| --- | --- |
| In-memory policy evaluation | Called with None, so it does not consume an in-memory grant. NeedsApproval creates a separate pending memory request. |
| Persistent issuance/consumption | Uses private PersistentApprovalGrant, its local seal and SQL snapshot/row; no conversion from the in-memory ApprovalGrant. |
| SQL rollback/database failure | SQL reservation/consumption/audits revert; any memory registration/pending policy request remains. No distributed commit with the memory broker exists. |
| Concurrent context registration | Map replacement and evaluation are separately locked; old snapshots can overwrite current memory state. Identical refresh invalidates memory receipts. |
| Retry after failed preparation | SQL receipt remains issued if transaction aborted; no memory receipt was consumed by the service. The partial context fence still differs between grant/no-grant paths. |
| Restart | Memory cache/pending requests disappear; SQL states survive. Recovery of a private receipt is privileged and explicit, not arbitrary deserialization/identifier trust. |

It would be incorrect to claim that PolicyEngine consumed a memory grant and SQLite later rolled that consumption back: **that is not this service call path**. It would also be incorrect to call the memory snapshot/decision and durable preparation one atomic authorization boundary.

### Process termination and side effects

An owned child runs the actual service through committed preparation and enters its controlled backend, which blocks on a pipe **before its fixture effect**. The parent observes the committed pair, kills that process, then checks integrity and observes CONSUMED + RESERVED/NULL usage, both ordered audit events and replay rejection. This verifies conservative post-commit persistence. It does not test a literal instruction between COMMIT and entering dispatch, nor termination midway through the new prepare transaction. Mid-transaction statement rollback is tested; exact new-method mid-transaction process termination is **Not Tested**.

The post-commit/pre-effect window already existed as F-561-04. No durable task/outbox/lease couples reservation to actual effect/result; ExecutionId is allocated afterward. A killed attempt can permanently consume the approval without completing an effect, while budget remains held. This is bounded conservative behavior for the synthetic-only profile, not end-to-end exactly-once execution or completed ADR-0003 recovery. Do not automatically replay ambiguous sensitive effects.

## 6. F-561-03 — Settlement and errors

| Path | Runtime result |
| --- | --- |
| dispatch returns ExecutionError; settlement also fails | ExecutionWithSettlementFailure; both messages visible; secondary accessor identifies Closed; SQL remains RESERVED with NULL actual cost. Passed. |
| verifier returns EvidenceVerificationError; settlement also fails | EvidenceWithSettlementFailure with the same conservative hold. Passed. |
| Either error path; settlement succeeds | Standalone Execution/Evidence error, no invented secondary failure; unknown usage remains held. Passed. |
| Valid Failed/TimedOut/Cancelled ExecutionResult; settlement fails | **Persistence only** for all three; original status/exit code/outcome is unavailable. Failed. |
| Compound typed primary/source information | Both concrete error objects are converted to strings; Error::source is None. Failed. |
| Error/authorization diagnostic redaction | Backend-message and evidence-media canaries appear in compound Display/Debug; PrepareExecutionRequest Debug prints approved arguments. Failed. |

The fault source is an actual successful shutdown of the **owned** managed connection from a controlled backend after preparation, before cleanup. This proves Closed-error handling, not physical IOERR, corruption, power loss or a failed native rollback.

`ServiceErrorKind`, is_execution/is_evidence and has_settlement_failure distinguish broad components without parsing text. They do **not** preserve the original ExecutionErrorKind/EvidenceVerificationErrorKind or structured PersistenceError fields/codes/attempts. `secondary_error: Option<String>` is inspectable but stringly typed; no source chain or typed accessor recovers those objects. It is not sufficient for classification-specific recovery without parsing rendered text. Arbitrary Display implementations are copied into message, so documenting a field as safe/redacted does not enforce redaction. The existing service redaction test actually asserts that its displayed secret remains present (`service_tests.rs:626`).

All four service settlement call sites were inspected: dispatch error, evidence error, terminal result and cancel_task. cancel_task propagates persistence failure with `?`; its primary cancellation report is a simulation, not real VM termination. No remaining `let _ = settle_budget(...)` occurs in these handlers. Terminal success settlement errors remain observable as Persistence; negative terminal outcomes additionally need their primary outcome preserved. TimedOut/Cancelled unknown usage and error cleanup retain NULL usage; they are not zero. Normal completed/failed synthetic results use the request estimate as actual cost, not a measured provider receipt; this is not validated provider billing and must not be carried into real paid operations unchanged.

## 7. Executed commands and raw evidence

Windows x64, PowerShell **7.6.9**, Rust/Cargo **1.99.0**, existing MSVC/cached SQLite dependencies. No other host/ARM64 support claim. All Cargo invocations are offline; no dependency, external service, API key, target code/build hook, VM/container, elevation or host security configuration change was introduced. Only Sentra/cached-dependency compilation and repository-controlled fixtures ran.

| Command / record | Actual result |
| --- | --- |
| Baseline before adversarial tests | fmt/check/Clippy/tests/list Passed; 205 Passed, 0 Failed, 4 ignored. |
| `cargo fmt --all -- --check` | Passed, exit 0 on final sources. |
| `cargo check --workspace --all-targets --all-features --offline` | Passed, exit 0. |
| `cargo clippy --workspace --all-targets --all-features --offline -- -D warnings` | Passed, exit 0; no warning suppression. |
| `cargo test --workspace --offline` in final review run | **Failed**, exit 101: 199 runtime Passed, 1 existing workspace test Failed, 28 ignored. Five doctests were not reached in this invocation. Other full runs below pass; this failure is retained. |
| Explicit `review_` assertions, same final review record | **Failed**, exit 101: **11 Passed / 12 Failed / 0 ignored / 1 filtered child helper**, 23 assertions executed. |
| `./experiments/phase1/persistence/Validate.ps1` — raw | **13/13 Passed**, source hashes stable. Repeated checks overlap the main suite. |
| `./experiments/phase1/authorization/Validate.ps1` — raw | **13/13 Passed**, original A-to-B probe and 64/32-round legacy races pass; its workspace run is 205 Passed / 28 ignored. |
| `./experiments/phase1/workspace/Validate.ps1` — raw | **11/11 Passed**, including the three platform cases; fixture creation/restoration/cleanup Passed. |
| Existing directory-change test, 20 isolated repeats | **14 Passed / 6 Failed**, same failure as the full review run; no sleeps or production changes to mask it. |

The three scale repeats complete 10,000 entries / 310,000 bytes, with discovery times 9610/8858/8659 ms and peak RSS 7,598,080/7,598,080/7,897,088 bytes. This is fixture metadata performance, not isolation or persistence production-load validation. ACL changes occur only on the two validator-owned disposable objects, are restored, and are not host configuration changes.

Command execution has **0 Blocked and 0 timed-out checks** in these final records. A Failed assertion is not reclassified as an environmental blocker or as Passed. Untested engineering areas are listed separately in §10.

Earlier development review runs and added two-process/preview run remain as raw history; their different test denominators are not added to the final count. Final review source hashes were unchanged during its execution. No production modification was made to make a failing assertion pass.

## 8. Reconciled test inventory

| Existing suite | Discovered | Passed in baseline / successful complete run | Directly ignored |
| --- | --- | --- | --- |
| Unit tests | 14 | 14 | 0 |
| authorization_tests | 27 | 27 | 0 |
| domain_tests | 9 | 9 | 0 |
| evidence_tests | 9 | 9 | 0 |
| execution_evidence_adversarial_tests | 11 | 11 | 0 |
| execution_tests | 8 | 8 | 0 |
| persistence_tests | 43 | 42 | 1 child helper |
| policy_tests | 9 | 9 | 0 |
| security_tests | 10 | 10 | 0 |
| service_tests | 19 | 19 | 0 |
| session_tests | 5 | 5 | 0 |
| workspace_tests | 40 | 37, with one intermittent failure retained separately | 3 platform cases |
| Compile-fail doctests | 5 | 5 | 0 |
| **Existing total** | **209** | **205 = 200 runtime + 5 doctests** | **4** |
| Added independent review suite | 24 | 11 Passed / 12 Failed in explicit run | 24 in ordinary runs; 1 child helper filtered by explicit review command |

After adding review artifacts, `cargo test --workspace --offline -- --list` discovers **233 = 228 runtime entries + 5 doctests**. Ordinary runs ignore 28 entries: 23 explicit review assertions, their child helper, the original child helper and three platform tests. All 23 assertions execute explicitly; the platform runner executes all three Windows cases; both helpers execute only through controlled parent protocols. They are not silently skipped security cases or extra unique successes.

Disjoint consolidated verdict (any observed failure takes precedence): **218 Passed, 13 Failed unique substantive tests, 2 harness-only helper entries**. The 13 comprise 12 deterministic review counterexamples plus one intermittent existing directory-observation failure. All 231 substantive tests were exercised across commands; 0 substantive cases are left Not Tested. This does not mean the untested engineering areas below are validated. If counting any observed success instead, 219 unique tests have a passing observation and 13 have a failing observation, with **one overlap**; do not sum them. No overlapping validator run, repetition or child-process invocation increases the unique denominator.

The 5.6.2 report's **222 Passed / 226 discovered / 225 with fixtures** is incorrect. Its table says 35 policy tests instead of 9 (+26), 11 evidence tests instead of 9 (+2), and omits the 11 execution/evidence adversarial tests (-11): net overcount **17**. Correct pre-review counts are 205 Passed / 209 discovered, or 208 substantive tests after the three platform cases. The 5.6.1 199-pass baseline plus six new service tests also yields 205. The persistence ignored entry is a helper already launched by parent tests, not an unexecuted cross-process scenario awaiting Validate.ps1.

## 9. Findings

| ID | Severity | Finding | Blocks next increment? |
| --- | --- | --- | --- |
| F-5621-01 | High | Public request-side context setters can overwrite trusted authorization | Yes |
| F-5621-02 | High | Atomic prepare can consume A approval and charge B | Yes |
| F-5621-03 | High | Automatic/no-grant prepare lacks authoritative context/policy fence | Yes |
| F-5621-04 | Medium | PAUSED sessions dispatch without resume | Yes |
| F-5621-05 | Medium | Canonical provider estimate and reservation can disagree | Yes before treating budget limits as enforced for paid operations |
| F-5621-06 | Medium | Sensitive authorization/error diagnostics are printed | Yes for privacy-safe service closure |
| F-5621-07 | Medium | Non-success outcomes and concrete error types are lost on settlement failure | Yes for F-561-03 closure |
| F-5621-08 | Medium | Identical context synchronization invalidates issued memory grants | Bounded in SQL-only service flow; fix before shared legacy broker use |
| F-5621-09 | Medium | Preview returns Granted for an unrelated receipt | Yes before clients rely on preview authorization; execute_task still rechecks |
| F-5621-10 | Informational | Post-commit/effect recovery is conservative, not exactly once | No for current synthetic profile; gate real side effects |
| F-5621-11 | Informational | Test/cryptographic guarantee claims exceed actual evidence | Correct status now; do not carry claims into readiness approval |
| F-5621-12 | Medium | Existing retained-directory observation misses ordinary changes intermittently | Follow-up required before relying on observation stability; independent of new service fixes |

Detailed reproduction, impact and recommendations follow. No recommended change is implemented by this review.

### F-5621-01 — Request-side authority escalation

- **Location:** `policy/engine.rs:72` register_session_context; `policy/approval.rs:271` ApprovalBroker::set_session_context, contrasted with privileged ApprovalAuthority::set_session_context at line 412.
- **Conditions/reproduction:** Obtain a delegated reference to a live engine or broker; an authority has installed a Restricted context. Register that same session with Public floor and a replacement revision through either request-side route, then evaluate Public metadata discovery.
- **Evidence:** Runtime `review_public_context_registration_cannot_lower_trusted_floor` fails for **both** routes (`[false,false]` secure outcomes). The previously denied action becomes Granted. Code inserts directly into the same shared map; no authority check exists.
- **Impact:** A delegate can overwrite authorization state established by the trusted authority. CoreService privately owns its engine and initially checks the SQL floor, so this is not asserted to be a remote standalone exploit of its private field. It violates the earlier read/plan/consume capability boundary and matters for shared clients and concurrent synchronization.
- **Recommendation:** Restore privileged context mutation; synchronize only from a trusted, versioned service snapshot through that authority. Do not expose a request-side setter that merely labels supplied values trusted. **High; blocks the next increment.**

### F-5621-02 — Split-session atomic preparation

- **Location:** `persistence/repository.rs:209` PrepareExecutionRequest and `:379` reserve_budget_and_consume_approval, particularly independent context loads before reservation and consumption.
- **Conditions/reproduction:** Two valid sessions A/B in the same repository; issued A grant and fully matching A ApprovalIntent; request.session_id set to B. No forged receipt or database tampering is needed.
- **Evidence:** Runtime `review_atomic_prepare_cannot_consume_a_while_reserving_for_b` fails: successful transaction, A receipt CONSUMED, A budget 0, B budget 7. The two audits are assigned to different sessions.
- **Impact:** An atomic transaction can still describe an unauthorized combination of subjects. The current service constructs matching IDs; the newly public repository contract is not safe for another consumer to trust as a prepared operation.
- **Recommendation:** Require one canonical subject/context for every preparation and assert equality of reservation session, intent session, frozen receipt and authoritative snapshot inside the transaction, before mutations. Bind the complete prepared action and reservation parameters. **High; blocks the next increment.**

### F-5621-03 — Missing automatic-operation context fence

- **Location:** `service/core.rs:479` execute_task; `persistence/repository.rs:209,379` PrepareExecutionRequest and its no-grant branch.
- **Conditions/reproduction:** Policy permits an automatic Internal operation, then the trusted session changes to revision B / Restricted. Submit the existing no-grant prepare request. It has no fields expressing the policy-evaluated snapshot/action/classification.
- **Evidence:** Runtime component interleaving `review_no_grant_prepare_revalidates_context_after_policy_decision` fails. The service-level concurrent schedule is inferred from separate load/register/evaluate/prepare steps, **not** forced end to end at runtime. SQL re-reads budget and state, but not an expected security epoch for this operation.
- **Impact:** With concurrent trusted context changes, an old automatic decision can survive a revision, policy or classification-floor change. A shared-memory registration can also overwrite a newer memory context with the old read. Grant-present operations have a stronger fence and reject stale snapshots.
- **Recommendation:** Always carry the authoritative operation context, including for no-grant decisions; compare expected generation/revision/policy/floor/action inside preparation and reject/re-evaluate stale decisions. Restore privileged synchronization; do not solve this by holding SQLite locks over external execution. **High; blocks the next increment.**

### F-5621-04 — Execution while paused

- **Location:** `service/core.rs:479` execute_task and `persistence/repository.rs:379` terminal-only eligibility checks.
- **Conditions/reproduction:** Issue a valid grant, transition Scoped→Planned→Running→Paused, then execute the approved task without resuming.
- **Evidence:** Runtime `review_paused_session_cannot_dispatch_new_work` fails; the controlled backend is called and the receipt is consumed.
- **Impact:** Pause is not an effective work-dispatch boundary, contrary to the design's explicit resume/re-evaluate transition. No real VM preemption is claimed or required to reproduce this admission defect.
- **Recommendation:** Define/enforce the permitted admission states in the service and transactional current-state check. Preserve intentionally allowed Scoped synthetic fixtures, but reject Paused until an authorized resume. **Medium; blocks admission-control closure.**

### F-5621-05 — Reservation under-declares canonical action cost

- **Location:** `service/core.rs:554` preparation amount assignment and `:652` completion settlement; `persistence/repository.rs:379` reservation validation.
- **Conditions/reproduction:** InvokeProvider action declares 200 micro-USD, session limit is 100, TaskExecutionRequest.estimated_cost is zero. A controlled synthetic observer accepts the typed request; no real provider exists or is contacted.
- **Evidence:** Runtime `review_provider_action_cost_cannot_be_under_reserved` fails: backend dispatch and completion occur despite the declared action upper bound exceeding the session limit. Policy evaluates the action's 200, while preparation/settlement use the caller's zero.
- **Impact:** The generic service cannot claim its budget tracks the authorized operation's declared upper bound. This demonstrates a model inconsistency, not measured real-world overspending or invented pricing.
- **Recommendation:** Derive/validate reservation amount and model identity from the same canonical authorized operation or a trusted bounded estimate; require known actual usage before calling it actual settlement. **Medium; must be corrected before paid-provider/budget-guarantee readiness.**

### F-5621-06 — Sensitive diagnostic material is not redacted

- **Location:** `service/error.rs:124,136,180,194` compound constructors/Display/Debug; `persistence/repository.rs:208` and `persistence/model.rs:192` derived Debug; `evidence/model.rs:validate` echoing invalid media metadata.
- **Conditions/reproduction:** A backend error contains a synthetic token/path; an evidence envelope has a token-like invalid media type; or an approved action contains a confidential argument and the prepare request is Debug-formatted.
- **Evidence:** Three runtime failures: `review_compound_execution_error_redacts_backend_sensitive_message`, `review_compound_evidence_error_redacts_untrusted_metadata`, `review_prepare_debug_does_not_disclose_authorization_parameters`. The actual service paths disclose the canaries, not just a direct artificial ServiceError constructor.
- **Impact:** Ordinary diagnostic formatting can expose authorization parameters or untrusted/private metadata. The existing service "redaction" test explicitly expects its secret to be displayed and does not establish privacy.
- **Recommendation:** Retain typed errors but make ordinary Display/Debug payload-free; do not interpolate arbitrary backend/evidence/action text into safe diagnostics. Offer classified details only through an explicit controlled path. **Medium; blocks privacy-safe closure.**

### F-5621-07 — Original outcomes and typed errors disappear

- **Location:** `service/core.rs:648–666` terminal-result settlement and `service/error.rs:46,124,136,174,203` string storage/conversion/source behavior.
- **Conditions/reproduction:** A valid result is Failed, TimedOut or Cancelled, then settlement encounters the controlled Closed database. Separately inspect the primary source/type of both genuine compound handler errors.
- **Evidence:** `review_non_success_results_keep_primary_outcome_when_settlement_fails` fails for **all three** outcomes: `(Persistence,false)`. `review_compound_error_keeps_typed_primary_source` fails for both error categories: `[false,false]` source preservation. SQLite numbers/kinds/attempts survive only in formatted text; no typed secondary accessor exists.
- **Impact:** Callers cannot recover the original terminal outcome or classification-specific error data without parsing strings; the normal result branch loses even the compound-component marker. Broad is_execution/is_evidence/has_settlement_failure flags work in the two new error handlers, so this is not a claim that those flags are absent.
- **Recommendation:** Preserve typed primary errors or execution outcome plus typed secondary PersistenceError, with redacted formatting and structured accessors/source chains. Cover every non-success result branch, not only dispatch Err. **Medium; blocks full F-561-03 closure.**

### F-5621-08 — Synchronization invalidates unrelated memory approvals

- **Location:** `policy/approval.rs:271` generation replacement; `service/core.rs:363,499` per-call synchronization.
- **Conditions/reproduction:** An authority issues a memory grant, then the new synchronization API installs the identical metadata/revision/floor before consumption.
- **Evidence:** Runtime `review_same_context_synchronization_does_not_invalidate_issued_memory_grant` fails: identical refresh creates a new Arc generation and the legitimate receipt is rejected.
- **Impact:** A read/preview or concurrent request can invalidate shared broker approvals without a real context change. The current service consumes only SQL receipts, so this is bounded to shared legacy broker use rather than SQL double consumption.
- **Recommendation:** Separate read-side synchronization/validation from explicit privileged context rebind. **Do not weaken the existing explicit authority rebind/ABA invalidation rule** merely to make this probe pass. **Medium; gate shared-memory approval clients.**

### F-5621-09 — Unvalidated approval preview

- **Location:** `service/core.rs:388` evaluate_action NeedsApproval branch.
- **Conditions/reproduction:** Pass an issued A receipt to evaluate_action for B with an otherwise approval-required action.
- **Evidence:** Runtime `review_policy_preview_does_not_grant_with_another_sessions_receipt` fails; any Some(grant) is mapped to ServicePolicyDecision::Granted.
- **Impact:** The public result claims authorization without validating subject, expiry, state or provenance. Actual execute_task revalidates and the existing A-on-B service test denies, so this is bounded to callers trusting the preview.
- **Recommendation:** Return a clearly non-authorizing pending/approval-required result until the trusted mechanism validates the context; never treat presence as validity or a preview as an execution capability. Preserve atomic consumption at actual execution. **Medium; blocks clients that rely on preview authorization.**

### F-5621-10 — Durable preparation is not durable dispatch

- **Location:** `service/core.rs:571–604` committed prepare followed by ExecutionId allocation and dispatch; no durable task/outbox record in the six-table schema.
- **Conditions/reproduction:** Kill the owned service child after committed preparation, inside the backend before its controlled effect.
- **Evidence:** Runtime `review_real_process_exit_after_prepare_preserves_pair_but_cannot_replay` passes: both records/audits persist, actual cost remains NULL, replay denies. A literal between-COMMIT-and-dispatch kill is Code-inferred, not executed.
- **Impact:** The grant can remain consumed and the reservation held without a completed effect or durable execution correlation. This is conservative/ambiguous recovery, not transactional memory/worker atomicity.
- **Recommendation:** Before real effects, complete the approved ADR-0003 lease/outbox/idempotency/reconciliation design; require explicit handling of ambiguous sensitive attempts. **Informational for the current synthetic profile; real side effects remain gated.**

### F-5621-11 — Completion claims exceed implementation evidence

- **Location:** 5.6.2 completion report §6, previous PROGRESS current status, and `service/core.rs:119` "cryptographically bound" invariant comment.
- **Conditions/evidence:** Enumerate actual tests and compare the arithmetic in §8. Baseline is 205, not 222, passing tests. Canonical action framing and private Arc provenance are not cryptographic authentication; no hash/signature implementation establishes that comment.
- **Impact:** Overstated coverage and guarantees can produce an incorrect readiness decision despite a green subset.
- **Recommendation:** Use the reconciled denominators and bounded trust claims in readiness documents; correct the code comment only in an authorized remediation. Do not add crypto to legitimize the statement. **Informational; corrected current review/progress supersede the claims.**

### F-5621-12 — Existing directory-change invalidation is intermittent

- **Location:** `workspace/boundary.rs:inspect`, `workspace/platform.rs:158` same_observation, `tests/workspace_tests.rs:384` workspace_directory_change_invalidates_retained_observation. These files are unchanged by this review.
- **Conditions/reproduction:** Resolve a directory observation, create a new child through the existing fixture, immediately inspect the retained observation. Run the existing exact test repeatedly without sleeps.
- **Evidence:** One failure in the full final review run and **6/20** failures in the isolated repeat record. inspect returns Ok(directory metadata) instead of PathChanged. Other complete validator runs passed the same test.
- **Impact:** A directory mutation can be missed; the passing fixture does not prove reliable observation invalidation. Windows same_observation compares attributes, creation/write times, length and kind, not an immutable inventory identity. The exact OS/cache timing cause is **not established** by this review. No containment escape, target-content read or execution exploit is claimed.
- **Recommendation:** Investigate under the existing OQ-22 filesystem-identity gate; narrow/fail closed for any operation needing stable identity. Do not hide the counterexample with sleeps or label a successful retry a fix. **Medium; follow up before relying on observation stability, independently of the core-service remediation.**

## 10. Remaining architectural risks and untested areas

| Area | Review status / limitation |
| --- | --- |
| Complete live execute_task context-change race | Not Tested end to end; vulnerable component ordering is Runtime, complete schedule is Code-inferred. No production scheduling hooks added. |
| Kill midway through new atomic prepare before commit | Not Tested; actual statement/audit rollback and post-commit process termination were tested. Existing SQLite engine/migration crash tests are separate evidence. |
| Physical write/fsync IOERR, disk exhaustion, power loss, native rollback/close failure | Not Tested here; actual controlled shutdown is Closed, not those fault classes. |
| Hostile mapped filesystems, immutable workspace identity | Not Tested; existing directory-change counterexample is retained. No race-free filesystem isolation claim. |
| Human authentication, cross-machine approvals, compromised database administrator | Not Tested/outside local trusted-controller model; receipts are not cryptographic identities. |
| Real providers, invoices, usage measurement, transport/privacy cancellation | Not Tested; synthetic estimates are not measured final pricing. No API keys or network. |
| Hyper-V worker identity/isolation/guest communication, real VM termination | Not Tested; no VM provisioned or host configuration changed. Default supplied backends remain fail-closed for untrusted targets. |
| Streaming evidence and cryptographic SHA-256 ingestion | Not Tested/deferred; no new dependency or custom algorithm. Structural bounds do not prove cryptographic integrity. |
| Linux/macOS/ARM64 and production load | Not Tested; native results are Windows x64 only. |

The trusted bootstrap controls repository/authority/backend construction; lower-level storage records and advisory policy results must not be treated as dispatch capabilities. Permission for real untrusted execution, external data egress or Phase 2 was not granted and is not inferred from this review.

## 11. Reproduction

From the repository root in PowerShell, with the existing pre-provisioned cache:

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --offline
cargo clippy --workspace --all-targets --all-features --offline -- -D warnings
cargo test --workspace --offline
./experiments/phase1/core-review/Validate-5.6.2.1.ps1 -IncludeAdversarial
cargo test --package sentra-core --test independent_core_review_tests --offline review_ -- --ignored --test-threads=1 --nocapture
./experiments/phase1/persistence/Validate.ps1
./experiments/phase1/authorization/Validate.ps1
./experiments/phase1/workspace/Validate.ps1
1..20 | ForEach-Object { cargo test --package sentra-core --test workspace_tests --offline workspace_directory_change_invalidates_retained_observation -- --exact }
```

The explicit review command is expected to return nonzero on this implementation; that is evidence to remediate, not a waiver. The review driver records stdout/stderr, exact arguments, source hashes and per-test statuses in timestamped JSON. The ordinary Cargo command does not run the ignored review assertions. The directory observation may fail intermittently; reproduce/disclose outcomes rather than retrying until green. Test-only databases, triggers and processes belong to `target/independent-5621-fixtures`; parent-controlled children never run repository targets or shell commands. Fixture cleanup retains no user databases. All review artifacts remain unstaged.

## 12. Final decision

**Rejected.** Do not close F-561-01/F-561-02/F-561-03 or proceed on the assumption that the claimed authorization, binding and error-handling invariants are satisfied. Preserve the verified atomic rollback/single-winner behavior while correcting the blocking defects through a separately authorized remediation. The intermittent workspace result also requires explicit follow-up; it is not silently waived.

This review implements no fix and starts no subsequent increment. Phase 1 remains incomplete; Phase 2 has not started. No untrusted target workload, guest VM, provider request, networking or host security configuration change occurred. No Git history, reference or index mutation was performed.
