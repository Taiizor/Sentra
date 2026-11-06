# Increment 5.6.2.2 — Authorization Context and Error Integrity Remediation

Date: 2026-11-06. Status: **Implemented and tested; ready for owner review.** This is targeted remediation, not an independent approval or Phase 1 completion. Phase 2 and subsequent increments have not started. The [rejected independent review](INCREMENT_5_6_2_1_INDEPENDENT_REVIEW.md) remains unchanged as historical evidence.

## 1. Reproduction and scope

Entry was clean `develop` at `fd83f0c46b23246dbdfca060ef045433b3bd2715`, with local `origin/develop` at the same commit. The owner-created commit includes the previous review, tests and raw results; there were no pre-existing unstaged/staged/untracked files to overwrite. All 205 original tracked files were fingerprinted before edits, together with HEAD, branch, full reachable history, references, index entries and physical index bytes.

The [fresh pre-fix baseline](../../experiments/phase1/core-review/results/5621-1793935908716.json) ran the previous review driver unchanged: fmt/check/Clippy/ordinary tests Passed, but the explicitly executed 23 adversarial cases again produced **11 Passed / 12 Failed**. This was a reproduction, not acceptance of the earlier completion claim. The [correctly selected pre-fix directory test](../../experiments/phase1/core-review/results/5622-directory-before-exact-1793936626701.json) failed **7/20** repetitions (13 Passed), independently reproducing the earlier 6/20 evidence. An earlier mistaken filter selected zero tests; that [raw record](../../experiments/phase1/core-review/results/5622-directory-before-1793936612686.json) is retained and contributes **zero executed test cases**.

Only policy context ownership, persistent preparation/settlement ownership, service admission/errors, retained directory observations and their tests/documentation changed. SQL schema, migrations, dependency manifests/lockfile, accepted ADRs, provider/VM/evidence-verifier implementations and execution backend remain unchanged. The old test source is preserved byte-for-byte in the [archive](../../experiments/phase1/core-review/archive/5.6.2.1-tests.rs); its current compiled version is adapted to the necessary API correction and promoted to ordinary regression coverage. The original review and all pre-entry raw results are untouched.

| Changed implementation / tests | Purpose |
| --- | --- |
| `policy/approval.rs`, `policy/engine.rs` | Read-only request-side comparison; authority-only context mutation; pure persistent policy evaluation. |
| `session/state.rs` | Shared explicit execution-eligibility rule. |
| `persistence/connection.rs`, `error.rs` | Safe per-session admission guards and ContextBusy. |
| `persistence/repository.rs`, `model.rs`, `mod.rs` | Opaque execution context, same-owner atomic prepare, lifecycle fencing, session-bound settlement and redacted approval intent; private-field compile-fail regression. |
| `service/core.rs`, `error.rs`, `mod.rs` | Single authoritative service path, truthful preview, dispatch guard ownership, typed errors/outcomes and conservative unknown usage. |
| `workspace/boundary.rs` | Exact bounded child-name revalidation independent of timestamps. |
| `tests/independent_core_review_tests.rs`, `service_tests.rs`, `workspace_tests.rs` | 23 promoted review regressions, 7 added service/persistence regressions and 1 deterministic directory regression; structured error assertions replace raw-string expectations. |
| Documentation, new PowerShell driver, archive and raw records | Reproducibility, current status and preservation of previous evidence. |

All Rust paths in this table are relative to `crates/sentra-core/src/`, except the explicit `tests/` paths, which are relative to `crates/sentra-core/`.

| Finding group | Remediation status in this increment |
| --- | --- |
| F-561-01 / F-5621-01, -04, -08, -09 | Implemented and tested: ownership, state eligibility, non-mutating comparison and exact preview. |
| F-561-02 / F-5621-02, -03, -05 | Implemented and tested: indivisible context, same-session transaction, all-path freshness and canonical provider quote. |
| F-561-03 / F-5621-06, -07 | Implemented and tested: typed primary/secondary causes, redacted preparation/errors and negative terminal outcomes. |
| F-5621-12 | Reproduced and fixed for ordinary child-name changes; deterministic and 20-round regression evidence. Broader OQ-22 limits remain. |
| F-5621-10, -11 | Conservative crash window remains explicitly open; test inventory and non-cryptographic guarantee descriptions corrected. |

## 2. F-561-01 — Authoritative context and eligible states

**Root cause:** request-side `ApprovalBroker::set_session_context` and `PolicyEngine::register_session_context` installed/replaced trusted context without the separate authority. Service refreshes rotated the memory generation, silently ignored registration errors, and could reinstall a stale SQL snapshot. Terminal-only checks admitted Paused sessions.

**Implemented boundary:**

- Those two request-side methods now only compare against an already owner-installed context. Missing context, changed session metadata, revision or classification floor is rejected without mutation. An exact comparison does not rotate generation. Only `ApprovalAuthority::set_session_context` mutates legacy in-memory context; explicit owner rebindings still rotate generation and retain ABA protection.
- The persistent service uses **SQLite security snapshots as its sole session-context authority**, not a synchronized second memory map. `PersistentApprovalAuthority::execution_context` reads the authoritative session, applies `PolicyEngine::evaluate_authoritative` and freezes the result in a private-field `ExecutionContext`. The authority is an explicit privileged capability, never obtained from execution request metadata. Cloning an existing authority does not let a repository-only caller construct one.
- The pure policy path shares operation validation with legacy policy: unknown/malformed operations, write-down and classification-floor violations deny; sensitivity, Restricted processing and the configured auto-budget threshold require approval. A provider action's canonical estimate must equal its reservation quote. The service fixes its auto-budget configuration at construction. Context registration persists policy ID, revision, generation, floor and budget limit together; explicit owner updates increment generation, keep prior snapshots and append an audit event.
- `SessionState::allows_execution` permits **Scoped, Planned and Running**. Created, WaitingForApproval, Paused, Completed, Failed and Cancelled deny. Scoped synthetic fixtures remain compatible with existing behavior. The authoritative mint, transaction preparation and service boundary enforce eligibility. Terminal contexts cannot be rebound and terminal transitions remain prohibited.
- Policy preview validates the exact persistent receipt without consuming it. Merely supplying `Some(grant)` cannot yield Granted for another operation/session. Preview is advisory; execution revalidates.

**Tested:** both public replacement routes cannot lower a Restricted floor; no-op comparison preserves a memory grant; genuine owner rebinding still invalidates old grants; stale generation/revision and every ineligible state deny; valid flows authorize exactly once. A new compile-fail doctest proves consumers cannot redirect a private execution context.

## 3. F-561-02 — Transaction binding and lifecycle fencing

**Root cause:** old `PrepareExecutionRequest` separately supplied the reservation session/model/amount and optional caller-created approval intent. One transaction could validate/consume A and charge B. Its no-approval path carried no expected generation, revision, classification or action. SQL atomicity did not synchronize external memory authorization.

### Immutable transaction input

The corrected request contains one authority-minted `ExecutionContext`, an optional private persistent receipt, reservation ID and two audit IDs. It has **no independent session ID, model ID, amount or ApprovalIntent**. The immutable context contains the repository's private provenance seal, full persisted security snapshot/metadata, exact typed action, classification, amount and trusted approval requirement. Model/category is derived from that action. Canonical action identity covers arguments and target paths; it remains a length-framed descriptor, **not cryptographic protection**.

Within the existing retryable `BEGIN IMMEDIATE` transaction, preparation:

1. Re-reads the same session and full security snapshot; compares generation, revision, policy/operator/workspace metadata, floor and budget limit, even without a grant.
2. Checks state eligibility and static operation/classification constraints.
3. When required or supplied, verifies receipt provenance, full stored snapshot, exact action/type/digest/classification, session, generation, revision, issue state and trusted-clock expiry.
4. Checks budget usage/limit for **that same context session** and reserves its quoted amount.
5. Conditionally consumes exactly one matching issued receipt, inserts both corresponding audit records using that same session, and commits all mutations together.

Failures roll back the complete operation. Budget denial preserves ISSUED approval. Invalid/mismatched/expired/replayed approval reserves nothing. Either audit failure or an approval UPDATE failure rolls back reservation, consumption and sequence changes. Whole-transaction retry still performs fresh reads under the existing bounded five-attempt protocol; no dispatch or external side effect occurs inside it. Separate database connections/processes still produce one winner, not one winner per Mutex.

### Fence through synchronous dispatch

`SqliteConnectionManager::session_admission` uses safe standard-library file locks on a validated local per-database/per-session lock file. The small isolated Windows lock experiment was executed before adoption; the actual implementation is additionally exercised by service, independent-connection and real subprocess regressions. No unsafe code or dependency was added.

- Preparation acquires a shared admission lock **before** SQLite validation. Successful `PreparedExecution` retains it through the service's synchronous `ExecutionEngine::dispatch` call. The actual ExecutionRequest copies action/revision/classification from the immutable context.
- Trusted context registration and session transitions acquire the same file's **exclusive** lock before opening their SQL transaction. `try_lock` returns typed `ContextBusy` if dispatch is live; it does not block/re-enter a backend indefinitely or silently replace authority.
- Context objects alone hold no lock: an owner can update them before preparation, and the subsequent full SQL comparison then rejects stale work. After successful preparation, the shared guard prevents context/state changes until dispatch returns. Concurrent matching admissions can share the lock; SQLite still serializes their budget/approval mutations.
- SQLite locks are released before calling the backend. A deterministic channel-gated test parks dispatch, proves a separate connection rejects same-session context/transition changes, reads SQL and transitions an unrelated session successfully, then allows dispatch to finish and proves the context update can proceed.
- A real owned subprocess holds admission after SQL commit/before its synthetic effect. The parent observes ContextBusy; killing that child releases the OS lock. SQL integrity, conservative reservation, consumed approval, audit ordering and replay rejection survive. An owner update can then proceed.

Lock files are persistent coordination artifacts, not secrets or approval tokens. They must not be deleted/replaced while any manager may be active. Windows opens use no-follow/reparse checks, deny deletion sharing and retain validated parent handles. All cooperating managers must use the same protected canonical database location; malicious direct SQL writers, lock-file deletion by a privileged actor, hard-link database aliases and distributed filesystems are outside this capability model. Cross-process evidence concerns tested local Windows x64 storage only.

Service cancellation/settlement additionally checks that the reservation belongs to its authoritative session. The existing unrestricted settlement method remains a privileged controller reconciliation operation, not an ordinary request capability.

**Tested:** A receipt cannot charge B, consume under B, or redirect budget ownership; foreign context seals deny; context changes before preparation deny both approved and automatic operations; live dispatch fences lifecycle updates; path/argument/action mismatches preserve the legitimate receipt; exhaustion preserves approval; duplicate audits/SQLite trigger failures roll back everything; concurrent approval/budget contention and separate-process single-use still pass.

## 4. F-561-03 — Typed errors and conservative usage

**Root cause:** compound errors retained strings instead of original typed sources; arbitrary backend/evidence messages entered diagnostics; Failed/TimedOut/Cancelled result branches lost their primary outcome when settlement failed. An existing redaction test incorrectly required the secret to appear.

`ServiceError` now holds a private typed `ServicePrimaryError` and a separate typed `PersistenceError` secondary. `primary_error()`, `secondary_error()` and `Error::source()` expose kinds without parsing strings. Execution/evidence source objects retain their original kinds; arbitrary backend/evidence message text is discarded on ingress, including caller-constructed error structs. Public summaries are generic. Display/Debug do not format the mutable summary field or confidential input. SQLite extended/rollback codes and retry-attempt counts remain inspectable. Free-form backend diagnostics are intentionally unavailable through service accessors; this trades message detail for confidentiality without losing the error category.

- Dispatch error plus settlement failure retains typed ExecutionError + PersistenceError.
- Evidence error plus settlement failure retains typed EvidenceVerificationError + PersistenceError.
- Failed, TimedOut or Cancelled result plus settlement failure retains `ExecutionOutcomeError { status, exit_code }` + PersistenceError in `OutcomeWithSettlementFailure`.
- Successful execution plus settlement failure is a typed Persistence error; successful settlement creates no secondary/compound error.
- Service preparation does not convert unrelated database errors into policy denial.

The backend supplies no measured monetary receipt. **Completed/Failed estimates are no longer recorded as actual usage.** They settle as UncertainPartial; TimedOut/Cancelled retain CancelledUncertain. SQL actual usage stays NULL, the full reservation remains counted, and failed settlement leaves the reservation conservative. No uncertain cost becomes zero. Privileged later reconciliation remains explicit.

Tests exercise actual closed-manager settlement failures for execution, evidence and all three negative outcomes, typed downcasts/source accessors, secondary kinds, successful settlement, successful-outcome/failed-settlement, NULL actual usage and diagnostic canaries. Service tests now assert structured kinds instead of requiring confidential strings. Neither the evidence verifier nor backend behavior was changed to hide failures.

## 5. Directory-change defect

The observed failure is an actual retained-observation weakness, not merely fixture timing: `same_observation` compared directory attributes/creation/last-write metadata, but NTFS last-write updates need not distinguish an immediate new child. Retained no-delete handles prevent namespace replacement; they do not freeze children or make timestamps an inventory.

Resolved ordinary directories now capture sorted exact child names, independently of mtimes, and compare them during inspect. Collection reads only entry names, never child contents/targets. It is bounded by **20,000 names / 4 MiB encoded names** per observation and fails closed on overflow/error. Git metadata remains opaque. Existing discovery depth/entry/byte limits remain; a root observation failure returns an error, and a child traversal failure records explicit incompleteness rather than a clean partial inventory.

The new deterministic Windows fixture creates a child and restores the directory timestamp to its original value using safe attribute-only APIs. It asserts timestamp equality and PathChanged. Both the original failing test and this regression pass **20/20** isolated executions on final sources. No sleeps, retry masking, weaker assertions, permissive links or unsafe filesystem APIs were introduced.

This is not a cryptographic tree snapshot or race-free handle-relative filesystem boundary. Unchanged names do not detect in-place child content changes, name-ABA between observations or all hard-link/object-identity attacks. Per-entry no-follow inspection and quarantine remain necessary; observations grant no content authority. OQ-22 remains open before source reads/exports/modifications.

## 6. Final validation evidence

Windows x64; PowerShell 7.6.9; Rust/Cargo 1.99.0 and the existing MSVC/cached SQLite toolchain. All Cargo dependency resolution was offline. No Linux/macOS/ARM64/older-Rust support is inferred.

| Command / record | Actual result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed, exit 0. |
| `cargo check --workspace --all-targets --all-features --offline` | Passed, exit 0. |
| `cargo clippy --workspace --all-targets --all-features --offline -- -D warnings` | Passed, exit 0; no warning suppression. |
| `cargo test --workspace --offline` | Passed, exit 0: **231 runtime + 6 compile-fail doctests**, 0 Failed, 5 directly ignored. |
| [Final remediation driver](../../experiments/phase1/core-review/results/5622-1793937445312.json) | **45/45 Passed**, source hashes unchanged, 0 timeouts/blocked checks; includes the four commands, discovered inventory and 40 isolated executions. |
| [Persistence validator](../../experiments/phase1/persistence/results/1793937462620.json) | **13/13 Passed**, including offline native MSVC build and three cross-process repeats; source hashes unchanged. |
| [Authorization validator](../../experiments/phase1/authorization/results/1793937519010.json) | **13/13 Passed**, including the original A-to-B negative probe and legacy concurrency repeats; source hashes unchanged. |
| [Workspace validator](../../experiments/phase1/workspace/results/1793937519018.json) | **11/11 Passed**; junction/deny-ACL fixtures, cleanup/restoration and all three 10,000-file measurements Passed; source hashes unchanged. |

The [earlier remediation run](../../experiments/phase1/core-review/results/5622-1793937306858.json) also Passed, but predates the final two focused tests/error-conversion adjustment and is not the final inventory. Development failures while adapting message assertions and correcting the evidence-kind expectation are not presented as final-source failures or added unique tests.

### Reconciled inventory

| Suite | Discovered | Passed in final ordinary run | Directly ignored |
| --- | ---: | ---: | ---: |
| Unit tests | 14 | 14 | 0 |
| authorization_tests | 27 | 27 | 0 |
| domain_tests | 9 | 9 | 0 |
| evidence_tests | 9 | 9 | 0 |
| execution_evidence_adversarial_tests | 11 | 11 | 0 |
| execution_tests | 8 | 8 | 0 |
| independent_core_review_tests (adapted regressions) | 31 | 30 | 1 owned child helper |
| persistence_tests | 43 | 42 | 1 owned child helper |
| policy_tests | 9 | 9 | 0 |
| security_tests | 10 | 10 | 0 |
| service_tests | 19 | 19 | 0 |
| session_tests | 5 | 5 | 0 |
| workspace_tests | 41 | 38 | 3 separate platform cases |
| Compile-fail doctests | 6 | 6 | 0 |
| **Total** | **242** | **237** | **5** |

The two helpers are actually launched by parent process tests; they are not independent standalone scenarios or hidden missing coverage. The three workspace cases are junction, deny-ACL and 10,000-file scale fixtures, separately executed by the workspace validator. Their runs, validator-overlapping suites, the 40 isolated directory executions and repeated concurrency rounds do not create new unique test cases. The original synthetic A-to-B executable is a separate probe, not another Rust `#[test]` case. Its negative authorization assertion must pass.

**Consolidated final inventory: 240 unique Passed (234 runtime including the three separate fixtures + 6 doctests), 0 Failed, 0 Blocked identified test cases, and 2 harness-only entries out of 242 discovered.** No identified standalone case is left unexecuted; the distinct unvalidated engineering areas below remain explicitly open. The old pre-review 222-test claim is not reused. No additional unique case is credited for overlapping validators or repetitions.

The 10,000-file measurements report 10,000 entries and 310,000 inventory bytes in each run; exact elapsed times/RSS remain in the workspace raw record. This measures the owned metadata fixture, not production workload capacity or strong containment. ACL edits affect only the validator's disposable objects and are restored.

## 7. Remaining risks and unvalidated areas

- Post-commit/pre-effect process termination is conservative, **not exactly-once execution**. No automatic replay, refund, outbox or asynchronous/distributed dispatch protocol was introduced. A prepared guard must remain in the trusted synchronous service through dispatch; it is not a reusable target-execution token. Real side effects need a separately reviewed lifecycle/recovery protocol.
- Context authority proves local capability possession, not human identity authentication. Protected local state and trusted controller/adapter composition remain prerequisites. SQL-only storage primitives are not independent execution permission.
- File locking is tested for cooperating local Windows x64 managers. Network/distributed filesystems, malicious direct storage writers, database hard-link aliases and other platforms are **Not Tested**. Lock artifacts require documented quiescent maintenance; automatic deletion is intentionally absent.
- Strong filesystem object identity/handle-relative containment and content-access authority remain unresolved. The name-inventory fix does not close all OQ-22 issues.
- Physical disk exhaustion, genuine write/fsync IOERR, power-loss durability, database/blob reconciliation, real provider billing/transports, Hyper-V provisioning/guest communication/cancellation, streaming evidence and SHA-256 remain **Not Tested or previously Blocked**, as documented in their original validation reports. No status was silently upgraded.
- No new dependency or unsafe code, no ADR status change, no human-authentication claim, no VM/container/network fallback. Untrusted target execution remains fail-closed. Only Sentra builds, approved cached dependency compilation and repository-controlled synthetic fixtures ran; **no target code, analyzed repository hooks or target build scripts executed**.

## 8. Reproduction and Git preservation

From repository root in PowerShell, with the existing cached MSVC toolchain:

```powershell
./experiments/phase1/core-review/Validate-5.6.2.2.ps1
./experiments/phase1/persistence/Validate.ps1
./experiments/phase1/authorization/Validate.ps1
./experiments/phase1/workspace/Validate.ps1
```

The remediation driver records exact arguments, exit codes, stdout/stderr, discovered cases, repetitions and source hashes. No API keys or external services are needed. Prior review commands/source remain historical; the promoted cases run without `--ignored`.

Final state: branch **develop**, HEAD **fd83f0c46b23246dbdfca060ef045433b3bd2715**, tracking local **origin/develop**, ahead/behind **0/0** without remote refresh; **19 modified tracked files, 12 untracked artifacts, 0 staged files**. The [complete read-only Git status, preservation and documentation record](../../experiments/phase1/core-review/results/5622-repository-and-documentation.json) contains the exact path inventory and comparisons. HEAD, branch, all references, reachable history, index entries and physical `.git/index` bytes match entry. All 205 original file hashes match except the 19 intended changes; the independent review, old raw evidence, manifests/lockfile, schema and seven ADRs are unchanged. ADR-0002/0007 remain Proposed. Local Markdown links/fragments, table shapes, requirement references and unchanged ADR statuses validate; whitespace diff checking exits 0.

No commit, tag, staging, stash, branch mutation, history rewrite, push, fetch or pull was performed. All changes remain unstaged. No new dependency, unsafe code, host configuration change, external transfer or target execution was introduced. This closes the requested implementation correction within the tested local synthetic profile; it is not an independent security approval or production-readiness certification. **Stop at Increment 5.6.2.2; no subsequent increment or Phase 2 started.**
