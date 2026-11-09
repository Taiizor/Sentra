# Increment 5.6.2.2.2 — Policy and Validator Hardening

Date: 2026-11-06. **Implemented and tested; ready for owner review.** Scope: targeted remediation of F-562221-01, F-562221-02 and F-562221-03 from the [independent review](INCREMENT_5_6_2_2_1_INDEPENDENT_REVIEW.md). This is implementation and regression verification, not another independent review or production-readiness certification. Phase 1 remains incomplete; Phase 2 and subsequent increments have not started.

## 1. Entry and preservation

Actual entry was clean `develop` at **74debdd7e905992205885969a504317a648081e6**, parent **15083f5f931da355322626c8d47bbe60d73c1a60**, tracking local `origin/develop` **1 ahead / 0 behind** without remote refresh. The externally created HEAD is `Add independent authorization security review`, timestamp 2026-11-06T16:20:00+03:00. No staged, modified or untracked repository files existed at entry. All **228** tracked file hashes, references, reachable history, index entries and physical index bytes were recorded before edits. Index SHA-256: `ca82253cfe310cede02d73cdc72e721784a2cd21fcc09cb420a4c544d4a760f9`.

All previous reports/raw records remain historical evidence. Two characterization tests in the previous review's test module now assert corrected behavior; their original source remains in the entry commit and the previous review report is unchanged. Existing negative authorization assertions were not weakened. No dependency or feature-graph change, unsafe code, agent-issued Git mutation/network operation, target workload or host security configuration change was introduced. Only approved cached dependency/Sentra builds and owned synthetic fixtures executed. Concurrent Git metadata observations are recorded explicitly in §8 rather than claiming physical index-byte preservation.

## 2. Original findings and changes

| Finding | Root cause | Implemented correction |
| --- | --- | --- |
| F-562221-01, Medium | A mutable PolicyEngine could change rules while previously minted contexts retained an unversioned approval-required bit; persisted policy ID alone did not identify effective configuration. | Engine configuration is immutable; effective rule identity is stored in the existing security snapshot and checked at mint. Owner activation reuses the existing persisted generation and exclusive dispatch fence. |
| F-562221-02, Low | Both preview persistence stages matched `Err(_)` into ordinary Denied, hiding Closed/Integrity/SQLite failures. | Stage-aware, non-consuming repository preview separates three authorization outcomes from typed evaluation failures. |
| F-562221-03, Low | Probe archive came from actual Cargo output but dependency search was hardcoded to repo/target/debug/deps; probe executable path was reused. | Resolve target through offline Cargo metadata, select this build's JSON artifact, derive dependencies from its location, and compile a unique probe per invocation. |

Changed implementation is in `policy/engine.rs`, `persistence/{model,repository,error,mod}.rs`, `service/core.rs`, the focused regression test module and `experiments/phase1/authorization/Validate.ps1`. The reproducible portability and quality runners are new validation artifacts. Six-table SQL schema/migration files, execution backend, evidence verifier, workspace implementation, session state machine, provider integration, dependencies/lockfile and all seven ADR statuses are unchanged.

## 3. Enforced immutable policy and activation lifecycle

### Immutability and identity

The public `PolicyEngine::set_max_auto_budget` mutator was removed. Config is private and `config()` returns a shared reference; mutating a caller-owned clone cannot affect the live engine. A new compile-fail doctest asserts that the removed mutation route cannot compile. Engines are constructed from values; CoreService performs its existing budget normalization only during ownership transfer into its private immutable engine. No hot reload, shared mutable policy registry or caller-controlled version field was added.

The current canonical identity is `sentra-policy:v1:auto-microusd=<canonical u64>`. It identifies effective compiled rules plus the currently effective auto-budget threshold. It is **not a cryptographic hash/signature**. Mandatory sensitivity, Restricted processing, default-deny and write-down rules remain unchanged. The previously reserved budget-config knobs do not relax those rules or currently change evaluation; changing only those knobs does not invalidate authorization. Activating them or changing compiled semantics in a future increment requires an explicit rule-identity version change and compatible old-snapshot handling, not silent reuse of v1.

| Version/identity | Meaning |
| --- | --- |
| SQLite schema/user_version 1 | Existing six tables and migration metadata, unchanged. |
| Security snapshot JSON version 2 | Adds effective `policy_identity`; generated only by trusted registration. |
| Canonical rules identity v1 | Current immutable evaluation semantics and auto-budget value; no cryptographic claim. |
| Existing session context_generation | Also the authoritative policy/approval epoch; maintained transactionally, never accepted from an execution caller. |
| Existing audit envelope version 1 | Unchanged event representation. |

### Authoritative activation

`PersistentApprovalAuthority::register_session_with_policy` pairs an immutable engine with the session budget limit. The ordinary repository/request interface cannot issue this registration capability. CoreService uses it for creation so custom service budgets register the actual normalized rules.

1. The trusted controller constructs a proposed immutable engine. Construction alone changes no session policy; a different engine cannot mint a context under an incompatible registered identity (`PolicyMismatch`).
2. Registration takes the existing per-session exclusive OS admission lock before SQL work. A live prepared/dispatching operation causes ContextBusy; no rule/state update can pass it.
3. In one existing managed transaction, registration derives the canonical identity internally and compares the complete current context. If effective identity and all context fields are identical, it returns the current record without generation/audit/snapshot changes.
4. An effective rule or other security-context change advances the existing generation, writes a new immutable snapshot and updates the session/audit atomically. A failed audit rolls back the epoch and rule activation as well. Numeric generations are not caller parameters.
5. Context mint requires exact engine/registered identity equality. Preparation re-reads the full snapshot/generation for every operation, including automatic operations. Grants carry the same frozen snapshot and approval rows reference `(session_id, context_generation)`, so old issued/pending approvals and contexts fail after activation, including A/B/A rule changes.
6. The shared PreparedExecution fence remains held through synchronous dispatch. Authoritative activation cannot occur between preparation and dispatch or during that call. An old CoreService remains immutable and fails mint after a different policy is activated; a matching newly constructed service can proceed with a fresh required approval.

The legacy `register_session` method still creates new sessions with default rules and preserves the existing effective policy during ordinary revision/floor changes. Its deliberate re-registration still rotates generation even for identical values, preserving the earlier explicit invalidation/ABA contract. The policy-aware registration path has the no-op behavior above. Merely evaluating or constructing an equivalent engine does not rotate anything.

Policy scope is per registered session. There is no global multi-session hot reload transaction; a future global policy rollout must explicitly invalidate every affected session and retire old service owners. Trusted controllers/storage remain prerequisites, not human identity authentication.

### Existing data

Well-formed version 1 security snapshots remain readable for session inspection/history but lack verifiable effective-policy binding. Execution, approval operations and preview fail closed with PolicyMismatch until the trusted owner explicitly supplies a policy through the new registration path. The compatibility registration method does not guess a default for an unbound existing record. Explicit binding advances generation and adds a version 2 snapshot; old data/snapshots/approval state are preserved and old receipts cannot revive. No database is recreated, repaired or silently upgraded by startup/preview. Malformed version 2 identity/missing fields remain typed Integrity failures.

## 4. Preview result and error semantics

The service result remains `Result<ServicePolicyDecision, ServiceError>`:

- `Granted`: valid current context and any required presented grant; no consumption.
- `Denied`: actual rule/state/classification rejection or invalid/expired/replayed/foreign presented grant.
- `NeedsApproval`: current context is valid but a required grant is absent.
- `Err(ServiceError::Persistence)`: database unavailability, missing/inconsistent authoritative state, policy mismatch, malformed storage or SQL/rollback/retry failure. The underlying PersistenceError kind and numeric codes remain inspectable via primary_error/source; free-form SQLite/path/approval text is not retained.

The repository's `ExecutionPreview` result distinguishes context-validation failures from ordinary receipt rejection. Infrastructure errors in either persistence stage propagate; they are not flattened into Denied. In particular, grant-binding ContextMismatch is a denial after the context itself has been validated, whereas missing/stale authoritative context is an evaluation failure. Preview always revalidates current context, including before NeedsApproval.

API corrections: the previous public `validate_execution` method is replaced by the explicitly non-consuming `preview_execution` returning ExecutionPreview. The service's existing public result shape is preserved. Callers that previously changed an engine in place must construct an immutable value and activate it through the owner lifecycle; there is no replacement caller-settable policy-generation API.

Preview changes no approval, reservation, session, snapshot, migration or audit rows. Tests compare every cell of all six tables before/after repeated decisions. It still uses existing short serialized SQLite transactions and admission locks; this is row-level read-only behavior, not a claim of zero filesystem I/O or lock-free reads. It creates no pending request and is not a reusable execution permission. The existing action-only preview does not reserve budget or certify an eventual independently quoted cost/scope; execution still performs the complete atomic gate.

## 5. Validator portability

The validator's child processes always run from the script-derived repository root, independently of the caller's working directory. Offline `cargo metadata --no-deps` resolves the effective target directory, including Cargo environment/configuration. `cargo build --message-format=json` selects the actual sentra_core rlib from this invocation. Its path must be inside that resolved target directory; there is no directory-glob/default-directory fallback.

The dependency directory is derived from the actual archive's profile directory (or its deps directory). `ProcessStartInfo.ArgumentList` passes all paths as individual arguments, including spaces. Each run compiles/executes a fresh GUID-directory probe beneath that target and records archive/probe paths and SHA-256 artifact fingerprints. Those hashes are validation-artifact fingerprints, not a new application cryptographic implementation or dependency. Cargo's valid same-directory compilation cache is permitted; a previous probe executable or a library from another target directory is not selected.

The first four-case portability run preserved one failure: the absolute-spaces case's **cold full suite exceeded the legacy 60-second command deadline after 215 runtime passes**, with no assertion failure. Archive/dependency selection and the original A/B probe passed even in that failed run. The other three cases passed. The bounded validator command budget is now **180 seconds, configurable 1–300**, matching core/persistence defaults and allowing cold compilation/launch of the complete growing workspace. SQLite busy timeouts, per-test assertions, filesystem benchmark criteria and execution quotas were not changed. Fresh directories were used for the final cold retest; a warm retry was not presented as a cold success. The earlier timeout record remains linked below.

`Validate-Portability.ps1` executes four actual validator invocations: default environment; absolute target with spaces from a different working directory; a separate initially empty target; and reuse of that same target. It verifies target/archive correspondence, initial emptiness, stable archive identity on reuse and a different probe output for the second invocation. No current-machine path is hardcoded in either validator. Alternative build artifacts are retained under owned ignored target directories for the warm case and inspection; historical raw records are not overwritten.

## 6. Regression coverage and actual results

The focused module has **22 cases**: eight earlier adversarial cases remain, two old characterization cases now require the corrected behavior, and twelve new cases cover policy activation/issued and pending receipts, automatic-context invalidation, equivalent-rule no-op, policy ABA, cloned-config manipulation, real dispatch/update concurrency, separate manager reconstruction, version 1 explicit binding, all preview decisions without writes, malformed/missing state, second-stage corruption, activation audit rollback and a real SQLite SELECT error (code 1). Existing policy/session/action/target/revision/classification/replay/cross-process and budget invariants remain in the full suite.

The live dispatch test uses channels and the real CoreService/repository fence, not arbitrary sleeps or a production test hook. Policy activation fails while dispatch is live; after activation, the old service cannot call its backend. The activation rollback test proves that a duplicate audit ID cannot partially change rules/epoch or burn a legitimate receipt. Preview failure tests include Closed, missing snapshot/session, malformed policy/JSON and real SQL query failure, preserving kinds/codes and diagnostic redaction.

| Check / raw evidence | Final outcome |
| --- | --- |
| `cargo fmt --all -- --check` | Passed, exit 0. |
| `cargo check --workspace --all-targets --all-features --offline` | Passed, exit 0. |
| `cargo clippy --workspace --all-targets --all-features --offline -- -D warnings` | Passed, exit 0; no warning suppression. |
| `cargo test --workspace --offline` | Passed: **253 runtime + 7 compile-fail doctests**, 0 Failed, 5 directly ignored. |
| Final quality driver | **6/6 Passed**, including discovery and explicit **22/22** focused regressions; source hashes stable. |
| Persistence validator | **13/13 Passed**, source stable; bundled/native MSVC build, rollback/WAL and process repeats executed. |
| Workspace validator | **11/11 Passed**, source stable; actual junction/deny-ACL fixtures, restoration/cleanup and scale cases executed. |
| Final four-case portability runner | **4/4 Passed; each child 13/13 Passed**, driver/source stable, target correspondence and warm reuse verified. |
| First portability run | **3 Passed / 1 Failed** from the 60-second cold command deadline; preserved, not relabeled successful. |

Development records also preserve the 20-case pass, new test comparison compile error, and 22-case pass before deadline adjustment. The test used an unsupported whole-SessionRecord equality; comparison now checks all record fields explicitly. A development Clippy initializer warning was corrected without suppression. These intermediate snapshots are not the final inventory and are not counted as additional cases.

### Reconciled inventory

| Suite | Discovered | Ordinary Passed | Directly ignored |
| --- | ---: | ---: | ---: |
| Unit | 14 | 14 | 0 |
| authorization_isolation_review_tests | 22 | 22 | 0 |
| authorization_tests | 27 | 27 | 0 |
| domain_tests | 9 | 9 | 0 |
| evidence_tests | 9 | 9 | 0 |
| execution_evidence_adversarial_tests | 11 | 11 | 0 |
| execution_tests | 8 | 8 | 0 |
| independent_core_review_tests | 31 | 30 | 1 helper |
| persistence_tests | 43 | 42 | 1 helper |
| policy_tests | 9 | 9 | 0 |
| security_tests | 10 | 10 | 0 |
| service_tests | 19 | 19 | 0 |
| session_tests | 5 | 5 | 0 |
| workspace_tests | 41 | 38 | 3 platform/scale cases |
| Compile-fail doctests | 7 | 7 | 0 |
| **Total** | **265** | **260** | **5** |

Three platform/scale cases are executed separately by the workspace validator. Two helper entries actually run via parent subprocess tests and are not independent standalone scenarios. Repeated full suites, four portability invocations, the focused suite, legacy 64/32-round authorization races, persistence process repeats and repeated scale measurements do not add unique cases. **Consolidated: 263 unique Passed (256 runtime + 7 doctests), 0 final-source failed assertions, 2 harness-only entries out of 265 discovered.** No identified standalone test remains unexecuted; out-of-scope engineering validations below remain Not Tested/Blocked. The A/B probe is a separate executable check, not another Rust test case.

| Portability invocation | Evidence | Actual result |
| --- | --- | --- |
| Default target, CARGO_TARGET_DIR unset | raw | 13/13 Passed; exit 0. |
| Absolute alternative with spaces, called from a different working directory | raw | 13/13 Passed; initially empty; exit 0. |
| Separate initially empty alternative target | raw | 13/13 Passed; pre-launch emptiness verified; exit 0. |
| Second invocation reusing that same directory | raw | 13/13 Passed; nonempty before run, same archive/hash, different newly compiled probe path; exit 0. |

Each child records resolved target/archive/dependency/executable paths and command arguments. The absolute-spaces run took about 144 seconds overall and the separate cold run about 96 seconds across all checks; these are cold fixture observations, not production performance guarantees. All final commands stayed within their bounded per-command deadlines. The first failed timeout remains part of the experiment history rather than being counted as a successful invocation.

## 7. Reproduction and limits

From any PowerShell working directory, invoke the repository-defined scripts by their path; they derive the repository root internally. From repository root:

```powershell
./experiments/phase1/core-review/Validate-5.6.2.2.2.ps1
./experiments/phase1/persistence/Validate.ps1
./experiments/phase1/workspace/Validate.ps1
./experiments/phase1/authorization/Validate-Portability.ps1
```

The portability record includes exact child executable/arguments, working directories, CARGO_TARGET_DIR values and each validator's raw record. All Cargo resolution/builds are offline, with only the three existing pinned direct dependencies. Windows x64/MSVC is the executed platform; Linux/macOS/ARM64, real providers/VMs and physical storage faults are not validated by this work.

No global dynamic policy infrastructure, external-effect crash recovery, exactly-once effects, strong filesystem identity, guest management, streaming evidence, SHA-256 integration or CLI/dashboard expansion was implemented. Untrusted target execution remains fail-closed; no host/Docker/WSL2 fallback was added. Protected local storage/lock artifacts, trusted controller composition, fresh explicit approvals and the existing resource limits remain prerequisites. Identity/worker authentication, cryptographic evidence integrity and database/blob reconciliation stay open. No accepted ADR was modified or Proposed ADR accepted.

## 8. Final Git state and completion

The three requested findings are implemented and tested under the documented immutable per-session policy model. Every required offline code/validator check passed on final sources, including four complete portable authorization invocations. All previous reports remain unchanged. This is ready for owner review, not a new independent approval or full production readiness.

Final branch **develop**, HEAD **74debdd7e905992205885969a504317a648081e6**, local upstream **origin/develop**, ahead/behind **0/0**. The first read saw 1/0; the reflog records an external `update by push` at 2026-11-06T16:20:03+03:00 and the fingerprint baseline already contained the caught-up tracking target. A later `remote set-head` event at 16:50:32+03:00 is also present. Neither operation was issued by the agent. All reference targets, reachable history and index entries match that fingerprint baseline; there are **12 modified tracked files, 20 untracked implementation-report/validation artifacts and 0 staged files**. The 216 other original tracked files, including all previous reports/raw records, manifests/lockfile/schema and seven ADRs, remain byte-identical. ADR-0002/0007 remain Proposed.

**Physical-index observation:** the `.git/index` SHA-256 changed from the entry value above; the observed file timestamp is 2026-11-06T14:00:57Z. Staged paths/blob IDs/modes did not change, but byte preservation cannot be claimed. The writer is not established; a stat/cache refresh is a possible explanation, not a verified attribution. The agent used read-only Git commands with optional locks disabled and issued no index/history/reference mutation. It did not restore or overwrite the changed index. The complete final status, source hashes, Git metadata observations and documentation/inventory checks retain both checksums and the exact path list. Its physical-index equality observation is a detected difference, separate from successful Rust/validator results.

No commit, amend, stage, stash, reset, rebase, cherry-pick, tag, branch change, push, fetch or pull was performed by the agent. All modifications remain in the working tree. **Stop at Increment 5.6.2.2.2; no subsequent increment or Phase 2 started.**
