# Phase 1 Final Independent Verification & Closure Assessment

Date: 2026-11-07. **Final decision: NOT APPROVED.** This is a verification/closure assessment, not an implementation increment. **Phase 2 was not started or authorized.**

## 1. Executive summary and decision

The Windows x64 local foundation is substantial and reproducibly testable: Core domain/session/policy, durable SQLite approval/budget primitives, metadata-only workspace boundaries, synthetic execution/evidence checks, and the local CLI pass current offline verification. All four specialized validators pass. The previously rejected authorization/context, cross-session transaction and compound-error defects have source-level corrections and passing adversarial regressions. No current shipped CLI/built-in backend route to untrusted target execution was found.

These results do **not** establish completion of the existing Phase 1 acceptance contract. [ROADMAP](../../ROADMAP.md#phase-1--technical-validation-and-local-foundation) still requires persisted session resume and interruption/reconciliation at dispatch, blob promotion and result commit, with no lost committed events or repeated sensitive effects. [REQUIREMENTS](../../REQUIREMENTS.md) F-01/F-02/F-14 also require capabilities beyond metadata observations, a single unversioned foundation record and synthetic cancellation. There is no implemented blob store/reconciliation, durable task/outbox/lease recovery, complete immutable acquisition manifest, CLI resume/recovery or actual VM cancellation. The design acceptance checklist additionally describes evidence tables, blob reconciliation and computed SHA-256 verification that the current six-table/structural-only implementation does not provide. The narrower implementation reports correctly disclose these gaps; no approved replacement of the outstanding closure criteria was found.

**NOT APPROVED applies to full Phase 1 closure, not to revocation of the prior bounded increment approvals.** Passing synthetic tests cannot satisfy absent application-recovery functionality. The permitted alternative in the VM gate (recording a blocking prerequisite while keeping execution disabled) is satisfied; Hyper-V permission blockers or untested ARM64 alone are not the reason for this decision. Likewise, real providers and licensing are not silently promoted into new Phase 1 blockers: they retain their documented later-use/release gates.

F-611-01's documentation condition is addressed. **F-611-02 remains an explicit pre-Phase-2 production-readiness requirement:** select atomic staging or explicit operator recovery, implement the approved choice, and verify the initialization crash windows. OQ-25 remains open, including the single-foundation-session project identity and fail-closed multi-session limitation. No finding is closed merely by moving it into PROGRESS.

An owner decision is needed on retaining the existing Phase 1 acceptance criteria versus explicitly approving a narrower closure baseline. Until the applicable criteria have evidence or an approved scope decision, this assessment does not declare Phase 1 complete. It authorizes no implementation, recovery operation, host configuration change or next phase.

## 2. Baseline, scope and Git preservation

The actual entry was **clean**, not the state recorded by an earlier increment:

| Item | Observed entry |
| --- | --- |
| Branch | `develop` |
| HEAD | `354021954f33768a76d6dbecfc1f37b7fed41a60` |
| Upstream | Locally recorded `origin/develop`; 0 ahead / 0 behind; no remote refresh |
| Staged / modified / untracked | 0 / 0 / 0 |
| Index entries | 280 |
| Physical index SHA-256 | `01c43128e01edee7984e639042af9884d9711768e1aa58080334826837649143` |

Before validation, file hashes for all 280 tracked files, complete index entries, all reference targets, reachable history, branch/HEAD/upstream and physical index bytes were captured in process memory. Git was invoked with `--no-optional-locks`; no snapshot artifact, index refresh/restore or historical-file rewrite was created. Checks between validation stages showed the same physical index. No unexpected change requiring attribution occurred in this assessment; historical explanations of earlier index changes are not new forensic attribution here.

Scope includes the eight Phase 0 root documents, detailed contracts/research, seven ADRs, all Phase 1 milestone/review/remediation records, both production crates, standalone experiments and existing validator/results inventory. Entry inventory: **61 Markdown files, 29 files under docs/phase1, 7 numbered ADRs, 76 Rust files and 112 JSON evidence records** across the tracked repository. The complete 280-path baseline inventory is retained in Appendix C. Generated ignored build caches are not additional product capabilities.

Only this report and a narrow current-status entry in PROGRESS are retained as final changes. Existing validators generate result JSON files and owned temporary fixtures; the four new result records from this run were captured into this report's evidence appendix and removed only after identity/hash checks, leaving all prior results untouched. This is cleanup of this assessment's generated outputs, not cleanup of pre-existing user work. Build/test caches remain ordinary ignored validation outputs. No production source, test, API, schema, dependency, manifest/lockfile, configuration, validator, ADR or historical review was modified.

## 3. Milestone assessment

### Milestone 1 — Rust/MSVC

[Recorded spike](../../experiments/phase1/rust-msvc/results.json) and [source](../../experiments/phase1/rust-msvc/src/main.rs) provide x86_64 MSVC check/build/link/test/run, Unicode/spaces/CRLF and CLI-error evidence. Recorded manifest/source/runner hashes match current files. Rust/Cargo 1.99.0, MSVC 14.52.37025 and installed SDK versions 10.0.22621.0/10.0.26100.0/10.0.28000.0 are recorded; SDK presence is not proof that every combination works. Current workspace and explicit native MSVC build checks also pass using the cached graph.

The historical ARM64 check returned **101 against expected 0**, with only x86_64 installed. Treat that compile attempt as failed/blocked by the unavailable target, with ARM64 native execution **Not Tested**. No target was installed and no ARM64 support is claimed. ADR-0002 remains Proposed because its complete suitability/process/packaging gates are wider than x64 compilation. Current host evidence is Windows 11 x64, OS build 26300, PowerShell **7.6.9**; no separate PowerShell 7.6.6 claim.

### Milestone 2 — SQLite

The [engine assessment](SQLITE_VALIDATION.md) has two final **18 Passed / 1 Blocked / 3 Not Tested** runs of the same 22 assessment IDs, not 36 unique tests. The [final Bun record](../../experiments/phase1/sqlite/results/1793888372059-15a304dd.json) uses Bun 1.4.4/SQLite **3.53.4**; its three script hashes match current files. Supported snapshot backup/restore (`VACUUM INTO`), actual committed/uncommitted writer termination, WAL reader/checkpoint behavior, transaction statement errors and stale snapshot 517 are engine evidence, not automatic proof of every Rust adapter feature.

The production [SQLite foundation](INCREMENT_5_4_2_SQLITE_IMPLEMENTATION.md), [remediation](INCREMENT_5_4_3_PERSISTENCE_REMEDIATION.md) and current [manager](../../crates/sentra-core/src/persistence/connection.rs), [transaction code](../../crates/sentra-core/src/persistence/transaction.rs), [repository](../../crates/sentra-core/src/persistence/repository.rs) and [schema](../../crates/sentra-core/src/persistence/schema_v1.sql) were inspected:

- Pinned rusqlite **0.32.1/bundled**, serde **1.0.229/derive**, serde_json **1.0.154**; native bundled SQLite **3.46.0**. These are distinct from Bun's SQLite release. Sentra crates forbid unsafe code; external/native dependency internals are not thereby unsafe-free.
- Mandatory FK ON, WAL, synchronous FULL, busy_timeout 5000 and wal_autocheckpoint 1000 are applied and effective values verified; trusted_schema OFF and defensive/no-checkpoint-on-close configuration further constrain behavior.
- Managed writes start `BEGIN IMMEDIATE`; statement failures latch an explicit full rollback, including caught errors, so a later commit cannot accidentally preserve partial business work. Rollback failure is typed and halts unsafe continuation.
- Retry restarts the complete database closure with fresh reads, at most five attempts and bounded 10–250 ms backoff. Ordinary BUSY and BUSY_SNAPSHOT extended code 517 remain distinguishable. Existing tests reproduce real stale snapshots, not statement-only retry against stale state. Retry closures/raw connections remain private; no provider/filesystem/network effect is repeated inside them.
- Six tables and ordered transactional migration validation reject newer/drifted/inconsistent schemas. FNV drift detection is not cryptographic authentication. `integrity_check(10)` plus `foreign_key_check` run; runtime invalidity halts the manager.
- Approval matching, same-session budget reservation, conditional single-use consumption and corresponding monotonically sequenced audit events commit in one transaction. Audit/update failures roll back all mutations. Separate connections/processes have one winner; budget exhaustion does not burn an issued grant.
- Clean shutdown attempts TRUNCATE checkpoint and surfaces reader-blocked failure. Quarantine halts/closes the local manager and preserves DB/WAL/SHM/journal **in place**; it neither proves external-process quiescence nor performs an atomic multi-file archive.

Current native persistence tests/validator pass, including real owned-process termination and foreign-key violation checks. Physical disk exhaustion, real write/fsync IOERR, physical power-loss durability, native backup/restore, blob reconciliation and complete application-effect recovery remain unverified. SQLITE_FULL via page limits, READONLY and CANTOPEN are not substitutes for those failures. FULL synchronization is not physical power-loss proof. The earlier Bun/Node type-declaration check remains a separate historical tooling limitation; no dependency download was attempted to change it.

### Milestone 3 — AI provider contract

[Contract report](PROVIDER_VALIDATION.md), [gateway](../../experiments/phase1/provider/src/gateway.rs), [mock](../../experiments/phase1/provider/src/mock.rs) and [tests](../../experiments/phase1/provider/tests/contract.rs) establish a standalone zero-third-party mock seam: explicit lifecycle/egress initiation, capabilities, malformed/structured output, virtual timeout/cancellation, bounded retry/rate limits, normalized errors and conservative integer usage reservations.

The [final historical record](../../experiments/phase1/provider/results/1793891274912-7d40439b.json) has **62 unique cases executed twice**, 62 Passed in each run, matching names/outcomes and unchanged source/manifest/lockfile/runner hashes. It is not 124 unique cases. This final assessment additionally ran the same standalone Cargo package: **62 Passed, 0 Failed, 0 Ignored**. Keep its namespace separate from the production workspace inventory.

Real SDK/authentication/interoperability, tokenizer/prices, wire JSON/SSE/arbitrary schema, streaming/backpressure, real transport cancellation/OS egress and durable/concurrent billing/IPC remain untested. Current Core/CLI construction is provider-free; this does not integrate the experimental provider gateway into production. Historical statements that Core had not yet been implemented describe that milestone date, not the present checkout. No API key, repository source transfer, provider call or network service was used.

### Milestone 4 — VM/sandbox

[Sandbox assessment](SANDBOX_VALIDATION.md), [raw record](../../experiments/phase1/sandbox/results.json) and [closure review](MILESTONE_4_REVIEW.md) support only a **Conditional Go for a fail-closed foundation**. The raw record has 27 assessment items: 22 Passed / 5 Blocked; the review reports repeated identical execution. Do not sum repetitions or treat all 22 as VM runtime tests.

Ten harmless Docker prototype stages exercised network-none, read-only rootfs, scratch resources, credential/environment separation, stream input, independently checked fixture hash, crash/timeout handling and disposal. These are historical curated container experiments, not an approved untrusted workload backend. Docker containers share their Linux host/WSL2 kernel; the observed WSL2/Docker environment is not a dedicated per-session VM security boundary. No claim that WSL2 uses the Windows NT kernel is implied.

ARCH-03 through ARCH-06 marked Passed are explicitly **design-level** AF_HYPERV/vsock, egress-switch, VHDX overlay and stream-channel assessments, as the milestone closure review already qualifies. No socket, VM switch, differencing VHDX, authenticated guest transport or real VM cancellation was implemented/proven by those rows. Hyper-V management/feature queries and dedicated VM execution remain permission-blocked/unvalidated. No Docker, WSL2 or Hyper-V workload was invoked in this final assessment; no host feature/security setting changed.

### Milestone 5 — Core Engine, 5.1 through 5.6.2.2.2.1

The implementation in [domain](../../crates/sentra-core/src/domain/mod.rs), [session](../../crates/sentra-core/src/session/state.rs), [policy](../../crates/sentra-core/src/policy/engine.rs), [workspace](../../crates/sentra-core/src/workspace/boundary.rs), persistence, [execution](../../crates/sentra-core/src/execution/engine.rs), [evidence](../../crates/sentra-core/src/evidence/verifier.rs) and [CoreService](../../crates/sentra-core/src/service/core.rs) supports the restricted foundation:

- Explicit classification rank/Ord implements Public < Internal < Confidential < Restricted; BLP no-write-down and session floors are checked. Unknown/malformed actions deny. Canonical length-prefixed action v2 includes every current action field, list framing, argument order, checkout target paths and optional destination classification. It is not a cryptographic digest.
- Memory broker request-side context registration is comparison only; privileged ApprovalAuthority owns binding/rebinding/issuance. Private provenance, stored canonical operation/session/revision/classification context, clock-based expiry and Mutex-protected validation/consumption reject A-to-B, forgery, mismatch and replay; failed mismatch does not consume the legitimate grant.
- Persistent service authorization uses one authoritative SQL snapshot, not request-driven synchronization into a second broker. `ExecutionContext` privately owns seal, complete snapshot, action, classification, cost and required-approval result. Prepare accepts no independent caller budget-owner/session field.
- Every admission mints against trusted state/effective policy; preparation rereads snapshot/state/classification for **all** operations, including no-grant actions. Scoped/Planned/Running are eligible; Created, WaitingForApproval, Paused and terminal states deny. Terminal transitions stay immutable.
- PolicyEngine effective configuration is immutable. Version-2 snapshots bind `sentra-policy:v1:auto-microusd=<n>`; equivalent effective policy/context registration is a no-op, actual owner activation advances context generation, and old contexts/receipts/old service instances fail. Unbound v1 records need explicit owner binding. Reserved config flags do not weaken mandatory rules. There is no hot-reload/global-rollout facility.
- Exclusive lifecycle OS admission conflicts with shared preparation/dispatch leases; the latter survives SQL commit through synchronous backend dispatch. Context changes cannot interleave with that protected dispatch on the same trusted database/session namespace. No long SQLite transaction is held across backend work. Protected local storage/lock artifacts and trusted controller ownership are prerequisites; aliases/host tampering are outside the proof.
- Typed primary execution/evidence/outcome errors and independent typed secondary persistence errors survive all settlement-failure branches. Service formatting discards untrusted messages; unknown usage remains conservatively reserved rather than becoming zero or estimated actual cost.
- Workspace paths use canonical component containment plus retained metadata handles and reparse attributes. Symlinks/junctions/unsupported entries quarantine; .git is opaque; metadata discovery is bounded and explicitly incomplete on limits/failure, with no content/tool execution authority. Exact bounded child-name inventories fix ordinary delayed-timestamp directory mutation detection, not all filesystem identity races.
- Evidence bounds/media/length checks and payload redaction are implemented. Declared SHA-256 fails closed because crypto is unavailable; undeclared-digest artifacts are only `StructuralBoundsVerified`. Post-allocation Vec checks are not bounded streaming intake. Labels/metadata retention are not producer authentication, proof of source truth or independent validation of a finding. Real external intake, including binding producer/session/task/classification to execution, remains unverified; do not infer it from execution-result ID correlation.

The consolidated matrix below reconciles the rejected and later remediated reviews. Complete durable dispatch/outbox/lease reconciliation, blob storage/promotions, independently computed production cryptographic evidence, and real worker lifecycle are absent. Synthetic integration success does not close these broader design/roadmap gates.

### Milestone 6 — CLI, 6.1 / 6.1.1 / 6.1.2

[CLI parser](../../crates/sentra-cli/src/lib.rs) has a fixed typed grammar, maximum 64 UTF-8 arguments, duplicate/unknown/missing/invalid argument rejection and stable JSON/exit codes. It delegates only init/status/session-show to [LocalWorkspace](../../crates/sentra-core/src/service/local_workspace.rs); help/version are local/static. No command invokes execute_task, providers, Git or target scripts. Storage is explicitly selected outside the canonical target root. Existing-only opening refuses missing/empty/unrelated/inconsistent storage instead of recreating it. Repeated init preserves the sole stored identity.

The [6.1.1 review](INCREMENT_6_1_1_INDEPENDENT_REVIEW.md) remains historical Approved with Conditions. [6.1.2](INCREMENT_6_1_2_STORAGE_SEMANTICS_DOCUMENTATION.md) satisfies disclosure, not implementation of recovery:

| Inspection layer | Actual contract |
| --- | --- |
| Domain-state read-only | No lifecycle, approval, audit, budget or migration-record change for a valid existing selection |
| Logical SQL operations | Domain reads and schema validation; managed BEGIN IMMEDIATE and initialization/verification PRAGMAs, not a SQL read-only connection |
| SQLite storage effects | Existing DB opens READ_WRITE; committed WAL state may be recovered/read and checkpointed into the main DB; normal shutdown attempts `wal_checkpoint(TRUNCATE)` and surfaces failure |
| Filesystem effects | `.local-context.lock` may be opened/created even when DB is absent; `-shm`, other coordination files, timestamps, lock/directory metadata and DB/WAL bytes may change; write permission can be required |

Read-only media/permissions may produce `storage_or_service_failure` (5), or earlier path validation (4); there is no read-only fallback or guaranteed byte-preserving inspection. Existing row tests compare five domain tables; unchanged migration records follow from the existing-schema validation branch, not a new six-table byte comparison. Output write failures return 8 by code inspection; no deterministic failing-console test was added.

Initialization windows remain: file/DDL interruption can leave version-zero/unusable storage (5); a committed schema without a session is incomplete (6); a committed Created record without Scoped is incomplete (6); a valid committed Scoped record can be recovered with the same ID (0, created=false), subject to workspace/storage/checkpoint validity. Transactional DDL is not assumed to expose a logically half-committed schema. Preserve DB/WAL/SHM/journal; no automatic delete, overwrite, adoption or repair is implemented. These are current code/fixture results and prior SQLite crash evidence, not a new four-window CLI kill campaign.

**F-611-02 remains open before Phase 2 production readiness:** choose atomic staging (same-filesystem initialization/validation/flush/closure and proven no-replace publication, including sidecars) or explicit authorized operator recovery (detect/classify/preserve/reconcile without automatic deletion/replacement), then implement and test the approved choice. Neither is implemented here. OQ-25 also remains open: project identity aliases the single foundation SessionId, and multi-session stores fail closed. No multi-session support is declared.

## 4. Consolidated findings and conditions

Statuses refer to current inspected behavior, not retroactive changes to historical reviews. **Closed** is bounded to the tested local profile. **Deferred/Open** is not validated or silently waived. Source and executable regression evidence supplement report claims.

### Persistence and execution/evidence findings

| ID | Original severity / issue | Inspected remediation or disposition and evidence | Final status / remaining prerequisite |
| --- | --- | --- | --- |
| F-542-01 | Medium; ambiguous settlement boolean | SettlementStatus enum distinguishes Completed, CancelledWithUsage, CancelledUncertain, UncertainPartial; actual-vs-held handling inspected; native settlement tests pass | Closed; only measured supplied usage can release a hold |
| F-542-02 | Low; generic offline metadata needs uncached optional dependency | Explicit negative probe still fails on uncached syn 2.0.119; Windows target-filtered/build/no-deps metadata in validators succeeds | Deferred; provision/review required cache before unfiltered/all-platform inventory; no download authorized |
| F-542-03 | Low; quarantine is process-local | Manager halt/close preserves recovery set in place; cannot stop independent external controllers | Open; external supervision/quiescence required before multi-controller recovery |
| F-542-04 | Low; runtime integrity omitted FK check | integrity_report executes integrity_check(10) and foreign_key_check; detects/halts FK violations; three dedicated native FK tests pass | Closed |
| F-542-05 | Informational; FNV checksum is non-cryptographic | Migration source and documentation explicitly limit it to accidental drift | Informational; cryptographic tamper protection unimplemented |
| F-542-06 | Informational; provenance seal resets after restart | Private grant seal and privileged recover_issued_grant boundary inspected; reopen/replay tests pass | Informational; no ID-only or human-authentication claim |
| F-542-07 | Informational; one connection serializes reads | Arc/Mutex connection remains private; controlled read transactions, no pool | Informational; single-operator/performance envelope only |
| F-551-01 | Low; tautological result invariant | validate_for_request checks concrete status/exit consistency; adversarial backend-result tests pass | Closed |
| F-551-02 | Low; no active backend cancellation | Trait is blocking execute only; Core cancellation reports are explicitly synthetic/simulated | Deferred; real acknowledgement/termination/late-response/recovery evidence before VM workloads; not closed by lifecycle prose |
| F-551-03 | Low; evidence checked after allocation | Vec payload structural ceiling remains post-allocation; no streaming ingress exists | Deferred; bounded intake before external artifacts |
| F-551-04 | Informational; narrow MIME handling | Current syntax/allowlist handling is constrained; not a complete MIME parser/interoperability claim | Informational; revisit only with a validated intake contract |
| F-551-05 | Informational; execution-ID correlation missing | ExecutionResult validates ID against request before successful service processing; mismatch regression passes | Closed; not proof of authenticated external producer/intake |

Sources: [5.4.2.1 review](INCREMENT_5_4_2_1_SECURITY_REVIEW.md), [5.4.3 remediation](INCREMENT_5_4_3_PERSISTENCE_REMEDIATION.md), [5.4.3.1 review](INCREMENT_5_4_3_1_INDEPENDENT_REVIEW.md), [5.5.1 review](INCREMENT_5_5_1_INDEPENDENT_REVIEW.md); current [persistence tests](../../crates/sentra-core/tests/persistence_tests.rs), [execution/evidence adversarial tests](../../crates/sentra-core/tests/execution_evidence_adversarial_tests.rs).

### Core service rejection and remediation history

| ID | Original severity / issue | Current evidence and disposition | Final status / prerequisite |
| --- | --- | --- | --- |
| F-561-01 | Medium; missing mandatory policy/floor enforcement | execute_task uses authoritative mint/policy evaluation, state eligibility and atomic revalidation; straight-line denial and owner-isolation tests pass | Closed for local profile |
| F-561-02 | Low; grant consumed before budget success | One prepare transaction binds owner/context, reserve, consume and audits; mismatch/exhaustion/audit/update faults roll back; process races have one winner | Closed; external dispatch is not in that transaction |
| F-561-03 | Low; settlement failure silently lost | Typed primary/secondary errors and non-success outcomes preserved; actual settlement-fault tests pass; uncertain amounts held | Closed |
| F-561-04 | Informational; pipeline not wholly atomic | Committed preparation and external effect/settlement remain distinct; no task/outbox/lease recovery | Deferred; application-effect reconciliation before real effects and full recovery acceptance |
| F-561-05 | Informational; streaming bounds | Same post-allocation boundary as F-551-03 | Deferred; external intake gate |
| F-5621-01 | High; public context replacement | Broker request-side setter compares only; privileged authority owns registration; actual Core service does not request-side synchronize another owner | Closed; trusted authority must remain private to controller |
| F-5621-02 | High; consume A while charging B | PrepareExecutionRequest carries one sealed immutable context; grant snapshot/session and budget/audits derive from it; cross-session tests pass | Closed |
| F-5621-03 | High; automatic path lacks context fence | Every prepare validates current full snapshot/state, with OS admission held through synchronous dispatch; no-grant stale tests pass | Closed under protected same-database namespace |
| F-5621-04 | Medium; Paused dispatch | allows_execution explicitly only Scoped/Planned/Running; paused/waiting/created/terminal regressions pass | Closed |
| F-5621-05 | Medium; provider quote/reservation mismatch | Authoritative evaluator requires action estimated cost equal reserved amount; overflow/budget tests pass | Closed for supplied bounds; real usage/pricing not validated |
| F-5621-06 | Medium; diagnostic leakage | Service/prepare Debug/Display redaction and sanitized typed error ingress; sensitive-message tests pass | Closed for reviewed service diagnostics; not arbitrary metadata secrecy |
| F-5621-07 | Medium; primary outcomes/types lost | Execution/evidence/outcome primary variants plus separate PersistenceError secondary, structured accessors/source chain; non-success result tests pass | Closed |
| F-5621-08 | Medium; identical request synchronization invalidates grants | Request-side context check is non-mutating; explicit privileged legacy rebind still invalidates ABA generations intentionally | Closed; do not relax explicit owner rebind invalidation |
| F-5621-09 | Medium; unrelated receipt makes preview Granted | preview_execution validates seal/snapshot/action/expiry/state non-consumingly; execute separately repeats atomic validation | Closed; preview is advisory, never a dispatch capability |
| F-5621-10 | Informational; durable prepare is not durable dispatch | Real owned post-prepare process exit retains consumed grant/held budget; no blind replay, no completed outbox protocol | Deferred; real effects/durable resume gate |
| F-5621-11 | Informational; counts/crypto claims overstated | Reconciled named-case denominators and canonical-not-crypto claims; old rejected records preserved, not relabeled passes | Closed in this assessment's claims; historical wording remains dated |
| F-5621-12 | Medium; intermittent directory mutation miss | Bounded sorted name inventory compared independently of timestamps; both old/deterministic tests currently pass; prior independent 20/20 + 20/20 evidence retained | Closed for ordinary child-name mutation; OQ-22 strong identity/hostile races open |

Sources: [5.6.1 review](INCREMENT_5_6_1_INDEPENDENT_REVIEW.md), [5.6.2.1 rejection](INCREMENT_5_6_2_1_INDEPENDENT_REVIEW.md), [5.6.2.2 remediation](INCREMENT_5_6_2_2_SECURITY_REMEDIATION.md), [5.6.2.2.1 review](INCREMENT_5_6_2_2_1_INDEPENDENT_REVIEW.md). The original 5.6.2 claim was not accepted as evidence: later remediation reproduced 12 failed adversarial assertions before fixing them. Current [independent Core tests](../../crates/sentra-core/tests/independent_core_review_tests.rs) cover actual production entry points, SQLite aborts and shared dispatch fencing; no new test hook or assertion edit was introduced here.

### Policy hardening and CLI conditions

| ID | Original severity / issue | Current evidence and disposition | Final status / prerequisite |
| --- | --- | --- | --- |
| F-562221-01 | Medium; changed policy leaves old contexts valid | Immutable evaluator, version-2 effective identity, owner activation/epoch rotation and unchanged-rule no-op; live dispatch/ABA/old-instance tests pass | Closed for fixed owned rules; dynamic/global rollout remains future design |
| F-562221-02 | Low; preview flattens database failure into Denied | Only expected semantic denial maps to Denied; Closed/Integrity/SQL errors retain typed PersistenceError; read-only domain-image tests pass | Closed |
| F-562221-03 | Low; validator assumes default Cargo target | Source derives actual archive/dependency path from Cargo artifacts/metadata and generates fresh probe; current default runner passes; historical four-scenario portability matrix remains evidence, not newly rerun | Closed for documented tested matrix; no universal toolchain/path claim |
| F-562221-04 | Informational; post-commit effect recovery | Same conservative consumed/held state; no durable exactly-once protocol | Deferred; before real effects/full recovery acceptance |
| F-5622221-01 | Informational; historical physical index change | Historical reports show equal semantic entries and later owner commits. This assessment observed unchanged physical bytes and assigns no historical writer independently | Informational; stop/investigate if a new unexplained change occurs |
| F-5622221-02 | Informational; policy string is not crypto | Canonical effective-rule string inspected; no hash/signature implementation claimed | Informational; trusted-local comparison only |
| F-5622221-03 | Informational; validator command budget | Existing bounded 180-second runner budget unchanged; current invocations complete without timeout | Informational; not a workload quota or isolation guarantee |
| F-611-01 | Low; inspection has physical storage effects | README four-layer contract and 6.1.2 explicitly disclose read-write open, WAL/TRUNCATE, lock/SHM/timestamps, permissions and exit 5/possible earlier 4 | Closed as documentation condition; runtime write requirement remains |
| F-611-02 | Low; incomplete initialization after interruption | Destination-file/schema/Created/Scoped windows remain; only design alternatives exist | Open; mandatory decision + implementation + verification before Phase 2 production readiness |
| F-611-03 | Informational; project identity aliases first session | Exactly-one-session query/fail-closed ambiguity inspected; multi-session regression passes | Informational limitation; OQ-25 remains Open before independent project/multi-session model |
| F-611-04 | Informational; transient Windows file contention | Earlier OS 5/32 observations retained; no such failure in this run, no binary deletion or security-setting change | Informational; no new attribution to a process without evidence |

Sources: [5.6.2.2.2 hardening](INCREMENT_5_6_2_2_2_POLICY_AND_VALIDATOR_HARDENING.md), [5.6.2.2.2.1 approval](INCREMENT_5_6_2_2_2_1_INDEPENDENT_REVIEW.md), [6.1.1 conditions](INCREMENT_6_1_1_INDEPENDENT_REVIEW.md), [6.1.2 disclosure/readiness](INCREMENT_6_1_2_STORAGE_SEMANTICS_DOCUMENTATION.md); current [22 policy/isolation cases](../../crates/sentra-core/tests/authorization_isolation_review_tests.rs) and [19 local lifecycle cases](../../crates/sentra-core/tests/local_workspace_tests.rs). The original in-memory A-to-B defect from [5.3.1](INCREMENT_5_3_1_SECURITY_REVIEW.md) is also denied by the original probe in this final run, with matching-once/replay assertions intact.

## 5. Final execution/security boundary assessment

**Verified boundary for the shipped composition:** untrusted target workloads cannot execute through the current CLI or either built-in backend. CLI constructs FailClosedBackend; production backend implementations are FailClosedBackend and SyntheticFixtureBackend only. Both declare supports_untrusted=false / isolated_vm_available=false, refuse untrusted scope, and contain no host/Docker/WSL2 process launch. ExecutionEngine validates requests, checks scope/capability compatibility and validates result correlation/status. SyntheticFixtureBackend simulates controlled outcomes in memory; it never interprets action arguments as executable commands or reads arbitrary source to run it. Policy/classification/session/grant/budget checks remain in CoreService before dispatch.

Evidence: actual source paths above, passing existing safe boundary/scope/result tests and CLI/source call-path inspection. No untrusted workload was executed as a probe. Enum tagging and synthetic fixtures are not proof of real VM isolation.

**Trust qualification:** CoreService/ExecutionEngine constructors accept a trusted Rust backend trait implementation. Capability flags are declarations, not cryptographic VM attestation; arbitrary malicious host code supplied through trusted composition is outside this boundary. No validated production VM backend exists. The invariant is not claimed for future/custom backends, untrusted plugins loaded in-process, hostile storage administrators or undeclared external integration. Before any such expansion, establish containment, transport/authentication, egress, cancellation, source/evidence correlation and recovery through separate gates. No fallback was added to hide a missing backend.

## 6. Offline verification and non-overlapping inventory

The exact main commands and existing scripts below ran successfully, offline, without changing the lockfile or downloading dependencies. They execute trusted Sentra fixtures, not target workloads:

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --offline
cargo clippy --workspace --all-targets --all-features --offline -- -D warnings
cargo test --workspace --offline
pwsh -NoProfile -File experiments/phase1/persistence/Validate.ps1
pwsh -NoProfile -File experiments/phase1/authorization/Validate.ps1
pwsh -NoProfile -File experiments/phase1/workspace/Validate.ps1
pwsh -NoProfile -File experiments/phase1/cli/Validate.ps1
cargo test --manifest-path experiments/phase1/provider/Cargo.toml --offline
```

| Command/check | Actual result |
| --- | --- |
| fmt / all-target all-feature check / Clippy with -D warnings | Each exit 0 |
| Workspace test | Exit 0: 290 runtime + 7 compile-fail doctests passed, 0 failed, 5 ignored |
| Persistence validator | Exit 0, 13/13 checks Passed; 42 persistence cases plus 3 separate repetitions of the cross-process parent case |
| Authorization validator | Exit 0, 13/13; 27 grant cases; original A-to-B/matching-once/replay probe; 64/32 deterministic concurrency rounds |
| Workspace validator | Exit 0, 11/11; two real junction/deny-ACL case IDs and three runs of the same scale case; owned fixture ACLs restored/cleanup Passed |
| CLI validator | Exit 0, 18/18; six JSON smoke invocations and two Windows junction invocations in addition to overlapping suite checks; cleanup Passed |
| Standalone mock contract | Exit 0: 62 Passed, 0 Failed, 0 Ignored; separate package/corpus |
| Local documentation/fence/heading checks | Passed; pre-report 61 Markdown files / 477 relative links, 129 external or absolute URLs intentionally not contacted; final report link check recorded below |

Additional bounded negative cache probe, **not a successful quality check**:

```powershell
cargo metadata --locked --offline --format-version 1
```

Actual exit **1**: `failed to download syn v2.0.119`, followed by the offline prohibition. This confirms F-542-02's unfiltered metadata cache limitation. No HTTP request/dependency download was allowed, no workaround/manifest edit was made. The required Windows build/no-deps/target-filtered validator graph succeeds; generic cross-platform metadata completeness is not claimed.

### Inventory reconciliation

| Workspace group | Discovered runtime entries | Ordinary passed | Ordinary ignored |
| --- | ---: | ---: | ---: |
| Core unit | 14 | 14 | 0 |
| Authorization isolation | 22 | 22 | 0 |
| Authorization | 27 | 27 | 0 |
| Domain / evidence / adversarial execution-evidence / execution | 37 | 37 | 0 |
| Independent Core review | 31 | 30 | 1 helper |
| Persistence | 43 | 42 | 1 helper |
| Policy / security / service / session | 43 | 43 | 0 |
| Workspace | 41 | 38 | 3 platform/scale |
| Local workspace | 19 | 19 | 0 |
| CLI | 18 | 18 | 0 |
| **Runtime** | **295** | **290** | **5** |

Add **7 passed compile-fail doctests**: **302 discovered harness entries, 297 ordinary passes, 0 failed, 5 ignored**. The workspace validator actually ran the three ignored case IDs (`workspace_windows_junction_is_quarantined_without_target_traversal`, `workspace_windows_permission_denied_is_not_accepted`, `workspace_scale_10000_file_measurement`) successfully, yielding **300 distinct named verification cases passed**, not 300 separately counted assert! statements. The two other ignored entries are **owned_5621_process** and **owned_persistence_process_worker**, exercised by parent tests, not standalone ignored passes or extra unique successes. Some historical prose calls the former independent_owned_worker; current source/output names it owned_5621_process.

The independent provider package adds a separately reported 62-case corpus, not another run of the workspace. Its two historical runs and this fresh run remain 62 unique provider cases. Validator full-suite reruns, concurrency rounds, subprocess executions, CLI smoke checks and the three scale repetitions are not summed into a larger unique workspace total. Earlier 153/205/231/253 counts concern earlier snapshots or erroneous historical summaries; this report does not silently rewrite them. The 5.6.2.1 failed probes/repeats remain failures on their original inputs, followed by identifiable remediation and independent successful regressions.

Current Q-05 runs enumerate 10,000 files / 310,000 bytes, complete=true, measured discovery **9481 / 8836 / 8796 ms**, with process peak working sets **8,425,472 / 8,724,480 / 8,646,656 bytes**. Fixture creation contributes to full process elapsed time and is separate from discovery timing. Recorded host: i7-11800H, 34,091,286,528 bytes RAM. These measurements pass the bounded 30-second/512-MiB fixture target, not a general repository-performance guarantee.

No new physical-fault, read-only-media, four-window CLI crash injection, alternative-target-directory matrix, genuine external provider, dedicated VM, real cancellation or untrusted target experiment was executed. Historical evidence is labeled where carried forward. Required checks/platform fixtures have no skipped failure disguised as Passed.

## 7. Cross-document and ADR consistency

Current README, architecture, requirements, security policy, roadmap, open questions and 6.1.2 accurately keep Phase 1 incomplete and Phase 2 unauthorized. Storage disclosure uses domain-state read-only rather than physical read-only. Mock/synthetic behavior, x64-only validation, unavailable crypto, single-session identity and open recovery gates remain explicit.

The [Core design](CORE_ENGINE_DESIGN.md) is a design/acceptance document, not implementation proof: its evidence tables, blob pruning/reconciliation and computed SHA-256 items remain unfulfilled. Dated provider/sandbox reports use terminology from their original stage; subsequent implementation/closure reviews provide narrower current evidence. In particular ARCH sandbox Passed labels are design assessments, and historical six-table byte-comparison/manual-deletion wording is qualified by 6.1.2. No historical review was rewritten to remove these discrepancies.

All seven ADRs retain their recorded status: 0001/0003/0004/0005/0006 Accepted with their existing qualifiers; 0002/0007 Proposed. Acceptance of VM/evidence/control-plane principles is not runtime proof. No new technology decision, license grant, schema change or phase authorization follows from this report. Offline link checks cover local files and headings; old absolute file URLs/HTTP links are not claimed portable/live-verified.

## 8. Capability and readiness disposition

| Classification | Supported statement |
| --- | --- |
| Validated | Current x64/MSVC offline build/lint/test; canonical metadata path fixtures; native SQLite schema/rollback/FK/WAL/approval/budget tests; exact grants and single use; CLI init/status/session-show/JSON |
| Validated only under restricted conditions | Protected local single-operator storage and trusted authority/backend composition; cooperative same-DB admission locks; metadata-only observations; one-session identity; synchronous synthetic execution; structural-only evidence |
| Design-level without VM runtime proof | AF_HYPERV transport, authenticated guest/control channel, zero-NIC/switch policy, VHDX reset; atomic staging and explicit operator recovery alternatives |
| Unverified | ARM64/Linux/macOS; real VM provisioning/containment/cancellation; real providers/tokenizer/pricing/wire transport; physical exhaustion/write-fsync IOERR/power loss; production crypto/evidence streaming/native backup/blob reconciliation |
| Explicitly deferred/open | Durable dispatch/outbox/leases, external-effect reconciliation, F-611-02 incomplete-init recovery, OQ-25 multi-session project model, OQ-22 strong identity, public distribution/licensing |

### Conditions, owners and deadlines

These are retained prerequisites, not authorized implementation instructions:

| Gate | Owner / rationale | Must be satisfied before |
| --- | --- | --- |
| Existing Phase 1 F-01/F-02/F-14 and roadmap recovery acceptance | Core/platform + security: provide complete scoped input/manifest and actual durable resume/dispatch/blob/result reconciliation evidence, or obtain an explicit owner-approved revision of closure criteria | Full Phase 1 closure under the applicable baseline; no silent waiver in this assessment |
| F-611-02 / OQ-25 bootstrap recovery | Core/platform with security review: decide atomic staging versus explicit operator recovery, implement approved choice and test real schema/Created/Scoped/checkpoint/publication/recovery interruptions, contention and sidecar preservation | **Phase 2 production readiness**; documentation/design alternatives alone do not close it |
| OQ-25 independent project/multi-session identity | Core/platform: versioned project model/migration and no ambiguous session selection | Any multi-session CLI/repository-support claim |
| OQ-22 / OQ-23 strong filesystem/revision/authority truth | Core/security: safe handle identity, alias/reparse/race/source-binding evidence and trustworthy owner/operator/worker identifiers | Target content reads/exports/modification or expanded trust boundary |
| OQ-03/04/18 + F-551-02 isolated worker | Execution/security: delegated permissions only with approval, disposable dedicated guest, authenticated transport, egress/credentials/filesystem/resources and real termination/recovery | Any untrusted build/test/scanner/PoC or real VM capability claim |
| F-5621-10 / F-562221-04 / ADR-0003 durable effects | Core/platform: outbox/lease/idempotency/correlation and explicit ambiguous-attempt reconciliation | Any real provider/network/filesystem/worker effect, in addition to applicable Phase 1 recovery criteria |
| OQ-06 and provider N01–N06 | AI/security: real endpoint conformance, transport/egress/cancellation, reliable usage and durable budgets | Provider integration or private-source egress |
| F-551-03 / OQ-24 evidence/storage | Core/security: bounded ingress, producer/session/task/classification correlation, audited crypto, safe native backup/blob recovery; physical faults tested or explicitly bounded | External evidence ingestion and relevant durability/integrity claims |
| OQ-01/02 / ADR-0002 | Core: complete language/platform suitability/packaging review; keep tested x64 envelope explicit | Unconditional core-language/release-support claim |
| OQ-10/11/12/13/16/21 / ADR-0007 | Owner/security/licensing: exact integration notices, chosen license, private reporting, retention/encrypted-volume/identity and governance decisions | Public distribution or expanded sensitive/multi-user service |
| Other OQ-05/07/08/14/15/17/19/20 | Research/tool/integration/platform owners: corpora, adapters, independence and justified scale | Their separately authorized later pilots/integrations; not additional completed Phase 1 capabilities |

## 9. Phase 2 boundary and final disposition

No current shipped untrusted-execution bypass was reproduced. The named closed defects have actual current implementation and regression support, with the trust limits above. Full Phase 1 closure nevertheless remains **NOT APPROVED** because mandatory application/input/recovery acceptance evidence is incomplete under the unchanged baseline. Green fixtures and prior incremental approvals are insufficient to erase those requirements. This report does not supersede or revoke their historical decisions.

F-611-02 is **not resolved**, OQ-25 is **not closed**, and no multi-session, VM, ARM64, real-provider, physical-durability, real-cancellation, streaming or cryptographic-production-readiness claim is made. Progress records only this assessment and preserves all earlier records.

**Phase 2 was not started or authorized. Stop after this verification report.**

## Appendix A — Final run evidence embedded in this report

The following transcript summaries are generated from the actual commands/results, not historical success claims. All newly generated validator result files were captured before cleanup; their original filenames and SHA-256 identify these executions, but they are not linked as retained artifacts. Existing historical result files remain available in Appendix C's inventory. Exit codes on intentional CLI-negative smoke checks are compared with their expected values, not mislabeled as process-success zero.

### A.1 Direct command transcripts

| Command | Exit | Actual result excerpt |
| --- | ---: | --- |
| `cargo fmt --all -- --check` | 0 | Completed without error |
| `cargo check --workspace --all-targets --all-features --offline` | 0 | Completed without error |
| `cargo clippy --workspace --all-targets --all-features --offline -- -D warnings` | 0 | Completed without error |
| `cargo test --workspace --offline` | 0 | 297 passed, 0 failed, 5 ignored across workspace harnesses |
| `cargo test --manifest-path experiments/phase1/provider/Cargo.toml --offline` | 0 | 62 passed, 0 failed, 0 ignored |
| `cargo metadata --locked --offline --format-version 1` | 1 | error: failed to download `syn v2.0.119` /   attempting to make an HTTP request, but --offline was specified |

### A.2 Persistence validator

Command: `pwsh -NoProfile -File experiments/phase1/persistence/Validate.ps1`, exit **0**. Transient generated record: `experiments/phase1/persistence/results/1794007257727.json`; captured before removal; SHA-256 `c7f929aa6374a1c45874553f3193d85f0b9163b0dfea94b528c4449b2e9fbd9a`. Recorded inputs unchanged: **true**. No target workload or external service.

| Check | Arguments | Exit / expected | Recorded status |
| --- | --- | --- | --- |
| rustc-version | `-vV` | 0 | Passed |
| cargo-version | `--version` | 0 | Passed |
| resolved-metadata | `metadata --offline --format-version=1 --filter-platform x86_64-pc-windows-msvc` | 0 | Passed |
| feature-graph | `tree --offline -e features` | 0 | Passed |
| native-msvc-build | `build --workspace --offline --target x86_64-pc-windows-msvc -vv` | 0 | Passed |
| format | `fmt --all -- --check` | 0 | Passed |
| check | `check --workspace --offline` | 0 | Passed |
| clippy | `clippy --workspace --all-targets --all-features --offline -- -D warnings` | 0 | Passed |
| workspace-tests | `test --workspace --offline` | 0 | Passed |
| persistence-integration | `test --package sentra-core --test persistence_tests --offline` | 0 | Passed |
| cross-process-repeat-1 | `test --package sentra-core --test persistence_tests --offline approval_cross_process_ -- --nocapture` | 0 | Passed |
| cross-process-repeat-2 | `test --package sentra-core --test persistence_tests --offline approval_cross_process_ -- --nocapture` | 0 | Passed |
| cross-process-repeat-3 | `test --package sentra-core --test persistence_tests --offline approval_cross_process_ -- --nocapture` | 0 | Passed |

### A.3 Authorization validator

Command: `pwsh -NoProfile -File experiments/phase1/authorization/Validate.ps1`, exit **0**. Transient generated record: `experiments/phase1/authorization/results/1794007325709.json`; captured before removal; SHA-256 `7db92ed93614726e499b03b66bf9ef0710347291d1f8d973fd98a3b0c387150d`. Recorded inputs unchanged: **true**. No target workload or external service.

| Check | Arguments | Exit / expected | Recorded status |
| --- | --- | --- | --- |
| rustc-version | `-vV` | 0 | Passed |
| cargo-version | `--version` | 0 | Passed |
| dependency-metadata | `metadata --offline --no-deps --format-version=1` | 0 | Passed |
| format | `fmt --all -- --check` | 0 | Passed |
| check | `check --offline --workspace --all-targets` | 0 | Passed |
| clippy | `clippy --offline --workspace --all-targets --all-features -- -D warnings` | 0 | Passed |
| workspace-tests | `test --offline --workspace` | 0 | Passed |
| grant-binding-regressions | `test --offline --package sentra-core --test authorization_tests` | 0 | Passed |
| repeat-concurrency | `test --offline --package sentra-core --test authorization_tests concurrency_ -- --nocapture` | 0 | Passed |
| probe-format | `--edition=2024 --check E:/MyProject/Mix/GitHub/Sentra/experiments/phase1/workspace/PolicyContextProbe.rs` | 0 | Passed |
| probe-library-artifact | `build --offline --package sentra-core --message-format=json` | 0 | Passed |
| original-probe-compile | `--edition=2024 --crate-name policy_context_probe E:/MyProject/Mix/GitHub/Sentra/experiments/phase1/workspace/PolicyContextProbe.rs --extern sentra_core=E:/MyProject/Mix/GitHub/Sentra/target/debug/libsentra_core.rlib -L dependency=E:/MyProject/Mix/GitHub/Sentra/target/debug/deps -o E:/MyProject/Mix/GitHub/Sentra/target/authorization-validation/45552cc34c05438b8be499efaf517fc0/policy-context-probe.exe` | 0 | Passed |
| original-a-to-b-probe | `` | 0 | Passed |

Recorded markers:

```text
CONCURRENCY rounds=32 mismatches=256 legitimate_successes=32
CONCURRENCY rounds=64 matching_successes=64 matching_replays=64 mismatches=384
POLICY_CONTEXT_BINDING=Passed: mismatched metadata action rejected; matching action accepted once; replay rejected
```

### A.4 Workspace validator

Command: `pwsh -NoProfile -File experiments/phase1/workspace/Validate.ps1`, exit **0**. Transient generated record: `experiments/phase1/workspace/results/1794007373508.json`; captured before removal; SHA-256 `30fdddb22f1ed42326f0d76cfd29f33e7a58bf1102fc8c1b5714b0f3fff2afe5`. Recorded inputs unchanged: **true**. Owned fixture cleanup: **Passed**.

| Check | Arguments | Exit / expected | Recorded status |
| --- | --- | --- | --- |
| rustc-version | `-vV` | 0 | Passed |
| cargo-version | `--version` | 0 | Passed |
| format | `fmt --all -- --check` | 0 | Passed |
| check | `check --offline --workspace` | 0 | Passed |
| clippy | `clippy --offline --workspace --all-targets --all-features -- -D warnings` | 0 | Passed |
| workspace-tests | `test --offline --workspace` | 0 | Passed |
| windows-fixture-tests | `test --offline --package sentra-core --test workspace_tests workspace_windows_ -- --ignored --nocapture` | 0 | Passed |
| benchmark-artifact | `test --offline --package sentra-core --test workspace_tests --no-run --message-format=json` | 0 | Passed |
| benchmark-1 | `--ignored --exact workspace_scale_10000_file_measurement --nocapture --test-threads=1` | 0 | Passed |
| benchmark-2 | `--ignored --exact workspace_scale_10000_file_measurement --nocapture --test-threads=1` | 0 | Passed |
| benchmark-3 | `--ignored --exact workspace_scale_10000_file_measurement --nocapture --test-threads=1` | 0 | Passed |

Recorded markers:

```text
test workspace_scale_10000_file_measurement ... DISCOVERY_METRICS entries=10000 elapsed_ms=9481 bytes=310000 complete=true
test workspace_scale_10000_file_measurement ... DISCOVERY_METRICS entries=10000 elapsed_ms=8836 bytes=310000 complete=true
test workspace_scale_10000_file_measurement ... DISCOVERY_METRICS entries=10000 elapsed_ms=8796 bytes=310000 complete=true
```

### A.5 CLI validator

Command: `pwsh -NoProfile -File experiments/phase1/cli/Validate.ps1`, exit **0**. Transient generated record: `experiments/phase1/cli/results/61-1794007470717.json`; captured before removal; SHA-256 `588df9a6874fbf6ccca9d6e81d0bf6ffa45c49038e3d54fd3c131cf6707546ac`. Recorded inputs unchanged: **true**. Owned fixture cleanup: **Passed**.

| Check | Arguments | Exit / expected | Recorded status |
| --- | --- | --- | --- |
| rust-version | `-vV` | 0 / 0 | Passed |
| cargo-version | `--version` | 0 / 0 | Passed |
| format | `fmt --all -- --check` | 0 / 0 | Passed |
| check | `check --workspace --all-targets --all-features --offline` | 0 / 0 | Passed |
| clippy | `clippy --workspace --all-targets --all-features --offline -- -D warnings` | 0 / 0 | Passed |
| workspace-tests | `test --workspace --offline` | 0 / 0 | Passed |
| discovered-tests | `test --workspace --offline -- --list` | 0 / 0 | Passed |
| dependency-tree | `tree --workspace --offline -e features` | 0 / 0 | Passed |
| metadata | `metadata --offline --no-deps --format-version 1` | 0 / 0 | Passed |
| cli-build-artifact | `build --offline --package sentra-cli --message-format=json` | 0 / 0 | Passed |
| json-uninitialized | `status --workspace E:/MyProject/Mix/GitHub/Sentra/target/cli-validation-099b48ed96ef4c48bae0a37bcfd7b641/workspace Unicode ü space --database E:/MyProject/Mix/GitHub/Sentra/target/cli-validation-099b48ed96ef4c48bae0a37bcfd7b641/storage/local.db --json` | 3 / 3 | Passed |
| json-init | `init --workspace E:/MyProject/Mix/GitHub/Sentra/target/cli-validation-099b48ed96ef4c48bae0a37bcfd7b641/workspace Unicode ü space --database E:/MyProject/Mix/GitHub/Sentra/target/cli-validation-099b48ed96ef4c48bae0a37bcfd7b641/storage/local.db --json` | 0 / 0 | Passed |
| json-repeat-init | `init --workspace E:/MyProject/Mix/GitHub/Sentra/target/cli-validation-099b48ed96ef4c48bae0a37bcfd7b641/workspace Unicode ü space --database E:/MyProject/Mix/GitHub/Sentra/target/cli-validation-099b48ed96ef4c48bae0a37bcfd7b641/storage/local.db --json` | 0 / 0 | Passed |
| json-status-from-workspace | `status --database E:/MyProject/Mix/GitHub/Sentra/target/cli-validation-099b48ed96ef4c48bae0a37bcfd7b641/storage/local.db --json` | 0 / 0 | Passed |
| json-session | `session show 53454ff5-e16c-4bfc-8000-000000000003 --database E:/MyProject/Mix/GitHub/Sentra/target/cli-validation-099b48ed96ef4c48bae0a37bcfd7b641/storage/local.db --json` | 0 / 0 | Passed |
| json-invalid-arguments | `scan --json` | 2 / 2 | Passed |
| windows-junction-root | `init --workspace E:/MyProject/Mix/GitHub/Sentra/target/cli-validation-099b48ed96ef4c48bae0a37bcfd7b641/root-junction --database E:/MyProject/Mix/GitHub/Sentra/target/cli-validation-099b48ed96ef4c48bae0a37bcfd7b641/storage/forbidden.db --json` | 4 / 4 | Passed |
| windows-junction-storage | `init --workspace E:/MyProject/Mix/GitHub/Sentra/target/cli-validation-099b48ed96ef4c48bae0a37bcfd7b641/workspace Unicode ü space --database E:/MyProject/Mix/GitHub/Sentra/target/cli-validation-099b48ed96ef4c48bae0a37bcfd7b641/storage-junction/forbidden.db --json` | 4 / 4 | Passed |

## Appendix B — Git and preservation result

Final documentation verification: **62 Markdown files, 528 relative file/heading links checked, 0 errors**; 129 external or machine-absolute URLs were excluded from live verification. Referenced requirement IDs resolve. Seven ADRs and all pre-existing reports remain unchanged. `git diff --check` exits 0. No renderer, external website or network verification was substituted for these bounded checks.

| Comparison to clean entry | Result |
| --- | --- |
| head | Unchanged |
| branch | Unchanged |
| upstream | Unchanged |
| ahead_behind | Unchanged |
| refs | Unchanged |
| history | Unchanged |
| index | Unchanged |
| index_sha256 | Unchanged |

Final branch/HEAD/upstream remain `develop` / `354021954f33768a76d6dbecfc1f37b7fed41a60` / locally recorded `origin/develop`, 0/0. Final index entry count is 280, with SHA-256 `01c43128e01edee7984e639042af9884d9711768e1aa58080334826837649143`, matching entry. All 279 pre-existing tracked files other than the narrowly authorized PROGRESS update remain byte-identical, including every historical report/evidence, Phase 0 document outside PROGRESS, implementation, test, manifest/lockfile, schema, ADR and validator. No pre-existing modified/untracked work existed at entry. After removal of only the four hash-verified result records created by this assessment, retained work is **1 modified file (`PROGRESS.md`), 1 untracked file (this report), 0 staged files**. No existing evidence file was removed or replaced. No index/history/ref restoration was attempted.

## Appendix C — Complete tracked artifact inventory at entry

This lists all 280 entry paths, including foundational/research/architecture/ADR documents, production crates, experiments, scripts/fixtures, raw results and earlier reviews/remediations. It excludes this newly created report and ignored build caches. The existing documentation/progress file in the list retains its historical sections.

```text
.gitattributes
.gitignore
AGENTS.md
ARCHITECTURE.md
Cargo.lock
Cargo.toml
PROGRESS.md
README.md
REQUIREMENTS.md
ROADMAP.md
SECURITY.md
VISION.md
crates/sentra-cli/Cargo.toml
crates/sentra-cli/src/lib.rs
crates/sentra-cli/src/main.rs
crates/sentra-cli/tests/cli_tests.rs
crates/sentra-core/Cargo.toml
crates/sentra-core/src/audit/event.rs
crates/sentra-core/src/audit/mod.rs
crates/sentra-core/src/common/clock.rs
crates/sentra-core/src/common/mod.rs
crates/sentra-core/src/domain/classification.rs
crates/sentra-core/src/domain/error.rs
crates/sentra-core/src/domain/id.rs
crates/sentra-core/src/domain/mod.rs
crates/sentra-core/src/domain/time.rs
crates/sentra-core/src/evidence/error.rs
crates/sentra-core/src/evidence/mod.rs
crates/sentra-core/src/evidence/model.rs
crates/sentra-core/src/evidence/verifier.rs
crates/sentra-core/src/execution/backend.rs
crates/sentra-core/src/execution/engine.rs
crates/sentra-core/src/execution/error.rs
crates/sentra-core/src/execution/mod.rs
crates/sentra-core/src/execution/model.rs
crates/sentra-core/src/execution/scope.rs
crates/sentra-core/src/lib.rs
crates/sentra-core/src/persistence/connection.rs
crates/sentra-core/src/persistence/error.rs
crates/sentra-core/src/persistence/migration.rs
crates/sentra-core/src/persistence/mod.rs
crates/sentra-core/src/persistence/model.rs
crates/sentra-core/src/persistence/repository.rs
crates/sentra-core/src/persistence/schema_v1.sql
crates/sentra-core/src/persistence/transaction.rs
crates/sentra-core/src/policy/action.rs
crates/sentra-core/src/policy/approval.rs
crates/sentra-core/src/policy/budget.rs
crates/sentra-core/src/policy/decision.rs
crates/sentra-core/src/policy/engine.rs
crates/sentra-core/src/policy/mod.rs
crates/sentra-core/src/service/config.rs
crates/sentra-core/src/service/core.rs
crates/sentra-core/src/service/error.rs
crates/sentra-core/src/service/harness.rs
crates/sentra-core/src/service/lifecycle.rs
crates/sentra-core/src/service/local_workspace.rs
crates/sentra-core/src/service/mod.rs
crates/sentra-core/src/session/machine.rs
crates/sentra-core/src/session/metadata.rs
crates/sentra-core/src/session/mod.rs
crates/sentra-core/src/session/state.rs
crates/sentra-core/src/workspace/boundary.rs
crates/sentra-core/src/workspace/discovery.rs
crates/sentra-core/src/workspace/error.rs
crates/sentra-core/src/workspace/mod.rs
crates/sentra-core/src/workspace/model.rs
crates/sentra-core/src/workspace/platform.rs
crates/sentra-core/tests/authorization_isolation_review_tests.rs
crates/sentra-core/tests/authorization_tests.rs
crates/sentra-core/tests/domain_tests.rs
crates/sentra-core/tests/evidence_tests.rs
crates/sentra-core/tests/execution_evidence_adversarial_tests.rs
crates/sentra-core/tests/execution_tests.rs
crates/sentra-core/tests/independent_core_review_tests.rs
crates/sentra-core/tests/local_workspace_tests.rs
crates/sentra-core/tests/persistence_tests.rs
crates/sentra-core/tests/policy_tests.rs
crates/sentra-core/tests/security_tests.rs
crates/sentra-core/tests/service_tests.rs
crates/sentra-core/tests/session_tests.rs
crates/sentra-core/tests/support/persistence.rs
crates/sentra-core/tests/workspace_tests.rs
docs/AGENT_MODEL.md
docs/DATA_MODEL.md
docs/EXTENSIONS.md
docs/OPEN_QUESTIONS.md
docs/OPERATING_MODES.md
docs/README.md
docs/REVIEW.md
docs/THREAT_MODEL.md
docs/VALIDATION.md
docs/adr/0001-platform-scope-and-phase-boundary.md
docs/adr/0002-conditional-rust-core.md
docs/adr/0003-local-modular-control-plane.md
docs/adr/0004-vm-boundary-for-untrusted-execution.md
docs/adr/0005-capability-scoped-process-adapters.md
docs/adr/0006-evidence-and-independent-verification.md
docs/adr/0007-open-source-and-integration-licensing.md
docs/adr/README.md
docs/phase1/CORE_ENGINE_DESIGN.md
docs/phase1/INCREMENT_5_2_1_SECURITY_REVIEW.md
docs/phase1/INCREMENT_5_3_1_SECURITY_REVIEW.md
docs/phase1/INCREMENT_5_3_2_REGRESSION_REVIEW.md
docs/phase1/INCREMENT_5_3_WORKSPACE_VALIDATION.md
docs/phase1/INCREMENT_5_4_1_DEPENDENCY_AUDIT.md
docs/phase1/INCREMENT_5_4_1_PERSISTENCE_DESIGN.md
docs/phase1/INCREMENT_5_4_2_1_SECURITY_REVIEW.md
docs/phase1/INCREMENT_5_4_2_SQLITE_IMPLEMENTATION.md
docs/phase1/INCREMENT_5_4_3_1_INDEPENDENT_REVIEW.md
docs/phase1/INCREMENT_5_4_3_PERSISTENCE_REMEDIATION.md
docs/phase1/INCREMENT_5_5_1_INDEPENDENT_REVIEW.md
docs/phase1/INCREMENT_5_5_EXECUTION_EVIDENCE_FOUNDATION.md
docs/phase1/INCREMENT_5_6_1_INDEPENDENT_REVIEW.md
docs/phase1/INCREMENT_5_6_2_1_INDEPENDENT_REVIEW.md
docs/phase1/INCREMENT_5_6_2_2_1_INDEPENDENT_REVIEW.md
docs/phase1/INCREMENT_5_6_2_2_2_1_INDEPENDENT_REVIEW.md
docs/phase1/INCREMENT_5_6_2_2_2_POLICY_AND_VALIDATOR_HARDENING.md
docs/phase1/INCREMENT_5_6_2_2_SECURITY_REMEDIATION.md
docs/phase1/INCREMENT_5_6_2_CORE_SERVICE_SECURITY_HARDENING.md
docs/phase1/INCREMENT_5_6_CORE_SERVICE_INTEGRATION.md
docs/phase1/INCREMENT_6_1_1_INDEPENDENT_REVIEW.md
docs/phase1/INCREMENT_6_1_2_STORAGE_SEMANTICS_DOCUMENTATION.md
docs/phase1/INCREMENT_6_1_LOCAL_CLI_FOUNDATION.md
docs/phase1/MILESTONE_4_REVIEW.md
docs/phase1/PROVIDER_VALIDATION.md
docs/phase1/README.md
docs/phase1/SANDBOX_VALIDATION.md
docs/phase1/SQLITE_VALIDATION.md
docs/research/ENVIRONMENT.md
docs/research/ISOLATION.md
docs/research/LANDSCAPE.md
docs/research/README.md
docs/research/SOURCES.md
docs/research/TECHNOLOGY.md
docs/research/TOOLING.md
experiments/phase1/authorization/Validate-Portability.ps1
experiments/phase1/authorization/Validate.ps1
experiments/phase1/authorization/results/1793904491573.json
experiments/phase1/authorization/results/1793904967368.json
experiments/phase1/authorization/results/1793905912132.json
experiments/phase1/authorization/results/1793909993262.json
experiments/phase1/authorization/results/1793910842702.json
experiments/phase1/authorization/results/1793911513511.json
experiments/phase1/authorization/results/1793912983333.json
experiments/phase1/authorization/results/1793913807036.json
experiments/phase1/authorization/results/1793915090242.json
experiments/phase1/authorization/results/1793915954066.json
experiments/phase1/authorization/results/1793917853611.json
experiments/phase1/authorization/results/1793920732438.json
experiments/phase1/authorization/results/1793934396429.json
experiments/phase1/authorization/results/1793937519010.json
experiments/phase1/authorization/results/1793970054692.json
experiments/phase1/authorization/results/1793970150200.json
experiments/phase1/authorization/results/1793972704601.json
experiments/phase1/authorization/results/1793972729182.json
experiments/phase1/authorization/results/1793972833671.json
experiments/phase1/authorization/results/1793972927885.json
experiments/phase1/authorization/results/1793973049614.json
experiments/phase1/authorization/results/1793973064148.json
experiments/phase1/authorization/results/1793973208064.json
experiments/phase1/authorization/results/1793973303912.json
experiments/phase1/authorization/results/1793974647335.json
experiments/phase1/authorization/results/1793974739056.json
experiments/phase1/authorization/results/1793974755118.json
experiments/phase1/authorization/results/1793974866323.json
experiments/phase1/authorization/results/1793974990153.json
experiments/phase1/authorization/results/1793976386599.json
experiments/phase1/authorization/results/1794006072312.json
experiments/phase1/authorization/results/portability-1793972704246.json
experiments/phase1/authorization/results/portability-1793973049250.json
experiments/phase1/authorization/results/portability-1793974738716.json
experiments/phase1/cli/Validate.ps1
experiments/phase1/cli/results/61-1793976246791.json
experiments/phase1/cli/results/61-1794006195662.json
experiments/phase1/cli/results/61-baseline-tests.txt
experiments/phase1/cli/results/61-documentation.json
experiments/phase1/cli/results/61-git-state.json
experiments/phase1/cli/results/612-1794006630618.json
experiments/phase1/cli/results/612-documentation-and-git.json
experiments/phase1/core-review/Validate-5.6.2.1.ps1
experiments/phase1/core-review/Validate-5.6.2.2.1.ps1
experiments/phase1/core-review/Validate-5.6.2.2.2.ps1
experiments/phase1/core-review/Validate-5.6.2.2.ps1
experiments/phase1/core-review/archive/5.6.2.1-tests.rs
experiments/phase1/core-review/results/5621-1793933555806.json
experiments/phase1/core-review/results/5621-1793933908453.json
experiments/phase1/core-review/results/5621-1793934123762.json
experiments/phase1/core-review/results/5621-1793934349382.json
experiments/phase1/core-review/results/5621-1793935908716.json
experiments/phase1/core-review/results/5621-directory-repeats.json
experiments/phase1/core-review/results/5621-final-review.json
experiments/phase1/core-review/results/5622-1793937306858.json
experiments/phase1/core-review/results/5622-1793937445312.json
experiments/phase1/core-review/results/5622-1793969307294.json
experiments/phase1/core-review/results/5622-directory-before-1793936612686.json
experiments/phase1/core-review/results/5622-directory-before-exact-1793936626701.json
experiments/phase1/core-review/results/5622-repository-and-documentation.json
experiments/phase1/core-review/results/562221-1793969850340.json
experiments/phase1/core-review/results/562221-alias-prerequisite.json
experiments/phase1/core-review/results/562221-final-review.json
experiments/phase1/core-review/results/562222-1793972364213.json
experiments/phase1/core-review/results/562222-1793972560127.json
experiments/phase1/core-review/results/562222-1793972581360.json
experiments/phase1/core-review/results/562222-1793973059467.json
experiments/phase1/core-review/results/562222-final-state.json
experiments/phase1/persistence/Validate.ps1
experiments/phase1/persistence/results/1793909666845.json
experiments/phase1/persistence/results/1793909947975.json
experiments/phase1/persistence/results/1793910614344.json
experiments/phase1/persistence/results/1793910739083.json
experiments/phase1/persistence/results/1793911046516.json
experiments/phase1/persistence/results/1793911483704.json
experiments/phase1/persistence/results/1793912954373.json
experiments/phase1/persistence/results/1793913781090.json
experiments/phase1/persistence/results/1793915068292.json
experiments/phase1/persistence/results/1793915934957.json
experiments/phase1/persistence/results/1793917829758.json
experiments/phase1/persistence/results/1793920705809.json
experiments/phase1/persistence/results/1793934396412.json
experiments/phase1/persistence/results/1793937462620.json
experiments/phase1/persistence/results/1793969910399.json
experiments/phase1/persistence/results/1793973166611.json
experiments/phase1/persistence/results/1793974621543.json
experiments/phase1/persistence/results/1793976346316.json
experiments/phase1/persistence/results/1794006044197.json
experiments/phase1/persistence/results/final-review.json
experiments/phase1/provider/.gitignore
experiments/phase1/provider/Cargo.lock
experiments/phase1/provider/Cargo.toml
experiments/phase1/provider/Validate.ps1
experiments/phase1/provider/results/1793890630373-442a6479.json
experiments/phase1/provider/results/1793891274912-7d40439b.json
experiments/phase1/provider/src/contract.rs
experiments/phase1/provider/src/gateway.rs
experiments/phase1/provider/src/lib.rs
experiments/phase1/provider/src/mock.rs
experiments/phase1/provider/tests/contract.rs
experiments/phase1/rust-msvc/.gitignore
experiments/phase1/rust-msvc/Cargo.lock
experiments/phase1/rust-msvc/Cargo.toml
experiments/phase1/rust-msvc/Validate.ps1
experiments/phase1/rust-msvc/results.json
experiments/phase1/rust-msvc/src/main.rs
experiments/phase1/sandbox/.gitignore
experiments/phase1/sandbox/Validate.ps1
experiments/phase1/sandbox/results.json
experiments/phase1/sqlite/.gitignore
experiments/phase1/sqlite/common.js
experiments/phase1/sqlite/quality-completion.json
experiments/phase1/sqlite/quality-results.json
experiments/phase1/sqlite/results/1793887687565-a3839418.json
experiments/phase1/sqlite/results/1793887887236-3f43b82e.json
experiments/phase1/sqlite/results/1793887997353-676ae9ce.json
experiments/phase1/sqlite/results/1793888306994-3852c6ae.json
experiments/phase1/sqlite/results/1793888372059-15a304dd.json
experiments/phase1/sqlite/validate.js
experiments/phase1/sqlite/worker.js
experiments/phase1/workspace/PolicyContextProbe.rs
experiments/phase1/workspace/Validate.ps1
experiments/phase1/workspace/results/1793901859226.json
experiments/phase1/workspace/results/1793902182023.json
experiments/phase1/workspace/results/1793902387953.json
experiments/phase1/workspace/results/1793905937841.json
experiments/phase1/workspace/results/1793909993262.json
experiments/phase1/workspace/results/1793910842720.json
experiments/phase1/workspace/results/1793911531040.json
experiments/phase1/workspace/results/1793913010755.json
experiments/phase1/workspace/results/1793913824042.json
experiments/phase1/workspace/results/1793915977600.json
experiments/phase1/workspace/results/1793917870983.json
experiments/phase1/workspace/results/1793920760476.json
experiments/phase1/workspace/results/1793934396430.json
experiments/phase1/workspace/results/1793937519018.json
experiments/phase1/workspace/results/1793970054698.json
experiments/phase1/workspace/results/1793973372051.json
experiments/phase1/workspace/results/1793974675798.json
experiments/phase1/workspace/results/1793976509800.json
experiments/phase1/workspace/results/1794006115809.json
experiments/phase1/workspace/results/policy-context.json
```


