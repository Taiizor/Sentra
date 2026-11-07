# ADR-0008: Recoverable Local Operations and Fenced Session Continuation

- Status: **Proposed**
- Date: 2026-11-07
- Decision owners: Core architecture, persistence and security, with project-owner acceptance
- Extends: ADR-0003 and ADR-0006; does not supersede accepted security boundaries

## Context

The original ROADMAP Phase 1 requires persisted session continuation and interruption recovery at dispatch, blob promotion and result commit without lost committed events or repeated sensitive effects. The [gap analysis](../phase1/PHASE1_GAP_ANALYSIS.md) identifies missing durable input/task/dispatch/result records. Current preparation atomically consumes approval/reserves budget, but ExecutionId and the backend request follow that commit; results are transient. SQLite atomicity alone cannot resolve the external-effect window.

This design-only proposal supports PG-00/DG-1/DG-2. Phase 1 remains NOT APPROVED. Exact records, schema versions, public APIs and implementation remain unauthorized; [REMEDIATION_ARCHITECTURE](../phase1/REMEDIATION_ARCHITECTURE.md) is the detailed proposed contract. Single-foundation-session/project identity is retained; OQ-25 stays open.

## Decision drivers

- Preserve trusted context ownership, immutable effective policy, exact approval binding/single use and same-session budget/audit atomicity.
- Resume the same session without treating old grants, a database ID or an absent result as permission to execute.
- Separate database idempotency, delivery, execution and reconciliation guarantees.
- Preserve uncertainty and conservative usage; avoid a workflow-service rewrite or a second authorization mechanism.
- Reject stale processes, incompatible writers and rollback/restore ambiguity without claiming distributed anti-rollback protection.

## Considered alternatives

1. Reconstruct work from reservation/audit rows and automatically retry: rejected; no durable full request or proof of non-execution exists.
2. Add a mandatory distributed workflow system: disproportionate to the current local scope and does not itself solve source identity, authorization or backend exactly-once effects.
3. Add a bounded durable operation/attempt/result ledger to the existing Core/repository, with explicit continuation and reconciliation: proposed.
4. Persist intent and assume fencing guarantees exactly once: rejected; a command may already have affected the backend.

## Proposed decision

Adopt alternative 3 subject to the evidence below. Keep four lifecycles distinct: session continuation, dispatch, blob reconciliation under ADR-0009, and result/settlement. Core remains the sole authorization/application owner.

Persist a frozen operation/attempt specification before admission. Within **one** BEGIN IMMEDIATE transaction, validate eligible session plus policy/context/epoch/input/action/target/classification, validate optional grant and same-session budget, reserve, consume, persist dispatch intent and insert all audits. Authorized/Reserved are in-transaction stages, not independently committed states. Conditional release intent commits before a private Core capability invokes the backend. Started requires a correlated receiver acknowledgement. Known terminal results, references, settlement and audits share one transaction; files/backend calls never enter retry closures.

After release intent, a missing outcome means Uncertain. No automatic replay, refund or grant revival follows. Recovered is an orthogonal disposition retaining the original outcome. Same-attempt at-least-once envelope delivery requires a tested deduplicating, fenced, queryable receiver; otherwise automatic redelivery is disabled. Non-start proof must also seal out late execution. No exactly-once external-effect claim is made.

One trusted mutating controller owns the protected store activation/epoch under a cooperating OS ownership guard and conditional SQL. Per-session admission guards exclude context changes through release/invocation. All mutations compare the current activation, recovery epoch, context generation and policy identity/generation. Genuine effective policy activation changes policy and context generation; equivalent policy is a no-op. Explicit resume/owner handoff changes recovery epoch and context generation, preserving SessionId. Callers cannot select generations or budget owners. Scoped, Planned and Running alone are execution-eligible; Paused/Waiting/Created/terminal remain denied.

Recovery records original issued bindings separately from current recovery authority: admitting a historical receipt cannot authorize a new execution. A duplicate terminal receipt is idempotent; a conflict is preserved/denied. Unknown usage retains the existing full typed hold. Existing `CancellationReport::uncertain`/settlement representation cannot be interpreted alone as termination proof; the durable outcome requires correlated phase/provenance.

Restore/clone activation requires an explicit fresh activation identity, verified retirement of the prior active store/controller, original lineage and conservative treatment of inherited unsettled work. A backup's pre-release state does not prove the original never executed later. If this cannot be established, block activation. Fencing is not global anti-rollback or process termination.

## Security implications

No approval scope broadening, expiry-clock bypass, implicit operator authentication or second PolicyEngine is introduced. Canonical action identifiers remain non-cryptographic; new immutable content binding depends on ADR-0009. Recovery must enforce classification, current access and original issued provenance at least as strictly as normal execution. Missing ownership, context, producer or outcome proof fails closed.

Locks coordinate cooperating processes; they do not defend against a compromised storage administrator. Backend-side fencing is a separate requirement and cannot be inferred from a successful SQLite transaction. All untrusted execution remains disabled; no host/Docker/WSL2 fallback or real VM/provider integration is proposed.

## Compatibility implications

Versioned schema evolution is necessary but not defined as DDL here. Preserve v1 history, terminal sessions, audits, consumed grants and conservative holds. Legacy snapshots lacking new bindings remain LegacyUnbound for execution; do not synthesize a current policy generation/input digest or upgrade old approvals permissively.

Reject unknown/newer schemas and incompatible writers. **Already-open legacy writers require proven quiescence/retirement**; changing user_version cannot fence them. Migration metadata and DDL are transactional. No destructive migration/down-migration/reset is proposed. Backup rollback requires explicit activation/reconciliation, not replacing a live database or resetting counters.

## Operational consequences

Explicit continuation and scoped recovery may block on uncertainty, trading automatic liveness for security. Diagnostics/decision replay do not resume execution. A live lock is not stolen on TTL/PID alone. Exact duplicate requests/results return prior records without duplicate audits or refunds. Failed SQLite operations retry the complete pure database transaction with fresh reads under the existing bound; external effects are excluded.

Protected store ownership, activation/ID allocation, migration preservation and backend capabilities require separately verified contracts. No schema or current CLI behavior changes with this proposal. F-611-02 follows ADR-0010, not automatic session continuation.

## Required verification evidence

- Independent security review of full binding and lifecycle exclusion from authorization through release, including no-approval operations, policy changes and competing contexts/processes.
- Real controlled process termination before/after admission, release, invocation, start/result receipt, result/ref/settlement/audit commit and response; restart/reconcile twice with no duplicate controlled effect or acknowledged-event loss.
- Same-session atomicity under grant mismatch, exhaustion, audit/transition faults, BUSY_SNAPSHOT fresh reads, replay, overflow and competing reservations/consumers.
- Populated legacy migration, incompatible/already-open old-writer handling, identity/policy/context compatibility, restore/clone uncertainty, FK/integrity/sequence invariants and preservation tests.
- Same-session two-task continuation and effect-free decision replay; typed primary/secondary errors, confidential diagnostics and uncertainty holds preserved.
- All detailed S/D/R/A0 cases in [the architecture](../phase1/REMEDIATION_ARCHITECTURE.md#15-required-acceptance-and-crash-recovery-evidence). No such tests were run in this design increment.

## Unresolved questions

- Exact table/constraint/migration versions and API shapes; how quiescence is established for every older controller before upgrade.
- Approved ID/activation source and safe restore lineage; how a former active backend is definitively retired.
- Purpose-scoped historical receipt reconciliation that preserves current classification without granting execution under stale context.
- Supported receiver deduplication/query/non-start-sealing capabilities; real worker transport remains unimplemented.
- DG-6 mock-only provider seam acceptance and exact bounded task/output/storage enforcement points.

Acceptance requires owner/architecture/security approval and explicit disposition of these gates; documentation alone closes no Phase 1 implementation criterion.

## Increment 0.2 contract refinement — Proposed

The [implementation contracts](../phase1/IMPLEMENTATION_CONTRACTS.md#3-sqlite-writer-fencing-and-migration-contract) recommend connection-lifetime admission/drain, immutable tokens and persistent all-table DML guards as a concrete candidate for proving that supported old connections cannot commit after migration, including after migrator death. This is not an implemented fence or a claim that legacy clients obey new locks. Logical retirement requires the complete guard/legacy/cached-statement proof; physical quiescence remains necessary for raw recovery-family capture and unsupported writers. Until independently proved and explicitly accepted, existing-store upgrades remain blocked. Optional rusqlite feature/backup topology approval and the [readiness gates](../phase1/IMPLEMENTATION_READINESS.md) are separate prerequisites. Status remains **Proposed**.
