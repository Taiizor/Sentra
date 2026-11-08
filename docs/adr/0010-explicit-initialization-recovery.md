# ADR-0010: Explicit Operator Recovery for Incomplete Initialization

- Status: **Accepted** (Approach B Validated in Phase 1 Increment 2.4)
- Date: 2026-11-07
- Decision owners: Project owner, Core lifecycle, Windows platform and security
- Related: F-611-02, OQ-25, Proposed ADR-0008/0009

## Context

CLI initialization creates the destination database directly. A process can die during DDL, after schema completion/before session creation, after Created/before Scoped, or after Scoped commit/before reply. Existing commands fail closed for corrupt/incomplete storage; they do not implement recovery. Domain-state read-only status/inspection can still open SQLite read-write, recover/checkpoint WAL and change lock/coordination metadata.

The [6.1.1 review](../phase1/INCREMENT_6_1_1_INDEPENDENT_REVIEW.md), [6.1.2 clarification](../phase1/INCREMENT_6_1_2_STORAGE_SEMANTICS_DOCUMENTATION.md) and [gap analysis](../phase1/PHASE1_GAP_ANALYSIS.md) require an accepted design, implementation and verification **before Phase 2 production readiness**. Neither alternative is currently accepted. Historical mentions of manual deletion describe impact, not authorized recovery instructions.

## Decision drivers

- Preserve original DB/WAL/SHM/journal and existing identity without automatic reset/delete/replacement.
- Distinguish valid interrupted sessions from unowned, corrupt and identity-less initialization.
- Maintain explicit authorization, exclusive ownership, current context and conservative grants/budgets.
- Minimize unproven Windows publication behavior while retaining a future atomic-staging option.
- Keep the single-foundation-session model; incomplete initialization is not a reason to add sessions or redefine ProjectId.

## Considered alternatives

1. **A — Atomic staging:** create a temporary same-filesystem store, complete schema and initial Scoped session, validate/checkpoint/flush/close, then publish atomically without replacing an existing destination. Requires sidecar/publication/identity/durability/collision proof and reconciliation of abandoned staging.
2. **B — Explicit operator recovery:** keep current fail-closed detection; add a separately authorized diagnose/preserve/plan/apply protocol for proven recoverable states. Unknown or corrupt data can remain blocked.
3. Automatically delete/recreate or adopt existing files: rejected; destroys recovery data or fabricates identity/authorization.

## Proposed decision

Prefer B for initial remediation, **subject to acceptance and prerequisites**. It avoids making safe multi-file/no-replace publication a hidden assumption of bootstrap completion and gives explicit, auditable state-specific decisions. It has higher operator cost and intentionally cannot recover every file. It does not remove ADR-0009's safe filesystem requirements or itself resolve F-611-02.

Before mutation, acquire exclusive cooperating-controller ownership; prove quiescence, stable path/object identity and the complete present recovery family, including absence records for missing sidecars/control metadata. Preserve a consistent recovery set **before** opening the original in a way that could apply WAL/checkpoint it. A simple copy while writers are active is not sufficient. Partial preservation, collision, unknown ownership or inconsistent sidecars stops without deleting the source.

Create a bounded immutable recovery plan bound to family identity, preserved evidence, session/epoch and exact action. The existing privileged authority plus explicit operator authorization approves it; a caller-controlled flag or database ID is not a grant or human authentication. Revalidate immediately before applying only approved Core lifecycle changes in one managed transaction/audit. Original pre-recovery evidence stays preserved; direct raw SQL or filesystem replacement is not a recovery shortcut.

| State | Proposed disposition |
| --- | --- |
| Unowned/version-zero/corrupt/partial schema | Preserve and block if provenance/consistency cannot be proved; no automatic repair/recreate. |
| Schema with no session | Diagnose incomplete. No identity can be invented as continuation; any explicitly authorized initialization at a different unused path is a separate new operation. |
| Single Created session | If full identity/input/policy/provenance is verifiable, propose explicit same-session lifecycle completion; otherwise block. No permissive legacy defaults. |
| Scoped already committed, reply lost | Rediscover the same identity; do not create a second session or consume new approval. Subordinate incomplete work follows its own recovery contract. |

Repeated approved recovery is idempotent. Application failure leaves original evidence and conservative state intact; typed primary/secondary failures remain visible without sensitive diagnostics. Restore/working-copy activation needs ADR-0008's retired old controller, fresh activation and uncertainty handling; an analyzed copy is not an automatically live clone.

## Security implications

No automatic data deletion, grant reuse, classification downgrade, identity uplift, target execution or relaxed path boundary. Recovery authorization is at least as strict as normal lifecycle authority; no claim of real human identity authentication. Foreign/multiple-session stores remain rejected. Ownership, source integrity or quiescence uncertainty stops recovery.

Preservation may require safe working-copy access and verified flush/close behavior under ADR-0009. Current status commands are not physically read-only acquisition tools. Several independent file renames do not create an atomic recovery set. No power-loss guarantee is inferred from FULL/sync_all.

## Compatibility implications

Retain current SessionId/project alias and all recorded budgets/grants/audits. Legacy missing immutable bindings are blocked until explicitly proven/rebound under ADR-0008/0009. Exact recovery-plan records/migration/API/CLI commands require separate design review and implementation authorization. No current schema or exit code changes here.

F-611-02 stays Open before Phase 2 production readiness. OQ-25 stays Open as the separate multi-session identity limitation. This proposal neither changes the original Phase 1 acceptance criteria nor approves Phase 1 closure.

## Operational consequences

Operators receive a typed state diagnosis and an explicit bounded plan or blocked result. There is no generic repair-everything/delete command. Read-write storage permission and safe preservation capacity may be necessary; preserve originals if insufficient. Atomic staging A remains a possible future improvement, with its own no-replace publication and sidecar/flush/abandoned-stage evidence obligations.

The detailed comparison and crash matrix are in [architecture section 9](../phase1/REMEDIATION_ARCHITECTURE.md#9-f-611-02-initialization-recovery-decision). Source preservation and approved logical SQLite changes are distinct: a pre-recovery evidence copy is retained before any authorized in-place domain mutation.

## Required verification evidence

- Real owned process termination at all four bootstrap windows and before/after preservation, plan approval, recovery commit and acknowledgement; repeat recovery twice with same identity/disposition and no duplicate audits.
- Stable full-family preservation; WAL/SHM/journal presence/absence, filename collisions, existing-file protection, busy writers, denied permissions, reparse swaps, partial preservation, checkpoint and rollback failure.
- No implicit adoption of version-zero/foreign/identity-less/corrupt/multi-session state; valid Created completion retains original authority/budget/grants, while unavailable input proof blocks.
- Concurrent initialize/recover/resume yields one owner, current fence and no second session; stale plans and changed source family fail closed.
- Typed confidential errors, clean existing inspection behavior and all current Core/CLI regressions.
- Independent Windows storage/lifecycle/security review. All these are planned, not executed in this design increment.

## Unresolved questions

- Owner acceptance of B versus A or a justified combination.
- Safe quiescent recovery-set acquisition and source identity verification under the current no-unsafe/no-new-dependency constraints.
- Exact proof required to complete a legacy Created session without fabricating immutable input identity.
- Recovery-plan persistence/authorization surface, retention policy and explicit command scope.
- Restore activation/preservation capacity and supported filesystem flush guarantees; no implementation proceeds without their resolution.

## Increment 0.2 contract refinement — Proposed

The [operator recovery contract](../phase1/IMPLEMENTATION_CONTRACTS.md#5-explicit-operator-recovery-contract--f-611-02) specifies diagnosis/plan/apply, the exact same-session CompleteFoundationInitialization action, existing-broker consent with atomic SQL consumption/lifecycle/audit, receipt-based idempotency and conservative legacy/corrupt refusal. The command surface and broker extension are proposals only; no recovery API exists by this reference. A changed source cannot execute a stale plan; only a verified committed receipt permits an AlreadyApplied lookup. The [readiness plan](../phase1/IMPLEMENTATION_READINESS.md) retains acceptance, preservation and crash-test gates. F-611-02 remains Open and status remains **Proposed**.
