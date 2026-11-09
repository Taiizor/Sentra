# Increment 6.1.2 — CLI Storage Semantics Documentation & Crash Recovery Readiness

Date: 2026-11-07. Status: **Documentation increment complete; F-611-01 documentation condition addressed; F-611-02 architectural requirement open.** No production behavior, public API, schema, dependency or existing test changed. Phase 1 is incomplete. Phase 1 final verification, Increment 6.2 and Phase 2 have not started.

## Scope, inspection and changed documents

This increment follows the preserved [6.1.1 independent review](INCREMENT_6_1_1_INDEPENDENT_REVIEW.md), whose decision remains historically **Approved with Conditions**. It clarifies the [6.1 implementation report](INCREMENT_6_1_LOCAL_CLI_FOUNDATION.md) against the actual implementation, rather than treating review prose as proof of runtime behavior. The independent review and all previous raw evidence remain unchanged.

Inspected instructions, roadmap/progress, user-facing CLI documentation, architecture, open questions and all seven ADRs. Source inspection covered:

| Source | Relevant behavior |
| --- | --- |
| [CLI adapter](../../crates/sentra-cli/src/lib.rs) | `run` delegates to LocalWorkspace; `core_error` maps storage failures to exit 5, incomplete stores to 6, and invalid workspace/storage-parent paths to 4 |
| [LocalWorkspace](../../crates/sentra-core/src/service/local_workspace.rs) | `run` acquires admission before checking database presence, opens existing stores, rejects incomplete/ambiguous state and attempts shutdown before returning |
| [Connection manager](../../crates/sentra-core/src/persistence/connection.rs) | `local_context_admission`/`admission`, `open_existing`/`open_mode`, mandatory PRAGMAs and `shutdown` |
| [Repository](../../crates/sentra-core/src/persistence/repository.rs) | `local_session` requires exactly one ID and valid current snapshot; `budget_used` performs a managed read |
| [Transactions](../../crates/sentra-core/src/persistence/transaction.rs), [migration](../../crates/sentra-core/src/persistence/migration.rs) | `BEGIN IMMEDIATE`, explicit rollback and atomic schema/metadata migration; existing supported schema is validated, not recreated |
| [CoreService](../../crates/sentra-core/src/service/core.rs) | `create_session` commits registration separately from Created-to-Scoped transition |
| [Local lifecycle tests](../../crates/sentra-core/tests/local_workspace_tests.rs), [persistence tests](../../crates/sentra-core/tests/persistence_tests.rs) | Existing row-preservation, incomplete-state, blocked-checkpoint and real SQLite process-termination assertions |

Documentation changes:

- [README](../../README.md#inspection-storage-permissions): user-facing four-layer storage contract, writable-storage requirements, failure categories and preservation advice.
- [6.1 report](INCREMENT_6_1_LOCAL_CLI_FOUNDATION.md): dated documentation clarification and precise domain-state read-only terminology, without changing historical implementation/test results.
- [Architecture](../../ARCHITECTURE.md): actual storage side effects and the mandatory open readiness requirement.
- [ROADMAP](../../ROADMAP.md): F-611-02 / OQ-25 as an unresolved pre-Phase-2 production-readiness gate, not deferred solely until multi-session support.
- [Open questions](../OPEN_QUESTIONS.md): accountable owner, required decision/evidence and current one-session identity limitation.
- [Phase 1 record](README.md), [PROGRESS](../../PROGRESS.md): current documentation status, historical-review separation and actual verification results.
- This report: crash windows, design-only alternatives, limitations and integrity evidence.

No new ADR or recovery design is accepted. ADR-0002 and ADR-0007 remain Proposed; the other five retain their existing Accepted status qualifiers. Existing F-14/Q-03/Q-04 recovery/schema requirements remain incomplete; this clarification does not waive or complete them.

## F-611-01: exact documentation resolution

`sentra status` and `sentra session show` are **domain-state read-only**, with **SQLite/storage side effects**. They are not physically read-only, do not offer a VFS read-only mode, and do not guarantee unchanged database file bytes.

| Layer | Source-backed current behavior | Meaning of read-only |
| --- | --- | --- |
| Domain-state immutability | Existing session/snapshot, approval, budget, audit and migration records are not changed by successful inspection of a supported store. No lifecycle transition, approval consumption or reservation is requested. | Domain-state read-only; not a claim about file contents/metadata |
| Logical SQL write behavior | Domain reads and supported-schema validation issue no domain INSERT/UPDATE/DELETE or persistent schema DDL against the existing store. Queries still run through managed `BEGIN IMMEDIATE`/commit transactions; connection initialization and verification PRAGMAs run. Migration validation also builds a separate in-memory DDL template. | Not a SELECT-only/read-only-connection contract; read transactions can obtain writer admission and contend |
| SQLite recovery/checkpoint side effects | `open_existing` uses `SQLITE_OPEN_READ_WRITE`, without CREATE. WAL recovery makes committed state available; recovery/checkpoint processing may apply pending committed WAL frames to the main database. Normal CLI shutdown explicitly attempts `PRAGMA wal_checkpoint(TRUNCATE)` before closing, copying eligible committed pages and truncating WAL on success. | Main DB/WAL bytes may change; checkpoint failure is reported, not silently successful |
| Filesystem and lock metadata effects | Admission opens/creates `<database>.local-context.lock` read-write, without truncating it, and takes an exclusive OS lock. SQLite may create/update `-shm` and other coordination files. Filesystem timestamps, directory entries and lock metadata may change, subject to OS behavior. | Storage-directory access can require writes; timestamps are not guaranteed unchanged or guaranteed to change |

The database and storage directory may need write permissions even for inspection. Read-only media, write-protected directories or insufficient access may cause **`storage_or_service_failure`, exit 5**. Earlier workspace/storage-parent validation can instead return exit 4; no universal permission-error exit-code promise is made. There is no automatic permission change, read-only fallback, repair or recreation. A busy reader can also prevent TRUNCATE and produce exit 5 despite unchanged domain records.

Admission precedes the presence check: a missing database can still leave a newly created `.local-context.lock`, followed by status exit 3 or session-show exit 7. Existing coordination/lock files must not be removed while other users/processes may hold them. Failures and uninitialized reports do not imply zero filesystem effects.

Terminology clarification for the historical review: committed WAL state can become visible before pages are checkpointed into the main database. Recovery does not commit uncommitted transactions; uncommitted work is discarded. The explicit CLI shutdown checkpoint is not a guarantee that every early error, abrupt process death or raw connection Drop executes a checkpoint. These distinctions preserve the review's findings without repeating broader physical-read-only or crash-durability claims.

**Disposition:** F-611-01's documentation condition is addressed in user-facing instructions and architecture/status records. The runtime write requirement and absence of a forensic/read-only-media inspection mode remain unchanged. This is not a new independent approval of production behavior.

## Incomplete initialization and current recovery behavior

Current `init` creates the database at its destination. Database-file creation, the atomic schema migration, the atomic session/snapshot/creation-audit registration and the subsequent atomic Scoped-transition/audit commit are separate boundaries. They do not form atomic staging or one bootstrap transaction.

The following describes source-inspected behavior and the crash states discussed by 6.1.1. **No new CLI crash experiment was performed in 6.1.2.** Results assume the original recovery set is preserved and accessible; integrity/path/permission/checkpoint errors can prevent a later success.

| Crash window | Possible surviving state | Current subsequent behavior |
| --- | --- | --- |
| A. Database creation or DDL interruption | Empty/version-zero destination, or an interrupted migration requiring SQLite recovery. DDL and migration metadata are transactional; a logically half-committed schema is not assumed. If the migration already committed, use window B. | `open_existing` refuses to initialize/adopt version-zero storage; integrity/schema/open failures surface as `storage_or_service_failure` (5). No silent re-creation. Physical partial/corrupt storage fails closed. |
| B. Schema completion before session creation | Valid supported schema, zero committed session rows | `local_session` observes zero IDs and returns ContextMismatch, mapped to `incomplete_storage` (6). It does not create a replacement session. |
| C. Session creation before transition to Scoped | Registration committed with state Created, snapshot and creation audit; scoping not committed | Created is explicitly rejected as `incomplete_storage` (6). It is not automatically advanced. An uncommitted registration falls back to B; an uncommitted Scoped transaction leaves C. |
| D. Successful Scoped transition before process termination | One valid committed Scoped session, potentially still in WAL before checkpoint | SQLite can read/recover the committed state. With matching workspace, valid storage and successful shutdown, repeated init returns the original identity with `initialized=true`, `created=false` (0). Status/matching session inspection can also succeed. Failed checkpoint/open/integrity still returns 5; success is not unconditional physical power-loss durability. |

Related categories: a genuinely absent DB with no recovery sidecars can be initialized; status returns uninitialized exit 3 and session show returns missing-session exit 7 without creating the DB, after admission. A missing DB with orphan `-wal`, `-shm` or `-journal` fails incomplete (6), preserving those files. A multi-session existing store also fails incomplete (6); an unrelated/corrupt/newer/inconsistent store remains a storage failure (5).

There is currently **no explicit operator recovery command** and no automatic resume, delete, replacement, overwrite or repair. Preserve the database together with WAL/SHM/journal recovery data and relevant ownership/audit context. Do not separate or discard recovery files, infer safe deletion from a coarse exit code, or treat the historical review's manual-deletion impact description as a cleanup instruction. This increment provides no deletion procedure. Even if an initiating command failed after Scoped committed (for example during checkpoint/output), that committed identity may already exist; another init must not replace it.

## Future recovery alternatives: design only

Neither option below is selected, implemented, tested as a new recovery workflow or authorized for implementation by this report. They must preserve workspace/policy boundaries, explicit approval, protected local storage, existing project identity and the complete SQLite recovery set.

| Dimension | A. Atomic staging | B. Explicit operator recovery |
| --- | --- | --- |
| Proposed lifecycle | Exclusively create a new temporary database in the **same filesystem**; finish schema and foundation session/scoping; validate schema, integrity, foreign keys and identity; successfully checkpoint, flush and close before publication. | Detect and classify incomplete initialization without adopting it; expose sufficient redacted diagnostic state; require explicit authorized operator action before a reviewed reconciliation/recovery step. |
| Publication/preservation | Select and validate an appropriate platform-specific atomic publish operation with **no replacement** of an existing destination. Prove existing-file protection against concurrent initialization and collisions. Atomic namespace publication alone is not power-loss durability. | Never automatically delete, replace or overwrite database files. Preserve the original DB and associated recovery files/evidence. Any future reconstruction, resume or separate-destination recovery must have an approved provenance/authorization design; unverifiable state remains denied. |
| WAL/SHM/coordination | Account for WAL/SHM/journal and admission locks. Publishing only `.db` while committed frames remain in staging WAL is unsafe. Several independent file renames are not one atomic transaction. Require successful proven checkpoint/closure or an approved consistent-set protocol. Do not guess that `-shm`/WAL can be discarded. | Preserve DB/WAL/SHM/journal as a recovery set and keep lock lifetimes consistent. Establish exclusive managed access/quiescence before recovery; do not unlink active admission files or assume SQLite atomicity establishes exclusive filesystem ownership. |
| Filesystem/security questions | Validate same-volume/no-follow paths, exclusive staging-name creation, safe flush/close semantics, crash durability and a publication primitive compatible with safe-code/dependency policy. No Windows rename API or new dependency is approved here. | Distinguish Created, schema-only, corruption and already-Scoped state; avoid exposing sensitive paths or accepting caller-supplied context as authority. Exact user command/API and permitted state changes remain undecided. |
| Failure/retry behavior | Failed validation/checkpoint/flush/close/publication must not report initialized or replace an existing project. Preserve staging evidence on ambiguous failure. Define how future invocations recognize and safely handle abandoned staging without automatic disposal. | Preserve state on interruption or failure; explicit recovery must be idempotent and auditable, with rollback and no accidental grant consumption, context downgrade, new identity or budget mutation. No retry-only-the-failed-step shortcut for unverified state. |
| Trade-off | Reduces partially initialized final destinations, but leaves staging-orphan recovery and platform publication/durability complexity. It does not eliminate all crash handling. | Avoids reliance on publishing a live multi-file SQLite store, but requires operator effort and a carefully specified recovery boundary. Current generic exit 5/6 is not that workflow. |

The options may be combined by a future approved design (for example staged creation plus explicit abandoned-stage recovery); that combination is also undecided. This assessment does not mandate a particular API, destructive clean/reset command, custom cryptography, dependency or unsafe FFI.

### F-611-02 readiness gate and decision owner

**F-611-02 remains open and mandatory before Phase 2 production readiness**, independently of when multi-session support is considered. It is now tracked consistently in architecture, roadmap and OQ-25.

Accountable owner: **Core/platform maintainer, with security review**. Required next decision/evidence, in a separately authorized increment:

1. Select and approve atomic staging, explicit operator recovery or a justified combination; document publication/reconciliation semantics and existing-file protection. Record any actual ADR change through its separate decision process.
2. Implement only that approved scope, preserving domain/authorization ownership and original DB/WAL/SHM/journal data; no automatic deletion or overwrite.
3. Run real process termination at file creation, schema commit, session registration, Scoped commit and checkpoint/publication/recovery boundaries. Test fresh/repeated/concurrent starts, collisions, busy readers, permissions/I/O failures where safely reproducible, orphan sidecars and recovery re-entry.
4. Demonstrate no misleading initialized state, lost committed identity/events, unauthorized context/budget/approval changes or replacement of an existing project. Separate process-crash evidence from untested physical power-loss/device guarantees and retain raw evidence.

A documented alternative is not sufficient to close this gate; implementation and reproducible evidence are still required. No implementation direction or Phase 2 authorization is requested or assumed here.

## OQ-25: project/session identity

The current CLI identifies a local project by the **single foundation session's SessionId**, not an independent project entity, path string or cryptographic identity. `local_session` reads at most two IDs and requires exactly one validated current snapshot. Existing zero/multiple-session stores fail closed; it does not choose a first session or silently add one. Multi-session CLI repositories are unsupported, even though lower-level Core APIs can store multiple sessions.

OQ-25 stays open for both the mandatory F-611-02 recovery gate and the independent future multi-session identity model/migration decision. No data-model change, separate project ID, new session API or multi-session support is introduced.

## Verification and evidence limits

The four required commands ran offline, exit 0, against unchanged production/test inputs:

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --offline
cargo clippy --workspace --all-targets --all-features --offline -- -D warnings
cargo test --workspace --offline
```

Raw verification evidence records exact commands, outputs, timings, environment, test names and pre/post non-Markdown fingerprints. Observed Windows x64/MSVC, PowerShell **7.6.9**, OS build `Microsoft Windows 10.0.26300`; no new platform claim. All four checks Passed; Clippy ran with warnings denied.

This run has **302 harness entries**: 295 runtime (290 passed, 5 ignored) plus 7 passed compile-fail doctests. There are **297 direct passes, 0 failed**. Two ignored entries are subprocess helpers invoked by parent tests; do not count them again. The three ignored junction/access-denied/10,000-file platform fixtures were **Not Tested separately in this increment**. Their prior 6.1/6.1.1 results remain historical; this task does not claim a new 300-case/platform-validation run. Specialized persistence/authorization/workspace/CLI validators were not rerun because this is documentation-only; their existing nonignored tests run in the full workspace suite.

Existing tests rerun include row-preserving init/status/session inspection, incomplete schema/Created fixtures, orphan sidecar preservation, reader-blocked checkpoint failure and real SQLite process-termination recovery (committed data retained, uncommitted data discarded). These assertions support bounded current behavior, not a tested future recovery mechanism. The local row-comparison helper enumerates the five domain tables; unchanged migration records are supported by the inspected existing-schema validation branch, not a newly executed six-table byte-comparison experiment. File/DDL crash-window behavior is source-inspected, not new CLI kill injection. Read-only-media/ACL side effects, all four CLI bootstrap kill points, atomic publish, flush/device/power-loss behavior and either future recovery option were **Not Tested as new experiments** here.

Documentation and Git evidence records changed-document local-link/heading checks, requirement references, ADR preservation, full tracked-file comparisons and Git fingerprints. No general Markdown renderer or live external-link verification is claimed; no network operation was performed.

## Git safety and remaining limitations

Entry: clean `develop`, HEAD `eb03cb500506f82b9980705ebf32d87c4b883344`, locally recorded upstream `origin/develop`, ahead/behind **0/0**, 277 tracked files, **0 staged / 0 modified / 0 untracked**. Physical index SHA-256 at entry: `6fe85227be130f9c5ff63ef0822460ec5431aa47418e2426cdc4abbfed72ce32`.

Final state: **7 modified, 3 untracked, 0 staged**, on the same `develop` HEAD and locally recorded upstream relationship (0 ahead / 0 behind). Exact path lists are in the linked integrity record. Branch, HEAD, all reference targets/history, index entries and physical index bytes match entry; all changes remain unstaged. Only the seven existing documentation files listed above, this new report and two new raw-evidence records are changed/added. Production code, APIs, schemas, manifests/lockfile/dependencies, test files, existing validators, accepted/proposed ADRs, historical reviews and prior evidence remain byte-identical to entry. No commit, staging, index rewrite/restore, branch/ref mutation, stash, fetch/pull/push, dependency download, network operation, untrusted target execution or host configuration change occurred.

Remaining limitations are unchanged: physical read-only inspection is unavailable; incomplete initialization has no implemented operator recovery or atomic staging; project identity is coupled to one session; strong filesystem identity/race-free containment, physical fault durability, external-effect recovery and real provider/VM execution remain unvalidated. Untrusted workloads remain fail-closed.

**Stop after Increment 6.1.2. Phase 1 final verification and Phase 2 are not started.**
