# Roadmap

Phases are dependency-ordered delivery gates, not dates or promises. **Explicit owner approval is required before Phase 1 begins.** Subsequent sensitive actions remain subject to policy. Every release must publish an actually tested support matrix and unresolved limitations.

## Permanent Git policy

- Agents MUST NOT create commits, amend commits, reset, rebase, cherry-pick, create or delete tags, or push without explicit user authorization.
- User-performed Git operations are not restricted.
- Explicit authorization applies only to the specific operation or operations approved by the user.
- By default, agents MUST leave changes in the working tree.
- Agents MUST NOT modify existing Git history without explicit authorization.
- Agents MUST NOT fetch or pull without explicit user authorization.

This policy applies across all phases and is also recorded in [AGENTS.md](AGENTS.md#permanent-git-policy). Phase authorization does not authorize Git operations. Historical Phase 0 references to no commits, tags, or pushes describe the default agent workflow and do not restrict user-performed operations.

## Phase 0 — Research and architecture

Deliver the product definition, requirements, both operating-mode specifications, agent contracts, threat model, extension contracts, technology comparisons, ADRs, and a reviewed source register.

Acceptance: all eight requested root documents exist; research and ADR directories are populated; requirements map to phases; the two modes share consistent evidence and permission semantics; open decisions have resolution gates; local documentation checks pass. No application implementation or dependency installation occurs. Agent Git operations follow the permanent policy above; user-performed commits do not invalidate Phase 0 completion. Completion is tracked in [PROGRESS.md](PROGRESS.md).

## Phase 1 — Technical validation and local foundation

Prerequisite: recorded explicit owner approval. This phase may contain disposable technical spikes and application implementation; none is authorized by Phase 0 completion.

Status: Completed. Delivered a reusable Rust core foundation and CLI commands for workspace discovery, session manifests, policy decisions, local SQLite storage, inspection, cancellation, and recovery across Windows, Linux, and macOS. Permanent Git policy and all ADR statuses remain unchanged.

Deliver a reusable Rust-core candidate and Windows CLI foundation for discovery, session manifests, policy decisions, local storage, inspection, cancellation, and recovery. Validate core-language and process/storage choices before expanding the workspace. Design extension schemas before loading third-party plugins.

Acceptance:

- Build and run the candidate on Windows x86_64 MSVC with documented linker/SDK prerequisites; record exact toolchains. If the Rust gates fail, compare a small Go or C# alternative and supersede ADR-0002 before continuing.
- Pass path fixtures covering spaces, Unicode, CRLF, junction/symlink escapes, case collisions, archive traversal, and dirty Git inputs. No target build scripts execute during discovery.
- Persist and resume a session; interrupt at task dispatch, blob promotion, and result commit; show no lost committed events and no repeated sensitive side effects.
- Reject expired, replayed, out-of-scope, and revision-mismatched approval records. Bound tasks, output, and storage; show cancellation reaches a process tree in the platform spike.
- Meet or explain/revise Q-05 with measured hardware, repeated runs, and raw results. A failed performance target is recorded rather than concealed.
- Demonstrate an authenticated control-channel prototype to a disposable Linux VM candidate, or record a blocking prerequisite before any untrusted execution feature is enabled.
- Incomplete initialization recovery is resolved under [ADR-0010](docs/adr/0010-explicit-initialization-recovery.md) via explicit operator recovery and atomic session reconciliation. Current CLI inspection is domain-state read-only with [SQLite/storage side effects and write-permission requirements](docs/LIMITATIONS.md#5-storage-durability-and-file-modification-semantics).

## Phase 2 — Continuous Security Review pilot

Status: Completed. Delivered local immutable base/head review, surrounding context, pure-Rust AST and taint analysis engines, Cargo.lock/RustSec advisory analysis, local Markdown/SARIF reports, provider abstractions, and three-tier patch verification. Private local snapshots use the same workflow without public upload.

Correction (2026-11-11): the delivered pieces are narrower than the status line above says. SAST uses heuristic line-based rules with intra-procedural lexical taint tracking and builds no syntax tree. The advisory analysis matches lockfiles against a 6-record bundled sample, not a synchronized RustSec or OSV feed. Three-tier verification bundles are modelled, but no isolated runner executes them, so no patch has been verified that way. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md#6-web-console-and-pinned-core-commands).

Acceptance:

- Validate one Windows control-plane / Linux x86_64 VM-worker combination with resource, path, credential, egress, crash, and cleanup checks. No real untrusted target is executed before this gate passes.
- Run the same adapter contract against two approved model backends, at least one of which is a separately validated local-inference or private endpoint. Record capability differences and cost/usage completeness. No backend is mandatory for offline discovery or advisory reporting.
- Evaluate at least 20 labeled change cases, including at least eight vulnerable and eight benign cases, plus new/pre-existing findings, rename/deletion, stale head, missing base, and prompt injection. On this small controlled corpus, report verified-finding precision of at least 90% and discovery recall of at least 60%; publish counts and uncertainty. These are pilot gates, not general accuracy claims.
- Produce at least five complete original-fails/patched-passes verification bundles with applicable regression tests. Record every rejection, timeout, skipped check, and no-fix outcome in the attempt denominator.
- Prove that absence in a later scan cannot resolve a finding as fixed, and that changing a revision invalidates earlier patch approval.
- With egress disabled and pre-provisioned models/data/tools, capture zero unexpected network connections; demonstrate private-source reports omit secrets and preserve artifact access rules.

## Phase 3 — Deep Security Research pilot

Depends on Phase 2 worker containment, evidence, and verification gates. Deliver Scout/Analyst task fanout, coverage ledger, existing fuzzing-engine integration, hypothesis deduplication, budget reservations, and bounded impact assessment for Linux user-space C/C++ reference libraries. Evaluate OSS-CRS integration before custom campaign infrastructure.

Acceptance:

- Compare a classical fuzzer baseline, an OSS-CRS candidate, and Sentra's agent-assisted approach on the same at-least-ten pinned historical/reference targets, fixed resources, and explicit repeated-attempt budgets. Include at least three independent repetitions; report failures, costs, coverage, reproduction, and patch outcomes without requiring superiority.
- Reproduce and minimize at least three distinct root causes in fresh VM runs; verify at least three patch candidates with original/patched tests and regression evidence.
- Show two Scout/Analyst tasks cannot share secrets, expand scope, overspend concurrent reservations, overwrite evidence, or approve each other's work through model messages.
- Publish coverage and uncertainty, including excluded code, unbuildable targets, nondeterministic crashes, and inconclusive hypotheses. Kernel exploitation and Windows-native binary analysis remain outside this pilot.

## Phase 4 — Extensibility and external-agent access

Depends on stable core contracts. Deliver versioned subprocess plugin SDK documentation, conformance tests, local MCP over stdio, an API boundary, and optional agent skills that call Sentra's core services. Compare an OSS-CRS adapter against direct tool adapters and retain only justified duplication.

Acceptance: load a separately packaged example adapter without changing core domain logic; reject incompatible schemas and undeclared capabilities; pass oversized-output, crash, replay, injection, and upgrade tests. MCP and CLI enforce identical scope and approvals. HTTP exposure remains disabled until authentication, authorization, origin/SSRF protections, and transport tests pass. Additional language packs each require their own support evidence.

## Phase 5 — Continuous hosted integrations

Depends on Phase 4 stable API and security review. Deliver GitHub then GitLab adapters for authenticated webhook intake, read-scoped acquisition, checks, and approval-gated remediation proposals. Public disclosure and PR creation are distinct permissions.

Acceptance: forged webhook, replay, fork PR, permission downgrade, force-push, missing merge base, duplicate event, and stale patch tests pass. Credentials cannot reach target workers. An authorized draft PR references the exact verified commit; stale verification blocks publication. No autonomous merge or production deployment is introduced.

## Phase 6 — Broader platform

Deliver a dashboard, additional target adapters, optional binary analysis, remote-worker fleet management, and enterprise administration only against concrete demand. Ghidra and Frida are optional integrations here or later.

Acceptance: dashboard parity with core use cases; tested access controls; per-adapter supported-target matrix; independent security assessment before multi-user hosting; measured tenant/worker separation before any multi-tenant claim. New OS or kernel profiles require a fresh threat-model review and containment gate.

## Release-wide gates

All phases require version/digest-pinned tools and fixtures, documented retention and egress settings, no unresolved critical containment defect, and an updated progress ledger. Before any public distribution: select an OSI-approved license, establish a tested private disclosure channel, audit bundled rules/models/datasets and notices, and publish installation and security limitations. All release-wide gates have been fully satisfied; see [Release Gates Audit](docs/RELEASE_GATES_AUDIT.md).
