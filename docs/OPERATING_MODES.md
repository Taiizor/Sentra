# Operating Modes

Both modes use the same immutable input, authorization, budget, task, evidence, and patch contracts. They differ in selection strategy and scheduling. Read this document with [DATA_MODEL.md](DATA_MODEL.md) and [AGENT_MODEL.md](AGENT_MODEL.md).

## Continuous Security Review

### Inputs and scope

Required inputs: authorized project identity; immutable base and head revisions or equivalent content manifests; project root; inclusion/exclusion policy; allowed adapters/providers; execution/egress profile; authorization reference; and time, cost, and resource budgets.

The first implementation accepts local Git history. Later webhook integrations must authenticate events, resolve object IDs, and never trust an event-supplied repository URL or branch name alone. For a PR, record the selected merge base and head; for direct branch changes, record the explicit previous/head pair. Do not silently use an arbitrary recent commit when history is missing. Fetching additional private history requires acquisition authorization; otherwise report an incomplete review.

### Workflow

| Stage | Action | Required result / stop condition |
| --- | --- | --- |
| 1. Admit | Validate authorization, input digests, scope, adapters, and budgets | Session manifest or denied admission |
| 2. Discover | Inspect bounded manifests and roots; identify relevant technology boundaries | Capability matrix and unsupported regions |
| 3. Contextualize | Compute change ranges; map renamed/deleted files; retrieve relevant callers, callees, guards, config, and tests | Context references and documented retrieval limits |
| 4. Generate candidates | Run authorized static/advisory adapters and scoped Analyst tasks | Provenance-linked hypotheses; no automatic confirmation |
| 5. Attribute and deduplicate | Compare base/head evidence, cluster root causes, retain independent signals | New, pre-existing, changed-exposure, or unknown attribution |
| 6. Validate | Prepare an independent oracle; use static/advisory review or isolated reproduction appropriate to the finding class | Validated, rejected, or inconclusive result |
| 7. Assess | Record attacker prerequisites, trust boundary, observed impact, and uncertainties | Evidence-linked assessment; optional CVSS vector |
| 8. Propose remediation | Patch an isolated overlay only after the candidate meets its required validation criteria | Revision-bound patch candidate and test plan |
| 9. Verify | Independently check original failure, patched behavior, regressions, scope, and controls | Verified, failed, or inconclusive patch result |
| 10. Report | Export local Markdown/JSON; summarize gaps and budgets | Local report; external publication requires separate approval |

Contextual reachability is a hypothesis unless supported by a suitable call/dataflow model or runtime evidence. An issue in unchanged code reached by a new caller may be a changed-exposure finding. If only head was assessed, attribution remains unknown rather than claiming the change introduced it.

### Review budgets and latency

Use a bounded foreground review and optional explicitly budgeted follow-up tasks. If the foreground budget expires, publish a local partial report showing what was checked and what remains. Escalation into deep research requires a new or extended scope/budget decision. No fixed vendor-like latency is claimed before measurement.

Start with a source/advisory Rust pilot on a small fixture set. A missing language/tool adapter, unbuildable project, absent test oracle, or unavailable VM is a visible coverage gap. A review can complete as an execution workflow while retaining inconclusive findings and an incomplete assessment outcome.

### Persistence and later pushes

Fingerprint findings using project identity, root-cause evidence, canonical source/symbol references, rule/advisory identity where applicable, and weakness class. File path/line alone is insufficient across renames. Preserve uncertain matches instead of merging unrelated defects.

A new push creates a new input revision and analysis result. Prior evidence remains attached to its original revision. Do not mark a defect fixed because a scanner no longer emits it; remediation requires revision-specific verification or an explicitly recorded human disposition. Force-pushes and history rewrites do not erase audit events.

## Deep Security Research

### Inputs and scope

Required inputs: an authorized immutable codebase; permitted components and threat surfaces; attacker model; execution profiles; available build/harness instructions; provider/egress policy; and campaign budgets. Initial targets are Linux user-space C/C++ reference libraries with reproducible builds and existing or reviewed harnesses.

Campaigns do not imply authorization to probe production services, access neighboring repositories, download arbitrary dependencies, or research kernel exploitation. An inaccessible build prerequisite becomes a recorded blocker, not permission to bypass isolation.

### Workflow

| Stage | Responsibility | Required artifact |
| --- | --- | --- |
| 1. Baseline | Core discovers technologies and pins source/build inputs | Manifest, support gaps, existing tests/harnesses |
| 2. Scout | Read scoped regions and rank security-sensitive entry points, parsers, privilege boundaries, and state machines | Audit targets with relevance/reachability rationale |
| 3. Plan | Deterministic scheduler admits targets within reserved budget | Bounded task graph and coverage ledger |
| 4. Analyze | Analysts investigate target context and form falsifiable root-cause hypotheses | Candidate, prerequisites, code references, disconfirming checks |
| 5. Exercise | Existing scanners/fuzzers or an approved CRS integration build/run in VM workers | Tool results, coverage, seed/corpus references, crash candidates |
| 6. Validate | Validator proposes a minimal PoC; independent verifier reviews the oracle and fresh evidence | Reproduction bundle or rejected/inconclusive outcome |
| 7. Assess impact | Authorized assessment tests only the necessary observable security claim | Observed impact and explicit untested escalation claims |
| 8. Patch and verify | Separate author and verifier produce minimal remediation and regression evidence | Patch attempt lineage and independent verification |
| 9. Report and hand off | Reporter assembles evidence; human decides disclosure/publication | Restricted report and approved export plan |

Scouts select targets; they do not certify absence of vulnerabilities in unselected code. Analysts can request additional context or tasks, but only the core can allocate workers or extend budgets. Fuzzing results can feed new hypotheses; a loop creates bounded child tasks with attempt limits and recorded causal links.

### Coverage and stopping rules

Track components as unexamined, selected, in progress, examined within scope, excluded, unsupported, or blocked. Examined means a defined analysis was attempted, not that the component is secure. Record lines/symbols considered, reachable entry points, instrumentation coverage when available, and build omissions as separate measures.

Stop on operator cancellation, scope expiry/revocation, budget exhaustion, infrastructure failure, repeated no-progress threshold, or completed planned targets. Initial proposal: no more than three automated PoC or patch iterations per candidate and a task depth of two, unless an operator approves a different bounded policy. These are proposed defaults to validate in Phase 3, not implemented settings.

Full weaponized exploits are not a default deliverable. Minimal safe reproductions and impact oracles are preferred. Higher-risk exploitation requires the separate high-risk profile and explicit human approval; kernel-target work remains deferred.

## Shared output and failure semantics

Every report identifies input digests, authorization scope, selected tools/models, completed and skipped work, findings by evidence state, patch verification state, resource use, and limitations. Raw crashes and confidential PoCs are restricted artifacts, not automatically embedded in public comments.

| Condition | Required behavior |
| --- | --- |
| Scanner/LLM claim without corroboration | Candidate only |
| No oracle or unbuildable target | Inconclusive; retain reason and required next evidence |
| Advisory identity/range established | Dependency advisory validation; no claim of dynamic exploitability |
| PoC reproduces a security-boundary violation | Eligible for independent dynamic validation review |
| Tool exits zero but ran no tests | Verification incomplete |
| Patched run stops crashing but disables functionality | Reject or investigate; cannot pass on crash suppression alone |
| Worker disappears | Reconcile lease/VM state; do not claim execution stopped |
| New revision or changed policy | Invalidate affected approvals and verification applicability |
| Later scan is quiet | Record no longer observed; do not infer remediation |

Neither operating mode inherits an external product's accuracy or operating guarantees.
