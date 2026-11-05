# Requirements

Status: normative design baseline, 2026-11-05. MUST denotes a release requirement; SHOULD permits a documented exception. Nothing in this file asserts implementation. Phase references identify the earliest delivery gate, not automatic approval to begin it.

## Functional requirements

| ID | Requirement | Earliest phase / acceptance evidence |
| --- | --- | --- |
| F-01 | MUST ingest an authorized local source snapshot and identify project roots, manifests, languages, and unsupported components without executing target code. | P1 / deterministic discovery fixture report |
| F-02 | MUST record canonical input identity, scope, exclusions, operator, authorization reference, policy digest, and budgets before planning work. | P1 / persisted session manifest |
| F-03 | MUST compare explicit immutable Git base/head revisions and retain surrounding context and attribution uncertainty. | P2 / new, pre-existing, rename, deletion, and missing-history fixtures |
| F-04 | MUST support bounded Scout/Analyst campaigns with a coverage ledger and stop conditions. | P3 / multi-target campaign with recorded skipped regions |
| F-05 | MUST normalize scanner and agent signals into candidates with provenance; deduplication MUST preserve source evidence. | P2 / duplicate and conflicting-signal cases |
| F-06 | MUST distinguish candidate, validated, rejected, and inconclusive findings and retain reasons for every transition. | P2 / lifecycle and invalid-transition checks |
| F-07 | MUST support a pinned Cargo.lock/RustSec advisory workflow; dependency presence MUST be separate from demonstrated runtime reachability. | P2 / affected, unaffected, stale-database, and unknown-version cases |
| F-08 | MUST broker builds, tests, dynamic analysis, and PoCs through an approved worker; MUST NOT execute untrusted project commands on the operator host. | P2 / containment and policy-denial suite |
| F-09 | MUST support a bounded Linux C/C++ reference fuzzing campaign using an existing engine. | P3 / reproducible minimized crash on reference targets |
| F-10 | MUST track exploitability prerequisites and observed impact separately from confidence and severity. | P2 / evidence-linked assessment with explicit unknowns |
| F-11 | MUST create a patch candidate against a fixed source digest in an isolated overlay, with a separately reviewed regression oracle. | P2 / patch and oracle provenance |
| F-12 | MUST independently verify original failure, patched behavior, applicable tests, and patch scope; skipped checks MUST NOT pass verification. | P2 / baseline-fails/patched-passes and incomplete-check cases |
| F-13 | MUST provide local Markdown and versioned JSON reports containing evidence references and limitations. | P2 / redacted round-trip export |
| F-14 | MUST offer session inspection, cancellation, crash recovery, and bounded retry. | P1 / recovery and orphan-worker reconciliation |
| F-15 | MUST expose provider adapters with structured output validation, usage accounting, cancellation, and declared egress. | P2 / offline mock and two real-backend conformance runs |
| F-16 | MUST define versioned tool, language, execution, provider, and integration adapter contracts before third-party loading. | P1 design, P4 delivery / conformance suite |
| F-17 | SHOULD expose the same application services through MCP and an API without bypassing authorization. | P4 / interface-parity and adversarial-access checks |
| F-18 | SHOULD automate authorized GitHub/GitLab review with replay protection, immutable revisions, least privilege, and approval-gated publishing. | P5 / webhook, fork, stale-head, and duplicate-delivery cases |
| F-19 | SHOULD provide a dashboard and richer policy administration after stable local workflows. | P6 / parity and access-control assessment |
| F-20 | MUST support private projects without public indexing or mandatory hosted source upload. | P2 / offline private-source review and egress capture |

## Security and privacy requirements

| ID | Requirement | Acceptance evidence |
| --- | --- | --- |
| S-01 | MUST deny out-of-scope targets and capabilities by default; project files and model text cannot grant permissions. | Policy boundary suite, P1 onward |
| S-02 | MUST bind approval to actor, session, action digest, target revision, capabilities, expiry, and budget. Recheck before dispatch. | Replay, revision-change, expiry, and revocation cases, P1 onward |
| S-03 | MUST treat source, comments, instructions, diffs, logs, findings, and model/tool output as untrusted data. | Prompt-injection and output-injection corpus, P2 |
| S-04 | MUST deny network egress by default in workers and require explicit provider/source egress approval. | Network capture, DNS/redirect and metadata-service denial cases, P2 |
| S-05 | MUST isolate secrets from targets and agents using brokered credentials; reports and telemetry MUST redact secrets. | Credential and artifact canary tests, P2 |
| S-06 | MUST enforce time, tokens, cost reservation, CPU, memory, disk, process, output-size, and task-fanout limits. | Exhaustion and cancellation checks, P1/P2 |
| S-07 | MUST require a disposable VM boundary for real untrusted builds, tests, and PoCs; container-only development is limited to curated trusted fixtures. Kernel-target work requires a separately designed VM profile. | Backend attestation and containment gate, P2/P3 |
| S-08 | MUST keep proposer and verifier in separate tasks, contexts, and clean executions; the patch author cannot approve the patch. | Task lineage, access controls, and contaminated-verifier tests, P2 |
| S-09 | MUST retain append-only logical events and content-addressed evidence; MUST NOT claim resistance to a compromised storage administrator without an external trust anchor. | Tamper detection and documented audit limits, P1/P2 |
| S-10 | MUST require approval before modifying the user's checkout, publishing findings/PRs, fetching out-of-scope inputs, or exporting confidential artifacts. | Sensitive-action matrix and denial tests, P2/P5 |
| S-11 | MUST confine paths and artifact extraction across Windows and Linux, including symlinks, junctions, case collisions, traversal, and oversized archives. | Host-specific path fixture suite, P1/P2 |
| S-12 | MUST declare retention, deletion, backup, and encryption boundaries. Sensitive local projects require an approved encrypted volume; application-level encryption is unresolved. | Storage policy and deletion verification, P2 |
| S-13 | MUST authenticate workers, prevent arbitrary host-command submission, reject stale/replayed results, and correlate results to execution leases. | Worker protocol adversarial suite, P2 |
| S-14 | MUST fail closed when required isolation, schema validation, approval, or evidence is unavailable. | Missing backend, unknown schema, disk-full, and interrupted-run cases |
| S-15 | MUST review executable, ruleset, advisory data, model, and dataset licenses independently before packaging or use. | Version/digest/license inventory, each integration gate |

## Quality requirements

| ID | Requirement | Gate |
| --- | --- | --- |
| Q-01 | MUST separate host support, target-language support, and execution-backend support. | Published matrix at each release |
| Q-02 | MUST make adapter omissions, timeouts, stale data, and unsupported targets visible. | Incomplete report cannot appear as a clean assessment |
| Q-03 | MUST support deterministic replay of recorded decisions without reissuing side effects. Live model reruns are not guaranteed deterministic. | P1/P2 recovery tests |
| Q-04 | MUST version schemas, preserve provenance across migrations, and reject incompatible writers. | P1 migration design; P2 upgrade/restore test |
| Q-05 | SHOULD complete metadata-only discovery of the reference 10,000-file / at-most-100-MiB text fixture within 30 seconds and 512 MiB peak RSS on recorded hardware. | P1 measurement; exclude Git acquisition and model calls |
| Q-06 | MUST publish benchmark denominators, failures, attempt counts, budgets, and contamination limitations. | P2/P3 evaluation report |

The [roadmap](ROADMAP.md) maps delivery gates; the [threat model](docs/THREAT_MODEL.md), [data model](docs/DATA_MODEL.md), and [validation plan](docs/VALIDATION.md) define the supporting contracts. Open questions have owners and decision deadlines in [OPEN_QUESTIONS.md](docs/OPEN_QUESTIONS.md).
