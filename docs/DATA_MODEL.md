# Domain and Evidence Model

This document specifies conceptual records and state semantics. It is not a database schema or implemented API. All records require schema versions, stable identifiers, creation metadata, and sensitivity labels. Durable times use UTC; durations use monotonic timing where available.

## Main records

| Record | Required content |
| --- | --- |
| Project | Operator-selected root identity, repository identity when available, owner/scope reference, classification, technology inventory |
| SourceSnapshot | Git base/head IDs where applicable, SHA-256 content manifest, dirty-file policy, root/submodule identities, exclusions and acquisition provenance |
| ResearchSession | Mode, source snapshots, authorization reference, effective policy digest, capabilities, provider/worker selections, budgets, retention, coverage ledger |
| Task | Role, dependencies, immutable input references, capability request, deadline, lease, reservations, idempotency key, attempts, terminal reason |
| Approval | Granting human/service identity, authorized operator, scope, action digest or bounded action-set digest, source/policy digest, capabilities, budget ceiling, expiry, revocation and consumption state |
| ToolRun | Tool/image/version digest, rules/config digest, argv as structured arguments, environment allowlist, source/build/harness digests, execution ID, limits, timestamps, exit/signal/timeout and test-count semantics |
| Finding | Class, hypothesis, source locations, root-cause fingerprint, attacker assumptions, validation state/basis, impact, severity, confidence, disposition, evidence references, review history |
| EvidenceArtifact | Digest, byte length, media type, producer/run, inputs, classification, retention, storage locator, admission status and redaction relationship |
| PatchCandidate | Base snapshot, diff digest, finding references, author task, changed paths, proposed oracle and tests, attempt lineage |
| Verification | Independent verifier, original/patched snapshots and runs, oracle digest, applicable check list, observed outcomes, limitations, decision and policy version |
| Event | Actor, sequence, session/task, event kind, causal/input/output references, policy/approval, UTC time and error category |
| Export | Source record set, redaction policy, target audience/destination, manifest/digests, approval, actual delivery status |

Store source paths relative to a snapshot root with explicit encoding/normalization metadata. Git SHA-1/SHA-256 object IDs retain their algorithm tag and are separate from Sentra's SHA-256 content digests. Never use a model-generated file path as an authorized storage locator.

## Session and task states

Session lifecycle: `created -> scoped -> planned -> running -> completed`. A session can enter `waiting_for_approval`, `paused`, `cancelled`, or `failed` with recorded cause and resume restrictions. `completed` means planned workflow execution ended; separate `assessment_completeness` values `complete`, `partial`, and `unsupported` prevent workflow success from implying a clean security assessment.

Task lifecycle: `queued -> leased -> running -> succeeded | failed | cancelled | timed_out`. Tasks may wait for approval or dependencies. An expired lease becomes reconciliation work before requeueing. A retry has a new attempt record under the same logical task and cannot overwrite prior evidence. A successful tool task can return no useful security conclusion; task success is not finding validation.

## Finding validation and disposition

Validation state is independent from business disposition and remediation state.

| Transition | Required evidence / authority |
| --- | --- |
| New signal -> `candidate` | Immutable source, falsifiable claim, provenance and known limitations |
| `candidate` -> `validating` | Admitted validation task and appropriate oracle/method |
| `validating` -> `validated` | Independent evidence review meeting the class-specific method below |
| `validating` -> `rejected` | Recorded counterevidence or confirmed false-positive reason |
| `validating` -> `inconclusive` | Missing evidence, unavailable environment, timeout, nondeterminism, or unresolved prerequisites |
| `inconclusive` -> `validating` | New inputs/evidence and a new bounded task |
| `rejected` -> `validating` | Explicit reopening with new evidence; preserve rejection history |

New evidence can supersede a prior validation assessment through an auditable review event, never by deleting history. A revision change creates a new occurrence/applicability record; previous evidence does not silently apply to different bytes.

Validation basis must be one of:

- **Dynamic reproduction:** a reviewed oracle demonstrates the stated security-boundary failure on the pinned original target, with fresh execution evidence.
- **Static evidence review:** independent source/dataflow reasoning establishes the claim under explicit assumptions, with unavailable dynamic checks disclosed. Never label this dynamically reproduced.
- **Dependency advisory match:** exact package/version/range and advisory provenance establish an affected dependency. Reachability/exploitability remains separate.

Disposition values include `open`, `duplicate`, `accepted_risk`, `out_of_scope`, and `withdrawn`, with actor, rationale, and expiry where applicable. Suppression/accepted risk is not remediation. Duplicate findings retain aliases and evidence links; uncertain duplicate clustering cannot erase candidates.

Remediation state includes `unpatched`, `patch_proposed`, `patch_verified`, `delivered`, and `fix_verified_at_revision`. A local verified patch is not necessarily applied upstream. A publication/delivery event does not prove integration. `not_observed_at_revision` is an observation attached to an occurrence, never a replacement for verified remediation.

## Patch verification lifecycle

`draft -> awaiting_verification -> verifying -> verified | failed | inconclusive`. Delivery and application are separate records. Modifying any patch, base, harness, oracle, or required check invalidates the existing verification's applicability and requires a new verification attempt.

A `verified` patch requires:

1. The pinned original reproduces the relevant failure under the reviewed oracle. For advisory upgrades, establish the original affected identity and exercise applicable compatibility tests rather than pretending every advisory has a PoC.
2. The patched target passes the same meaningful oracle with normal behavior preserved.
3. Applicable regression, build, and security checks actually ran and passed; test counts and skipped/filtered cases are recorded.
4. The verifier reviews diff scope, changed dependencies/configuration, disabled tests/assertions, and compensating controls.
5. The result references fresh isolated executions and an independent verifier task. Missing required checks yields `inconclusive` or `failed`, not `verified`.

Static-only findings without an adequate executable oracle can receive a reviewed patch proposal, but cannot claim dynamic patch verification. The required verification method and remaining limits must be explicit.

## Evidence admission and reproduction bundle

Artifacts enter a size-bounded staging area. Validate lease/run correlation, declared lengths/digests, path safety, classification, and parser limits before admitting them. Hash raw bytes; redacted derivatives get different digests and links to originals. A tool's claim that an artifact exists or a test passed is not sufficient.

A reproduction bundle records source/build/harness identities, toolchain and guest/image digests, sanitized invocation/environment, required inputs and seed, oracle, stdout/stderr/diagnostics, exit status, test counts, resource limits, and repeated-run outcomes. Include network/dependency provisioning manifests when relevant. Hashing gives integrity checks, not authenticity of a malicious producer's explanation.

Reports cite evidence IDs with resolvable local references. Exports include manifests, schema versions, classification, redaction descriptions, and limitations; restricted PoCs/crash dumps are excluded by default unless the audience and approval allow them.

## Assessment semantics

Store severity, confidence, validation basis, exploitability, and business priority separately. Confidence is a reasoned label with evidence, not a model's unsupported probability. Record reachable attacker identity, privileges, required configuration, user interaction, and observed confidentiality/integrity/availability effects.

An optional CVSS v4.0 vector must identify assumptions, author/reviewer, and unresolved metrics. Never fabricate missing metric values to generate a score. CVSS is an assessment format, not a substitute for evidence or organizational risk prioritization. [FIRST specification](https://www.first.org/cvss/v4.0/specification-document)

## Storage, retention, and audit limits

Use transactions for metadata/events/outbox and staged durable blob promotion with recovery reconciliation. Backups must include compatible database and referenced blobs; deleting only the primary database does not delete WAL files, exports, caches, or backups. Retention policy must identify all copies and permitted deletion timing. Deletion events retain non-sensitive tombstones where policy allows.

Sensitive local data initially requires an approved encrypted volume and OS access controls; application-level encryption/key management is unresolved. Secrets use references to an operator credential store, not raw values in task records. No multi-tenant or storage-administrator tamper resistance is claimed. Export signing/external anchoring requires a separately managed trust root and remains a later decision.
