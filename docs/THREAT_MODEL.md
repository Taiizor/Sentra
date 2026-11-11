# Threat Model and Permissions

Status: Active Platform Security Requirements. Deployment consists of an authorized operator with a local control plane and dedicated isolated VM workers. This forms the baseline platform security architecture.

## Assets and trust assumptions

Protect operator files, target source and intellectual property, repository/model credentials, authorization records, evidence integrity, unpublished vulnerability details, patch correctness, compute resources, and audit history.

The operator and approved host administrator are trusted to select scope and manage the host. The operating system, hypervisor, installed Sentra core, and provisioned worker base are in the trusted computing base. A compromised host administrator can defeat local controls. This assumption must be reconsidered for hosted or shared enterprise deployment.

Target code and dependencies may be intentionally malicious. AI outputs, repository instructions, build scripts, test fixtures, tool output, external content, third-party plugins, and returned artifacts are untrusted. Even trusted tool executables can contain bugs or emit incomplete evidence.

## Boundaries

| Boundary | Protection required |
| --- | --- |
| Operator -> core | Recorded identity, project authorization, explicit policy and approvals |
| Source/acquisition -> context | Immutable snapshots, safe extraction, bounded parsing, provenance and classification |
| Agent -> capabilities | Typed arguments, scope checks, resource reservations, no implicit shell authority |
| Core -> provider | Endpoint/data policy, credential separation, approved egress, usage limits |
| Core -> worker supervisor | Authentication, pinned identity, structured job contract, leases/replay protection |
| Supervisor -> target workload | Disposable VM boundary, guest privilege separation, no management/credential access |
| Worker/plugin -> evidence intake | Size/path/schema/digest validation; treat reported success as a claim |
| Patch author -> verifier | Different context/task, fresh execution, independent oracle review |
| Local records -> external publication | Destination-specific approval, redaction, revision and audience checks |

## Threat register

| ID | Threat | Required mitigation | Requirement |
| --- | --- | --- | --- |
| T-01 | Prompt injection in source/comments/docs/logs causes secret access or scope expansion | Label origin, keep policy outside context, enforce capabilities in broker | S-01, S-03, S-05 |
| T-02 | Build script, procedural macro, test, parser, or PoC executes malicious native code | No target execution on host; disposable VM and resource/network controls | S-07, S-11 |
| T-03 | Target escapes a container through guest kernel or daemon socket | Outer VM boundary, no engine socket/privilege/device exposure; patch guest/hypervisor | S-07 |
| T-04 | Source, dependency names, crash data, or secrets leave through model/tool egress | Default deny, brokered allowlist, explicit classification-aware approval, redacted exports | S-04, S-05, S-12 |
| T-05 | Agent loops/fanout or fork/disk/output bombs exhaust resources/spend | Atomic reservations, quotas, deadlines, bounded framing, kill/reset/quarantine | S-06 |
| T-06 | Forged or replayed approval/worker result authorizes stale work | Bind actor/action/source/policy/lease/expiry, authenticate channel, idempotency | S-02, S-13 |
| T-07 | Fabricated scanner/model evidence becomes a confirmed finding | Independent review, method-specific validation, raw artifact provenance | F-05, F-06, S-08 |
| T-08 | Patch deletes checks or breaks behavior while hiding the reported failure | Original/patched oracle, independent test review, diff scope and regression checks | F-12, S-08 |
| T-09 | Path traversal, symlink/junction, UNC/ADS path, archive bomb, or terminal escape reaches host | Canonical root confinement, bounded extraction, name/encoding validation, sanitized rendering | S-11 |
| T-10 | Malicious plugin/ruleset runs with host privilege or exfiltrates data | Explicit installation trust, exact digests/licenses, constrained worker, capability manifest | S-01, S-04, S-15 |
| T-11 | CI fork/webhook tricks privileged integration into fetching/publishing | Verify event auth, separate read/write credentials, fixed object IDs, no fork secrets | F-18, S-10 |
| T-12 | Incomplete/skipped tests, stale data, or lost base history appear as clean analysis | Explicit gaps, test counts, freshness policy, fail closed on required evidence | Q-02, S-14 |
| T-13 | Local evidence is rewritten, partially deleted, or inconsistent after crash | Transactions, content digests, staged promotion, recovery, audit-limit disclosure | S-09, Q-03, Q-04 |
| T-14 | MCP confused deputy, token passthrough, SSRF, or local server compromise | No automatic privilege inheritance, scoped server identity, destination checks, transport auth | S-01, S-04, S-13 |

Prompt injection and agentic risks are documented by OWASP; Sentra's deterministic broker requirements are design responses, not a claim that prompts eliminate the risk. MCP's published security guidance motivates additional integration-specific checks.

## Permission and approval matrix

A human can preauthorize a bounded action set for a session. This avoids prompting for every safe read while preserving action-specific authority. Scope, digest, capability ceiling, expiry, and resource limits must still be concrete. The same grant applies only while those conditions remain true.

| Action | Default | Required authorization |
| --- | --- | --- |
| Read selected source/metadata and write session-local records | Allowed inside admitted scope | Project/session authorization and local storage policy |
| Run trusted bounded metadata discovery | Allowed within profile | Explicit installed adapter capability; no target execution |
| Run real target build/test/scanner/PoC | Denied until worker gate | Approved disposable VM profile and bounded execution plan; high-risk operations require additional approval |
| Run CodeQL on the operator host against a workspace (build mode `none`; actions, cpp, javascript, python, ruby) | Denied (off by default) | Web console: an administrator enables host analysis in a setting that records the CodeQL terms acknowledgement. Core CLI: anyone who can run `sentra codeql analyze --accept-codeql-terms` on the host (an operator, a script or a coding agent with shell access); the flag acknowledges the licence and authorises nothing. Containment and limits of [ADR-0011](adr/0011-opt-in-host-codeql-analysis.md) apply to both. `sentra codeql packs --download` runs the same CodeQL launcher only to download query packs into the pack cache (no workspace, no database; no `--accept-codeql-terms` needed, see ADR-0011 Licence), with the same environment allowlist, containment and cancellation. Not an exception for builds, tests, other build modes, languages or scanners |
| Send source/context to hosted or remote inference | Denied | Endpoint, classification, input scope, purpose, retention assumptions, and budget grant |
| Fetch dependencies, images, submodules, or private history | Denied unless in provisioning plan | Destination/artifact identity, allowed data, credentials and network grant |
| Execute on operator host or mount home/credentials/engine socket | Denied | No initial exception for untrusted code; requires a new reviewed architecture, not an agent request. ADR-0011 (CodeQL extraction in build mode `none`, previous row) is the only reviewed exception |
| Generate a local patch overlay | Allowed after admitted patch task | Session-local write capability; no checkout modification |
| Apply patch to user's checkout | Denied | Exact patch/base approval and workspace-conflict checks |
| Create PR/comment/check or publish report | Denied | Exact destination, audience, content digest, credentials, and current source/verification binding |
| Run high-risk impact checks or privileged instrumentation | Denied | Separate risk/profile review and explicit human approval; kernel profile deferred |
| Add a third-party plugin/provider or broaden repository/URL scope | Denied | Operator trust decision, capability/egress/license review and new scope digest |
| Delete evidence before policy expiry or export confidential data | Denied | Data-owner-authorized retention/export action; audit any exception |

Approvals cannot be created by a model, target file, webhook, tool result, or untrusted external agent. The core rechecks current authority immediately before dispatch. A changed revision, patch, destination, capability set, policy, or budget invalidates the affected approval. Permission to analyze is separate from permission to disclose or modify.

## Private/proprietary projects

Source classification follows the project into snippets, embeddings if introduced, dependency inventories, crash dumps, patches, and reports. Public advisory IDs do not make a private dependency inventory public. No mandatory public indexing, upstream submission, telemetry, or hosted provider transfer is allowed.

Secrets are acquired by trusted brokers and scoped to acquisition or provider calls. Workers receive only required short-lived task credentials; target processes receive none by default. Internal registry access may require an approved provisioning proxy rather than exposing registry credentials to build scripts.

Before retaining evidence, declare storage location, encrypted-volume requirements, access, retention period, and backup/export behavior. Redaction is defense in depth and cannot guarantee removal of all proprietary logic. Original restricted artifacts and redacted derivatives have distinct IDs and access rules.

## Security validation and residual risk

All control-plane and worker components must pass containment, egress, credential, replay, path, artifact-intake, and independent-verification tests before target execution. Known critical boundary failures block the corresponding feature. Windows-native and kernel profiles need separate threat-model reviews.

Remaining risks include unknown VM escapes, malicious toolchain/base images, parser vulnerabilities, model error, shared-provider bias, benchmark contamination, nondeterministic races, and host compromise. General security completeness, universal platform coverage, and multi-tenant isolation are not initial claims.
