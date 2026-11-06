# Technical Validation and Evaluation Plan

This document defines the validation plan. Phase 0 performed documentation checks and read-only environment inspection only; no application tests, model evaluations, sandbox exercises or benchmarks ran in that phase. Phase 1 is now explicitly authorized. Its [execution record](phase1/README.md) links experiments and implementation evidence, retaining historical milestone boundaries. [Increment 6.1](phase1/INCREMENT_6_1_LOCAL_CLI_FOUNDATION.md) adds scoped Windows x64/MSVC CLI invocation, JSON, exit-code, identity-preservation and storage-failure evidence for V-01/F-02/F-14. This does not complete immutable acquisition, cancellation/recovery, packaging or those requirements. No dedicated-VM containment suite has run; untrusted execution remains disabled.

Increment 5.4.2's [SQLite implementation report](phase1/INCREMENT_5_4_2_SQLITE_IMPLEMENTATION.md) adds scoped V-01/V-02/V-05 and F-02/F-14/S-01/S-02/S-06/S-09/S-14/Q-03/Q-04 evidence: native bundled SQLite 3.46.0/MSVC integration, real process recovery, atomic migrations, private durable approvals with local cross-process single-use, transaction rollback/retry and audit/budget consistency. The final workspace passes 153 tests (49 new persistence cases included). It does not complete those requirements: physical faults, power loss, native backup/restore, blob reconciliation, real identity, cryptographic evidence and integrated side-effect dispatch remain unvalidated. No ADR status or acceptance requirement is waived. Earlier engine/mock/in-memory counts below are historical.

Increment 5.3's [workspace report](phase1/INCREMENT_5_3_WORKSPACE_VALIDATION.md) adds historical partial F-01/S-11/S-14 and V-04/Q-05 evidence: 76 passing tests and three measured 10,000-file runs on Windows x64. The filesystem layer grants no authority and provides no content-open API. Its separate Failed S-02 probe led to the correction below. Strong handle-relative identity, immutable snapshots and full F-01/V-04 support remain unvalidated. No accepted ADR or requirement has been waived.

Increment 5.3.1's [security review](phase1/INCREMENT_5_3_1_SECURITY_REVIEW.md) closes that in-process S-02 defect: exact operation/target/revision/session/classification binding, trusted receipt provenance, expiry and atomic replay prevention pass 27 new regressions and the original independent probe. The workspace command records 103 Passed, 0 Failed and three prior fixture/scale cases Not Tested. This adds scoped S-01/S-02/S-14 and V-05 evidence; real human identity, persistent grants, actual snapshot acquisition and end-to-end dispatch are not claimed implemented.

Milestone 2's [SQLite assessment](phase1/SQLITE_VALIDATION.md) records two final source-identical runs with 18 Passed, 0 Failed, 1 Blocked and 3 Not Tested engine items each. JavaScript semantic checking separately Failed; it is not part of that SQLite pass count. The owner approved SQLite as the persistence candidate, preserving the actual Rust-binding/database-blob portion of V-02 and the outstanding physical storage/power-fault gates. No ADR status changed.

Milestone 3's [provider contract assessment](phase1/PROVIDER_VALIDATION.md) is ready for review: 62 Passed, 0 Failed, 0 Blocked and 6 Not Tested assessment items, with all 62 mock tests passed twice. It adds partial F-15, F-16, S-06 and S-14 evidence for provider-neutral contracts, explicit capabilities, structured output, virtual timeout/cancellation, retries, normalized errors and usage. Provider-free experimental boundary construction passes; the real Core Engine is unimplemented and its provider-free integration is Not Tested. This is not completion of V-05's human-grant/concurrent-reservation gate, F-15's two-backend gate, the S-03 injection corpus, or real transport/OS egress validation.

## Phase 1 technical spikes

| ID | Question | Minimum experiment after implementation approval | Decision |
| --- | --- | --- | --- |
| V-01 | Can Rust deliver the Windows core? | Compile/link a minimal candidate on x86_64 MSVC; verify paths/Unicode/CRLF, CLI invocation, supervised child-process termination, structured I/O, and packaging prerequisites | Accept or supersede ADR-0002; document minimum tested toolchain |
| V-02 | Is local metadata/blob storage recoverable? | Interrupt before/after outbox commit, blob promotion, result commit, checkpoint, and backup; restore and reconcile orphaned artifacts | Select SQLite version/journal/durability settings or revise ADR-0003 |
| V-03 | Is the worker topology feasible? | Inspect Hyper-V eligibility/resources and provision an approved dedicated Linux VM after authorization; prove identity bootstrap, authenticated job channel, source transfer, reset, and cleanup | Choose backend candidate or block execution feature |
| V-04 | Is discovery safe and useful? | Use benign and hostile metadata/path fixtures with observable execution/network canaries; measure Q-05 on declared hardware | Approve detection envelope; no universal language claim |
| V-05 | Are grants and retries bounded? | Exercise expiry, revocation, revision change, concurrent reservations, lease loss, and idempotency | Validate policy/outbox contract before paid or sensitive operations |

These are reversible small experiments, not a justification for building every planned subsystem at once. Installing an optional research stack is justified only when the relevant experiment needs it.

## Containment and privacy gate before real targets

Test target attempts to read host/home credentials, reach management sockets, escape path roots, access cloud metadata, use DNS/HTTP/redirect egress, spawn excess processes, fill disk/output, and retain state across reset. Verify quotas outside target control. Confirm no source or secret canaries appear in telemetry, provider traffic, reports, or unrelated sessions.

Use a dedicated test host/VM policy appropriate to these fixtures. Passing known checks is a bounded assurance result, not proof against every VM escape. Publish backend versions and controls. Any critical failure blocks real untrusted builds, tests, native scanning, and PoCs on that configuration.

On cancellation and transport failure, reconcile the worker execution ID and VM state. An acknowledgment is not proof of termination. Confirm actual stop/reset before reuse, or quarantine the worker and preserve unresolved status.

## Reference datasets

| Dataset family | Purpose | Required controls |
| --- | --- | --- |
| Maintainer-owned synthetic fixtures | Deterministic permission, path, lifecycle, oracle and patch tests | Benign counterparts and deliberately incomplete checks |
| Pinned historical Rust change pairs | Initial review and remediation pilot | Original and fixed revisions, root-cause labels, relevant tests and explicit fixture licenses |
| Pinned Linux C/C++ library targets | Deep research, harness, fuzzing and patch comparison | Reproducible source/build, reviewed harnesses, sanitizer configuration, root-cause ground truth |
| Selected CyberGym instances | Historical vulnerability reproduction comparison | License/access review, fixed instances, attempt budgets, known supplied-description advantage and contamination risk |
| Private-source canary projects | Verify local/privacy behavior | Authorized synthetic confidential data and network/secret canaries; no production secrets |

CyberGym evaluates historical-vulnerability reproduction; its leaderboard does not measure novel discovery, complete remediation, or Sentra's private-project usability. Use it as one component and report its limitations. [S51](research/SOURCES.md#s51)

## Evaluation design

Freeze the corpus and scoring rules before comparing systems. Split development/tuning and held-out cases by project/root cause, not adjacent revisions of the same defect. Avoid giving agents known fixes or advisory-derived root-cause descriptions in a novel-discovery experiment. Record which historical cases may already be in model training; complete contamination elimination cannot be promised.

Compare classical tools, an existing CRS integration, and the proposed Sentra workflow using the same source/build images, CPU/memory/time limits, model/currency budget, available hints, and network policy. Publish tool/model identities, configuration, prompts/templates, attempt limits, exclusions, and all failure categories. For nondeterministic research runs, Phase 3 requires at least three repetitions; report distribution and total cost, not only the best attempt.

Human reviewers should label correctness against root cause and evidence, with uncertain/disputed labels retained and adjudication recorded. Avoid using the same model as sole generator, ground-truth labeler, and verifier. An independent human sample review strengthens model-based assessment.

## Metrics and denominators

| Metric | Definition |
| --- | --- |
| Verified precision | Correct independently validated findings / all findings promoted to validated; adjudicate against held-out labels or human review |
| Discovery recall | Ground-truth in-scope vulnerabilities found / all known in-scope ground-truth vulnerabilities; disclose unsupported exclusions |
| Reproduction rate | Candidates with fresh evidence meeting the oracle / all candidates attempted for reproduction |
| Patch verification rate | Independently verified patch attempts / all patch attempts; also report per-finding eventual success |
| Regression rate | Evaluated patches that break required behavior/tests / all patches evaluated |
| Reviewer acceptance | Proposals accepted by an authorized reviewer / proposals submitted; distinct from verification |
| Time to evidence | Wall time from admitted input to first independently useful evidence; include queue/build time |
| Cost per validated finding | Total observed campaign cost / validated findings; report total cost and undefined ratio when zero findings |
| Coverage | Selected/examined/unsupported/excluded components plus instrumentation coverage where available; not a security-completeness score |
| Containment outcomes | Attempted boundary checks, blocked/escaped/unknown counts, backend versions and unresolved cleanup |

Timeouts, infrastructure failures, denied actions, unbuildable targets, missing tests, and inconclusive outcomes remain in the report. Do not remove hard targets to improve a headline rate. Report uncertainty for the small Phase 2 corpus; the 90% precision / 60% recall gates are pilot engineering targets, not statistical proof of production quality.

## Independent patch checks

Review the security oracle before execution. Run the original and patched target in clean environments under the same relevant inputs/configuration. Preserve normal-operation checks, test counts, sanitizer diagnostics, and the exact diff/harness identities. Verify the patch did not remove functionality, skip tests, change expected output to accept the defect, or suppress the detection mechanism.

For nondeterministic defects, record repeated outcomes and a justified confidence criterion; failure to reproduce is inconclusive, not disproof. For dependency upgrades, establish affected/unaffected identities and applicable compatibility tests without claiming a dynamic exploit reproduction that was never performed.

## Requirement traceability

| Requirement group | Verification artifact |
| --- | --- |
| F-01, F-02, Q-01, Q-05 | Discovery fixtures, session manifest, host/target/worker matrix and measurements |
| F-03, F-05, F-06, F-10, Q-02 | Change corpus, provenance/deduplication cases, lifecycle/assessment reports |
| F-07, S-15 | Advisory/range fixtures, database freshness and separate license inventory |
| F-08, S-04, S-05, S-07, S-11, S-13 | Containment, egress, credential, path and worker-auth suite |
| F-04, F-09, S-06 | Deep campaign comparison, coverage ledger, limits and reservation tests |
| F-11, F-12, S-08 | Independent oracle and original/patched verification bundles |
| F-13, F-20, S-09, S-12 | Local export/redaction, audit, retention/deletion/backup and private-source canaries |
| F-14, Q-03, Q-04 | Crash recovery, idempotency, migration and restore tests |
| F-15, S-03 | Two-backend conformance, structured-output, injection and usage tests |
| F-16, F-17, S-01, S-02 | Extension/MCP/API capability parity, approval and schema tests |
| F-18, F-19, S-10 | Integration/dashboard authorization, stale-head and publication tests |
| S-14 | Cross-cutting missing-control/fail-closed cases at every feature gate |
| Q-06 | Frozen benchmark protocol, complete denominators/attempts/budgets, uncertainty and contamination disclosures |

The roadmap defines numerical corpus sizes and phase dependencies. Every support claim must cite the concrete validation artifact produced at that gate.
