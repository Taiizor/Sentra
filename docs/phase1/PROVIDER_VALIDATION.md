# AI Provider Contract Validation — Phase 1, Milestone 3

Date: 2026-11-05. **Mock contract validation is complete and ready for review.** No real AI provider, autonomous agent, vulnerability workflow, production Core Engine or Phase 2 implementation was introduced. Phase 1 remains incomplete.

## Result and recommendation

Retain a provider-optional Core Engine with provider-neutral requests, capability descriptors, responses, usage and error categories. Keep provider SDKs, raw vendor failures, credentials and transport behavior behind approved adapters. Do not equate an endpoint's advertised compatibility with validated behavior or treat missing usage as measured zero cost.

The isolated Rust experiment passes **62 contract tests twice**, with identical test names/outcomes: **62 Passed, 0 Failed, 0 Blocked, 6 Not Tested** per recorded contract assessment. All executed formatting, compilation and Clippy checks pass. The six untested items are explicitly listed below; the count does not imply production integration or universal provider support.

The real Core Engine is not implemented. T01 proves that the experimental boundary can be constructed and inspected without a provider and returns NotConfigured for an explicitly requested inference operation. T02 proves that construction/status inspection do not initialize or call a provider. These are architecture/contract evidence, not completed production Core Engine integration tests.

## Scope and implementation

The standalone package has its own workspace boundary, `publish=false`, and **zero third-party direct/transitive crates**. It uses the installed Rust standard library and forbids unsafe code. There is no HTTP client, provider SDK, network transport, API-key field, telemetry, package download or cloud service. All request/response bodies are synthetic test fixtures; no repository source or findings are submitted to a provider.

| Artifact | Responsibility |
| --- | --- |
| `contract.rs` | Provider-neutral model/capability, request/response, classification, usage, error and diagnostic types; narrow typed structured-output validation |
| `gateway.rs` | Explicit lifecycle/policy gates, optional provider, limits, virtual deadlines, bounded retry and in-memory accounting |
| `mock.rs` | Deterministic scripts, configurable model capabilities, mock-only vendor errors and operation/cancellation receipts |
| contract tests | All 62 named test cases; no API keys or external services |
| `Validate.ps1` | Offline quality commands, two serial test runs, per-test status extraction, source hashes and raw evidence |

The Rust traits are an experimental behavior/payload seam. They do not implement or replace ADR-0005's versioned process/worker adapter boundary, establish a native plugin ABI, or commit the production public API. SDK/IPC and wire serialization remain future validation work. No additional orchestration layer was added.

## Reproduce and inspect evidence

From the repository root:

```powershell
pwsh -NoProfile -File experiments/phase1/provider/Validate.ps1
```

The final raw result records every executed command, stdout/stderr, exit code, timeout state, all 62 individual test statuses in each run, exact source/runner/manifest/lockfile SHA-256 digests, dependency metadata, matching repeat outcomes and ordinary-test-log canary checks. The earlier 61-test result is preserved as historical evidence for its recorded source hashes; the final source adds conservative handling of partial usage before confirmed cancellation. Ignored target files are generated build artifacts; the lockfile contains only this experiment package. The runner exits nonzero on a command failure, missing test cases, ignored/failed cases, mismatched repeated outcomes, dependencies or unexpected canary output.

Observed environment: Windows 11 x64, build `10.0.26300`; PowerShell `7.6.9`; `rustc 1.99.0 (b940084d7 2026-09-28)`, LLVM `23.1.1`; Cargo `1.99.0 (5f94df478 2026-08-27)`. The tested target is `x86_64-pc-windows-msvc`. The existing MSVC installation was reused. ARM64 remains unverified, and no toolchain component was installed.

| Executed check | Status | Evidence |
| --- | --- | --- |
| Rust/Cargo version capture | Passed | Actual installed tools respond; versions are in raw output |
| cargo fmt --check | Passed | Probe formatting is clean |
| cargo metadata --offline --no-deps | Passed | One package and zero dependencies |
| cargo check --offline --all-targets | Passed | Library and integration tests type-check on the tested target |
| cargo clippy --offline --all-targets -- -D warnings | Passed | No warnings or lint suppressions |
| cargo test --offline -- --test-threads=1 | Passed | 62 passed, zero failed/ignored/filtered |
| Repeated serial contract test run | Passed | Same 62 Passed outcomes; deterministic logical-time assertions |

The PowerShell process wrapper has a 60-second command limit. This protects the validation invocation; it is separate from the mock's virtual-time timeout tests. No benchmark, real model latency or native worker lifecycle claim follows from these timings.

Documentation/evidence checks Passed for 35 Markdown documents, 225 local file/fragment links, 59 tables, all 41 requirement mappings and seven matching ADR status records. An ephemeral Bun checker verified links/fragments, balanced fences, table widths, final newlines and whitespace; the PowerShell parser and Git whitespace check also passed. All eight final evidence input hashes match the current experiment; the 62 named tests exactly match both raw run records. All preexisting experiment artifacts and ADR contents match their entry hashes. HEAD, branch, history, references and index match the entry snapshot; only the intended 11 existing documentation files and 12 new provider/report artifacts differ. No production code or third-party dependency was introduced.

## Required investigation matrix

Every listed test is individually marked Passed in the raw record. Groups below cover the complete T01–T62 suite; negative scenarios pass only when their expected rejection or accounting behavior is observed.

| Investigation | Tests | Status | Observed contract behavior |
| --- | --- | --- | --- |
| Lifecycle and initialization | T01–T06 | Passed | No provider is required for local boundary status; no implicit initialization; explicit metadata permission; idempotent initialization; failure leaves unready state; terminal close |
| Model/capability discovery | T07–T08, T57, T61 | Passed | Distinct configured capability sets are preserved; duplicate/malformed models and unknown-model fallback are rejected; Unsupported identifies the missing feature |
| Request/response normalization | T09–T10, T30–T31, T51 | Passed | Stable neutral results and diagnostics; vendor auth/unavailable/internal/output errors stay inside the mock adapter; model mismatch is a protocol error with uncertain cost retained |
| Structured output | T11–T14, T16, T58 | Passed | DecisionV1 validates required fields/types, nonempty bounded summary and no extra fields; malformed/mismatched output is rejected; no downgrade to text |
| Streaming requirements | T15, T17–T20, T43, T56, T58 | Passed | Text chunks require declared support, order, byte/event bounds and matching final content; unsolicited/partial failed streams never become successful results or trigger automatic retry |
| Timeout and cancellation | T21–T25, T48–T49, T52, T54, T62 | Passed | Virtual deadline and mid/pre-dispatch cancellation; cancellation capability negotiated; unconfirmed cancellation remains unconfirmed; a partial receipt cannot release budget while work may continue |
| Retry and rate limit | T26–T29, T50, T60 | Passed | Stable logical request ID across bounded attempts; Retry-After respected; finite exponential fallback; total deadline/delay/attempt constraints; no auth/internal/invalid-output retry |
| Error normalization | T13, T30–T31, T35, T51 | Passed | Typed error categories, no vendor message leakage; invalid usage/model identity rejects misleading success |
| Token/cost accounting | T09, T32–T38, T53–T54, T59, T62 | Passed | Reserve before dispatch; measured final usage settles actual cost; missing/invalid/unconfirmed final usage holds uncertainty; retry-attempt uncertainty survives later success; overflow/budget checks; unknown prices block dispatch |
| Input/context/output limits | T39–T43, T48, T60 | Passed | UTF-8 byte limits intersect policy/model limits; input plus requested output fits context; unknown token counting cannot imply compatibility; output bytes/chunks and arithmetic are bounded |
| Provider feature differences | T07, T14–T16, T24–T25, T34, T41, T58, T61 | Passed | Unsupported structured/stream/cancel/usage/token features remain explicit; advertisements cannot enable an unimplemented structured-streaming path |
| Privacy and explicit operation | T02, T04–T05, T44–T47, T55 | Passed | No automatic dispatch; separate metadata/inference and egress grants; classified inputs require approval; Secret input denied; classification propagated; payload/vendor canaries absent from ordinary diagnostics |

## Contract recommendations from the experiment

### Lifecycle and capabilities

Use explicit initialize, discover, authorized invocation and close operations. Core construction and local use cases must not initiate discovery or inference. Keep advertised capabilities distinct from gateway-supported features and granted permissions; their intersection determines whether a request is admitted. Provider metadata cannot grant scope or enable an unimplemented feature.

Descriptors need versioned model identity, supported output/stream/cancellation/token/usage features, context/input/output limits and pricing provenance. This experiment validates bounded descriptors and two configured model profiles; it does not validate two independent real provider backends. Local inference is still a provider whose capabilities and privacy must be assessed.

Real token counts must be scoped to the selected model/revision and include protocol/tool/schema overhead; the shared mock byte counter proves neither tokenizer compatibility nor real context fit. Initialization, discovery and counting return immediately in this mock. Any future potentially blocking adapter operation needs bounded transport deadlines and cancellation rather than inheriting that fixture assumption.

### Structured and streaming output

DecisionV1 is a deliberately narrow **typed object**, not JSON parsing or general JSON Schema support. It requires exactly `summary: nonempty string` and `accepted: boolean`; summary is bounded to 256 UTF-8 bytes. Its synthetic `accepted` field has no permission or ADR-approval authority. Do not replace established wire/schema libraries with this fixture validator in production.

The gateway supports bounded text streams and buffered typed structured results. Structured streaming is explicitly Unsupported even if a mock descriptor advertises it. Stream sequencing, a maximum of 64 chunk events, content byte bounds and terminal consistency are checked. Byte accounting here measures typed payload content; transport framing/JSON escaping needs separate wire-size limits before real integration. Failed partial output is not promoted to a successful response.

### Deadlines, cancellation and retry

Tests use a deterministic virtual clock; no sleeps, timer races, sockets or remote work are needed. Deadline is exclusive: a completion at the deadline is timed out. Cancelling the caller and confirming provider termination are separate states. Keep `cancellation_confirmed=false` visible and retain uncertain spend when a provider cannot confirm cancellation.

Retry only admitted transient rate-limit/unavailable errors explicitly safe to retry and occurring before any stream output. Preserve the logical request identity; do not claim real provider idempotency from the mock trace. Authentication, internal errors, invalid output, timeout, cancellation and partial-stream failure do not automatically retry. Attempts are bounded to at most 16, mock request duration to at most 1,000 logical milliseconds, and delays by policy and remaining deadline. An excessive Retry-After is rejected rather than shortened into a premature request. These are probe limits, not production defaults.

### Accounting

The mock counts input UTF-8 bytes as synthetic tokens and uses configured synthetic micro-USD rates; these are neither a real tokenizer nor current commercial prices. For the standard fixture, two input tokens plus four requested output tokens reserve 10 units. A measured two-input/two-output response costs 6 and releases the unused reservation.

Unknown usage is represented as unknown. It retains the maximum reservation and an unknown-attempt count, preventing another call from spending that capacity. Measured usage after timeout is settled only when cancellation confirms finality. If cancellation is unconfirmed, even a partial usage receipt leaves the entire upper bound held; the probe does not book that receipt as final spend. Billed but invalid output is not free. Wrong-model responses cannot be safely priced under the requested model and retain uncertainty. Unknown usage on an earlier attempt remains visible in the request outcome after a later successful retry; it cannot disappear behind the final attempt's usage. Even a zero-price fixture does not relabel missing usage as measured completeness.

Production accounting needs exact currency/rate/model revisions and provider-specific cached/reasoning/billable categories where applicable. This sequential in-memory ledger does not validate concurrent reservations, persistence or invoice reconciliation. Reserve and reconcile through the eventual authoritative storage services; no production billing/storage layer is introduced here.

## Data classification and egress boundary

| Classification | Mock policy behavior | Future production boundary |
| --- | --- | --- |
| Public | Explicit inference initiation and permission still required | Public content does not authorize arbitrary endpoint access or spend |
| PrivateSource | Separate classified-input grant required, including local mock calls | Approved provider/destination, repository scope, retention and privacy configuration |
| SecurityFinding | Same explicit classified-input treatment; output inherits classification | Restricted evidence/PoC/report access and publication are separate permissions |
| Secret | Always denied in the experiment | Credentials belong in brokers; do not treat a prompt or egress flag as permission to disclose keys |

Remote inference adds a separate egress permission even for Public input. The Remote descriptor test still runs the same in-process local mock; it does not contact an endpoint. Initialization/discovery/token counting are local mock operations here; any future transport activity in those operations also requires an egress decision before contacting an endpoint. Production destination classification must come from trusted adapter/endpoint configuration, not a model's self-declaration. Actual destination allowlists, transport authentication, human grant issuance/expiry/revocation and OS-enforced egress remain future work.

Ordinary diagnostics contain only bounded event codes, attempt numbers and normalized error categories, with at most 64 records. Request/response/value Debug output redacts payloads; raw vendor messages are discarded at normalization. Canary tests cover input, output and authentication-error fixtures. Restricted evidence/debug retention would require a separate explicit policy; this experiment does not persist real source, prompts, keys or findings.

## Not Tested and unresolved decisions

| ID | Validation item | Status | Reason |
| --- | --- | --- | --- |
| N01 | Real provider SDKs, authentication and backend interoperability | Not Tested | Real connections and keys are outside this milestone; synthetic errors are not real protocol conformance |
| N02 | Production Core Engine operation/integration without a provider | Not Tested | The provider-free boundary probe passes; the actual Core Engine and its local services are not implemented |
| N03 | Real tokenizers, prices and invoice reconciliation | Not Tested | Only deterministic mock token/cost fixtures are used |
| N04 | Real cancellation latency, backpressure, remote termination and OS egress enforcement | Not Tested | Virtual in-process operations do not prove live transport or containment guarantees |
| N05 | JSON/SSE wire parsing, arbitrary JSON Schema and structured streaming | Not Tested | Typed DecisionV1 and text streams only; serialization/framing libraries are not selected |
| N06 | Concurrent/durable reservations, IPC and process/restart recovery | Not Tested | Ledger/gateway are sequential and in-memory; accepted adapter/storage boundaries remain unimplemented |

No required mock test is Failed or Blocked. The existing SQLite JavaScript semantic-check failure remains separately documented; passing Rust checks here does not resolve or conceal that earlier issue. ARM64 and the Hyper-V management/containment limitations remain unchanged. No ADR is accepted or superseded by this experiment.

## SQLite decision carried forward

The project owner approved SQLite as the candidate for local persistence in this milestone. This does **not** establish production readiness. Preserve explicit rollback after statement failure; full transaction restart and fresh reads after SQLITE_BUSY_SNAPSHOT; bounded retries; WAL/checkpoint lifecycle management; and evidence integrity across process termination.

Physical disk exhaustion, real write/fsync IOERR, power-loss durability, the production Rust binding and database/blob reconciliation remain unresolved exactly as recorded in [SQLITE_VALIDATION.md](SQLITE_VALIDATION.md). Do not interpret candidate approval or these provider tests as evidence for those items.

## Scope and repository state

Entry inspection found clean `develop` at `2689268f2676304de69bc2ef1767c79b951f76fd`, with local `origin/develop` at the same commit. Previous SQLite completion changes were already recorded there and were preserved. No preexisting user changes were staged, stashed, discarded or reverted.

All new code is confined to the provider experiment. Relevant documentation records the owner-approved SQLite candidate and this contract evidence; all seven ADR files remain unchanged, including Proposed ADR-0002 and ADR-0007. No autonomous research, discovery workflow, production AI adapter, Core Engine implementation or Phase 2 work was started. No Git commit, amend, reset, rebase, cherry-pick, tag, push, fetch, pull or history/reference-changing command was issued; changes remain in the working tree.
