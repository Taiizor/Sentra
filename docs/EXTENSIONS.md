# Plugin and Adapter Architecture

Status: conceptual contract. No SDK, plugin loader, registry, MCP server, or API exists yet. Built-in adapters follow the same domain boundaries as future external extensions.

The [Phase 1 mock provider experiment](phase1/PROVIDER_VALIDATION.md) validates a subset of provider behavior with neutral domain types and 62 deterministic tests. Its in-process traits do not implement the process protocol below or establish a production SDK. Capability advertisements, gateway support and policy grants must intersect; unsupported features are explicit. Unknown usage retains budget reservations, and cancellation acknowledgment is separate from confirmed termination. Live interoperability, IPC/restart behavior and OS egress controls remain untested.

## Adapter families

| Family | Required responsibility | Declared capability examples |
| --- | --- | --- |
| Language/framework | Detect bounded project metadata; provide scoped context, build/test/harness plans, support gaps | Rust source-context pilot; later C/C++ harness metadata |
| Analysis tool | Plan isolated invocations; parse bounded native output; normalize signals and test semantics | Cargo.lock advisory analysis, SARIF import, libFuzzer run |
| AI provider | Validate model capabilities, structure requests/results, account usage, cancel, declare endpoint/retention assumptions | Hosted endpoint or validated local/private endpoint |
| Execution backend | Provision approved worker, enforce profile/quotas, authenticate job/result, terminate/reset and reconcile | Dedicated Linux VM candidate |
| Research-system / CRS | Map an existing system's tasks/artifacts/budgets to Sentra records | OSS-CRS integration candidate |
| Integration | Authenticate external events, resolve immutable inputs, propose approved publication | Later GitHub/GitLab checks and PR proposals |
| Export/import | Read or produce versioned records without overstating evidence | Markdown/JSON, SARIF, future SBOM |

Support declarations are tuples of **host, worker OS/architecture, target language/framework/version, tool version, action, and evidence method**. A wildcard language or platform declaration is not acceptable without matching conformance evidence. Discovery-only support is distinct from analysis, reproduction, and patch verification.

## Packaging and trust

An extension manifest declares identity, publisher, version, executable/image digest, interface version range, adapter family, supported tuples, required non-JavaScript runtimes, capabilities, egress destinations, quotas, data classes, licenses/notices, output schemas, update policy, and optional dependencies.

Installation is an operator trust decision, separate from using an existing approved adapter. No automatic marketplace execution, floating-tag updates, arbitrary downloaded executable, or repository-requested plugin installation. Pin executable, image, configuration, rules, and advisory data independently. Verify provenance/signatures where available without treating them as proof of safe behavior.

Only trusted bundled control-plane helpers may run on the host. Third-party target-facing adapters run inside an approved worker. A subprocess under the operator's account has that account's privileges; pipes and schemas do not make it safe. Native dynamic libraries and a stable Rust plugin ABI are outside the initial design. A future Wasmtime/WASI path must specify host capabilities and demonstrate its own limits.

## Message protocol

Start with supervised subprocess pipes and bounded UTF-8 newline-delimited structured messages for trusted local helpers, plus an authenticated framed transport for worker control. Transport and payload versions are explicit. Newline framing requires escaped embedded newlines, maximum frame/total-output sizes, and strict parsing; stdout carries protocol messages, while stderr carries bounded sanitized diagnostics.

| Operation | Required behavior |
| --- | --- |
| Initialize / negotiate | Declare protocol version, identity/digest, family, capabilities and supported schemas; reject incompatible major versions |
| Probe | Report availability, exact tool version, prerequisites, target applicability, and unsupported reasons without executing target code |
| Plan | Return immutable input refs, proposed jobs, required capabilities, predicted resources, and expected evidence; no side effects |
| Execute | Accept only an authorized job/lease with validated structured arguments and constrained artifact namespace |
| Result / event | Return correlation IDs, input digests, actual status, test counts/skips, usage, evidence refs, and limits; no direct finding-state mutation |
| Cancel / reconcile | Acknowledge cancellation separately from confirmed termination; query known execution ID after transport loss |
| Shutdown | Close channels, release resources, and return cleanup status; uncertain cleanup quarantines the worker |

These operation names describe contracts rather than fixed public method identifiers. Define formal schemas and compatibility fixtures before P4 SDK delivery. A new optional field is only backward compatible if older readers can safely ignore it; security-critical fields cannot be silently dropped. Reject unknown required capabilities and never downgrade an isolation requirement to satisfy version negotiation.

Extension callbacks to read context, request inference, fetch dependencies, or submit artifacts pass through the broker. No raw shell fallback, arbitrary host path, provider-key passthrough, or direct database access is allowed. If an upstream tool truly needs shell execution, the approved worker plan must confine that shell and its scripts to the target VM.

## Result and error semantics

Normalize unavailable prerequisites, unsupported target, denied permission, invalid input/schema, cancelled, timed out, infrastructure failure, tool failure, partial result, and successful execution as distinct outcomes. A nonzero tool exit can mean findings rather than failure; adapter-specific exit semantics must be documented and tested. Exit zero and missing test scripts cannot stand in for passing tests.

Retain raw/native output as restricted evidence alongside normalized records. Reject results with stale leases, changed source digests, unexpected artifacts, forged identity, or undeclared destinations. Reserve budgets before dispatch and reconcile observed consumption; an adapter cannot relabel cost as free.

## OSS-CRS interoperability

Evaluate OSS-CRS as a coarse-grained research-system adapter in a disposable worker. Map target identity, prepared images, campaign budgets, seeds/corpora, PoVs, patch attempts, and test outcomes into Sentra references. The adapter must not expose an upstream Docker socket or provider credentials to target code.

The upstream development guide permits a successful result when no project test script exists; Sentra must preserve this as skipped/incomplete verification. [S06](research/SOURCES.md#s06) If required quotas, egress, isolation, or artifact semantics cannot be enforced, mark that configuration unsupported rather than trusting upstream orchestration implicitly. Compare against direct adapters before duplicating campaign machinery.

## MCP, skills, and API

MCP/API are frontends to the same core application services as the CLI. Start with a trusted local stdio MCP server. The researched protocol candidate is revision 2026-07-28, subject to implementation-time compatibility checks. A skill is documentation/client guidance invoking Sentra; it is not a second engine or permission authority. [S42](research/SOURCES.md#s42)

Proposed external use cases include scoped project discovery, session planning/status/cancellation, evidence/finding reads, validation requests, patch proposals, and approval requests. Reading restricted artifacts still requires authorization. An external agent can request approval but cannot grant it on behalf of a human. Sensitive dispatch occurs only after the core validates a trusted human approval record.

Remote HTTP remains disabled until transport authentication, resource-scoped authorization, origin checks where relevant, SSRF/destination checks, rate limits, and audit controls pass. Follow the transport-specific authorization model; do not forward unrelated user tokens to downstream services. Tool annotations are descriptive metadata, not security enforcement. [S43](research/SOURCES.md#s43), [S44](research/SOURCES.md#s44)

## Conformance gate

Every supported adapter must pass fixtures for version negotiation, capability denial, deterministic input correlation, malformed/oversized output, cancellation, crash/restart, duplicate requests, stale results, unknown test status, secret canaries, and failed cleanup. Analysis adapters additionally need labeled positive/negative targets and native-to-normalized result checks. Execution adapters need the full containment suite; provider adapters need structured-output and usage/egress checks.

No plugin is considered supported merely because it starts successfully or lists a tool. Publish exact tested versions and limitations with each release.
