# ADR-0005: Capability-Scoped Out-of-Process Adapters

- Status: Accepted (Fully Validated)
- Date: 2026-11-05

## Context

Sentra must integrate heterogeneous providers, analysis tools, languages, research systems, execution backends, and external clients. Native plugin loading would couple the core to ABI/runtime choices and increase the trusted code surface.

## Alternatives

1. In-process native plugins with unrestricted host APIs.
2. External tools invoked as arbitrary shell strings.
3. Typed, versioned, capability-scoped process/worker adapters.
4. WASI-only plugins for every workload.

## Decision

Choose option 3. Define family-specific capabilities, supported-target tuples, structured plans/jobs/results, resource limits, provenance, cancellation, and schema negotiation. Keep third-party target-facing adapters in approved workers. Process separation is a compatibility boundary; VM containment remains required.

Avoid a stable Rust dynamic-library ABI and unrestricted shell fallback. WASI may be useful for future restricted data-processing extensions, but is not the universal runtime for native security tools.

MCP, API, skills, and dashboard clients call the same core application services. Sentra provides MCP over local stdio transport, adhering to schema and permission conformance. The inspected candidate protocol revision is 2026-07-28. HTTP remains disabled until its separate authentication, authorization, SSRF, and parity gates pass.

## Consequences

Adapters can use different non-JavaScript runtimes without changing the core. Bun remains the only Sentra JavaScript/TypeScript runtime. Startup/framing/versioning overhead is accepted for clearer contracts and crash isolation.

A registry is a distribution mechanism, not a trust mechanism. Installation, licensing, exact digests, egress, and output semantics require independent review. Tool exit zero is not a universal success or test-pass signal.

## Validation and reversal

Specify formal schemas and fixtures before external loading. Reject unknown major versions, undeclared capabilities, oversized/malformed results, stale leases, and unsafe artifacts. If a protocol becomes insufficient, version it explicitly and retain compatibility evidence; never silently drop security fields.
