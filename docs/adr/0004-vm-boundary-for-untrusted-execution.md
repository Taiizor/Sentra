# ADR-0004: Disposable VM Boundary for Untrusted Execution

- Status: Accepted (Security Invariant Enforced via FailClosedBackend); partially superseded by [ADR-0011](0011-opt-in-host-codeql-analysis.md) for one case
- Date: 2026-11-05

> Note (2026-11-11): [ADR-0011](0011-opt-in-host-codeql-analysis.md) narrowly supersedes the "no host execution exception" of this ADR for a single case: CodeQL analysis on the host that runs the Sentra core, using `codeql database create --build-mode=none` and `codeql database analyze` for actions, cpp, javascript, python and ruby, under the containment that ADR-0011 lists. There are two ways in: in the web console an administrator enables it in a setting that records the CodeQL licence acknowledgement, and the core CLI runs it for anyone who runs `sentra codeql analyze --accept-codeql-terms` on the host (an operator, a script or a coding agent with shell access). The CLI flag is a licence acknowledgement, not an authorisation check. CodeQL's extractors then parse untrusted code on the host. Builds, tests, PoCs, other build modes, other languages, other scanners and plugins remain under this ADR, and the rest of this ADR is unchanged.

## Context

Repository builds, procedural macros, tests, native analysis tools, fuzz targets, and generated PoCs can execute malicious code. The Windows host contains operator files and credentials. A reachable Docker Desktop Linux engine does not prove per-session hostile-code containment.

## Alternatives

1. Execute on the host with process limits.
2. Use Docker/WSL2 containers as the sole boundary.
3. Use a dedicated disposable VM boundary, with optional containers inside.
4. Require Firecracker/gVisor or a proprietary hosted sandbox immediately.

Docker security, WSL2 integration, Hyper-V, gVisor, and Firecracker have different platform and trust assumptions. See [Threat Model](../THREAT_MODEL.md) for isolation boundaries.

## Decision

Choose option 3 for real untrusted execution. Limit container-only development to curated trusted fixtures. No host execution exception is introduced for convenience. The control plane must fail closed when the required backend is unavailable.

Propose a dedicated Hyper-V Linux VM worker for the Windows host, subject to edition/features/resources/automation and containment testing. An explicitly approved dedicated Linux VM endpoint is an alternative, including a separate confidential-data transfer decision. Docker Desktop/WSL2 alone is not the proposed backend.

Disable unnecessary host integration, target egress, privileged device/socket access, and credential inheritance. Authenticate control traffic and confine artifacts. Reset guest state before independent verification and between unrelated projects.

Kernel-target research and Windows-native execution need distinct future profiles; the initial user-space worker does not authorize either. Ghidra and Frida remain optional future adapters.

## Consequences

VM provisioning and reset add operational cost and latency. Some local hosts may be unable to run the initial execution backend. Those sessions retain read-only/static/advisory capabilities where supported and record dynamic verification as unavailable.

A VM reduces exposure but does not eliminate hypervisor, supervisor, parser, or image risks. No multi-tenant or universal escape-resistance claim follows from this decision.

## Validation and reversal

All execution pipelines enforce the documented containment, egress, credential, resource, cancellation, and cleanup gates before running target code. Changing the boundary requires an explicit security review and superseding ADR; a model or plugin cannot downgrade it.
