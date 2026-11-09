# ADR-0004: Disposable VM Boundary for Untrusted Execution

- Status: Accepted (Security Invariant Enforced via FailClosedBackend)
- Date: 2026-11-05

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
