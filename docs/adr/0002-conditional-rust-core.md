# ADR-0002: Conditional Rust Core Recommendation

- Status: Accepted (Validated on Windows x64 MSVC and Linux Docker in Phase 1)
- Date: 2026-11-05
- Decision gate: Phase 1 V-01/V-02, after explicit implementation approval

## Context

The owner prefers Rust subject to technical validation. The inspected machine has a Windows MSVC Rust toolchain and Cargo, but no program was compiled. Visual Studio discovery returned no matching VC tools version; linker/SDK readiness remains unverified.

Rust documents Windows MSVC platform support and tooling requirements. This is evidence of upstream viability, not successful local linking or a Sentra support guarantee. [S14](../research/SOURCES.md#s14), [S15](../research/SOURCES.md#s15)

## Alternatives

| Language | Main attraction | Main question |
| --- | --- | --- |
| Rust | Native reusable core, explicit state models, resource control | Windows tooling, integration friction, and implementation complexity |
| Go | Service/CLI orchestration alternative | Native integrations and OS-specific lifecycle control |
| C# | Windows integration and deployment options | Runtime/AOT constraints and cross-platform worker boundary |
| TypeScript/Bun | Shared UI/tooling language | Dependency/runtime compatibility and core security boundary |
| Python | Existing research/agent ecosystem | Operator-host packaging and dependency footprint |

The [technology study](../research/TECHNOLOGY.md) documents the source-backed comparison and its unbenchmarked limits.

## Proposal

Use Rust for the core and CLI if the Phase 1 spike passes. Keep worker protocols language-neutral so Python/JVM/native analysis tools do not force the core into their runtime. Use Bun exclusively for any Sentra-owned JavaScript/TypeScript work.

Do not select crate versions, publish an MSRV, create a workspace, or claim production performance in Phase 0. Dependency selection follows validation and version-specific maintenance/license review.

## Required evidence

- Successful Windows x86_64 MSVC compile/link/run and documented SDK/linker prerequisites.
- Correct Unicode/spaced paths and CRLF input handling.
- Supervised child-process trees, bounded structured I/O, cancellation, and crash handling.
- SQLite/blob crash-recovery feasibility and authenticated worker-channel feasibility.
- A small dependency and packaging inventory, including native library requirements and unsafe/FFI surfaces.

## Consequences and reversal

Rust may improve memory-safety properties but cannot guarantee safe toolchains, policy logic, native parsers, or sandbox execution. If the required integration/lifecycle tests fail or the operational cost is unreasonable, compare a small Go/C# alternative, record results, and supersede this proposal before expanding implementation. The language preference must not override product feasibility.
