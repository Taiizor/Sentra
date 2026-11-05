# Core Technology Evaluation

This is a qualitative architecture comparison. No performance, build, memory, or developer-productivity benchmark was run. Decisions marked proposed require experiments after Phase 1 approval.

## Core language alternatives

| Candidate | Documented foundation | Fit judgment | Validation / cost |
| --- | --- | --- | --- |
| Rust | Official support includes Windows MSVC targets; host toolchain and platform prerequisites are documented. [S14](SOURCES.md#s14), [S15](SOURCES.md#s15) | Recommended for a native core, explicit domain modeling, resource-sensitive brokers, and portable interfaces. Memory safety reduces some classes of bugs but does not secure unsafe/native dependencies or policy logic. | Windows linker/SDK readiness, async process cancellation, native dependency packaging, and team complexity remain gates. |
| Go | Official distribution supports multiple host/target combinations. [S18](SOURCES.md#s18) | Credible fallback for service orchestration and a compact CLI. Compare if Rust integration friction is high. | Native analysis-library integration and OS-specific process/VM controls still require testing; no portability assumption from language choice alone. |
| C# / .NET | Native AOT is documented with deployment limitations. [S19](SOURCES.md#s19) | Strong alternative for a Windows-focused control plane and OS integration. | Evaluate packaging, reflection/dynamic-code constraints, Linux worker integration, and runtime choice before claiming an easier overall product. |
| TypeScript / Bun | Bun documents Windows installation and its runtime/tooling platform. [S17](SOURCES.md#s17) | Suitable for future UI and optional developer tooling; possible prototype language after approval. | Bun compatibility must be validated per dependency; Sentra must not fall back to another JavaScript runtime. Not chosen for the security-sensitive core initially. |
| Python | Existing agent/CRS frameworks use Python-oriented stacks. [S04](SOURCES.md#s04), [S11](SOURCES.md#s11) | Useful inside optional research workers; not required on the initial operator host. | Dependency and distribution footprint, policy isolation, and schema contracts remain integration costs. |

Rust is a **conditional recommendation**, not a completed technical validation. ADR-0002 stays proposed until a Windows compile/link, process lifecycle, storage, and worker-control spike passes. If not, prefer a documented reversal to preserving a language preference at product cost.

## Runtime and dependency strategy

Rust/Cargo would manage Rust components. Bun is the only permitted JavaScript/TypeScript runtime/package manager for Sentra-owned components. Upstream Python, JVM, LLVM, or other non-JavaScript runtimes belong in declared optional worker environments. An upstream tool that requires a different JavaScript runtime is deferred unless an independently verified Bun-compatible path exists.

Do not select a broad dependency set in Phase 0. Later evaluate small, maintained libraries for CLI parsing, async I/O, serialization, HTTP, SQLite, and protocol handling, with Windows support, licensing, security history, and release cadence checked at the chosen version. There is no initial Cargo workspace or package manifest.

Target builds are inherently untrusted: Cargo supports executable build scripts, and compile-time mechanisms can run code. Dependency resolution and fetching also create privacy and supply-chain effects. Initial discovery reads manifest bytes rather than invoking Cargo on unknown projects. [S16](SOURCES.md#s16)

## Control-plane architecture alternatives

| Choice | Reason to adopt | Reason to defer alternatives |
| --- | --- | --- |
| Modular core with CLI frontend | Shared use cases can serve future MCP/API/UI clients without duplicating policy | Microservices and a hosted control plane add operational and authentication complexity before a useful local workflow exists |
| Small deterministic persisted task DAG | Required role boundaries and recoverable bounded workflows are explicit | LangGraph and Temporal remain options when their benefits justify runtime/server dependencies; avoid building a general workflow framework [S11](SOURCES.md#s11), [S12](SOURCES.md#s12) |
| Local SQLite metadata plus blob directory | Transactional state and evidence references fit single-operator operation | PostgreSQL/object storage are future distribution needs, not initial requirements; keep storage interfaces narrow |
| Typed subprocess extensions | Cross-language integration without a stable native ABI | In-process dynamic Rust plugins increase compatibility and trust problems; WASI remains an option for suitable restricted workloads [S41](SOURCES.md#s41) |
| Provider-specific adapters behind a common contract | Captures differences in tool calls, usage, streaming, and privacy | An OpenAI-compatible endpoint label does not prove matching behavior; no universal SDK is assumed |

SQLite WAL requires same-host shared-memory coordination and has concurrency/checkpoint tradeoffs. The proposed store uses a local volume, bounded write coordination, explicit durability settings, backups, and crash recovery; actual journal mode and library version remain a Phase 1 decision. [S48](SOURCES.md#s48)

## Protocol and interchange choices

| Boundary | Initial proposal | Validation gate |
| --- | --- | --- |
| Internal extensions | Versioned UTF-8 structured messages over supervised pipes with bounded framing | P1 schema design; P4 third-party conformance |
| Remote worker control | Authenticated typed jobs, mutually authenticated TLS for network transport, lease-scoped credentials | P1 feasibility; P2 containment/replay suite |
| External coding agents | MCP stdio first; HTTP later, with explicit authorization | P4; inspected MCP candidate revision is 2026-07-28 [S42](SOURCES.md#s42), [S43](SOURCES.md#s43), [S44](SOURCES.md#s44) |
| Scanner interchange | SARIF 2.1.0 plus native evidence | P2/P4 import/export fixtures [S46](SOURCES.md#s46) |
| Advisory interchange | OSV with versioned schema and package identity | P2/P4 affected-range fixtures [S28](SOURCES.md#s28) |
| Inventory interchange | CycloneDX where supported by a selected tool | Later adapter gate [S49](SOURCES.md#s49) |
| Severity | Optional CVSS v4.0 vector, with unknown metrics left unresolved | P2 assessment contract [S47](SOURCES.md#s47) |

Protocol versions above are researched candidates, not runtime compatibility promises. Pin exact schemas and SDKs when implemented; reject unsupported major versions and record negotiated capabilities.

## Build versus reuse rule

Reuse scanner engines, advisory formats, fuzzing engines, cryptographic libraries, VM runtimes, and protocol implementations. Build the minimal product-specific policy and evidence invariants. Before custom harness generation, campaign ensemble, or research scheduling infrastructure, document an OSS-CRS/Buttercup comparison. Revisit this split when experiments show a reusable system can satisfy more of the product contract.

## Phase 1 evidence update

The [initial Phase 1 report](../phase1/README.md) records successful dependency-free x64 Rust/MSVC compilation, execution, three probe tests, formatting and Clippy on the inspected host. It does not validate SQLite/native crates, full process lifecycle, provider contracts, core/CLI behavior, or an authenticated disposable worker. ARM64 compilation is blocked by the absent target standard library. ADR-0002 therefore remains Proposed, and this Phase 0 qualitative comparison is not promoted into a general support or performance claim.
