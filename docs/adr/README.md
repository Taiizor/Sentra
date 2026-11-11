# Architecture Decision Records

ADRs record the architectural rationale, context, and validation conditions for foundational design choices across the Sentra platform. ADR-0001 through ADR-0010 are Accepted and empirically validated. ADR-0011 is Accepted and implemented in the core CLI and the web console; a real CodeQL run passed on Windows 11 x64 (experiment E3), its Linux, macOS and other experiments are pending, and it partially supersedes ADR-0004 for one case only.

| ADR | Decision | Status | Validation / Implementation Evidence |
| --- | --- | --- | --- |
| [0001](0001-platform-scope-and-phase-boundary.md) | Independent platform, modular core services, and CLI interface | Accepted | Fully validated across core architecture |
| [0002](0002-conditional-rust-core.md) | Safe Rust as core platform language | Accepted | Validated via Windows MSVC and Linux Docker dual-platform test suites |
| [0003](0003-local-modular-control-plane.md) | Local modular control plane and durable bounded workflows | Accepted | Validated via SQLite WAL repository and CoreService |
| [0004](0004-vm-boundary-for-untrusted-execution.md) | Disposable VM boundary for real untrusted execution | Accepted; partially superseded by ADR-0011 for opt-in CodeQL build-mode `none` analysis only | FailClosedBackend host containment enforced for every other case |
| [0005](0005-capability-scoped-process-adapters.md) | Capability-scoped out-of-process adapters and shared client services | Accepted | Validated via PluginHost and MCP stdio server |
| [0006](0006-evidence-and-independent-verification.md) | Evidence-based findings and independent patch verification | Accepted | Validated via Three-Tier Verification Invariant |
| [0007](0007-open-source-and-integration-licensing.md) | OSI license selection and integration licensing | Accepted | Apache-2.0 license and third-party notices incorporated |
| [0008](0008-recoverable-local-operations.md) | Fenced session continuation and durable dispatch/result recovery | Accepted | Validated via Schema V2, outbox state machine, and atomic resume |
| [0009](0009-verified-content-and-blob-reconciliation.md) | Immutable SHA-256 content, canonical manifests and blob reconciliation | Accepted | Validated via pure-Rust sha2, CAS BlobStore, and manifest binding |
| [0010](0010-explicit-initialization-recovery.md) | Explicit operator recovery for incomplete initialization | Accepted | Validated via LocalWorkspace::recover and sentra recover |
| [0011](0011-opt-in-host-codeql-analysis.md) | Opt-in host CodeQL analysis (build mode `none`, five languages) and CodeQL result import | Accepted (2026-11-11) | Contract tests with a fake launcher and a real CodeQL 2.27.4 run (E3, 2026-11-11) pass on Windows 11 x64; Linux and macOS runs and canary checks of the excluded extractors pending |

ADR-0001 through ADR-0010 are validated and Accepted; ADR-0011 is Accepted with pending experiments (see its last section). The official Apache-2.0 license and third-party notices have been incorporated.

## Maintenance

Each ADR states context, alternatives, decision/proposal, consequences, and required evidence. When a decision changes, preserve history and mark the old ADR superseded rather than silently rewriting the rationale. Update requirements, architecture, roadmap, and affected contracts together. Record unresolved operational details in project issue trackers or roadmap milestones.
