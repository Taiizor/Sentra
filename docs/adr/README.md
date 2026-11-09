# Architecture Decision Records

ADRs record the architectural rationale, context, and validation conditions for foundational design choices across the Sentra platform. All records below (ADR-0001 through ADR-0010) are Accepted and empirically validated.

| ADR | Decision | Status | Validation / Implementation Evidence |
| --- | --- | --- | --- |
| [0001](0001-platform-scope-and-phase-boundary.md) | Independent platform, modular core services, and CLI interface | Accepted | Fully validated across core architecture |
| [0002](0002-conditional-rust-core.md) | Safe Rust as core platform language | Accepted | Validated via Windows MSVC and Linux Docker dual-platform test suites |
| [0003](0003-local-modular-control-plane.md) | Local modular control plane and durable bounded workflows | Accepted | Validated via SQLite WAL repository and CoreService |
| [0004](0004-vm-boundary-for-untrusted-execution.md) | Disposable VM boundary for real untrusted execution | Accepted | FailClosedBackend host containment permanently enforced |
| [0005](0005-capability-scoped-process-adapters.md) | Capability-scoped out-of-process adapters and shared client services | Accepted | Validated via PluginHost and MCP stdio server |
| [0006](0006-evidence-and-independent-verification.md) | Evidence-based findings and independent patch verification | Accepted | Validated via Three-Tier Verification Invariant |
| [0007](0007-open-source-and-integration-licensing.md) | OSI license selection and integration licensing | Accepted | Apache-2.0 license and third-party notices incorporated |
| [0008](0008-recoverable-local-operations.md) | Fenced session continuation and durable dispatch/result recovery | Accepted | Validated via Schema V2, outbox state machine, and atomic resume |
| [0009](0009-verified-content-and-blob-reconciliation.md) | Immutable SHA-256 content, canonical manifests and blob reconciliation | Accepted | Validated via pure-Rust sha2, CAS BlobStore, and manifest binding |
| [0010](0010-explicit-initialization-recovery.md) | Explicit operator recovery for incomplete initialization | Accepted | Validated via LocalWorkspace::recover and sentra recover |

All Architectural Decision Records (ADR-0001 through ADR-0010) are now fully validated and Accepted. The official Apache-2.0 license and third-party notices have been incorporated.

## Maintenance

Each ADR states context, alternatives, decision/proposal, consequences, and required evidence. When a decision changes, preserve history and mark the old ADR superseded rather than silently rewriting the rationale. Update requirements, architecture, roadmap, and affected contracts together. Record unresolved operational details in project issue trackers or roadmap milestones.
