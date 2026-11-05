# Architecture Decision Records

ADRs record the rationale and reversal conditions for important choices. **Accepted** means an agreed Phase 0 design baseline derived from the owner's requirements; it does not mean code exists or a technology has passed experiments. **Proposed** means evidence or owner selection is still required. Neither status authorizes Phase 1.

| ADR | Decision | Status | Validation / review gate |
| --- | --- | --- | --- |
| [0001](0001-platform-scope-and-phase-boundary.md) | Independent platform, bounded pilots, documentation-only Phase 0 | Accepted | Explicit owner approval before Phase 1 |
| [0002](0002-conditional-rust-core.md) | Rust as the conditional core-language recommendation | Proposed | Phase 1 Windows/toolchain/process/storage spike |
| [0003](0003-local-modular-control-plane.md) | Local modular control plane and durable bounded workflows | Accepted | Concrete SQLite/journal/runtime choices validated in Phase 1 |
| [0004](0004-vm-boundary-for-untrusted-execution.md) | Disposable VM boundary for real untrusted execution | Accepted | Hyper-V/backend selection remains proposed until containment gates |
| [0005](0005-capability-scoped-process-adapters.md) | Capability-scoped out-of-process adapters and shared client services | Accepted | Schema conformance and MCP/API gates |
| [0006](0006-evidence-and-independent-verification.md) | Evidence-based findings and independent patch verification | Accepted | Oracle/lifecycle/evaluation corpus in Phase 2 |
| [0007](0007-open-source-and-integration-licensing.md) | OSI license selection and independent integration license review | Proposed | Owner choice and exact-version review before distribution |

## Maintenance

Each ADR states context, alternatives, decision/proposal, consequences, and required evidence. When a decision changes, preserve history and mark the old ADR superseded rather than silently rewriting the rationale. Update requirements, architecture, roadmap, progress, and affected contracts together. Record unresolved operational details in [OPEN_QUESTIONS.md](../OPEN_QUESTIONS.md).
