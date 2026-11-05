# ADR-0001: Independent Platform and Phase Boundary

- Status: Accepted (design baseline)
- Date: 2026-11-05
- Basis: Project-owner Phase 0 requirements

## Context

Sentra must combine continuous change review and deep research while supporting authorized public and private projects. A CLI-only script, prompt pack, or external-agent skill cannot own the complete permission, evidence, and verification contract. The owner explicitly prohibited implementation during Phase 0.

## Alternatives

1. Build an agent skill or scanner wrapper as the product.
2. Begin a broad multi-service platform immediately.
3. Specify a reusable independent core, CLI first, with gated adapters and future interfaces.

## Decision

Choose option 3. Define one product core with interface-neutral services, a local CLI, and shared policy/evidence semantics across both modes. Treat API, MCP, skills, web dashboard, GitHub/GitLab automation, and binary-analysis tools as later interfaces/integrations.

Phase 0 produces research, requirements, architecture, decision records, and reviewable documentation only. Do not create application code, technical prototypes, manifests, dependencies, commits, tags, or pushes. Explicit project-owner approval is required before Phase 1.

Initial targets are Windows control-plane foundation, a narrow Rust review/advisory pilot with Linux VM validation, then a Linux C/C++ deep-research pilot. Proprietary source is a first-class input class; arbitrary binary-only or enterprise-runtime support is not implied.

## Consequences

The initial scope is smaller than the product vision, while the architecture can serve later clients. Phase 0 can be complete with explicitly documented empirical questions. A completed document set is not a working product, implementation authorization, or validated support claim.

## Acceptance and reversal

Use the Phase 0 completion checklist in [PROGRESS.md](../../PROGRESS.md). Any scope expansion updates the requirements, roadmap, and relevant ADRs. The prohibition on Phase 1 remains until the owner's explicit instruction changes it.
