# ADR-0001: Independent Platform and Architecture Boundary

- Status: Accepted (Fully Validated)
- Date: 2026-11-05
- Basis: Core modular platform architecture

## Context

Sentra must combine continuous change review and deep research while supporting authorized public and private projects. A CLI-only script, prompt pack, or external-agent skill cannot own the complete permission, evidence, and verification contract.

## Alternatives

1. Build an agent skill or scanner wrapper as the product.
2. Begin a broad multi-service platform immediately.
3. Specify a reusable independent core, CLI first, with gated adapters and future interfaces.

## Decision

Choose option 3. Define one product core with interface-neutral services, a local CLI, and shared policy/evidence semantics across both modes. Treat API, MCP, skills, web dashboard, GitHub/GitLab automation, and binary-analysis tools as modular interfaces/integrations.

Initial targets are Windows and Linux control-plane foundations, Rust review/advisory workflows with Linux VM validation, and multi-ecosystem research. Proprietary source is a first-class input class; arbitrary binary-only or enterprise-runtime support is not implied.

## Consequences

The architecture provides a clean separation of concerns: core services, deterministic policies, durable persistence, and modular client interfaces (CLI, MCP, Web Dashboard).
