# Sentra

**Autonomous AI Security Research & Remediation Platform**

Sentra is a planned independent, extensible platform for authorized security research on open-source and proprietary software. It will combine specialized AI agents, established analysis tools, isolated execution, evidence management, and independently verified remediation.

**Status: Phase 0 complete; Phase 1 technical validation in progress.** The isolated Rust/MSVC x64 probe has passed. SQLite is the owner-approved persistence candidate, with [remaining reliability/integration gaps](docs/phase1/SQLITE_VALIDATION.md). The [Milestone 3 mock provider contract report](docs/phase1/PROVIDER_VALIDATION.md) is ready for review: 62 tests pass twice without external services. The Core Engine, product CLI, production persistence, scanner, sandbox, API and real provider integrations are not implemented. Phase 1 is not complete; Phase 2 has not started. See the [Phase 1 execution record](docs/phase1/README.md).

## Two operating modes

- **Continuous Security Review:** review an immutable base/head change with surrounding context, validate candidate findings, and prepare remediation proposals. Local Git input comes before hosted pull-request automation.
- **Deep Security Research:** use Scout and Analyst roles to prioritize a larger codebase, investigate hypotheses, reproduce vulnerabilities, assess impact, and develop fixes in bounded research campaigns.

Both modes use the same policy, evidence, execution, and verification services. An AI claim or scanner alert alone does not constitute a verified vulnerability. A passing scanner does not prove a patch is correct.

## Intended initial scope

The first implementation milestone is a Windows 11 CLI and reusable core with project discovery, immutable inputs, policy decisions, local persistence, and resumable sessions. The first useful review release follows in Phase 2: a narrow Rust source-review pilot, Cargo.lock advisory analysis, a provider adapter, and reference validation on a dedicated Linux VM worker. A bounded Linux C/C++ fuzzing pilot for deep research follows in Phase 3.

These are targets, not available features. Rust is the recommended core language pending the Phase 1 validation gate. Bun is the sole runtime and package manager for any Sentra-owned JavaScript/TypeScript tooling. Optional analysis workers may require their own non-JavaScript runtimes.

Ghidra, Frida, Windows-native target execution, additional language packs, MCP, API, dashboard, GitHub/GitLab automation, and a public plugin registry belong to later milestones. No universal language or operating-system coverage is claimed.

## Documentation

| Document | Purpose |
| --- | --- |
| [Vision](VISION.md) | Identity, users, boundaries, and product outcomes |
| [Requirements](REQUIREMENTS.md) | Testable functional and security requirements |
| [Architecture](ARCHITECTURE.md) | Components, trust boundaries, and execution flow |
| [Roadmap](ROADMAP.md) | Dependency-ordered phases and measurable gates |
| [Security](SECURITY.md) | Security posture and disclosure status |
| [Agent instructions](AGENTS.md) | Rules for contributors and coding agents |
| [Progress](PROGRESS.md) | Completed work, review evidence, and pending gates |
| [Documentation index](docs/README.md) | Detailed contracts and threat model |
| [Research](docs/research/README.md) | Source-backed comparisons and environment observations |
| [Architecture decisions](docs/adr/README.md) | Decisions, alternatives, and unresolved proposals |

Research was checked on **2026-11-05**. External capabilities, licenses, and protocol versions must be rechecked when an integration is implemented. The supplied Vercel inspiration URL was unavailable during research; its [canonical article](https://vercel.com/blog/vercel-security-review) was reviewed instead.

## Authorization and privacy

Sentra's design requires a recorded authorization scope, bounded permissions, and explicit approval for sensitive actions. Private repositories are first-class inputs; local operation does not authorize source-code transfer to a hosted model. Untrusted builds, tests, and generated proofs of concept require an approved isolation profile.

## License status

Sentra is intended to be open source. The owner has not yet selected an OSI-approved license, and no license grant is implied by this documentation. Apache-2.0 is a proposal recorded in [ADR-0007](docs/adr/0007-open-source-and-integration-licensing.md). License selection and third-party notice review are public-release gates.
