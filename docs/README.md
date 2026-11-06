# Documentation Index

Sentra is in Phase 1, with Core library, SQLite, synthetic service and [initial local CLI foundations](phase1/INCREMENT_6_1_LOCAL_CLI_FOUNDATION.md). Real providers, untrusted execution and full recovery remain unavailable; Phase 1 is incomplete and Phase 2 is not authorized. Start with the root [README](../README.md), [vision](../VISION.md), [requirements](../REQUIREMENTS.md), [architecture](../ARCHITECTURE.md), and [roadmap](../ROADMAP.md).

The [5.3.1 approval-binding review](phase1/INCREMENT_5_3_1_SECURITY_REVIEW.md) records the current correction to the historical approval defect and its remaining integration limits.

| Specification | Scope |
| --- | --- |
| [Operating modes](OPERATING_MODES.md) | Continuous review and deep-research workflows |
| [Agent model](AGENT_MODEL.md) | Responsibilities, capabilities, messages, and independence |
| [Data model](DATA_MODEL.md) | Sessions, tasks, findings, evidence, approvals, and patches |
| [Threat model](THREAT_MODEL.md) | Assets, adversaries, permission gates, and containment |
| [Extensions](EXTENSIONS.md) | Adapter contracts, versioning, packaging, and MCP boundary |
| [Validation](VALIDATION.md) | Technical spikes, evaluation design, and release evidence |
| [Open questions](OPEN_QUESTIONS.md) | Assumptions, owner roles, decision gates, and safe defaults |
| [Review record](REVIEW.md) | Phase 0 consistency and documentation checks |
| [Phase 1 execution record](phase1/README.md) | Rust/MSVC, SQLite and mock provider evidence, reproducibility and outstanding gates |
| [Research](research/README.md) | Existing systems, tooling, isolation, technology, and source register |
| [ADRs](adr/README.md) | Architectural decisions and proposals |

The root [AGENTS.md](../AGENTS.md) governs contributors and coding agents. The research-agent contract in [AGENT_MODEL.md](AGENT_MODEL.md) describes Sentra's planned product behavior; these are different subjects.

Design precedence: owner instructions and phase authorization; requirements/security invariants; accepted ADRs; detailed architecture/contracts; roadmap; research recommendations. A conflict must be resolved explicitly by updating the affected documents. A proposed ADR cannot override an accepted security invariant.

Terminology: **initial foundation** means Phase 1; **first review pilot** means Phase 2; **deep-research pilot** means Phase 3; **later platform interfaces** start in Phase 4. None is currently implemented.
