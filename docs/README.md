# Sentra Documentation Index

Welcome to the **Sentra** technical documentation. Sentra is an open-source, extensible, dual-mode security research platform for autonomous repository vulnerability discovery, differential code review, and independently verified remediation.

All core crates (`crates/sentra-core`, `crates/sentra-cli`) and the web operations dashboard (`web/`) are implemented under `#![forbid(unsafe_code)]` and verified across Windows 11, Linux, and macOS platforms.

---

## 1. Primary Architecture & System Specifications

These specifications describe Sentra's runtime architecture, operating modes, data structures, and security containment boundaries:

| Specification | Scope & Focus |
| :--- | :--- |
| [**Architecture Overview**](ARCHITECTURE.md) | High-level system topology, core services, and trust boundaries. |
| [**Installation & Quick Start**](INSTALLATION.md) | Setup, compiler prerequisites, build instructions, and CLI usage. |
| [**Operating Modes**](OPERATING_MODES.md) | Detailed workflows for Continuous Security Review and Deep Research. |
| [**Threat Model**](THREAT_MODEL.md) | Assets, threat catalog (STRIDE), permission gates, and fail-closed isolation. |
| [**Limitations & Constraints**](LIMITATIONS.md) | Documented security assumptions, assurance limits, and non-goals. |
| [**Data Model**](DATA_MODEL.md) | SQLite schema, domain entities (Findings, Evidence, Approvals, Patches). |
| [**Extensions & Fleet Management**](EXTENSIONS.md) | Subprocess plugin SDK, Model Context Protocol (MCP), and target matrices. |
| [**Agent Model**](AGENT_MODEL.md) | Multi-role autonomous agent architecture (Scout, Analyst, Patch Author). |
| [**Architectural Decisions (ADRs)**](adr/README.md) | Formal records of accepted design decisions (ADR-0001 through ADR-0010). |
| [**Security Policy**](../SECURITY.md) | Vulnerability disclosure policy, private reporting channels, and SLAs. |

---

## 2. Formal Verification & Security Audit Archive

Sentra adheres to strict, evidence-based security engineering. The directories below preserve the independent review reports, verification evidence, and quality audit trails produced across Sentra's delivery gates:

| Verification Stage | Scope & Audited Deliverables |
| :--- | :--- |
| [**Phase 1: Local Foundation**](phase1/README.md) | SQLite WAL persistence, content-addressed storage, workspace boundaries, and CLI bootstrap. |
| [**Phase 2: Continuous Review**](phase2/README.md) | Base/head differential review, POSIX cross-platform parity, zero-dependency lockfile audit, and 3-tier patch verification. |
| [**Phase 3: Deep Security Research**](phase3/PHASE3_FINAL_VERIFICATION.md) | Autonomous campaign engine, Scout/Analyst task fanout, coverage ledgers, and Linux fuzzing integration. |
| [**Phase 4: Extensions & Integrations**](phase4/PHASE4_FINAL_VERIFICATION.md) | Capability-fenced subprocess plugin SDK and JSON-RPC 2.0 Model Context Protocol (MCP) server. |
| [**Phase 5: Managed Deployment**](phase5/PHASE5_FINAL_VERIFICATION.md) | HMAC-SHA256 authenticated webhook intake, replay attack defense, and human-gated PR proposals. |
| [**Phase 6: Enterprise Operations**](phase6/PHASE6_FINAL_VERIFICATION.md) | Multi-tenant session isolation, RBAC permissions, supported-target matrices, and worker fleet leasing. |
| [**Release-Wide Gates Audit**](release/RELEASE_GATES_AUDIT.md) | Comprehensive cross-platform audit of toolchain pinning, network egress controls, and evidence integrity. |

---

## 3. Contributing and Governance

- **Contributor & Agent Guidelines:** Refer to [AGENTS.md](../AGENTS.md) and [CONTRIBUTING.md](../CONTRIBUTING.md) for coding standards, safe Rust invariants, and PR guidelines.
- **Community Standards:** Adhere to the [Code of Conduct](../CODE_OF_CONDUCT.md).
- **Release History:** Refer to [CHANGELOG.md](../CHANGELOG.md) for published release versions and milestone changes.
