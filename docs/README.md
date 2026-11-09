# Sentra Documentation Index

Welcome to the **Sentra** technical documentation. Sentra is an open-source, extensible, dual-mode security research platform for autonomous repository vulnerability discovery, differential code review, and independently verified remediation.

All core crates (`crates/sentra-core`, `crates/sentra-cli`) and the web operations dashboard (`web/`) are implemented under `#![forbid(unsafe_code)]` and verified across Windows 11, Linux, and macOS platforms.

---

## 1. Primary Architecture & System Specifications

These specifications describe Sentra's runtime architecture, operating modes, data structures, and security containment boundaries:

| Specification | Scope & Focus |
| :--- | :--- |
| [**Architecture Overview**](../ARCHITECTURE.md) | High-level system topology, core services, and trust boundaries. |
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

## 2. Release & Verification Quality

Sentra adheres to strict, evidence-based security engineering. All core capabilities across continuous review, autonomous research, plugin extensions, and multi-tenant operations are audited against release-wide quality and containment gates:

- [**Release-Wide Gates Audit**](RELEASE_GATES_AUDIT.md) — Comprehensive cross-platform audit of toolchain pinning, network egress controls, fail-closed containment, and evidence integrity.
- [**Architectural Decisions (ADRs)**](adr/README.md) — Formal records of accepted design decisions (ADR-0001 through ADR-0010).

---

## 3. Contributing and Governance

- **Contributor & Agent Guidelines:** Refer to [AGENTS.md](../AGENTS.md) and [CONTRIBUTING.md](../CONTRIBUTING.md) for coding standards, safe Rust invariants, and PR guidelines.
- **Community Standards:** Adhere to the [Code of Conduct](../CODE_OF_CONDUCT.md).
- **Release History:** Refer to [CHANGELOG.md](../CHANGELOG.md) for published release versions and milestone changes.
