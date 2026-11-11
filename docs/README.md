# Sentra Documentation Index

Welcome to the **Sentra** technical documentation. Sentra is an open-source, local-first security review toolkit: heuristic SAST pattern rules, lockfile inventory and sample-based dependency auditing, differential snapshot comparison, positional patch application, and a web console that reads the core CLI. Model output and scanner results are unverified candidates; no independent patch verifier or worker fleet exists yet (see [LIMITATIONS](LIMITATIONS.md)).

The Rust crates (`crates/sentra-core`, `crates/sentra-cli`, `crates/sentra`) are built under `#![forbid(unsafe_code)]`. CI builds and tests them on Windows, Linux and macOS; the web console (`web/`, TypeScript on Bun) has been exercised on a real Windows 11 x64 host only (see [web/README.md](../web/README.md)).

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
| [**Architectural Decisions (ADRs)**](adr/README.md) | Formal records of accepted design decisions (ADR-0001 through ADR-0011). |
| [**Security Policy**](../SECURITY.md) | Vulnerability disclosure policy, private reporting channels, and SLAs. |

---

## 2. Release & Verification Quality

Release gates and their current status are recorded, including the gates that are not met (for example, adapter network egress is declared but not enforced, and no worker fleet exists):

- [**Release-Wide Gates Audit**](RELEASE_GATES_AUDIT.md) — The 2026-11-08 gate audit with its dated 2026-11-11 correction: toolchain pinning, egress, containment and evidence integrity.
- [**Architectural Decisions (ADRs)**](adr/README.md) — Formal records of accepted design decisions (ADR-0001 through ADR-0011).

---

## 3. Contributing and Governance

- **Contributor & Agent Guidelines:** Refer to [AGENTS.md](../AGENTS.md) and [CONTRIBUTING.md](../CONTRIBUTING.md) for coding standards, safe Rust invariants, and PR guidelines.
- **Community Standards:** Adhere to the [Code of Conduct](../CODE_OF_CONDUCT.md).
- **Release History:** Refer to [CHANGELOG.md](../CHANGELOG.md) for published release versions and milestone changes.
