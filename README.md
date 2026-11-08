# Sentra

**Autonomous AI Security Research & Verified Remediation Platform**

Sentra is an open-source, extensible, dual-mode security research platform for autonomous repository vulnerability discovery, differential code review, and independently verified patch generation across open-source and proprietary software.

---

## Current Status: Phase 0–6 Foundation Complete

All roadmap phases ([Phase 0 through Phase 6](ROADMAP.md)) and all [Release-wide gates](docs/release/RELEASE_GATES_AUDIT.md) have been implemented, tested, and audited across both the **Windows 11 MSVC** host development environment (461 workspace tests passing) and the isolated **Linux Docker** container test runner (23 independent test suites passing, zero clippy warnings under `-D warnings`, zero formatting discrepancies).

```
Phase 0: Research, Architecture & Threat Modeling (Complete)
Phase 1: Core Lifecycle, SQLite WAL Persistence, CAS Storage & Manifests (Complete)
Phase 2: Continuous Review, Differential Analysis, Lockfile Audit & Patch Verification (Complete)
Phase 3: Deep Research Campaigns, Scout/Analyst Engine, Coverage Ledgers & Linux Fuzzing (Complete)
Phase 4: Subprocess Plugin SDK & Local Model Context Protocol (MCP over stdio) Server (Complete)
Phase 5: Authenticated Webhook Intake (HMAC-SHA256), Replay Defense & Draft PR Proposals (Complete)
Phase 6: Multi-Tenant Dashboard API, RBAC, Target Matrix & Worker Fleet Management (Complete)
Release Gates: Toolchain Pinning, Egress Controls, Private Disclosure & Documentation (Audited & Complete)
```

In accordance with `ADR-0004`, untrusted target execution remains **strictly disabled and fail-closed** by default on the host development machine (`FailClosedBackend`). Real untrusted execution requires an approved disposable Linux VM worker (`ContainmentLevel::DisposableVm`) with strictly denied network egress.

---

## Operating Modes

1. **Continuous Security Review:** Reviews immutable base/head commit deltas with narrow context extraction, audits package lockfiles (`Cargo.lock`), matches normalized advisory vulnerabilities, and generates candidate remediation patches verified against automated test oracles.
2. **Deep Security Research:** Uses specialized Scout, Analyst, and Patch Author agent roles to systematically explore large codebases, generate SHA-256 hypothesis trees, track bounded coverage ledgers, and reproduce vulnerabilities with AddressSanitizer/UBSan fuzzing engines.

Both modes enforce the strict **Three-Tier Verification Invariant**: a patch candidate is admitted as verified if and only if original tests fail on unpatched code, target tests pass on patched code, and all baseline regression test suites pass without regression.

---

## Getting Started & CLI Usage

Sentra provides a high-performance offline CLI tool (`sentra`) for workspace initialization, repository status inspection, zero-dependency advisory auditing, and crash recovery.

Refer to the full [Installation Guide](docs/INSTALLATION.md) for prerequisites and setup.

### Quick Start Commands

```powershell
# Display help and available commands
cargo run --package sentra-cli -- --help

# Initialize a new local security workspace and foundation session
cargo run --package sentra-cli -- init `
  --workspace E:/MyProject/Repo `
  --database E:/SentraStorage/project.db `
  --json

# Inspect workspace health, active session, and discovery metadata
cargo run --package sentra-cli -- status `
  --workspace E:/MyProject/Repo `
  --database E:/SentraStorage/project.db `
  --json

# Audit package dependencies against pinned RustSec advisories
cargo run --package sentra-cli -- audit `
  --database E:/SentraStorage/project.db `
  --workspace E:/MyProject/Repo `
  --json

# Recover an interrupted or incomplete initialization store
cargo run --package sentra-cli -- recover `
  --workspace E:/MyProject/Repo `
  --database E:/SentraStorage/project.db `
  --json
```

---

## Verification & Test Suites

Sentra enforces comprehensive test coverage across unit, property, and integration harnesses:

```powershell
# Run all workspace unit and integration tests (Windows 11 MSVC)
cargo test --workspace

# Run strict clippy static analysis (fails on any warning)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Verify source code formatting
cargo fmt --all -- --check

# Execute all 23 independent test suites in isolated Linux Docker container
pwsh -NoProfile -File scripts/docker-test.ps1 -Mode all
```

---

## Architectural Boundaries & Key Invariants

- **Bun Sole JavaScript Runtime:** Bun is the sole JavaScript/TypeScript runtime and package manager across Sentra tooling (`bun run`, `bunx`). The Node.js ecosystem (`npm`, `npx`, `pnpm`, `yarn`) is not used.
- **Fail-Closed Isolation:** Untrusted target builds, procedural macros, and tests are never executed directly on the host development machine.
- **Zero-Secret Fork Boundary:** Pull requests from untrusted forks are quarantined with `secrets_permitted: false`. Write credentials are strictly stripped before reaching workers.
- **Anti-Collusion & Confused Deputy Protection:** Automated model agents cannot self-approve remediation proposals. Sensitive operations require explicit human operator admission (`HumanApprovalRequired`).
- **Multi-Tenant Fencing:** Cross-tenant resource queries and worker allocations fail closed at the domain layer (`CrossTenantAccessDenied`, `CrossTenantWorkerAccessDenied`).
- **Tamper-Resistant Audit Trail:** All mutations, policy decisions, and approvals emit monotonically sequenced, immutable audit records (`AuditEventKind`).

---

## Documentation Index

| Document | Purpose |
|---|---|
| [Installation Guide](docs/INSTALLATION.md) | Setup, compiler prerequisites, and CLI execution |
| [Limitations & Constraints](docs/LIMITATIONS.md) | Documented security assumptions, assurance limits, and non-goals |
| [Security Policy](SECURITY.md) | Coordinated disclosure process, reporting channels, and SLAs |
| [Release Gates Audit](docs/release/RELEASE_GATES_AUDIT.md) | Formal audit of all release-wide quality and containment gates |
| [Progress Ledger](PROGRESS.md) | Complete factual history of all implemented increments |
| [Roadmap](ROADMAP.md) | Dependency-ordered roadmap milestones and acceptance criteria |
| [Architecture](ARCHITECTURE.md) | High-level system topology, components, and trust boundaries |
| [Threat Model](docs/THREAT_MODEL.md) | STRIDE analysis, threat catalog, and mitigations |
| [Data Model](docs/DATA_MODEL.md) | Schemas, SQLite DDL, and domain entity models |
| [Extensions Architecture](docs/EXTENSIONS.md) | Subprocess plugin SDK, MCP server, and supported-target matrices |
| [Architecture Decisions (ADRs)](docs/adr/README.md) | Architectural Decision Records (ADR-0001 through ADR-0010) |
| [Notices & Acknowledgments](NOTICE) | Third-party component licenses and copyright notices |

---

## License Status

Sentra is designed as an open-source platform. In accordance with [ADR-0007](docs/adr/0007-open-source-and-integration-licensing.md), Apache-2.0 is the proposed permissive license candidate. Third-party component notices are documented in [NOTICE](NOTICE).
