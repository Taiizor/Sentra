# Sentra

**Autonomous AI Security Research & Remediation Platform**

Sentra is a planned independent, extensible platform for authorized security research on open-source and proprietary software. It will combine specialized AI agents, established analysis tools, isolated execution, evidence management, and independently verified remediation.

**Status: Phase 0 complete; Phase 1 foundation in progress.** The Core library provides session/policy, metadata-only workspace, SQLite and synthetic service foundations. [Increment 6.1](docs/phase1/INCREMENT_6_1_LOCAL_CLI_FOUNDATION.md) adds an offline CLI for local initialization, status and session inspection on Windows x64/MSVC. Scanning, real providers and VM workloads are unavailable; untrusted execution remains fail-closed. Physical storage faults, power loss, blob reconciliation and external-effect recovery remain unvalidated. Phase 1 is incomplete; Increment 6.2 and Phase 2 have not started. See the [Phase 1 execution record](docs/phase1/README.md).

## Local CLI foundation

Use an explicitly selected workspace and an existing, protected local storage directory **outside** that workspace. These example paths must already exist; no source repository is built or scanned by these commands.

```powershell
cargo run --offline --package sentra-cli -- --help
$context = cargo run --offline --package sentra-cli -- init --workspace E:/AuthorizedProject --database E:/SentraData/project.db --json | ConvertFrom-Json
cargo run --offline --package sentra-cli -- status --workspace E:/AuthorizedProject --database E:/SentraData/project.db --json
cargo run --offline --package sentra-cli -- session show $context.session_id --workspace E:/AuthorizedProject --database E:/SentraData/project.db --json
```

The first command builds trusted Sentra code through the cached development toolchain. The binary is named `sentra`; installation/distribution is not implemented. A dedicated database contains one foundation session whose ID is also the local project identity. Repeating `init` preserves that identity. `status`/`session` do not create databases or change domain records; SQLite recovery, lock files and checkpointing can change physical storage files. An uninitialized status exits with code 3; errors have distinct nonzero codes. No execution, scanning, approval or provider commands exist. Full behavior, JSON and error contracts are in the [increment report](docs/phase1/INCREMENT_6_1_LOCAL_CLI_FOUNDATION.md).

### Inspection storage permissions

`sentra status` and `sentra session show` are **domain-state read-only**, not physically read-only inspection tools. Use writable, protected local storage even for these commands; do not expect forensic/read-only-media access or unchanged database file bytes.

| Layer | Current inspection behavior |
| --- | --- |
| Domain-state immutability | Does not change session/snapshot, approval, audit, budget or migration records. No permission to execute, export or modify target content follows from inspection. |
| Logical SQL write behavior | Reads existing domain records and validates the existing schema; does not issue domain INSERT/UPDATE/DELETE or persistent DDL against a supported existing store. It still uses managed `BEGIN IMMEDIATE` transactions and initialization/verification PRAGMAs, not a read-only SQL connection. |
| SQLite recovery/checkpoint side effects | Opens existing SQLite with `SQLITE_OPEN_READ_WRITE`. WAL recovery/checkpoint processing may apply pending **committed** frames to the main database. Normal CLI shutdown attempts `PRAGMA wal_checkpoint(TRUNCATE)` before closing; errors are surfaced. This can change `.db` bytes and truncate `-wal`; uncommitted data is not promoted to committed state. |
| Filesystem and lock metadata effects | May create/open `<database>.local-context.lock` with read-write access. SQLite may create/update `-shm` and other coordination files. Filesystem timestamps, directory and lock metadata may change. The admission file can be created even when the database is absent and status reports uninitialized. |

Write access to the database and sufficient storage-directory permissions may therefore be required. Read-only media or inadequate permissions may cause `storage_or_service_failure` (exit **5**); path/parent validation can fail earlier with exit **4**. There is no automatic read-only fallback, repair or permission change.

Interrupted `init` can leave incomplete initialization (`incomplete_storage`, exit **6**, or a storage failure, exit **5**). Preserve the original database and WAL/SHM/journal recovery set; do not treat these errors as instructions to delete or overwrite files. No recovery command exists. The [crash-window analysis and future alternatives](docs/phase1/INCREMENT_6_1_2_STORAGE_SEMANTICS_DOCUMENTATION.md#incomplete-initialization-and-current-recovery-behavior) track atomic staging versus explicit operator recovery as an unresolved pre-Phase-2 readiness gate. Stores with multiple sessions are currently rejected fail-closed; project identity remains the single foundation SessionId.

## Two operating modes

- **Continuous Security Review:** review an immutable base/head change with surrounding context, validate candidate findings, and prepare remediation proposals. Local Git input comes before hosted pull-request automation.
- **Deep Security Research:** use Scout and Analyst roles to prioritize a larger codebase, investigate hypotheses, reproduce vulnerabilities, assess impact, and develop fixes in bounded research campaigns.

Both modes use the same policy, evidence, execution, and verification services. An AI claim or scanner alert alone does not constitute a verified vulnerability. A passing scanner does not prove a patch is correct.

## Intended initial scope

The first implementation milestone is a Windows 11 CLI and reusable core with project discovery, immutable inputs, policy decisions, local persistence, and resumable sessions. The first useful review release follows in Phase 2: a narrow Rust source-review pilot, Cargo.lock advisory analysis, a provider adapter, and reference validation on a dedicated Linux VM worker. A bounded Linux C/C++ fuzzing pilot for deep research follows in Phase 3.

The broader workflows remain targets beyond the implemented local foundation. Rust is the recommended core language pending the full Phase 1 validation gate. Bun is the sole runtime and package manager for any Sentra-owned JavaScript/TypeScript tooling. Optional analysis workers may require their own non-JavaScript runtimes.

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
