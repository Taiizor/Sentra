# ADR-0003: Local Modular Control Plane and Durable Tasks

- Status: Accepted (design baseline; concrete storage/runtime configuration unvalidated)
- Date: 2026-11-05

## Context

Both operating modes need shared input identity, policy, evidence, recovery, and independent verification. The initial user is a single local operator. A distributed service topology would introduce operational requirements before a useful review workflow exists.

## Alternatives

1. Stateless CLI with ad hoc files and model-managed coordination.
2. Mandatory workflow/database services from the start.
3. Modular reusable core with transactional local state and a small bounded task DAG.

LangGraph and Temporal offer existing workflow capabilities, and OSS-CRS offers research orchestration. Their reuse value must be compared rather than ignored. They do not automatically meet Sentra's complete local policy/evidence contract.

## Decision

Choose option 3. Keep authoritative state and permissions in deterministic core services. Use transactional task/event/outbox records, leases, bounded retries, idempotency, and reconciliation. Plan SQLite metadata plus content-addressed blobs on a local volume; select the exact library, journal mode, and durability configuration only after crash-recovery tests.

Blob promotion and database commit require reconciliation rather than pretending they form one atomic transaction. External delivery is at least once; ambiguous sensitive side effects require inspection instead of automatic replay. Keep agent prompts and transient conversations outside the authority model.

SQLite WAL's same-host/network-filesystem constraints inform the local-volume requirement; they do not settle the exact configuration.

## Consequences

The CLI can become one client of shared application services. Recovery logic must be tested early. Single-operator local storage is not a shared tenant database, and hash-linked local history is not tamper-proof against an administrator.

Keep the scheduler narrowly product-specific. Before custom deep-campaign infrastructure, test OSS-CRS reuse. Revisit a workflow service or server database when measured scale/recovery needs justify it, rather than expanding a bespoke general-purpose workflow engine.

## Validation and reversal

Phase 1 must demonstrate recovery around dispatch, blob promotion, and result commit. Phase 2 must verify backup/restore and schema migration. If local persistence cannot meet the contract, revise storage before introducing more interfaces. Distribution or multi-user hosting requires a new ADR and threat model.
