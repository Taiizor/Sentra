# ADR-0009: Verified Immutable Content and Blob Reconciliation

- Status: **Proposed**
- Date: 2026-11-07
- Decision owners: Core evidence, Windows platform, dependency/license and security owners
- Extends: ADR-0003 and ADR-0006; complements Proposed ADR-0008

## Context

F-01/F-02 require an authorized immutable source snapshot and canonical session manifest before planning. The original Phase 1 recovery criterion includes blob promotion. Current evidence validates structural bounds in memory, has no available cryptographic verifier and has no persistent blob/reference ledger. Current workspace validation does not establish stable race-free content-open identity.

[REMEDIATION_ARCHITECTURE](../phase1/REMEDIATION_ARCHITECTURE.md) sections 5–6 and 10 define the candidate contracts. SHA-256 and safe Windows content/publication primitives remain blocked prerequisites, not implemented guarantees. Phase 1 remains NOT APPROVED. This proposal adds no dependency or custom cryptography.

## Decision drivers

- Bind actual immutable bytes to scope, session, classification, policy and operation without executing repository tools.
- Recover partial writes, promotion/reference gaps and cleanup safely; SQL and filesystem mutations are not one transaction.
- Preserve pending/live reference reachability under concurrent promotion and GC.
- Avoid replacing SHA-256 with the canonical action identifier or migration drift checksum.
- Preserve `forbid(unsafe_code)` in Sentra and explicitly audit dependency internals and Windows assumptions.

## Considered alternatives

1. Store only caller paths/revision/digest labels: rejected; mutable paths and unverified digests do not identify immutable bytes.
2. Put all payloads in SQLite: could simplify a subset of atomicity but changes the accepted metadata-plus-blob baseline and does not solve safe source acquisition/crypto. No architectural justification to replace storage here.
3. Core-owned bounded streamed CAS with verified SHA-256, versioned canonical manifests and explicit reconciliation: proposed.
4. Use weak hashes/custom SHA-256/unsafe FFI or unchecked rename to meet the schedule: rejected.

## Proposed decision

Adopt alternative 3 only after safe filesystem and audited dependency gates pass. SHA-256 over raw bytes plus verified length identifies blobs; classification/authorization remain separate. Core-generated staging/object locators live on protected local storage outside the workspace. Equal content does not grant cross-session access or disclose classified existence.

Persist ownership/quota/pending-reference intent before bounded staged writes. Compute the approved SHA-256 while streaming, validate length, complete the required flush/close verification and persist promotion intent. Publish with a proven same-filesystem no-replace mechanism. Verify any existing destination's actual bytes/identity before authorized deduplication. Persist Ready without dropping the pending pin; convert pending to live references in the input/result transaction. Crash gaps are reconciled, not treated as atomic SQL/file operations.

Reconciliation distinguishes partial/unverified, verified/promotion-pending, Ready-pinned, live, orphan, dangling and corrupt data. Missing/corrupt referenced bytes make affected records unavailable; do not erase references to hide failures. GC requires owned provenance, all-store live/pending/retention/backup reachability, a conditional deletion claim and held mutation guard/fence excluding attachment. Age/lease expiry alone never proves safe deletion. Startup pruning is restricted to proven eligible orphans under approved retention policy.

Freeze an input/session manifest before planning, and a separate operation manifest before admission. Proposed SCF-1 framing uses domain/schema version, deterministic tagged length-prefixed fields, explicit option tags/counts, checked integers/no floats, specified ordering and duplicate/noncanonical rejection. Preserve argument order and exact supported path semantics; reject ambiguous/lossy names rather than silently normalize. Independently specified digest domains bind canonical manifest bytes, not unspecified JSON order. Exact test vectors precede implementation.

The minimum model includes actual content references/digests, classification, revision/dirty status, scope/exclusions, roots/manifests/languages/unsupported components, operator/authorization reference, policy/context generations, budgets, backend/tool version/configuration and session/operation/attempt/result correlation. Metadata discovery is not arbitrary content-read authorization. New immutable-input binding invalidates old context/grants when bytes/configuration change.

## Security implications

Content integrity is separate from authorization, producer provenance and semantic correctness. A valid SHA-256 cannot establish a true vulnerability or trusted worker. Existing action_digest remains a non-cryptographic canonical identity. Legacy approvals without the new input binding cannot acquire it by default.

Reparse points, symlinks, junctions, aliases, path changes and unsupported filesystem identities fail closed. No check-then-open/string-prefix fallback, host helper execution or unsafe Sentra FFI is permitted. Locks protect cooperating actors only; current std capabilities do not prove strong identity or power-loss durability. Complex/native target-facing parsing remains isolated under ADR-0004; no target execution is enabled.

## Compatibility implications

Input/blob/reference/pin/retention records require reviewed versioned migration alongside ADR-0008, not ad hoc extra v1 tables. Existing structural-only evidence remains explicitly structural; do not relabel it SHA-verified or invent missing bytes/provenance. Unknown/legacy manifests remain unavailable for new execution until explicitly rebound from verified input. No project/multi-session expansion is implied.

Canonicalization and hash algorithm are versioned. Reject unsupported required versions; do not silently reinterpret a digest under another algorithm. Retain old canonical bytes and provenance for inspection. No administrator-resistant tamper guarantee is added without an external trust anchor.

## Operational consequences

Safe file identity, no-follow access, no-replace publication, flush/close and GC semantics are implementation stop gates. Standard rename replacement behavior and multi-file sidecars require specific Windows verification, not an atomicity assumption. A directory/protected-store trust profile must be explicit if selected.

No SHA-256 package was found in the inspected local registry cache. Cached getrandom is entropy, and raw windows-sys/windows-link are not selected safe hashing/filesystem implementations. Exact version/features/transitive licenses/maintenance/security/platform audit and offline MSVC build are required before any dependency addition. No network provisioning is authorized by this ADR; no custom crypto is an alternative.

## Required verification evidence

- Approved safe same-object reads and Windows identity/no-follow/reparse/alias/race/permission/share tests; audited no-replace promotion and documented process-crash flush/publication guarantees. Physical power loss stays unverified absent separate evidence.
- Audited exact cryptographic/ID dependencies, independent SHA-256 vectors, chunking/bounds/empty/large input, same-length corruption and manifest canonicalization collision/ambiguity fixtures.
- Real owned process kills at stage intent/create/write/flush/verification/promotion/Ready/reference/GC boundaries; repeated reconciliation retains every live/pending reference and acknowledged event.
- Competing promoters, preexisting conflicting object, hash-name substitution, missing/dangling objects, concurrent GC/reference attachment and quota/overflow/partial-write faults.
- F-01/F-02 dirty/Unicode/CRLF/case/archive/unsupported input fixtures through the actual safe boundary without Git/hooks/build/tool execution; binding and diagnostic-redaction regressions.
- Independent Windows/filesystem/evidence review; B/I/A0 cases in [the architecture](../phase1/REMEDIATION_ARCHITECTURE.md#15-required-acceptance-and-crash-recovery-evidence). These remain Not Tested here.

## Unresolved questions

- Exact safe stable-handle implementation/dependency and supported filesystem profile; current stable std lacks the assumed Windows by-handle identity methods.
- Exact atomic no-replace and durable publication/close contract, including directory metadata and sharing failures.
- Approved locally available SHA-256 and activation-ID source, maintenance/licensing evidence and provisioning authority.
- Final SCF-1 schema/test vectors, precise quota accounting/dedup confidentiality and retention/backup pin policy.

No dependent content acquisition/promotion implementation proceeds by assuming these answers. Acceptance requires explicit architectural/security review and separate implementation authorization.
