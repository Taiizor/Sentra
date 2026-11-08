# Phase 2 — Increment 3.0: Continuous Security Review Foundation — Implementation Report

**Status:** Completed  
**Date:** 2026-11-08  
**Scope:** Increment 3.0 — Cargo.lock / RustSec Advisory Workflow (`F-07`) & Findings Data Model (`F-05`, `F-06`, `F-10`)  
**Host Environment:** Windows 11 (PowerShell 7.6.6) & Linux Container Verification  

---

## 1. Executive Summary

Increment 3.0 introduces the core continuous security review data model and offline dependency vulnerability audit workflow for Sentra:

1. **Normalized Security Findings Domain Model (`F-05`, `F-06`, `F-10`):**
   - Implemented `Finding`, `FindingId`, `FindingStatus`, `Severity`, `Confidence`, `Reachability`, and `StatusTransitionEntry` in `crates/sentra-core/src/domain/finding.rs`.
   - Validated state transition invariants: every status mutation (`Candidate` $\rightarrow$ `Validated`, `Rejected`, `Inconclusive`) enforces a non-empty operator/verifier justification reason, permanently captured in the immutable audit trail (`history`).
   - Reachability isolation: dependencies detected from lockfiles strictly receive `Reachability::PresentOnly` per Requirement `F-07`, preventing premature claims of dynamic runtime vulnerability without verifier proof.

2. **Zero-Dependency Advisory Engine & Cargo.lock Parser (`F-07`):**
   - Safe, pure-Rust semver comparator and version requirement parser (`=, <, <=, >, >=, ^, ~`) in `crates/sentra-core/src/advisory/semver.rs`.
   - Pure-Rust `Cargo.lock` parser supporting lockfile v2/v3/v4 specifications in `crates/sentra-core/src/advisory/cargo_lock.rs`.
   - Built-in pinned advisory database with stale database detection (`is_stale`) and unparseable/unknown package isolation (`unknown_version_packages`) in `crates/sentra-core/src/advisory/database.rs`.

3. **Workspace & CLI Integration:**
   - Added `LocalWorkspace::audit_dependencies` in `crates/sentra-core/src/service/local_workspace.rs`, managing session task registration and state transitions (`Pending` $\rightarrow$ `InProgress` $\rightarrow$ `Completed`).
   - Added `sentra audit --database <file> [--workspace <dir>] [--json]` in `crates/sentra-cli/src/lib.rs` with predictable exit codes and fail-closed security.
   - All untrusted execution remains strictly fail-closed (`FailClosedBackend`).

---

## 2. Implemented Modules

### 2.1 Domain Findings (`crates/sentra-core/src/domain/finding.rs`)

- **Finding Representation:**
  - `FindingId`: Canonical typed ID with prefix tag `0x5345_4e54_5241_000a`.
  - `FindingStatus`: `Candidate`, `Validated`, `Rejected`, `Inconclusive`.
  - `Severity`: `Critical`, `High`, `Medium`, `Low`, `Informational`.
  - `Confidence`: `Confirmed`, `Tentative`, `Suspected`.
  - `Reachability`: `PresentOnly`, `ReachableCallPath`, `DemonstratedRuntime`, `BlockedByConfiguration`.
  - `FindingSource`: `CargoLockAdvisory { advisory_id, package, version }`, `StaticRule`, `Manual`.
  - `StatusTransitionEntry`: Records `from`, `to`, `reason`, and timestamp. Transition with empty justification returns `DomainError::InvalidMetadata`.

### 2.2 Advisory Database & Semver Parsing (`crates/sentra-core/src/advisory/`)

- **`semver.rs`**: Safe semantic version parsing and range expressions supporting:
  - Exact match (`=0.2.11` or `0.2.11`)
  - Bounds (`<0.2.14`, `>=1.0.0`)
  - Caret and tilde constraints (`^1.2.3`, `~1.2.0`)
  - Range conjunctions (e.g., `>=0.1.0, <0.2.14`)
- **`cargo_lock.rs`**: Safe parser extracting package records `(name, version, source)`. Captures unknown/malformed versions into `unknown_version_packages` without aborting or crashing.
- **`database.rs`**: Holds pinned RustSec advisories (including reference CVEs `RUSTSEC-2021-0145` and `RUSTSEC-2020-0071`). Detects stale database conditions when evaluated beyond the staleness threshold (default 30 days). Produces candidate findings with `Reachability::PresentOnly`.

### 2.3 CLI & Local Workspace (`sentra-cli` & `local_workspace.rs`)

- **Command Syntax:**
  ```text
  sentra audit --database <file> [--workspace <directory>] [--json]
  ```
- **CLI Outputs:**
  - JSON mode: Machine-readable payload containing `session_id`, `task_id`, `packages_audited`, `vulnerable_packages`, `is_stale`, `unknown_version_packages`, `findings`, and `untrusted_execution: false`.
  - Human mode: Structured summary with severity tags, reachability tags, and status.
- **Task Lifecycle:**
  - Automatically records a task in SQLite persistence (`create_task`), transitions through `TaskState::Pending` $\rightarrow$ `TaskState::InProgress` $\rightarrow$ `TaskState::Completed`.

---

## 3. Verification & Test Evidence

### 3.1 Advisory Integration Tests (`crates/sentra-core/tests/advisory_tests.rs`)

- `test_semver_parsing_and_comparisons`: Validates version parsing and comparator logic.
- `test_version_requirements_and_ranges`: Validates range matching and exclusions.
- `test_cargo_lock_parsing`: Validates lockfile extraction.
- `test_f07_affected_package_creates_present_only_finding`: Verifies vulnerable packages generate candidate findings with `Reachability::PresentOnly`.
- `test_f07_unaffected_package_produces_zero_findings`: Verifies patched versions generate 0 findings.
- `test_f07_stale_advisory_database_detected`: Validates `is_stale` flag when database age exceeds limit.
- `test_f07_unknown_version_handling`: Validates quarantine of non-semver versions.
- `test_f06_finding_status_transitions_with_reason`: Validates rejection of empty justification reasons and preservation of transition history.
- `test_finding_serialization_roundtrip`: Validates JSON serialization and deserialization.
- `test_local_workspace_audit_dependencies_integration`: End-to-end workspace initialization, dependency audit, task recording, and findings generation.

### 3.2 CLI Binary Tests (`crates/sentra-cli/tests/cli_tests.rs`)

- `binary_audit_reports_cargo_lock_vulnerabilities`: Verifies `sentra audit` JSON and human-readable outputs against vulnerable fixtures.
- `binary_audit_uninitialized_database_fails_closed`: Verifies exit code 6 (`incomplete_storage`) on uninitialized databases.
- `binary_audit_parses_arguments`: Verifies CLI argument grammar and flag combinations.

---

## 4. Invariants & Safety Constraints

- `#![forbid(unsafe_code)]` enforced across both `sentra-core` and `sentra-cli`.
- Zero compiler warnings (`clippy::all` denied).
- Target execution remains fail-closed (`FailClosedBackend`).
- Permanent Git policy respected: working-tree modifications only, zero commits/pushes.
