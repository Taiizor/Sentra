# Phase 4 — Increment 5.0: Subprocess Plugin SDK & Versioned Adapter Protocol — Implementation Report

**Status:** Completed  
**Date:** 2026-11-08  
**Scope:** Increment 5.0 — Subprocess Plugin SDK, Versioned Message Protocol (`F-16`), Capability Fencing, Quota Boundaries (`S-06`), Replay Protection (`S-02`), and Conformance Suite (Roadmap Phase 4).  
**Host Environment:** Windows 11 (PowerShell 7.6.6) & Linux Docker Container Verification (`scripts/docker-test.ps1`).  

---

## 1. Executive Summary

Increment 5.0 delivers the subprocess plugin architecture, versioned adapter protocol, and conformance test harness required by Phase 4 ("Extensibility and external-agent access"):

1. **Packaging Manifests & Adapter Families (`F-16`, EXTENSIONS.md):**
   - Implemented `PluginManifest`, `AdapterFamily`, `PluginCapability`, and `PluginQuotas` in `crates/sentra-core/src/plugin/manifest.rs`.
   - Covers all 6 defined adapter families: `LanguageFramework`, `AnalysisTool`, `AiProvider`, `ExecutionBackend`, `ResearchSystem`, and `ExportImport`.
   - Mandates explicit capability declarations (`SourceDiscovery`, `DependencyAudit`, `StaticAnalysis`, `FuzzExecution`, `PatchGeneration`, `Custom`). Undeclared capabilities are strictly rejected.

2. **Framed Message Protocol & Transport Schema (`F-16`):**
   - Implemented `PluginRequest`, `PluginResponse`, `encode_frame`, and `decode_frame` in `crates/sentra-core/src/plugin/protocol.rs`.
   - Implements bounded newline-delimited JSON framing:
     - Newline sanitization: embedded carriage returns/newlines are eliminated from JSON payloads.
     - Frame size validation: frames exceeding `max_frame_bytes` are rejected with `OutputQuotaExceeded`.
   - Standardized operations: `Initialize`, `Probe`, `Plan`, `Execute`, `Cancel`, `Shutdown`.

3. **Host Supervisor & Conformance Fencing (`PluginHost`, `S-02`, `S-06`):**
   - Implemented `PluginHost` in `crates/sentra-core/src/plugin/host.rs` managing adapter lifecycles (`Uninitialized`, `Ready`, `Executing`, `Terminated`, `Quarantined`).
   - Enforces 5 security gates:
     - **Gate 1 (Version Compatibility):** Rejects interface version mismatches (`IncompatibleInterfaceVersion`) and quarantines the plugin.
     - **Gate 2 (Capability Clearance):** Rejects undeclared capabilities during both initialization and execution dispatch (`UndeclaredCapability`).
     - **Gate 3 (Replay Protection):** Prevents duplicate execution dispatches for the same task ID (`ReplayRejected`).
     - **Gate 4 (Output Quotas):** Tracks frame size and cumulative byte ceilings, quarantining processes that exceed thresholds (`OutputQuotaExceeded`).
     - **Gate 5 (Crash Containment):** Catches non-zero or signal terminations cleanly (`ProcessCrashDetected`) without compromising host stability.

4. **Reference Conformance Adapter (`SampleAdapter`):**
   - Implemented `SampleAdapter` in `crates/sentra-core/src/plugin/sample_adapter.rs`.
   - Supports standard conformant operation and 4 adversarial test modes (`IncompatibleVersion`, `UndeclaredCapability`, `OversizedOutput`, `CrashDuringExecution`).

---

## 2. Verification Evidence

### 2.1 Plugin Conformance Suite (`crates/sentra-core/tests/plugin_tests.rs`)

1. `test_plugin_manifest_validation`: Validates required manifest fields and rejects empty IDs, empty paths, or zero quotas.
2. `test_plugin_handshake_standard_conformance`: Proves successful handshake negotiation and transition to `Ready`.
3. `test_plugin_incompatible_version_rejection`: Proves rejection and quarantine when an adapter declares an incompatible interface version (v999 vs v1).
4. `test_plugin_undeclared_capability_rejection`: Proves rejection and quarantine when an adapter attempts to return an undeclared capability.
5. `test_plugin_dispatch_and_execution_lifecycle`: Exercises the complete lifecycle: `Probe` $\rightarrow$ `Plan` $\rightarrow$ `Execute` $\rightarrow$ `Complete`.
6. `test_plugin_undeclared_capability_at_dispatch_rejected`: Proves rejection when an execution job demands a capability not declared in the manifest.
7. `test_plugin_replay_protection`: Proves rejection of duplicate task execution dispatches under identical task IDs.
8. `test_plugin_oversized_frame_quota_rejection`: Proves detection and quarantine when an adapter emits an output frame exceeding the 1 MiB limit.
9. `test_plugin_process_crash_handling`: Verifies clean detection and typed error handling when a plugin subprocess crashes (SIGSEGV / exit code 139).
10. `test_plugin_protocol_frame_encoding_and_decoding`: Verifies single-line newline JSON encoding, roundtrip decoding, and frame bounds.
11. `test_plugin_prompt_injection_containment`: Proves that adversarial command injection payloads in arguments are strictly parsed as passive data without code execution.

---

## 3. Dual-Platform Validation

- **Windows 11 MSVC Host:** All 11 plugin integration tests passed in 0.01s. Total workspace test suite: **418 tests passed, 0 failed, 3 ignored, 7 compile-fail doctests passed**.
- **Clippy:** Passed `--workspace --all-targets --all-features -- -D warnings` with zero warnings.
- **Formatting:** Passed `cargo fmt --all -- --check`.
- **Linux Docker Container (`scripts/docker-test.ps1 -Mode all`):** 19 independent test suites executed under `#![forbid(unsafe_code)]`.
