# Phase 3 — Increment 4.1: Linux User-Space C/C++ Fuzzing & Crash Reproduction Engine — Implementation Report

**Status:** Completed  
**Date:** 2026-11-08  
**Scope:** Increment 4.1 — Linux User-Space C/C++ Fuzzing Engine Integration (`F-09`), Crash Artifact & Impact Tracking (`F-10`), Patch Candidate Oracle (`F-11`), Root-Cause Input Minimization, 3 Canonical Targets, and Tri-Method Comparison Matrix (Roadmap Phase 3).  
**Host Environment:** Windows 11 (PowerShell 7.6.6) & Linux Docker Container Verification (`scripts/docker-test.ps1`).  

---

## 1. Executive Summary

Increment 4.1 delivers the Linux user-space fuzzing integration, crash reproduction, input minimization, and benchmark comparison subsystem required to satisfy Phase 3 milestones:

1. **Fuzzing Engine & Target Harness Abstraction (`F-09`):**
   - Implemented `FuzzEngine` (`LibFuzzer`, `AflPlusPlus`, `SyntheticBenchmark`), `SanitizerType` (`AddressSanitizer`, `UndefinedBehaviorSanitizer`, `MemorySanitizer`), `FuzzTarget`, and `FuzzRunConfig` in `crates/sentra-core/src/research/fuzzing.rs`.
   - Supports compiler instrumentation flags (`-fsanitize=address`, `-fsanitize=undefined`, `-fsanitize=memory`), per-run timeout ceilings, and disposable worker memory caps.

2. **Crash Artifacts & Fresh-Worker Reproduction (`F-10`, Roadmap Phase 3):**
   - Implemented `CrashArtifact` binding cryptographic input identifiers (`sha256:...`), confirmed root-cause classifications (`VulnerabilityCategory`), fatal OS signals (SIGSEGV 11, SIGABRT 6), AddressSanitizer traceback diagnostics, raw input bytes, minimized input bytes, and fresh worker reproduction verification (`reproducible_in_fresh_worker`).

3. **Hierarchical Delta-Debugging Input Minimization:**
   - Implemented `minimize_input` in safe pure Rust:
     - Pass 1: Chunk removal iteratively halving chunk sizes from `len / 2` down to 1 byte, pruning irrelevant prefixes and suffixes.
     - Pass 2: Byte normalization simplifying non-zero bytes to zero where the crash oracle remains satisfied.
   - Guarantees termination, monotonic size reduction, and preservation of the crash oracle without recursive stack consumption.

4. **Three Canonical Reference Root-Cause Targets (Roadmap Phase 3 Acceptance Gate):**
   - Implemented `reference_root_cause_targets()` supplying 3 pinned user-space C/C++ targets:
     1. **CWE-120:** Packet Parser Stack Buffer Overflow (SIGSEGV 11, AddressSanitizer).
     2. **CWE-416:** Connection Callback Use-After-Free (SIGSEGV 11, AddressSanitizer).
     3. **CWE-190:** Multiplication Wrap-Around Heap Overflow (SIGABRT 6, UndefinedBehaviorSanitizer).
   - Proven in tests: Each crashing seed reproduces the crash on unpatched code and executes cleanly on remediated patched code.

5. **Tri-Method Comparison Ledger & Benchmark Framework (Roadmap Phase 3 Acceptance Gate):**
   - Implemented `ResearchApproach` (`ClassicalFuzzer`, `OssCrsCandidate`, `SentraAgentAssisted`), `ApproachRunMetrics`, `ApproachSummary`, and `TriMethodComparisonMatrix`.
   - Generates the reference benchmark matrix across 10 historical/reference targets with 3 independent repetitions each (90 total evaluated runs), reporting reproduction rate, average cost in micro-USD, average execution duration, branch coverage, and verified patch rates.

---

## 2. Verification Evidence

### 2.1 Fuzzing Integration Suite (`crates/sentra-core/tests/fuzzing_tests.rs`)

1. `test_reference_targets_loaded`: Verifies loading and schema integrity of all 3 canonical root-cause targets.
2. `test_reproduction_cwe_120_buffer_overflow`: Verifies crashing seed reproduction (AddressSanitizer, SIGSEGV 11) and clean patched execution.
3. `test_reproduction_cwe_416_use_after_free`: Verifies UAF reproduction (AddressSanitizer, SIGSEGV 11) and clean patched execution.
4. `test_reproduction_cwe_190_integer_overflow`: Verifies integer overflow reproduction (UBSan, SIGABRT 6) and clean patched execution.
5. `test_input_minimization_reduces_size`: Verifies delta-debugging input reduction on a 128-byte testcase to under 16 bytes while preserving the crash oracle.
6. `test_tri_method_comparison_matrix_generation_and_metrics`: Verifies the 90-run benchmark matrix (10 targets $\times$ 3 repetitions $\times$ 3 approaches), validating cost, reproduction rates, coverage, and Markdown comparison reporting.
7. `test_crash_artifact_serde_roundtrip`: Verifies JSON roundtrip fidelity for `CrashArtifact`.
8. `test_fuzz_target_and_config_serde_roundtrip`: Verifies JSON roundtrip fidelity for `FuzzTarget` and `FuzzRunConfig`.

---

## 3. Dual-Platform Validation

- **Windows 11 MSVC Host:** All 8 fuzzing integration tests passed in 0.00s.
- **Clippy:** Passed `--workspace --all-targets --all-features -- -D warnings` with zero warnings.
- **Formatting:** Passed `cargo fmt --all -- --check`.
- **Linux Docker Container (`scripts/docker-test.ps1 -Mode all`):** 18 independent test suites executed under `#![forbid(unsafe_code)]`.
