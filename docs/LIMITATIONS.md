# Sentra Security & Operational Limitations

**Document Version:** 1.0.0  
**Effective Date:** 2026-11-08  
**Applicability:** All Sentra Platform Deployments (v0.1.0+)  

---

## 1. Fail-Closed Target Execution Boundary

1. **Untrusted Target Code Execution:** Under Phase 1 through Phase 6 architectural specifications (`ADR-0004`, `REQ-F12`), untrusted repository execution (including build scripts, procedural macros, unit tests, fuzz targets, and generated PoCs) remains **strictly disabled and fail-closed** by default on the host development machine (`FailClosedBackend`).
2. **Dedicated Disposable VM Requirement:** Target execution requires an explicitly provisioned disposable Linux VM worker (`ContainmentLevel::DisposableVm`) with strictly denied outbound network egress (`EgressPolicy::StrictlyDenied`). Docker Desktop or WSL2 running directly on the host development workstation does NOT satisfy this boundary.
3. **No Host Convenience Exceptions:** Sentra does not provide a convenience flag or option to run untrusted target code directly on the host machine.

---

## 2. Platform & Toolchain Scope

1. **Host Platform Envelope:** The primary tested development and control-plane host platform is **Windows 11 x64** with MSVC and PowerShell 7. Linux x86_64 is validated via the Docker test runner. Other operating systems (macOS, BSD) and architectures (ARM64, RISC-V) remain untested and unsupported.
2. **Strict Wildcard Prohibition:** Per `EXTENSIONS.md`, target adapter capability claims must use exact 7-tuples. Any declaration specifying wildcards (`*`, `%`, `all`, `any`) fails closed with `WildcardProhibited`. No universal language or tool support is claimed.
3. **Kernel-Space and Native Ring-0:** Kernel drivers, kernel-space fuzzing, and Windows-native ring-0 execution are explicitly out of scope. Target profiles are restricted strictly to user-space applications.

---

## 3. Host Administrator & Shared Host Boundary

1. **Host Administrator Trust Model:** The security architecture assumes that the local host operating system administrator account is not compromised. A malicious local administrator or process executing under the same user token with elevated privileges can inspect local process memory, modify NTFS file attributes, or access unencrypted local SQLite databases.
2. **Multi-User Shared Host Warning:** Sentra is designed for single-operator local control planes or isolated remote worker fleets. Running Sentra on a multi-user shared host without service credential boundaries does not provide hostile same-user protection.

---

## 4. Analytical Confidence & Verifier Independence

1. **Candidate Claims vs. Verified Facts:** Model and scanner outputs (including LLM inferences, SARIF imports, and advisory matches) are classified as *candidate claims*. Absence in a subsequent scan does not prove a vulnerability is fixed.
2. **Three-Tier Verification Invariant:** A patch candidate is only admitted as verified when all three independent conditions hold:
   - Original baseline tests fail on unpatched code.
   - Target tests pass on patched code.
   - All baseline regression test suites pass with zero regressions.
3. **Anti-Collusion & Independent Verification:** External model agents and automated patch authors cannot self-approve remediation proposals. All sensitive actions require explicit human operator admission (`HumanApprovalRequired`).

---

## 5. Storage Durability and File Modification Semantics

1. **Domain Immutability vs. Physical File Modification:** CLI inspection commands (`sentra status`, `sentra session show`) are domain-state read-only. However, opening SQLite databases under WAL mode triggers standard database recovery and truncation checkpoints (`PRAGMA wal_checkpoint(TRUNCATE)`), which may modify physical file bytes and timestamps. Writable storage permissions are required even for inspection.
2. **Unrecoverable Storage Corruption:** Corrupt storage files or orphaned WAL locks fail closed immediately (`storage_or_service_failure`, exit code 5) to preserve forensic bytes. Automatic repair or destructive overwrite is prohibited.
