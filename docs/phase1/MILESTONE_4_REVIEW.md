# Phase 1 Milestone 4 Closure Review & Core Engine Readiness Assessment

Date: 2026-11-05. **Milestone 4 closure review is complete.** This review evaluates the evidence from Milestone 4 (VM and Sandbox Isolation Validation), examines critical security assumptions, assesses technical dependencies, and establishes explicit conditions for proceeding to Core Engine Foundation development (Increment 5).

No production application code was implemented, no host configuration was modified, no Git operations were executed, and Phase 2 was not started. Phase 1 remains in progress.

---

## 1. Executive Summary

Milestone 4 evaluated whether the Windows 11 host environment can support disposable Linux worker virtual machines for untrusted project workloads in accordance with [ADR-0004](../adr/0004-vm-boundary-for-untrusted-execution.md).

The assessment confirmed that the Windows 11 Education host has an active hypervisor with Virtualization-Based Security (VBS) and running Hyper-V host services (`vmms`, `vmcompute`). However, non-elevated management of Hyper-V VMs is currently **Blocked** because the current user is not enrolled in the local `Hyper-V Yöneticileri` (`Hyper-V Administrators`) security group (which currently has 0 members).

To validate the worker lifecycle, communication framing, stream input/output, crash recovery, and independent evidence verification ([ADR-0006](../adr/0006-evidence-and-independent-verification.md)) without mutating host security policies, a harmless prototype was executed using non-privileged container isolation (`ubuntu:24.04`). The validation script executed **27 assessment items twice with identical results: 22 Passed, 0 Failed, 5 Blocked, 0 Not Tested**.

**Final Recommendation:** **CONDITIONAL GO** for Core Engine Foundation (Increment 5).

Development of Core Engine Foundation (session management, project discovery, path traversal security, policy enforcement, local SQLite persistence, AI provider gateway, and abstract worker interfaces) may proceed safely **under the strict invariant that all untrusted execution is disabled by default and fails closed (`ExecutionBackend::NotAvailable`)**. Neither the host nor the development Docker/WSL2 prototype may be used as an execution fallback for untrusted target workloads.

---

## 2. Evidence Reviewed and Verification Method

### Inspected artifacts

| Artifact | Location | Inspected Content & Purpose |
| --- | --- | --- |
| Milestone 4 Report | [`docs/phase1/SANDBOX_VALIDATION.md`](SANDBOX_VALIDATION.md) | Technical assessment report, environment findings, isolation architecture evaluation, and prototype results |
| Validation Runner | [`experiments/phase1/sandbox/Validate.ps1`](../../experiments/phase1/sandbox/Validate.ps1) | PowerShell 7 validation script; Stage A CIM/WMI queries; Stage C 10-step container prototype |
| Raw Evidence | [`experiments/phase1/sandbox/results.json`](../../experiments/phase1/sandbox/results.json) | Structured machine-readable test records, host metadata, individual statuses, and cryptographic hashes |
| Isolation Decision | [`docs/adr/0004-vm-boundary-for-untrusted-execution.md`](../adr/0004-vm-boundary-for-untrusted-execution.md) | Accepted security invariant requiring dedicated disposable VM boundary for untrusted code |
| Evidence Decision | [`docs/adr/0006-evidence-and-independent-verification.md`](../adr/0006-evidence-and-independent-verification.md) | Accepted requirement for independent verifier and cryptographic evidence admission |
| Progress Record | [`PROGRESS.md`](../../PROGRESS.md) | Milestone status, completed milestones ledger, and pending implementation gates |
| Phase 1 Execution Plan | [`docs/phase1/README.md`](README.md) | Dependency-ordered breakdown, technical validation gates, and environment observations |
| Isolation Research | [`docs/research/ISOLATION.md`](../research/ISOLATION.md) | Primary-source technology comparisons: Docker, WSL2, Hyper-V, gVisor, Firecracker |
| SQLite Evidence | [`docs/phase1/SQLITE_VALIDATION.md`](SQLITE_VALIDATION.md) | Milestone 2 database reliability findings, WAL lifecycle, and concurrency constraints |
| Provider Evidence | [`docs/phase1/PROVIDER_VALIDATION.md`](PROVIDER_VALIDATION.md) | Milestone 3 mock AI provider contract findings, virtual deadlines, and cost reservations |

### Verification method

1. **Deterministic Reproducibility Check:** The validation runner `Validate.ps1` was re-executed from the repository root in non-elevated PowerShell 7. The execution completed with exit code 0, reproducing all 27 individual item statuses with zero regressions.
2. **Raw Output Audit:** Each item in `results.json` was cross-checked against the claims in `SANDBOX_VALIDATION.md` and the underlying commands in `Validate.ps1`.
3. **Boundary and Assumption Scrutiny:** Hyper-V permission requirements, group membership sufficiency, differencing VHDX lifecycle, AF_HYPERV socket behavior, and SHA-256 evidence integrity claims were critically analyzed against Windows operating system security internals.
4. **Dependency and Readiness Analysis:** The Core Engine component architecture was mapped against the validated subsets and unresolved gaps of Milestones 1, 2, 3, and 4.

---

## 3. Milestone 4 Result Assessment

The 27 evaluation items are categorized into three distinct operational groups:

```
Total Items: 27
|-- Stage A: Environment Assessment (11 items) : 7 Passed, 4 Blocked
|-- Stage B: Architecture Evaluation (6 items) : 5 Passed, 1 Blocked
`-- Stage C: Harmless Prototype      (10 items): 10 Passed
Summary: 22 Passed, 0 Failed, 5 Blocked, 0 Not Tested
```

### Classification of the five blocked items

| ID | Item | Cause of Blocker | Classification Verification |
| --- | --- | --- | --- |
| **ENV-04** | Hyper-V Feature Query | `Get-WindowsOptionalFeature` queries DISM servicing stack, which demands Administrator elevation. | **Correctly Blocked.** Access Denied exception caught and handled. |
| **ENV-06** | Hyper-V Cmdlet Query | `Get-VM` and `Get-VMSwitch` return authorization error: caller lacks authorization policy permissions. | **Correctly Blocked.** Permission failure distinct from feature absence. |
| **ENV-07** | Hyper-V Group Token | Local group `Hyper-V Yöneticileri` exists but has 0 members; current user token lacks group SID. | **Correctly Blocked.** Confirms group existence while recording non-membership. |
| **ENV-08** | Host Compute Service CLI | `hcsdiag.exe list` fails with `0x80070522` (`A privilege that the client does not possess is required`). | **Correctly Blocked.** Low-level HCS management requires elevated compute privileges. |
| **ARCH-01**| Dedicated Hyper-V Linux VM | Cannot instantiate or manage VMs without Hyper-V group membership or UAC elevation. | **Correctly Blocked.** Reflects operational boundary; no attempt to force privileged bypass. |

All five Blocked items represent **security authorization boundaries** in the non-privileged session, NOT hardware incompatibility or operating system feature absence.

---

## 4. Confirmed Findings and Unsupported Claims

### Confirmed findings

1. **Hardware and Hypervisor Readiness:** The Windows 11 Education host (Build 26300 x64, 11th Gen Intel Core i7-11800H, 31.75 GB RAM) has an active hypervisor with VBS enabled. Core virtualization services (`vmms`, `vmcompute`) are running.
2. **Resource Availability:** Host memory (~11.5 GB free) and multi-drive storage (60 GB to 221 GB free) provide ample capacity for ephemeral worker VMs.
3. **Non-Privileged Management Boundary:** Standard non-elevated user sessions cannot query or manage Hyper-V VMs because the local delegation group `Hyper-V Yöneticileri` is currently unpopulated.
4. **Worker Protocol Feasibility (Prototype):** The prototype demonstrated that a worker harness can function strictly offline (`--network none`), with a read-only root filesystem, in-memory scratch storage (`/tmp`), zero host environment variables, stream-based input passing without filesystem mounting, crash detection (SIGKILL 137, SIGSEGV 139), host timeout enforcement and process reaping, and clean ephemeral disposal.
5. **Independent Evidence Verification:** The prototype confirmed that the host can independently recompute and verify SHA-256 digests of worker-emitted payloads before admitting them, satisfying ADR-0006's verification requirement.

### Unsupported claims and critical corrections

The review identified three areas where claims or labels in the Milestone 4 report require technical qualification:

#### 1. "Passed" status on architectural items (ARCH-03 through ARCH-06)
- *Report Status:* `ARCH-03` (AF_HYPERV vsock), `ARCH-04` (Default-deny virtual switch), `ARCH-05` (VHDX differencing overlay), and `ARCH-06` (Stream I/O over vsock) are listed as "Passed".
- *Technical Reality:* These four items represent **architectural feasibility evaluations and design invariants**, NOT runtime experimental test executions. `Validate.ps1` did not open an `AF_HYPERV` socket, did not create an internal virtual switch, and did not create a VHDX differencing disk.
- *Correction:* These items must be understood as *Design Validated / Feasible*, pending live Hyper-V runtime validation in Phase 2.

#### 2. Group membership sufficiency for all Hyper-V operations
- *Assumption:* Enrolling the user in `Hyper-V Yöneticileri` (`Hyper-V Administrators`) is sufficient for all Sentra VM orchestration needs.
- *Technical Reality:* While `Hyper-V Administrators` allows non-elevated creation, configuration, startup, shutdown, and deletion of VMs and VHDX disks, **it does NOT permit creating or deleting Virtual Network Switches (`New-VMSwitch`) or configuring NAT rules (`New-NetNat`)**. Furthermore, registering a new Hyper-V Socket service GUID in `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices` requires Administrator write access.
- *Correction:* Creating the private virtual switch and registering the AF_HYPERV service GUID must be classified as **one-time elevated host preparation prerequisites**. Day-to-day session orchestration will then run completely non-elevated.

#### 3. SHA-256 evidence integrity guarantees
- *Assumption:* Worker-computed SHA-256 digests verified by the host ensure evidence integrity.
- *Technical Reality:* A SHA-256 digest guarantees **transit integrity** (detecting corruption, truncation, or network drops between worker and host). It does **NOT prove provenance or absence of malicious tampering** if hostile target code has already compromised the worker process before the digest is computed.
- *Correction:* Host verification must also enforce independent structural schema validation, cross-check tool execution logs, and keep the worker daemon supervisor isolated from target code processes inside the guest.

---

## 5. Hyper-V Prerequisite and Permission Analysis

To establish a clear path for eventual Phase 2 Hyper-V validation without compromising the Phase 1 non-elevation policy, the required host setup is separated into one-time host preparation and routine execution:

```
[Phase 1: Present State]
  Standard User Session (Medium Integrity)
    |-- vmms / vmcompute: Running
    |-- Hyper-V Yöneticileri: Empty
    `-- Hyper-V Management: BLOCKED (Fail-Closed)

[One-Time Host Preparation (Requires Explicit User Execution)]
  Elevated Administrator Action:
    1. net localgroup "Hyper-V Yöneticileri" $env:USERNAME /add
    2. New-VMSwitch -Name "SentraIsolatedSwitch" -SwitchType Private
    3. Register Sentra AF_HYPERV Service GUID in HKLM
    4. Operator logs out and logs in (token refresh)

[Phase 2 Target State]
  Standard User Session (Medium Integrity, Hyper-V Group Token Active)
    |-- New-VM, Set-VM, Start-VM, Stop-VM, Remove-VM : NON-ELEVATED
    |-- New-VHD (Differencing disk creation/deletion) : NON-ELEVATED
    `-- AF_HYPERV (vsock IPC stream connection)       : NON-ELEVATED
```

Until the project owner explicitly approves and executes the one-time host preparation, direct Hyper-V orchestration remains disabled.

---

## 6. Security Risks and Unresolved Questions

| Risk / Question | Severity | Impact on Sentra | Mitigation / Required Evidence |
| --- | --- | --- | --- |
| **Hypervisor Escape Vulnerability** | Critical | Host compromise from malicious target exploiting virtual hardware emulation. | Omit virtual network adapters, sound cards, and USB/PCI passthrough. Rely strictly on `vsock` and memory-backed virtio devices. |
| **Orphaned VHDX Differencing Disks** | Medium | Disk space exhaustion or file locking after abrupt worker crash or host reboot. | Core Engine must perform an idempotent startup sweep to identify, unlock, and delete unreferenced child VHDX files. |
| **Rust Windows AF_HYPERV Bindings** | Medium | `std::net` does not support Hyper-V sockets on Windows; requires raw WinSock2 FFI. | Validate `AF_HYPERV` via `windows-sys` or `socket2` with `SOCKADDR_HV` in a standalone isolated Rust spike. |
| **Guest Supervisor Compromise** | High | Hostile code running in guest tampers with finding reports before submission. | Run target code under an unprivileged guest user account; run worker daemon under separate UID with read-only target access. |
| **Offline Guest Base Image Supply Chain** | Medium | Base Linux VHDX image could contain vulnerabilities or drift from reproducible definitions. | Build base VHDX from versioned Packer/systemd-repart manifests; record SHA-256 digest in source control. |

---

## 7. Core Engine Components That May Safely Proceed

The following Core Engine Foundation components have zero dependency on untrusted target execution and may proceed immediately:

```
+--------------------------------------------------------------------------+
|                  Core Engine Foundation (Increment 5)                    |
|                                                                          |
|  [Session Management]             [Workspace & Path Discovery]           |
|  - Lifecycle (create/pause/cancel)- Strict workspace root boundary       |
|  - Session state machine          - Symlink quarantine (V-04)            |
|  - Operator context & leases      - .gitignore & UTF-8 traversal         |
|                                                                          |
|  [Policy Enforcement Engine]      [Persistence & Evidence Repository]    |
|  - Authorization checks           - Local SQLite candidate (WAL, fsync)  |
|  - Sensitive-action approvals     - Transaction rollback on stmt errors  |
|  - Security classification tags   - SQLITE_BUSY_SNAPSHOT restart loop    |
|                                                                          |
|  [AI Provider Gateway]            [Abstract Worker Interface]            |
|  - Provider-neutral contract      - ExecutionBackend trait definition    |
|  - Milestone 3 mock adapter       - Task envelope & lease schemas        |
|  - Virtual timeouts & retry       - Timeout and cancellation contracts   |
|  - Conservative cost accounting   - Independent SHA-256 verifier         |
+--------------------------------------------------------------------------+
```

1. **Session & Lifecycle Management:** Core Engine service initialization, session state machines (Created, Active, Paused, Cancelled, Terminated), and audit logging.
2. **Project Discovery & Path Security (V-04):** Bounded file discovery, `.gitignore` traversal, path canonicalization, symlink quarantine (rejecting links pointing outside workspace root), NUL byte rejection, and 10,000-file discovery benchmark.
3. **Policy Enforcement Engine (F-02, S-01, S-02):** Deterministic policy evaluation, sensitive-action approval brokers, classified input propagation, and secret-data redaction.
4. **Persistence & Evidence Management (V-05):** Local SQLite schema for sessions, events, evidence, and approvals, incorporating Milestone 2 concurrency patterns.
5. **AI Provider Gateway:** Integrating the provider-neutral trait, capability descriptors, DecisionV1 structured validation, and conservative cost accounting validated in Milestone 3.
6. **Abstract Worker / Sandbox Interfaces:** Defining the Rust `ExecutionBackend` trait, task envelope wire formats, job leases, and timeout contracts.
7. **Independent Evidence Verifier (ADR-0006):** Host-side parser validating artifact envelopes, checking size bounds, rejecting absolute paths, and calculating independent SHA-256 digests.

---

## 8. Components That Must Remain Disabled or Blocked

To ensure complete host safety, the following capabilities must be strictly disabled and configured to fail closed:

| Component | Status | Required Fail-Closed Behavior |
| --- | --- | --- |
| **Real Target Execution** | **DISABLED** | Any call to `ExecutionBackend::execute` for untrusted workloads returns `Err(ExecutionError::BackendUnavailable("Hyper-V isolation backend is not provisioned. Untrusted execution is disabled."))`. |
| **Host Process Execution Fallback** | **FORBIDDEN** | The control plane must never execute target build scripts, native parsers, tests, or compilers on the host. |
| **Docker / WSL2 Target Execution** | **FORBIDDEN** | Docker and WSL2 must not be used as an execution substitute for real untrusted repositories. |
| **Real AI Provider Network Egress** | **DISABLED** | Core Engine communicates only with mock providers; live HTTP/transport egress remains unverified. |
| **Dynamic Fuzzing & Exploit Verification** | **DEFERRED** | Phase 3 capability; strictly forbidden in Phase 1. |

---

## 9. Dependencies on SQLite, Provider, and Sandbox Validation

The Core Engine Foundation integrates evidence from all four completed Phase 1 milestones:

```
[Milestone 1: Rust/MSVC] ----> x64 Toolchain, MSVC Linker, Offline Cargo, Zero 3rd-Party Crates
[Milestone 2: SQLite] -------> Explicit Rollback on Statement Error, SQLITE_BUSY_SNAPSHOT Retry
[Milestone 3: AI Provider] ---> Neutral Contract, DecisionV1 Validator, Conservative Cost Ledger
[Milestone 4: VM Sandbox] ---> Abstract Backend Trait, vsock Envelope Schemas, Fail-Closed Stub
                                           |
                                           v
                          [Core Engine Foundation (Increment 5)]
```

- **SQLite Rules (Milestone 2):** Core Engine persistence must handle transaction errors by issuing explicit rollback. Any `SQLITE_BUSY_SNAPSHOT` error must trigger a full transaction rollback, fresh read snapshot, and bounded retry. Unverified items (production Rust `rusqlite` binding, power-loss durability) must be validated during integration.
- **Provider Rules (Milestone 3):** Core Engine must keep AI provider integration optional. All model outputs must be validated through narrow typed structures (e.g., `DecisionV1`). Cost reservations must be held conservatively until confirmed settlement.
- **Sandbox Rules (Milestone 4):** Core Engine must treat `ExecutionBackend` as an out-of-process boundary. The worker interface must enforce finite timeouts, cancellation tokens, and independent SHA-256 evidence verification.

---

## 10. Explicit Recommendation: CONDITIONAL GO

The reviewer issues a **CONDITIONAL GO** for **Core Engine Foundation (Increment 5)**.

### Mandatory conditions

1. **Fail-Closed Execution Invariant:** The Core Engine must implement `ExecutionBackend` with a default `FailClosedBackend` that rejects all untrusted workload dispatch with explicit, typed errors.
2. **Zero Host Execution for Targets:** No convenience bypass or local child process fallback may be introduced for target repository builds, tests, or scanners.
3. **Curated Fixtures Only:** Development tests for Core Engine components must use synthetic, maintainer-reviewed fixtures stored in the repository.
4. **Offline Compilation & Review:** The Core Engine package must build offline and introduce only maintainer-reviewed, license-compatible dependencies.
5. **Phase 2 Boundary Maintained:** Real untrusted target scanning, package build execution, and dynamic analysis remain strictly blocked until Phase 2 is authorized and Hyper-V VM containment is verified.

---

## 11. Concrete List of Remaining Validation Tasks

The following technical validation tasks remain before Sentra can achieve production readiness:

| Task ID | Task Description | Target Milestone / Phase | Dependency |
| --- | --- | --- | --- |
| **VAL-01** | Execute one-time elevated host setup (`Hyper-V Yöneticileri` group, private switch, vsock GUID registration) | Post-Phase 1 / Prior to Phase 2 | Explicit User Authorization |
| **VAL-02** | Implement standalone Rust `AF_HYPERV` (WinSock2 vsock) IPC spike | Phase 1 / Milestone 4 Follow-up | VAL-01 |
| **VAL-03** | Build minimal, reproducible Linux guest base VHDX image (offline rootfs) | Phase 2 | VAL-01 |
| **VAL-04** | Integrate and test Rust SQLite binding (`rusqlite`) in Core Engine against Milestone 2 concurrency patterns | Phase 1 / Increment 5 | Core Engine Foundation |
| **VAL-05** | Execute 10,000-file project discovery, symlink quarantine, and path benchmark (V-04) | Phase 1 / Increment 5 | Core Engine Foundation |
| **VAL-06** | Validate real AI provider adapter with live transport cancellation and measured egress (F-15) | Phase 2 | Milestone 3 Mock Contract |
| **VAL-07** | Execute end-to-end VM containment and escape-resistance test suite with hostile fixtures | Phase 2 | VAL-01, VAL-02, VAL-03 |
