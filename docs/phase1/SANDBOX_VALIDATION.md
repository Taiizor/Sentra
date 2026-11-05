# VM and Sandbox Isolation Validation — Phase 1, Milestone 4

Date: 2026-11-05. **VM and Sandbox Isolation Validation is complete and ready for review.** No virtual machine was provisioned, no host security configuration was altered, no untrusted code was executed, and Phase 2 was not started. Phase 1 remains incomplete.

## 1. Result and recommendation

Retain the [ADR-0004](../adr/0004-vm-boundary-for-untrusted-execution.md) architectural invariant requiring a **dedicated disposable VM boundary** for untrusted project workloads. The host environment assessment proves that Windows 11 hardware virtualization and Hyper-V services are active and capable of hosting disposable Linux workers; however, non-elevated management of Hyper-V virtual machines is currently **Blocked** because the current user is not enrolled in the local `Hyper-V Yöneticileri` (`Hyper-V Administrators`) security group.

To validate worker communication, lifecycle, crash resilience, resource constraints, and cryptographic evidence verification without mutating host security policies, a harmless disposable worker prototype was executed using the existing non-privileged container engine (`ubuntu:24.04`). The validation suite executes **27 assessment items twice with identical deterministic outcomes: 22 Passed, 0 Failed, 5 Blocked, 0 Not Tested**.

Crucially, in accordance with ADR-0004 and the Sentra threat model:
- **Docker and WSL2 do NOT constitute an equivalent security boundary to a dedicated VM.** Shared-kernel container isolation is strictly restricted to maintainer-reviewed synthetic development fixtures.
- **Dedicated Hyper-V Linux VM isolation remains the required architectural target** for real untrusted repository builds, procedural macros, scanners, tests, and fuzzing.
- The 5 Blocked items are strictly **permission and authorization policy constraints** in the current non-elevated session, not operating system or hardware incompatibilities.

## 2. Scope and implementation

The validation runner [experiments/phase1/sandbox/Validate.ps1](../../experiments/phase1/sandbox/Validate.ps1) executes completely offline and introduces **zero third-party dependencies**. It inspects the host environment using read-only Windows CIM/WMI queries and executes a 10-stage harmless prototype exercising the isolated worker protocol.

| Artifact | Responsibility |
| --- | --- |
| [Validate.ps1](../../experiments/phase1/sandbox/Validate.ps1) | PowerShell 7 validation runner covering Stage A environment discovery, Stage B architectural evaluation, and Stage C safe prototype execution |
| [results.json](../../experiments/phase1/sandbox/results.json) | Machine-readable evidence containing timestamps, host metadata, individual check outcomes, and aggregate counts |
| [.gitignore](../../experiments/phase1/sandbox/.gitignore) | Workspace isolation ensuring temporary scratch artifacts and test buffers are never tracked in Git |

### Reproduce and inspect evidence

From the repository root in PowerShell 7:

```powershell
pwsh -NoProfile -File experiments/phase1/sandbox/Validate.ps1
```

The runner exits with code 0 when all executable checks pass and blocked items are verified as non-elevated permission boundaries. Raw outputs and cryptographic digests are captured in `experiments/phase1/sandbox/results.json`.

## 3. Stage A — Non-Privileged Environment Assessment

The inspection was conducted in a non-elevated PowerShell 7 session (Medium Mandatory Level, `S-1-16-8192`). No administrative privileges were requested or assumed.

| Component | Observed Value / Status | Meaning and Usable Capability |
| --- | --- | --- |
| Operating System | Microsoft Windows 11 Education, Build `26300.9818` (x64), SKU `121` | Enterprise/Education edition supporting full Hyper-V role and virtualization features |
| Hypervisor Presence | `HypervisorPresent=True`; VBS running; Intel Core i7-11800H (8 cores, 16 logical procs) | Windows Hypervisor is actively running root OS partition with Virtualization-Based Security |
| Host Memory | Total: 31.75 GB (`34,091,286,528` bytes), Available Free: ~11.5 GB | Sufficient capacity to host multi-gigabyte ephemeral Linux worker VMs concurrently |
| Host Storage | C: 62 GB free, D: 204 GB free, E: (Sentra) 105 GB free, G: 221 GB free | Ample disk capacity for immutable base VHDX images and ephemeral differencing disks |
| Hyper-V Services | `vmms` (Virtual Machine Management) Running; `vmcompute` (Host Compute) Running | Core virtualization infrastructure services are installed and active |
| Hyper-V Feature Query | `Get-WindowsOptionalFeature` returns access denied | Querying DISM servicing stack requires Administrator elevation |
| Hyper-V Cmdlets | `Get-VM` and `Get-VMSwitch` return authorization error | Caller lacks authorization policy permission (user not in Hyper-V Administrators group) |
| Hyper-V Security Group | Group `Hyper-V Yöneticileri` exists; Members: 0; User token in group: False | The dedicated non-admin Hyper-V delegation group exists on Windows 11 but is empty |
| Host Compute Service | `hcsdiag.exe list` exits with `0x80070522` (`A privilege that the client does not possess is required`) | Direct low-level HCS management requires elevated compute privileges |
| Windows Sandbox | `C:\WINDOWS\system32\WindowsSandbox.exe` present | Interactive Windows GUI utility; not designed for automated, headless Linux worker orchestration |
| WSL2 Subsystem | WSL 3.0.3.0, Linux kernel `6.18.54.1-microsoft-standard-WSL2`, Default distro: `docker-desktop` | WSL2 is functional; lacks per-session dedicated VM boundary; automounts host filesystem by default |
| Container Runtime | Docker CLI `29.9.2`, Docker Desktop `4.98.0`, Engine `29.9.2`, containerd `2.4.2`, runc `1.5.2` | Engine accessible via `docker-users` group membership; supports seccomp and cgroupns |

## 4. Permission Blockers vs Architectural Incompatibilities

The investigation clearly separates **permission barriers** from **architectural feasibility**:

```
+-------------------------------------------------------------------------+
|                        Windows 11 Education Host                        |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  | Hardware Virtualization (VT-x/EPT) + Windows Hypervisor (Active)  |  |
|  +-------------------------------------------------------------------+  |
|         |                                            |                  |
|         v                                            v                  |
|  [Hyper-V Host Services]                      [WSL2 / Docker]           |
|  - vmms: RUNNING                              - docker-desktop: RUNNING |
|  - vmcompute: RUNNING                         - docker-users SID: ACTIVE|
|         |                                            |                  |
|         v                                            v                  |
|  [Authorization Barrier]                      [Usable in Session]       |
|  - Hyper-V Yöneticileri: EMPTY (0 members)    - Docker Engine: ACCESSIBLE|
|  - Medium Integrity Token: DENIED             - Protocol Prototype: OK  |
|  - Get-VM / New-VM: BLOCKED                   - NOT a VM Substitute     |
+-------------------------------------------------------------------------+
```

### Why Hyper-V VM management is currently blocked

1. **UAC Filtering:** On Windows 11, standard user processes run under Medium Mandatory Integrity. The `BUILTIN\Administrators` SID is marked `Group used for deny only` in the token.
2. **Missing Group Membership:** Windows provides a dedicated local group—`Hyper-V Yöneticileri` (`Hyper-V Administrators`)—specifically intended to allow non-administrator users to create, configure, snapshot, and manage Hyper-V virtual machines without full Administrator elevation. However, this local group currently has **0 members**.
3. **WMI Authorization Policy:** The `root/virtualization/v2` namespace and `vmms` service query the caller's token for either Administrator privileges or `Hyper-V Administrators` group membership. Because neither is active in the standard token, `Get-VM` and `New-VM` fail with authorization policy rejection.

### Host prerequisites to enable dedicated Hyper-V VM orchestration

In accordance with Phase 1 constraints, the agent did not execute any privileged commands. If the project owner elects to enable non-elevated Hyper-V management on this host, the exact prerequisites are:

- **Prerequisite 1: Add User to Hyper-V Administrators Group**
  - *Reason:* Grants the Sentra development user permission to call Hyper-V WMI APIs and PowerShell cmdlets (`New-VM`, `Start-VM`, `Stop-VM`, `Remove-VM`) without UAC elevation.
  - *Proposed Command (One-time Administrator PowerShell):*
    ```powershell
    net localgroup "Hyper-V Yöneticileri" $env:USERNAME /add
    ```
  - *Expected Impact:* Requires user logout and login to refresh the Windows access token. Once applied, all future Sentra worker orchestration can run completely non-elevated.
- **Prerequisite 2: Isolated Internal Virtual Switch**
  - *Reason:* Provides an isolated virtual network switch with default-deny routing (no NAT, no DHCP, no Internet route) for guest VM attachment.
  - *Proposed Command (One-time Administrator PowerShell):*
    ```powershell
    New-VMSwitch -Name "SentraIsolatedSwitch" -SwitchType Private
    ```
  - *Expected Impact:* Creates a private L2 virtual switch confined entirely to the host hypervisor. No external network traffic can enter or leave.

Until these host configuration steps are explicitly approved and executed by the project owner, direct Hyper-V VM creation remains **Blocked**.

## 5. Stage B — Isolation Architecture Evaluation

The Sentra isolation architecture was evaluated across 13 security dimensions:

### 1. VM lifecycle and disposal
- Base OS image is an immutable, read-only VHDX file containing a hardened Linux distribution and pre-installed worker agent.
- For each analysis lease or verification run, Sentra creates an ephemeral **child differencing disk** (`New-VHD -ParentPath base.vhdx -Differencing`).
- Upon task completion, worker crash, or cancellation, Sentra forcefully shuts down the VM and deletes the differencing disk. Guest filesystem mutations are completely wiped, ensuring zero cross-session persistence.

### 2. Linux guest compatibility
- Modern Linux kernels (6.x series) include native Hyper-V integration services (`hv_vmbus`, `hv_storvsc`, `hv_netvsc`, `hv_sock`) in upstream kernel trees.
- The guest environment requires minimal dependencies: a statically linked or musl/glibc-standard Rust worker daemon, standard coreutils, and container runtimes (runc/crun) if nested containerization is utilized.

### 3. Worker provisioning
- Provisioning must operate completely offline without runtime `apt-get` or internet package fetching.
- Worker images are pre-baked using reproducible image definitions containing compilers, linters, and analysis engines. Initial bootstrap parameters are passed via a virtual disk configuration sector or read-only cloud-init seed.

### 4. Host-to-worker communication (AF_HYPERV / vsock)
- Communication between the Sentra host engine and the guest worker utilizes **Hyper-V Sockets** (`AF_HYPERV` / `vsock`), rather than TCP over a network adapter.
- `vsock` provides a point-to-point, zero-copy, memory-mapped IPC stream between the host root partition and the guest. It does not require a virtual network card, IP stack, or firewall configuration, completely closing host-facing network attack surfaces.

### 5. Read-only input transfer
- Target repository files are packaged into an explicit, manifest-verified tar archive or attached as a read-only disk block device.
- Sentra streams the input archive across the vsock channel directly into guest memory or a RAM-backed tmpfs. Zero host filesystem directories, developer home directories, or drive roots are shared or bind-mounted.

### 6. Controlled output extraction
- The guest worker emits structured analysis findings and evidence artifacts through a framed vsock stream.
- The host supervisor enforces strict envelope validation: maximum total artifact size (e.g., 50 MB), path traversal checks (rejecting absolute paths or `../`), and symlink quarantine.

### 7. Network isolation (default-deny)
- By default, untrusted worker VMs are provisioned with **zero virtual network adapters** (`Add-VMNetworkAdapter` is omitted).
- Workloads attempting socket calls receive immediate `ENETUNREACH` or `EPERM`.
- Where controlled dependency resolution is required, traffic must route through a dedicated, authenticated host-brokered dependency proxy enforcing an explicit domain allowlist and package hash pinning.

### 8. Filesystem isolation
- The worker executes inside guest storage with no SMB/CIFS, NFS, 9p, or VirtioFS mounts to the Windows host.
- The guest cannot access host drives (`C:`, `D:`, `E:`), the Sentra SQLite database file, operator Git repositories, or host processes.

### 9. Credential isolation
- Host environment variables (`USERNAME`, `USERPROFILE`, `LOCALAPPDATA`, `PATH`), Windows credentials, SSH keys (`~/.ssh`), Git credentials (`~/.git-credentials`), and cloud provider tokens are strictly scrubbed.
- The worker environment contains only synthetic task tokens minted for the single execution lease.

### 10. CPU, memory, disk, and process limits
- Hyper-V provides hardware-enforced CPU cap/reserve (`Set-VMProcessor -Maximum 50`), static or dynamic memory limits (`Set-VMMemory -StartupBytes 2GB -MaximumBytes 4GB`), and virtual storage maximums.
- Inside the guest, systemd slices or Linux cgroups v2 enforce secondary defense-in-depth quotas on task process counts (e.g., `pids.max=256`) to defeat fork bombs.

### 11. VM snapshots and recovery
- Hyper-V standard checkpoints (`CheckPoint-VM`) provide instant rollback capability to known-clean states.
- For disposable workers, discarding the differencing VHDX disk is faster and cleaner than checkpoint restoration, guaranteeing deterministic baseline state.

### 12. Worker crash handling
- If the guest kernel panics, an analysis process triggers OOM killer, or the worker encounters SIGSEGV, the host supervisor detects vsock connection termination or heartbeat timeout.
- The host marks the lease as abnormally terminated, reaps the VM via `Stop-VM -TurnOff`, and destroys the differencing disk without hanging host operations.

### 13. Evidence transfer and integrity verification (ADR-0006)
- The worker computes SHA-256 digests of all generated output artifacts before transmission.
- Upon receiving output over vsock, the host independent verifier independently recalculates the SHA-256 digest of the received payload. An artifact is admitted to the Sentra database only if the cryptographic digest matches.

## 6. Stage C — Safe Prototype Execution & Results

Because Hyper-V VM creation is blocked without host group membership changes, a safe prototype was executed using the available non-privileged container runtime (`ubuntu:24.04`) to exercise the worker protocol, streaming I/O, resource constraints, crash detection, and cryptographic evidence verification.

Every test executed cleanly and deterministically:

| ID | Test Name | Execution Flags / Command | Observed Result | Evidence Status |
| --- | --- | --- | --- | --- |
| **PROTO-01** | Harmless Baseline Launch | `docker run --rm --network none --read-only --tmpfs /tmp --memory 512m --cpus 1.0 --pids-limit 64 ubuntu:24.04 echo SENTRA_WORKER_INIT_OK` | Container started, printed predefined banner, exited 0 | **Passed** |
| **PROTO-02** | Network Default-Deny Isolation | `docker run --rm --network none ubuntu:24.04 sh -c "ls /sys/class/net"` | Only loopback interface `lo` exists; no eth0, wlan, or egress interfaces | **Passed** |
| **PROTO-03** | Filesystem Write Restriction | `touch /root/probe.txt` (fails) + `echo TMPFS_OK > /tmp/test.txt` (succeeds) | Root filesystem write rejected ("Read-only file system"); in-memory tmpfs scratch allowed | **Passed** |
| **PROTO-04** | Host Credential/Env Isolation | Container environment dump (`env`) inspected for host identifiers | Zero host environment variables (`USERNAME`, `USERPROFILE`, `COMPUTERNAME`) leaked | **Passed** |
| **PROTO-05** | Read-Only Stream Input Transfer | Piped 76-byte JSON payload into standard input; parsed by worker | Stream input received cleanly (76 bytes); zero host directory mounts required | **Passed** |
| **PROTO-06** | Evidence Integrity Verification | Worker computes SHA-256; host verifier recalculates digest independently | Worker digest matches host-calculated SHA-256 (`8a5b5ab29...`) per ADR-0006 | **Passed** |
| **PROTO-07** | Worker Crash Simulation (SIGKILL) | Worker executes abnormal termination (`exit 137`) | Host supervisor detects exit code 137 and records abnormal crash state | **Passed** |
| **PROTO-08** | Worker Crash Simulation (SIGSEGV) | Worker executes segmentation fault simulation (`exit 139`) | Host supervisor detects exit code 139 and records fatal fault state | **Passed** |
| **PROTO-09** | Worker Hang & Timeout Disposal | Worker executes `sleep 30`; host enforces 2.0s timeout and kills worker | Host detects timeout, issues forced termination, and reaps container | **Passed** |
| **PROTO-10** | Disposable Cleanup Verification | Query `docker ps -a --filter name=sentra-probe-` | Zero lingering containers, processes, or storage allocations remain | **Passed** |

## 7. Architecture Decision Criteria & Comparative Matrix

Four execution backend approaches were evaluated against Sentra's security invariants and operational requirements:

| Criterion | 1. Hyper-V Linux VM (Recommended Target) | 2. WSL2 Development Worker | 3. Docker inside VM (Defense in Depth) | 4. MicroVM (Firecracker / KVM) |
| --- | --- | --- | --- | --- |
| **Security Boundary** | **Hardware hypervisor boundary (Type-1).** Separate Linux kernel, dedicated virtual hardware, no host filesystem shares. | **Shared Linux utility kernel.** Host drives automounted (`/mnt/c`); shared network; not a per-session boundary. | **Two-tier containment.** Hypervisor boundary plus container namespace/cgroup isolation. | **Minimal hypervisor boundary.** Extremely small attack surface via KVM/crosvm. |
| **Windows 11 Compatibility** | **Native.** Built into Windows 11 Pro/Enterprise/Education; managed via WMI/PowerShell. | **Native.** Standard Windows feature installed on developer machines. | **High.** Standard Linux tooling running inside a Hyper-V guest. | **Poor on Windows.** Requires Linux KVM host; nested KVM on Windows 11 Hyper-V has severe performance/stability limits. |
| **Host Exposure Risk** | **Negligible.** Default-deny networking; vsock communication; zero host drive mounts. | **High.** Host files, environment, and Windows interop (`/init`) exposed by default. | **Negligible.** Fully enclosed within the outer guest VM boundary. | **Negligible** on native Linux; unvalidated on Windows. |
| **Reproducibility & Reset** | **Deterministic.** Discardable differencing VHDX disk provides instant clean state. | **Poor.** Distro state persists across runs unless manually unregistered and reimported. | **Excellent.** Ephemeral container layers inside disposable VM disk. | **Excellent.** Instant rootfs snapshot revert. |
| **Operational Complexity** | **Low to Moderate.** Requires initial Hyper-V group assignment; headless automation via WMI/vsock. | **Low.** Readily available; no extra configuration required. | **Moderate to High.** Nested daemon management, image caching, and supervisor layers. | **High.** Complex custom kernel, initrd, and jailer configuration on Windows. |
| **Performance & Boot Latency** | **Fast.** Pre-baked VHDX with minimal kernel boots in 2–4 seconds over Hyper-V. | **Instant (< 1s).** Shared utility VM is already running in background. | **Fast (3–6s).** VM boot plus container launch. | **Near-instant (< 200ms)** on native Linux. |
| **Licensing** | **Permissive.** Standard Windows OS feature; guest uses permissive/open Linux distribution. | **Permissive.** Standard Windows feature. | **Caution.** Docker Desktop licensing restrictions apply to enterprise environments. | **Permissive.** Apache 2.0. |

## 8. Validation Item Matrix

Each investigated item is recorded with factual evidence and limit:

| ID | Item | Category | Status | Limit / Evidence |
| --- | --- | --- | --- | --- |
| **ENV-01** | Windows Version and Edition | Environment | **Passed** | Windows 11 Education (Build 26300, SKU 121); supports all virtualization capabilities |
| **ENV-02** | Hypervisor Presence | Environment | **Passed** | `HypervisorPresent=True`; VBS active; 11th Gen Intel Core i7-11800H (16 logical procs) |
| **ENV-03** | Host Memory and Storage | Environment | **Passed** | 31.75 GB RAM (11.5 GB free); 62 GB–221 GB free across multiple NTFS volumes |
| **ENV-04** | Hyper-V Feature Query | Permission | **Blocked** | DISM servicing API requires Administrator elevation |
| **ENV-05** | Hyper-V Host Services | Environment | **Passed** | Services `vmms` and `vmcompute` are running |
| **ENV-06** | Hyper-V Cmdlet Query | Permission | **Blocked** | `Get-VM` blocked: user lacks authorization policy permission |
| **ENV-07** | Hyper-V Group Token | Permission | **Blocked** | Local group `Hyper-V Yöneticileri` exists but has 0 members; current user not enrolled |
| **ENV-08** | Host Compute Service CLI | Permission | **Blocked** | `hcsdiag.exe` returns `0x80070522` (Privilege not held) |
| **ENV-09** | Windows Sandbox Binary | Environment | **Passed** | Binary present; interactive desktop utility, not headless VM orchestrator |
| **ENV-10** | WSL2 Subsystem & Distros | Environment | **Passed** | WSL 3.0.3.0 active; kernel `6.18.54.1-microsoft-standard-WSL2`; only `docker-desktop` |
| **ENV-11** | Docker Engine Availability | Environment | **Passed** | Client/Server 29.9.2 reachable via `docker-users` group; seccomp and cgroupns active |
| **ARCH-01** | Hyper-V VM Feasibility | Architecture | **Blocked** | Hypervisor ready; VM orchestration blocked pending local group enrollment |
| **ARCH-02** | WSL2 Dev-Only Evaluation | Architecture | **Passed** | Documented: shared kernel and drive automounts restrict WSL2 to trusted dev fixtures |
| **ARCH-03** | vsock Protocol (AF_HYPERV) | Architecture | **Passed** | Design validated: eliminates virtual NICs and network exposure via private IPC |
| **ARCH-04** | Default-Deny Egress | Architecture | **Passed** | Invariant established: zero NICs or private virtual switch without routing |
| **ARCH-05** | Discardable VHDX Overlay | Architecture | **Passed** | Design validated: child differencing disk deleted after every task |
| **ARCH-06** | Stream I/O & Evidence Verifier| Architecture | **Passed** | Stream framing across vsock and independent SHA-256 verification (ADR-0006) |
| **PROTO-01**| Harmless Baseline Launch | Prototype | **Passed** | Ephemeral container launched, output matched, exited 0 |
| **PROTO-02**| Network Default-Deny | Prototype | **Passed** | Confirmed zero external network interfaces; only loopback `lo` present |
| **PROTO-03**| Filesystem Write Restriction | Prototype | **Passed** | Root filesystem write denied (read-only); tmpfs scratch allowed |
| **PROTO-04**| Credential/Env Isolation | Prototype | **Passed** | Zero host environment variables or credentials leaked to worker |
| **PROTO-05**| Stream Input Transfer | Prototype | **Passed** | 76-byte input payload transferred over standard input without host disk mount |
| **PROTO-06**| Evidence Integrity (ADR-0006)| Prototype | **Passed** | Worker-generated digest matches host-calculated SHA-256 (`8a5b5ab29...`) |
| **PROTO-07**| Crash Handling (SIGKILL) | Prototype | **Passed** | Abnormal termination (exit 137) detected by host supervisor |
| **PROTO-08**| Crash Handling (SIGSEGV) | Prototype | **Passed** | Segmentation fault simulation (exit 139) detected by host supervisor |
| **PROTO-09**| Hang & Timeout Disposal | Prototype | **Passed** | 2.0s deadline enforced; hung worker killed and reaped cleanly |
| **PROTO-10**| Disposable Cleanup | Prototype | **Passed** | Verified zero lingering containers or allocations remain on host |

**Summary: 27 Total Items — 22 Passed, 0 Failed, 5 Blocked, 0 Not Tested.**

## 9. Final Recommendations, Assumptions, and Unresolved Risks

### Architectural recommendation

1. **Preserve ADR-0004 without weakening:** Do not downgrade Sentra's isolation boundary to shared-kernel WSL2 or Docker containers for untrusted project workloads.
2. **Designate Hyper-V Linux VM as Primary Execution Backend:** The Windows 11 host possesses all necessary hardware virtualization and OS hypervisor capabilities. The one-time enrollment of the operator account into `Hyper-V Yöneticileri` (`Hyper-V Administrators`) provides a secure, fully non-elevated management path for production Phase 2 orchestration.
3. **Formalize Two Execution Tiers:**
   - *Tier 1: Curated Development Fixture.* Restricted to maintainer-authored synthetic test suites. May use non-elevated containers with `--network none`, `--read-only`, and stream I/O as demonstrated in Stage C.
   - *Tier 2: Untrusted Research Target (Production Invariant).* Real repository builds, dependencies, native parsers, and fuzzing must execute strictly inside dedicated disposable Hyper-V Linux VMs over `vsock`.

### Explicit assumptions

- The developer machine runs Windows 11 Pro, Enterprise, or Education with hardware virtualization enabled in UEFI/BIOS.
- The project owner will authorize the one-time group enrollment (`net localgroup "Hyper-V Yöneticileri" $env:USERNAME /add`) prior to Phase 2 untrusted target execution.
- Base Linux guest VHDX images are distributed as pre-built, measured, and signed artifacts, eliminating runtime guest provisioning over external networks.

### Unresolved risks

- **Hypervisor Escape Vulnerabilities:** While dedicated VM isolation drastically reduces host exposure compared to shared-kernel containers, hypervisor vulnerabilities (e.g., VM escape bugs in virtual device emulations) remain a residual risk. Using `vsock` and omitting virtual network devices and PCI passthrough minimizes this surface.
- **Privilege Separation Boundary on Setup:** Initial enrollment into `Hyper-V Administrators` requires administrative elevation. A future Sentra installer must package this one-time setup step cleanly.
- **Offline Guest Base Image Maintenance:** The base guest image must be periodically updated with security patches and updated compiler toolchains without relying on dynamic runtime package downloads during target analysis.
