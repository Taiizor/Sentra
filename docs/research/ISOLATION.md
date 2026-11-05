# Isolation and Execution Research

The host is Windows 11; most initial dynamic-analysis candidates assume Linux user space. Host convenience, process organization, and hostile-code containment are separate concerns. This comparison is based on documentation, not a local escape assessment.

## Technology comparison

| Technology | Source-reported boundary / requirement | Sentra assessment |
| --- | --- | --- |
| Docker Engine | Namespaces, capabilities, daemon access, and kernel security are relevant to containment. [S34](SOURCES.md#s34) | Useful tool packaging and trusted-fixture execution. Shared-kernel containers alone are insufficient for real hostile research workloads. |
| Docker Desktop WSL2 | Linux engine runs using WSL2, with host/guest integration. [S35](SOURCES.md#s35) | Existing local convenience, not an automatically disposable per-session research VM. No mounts of developer home, credentials, or engine sockets. |
| Docker Enhanced Container Isolation | Additional isolation controls with a documented Business subscription requirement. [S36](SOURCES.md#s36) | Optional defense in depth; not a mandatory open-source platform dependency or a replacement for the required VM profile. |
| Hyper-V | Windows hardware-virtualization platform for guest VMs. [S37](SOURCES.md#s37) | First local disposable Linux-VM candidate. Edition, features, image licensing, resource limits, network isolation, snapshots, and automation remain unvalidated locally. |
| Windows Sandbox | Disposable hypervisor-isolated desktop on supported Windows editions. [S38](SOURCES.md#s38) | Possible future manual Windows investigation aid. Not chosen as the initial headless job manager; automation, evidence export, and networking need a separate study. |
| gVisor | Userspace application-kernel approach with compatibility constraints. [S39](SOURCES.md#s39) | Optional Linux-worker hardening. Not a native Windows execution backend and not required initially. |
| Firecracker | Uses Linux KVM to run microVMs. [S40](SOURCES.md#s40) | Future dedicated Linux execution infrastructure. Do not promise native Windows/Hyper-V deployment or nested-KVM availability. |
| Wasmtime / WASI | Sandboxed WebAssembly with host-exposed capabilities as part of the security boundary. [S41](SOURCES.md#s41) | Candidate for restricted data-processing extensions. Does not run arbitrary native build/test/fuzz workloads without a separate execution strategy. |
| Host child process / Windows job object | Process lifecycle/resource control mechanism; Sentra must validate its use | Useful for trusted Sentra helpers and cancellation. Not accepted as the sole untrusted-code security boundary. |

## Execution profiles

| Profile | Permitted work | Required controls | Initial availability |
| --- | --- | --- | --- |
| Metadata-only | Bounded file/manifest discovery; no target code execution | Scoped read access, path/size validation, untrusted-data handling | Phase 1 target |
| Curated development fixture | Maintainer-reviewed synthetic targets | Hardened container, resource limits, no secrets, denied egress | Implementation testing only; not real-target containment |
| Untrusted user-space research | Real builds, native scanners/parsers, tests, generated PoCs, fuzzing | Disposable dedicated VM, isolated guest storage, authenticated job control, network deny, quotas, clean reset | Required before Phase 2 real-target execution |
| Kernel / high-risk exploitation | Kernel-target validation, kernel attack primitives, privileged instrumentation | Separate threat model, guest-kernel control, dedicated VM/host policy, snapshot recovery, additional approval | Deferred; no initial claim |
| Windows-native target | PE execution, Windows-only builds, OS-specific instrumentation | Separately validated Windows VM profile and compatible tools | Deferred |

## Recommended first topology

The Windows CLI controls a dedicated disposable Linux VM through a narrowly scoped authenticated worker interface. Tools may run in hardened containers inside that VM. Transfer only manifest-listed input blobs and explicit artifacts; do not expose a general host filesystem share. Reset the guest before a fresh verification run and between unrelated projects.

The operator selects and approves a VM backend. If Hyper-V cannot meet local prerequisites, an explicitly authorized dedicated Linux VM endpoint is an alternative, not an automatic cloud fallback. Remote transfer of proprietary source is a separate egress decision. Missing required isolation blocks the task.

The control plane may communicate with the trusted worker supervisor, but target workloads cannot access that management channel, control-plane credentials, provider credentials, hypervisor APIs, or cloud metadata services. Target internet access defaults to denied. Brokered build dependency provisioning uses pinned artifacts and a separate, scoped fetch stage; internal package registries need explicit credential and egress design.

## Required controls before real targets

- Boot from a versioned, measured base image and create a disposable overlay. Record guest kernel, tool image, compiler, and configuration identities.
- Disable privileged containers, broad capabilities, host networking, device passthrough, shared clipboard, home/credential mounts, and guest-to-host integration not required for the worker.
- Enforce CPU, memory, disk/inode-equivalent capacity, process count, wall time, output size, and total campaign quotas at the appropriate guest/hypervisor layers.
- Separate the trusted guest supervisor from target processes; expose only the current lease and artifact submission scope.
- Deny outbound DNS and network access unless allowed. Enforce destination and redirect rules outside target control; audit approved dependency-fetch traffic.
- Validate artifact paths, sizes, symlinks, compression ratios, MIME handling, and terminal control sequences before intake.
- On cancellation, stop dispatch, revoke leases, terminate/reset the VM where reachable, and verify cleanup. Quarantine any uncertain worker; do not reuse a dirty guest.

These are Sentra requirements. Each selected backend must demonstrate them; none follows merely from the presence of a VM product.

## Residual risks

A hypervisor, guest supervisor, parser, toolchain, or artifact importer may have exploitable bugs. Host administrator compromise, malicious base images, side channels, and all novel VM escapes are not eliminated. Dedicated single-operator use reduces initial tenancy complexity; shared-host multi-tenant claims require a separate design and independent assessment.

The Phase 1 topology spike establishes feasibility; Phase 2 containment tests establish the initial supported profile. Phase 3 fuzzing does not authorize kernel-target or production-service testing.
