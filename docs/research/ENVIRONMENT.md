# Development Environment Inspection

Observed on 2026-11-05 in `E:/MyProject/Mix/GitHub/Sentra`, using PowerShell. Commands were read-only. No dependencies, workloads, services, images, or toolchains were installed or started.

## Repository

| Item | Observation |
| --- | --- |
| Branch | `develop` |
| Initial working tree | Clean |
| Initial tracked content | `.gitattributes` only |
| Text attributes | `* text=auto` for Git text normalization |
| Existing application/manifests/tests | None |
| Ancestor/repository AGENTS.md files | None found at the checked ancestor locations; user-supplied global instructions applied |

The requested documentation is new. The existing `.gitattributes` is preserved. No Git commit, tag, or push is part of this work.

## Tools and runtime observations

| Item | Observed value | What it proves |
| --- | --- | --- |
| User-declared host | Windows 11 | Development target declaration |
| Runtime OS description | `Microsoft Windows 10.0.26300` | Kernel/build identifier; the `10.0` prefix does not independently identify the Windows product edition |
| PowerShell | `7.6.9` | Actual inspected version; differs from the supplied general environment note of 7.6.6 |
| Git | `2.56.0.windows.2` | Git executable available |
| Bun | `1.4.4` | Approved JavaScript/TypeScript runtime available |
| rustc | `1.99.0 (b940084d7 2026-09-28)` | Compiler executable responds |
| Cargo | `1.99.0 (5f94df478 2026-08-27)` | Cargo executable responds |
| Active Rust toolchain | `stable-x86_64-pc-windows-msvc` | Configured toolchain identity |
| Docker CLI/Engine | `29.9.2`, API `1.56` | Client available and server metadata reachable |
| Docker Desktop | `4.98.0 (245422)` | Server-reported platform identity |
| Docker server platform | Linux / amd64 | Current engine does not provide evidence of Windows-container or native Windows-target support |
| Server kernel | `6.18.54.1-microsoft-standard-WSL2` | Engine is using a WSL2 Linux kernel |
| WSL | Default version 2; `docker-desktop` distribution listed | WSL configuration exists; output was UTF-16-oriented in command capture |
| ripgrep / CMake | Commands resolved | Tools available; no build validated |
| Podman / clang / cl | Not resolved in the current shell PATH | No proof that those tools are absent from the machine |
| Visual Studio discovery | Standard `vswhere.exe` probe returned no matching VC x86/x64 tools installation version | Required MSVC toolchain components remain unverified; no installation attempted |

## Inspection commands

The inspection used PowerShell directory and command discovery, `git status --short --branch`, `git ls-files`, `rg --files`, version commands for Git/Bun/Rust/Cargo/Docker, `rustup show active-toolchain`, `wsl --status`, `wsl --list --quiet`, Docker server metadata, and a narrowly scoped Visual Studio discovery query.

Tool availability is not a successful compile or execution test. No Rust source was written or compiled, and no container or VM was launched. Hyper-V edition/feature eligibility, available memory/disk, guest images, nested virtualization, worker networking, and containment controls were not validated.

## Consequences for planning

1. Rust is plausible on the host but requires a Phase 1 compile/link spike.
2. Bun can support future Sentra-owned TypeScript tooling without another JavaScript runtime.
3. Existing Docker Desktop can help with curated development fixtures after implementation approval; it does not fulfill the disposable-VM security requirement.
4. A local dedicated Linux VM candidate needs explicit prerequisite and worker validation. No general-purpose Linux user distribution is assumed from the Docker WSL listing.
5. Installed versions are observations, not project minimum versions. Pin supported versions only after the relevant validation gates.
