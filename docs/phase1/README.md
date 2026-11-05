# Phase 1 Initial Execution and Validation Report

Date: 2026-11-05. Phase 1 is explicitly authorized by the project owner. Phase 2 is not authorized. This report covers the requested initial inspection and first technical-validation increment, before substantial application implementation. **Phase 1 is not complete.**

## Repository and instructions

- Entry branch: `develop`; HEAD: `e3a2589c5380ddc26980ae1aec13010a0a729723`; local `origin/develop` at the same commit, ahead/behind 0/0. The entry working tree was clean.
- The earlier four Phase 0 closure edits were committed in `e3a2589` (`Document permanent Git policy and Phase 0 closure`, 2026-11-05T16:41:04+03:00), whose parent is `22676aa40871cbc86f6c101cfb71aa4b79f09a37`. They were preserved.
- The global `C:/Users/Taiizor/.codex/AGENTS.md`, project instructions, required root documents, all seven ADRs, and relevant contracts/research were inspected before changes.
- The prompt's `docs/ISOLATION.md` does not exist. The existing [isolation research](../research/ISOLATION.md) is the relevant document; no duplicate was created.
- No accepted ADR conflicts with the authorized Phase 1 scope. Explicit approval satisfies the earlier phase gate; it does not authorize Git mutations or Phase 2 work.

## Dependency-ordered execution breakdown

| Increment | Experiment before dependent implementation | Required outcome / current state |
| --- | --- | --- |
| 1. Rust/MSVC, V-01 | Dependency-free isolated Cargo package; exact toolchain/linker discovery; x64 build/tests/lints/runtime and ARM64 check | Initial x64 subset validated; full V-01 remains partial |
| 2. Persistence, V-02 | Pin a reviewed SQLite integration and test transactions, WAL, killed writers, integrity, backup/restore, concurrency, migration and corruption handling | Not started; no database abstraction or additional storage selected |
| 3. Worker feasibility, V-03 | Read-only Hyper-V/WSL assessment followed by an explicitly approved harmless dedicated-VM prototype | Read-only assessment partial; management queries blocked by current permissions; no VM provisioned |
| 4. Provider contract | Deterministic mock-only capabilities, structured output, errors, timeout/retry, cancellation, token/cost accounting and egress-denial tests | Not started; no API keys, real providers or external data transfer required |
| 5. Core foundation, V-04/V-05 | Implement only after relevant storage/process/policy assumptions pass; scope/path fixtures, sessions, evidence, approvals, recovery and discovery measurement | Not implemented; no production workspace or dependency set selected |
| 6. CLI foundation | Add a thin frontend to validated core services, with stable human/JSON results and permission/error tests | Not implemented; experiment executable is not the product CLI |

ADR-0002 remains **Proposed** until its complete evidence gate passes. ADR-0007 remains **Proposed**, because a project license has not been selected. The five accepted design ADRs are unchanged. Rust was not replaced and no architecture was weakened.

## Initial Rust/MSVC experiment

The isolated [Cargo package](../../experiments/phase1/rust-msvc/Cargo.toml) uses only the Rust standard library. Its local workspace boundary prevents it from committing the future production workspace layout. It reads an operator-supplied UTF-8 fixture, counts lines, and returns explicit errors. It contains no networking, telemetry, vulnerability analysis, plugin loading, build script, or third-party dependency.

The [PowerShell runner](../../experiments/phase1/rust-msvc/Validate.ps1) captures exact commands, outputs, exit codes, timeout flags, durations, tool versions, installed targets, SDK inventory, and source/runner/manifest SHA-256 digests in [results.json](../../experiments/phase1/rust-msvc/results.json). Build and generated fixture directories are ignored locally; evidence JSON and the dependency-free lockfile are intentional review artifacts.

Reproduce from the repository root:

```powershell
pwsh -NoProfile -File experiments/phase1/rust-msvc/Validate.ps1
```

The runner returns **1** on this machine because the ARM64 check fails. That failure is deliberately preserved, not waived into a passing aggregate result. The recorded x64 steps pass independently. Each child command has a 30-second default limit; the runner uses structured process arguments and does not alter persistent environment variables. This helper's timeout mechanism is not the full future Windows process-tree security validation.

### Observed environment

| Item | Observation |
| --- | --- |
| Host | Windows 11 Education, build `10.0.26300`, x64 |
| PowerShell | `7.6.9`; the supplied general note of 7.6.6 differs from the inspected runtime |
| Rust | `rustc 1.99.0 (b940084d7 2026-09-28)`, LLVM `23.1.1` |
| Cargo | `1.99.0 (5f94df478 2026-08-27)` |
| Toolchain / installed target | `stable-x86_64-pc-windows-msvc` / only `x86_64-pc-windows-msvc` |
| rustfmt | `1.10.0-stable (b940084d7e 2026-09-28)` |
| Clippy | `0.1.99 (b940084d7e 2026-09-28)` |
| Visual Studio | Enterprise 2026 Insiders, installation `18.12.12324.72` |
| Actual linker | `D:/Program Files/Microsoft Visual Studio/2026/Insiders/VC/Tools/MSVC/14.52.37025/bin/HostX64/x64/link.exe`; file version `14.52.37025.0` |
| SDK root | `D:/Windows Kits/10` |
| Installed SDK library versions | `10.0.22621.0`, `10.0.26100.0`, `10.0.28000.0` |
| Git / Bun | `2.56.0.windows.2` / `1.4.4` |

Initial `vswhere -all -products '*'` returned an empty list because the installation is a prerelease. Adding `-prerelease` finds it. The PATH-resolved `link.exe` is a coreutils utility, but Rust successfully discovers the real MSVC linker independently. `cargo rustc ... -- --print link-args` records the actual linker path. The SDK inventory establishes installed versions, not an explicitly pinned SDK or a claim that each was separately tested.

The official [Rust MSVC target documentation](https://doc.rust-lang.org/rustc/platform-support/windows-msvc.html), [rustc command-line reference](https://doc.rust-lang.org/rustc/command-line-arguments.html), and [Microsoft command-line tooling documentation](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line?view=msvc-170) were checked for diagnostic context. Local experiment results, rather than upstream support tiers, establish the narrow validation below.

### Executed results

All Cargo compilation commands used `--offline`; the runner also sets `CARGO_NET_OFFLINE=true` for its child processes. Every command includes the isolated manifest path; exact argument arrays and full diagnostics are in the JSON evidence.

| Command / check | Result | Meaning and limits |
| --- | --- | --- |
| `cargo fmt ... -- --check` | Exit 0 | Probe formatting passes |
| `cargo check --offline ... --all-targets --target x86_64-pc-windows-msvc` | Exit 0 | Probe and test code type-check |
| `cargo clippy --offline ... --all-targets --target x86_64-pc-windows-msvc -- -D warnings` | Exit 0 | Probe static analysis passes without warnings |
| `cargo build --offline ... --target x86_64-pc-windows-msvc` | Exit 0 | Actual x64 native compilation/linking succeeds |
| `cargo test --offline ... --target x86_64-pc-windows-msvc` | Exit 0; three passed, none ignored/filtered | Unicode/CRLF line counting, NUL rejection and empty-input behavior execute successfully |
| `cargo run --offline ... --target x86_64-pc-windows-msvc -- <fixture>` | Exit 0; `lines=2` | Runtime reads a file beneath a directory containing spaces and Unicode; runner checks the expected output |
| Probe with missing argument / missing file | Expected exits 2 / 1 | Error behavior matches expectations; not product CLI validation |
| `cargo rustc --offline ... --target x86_64-pc-windows-msvc -- --print link-args` | Exit 0 | Identifies the actual MSVC linker; does not pin an SDK |
| `cargo check --offline ... --target aarch64-pc-windows-msvc` | Exit 101; E0463, missing `std` | ARM64 standard library is not installed. No ARM64 executable was compiled or run |

No ARM64 component was installed. An ARM64 tools directory exists in the MSVC installation, but its presence is not compilation or execution validation. There is no ARM64 support claim, MSRV claim, stable Visual Studio release matrix, native-crate compatibility claim, or general Windows security guarantee.

The successful build/run and tests were repeated as the runner gained linker discovery, negative CLI cases and output/digest checks. This is a reproducibility check on one host, not an independent-machine validation. No benchmark or discovery performance test was executed.

## Read-only VM feasibility observations

| Observation | Result / limit |
| --- | --- |
| Hypervisor / memory | `HypervisorPresent=true`; `34,091,286,528` bytes physical memory reported |
| Hyper-V module | Version `2.0.0.0` is available; `Get-VM` resolves |
| Services | `vmms` and `vmcompute` report Running |
| Feature query | `Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All` requires elevation in this session; feature state not established |
| VM query | `Get-VM` reports insufficient permission; existing VM inventory not available |
| WSL query | Default version 2; only `docker-desktop` listed, Stopped at inspection |

Commands used: `Get-CimInstance Win32_OperatingSystem`, `Get-CimInstance Win32_ComputerSystem`, `Get-Module -ListAvailable Hyper-V`, `Get-Service vmms,vmcompute`, the feature and VM queries above, `wsl --status`, and `wsl --list --verbose`. These are observations, not an authenticated-worker or containment test.

No service, distribution, container, VM, snapshot or network was started or created. No feature, host security setting, group membership, virtualization software or host configuration was changed. No credentials were supplied to a worker. VM communication, default-deny networking, filesystem/secret isolation, quotas, reset and failure recovery are **not validated**.

The safe next options are an owner-approved Hyper-V management/provisioning path with explicit configuration boundaries, or a separately approved dedicated Linux VM endpoint. An ordinary Docker/WSL container is not a substitute. Until the dedicated worker gate passes, real untrusted execution stays disabled by design; no backend is implemented yet.

## Dependency and license inventory for this increment

| Component | State |
| --- | --- |
| Probe source and runner | New local experiment; no product release or license selection implied |
| Cargo dependencies | Zero direct or transitive third-party crates; lockfile contains only the probe package |
| Rust standard library/toolchain | Existing installed toolchain; exact versions recorded above; no toolchain installation or redistribution |
| MSVC / Windows SDK | Existing installed native tools; local smoke use only; no installation, entitlement conclusion or redistribution |
| SQLite / database binding | None introduced; executable/binding/license/version selection and reliability tests remain pending |
| Provider SDK / HTTP library | None introduced; mock contract work remains pending |

ADR-0007 remains Proposed. A future exact-version inventory must cover all selected crates, native libraries and redistribution notices before use/distribution. This empty crate inventory does not satisfy that future review in advance.

## Initial traceability and remaining gates

| Gate / requirement | Current evidence |
| --- | --- |
| V-01 / OQ-01 / OQ-02 | Partially validated: x64 toolchain, linking, three probe tests, format/lint and basic Unicode/CRLF/error behavior |
| ADR-0002 remaining gate | Supervised process trees/bounded I/O/recovery, native dependency integration, SQLite/blob recovery and authenticated worker channel are not validated |
| V-02 / OQ-09 / Q-04 | SQLite integration, integrity, migration, concurrency, backup/restore, crash/corruption and blob reconciliation not started |
| V-03 / OQ-03 / S-07 / S-13 | Read-only host observation only; VM management permission is a blocking prerequisite for the local topology experiment |
| V-04 / F-01 / S-11 / Q-05 | No project discovery implementation, path-security suite or 10,000-file measurement yet |
| V-05 / F-02 / F-14 / S-01 / S-02 / Q-03 | No production session, policy, approval, cancellation or persistence implementation yet |
| Provider contract / F-16 | Mock-only design/test increment pending; real provider compatibility in F-15 remains Phase 2 work |
| Core / CLI | Not implemented; no product unit/integration/security suite has run |

**Validated:** the narrow x64 standard-library probe and its listed checks. **Implemented and tested:** the isolated probe only. **Partially validated:** V-01 and host virtualization availability. **Not validated:** SQLite/native crate integration, provider contract, core/CLI, full process/path/permission/security behavior. **Blocked:** local VM management/provisioning under the current permissions, and ARM64 compilation under the currently installed targets.

Cargo offline mode and absence of networking code constrain this experiment; no packet capture or OS-enforced network-isolation test was performed. Public documentation was read, but no repository source, private data or findings were sent to an AI provider. No API keys, telemetry or cloud service was used.

## Increment quality checks

The documentation checker passed for 33 Markdown documents, 192 local file/fragment links, 50 table structures and all 41 requirement-to-validation mappings. All seven ADR contents match their entry SHA-256 digests and their indexed statuses remain consistent. The new source, manifest and runner match the digests in the raw experiment evidence. PowerShell parser validation reports zero errors; Git whitespace checks pass. No unexpected non-document artifacts were found outside the explicitly declared experiment files and ignored build/fixture outputs.

Branch, HEAD, full local history, reference targets and index entries match the entry snapshot. These are initial-increment checks, not the complete Phase 1 quality gate. The aggregate experiment runner still exits 1 for the unfulfilled ARM64 check, and no product core/CLI/security or SQLite tests are included in the three passing probe tests.

No Git commit, amend, reset, rebase, cherry-pick, tag, push, fetch, pull, staging, stashing or history/reference-changing operation was performed. Changes remain in the working tree. Phase 1 is in progress, not complete; Phase 2 is not ready or authorized. The next bounded technical increment is SQLite reliability after its exact integration choice is reviewed, while the VM permission/configuration prerequisite is resolved separately.
