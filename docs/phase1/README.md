# Phase 1 Execution and Validation Record

Date: 2026-11-05; latest status update: 2026-11-06. Phase 1 is explicitly authorized by the project owner. Phase 2 is not authorized. This record links technical-validation increments and preserves historical observations. **Phase 1 is not complete.** Core library, persistence and synthetic service foundations are implemented; CLI and real provider/VM workload integrations remain unimplemented.

## Increment 5.6.2.2 update

The [targeted security remediation](INCREMENT_5_6_2_2_SECURITY_REMEDIATION.md) is implemented and tested, ready for owner review. Persistent owner-minted execution context, same-session approval/budget/audit binding, full context revalidation for automatic operations, state eligibility and a local OS admission fence through synchronous dispatch address F-561-01/F-561-02. Typed primary/secondary errors and conservative unknown usage address F-561-03. Exact bounded directory-name observations fix the reproduced timestamp-dependent directory test without claiming race-free containment. Final ordinary run: 231 runtime + 6 doctests Passed, 5 ignored entries; the workspace validator separately executes three fixtures, yielding 240 unique Passed and two indirectly exercised helper entries out of 242 discovered. Format/check/Clippy and all three existing validators pass offline. The rejected independent review remains historical evidence, not rewritten approval. No independent review or next increment was performed in this task; real effects/recovery, identity, crypto, isolation and other-platform gates remain open.

## Increment 5.4.2 update (historical)

The owner-authorized [SQLite implementation](INCREMENT_5_4_2_SQLITE_IMPLEMENTATION.md) is ready for review. Actual bundled SQLite 3.46.0 compiles through cached MSVC dependencies offline. The final driver passes 13 checks; the workspace passes 153 tests, including 49 new native persistence cases. Separate-process single-use approval, full transaction rollback/retry, atomic audit/budgets, version 1 migrations and conservative WAL-aware in-place preservation are implemented and tested. Four ordinary-suite ignored entries are explained in the report, including the subprocess helper actually launched by parent tests. The actual Windows graph has 29 external packages; unfiltered offline metadata remains blocked on an unused syn 2.0.119 source. Physical faults/power loss, native backup/restore, blob reconciliation, cryptographic integrity and full application dispatch remain open. No ADR status change, host configuration change, networking or Git mutation. Increment 5.4.3 and Phase 2 have not started. All milestone observations below remain historical.

## Increment 5.3.1 update (historical)

The [approval-binding security review](INCREMENT_5_3_1_SECURITY_REVIEW.md) is complete. The original A/B probe now requires an issued grant, rejects B with ApprovalMismatched, authorizes A once and rejects replay. Registered session/workspace/revision context, receipt provenance and atomic consumption enforce the complete current binding. Final checks record 103 Passed (101 runtime plus two compile-fail doctests), 0 Failed and three unchanged 5.3 fixture/scale cases Not Tested. All 27 new regressions pass; new barrier races ran 288 rounds across the workspace, focused and repeat commands. No dependency, unsafe code, workspace/domain/session change, network or Git mutation was introduced. The specific in-process defect is closed; production identity, filesystem and dispatch guarantees remain pending. Stop remains at 5.3.1; no 5.4 or Phase 2 work started.

## Increment 5.3 update (historical)

The [workspace validation report](INCREMENT_5_3_WORKSPACE_VALIDATION.md) is ready for review. Canonical root/instance binding, Windows reparse quarantine, metadata-only discovery and explicit limits/incompleteness are implemented in sentra-core, with 76 unique passing tests. Real internal/external junction and deny-ACL fixtures execute through the reviewed runner. Three 10,000-file Unicode/nested measurements meet the declared Q-05 fixture target; no race-free filesystem isolation or content-access authority is claimed. A separate synthetic probe Failed for the preexisting PolicyEngine current-operation grant-binding gap, so composed authorization is Blocked. Policy/session code, zero dependencies and ADR statuses are preserved. No Increment 5.4 or Phase 2 work started.

Milestone sections below are historical reports, not claims that later Core foundations remain absent.

## Milestone 4 update

The [VM and sandbox isolation report](SANDBOX_VALIDATION.md) is ready for review. Two final runs each record **22 Passed, 0 Failed, 5 Blocked and 0 Not Tested** assessment items; all 22 executable checks pass in each run. The host environment assessment confirms that Windows 11 Education (Build 26300 x64) has an active hypervisor and running Hyper-V host services (`vmms`, `vmcompute`) with ~11.5 GB free RAM and 100+ GB free disk capacity. Dedicated Hyper-V VM orchestration is currently **Blocked** because the current user is not in the local `Hyper-V Yöneticileri` (`Hyper-V Administrators`) security group (which currently has 0 members) and standard UAC tokens cannot call management WMI/cmdlets without elevation.

To validate the worker lifecycle, communication protocol, stream I/O, resource limits, crash handling, and cryptographic evidence verification without mutating host security policies, a harmless disposable prototype was executed using non-privileged container isolation (`ubuntu:24.04`). The prototype passed all 10 validation stages: baseline initialization, network default-deny (loopback only), read-only rootfs write rejection, complete credential/environment isolation (host USERNAME/USERPROFILE/COMPUTERNAME excluded), stream input transfer without host mounts, controlled output extraction with matching independent SHA-256 verification (ADR-0006), worker crash handling (SIGKILL 137, SIGSEGV 139), host timeout enforcement and forced termination, and zero lingering containers.

In accordance with ADR-0004, Docker and WSL2 are explicitly documented as **Curated development fixture protocols**, NOT a substitute for dedicated VM hardware isolation. Untrusted research workloads in Phase 2 require dedicated Hyper-V Linux VM isolation.

## Milestone 3 update

The [mock provider contract report](PROVIDER_VALIDATION.md) is ready for review. Two final runs each record **62 Passed, 0 Failed, 0 Blocked and 6 Not Tested** assessment items; all 62 named mock tests pass in each run. Formatting, offline Cargo metadata/check and Clippy pass, with no third-party dependencies. The probe covers neutral types, explicit lifecycle/capabilities, narrow typed structured output, text streams, virtual timeout/cancellation, bounded retries, conservative usage/cost accounting and policy/redaction tests. Real SDKs, Core Engine integration, tokenizers/prices, transport/OS egress, wire schemas and durable/concurrent ledger/IPC remain Not Tested. No real provider, key, external service or networking implementation is used.

Provider contract validation is independent of VM provisioning and was explicitly requested as Milestone 3 while VM management remains blocked. This reordering does not authorize untrusted execution or relax containment. SQLite is now the owner-approved persistence candidate; its required rollback/restart/checkpoint/evidence policies and all five remaining storage validation areas are preserved.

## Milestone 2 update

The [SQLite reliability report](SQLITE_VALIDATION.md) records two final runs with 18 Passed, 0 Failed, 1 Blocked and 3 Not Tested SQLite items each. Real process termination, WAL/checkpoints, rollback, migrations, backup/restore, locking and safe error paths were exercised using the existing Bun SQLite engine. JavaScript semantic type checking Failed separately; formatting and syntax bundling pass. No Rust database binding or production persistence is implemented and no ADR status changed. The owner subsequently authorized Milestone 3 and approved SQLite as a candidate, preserving physical disk exhaustion, real write/fsync IOERR, power-loss durability, Rust binding and database/blob reconciliation as unresolved. The initial-increment observations below remain historical where later evidence is linked.

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
| 2. Persistence, V-02 | Assess SQLite transactions, WAL, killed writers, integrity, backup/restore, concurrency, migration and corruption before production integration | Owner-approved candidate; engine assessment complete; production Rust binding, database/blob reconciliation and device/power-fault gaps remain unvalidated |
| 3. Provider contract | Deterministic mock-only capabilities, structured output, errors, timeout/retry, cancellation, token/cost accounting and egress-denial tests | 62 mock tests pass twice; report ready for review; real providers and Core integration Not Tested |
| 4. Worker feasibility, V-03 | Read-only Hyper-V/WSL assessment followed by an explicitly approved harmless dedicated-VM prototype | Validation report complete; 22 Passed, 0 Failed, 5 Blocked, 0 Not Tested; non-elevated prototype validated; dedicated VM orchestration blocked by Hyper-V Administrators group enrollment |
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
| SQLite / database binding | No dependency introduced: Milestone 2 uses the existing Bun SQLite engine; production Rust binding/version/license review and integration remain pending |
| Provider SDK / HTTP library | None introduced; Milestone 3 adds a separate zero-dependency Rust mock experiment, not a real adapter |

ADR-0007 remains Proposed. A future exact-version inventory must cover all selected crates, native libraries and redistribution notices before use/distribution. This empty crate inventory does not satisfy that future review in advance.

## Initial traceability and remaining gates

| Gate / requirement | Current evidence |
| --- | --- |
| V-01 / OQ-01 / OQ-02 | Partially validated: x64 toolchain, linking, three probe tests, format/lint and basic Unicode/CRLF/error behavior |
| ADR-0002 remaining gate | Supervised process trees/bounded I/O/recovery, native dependency integration, SQLite/blob recovery and authenticated worker channel are not validated |
| V-02 / OQ-09 / Q-04 | Milestone 2 engine assessment executed; actual Rust integration, database/blob reconciliation and untested device/power-fault scenarios remain pending |
| V-03 / OQ-03 / S-07 / S-13 | Milestone 4 assessment complete; protocol/lifecycle/crash/integrity prototype passes (22 items); non-elevated Hyper-V orchestration blocked pending group authorization |
| V-04 / F-01 / S-11 / Q-05 | No project discovery implementation, path-security suite or 10,000-file measurement yet |
| V-05 / F-02 / F-14 / S-01 / S-02 / Q-03 | No production session, policy, approval, cancellation or persistence implementation yet |
| Provider contract / F-15 subset, F-16, S-06, S-14 | Milestone 3 passes 62 mock tests twice; production Core integration, wire/process conformance, real backend compatibility and OS egress remain pending; F-15's full gate remains Phase 2 work |
| Core / CLI | Not implemented; no product unit/integration/security suite has run |

**Milestone 1 assessment:** the narrow x64 standard-library probe and its listed checks passed; only the isolated probe was implemented. V-01 and host virtualization availability remained partial; provider contract, core/CLI and full process/path/permission/security behavior were unvalidated. Local VM management and ARM64 compilation were blocked as described above. Milestone 2 adds SQLite engine evidence without validating the production Rust binding or the remaining storage gaps.

Cargo offline mode and absence of networking code constrain this experiment; no packet capture or OS-enforced network-isolation test was performed. Public documentation was read, but no repository source, private data or findings were sent to an AI provider. No API keys, telemetry or cloud service was used.

## Increment quality checks

At Milestone 1, the documentation checker passed for 33 Markdown documents, 192 local file/fragment links, 50 table structures and all 41 requirement-to-validation mappings. All seven ADR contents matched their entry SHA-256 digests and indexed statuses. Source, manifest and runner matched the raw experiment evidence; PowerShell parser and Git whitespace checks passed. These counts describe that increment, not the later SQLite report.

Branch, HEAD, full local history, reference targets and index entries match the entry snapshot. These are initial-increment checks, not the complete Phase 1 quality gate. The aggregate experiment runner still exits 1 for the unfulfilled ARM64 check, and no product core/CLI/security or SQLite tests are included in the three passing probe tests.

The agent has issued no Git commit, amend, reset, rebase, cherry-pick, tag, push, fetch, pull, staging, stashing or history/reference-changing operation. Subsequent externally performed commits are recorded in the progress ledger; new completion edits remain in the working tree. Phase 1 is in progress, not complete; Phase 2 is not ready or authorized. Milestone 3's mock provider report is ready for review; no following milestone was started, and the VM permission/configuration prerequisite remains unresolved.
