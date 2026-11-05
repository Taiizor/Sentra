# Open Questions, Assumptions, and Decision Gates

Owner entries are accountable roles to be assigned, not claims that those people already exist. No unresolved item authorizes implementation or weakens a security invariant. Phase 1 still requires explicit owner approval.

## Decision register

| ID | Question / assumption | Owner role | Deadline and evidence | Safe default / reversal |
| --- | --- | --- | --- | --- |
| OQ-01 | Is Rust the right core language on this Windows host? | Core maintainer | P1 before workspace expansion: V-01 compile/link, process, storage, packaging results | Keep ADR-0002 proposed; evaluate Go/C# if gates fail |
| OQ-02 | Are MSVC linker/Windows SDK prerequisites installed and sufficient? | Core maintainer | First P1 build spike; no matching tools version was returned by current discovery probe | Do not claim build readiness or install workloads during P0 |
| OQ-03 | Can local Hyper-V provide the required dedicated Linux VM topology? | Execution maintainer | P1 topology spike; verify edition, features, resources, image, network, automation and reset | Block untrusted execution; evaluate explicitly approved dedicated VM endpoint |
| OQ-04 | Can selected backend enforce containment/egress and cleanup? | Security/execution maintainer | P2 before real targets: full containment and credential canary suite | No real builds, tests, scanners, or PoCs on an unvalidated backend |
| OQ-05 | What should OSS-CRS provide versus Sentra's own research scheduler? | Research maintainer | Before custom P3 harness/campaign infrastructure: fixed-corpus interoperability/baseline comparison | Prefer coarse-grained reuse; remove duplicated functionality if upstream fits |
| OQ-06 | Which provider endpoints satisfy tool-call, usage, privacy, and cancellation requirements? | AI/security maintainer | P2: two-backend conformance, including validated local/private option | No mandatory provider; hosted egress off until explicitly approved |
| OQ-07 | What is the initial reviewed Rust source/oracle fixture set? | Research maintainer | Before P2 evaluation: at least 20 labeled change cases and license review | No generalized Rust accuracy/support claim |
| OQ-08 | Which libFuzzer/AFL++ configuration and C/C++ reference corpus should be supported? | Research maintainer | P3 before support declaration: pinned tools, ten targets and repeated comparison | One narrow Linux user-space envelope; no custom mutation engine |
| OQ-09 | Which SQLite release, journal mode, durability and backup strategy pass crash recovery? | Core maintainer | P1 V-02 and P2 migration/restore test | Local volume only; no network WAL; preserve unresolved executions |
| OQ-10 | Are Semgrep engine/rules, CodeQL entitlement, CRS dependencies, models and fixtures compatible with product use? | Licensing reviewer | Before each integration/use/package gate: exact-version license and notices inventory | Do not bundle restricted rules or assume proprietary-target entitlement |
| OQ-11 | Which OSI license should cover Sentra? | Project owner | Before public distribution: explicit license selection and matching file/notices | Apache-2.0 proposal only; no implied license grant |
| OQ-12 | Which private vulnerability-reporting channel is monitored? | Project owner / security maintainer | Before first release: configure, test, publish contact and response process | No invented contact address or SLA |
| OQ-13 | What are retention defaults and encryption/key-management requirements? | Security maintainer | Before P2 sensitive evidence collection: per-class retention, deletion/backups, encrypted-volume policy and key plan | Require declared retention and approved encrypted volume; application-level encryption unclaimed |
| OQ-14 | Are Rust/Bun lockfiles and private registries handled correctly by chosen scanners? | Tool maintainer | Per-adapter fixture/credential tests before support declaration | Cargo.lock pilot only; Bun runtime availability is not lockfile-analysis support |
| OQ-15 | Which exact MCP SDK/revision and API transport should be implemented? | Integration maintainer | P4: pin candidate revision and test protocol/auth/SSRF/approval parity | Stdio first; HTTP disabled until security gate passes |
| OQ-16 | Do local approvals need signatures, OS-protected storage, or remote human identity? | Security/core maintainer | P1 local design; revisit before P4 remote access | Trust local operator/host admin; no model-granted permissions; no administrator-tamper claim |
| OQ-17 | How much verifier independence is practical within cost/latency budgets? | Research/security maintainer | P2/P3: compare isolated tasks, model/provider overlap and sampled human reviews | Require separate tasks/context/oracle/fresh runs; disclose shared-model bias |
| OQ-18 | How will offline models, images, dependencies and advisory snapshots be provisioned? | Execution/AI maintainer | P2 offline pilot: measured zero unexpected egress and freshness policy | Offline claim requires pre-provisioned artifacts; missing inputs stay incomplete |
| OQ-19 | Which Windows-native, binary-only, and kernel profiles are justified? | Research/execution maintainer | P6 or later: separate threat model, tooling, licensing and containment validation | Ghidra/Frida optional; no initial native/kernel support |
| OQ-20 | When is distributed workflow/storage infrastructure justified? | Core/platform maintainer | After measured multi-worker recovery/scale limits | Single-operator local core; revisit Temporal/server database before expanding custom infrastructure |
| OQ-21 | Are name/trademark and public project governance ready? | Project owner | Before public launch: naming and contribution/governance review | Keep current working identity without asserting name clearance |

## Critical assumptions

- The operator has legitimate authority over the selected source and separately approves any runtime/service targets. The software cannot independently prove legal authority from source possession.
- Initial dynamic targets can be reproduced in Linux user space. Private enterprise applications may have unavailable infrastructure, secrets, datasets, or licenses and must remain unsupported/inconclusive until an adapter strategy exists.
- A dedicated VM is operationally feasible. Existing Docker/WSL metadata does not establish this.
- A meaningful security oracle and regression suite can be defined for some initial fixtures. Not all findings will permit automatic dynamic verification.
- Model outputs and tool results can be constrained through brokered capabilities, but neither is assumed correct or injection-proof.
- Local administrator compromise and shared-host adversarial tenancy are outside the initial trust model. Future hosting changes this assumption.
- Historical benchmarks can be contaminated and are only partial evidence. Novel discovery performance remains an empirical question.

## What blocks what

Phase 0 can finish with these questions explicitly recorded. Owner approval blocks entry to Phase 1. Rust/toolchain/storage results block expanding the selected implementation foundation. Worker containment blocks real target execution. Provider/retention decisions block confidential egress/collection. License and disclosure-channel choices block public distribution. Windows-native, kernel, distributed hosting, and binary-only decisions do not block the narrow initial pilots.
