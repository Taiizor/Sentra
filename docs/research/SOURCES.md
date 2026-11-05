# Primary Source Register

Reviewed on **2026-11-05**. Links identify publisher/project sources used in Phase 0; they are not version locks or proofs of local compatibility. Each entry states the narrow evidence used. External claims in research documents link here; Sentra-specific requirements and recommendations are design judgments.

### S01

[Vercel — Introducing Vercel Security Review](https://vercel.com/blog/vercel-security-review). Published 2026-11-02. Evidence: contextual push/change review, tracking, and permission-based fix workflow. Accessible canonical replacement for the supplied `/blog/security-review` URL, which could not be retrieved. Vendor description, not an independent evaluation.

### S02

[OpenAI — A thousand fewer paths to root](https://openai.com/index/a-thousand-fewer-paths-to-root/). Published 2026-11-04. Evidence: Scout/Analyst separation, dynamic VM validation, impact assessment, patching, and human review. Reported campaign outcomes are not Sentra benchmarks or guarantees.

### S03

[DARPA — AI Cyber Challenge results](https://www.darpa.mil/news/2025/aixcc-results). Evidence: competition demonstrated autonomous discovery/patching systems. Competition conditions differ from arbitrary enterprise analysis.

### S04

[OpenSSF OSS-CRS — Overview and quick start](https://oss-crs.openssf.org/). Evidence: OSS-Fuzz-style targets, compose-based CRS use, and documented Python/uv/Docker/Git prerequisites. No Sentra integration was executed.

### S05

[OSS-CRS — Architecture](https://oss-crs.openssf.org/docs/design/architecture). Evidence: orchestration, component isolation/composition, infrastructure, and budget-oriented interfaces. Container isolation is evaluated under Sentra's separate threat model.

### S06

[OSS-CRS — CRS Development Guide](https://oss-crs.openssf.org/docs/crs-development-guide). Evidence: prepare/build/run contracts, libCRS artifact exchange, and absent-test-script success semantics. Exact skipped-test mapping must be checked at an implementation revision.

### S07

[OSS-CRS — CRS Registry](https://oss-crs.openssf.org/registry). Evidence: modular finding, fuzzing, harness, seed, triage, and patch-related integrations exist. Registry membership does not validate a component's license, safety, or compatibility for Sentra.

### S08

[Trail of Bits — Buttercup is now open-source](https://blog.trailofbits.com/2025/08/08/buttercup-is-now-open-source/). Published 2025-08-08. Evidence: system components, standalone variant, existing fuzzing/context tools, and multi-agent patching. Local resource claims need measurement.

### S09

[Team Atlanta — Research publications and source code](https://team-atlanta.github.io/artifacts/). Evidence: Atlantis, patching modules, technical reports, and OSS-CRS-related artifacts are available for investigation. Source-code auditing and license composition were not performed.

### S10

[Google OSS-Fuzz — Architecture](https://google.github.io/oss-fuzz/architecture/). Evidence: established fuzzing build/execution architecture and related ecosystem. The public service is not assumed suitable for proprietary inputs.

### S11

[LangChain — LangGraph overview](https://docs.langchain.com/oss/python/langgraph/overview). Evidence: workflow graph/state, persistence, interrupts, and agent orchestration capabilities. No OS containment guarantee is inferred.

### S12

[Temporal — Platform documentation](https://docs.temporal.io/). Evidence: durable execution and workflow platform as an alternative to custom distributed scheduling. No specific Rust SDK maturity or zero-operations claim is made.

### S13

[OpenHands — Introduction](https://docs.openhands.dev/overview/introduction). Evidence: AI development application/SDK ecosystem and integration surface. Does not establish Sentra-specific permission/evidence compliance.

### S14

[Rust — Platform support](https://doc.rust-lang.org/rustc/platform-support.html). Evidence: support tiers and host/target distinctions. Upstream tier support does not establish Sentra support.

### S15

[Rust — Windows MSVC targets](https://doc.rust-lang.org/rustc/platform-support/windows-msvc.html). Evidence: Windows MSVC targets and tooling/platform prerequisites. The earlier guessed `/pc-windows-msvc.html` path was unavailable; this reviewed path is used.

### S16

[Cargo — Build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html). Evidence: a build can execute project/dependency-controlled scripts. Supports treating target builds as untrusted execution.

### S17

[Bun — Installation](https://bun.sh/docs/installation). Evidence: documented Windows runtime/tooling availability. Installed Bun version was observed separately; package-level compatibility was not tested.

### S18

[Go — Installing from source and supported systems](https://go.dev/doc/install/source). Evidence: host/target/toolchain alternative for the core-language comparison. No performance comparison was run.

### S19

[Microsoft — .NET Native AOT overview](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/). Evidence: native deployment alternative and limitations. No .NET environment was installed or validated.

### S20

[Semgrep — Licensing](https://docs.semgrep.dev/licensing). Evidence: separate CE engine, proprietary offerings, and rule licenses with usage restrictions. Recheck exact applicable license text/version before use; no default rule redistribution is authorized by this research.

### S21

[Semgrep — Supported languages](https://docs.semgrep.dev/supported-languages). Evidence: coverage depends on language and product tier. No universal CE language/dataflow parity is assumed.

### S22

[GitHub — CodeQL CLI](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli). Evidence: database/query workflow, SARIF, and usage/license conditions. Operator entitlement and private-target use must be checked before integration.

### S23

[Tree-sitter — Using parsers](https://tree-sitter.github.io/tree-sitter/using-parsers/). Evidence: parser API and language bindings. Syntax trees are not a complete semantic security analysis.

### S24

[RustSec — Advisory database and tooling](https://rustsec.org/). Evidence: Cargo.lock advisory analysis and related Rust supply-chain tools. No reachability guarantee is inferred.

### S25

[Embark — cargo-deny](https://embarkstudios.github.io/cargo-deny/). Evidence: dependency advisories, licenses, bans, and source-policy checks. Configuration and resolution behavior require adapter validation.

### S26

[Google — OSV-Scanner](https://google.github.io/osv-scanner/). Evidence: dependency/advisory scanner and supported-artifact documentation. Exact Bun lockfile support is left unresolved.

### S27

[OSV-Scanner — Offline mode](https://google.github.io/osv-scanner/usage/offline-mode/). Evidence: local database workflow. Initial provisioning and update egress are separate from offline queries.

### S28

[OpenSSF — OSV schema](https://ossf.github.io/osv-schema/). Evidence: advisory identifiers, affected packages/ranges, and interchange semantics. Reviewed page reported version 1.9.2; a runtime schema version is not selected yet.

### S29

[AFL++ — Documentation](https://aflplus.plus/docs/). Evidence: instrumentation, campaign lifecycle, and specialized modes. Only a Linux user-space reference pilot is proposed initially.

### S30

[LLVM — libFuzzer](https://llvm.org/docs/LibFuzzer.html). Evidence: in-process coverage-guided fuzzing and harness interface. Maintenance state and exact compiler/runtime release must be revisited at integration time; no future-roadmap assertion is made.

### S31

[Rust Fuzz Book — Windows cargo-fuzz setup](https://rust-fuzz.github.io/book/cargo-fuzz/windows/setup.html). Evidence: a Windows-specific setup path exists. Does not establish a tested Sentra Windows fuzzing backend.

### S32

[Clang — AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html). Evidence: instrumented memory-error detection and platform/configuration limits. A sanitizer observation is not a full exploitability assessment.

### S33

[Code Intelligence — Jazzer back to open source](https://www.code-intelligence.com/blog/jazzer-back-to-open-source). Evidence: JVM fuzzing project and vendor-described Apache-2.0 transition. Exact chosen release and dependencies still require review.

### S34

[Docker — Engine security](https://docs.docker.com/engine/security/). Evidence: kernel, namespace, capability, and daemon considerations. Sentra requires an outer VM boundary for real untrusted workloads as a design choice.

### S35

[Docker — Desktop WSL2 backend](https://docs.docker.com/desktop/features/wsl/). Evidence: Windows/Linux backend topology and integration considerations. Does not establish per-session disposable isolation.

### S36

[Docker — Enhanced Container Isolation](https://docs.docker.com/desktop/enterprise/hardened-desktop/enhanced-container-isolation/). Evidence: extra isolation features and Business subscription requirement on the reviewed page. Not selected as a mandatory dependency.

### S37

[Microsoft — Hyper-V overview](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/overview?pivots=windows). Evidence: Windows hardware virtualization and guest VM capability. Edition/feature eligibility and automation remain local validation gates.

### S38

[Microsoft — Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/). Evidence: disposable desktop VM model and supported-edition considerations. No headless worker integration is claimed.

### S39

[gVisor — Overview](https://gvisor.dev/docs/). Evidence: application-kernel isolation approach and compatibility context. Optional Linux-worker hardening candidate.

### S40

[Firecracker — Project overview](https://firecracker-microvm.github.io/). Evidence: Linux KVM-based microVM runtime. Native Windows compatibility is not inferred.

### S41

[Wasmtime — Security](https://docs.wasmtime.dev/security.html). Evidence: WebAssembly sandbox and host-capability security considerations. General native target execution requires a different backend.

### S42

[MCP — Tools, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/server/tools). Evidence: typed external tool surface and interaction/security considerations. This researched revision is a future compatibility candidate, not an implemented protocol claim.

### S43

[MCP — Authorization, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization). Evidence: HTTP authorization and transport-specific distinctions. Stdio is not assumed to have HTTP OAuth semantics.

### S44

[MCP — Security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices). Evidence: confused deputy, token passthrough, SSRF, local-server and transport risks. Controls must be tested for the chosen transport.

### S45

[OWASP — Top 10 for LLM applications](https://owasp.org/projects/top-10-for-large-language-model-applications). Evidence: LLM/agent risk context and links to the GenAI security project. This is guidance, not a Sentra security certification.

### S46

[OASIS — SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html). Evidence: static-analysis interchange standard. Not selected as the complete internal research database model.

### S47

[FIRST — CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document). Evidence: severity vector semantics. Sentra must retain assumptions and separate organizational risk.

### S48

[SQLite — Write-ahead logging](https://www.sqlite.org/wal.html). Evidence: journaling, concurrency, checkpoint, and same-host/network-filesystem constraints. Exact SQLite release, journal mode, durability settings, and recovery behavior are implementation validation gates.

### S49

[CycloneDX — Specification overview](https://cyclonedx.org/specification/overview/). Evidence: component/dependency inventory interchange. No implemented SBOM import/export is claimed.

### S50

[Anchore — Product documentation and open-source tooling links](https://docs.anchore.com/). Evidence: distinct Syft/Grype/Grant ecosystem roles. Detailed packaging and license suitability were not audited.

### S51

[UC Berkeley — CyberGym](https://www.cybergym.io/cybergym/). Evidence: historical-vulnerability reproduction benchmark and its stated evaluation limitations. Reproduction with a supplied vulnerability description is not novel discovery or patch verification; leaderboard results are not used as Sentra forecasts.

### S52

[Frida — Documentation](https://frida.re/docs/home/). Evidence: dynamic instrumentation toolkit. Optional future integration only.

### S53

[Ghidra — Official project landing page](https://ghidra-sre.org/). The reviewed URL redirected to the NSA project's repository. Evidence: reverse-engineering framework identity. No binary-analysis integration or source-code audit was performed.

### S54

[ZAP — Documentation](https://www.zaproxy.org/docs/). Evidence: established web-application testing tooling. Future scoped test-service adapter; no production or internet-scanning authorization is implied.
