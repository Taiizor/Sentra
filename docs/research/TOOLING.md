# Analysis Tool Evaluation

Selection is by explicit target family and required evidence. None of these integrations is implemented. Engine, rules, advisory data, model, fixture, and redistribution licenses must be checked separately at the exact version used.

## Discovery and static analysis

| Tool / approach | Useful capability | Constraint and proposed role |
| --- | --- | --- |
| Bounded manifest/text inspection | Low-dependency project discovery | Initial Rust manifest pilot. Recognizing a language is not deep analysis support. Avoid package-manager execution during discovery. |
| Tree-sitter | Syntax trees and language bindings, including Rust. [S23](SOURCES.md#s23) | Candidate context/index adapter. Syntax structure is not type resolution, whole-program dataflow, or a sound vulnerability proof; native grammars require containment and license review. |
| Semgrep CE | Existing rule-based analysis; support varies by language and product tier. [S21](SOURCES.md#s21) | Optional scanner adapter with independently licensed rules. Do not infer CE capabilities from commercial tiers. Run in an isolated tool environment rather than assuming native Windows parity. |
| Semgrep licensing | CE engine is LGPL-2.1, while maintained registry rules have separate usage restrictions, including restrictions on competing offerings. [S20](SOURCES.md#s20) | Do not bundle default registry rules. Evaluate owner-authored or otherwise compatible rule packs with version-specific review. Engine availability does not resolve rule licensing. |
| CodeQL CLI | Queryable code databases and SARIF output, with usage conditions. [S22](SOURCES.md#s22) | Optional entitled integration. Do not make it a mandatory freely redistributable scanner or assume every private/proprietary target is covered by the operator's license. Database creation may involve target builds. |
| Existing compiler/test tooling | Ecosystem-aware diagnostics and behavior checks | Use per-language adapters. Build scripts, macros, tests, plugins, and code generators execute target-controlled code and require VM workers. |

The initial Rust review pilot uses source context and explicit test oracles, not a claim that Rust has a validated complete static-analysis pipeline. If a supported semantic analysis adapter is unavailable, report that gap. Avoid inventing a universal intermediate representation or cross-language taint engine in the initial core.

## Dependency and supply-chain analysis

| Tool / standard | Source-reported purpose | Sentra decision |
| --- | --- | --- |
| cargo-audit / RustSec | Match Rust lockfile dependencies to security advisories. [S24](SOURCES.md#s24) | First advisory-analysis candidate. Preserve package identity, affected range, advisory aliases, database digest/date, and unknown resolution cases. Presence is not demonstrated exploitability. |
| cargo-deny | Dependency graph checks for advisories, licenses, bans, and sources. [S25](SOURCES.md#s25) | Candidate for Sentra's future own supply-chain checks and richer Rust target policy. May need dependency resolution; do not run target-controlled configuration on the host. |
| OSV-Scanner | Existing multi-ecosystem advisory matching. [S26](SOURCES.md#s26) | Later adapter to widen manifest coverage only after a supported-artifact matrix and fixtures exist. Bun lockfile support must be checked explicitly. |
| OSV offline mode | Local advisory databases can support disconnected queries after provisioning. [S27](SOURCES.md#s27) | Preferred private-project approach where feasible. Provisioning/updating is a separate network action; record freshness and stale-data policy. |
| OSV schema | Structured vulnerability identifiers, affected packages, and ranges. [S28](SOURCES.md#s28) | Import semantics rather than invent an advisory format. Preserve withdrawn advisories and aliases. |
| Syft / Grype | Anchore publishes distinct inventory and vulnerability-analysis tools. [S50](SOURCES.md#s50) | Future image/artifact adapters. Avoid adding a second full scanner stack for the first Cargo-only pilot. |
| CycloneDX | Structured inventory and dependency relationships. [S49](SOURCES.md#s49) | Future SBOM interchange alongside source dependency records; do not build a new SBOM standard. |

An advisory match is a validated **dependency advisory finding** if identity/range/data checks succeed. It is not automatically a dynamically validated **source vulnerability**. Supply-chain scope later includes source provenance, build dependencies, license policy, and artifact inventory; the initial lockfile pilot covers none of these universally.

## Dynamic analysis and fuzzing

| Tool | Useful capability | Proposed integration and limits |
| --- | --- | --- |
| libFuzzer | Coverage-guided in-process fuzzing. [S30](SOURCES.md#s30) | Baseline candidate for existing Linux C/C++ harnesses in Phase 3; pin compiler and instrumentation. A harness and meaningful oracle are prerequisites. |
| AFL++ | Instrumentation and campaign options for source-available and other targets. [S29](SOURCES.md#s29) | Compare against libFuzzer on the reference corpus. Prefer an existing engine over a custom mutation engine. Specialized modes are not initial support claims. |
| cargo-fuzz | Rust fuzzing wrapper; the Fuzz Book documents Windows-specific setup. [S31](SOURCES.md#s31) | Later Rust fuzz adapter. Do not claim Windows is categorically unsupported; choose Linux workers initially to reduce the validated matrix. Nightly/instrumentation requirements need version-specific checks. |
| AddressSanitizer | Runtime detection of memory errors in instrumented programs. [S32](SOURCES.md#s32) | Default C/C++ reference oracle candidate; record sanitizer/compiler configuration. Does not establish all bug classes or production exploitability. |
| Jazzer | Vendor documents JVM fuzzing and an open-source licensing transition. [S33](SOURCES.md#s33) | Optional later JVM adapter; exact release/license, JDK, and harness validation required. No JVM dependency in the initial core. |
| ZAP | Existing web-application security testing tooling. [S54](SOURCES.md#s54) | Later local test-service adapter. Requires an explicit URL/service scope and isolated network; repository authorization does not authorize internet scanning. |
| Ghidra | Reverse-engineering framework. [S53](SOURCES.md#s53) | Optional future binary-analysis adapter; not mandatory for source review, fuzzing, or the CLI. |
| Frida | Dynamic instrumentation toolkit. [S52](SOURCES.md#s52) | Optional future authorized instrumentation adapter; target-specific runtime/injection permissions and containment required. |

Time-limited fuzzing can produce useful crashes without proving absence of defects. Deduplicate by root cause where possible; retain divergent stacks, input digests, minimization history, build identity, and reproducibility counts. A sanitizer crash, denial of service, data disclosure, and privilege escalation are distinct claims.

## Output and packaging policy

Adopt SARIF 2.1.0 for scanner interchange where a tool supports it, while retaining native output and Sentra's richer evidence graph. Preserve unresolved paths and rule identities rather than converting every imported alert into a confirmed issue. [S46](SOURCES.md#s46)

Each adapter needs an executable/image digest, version, invocation contract, supported target matrix, output schema, exit-status semantics, timeout/cancellation behavior, network profile, and notices. Tests skipped upstream must be explicit downstream. No automatic scanner download, rule update, image pull, or binary execution is part of Phase 0.
