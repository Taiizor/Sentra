# Existing Systems and Agent Architectures

All external facts below are source-reported. Fit assessments are Sentra design judgments, not executed comparisons. Sources were reviewed on 2026-11-05.

## Product inspirations

**Vercel Security Review.** The canonical introduction describes push-triggered change review with surrounding source context, finding tracking, and permission-based fix actions. Sentra adopts contextual change analysis as a workflow idea, while planning local/private-project operation independent of Vercel deployment. A later scan failing to detect an issue is insufficient evidence for Sentra to mark it fixed. No proprietary Vercel implementation or performance estimate is assumed reusable. [S01](SOURCES.md#s01)

**OpenAI Linux research.** The article separates target selection by Scouts, investigation by Analysts, dynamic validation, impact assessment, patch generation, and human review. It describes VM-based reproduction with kernel instrumentation. Sentra adopts the separation of responsibilities and preservation of runtime evidence. The article's kernel campaign scale, model access, cost, and reported results do not establish feasibility or expected accuracy for Sentra. Native kernel research is outside the initial roadmap. [S02](SOURCES.md#s02)

## Reuse candidates

| System | Source-reported scope | Sentra fit and decision |
| --- | --- | --- |
| OSS-CRS | Framework and registry for composing CRS components against OSS-Fuzz-style targets; documented setup includes Python, uv, Docker, and Git. | Highest-priority deep-research reuse candidate. Test a worker-side integration; do not add its runtimes to Phase 0. Its published target envelope is narrower than arbitrary private enterprise applications. [S04](SOURCES.md#s04) |
| OSS-CRS architecture | Separates campaign orchestration, CRS containers, shared infrastructure, and provider-budget facilities. | Evaluate budget and artifact mapping instead of recreating them blindly. Preserve Sentra's outer policy authority and VM boundary. [S05](SOURCES.md#s05) |
| OSS-CRS libCRS/development contract | Defines preparation/build/run phases and artifact exchange. Its test interface can return a successful status when no test script exists. | Adapter must distinguish absent tests from verification success and retain raw provenance. Establish exact skipped-test semantics in the interoperability spike. [S06](SOURCES.md#s06) |
| Atlantis and registry modules | Atlanta publishes its CRS artifacts and papers; the OSS-CRS registry exposes separate finding, seed, and patch-related components. | Study composition and selective reuse; validate exact component licensing, budgets, and portability before inclusion. Competition infrastructure is not a Windows product foundation by default. [S07](SOURCES.md#s07), [S09](SOURCES.md#s09) |
| Buttercup | Trail of Bits describes orchestration, AI-assisted fuzzing, contextual program analysis, and multi-agent patch generation, including a standalone release. | Compare standalone integration against an OSS-CRS component. Reuse proven engines; avoid importing an entire deployment merely to obtain one stage. Reported laptop suitability requires local measurement. [S08](SOURCES.md#s08) |
| OSS-Fuzz / ClusterFuzz ecosystem | Established architecture for building fuzz targets, executing engines, and handling crashes. | Adopt target/build/corpus conventions for initial C/C++ research. The public OSS-Fuzz service is not a default destination for proprietary source or artifacts. [S10](SOURCES.md#s10) |
| OpenHands | General AI development environment with SDK and application interfaces. | Candidate external agent runtime/client. No inspected documentation establishes Sentra's full evidence/permission contract; do not delegate security authority to a general coding agent. [S13](SOURCES.md#s13) |

DARPA's AIxCC results are evidence that integrated discovery-and-patching systems are practical research artifacts. Competition success does not validate arbitrary language coverage, offline enterprise operation, or unsupervised deployment safety. [S03](SOURCES.md#s03)

## Adopt a platform, orchestrate it, or build a core?

| Option | Benefit | Main unresolved constraint | Phase 0 disposition |
| --- | --- | --- | --- |
| Base Sentra entirely on OSS-CRS | Immediate alignment with existing CRS components | Target conventions, Windows workflow, private-project policy, and independent evidence admission need validation | Do not commit before interoperability spike |
| Fork a complete CRS such as Buttercup/Atlantis | Rich existing research workflow | Operational assumptions, dependency footprint, license composition, and lifecycle control | Study and benchmark; no fork in Phase 0 |
| Thin CLI wrapper around scanners/agent prompts | Small initial surface | Cannot by itself supply reusable policy, durable evidence, independent verification, and future interfaces | Insufficient product architecture |
| Small Sentra core plus worker-side integrations | Retains product-specific invariants while reusing research engines | Risk of duplicating upstream scheduling and artifact management | Recommended, with a mandatory reuse comparison before custom campaign infrastructure |

The recommended core should own only what the product contract needs: authorization, input identity, task/evidence state, approvals, and interface-neutral use cases. A successful OSS-CRS trial may remove planned custom research scheduling rather than merely add another layer.

## Generic orchestration alternatives

| Candidate | What its documentation establishes | Design judgment |
| --- | --- | --- |
| LangGraph | Graph-oriented agent workflows with persistence, interrupts, and state management. [S11](SOURCES.md#s11) | Useful worker-side option if a Python agent component justifies it. It does not replace OS containment or deterministic evidence admission. Do not require it in the Rust host core initially. |
| Temporal | Durable execution with recoverable workflows and operational infrastructure. [S12](SOURCES.md#s12) | Revisit for distributed workers after measured recovery/scale pressure. A server and SDK boundary are unnecessary initial operational commitments. |
| Bounded persisted task DAG in the core | Sentra proposal, not an external validated system | Keep minimal: finite task states, leases, retries, outbox, and reconciliation. Re-evaluate if this grows into a general workflow engine. |

## Agent architecture recommendation

Use a deterministic supervisor with short-lived specialized role tasks. Agents exchange evidence references and structured hypotheses through the core. Free-form peer conversations, unrestricted shell access, agents approving their own work, and uncontrolled recursive spawning are outside the initial contract.

A second model opinion is useful but is not execution evidence. A crash is useful but is not proof of exploitability. A generated patch is useful but requires an independent oracle and clean verification run. The detailed authority boundaries are in [AGENT_MODEL.md](../AGENT_MODEL.md).

## Required empirical follow-up

Before custom deep-research infrastructure, pin one OSS-CRS configuration, one standalone/compatible CRS candidate, and a classical fuzzer baseline. Compare setup requirements, host/guest compatibility, privacy/egress, normalized artifacts, skipped-test behavior, quotas, cancellation, cost, and patch verification on the same corpus. No such execution occurred in Phase 0.
