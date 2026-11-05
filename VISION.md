# Vision

## Identity and purpose

Sentra is an Autonomous AI Security Research & Remediation Platform: independent software with a reusable core, initially operated through a CLI. External coding agents can become clients of Sentra; they do not replace its policy engine, evidence store, or execution controls.

The product goal is to reduce the time from a security-relevant change or research hypothesis to a reviewable finding and a verified remediation proposal. Sentra should make the scope, evidence, uncertainty, cost, and human decisions visible at every step.

## Users and authorized targets

| User | Primary need |
| --- | --- |
| Maintainer | Review changes and receive minimal, testable fixes |
| Security researcher | Investigate hypotheses and preserve reproducible evidence |
| Enterprise application-security team | Analyze private source while controlling egress, access, and retention |
| Platform/integration developer | Add a language, provider, tool, or execution backend through a versioned contract |

Authorized proprietary source analysis is a product requirement, not a premium hosting assumption. Supporting a private source tree does not imply initial support for binary-only targets, all enterprise build systems, or every language. Ownership and target-specific authorization remain the operator's responsibility.

## Product outcomes

1. Discover a project's technologies and security boundaries without executing its code.
2. Review changes using relevant context and explicitly report analysis gaps.
3. Prioritize deep research rather than assigning every file indiscriminately to agents.
4. Validate candidate findings with appropriate evidence and independent review.
5. Generate small patches and test both the original failure and expected behavior.
6. Preserve an auditable session that another authorized researcher can inspect and rerun.

## Operating modes

Continuous Security Review optimizes for bounded latency, change attribution, and low reviewer noise. Deep Security Research optimizes for investigation depth, coverage accounting, and controlled exploration. Both are budgeted and share the same evidence semantics; neither can silently relax policy to meet a deadline.

The inspirations are Vercel's contextual change review and OpenAI's Scout/Analyst research pipeline. Their reported results are external observations, not forecasts for Sentra. See [the landscape study](docs/research/LANDSCAPE.md).

## Product principles

- Adopt established scanners, fuzzers, protocols, and research systems where their behavior and licenses fit.
- Keep the control plane provider-independent and local by default.
- Treat repository content, model output, tool output, and third-party plugins as untrusted inputs.
- Separate discovery, validation, impact assessment, patch authorship, and verification responsibilities.
- Require human decisions for scope expansion, sensitive execution, source egress, and external publication.
- Report unknowns and incomplete checks instead of turning them into success.
- Build extensibility around explicit capabilities and conformance tests, not unrestricted host access.

## Scope boundaries

The initial product is a single-operator, single-project-per-session platform. Shared enterprise tenancy, fleet execution, hosted review services, production penetration testing, native kernel exploitation, binary-only analysis, and autonomous merging/deployment are outside the initial scope.

Long-term coverage may include multiple ecosystems, operating systems, containers, VMs, hosted integrations, and dashboards. Each addition requires an adapter, fixtures, a documented execution strategy, and its own support declaration. There is no initial promise to reproduce OpenAI's kernel campaign or to match any vendor's accuracy or cost.

## Measures of progress

Measure verified precision, vulnerability reproduction rate, patch verification rate, reviewer acceptance, cost per validated finding, time to first useful evidence, and visible coverage gaps. Track these separately by target family, mode, provider, and tool version. Numerical acceptance gates are defined in [ROADMAP.md](ROADMAP.md) and the [validation plan](docs/VALIDATION.md).
