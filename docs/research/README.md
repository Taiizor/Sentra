# Phase 0 Research

Research date: **2026-11-05**. This is a documentation-based technical assessment with read-only local environment inspection. No candidate system was installed, executed, benchmarked, or audited at source-code level.

## Reading order

| Study | Question answered |
| --- | --- |
| [Environment](ENVIRONMENT.md) | What exists locally, and what remains unverified? |
| [Landscape](LANDSCAPE.md) | Can existing platforms provide all or part of Sentra? |
| [Tooling](TOOLING.md) | Which established analysis engines should be adapted? |
| [Isolation](ISOLATION.md) | Which boundaries fit Windows control and untrusted execution? |
| [Technology](TECHNOLOGY.md) | Why propose Rust and a local modular core? |
| [Sources](SOURCES.md) | Which primary sources support the external claims? |

## Method and confidence

Inspect the repository and installed tool metadata; consult the two requested inspirations; compare existing CRS platforms and orchestration frameworks; evaluate analysis and isolation tools; map recommendations to requirements and decision gates. Prefer publisher documentation, original research, and project-maintainer material. Vendor claims are attributed rather than treated as independently validated results.

Each study distinguishes **observed facts**, **source-reported behavior**, **Sentra design judgment**, and **required validation**. A feature listed by an upstream project is not automatically supported by Sentra. Compatibility, executable licensing, ruleset licensing, data licensing, privacy, and packaging need separate checks at a pinned revision.

External links were reviewed through web retrieval on the research date. The original `https://vercel.com/blog/security-review` could not be retrieved; [S01](SOURCES.md#s01) is the accessible canonical article. Some upstream documentation redirects to newer paths; the source register records the reviewed destination. Mutable sources are not reproducibility locks. Exact upstream revisions and image digests are implementation gates.

## Conclusions

- Reuse established engines and compare OSS-CRS before custom campaign/harness infrastructure.
- Retain a Sentra-owned policy, evidence, permission, and workflow core because none of the inspected material validates the complete intended product contract.
- Propose Rust conditionally; validate Windows linking, process control, storage, and integration friction in Phase 1.
- Separate Windows host support from Linux target execution. Docker Desktop availability is useful environment evidence, not proof of hostile-code containment.
- Start with a small tested target set; add languages, OS profiles, and binary tools through explicit adapter gates.

These conclusions are architectural judgments from available documentation. [OPEN_QUESTIONS.md](../OPEN_QUESTIONS.md) records uncertainties and reversal conditions; [VALIDATION.md](../VALIDATION.md) defines the experiments.
