# ADR-0007: Open-Source License and Integration Licensing

- Status: Proposed
- Date: 2026-11-05
- Decision owner: Project owner, with licensing review where needed

## Context

The product is intended to be open source and usable for authorized proprietary-project analysis. The owner has not selected a license. Tools, rules, models, datasets, advisory databases, containers, and SDKs may have different terms even when they belong to one product ecosystem.

Semgrep's CE engine and maintained rule sets have distinct licenses and usage restrictions. CodeQL use also has conditions that matter for private targets. These examples prevent treating every publicly available scanner artifact as freely redistributable or universally usable. [S20](../research/SOURCES.md#s20), [S22](../research/SOURCES.md#s22)

## Alternatives

| Option | Consideration |
| --- | --- |
| Apache-2.0 | Proposed permissive OSI-license candidate with explicit patent terms; requires owner selection and correct notices |
| MIT | Alternative permissive license candidate; owner may prefer a simpler grant |
| Copyleft license | Alternative if reciprocal distribution obligations are a deliberate project goal; requires ecosystem/product review |

These are project-governance options, not a legal determination of compatibility or contributor rights.

## Proposal

Recommend Apache-2.0 for owner consideration, but do not add LICENSE text or assert a license grant without selection. Before public distribution, choose an OSI-approved license, identify copyright holders, and prepare necessary notices and contribution terms.

Review each exact integration component independently. Do not bundle Semgrep-maintained registry rules by default. Keep CodeQL optional and entitlement-aware. Evaluate CRS/model/dataset/image licenses and service terms before running or redistributing them. A subprocess boundary alone does not settle licensing obligations.

Authorized proprietary source analysis must not require uploading source publicly or applying Sentra's license to a target by assumption. Patch/evidence ownership, contractual restrictions, provider terms, and disclosure rules remain governed by the actual input context and selected terms.

## Consequences and gate

The repository currently expresses open-source intent without an effective project license grant. Public distribution is blocked until owner selection and notice review. License-specific legal questions remain with the owner/reviewer; Phase 0 does not resolve them by implication. This proposal does not block documenting the architecture or, after explicit approval, conducting narrowly scoped technical validation under appropriate terms.
