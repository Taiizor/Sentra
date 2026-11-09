# ADR-0007: Open-Source License and Integration Licensing

- Status: Accepted
- Date: 2026-11-05 (Updated & Accepted: 2026-11-09)
- Decision owner: Project owner, with licensing review where needed

## Context

The product is intended to be open source and usable for authorized proprietary-project analysis. Tools, rules, models, datasets, advisory databases, containers, and SDKs may have different terms even when they belong to one product ecosystem.

Semgrep's CE engine and maintained rule sets have distinct licenses and usage restrictions. CodeQL use also has conditions that matter for private targets. These examples prevent treating every publicly available scanner artifact as freely redistributable or universally usable.

## Decision

The project owner explicitly selected **Apache License 2.0** on 2026-11-09 as the official open-source license for Sentra. The canonical `LICENSE` file and third-party attribution `NOTICE` have been incorporated into the repository.

Review each exact integration component independently. Do not bundle Semgrep-maintained registry rules by default. Keep CodeQL optional and entitlement-aware. Evaluate CRS/model/dataset/image licenses and service terms before running or redistributing them. A subprocess boundary alone does not settle licensing obligations.

Authorized proprietary source analysis must not require uploading source publicly or applying Sentra's license to a target by assumption. Patch/evidence ownership, contractual restrictions, provider terms, and disclosure rules remain governed by the actual input context and selected terms.

## Consequences

Sentra is formally governed by the OSI-approved Apache-2.0 license with explicit patent protection. Third-party component attributions and notices are documented in `NOTICE`. License and public distribution gates are fully satisfied.
