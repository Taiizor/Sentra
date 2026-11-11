# ADR-0007: Open-Source License and Integration Licensing

- Status: Accepted
- Date: 2026-11-05 (Updated & Accepted: 2026-11-09)
- Decision owner: Project owner, with licensing review where needed

## Context

The product is intended to be open source and usable for authorized proprietary-project analysis. Tools, rules, models, datasets, advisory databases, containers, and SDKs may have different terms even when they belong to one product ecosystem.

Semgrep's CE engine and maintained rule sets have distinct licenses and usage restrictions. CodeQL use also has conditions that matter for private targets. These examples prevent treating every publicly available scanner artifact as freely redistributable or universally usable.

## Decision

The project owner explicitly selected **Apache License 2.0** on 2026-11-09 as the official open-source license for Sentra. The canonical `LICENSE` file and third-party attribution `NOTICE` have been incorporated into the repository.

Review each exact integration component independently. Do not bundle Semgrep-maintained registry rules by default. Keep CodeQL optional and entitlement-aware (host analysis requires an explicit acknowledgement of the CodeQL terms and is off by default; see [ADR-0011](0011-opt-in-host-codeql-analysis.md)). Evaluate CRS/model/dataset/image licenses and service terms before running or redistributing them. A subprocess boundary alone does not settle licensing obligations.

Authorized proprietary source analysis must not require uploading source publicly or applying Sentra's license to a target by assumption. Patch/evidence ownership, contractual restrictions, provider terms, and disclosure rules remain governed by the actual input context and selected terms.

## Consequences

Sentra is formally governed by the OSI-approved Apache-2.0 license with explicit patent protection. `NOTICE` lists the direct Rust dependencies (rusqlite with bundled SQLite, Serde and serde_json, sha2, and on Windows win32job for the kill-on-close Job Object that contains plugin adapter process trees, which cannot be created from safe Rust without it) and every bundled third-party agent skill with its source repository, pinned commit (also recorded in `crates/sentra-core/assets/skills-lock.json`), license, and the upstream copyright line where the license states one; each bundled skill directory ships the upstream license text (`LICENSE` or `LICENSE.txt`), which `build.rs` embeds in the binary together with the rest of the skill directory. Transitive Rust dependencies are not listed individually in `NOTICE`. License and public distribution gates are fully satisfied.
