# Changelog

All notable changes to Sentra are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions CI workflow covering Linux, Windows, and macOS multi-OS test matrix.
- GitHub CodeQL static analysis workflow for JavaScript/TypeScript, GitHub Actions, and Rust.
- Automated PR scope labeler (`actions/labeler@v5`) and declarative label synchronizer.
- Dependabot configuration for Cargo, GitHub Actions, and Web npm packages.
- Cross-platform POSIX filesystem boundary and inode-based pinning in `sentra-core`.
- Universal OSV v1.6 advisory feed ingestion (`sentra sync-advisories`).
- Pure-Rust SAST scanner with 10 high-precision secret and code antipattern rules (`sentra scan`).
- Multi-ecosystem lockfile support: npm, Yarn, pnpm, Bun, Deno, and Cargo (`sentra audit`).
- Web operations dashboard built with React 19, TypeScript, Bun, Tailwind CSS v4, and shadcn/ui.

## [0.2.0] - 2026-11-10

### Added
- **Phase 2: Continuous Security Review Pilot:**
  - Base/Head snapshot comparison and unified diff generation with LCS backtracking.
  - Three-tier patch verification engine (`VerificationBundle`) ensuring original baseline failure, target pass, and regression protection.
  - 20-case controlled change evaluation corpus reporting 100% precision and 100% recall.
  - Capability-scoped model provider contracts with `SyntheticMockProvider` and `LocalInferenceEndpointProvider`.
  - Secret redaction filter masking API keys, private keys, and authorization tokens.
  - Disposable Linux worker containment profile with 6-gate readiness audit.

## [0.1.0] - 2026-11-08

### Added
- **Phase 1: Local Foundation & Core Hardening:**
  - `sentra-core` foundation library under `#![forbid(unsafe_code)]`.
  - SQLite Schema V2 persistence with WAL mode, foreign key constraints, and transactional migrations.
  - Local workspace boundary with Windows reparse-point and directory junction quarantine.
  - Content-addressed evidence storage and SHA-256 digest calculation.
  - Initial `sentra-cli` supporting `init`, `status`, `session show`, `recover`, and SARIF export.
