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
- `sentra inventory`: read-only, recursive lockfile inventory with OSV ecosystem names.
- `sentra scan --file-name <name>` for snippet and stdin scans (selects language rules; replaces the fixed `sample.ts` label).
- `sentra patch apply --dry-run` and the `patch_does_not_apply` error code.
- `PatchApplied` / `PatchRolledBack` core audit events recorded through the persistence repository when `--database` is given.

### Changed
- Web console rebuilt to show real data only. Removed all seeded findings, patches, sessions, audit entries, workers, advisories, trends and scores; fake pull requests and CI runs; simulated webhook dispatch; fake intel sync; canned AI patches that were always reported as verified; and the hard-coded coverage ledger and reconnaissance reports. Every view now reads the core CLI, read-only core stores, the bridge's persisted history, GitHub, OSV (opt-in) or configured model providers, and shows an explicit empty or "not configured" state otherwise.
- Web bridge (`web/server.ts`, `web/server/`) rewritten:
  - binds to loopback by default;
  - token authentication and server-side role permissions;
  - Host, Origin and CSRF guards; no CORS;
  - path confinement, an SSRF guard, encrypted credential storage, and an HMAC-chained append-only operator audit log;
  - webhook HMAC/token verification with duplicate-delivery detection;
  - a production mode that serves the built UI.
- The bridge no longer writes to core stores. Each workspace has its own core store under `<data dir>/core-stores/`.
- The patch engine applies hunks by position with exact context matching. It applies all hunks or none, and it reports `already_patched` only when every hunk's post-image is in place.
- `sentra tenant list` no longer seeds demo tenants.

### Security
- Fixed the legacy bridge's critical issues: unauthenticated API reachable from any interface or website, arbitrary file read and write, plugin command execution through client-supplied manifest paths, stored provider keys forwarded to client-chosen endpoints, and client-supplied roles.

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
