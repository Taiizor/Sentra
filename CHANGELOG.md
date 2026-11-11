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
- `sentra install mcp amp`: Sourcegraph Amp is its own MCP target (`amp.mcpServers` in `.amp/settings.json` or `~/.config/amp/settings.json`).
- `sentra install ... --mcp --command <path>` overrides the registered executable; by default the absolute path of the running `sentra` binary is registered.
- `sentra mcp [--workspace <dir>] [--database <file>]`: the MCP server's tools are confined to the workspace, and `--database` enables persisted session status.
- Bundled skills now ship every supporting file (references, scripts, rules) and their upstream `LICENSE`; NOTICE lists source, commit and license for each skill. `sentra skills show --json` lists the files.
- `sentra plugin list` reports discovery diagnostics (invalid manifests, duplicate ids, missing directories) and which manifest limits are enforced; `plugin run` reports the host-observed process exit code and the workspace sent to the adapter.

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
- Skill installation writes on-demand `<skills dir>/<id>/SKILL.md` trees in each agent's documented location (`.agents/skills` for Zed, Warp, Codex, Windsurf, OpenHands, Goose and Kimi) and no longer appends playbooks to always-on rule files (`.cursorrules`, `.windsurfrules`, `.clinerules`, `.roorules`, `CONVENTIONS.md`, `copilot-instructions.md`); unmodified legacy blocks and files are removed after a backup. Cody is unsupported; Amazon Q, Continue and Replit are workspace-only; Aider gets `read:` entries in `.aider.conf.yml`. See docs/EXTENSIONS.md for the target table.
- MCP registration writes each agent's documented configuration file (for example `.mcp.json` and `~/.claude.json` for Claude Code, TOML for Codex, YAML for Goose, Hermes and Continue); the generic `.agents/mcp.json` fallback is gone. Aider, OpenHands, Replit and Cody fail with `mcp_unsupported_target`, and unsupported scopes with `unsupported_scope`.
- `install`, `install --mcp`, `skills`, `prompt` and `plugin` failures exit non-zero with specific error codes (for example `skill_not_found` 7, `mcp_config_unparseable` 4, `manual_config_edit_required` 6, `plugin_timeout` 5, `plugin_duplicate_id` 4); `install --json` output is built with serde_json and is valid JSON on Windows. `install --json` `count` is the number of skills; `file_count` and `file_changes` list the files.
- `sentra skills list --json` returns `{schema_version, command, count, skills}` instead of a bare array; `skills show --json` adds `schema_version`, `command` and `files`.
- `sentra prompt --skills` appends the playbooks to the workflow prompt, keeping its grounding rules and `expected_schema`, removes duplicate ids and rejects unknown ids (`skill_not_found`). The MCP `sentra_generate_prompt` tool does the same.
- The MCP server negotiates the legacy revisions `2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05` instead of always answering `2026-07-28`, which it does not implement. The stdio loop enforces the 1 MiB line quota while reading; oversized lines and invalid UTF-8 are answered with JSON-RPC errors and no longer stop the server.
- `sentra plugin` loads adapters only from `--dir` or the default plugin directory (`SENTRA_PLUGIN_DIR`, else the platform configuration directory), never from the working directory, its parents or `examples/adapters`; `plugin run --workspace` is passed to the adapter.

### Security
- Fixed the legacy bridge's critical issues: unauthenticated API reachable from any interface or website, arbitrary file read and write, plugin command execution through client-supplied manifest paths, stored provider keys forwarded to client-chosen endpoints, and client-supplied roles.
- `sentra install --mcp` no longer replaces configuration files it cannot parse (JSONC, BOM, UTF-16, unexpected structure): such files are left untouched and the command prints the snippet to add by hand. Every edit keeps unrelated content, writes `<file>.bak` first and replaces the file atomically.
- Removed the `sentra_install_skills` MCP tool, which let a model write files anywhere without approval, and the no-op `sentra_apply_checkout_mutation`. MCP tools no longer return fabricated workspace, session or findings data, and file paths are confined to the launch workspace.
- Plugin host: a planted `manifest.json` in a repository can no longer shadow an operator adapter. Adapters run with an allowlisted environment, an executable resolved inside the adapter directory, enforced time and output quotas, drained stderr, and are killed with their process tree on every exit path. Memory and egress limits remain declared, not enforced.

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
