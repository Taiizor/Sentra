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
- Web console: tool detection on the *Host & workers* page searches the bridge process PATH, the persisted PATH (Windows registry system and user `Path`, macOS `/etc/paths` and `/etc/paths.d`, Linux `/etc/environment`) and standard install locations, where it used to search the process PATH only. Each tool row reports where the tool was found, whether the bridge process can see it, later (shadowed) matches, a symlink or junction target (not a mere 8.3 short-name or drive-letter expansion) or Scoop shim target, the architecture read from its PE, ELF or Mach-O header (universal binaries and scripts included), and how the bridge uses it (`gh` executed, `bun` runtime, `codeql` presence only, the rest not used). Tools are never run to detect them. The same file reached through symlinked directories is reported once, and skipped UNC and device `PATH` entries are counted. A tool found outside the process PATH comes with an explanation for the host OS (Windows: the bridge's environment predates the `PATH` change; macOS: launchd does not apply `/etc/paths` or shell profiles; Linux: systemd and cron do not apply `/etc/environment` or shell profiles) and what to change. See web/README.md.
- Web console host details: OS name, the native hardware architecture next to the process architecture (emulation under Windows on Arm or Rosetta 2), the Bun executable running the bridge, and the core binary's architecture.
- Web console: `API_CONTRACT_VERSION` in `web/src/types/api.ts`, reported by the bridge as `apiContractVersion` in `/api/health` and `/api/system`. When the bridge runs code with a different contract (for example after Vite hot-reloaded the console but not the bridge), the console shows a banner asking to restart an older bridge, or, when the bridge is newer, to reload the page and in production to rebuild `web/dist` (`bun run build`), shows placeholders instead of failing on response shapes it does not expect, and renders each tab inside an error boundary.
- CI: the `web-test` job runs the web bridge unit tests (`bun run test` in `web/`) on `ubuntu-latest`, `windows-latest` and `macos-latest`.

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
- Web console API: `HostInfo.freeMemoryBytes` is replaced by `availableMemoryBytes` with a `memorySource`; `ToolAvailability` adds `resolvedPath`, `resolvedVia`, `source`, `onProcessPath`, `binary`, `usage`, `usageNote` and `shadowed`; `SystemStatus` adds `apiContractVersion`, `toolSearch` and `core.binary`. Tool rows of topology reports stored by earlier bridges are upgraded when read.
- Web console: the scan's CodeQL stage message and the topology report note name the locations searched for tools instead of "on PATH", and say when the persisted PATH could not be read.

### Fixed
- Web console: tools in a directory that was added to `PATH` after the bridge started (for example by an installer, such as CodeQL in a directory added to the system `Path`) were reported as missing because only the bridge process PATH was searched; tools installed later into a directory already on that PATH were found. They are now found through the persisted PATH, and the page explains why the bridge cannot see them.
- Web console: the *bun* tool row showed the temporary `bun-node-<hex>` shim that `bun run` puts first on `PATH`. Shim directories are skipped, and the running Bun is matched to a located installation by file identity (through symlinks, and through a Scoop shim's `.shim` target); when none matches, the console says so instead of naming another Bun.
- Web console: macOS memory use was overstated because `os.freemem()` counts only free pages. Available memory now comes from `vm_stat` on macOS and from `MemAvailable` in `/proc/meminfo` on Linux.
- Web console: "Configured access grants" counted the generated local admin token as a `SENTRA_WEB_TOKENS` grant ("1 + a generated local admin token"). `configuredGrants` now counts only `SENTRA_WEB_TOKENS` grants.

### Security
- Fixed the legacy bridge's critical issues: unauthenticated API reachable from any interface or website, arbitrary file read and write, plugin command execution through client-supplied manifest paths, stored provider keys forwarded to client-chosen endpoints, and client-supplied roles.
- `sentra install --mcp` no longer replaces configuration files it cannot parse (JSONC, BOM, UTF-16, unexpected structure): such files are left untouched and the command prints the snippet to add by hand. Every edit keeps unrelated content, writes `<file>.bak` first and replaces the file atomically.
- Removed the `sentra_install_skills` MCP tool, which let a model write files anywhere without approval, and the no-op `sentra_apply_checkout_mutation`. MCP tools no longer return fabricated workspace, session or findings data, and file paths are confined to the launch workspace.
- Web console: `gh auth token` was started with the bridge's full environment (including `SENTRA_WEB_SECRET_KEY`, `SENTRA_WEB_TOKENS` and the webhook secrets), without a timeout, from whatever `Bun.which("gh")` returned, which on Windows includes `.cmd`/`.bat` wrappers and which searches relative `PATH` entries. It now runs with an allow-listed environment and a 5-second timeout, only from the process PATH or the persisted PATH (never from standard install locations, which on Windows include directories any local user can create), on Windows only as a `.exe` or `.com`, and on macOS and Linux a persisted-PATH match only when it, its target and their directories are owned by root or the bridge user and writable neither by others nor by a non-root group. The page names the file that is run, or why a match was skipped.
- Web console: the `sentra` binary fallback on `PATH` skips relative and UNC entries and, on Windows, accepts only `sentra.exe`/`sentra.com`, where `Bun.which("sentra")` also matched batch wrappers and relative entries. Standard install locations are never used for it.
- Web console: host detection never executes a discovered tool. It starts only fixed system programs, by absolute path, without a shell, with a minimal environment and a 5-second timeout: on Windows `powershell.exe -NoProfile -NonInteractive -NoLogo -Command -` with a fixed registry script on standard input (no `-EncodedCommand`, no `-ExecutionPolicy` override), whose result is reused for 10 minutes and, after a failure, retried after 1, 2, 4 and 8 minutes and then at most every 10 minutes; on macOS `sw_vers`, `sysctl` and `vm_stat`. On Linux everything is read from files. UNC and device paths are never listed, whether they come from a `PATH` entry or from an install-location variable such as an `APPDATA` redirected to a share, and search refreshes check and list directories asynchronously with a 2-second deadline each.
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
