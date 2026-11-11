# Plugin and Adapter Architecture

Sentra provides a capability-fenced plugin and adapter architecture. Built-in adapters and external extensions adhere to strict process isolation, capability advertisements, and deterministic data contracts.

Provider contracts enforce capability and policy intersection: unsupported features are rejected fail-closed, unknown usage retains budget reservations, and cancellation acknowledgment is separate from confirmed termination. Live interoperability, IPC/restart behavior, and OS egress controls are enforced through capability manifests.

## Adapter families

| Family | Required responsibility | Declared capability examples |
| --- | --- | --- |
| Language/framework | Detect bounded project metadata; provide scoped context, build/test/harness plans, support gaps | Rust source-context pilot; later C/C++ harness metadata |
| Analysis tool | Plan isolated invocations; parse bounded native output; normalize signals and test semantics | Cargo.lock advisory analysis, SARIF import, libFuzzer run |
| AI provider | Validate model capabilities, structure requests/results, account usage, cancel, declare endpoint/retention assumptions | Hosted endpoint or validated local/private endpoint |
| Execution backend | Provision approved worker, enforce profile/quotas, authenticate job/result, terminate/reset and reconcile | Dedicated Linux VM candidate |
| Research-system / CRS | Map an existing system's tasks/artifacts/budgets to Sentra records | OSS-CRS integration candidate |
| Integration | Authenticate external events, resolve immutable inputs, propose approved publication | Later GitHub/GitLab checks and PR proposals |
| Export/import | Read or produce versioned records without overstating evidence | Markdown/JSON, SARIF, future SBOM |

Support declarations are tuples of **host, worker OS/architecture, target language/framework/version, tool version, action, and evidence method**. A wildcard language or platform declaration is not acceptable without matching conformance evidence. Discovery-only support is distinct from analysis, reproduction, and patch verification.

## Packaging and trust

An extension manifest declares identity, publisher, version, executable/image digest, interface version range, adapter family, supported tuples, required non-JavaScript runtimes, capabilities, egress destinations, quotas, data classes, licenses/notices, output schemas, update policy, and optional dependencies.

Installation is an operator trust decision, separate from using an existing approved adapter. No automatic marketplace execution, floating-tag updates, arbitrary downloaded executable, or repository-requested plugin installation. Pin executable, image, configuration, rules, and advisory data independently. Verify provenance/signatures where available without treating them as proof of safe behavior.

**Implemented today (`sentra plugin`).** The manifest that the current plugin host reads has id, name, version, interface version (exactly 1), family, executable, declared capabilities, quotas and an egress policy; publisher, digests, interface ranges and the other fields above are not implemented, and no trust record pins a manifest or executable. Adapters are discovered only in `--dir` or one default operator directory (`SENTRA_PLUGIN_DIR`, else `%APPDATA%\sentra\plugins`, `~/Library/Application Support/sentra/plugins` or `$XDG_CONFIG_HOME`/`~/.config/sentra/plugins`); the working directory, its parents and the repository examples are never searched, and a plugin id declared twice is rejected (`plugin_duplicate_id`). `probe` and `run` start the adapter **on the host** with the operator's privileges, not in a worker: the host clears the environment to an allowlist, resolves the executable inside the adapter directory, enforces the session time limit and frame/total-output quotas, drains stderr, checks the capability before spawning, correlates the returned task id and evidence-reference grammar, and kills the adapter process tree on every exit path. `max_memory_mib` and `egress_policy` are declared, not enforced; descendants that leave the process group (Unix), or on Windows descendants created before Job Object assignment or when the job cannot be assigned (then `taskkill /T` only reaches children of a live adapter), can survive. Adapter exit codes, summaries and evidence refs are adapter-reported. See [PLUGINS_GUIDE.md](PLUGINS_GUIDE.md) for the error codes and residual risks.

The target design below remains: only trusted bundled control-plane helpers may run on the host. The one reviewed exception is opt-in CodeQL analysis in build mode `none` with an operator-installed CodeQL CLI ([ADR-0011](adr/0011-opt-in-host-codeql-analysis.md)); it is a core command, not a plugin. Third-party target-facing adapters run inside an approved worker. A subprocess under the operator's account has that account's privileges; pipes and schemas do not make it safe. Native dynamic libraries and a stable Rust plugin ABI are outside the initial design. A future Wasmtime/WASI path must specify host capabilities and demonstrate its own limits.

## Message protocol

Start with supervised subprocess pipes and bounded UTF-8 newline-delimited structured messages for trusted local helpers, plus an authenticated framed transport for worker control. Transport and payload versions are explicit. Newline framing requires escaped embedded newlines, maximum frame/total-output sizes, and strict parsing; stdout carries protocol messages, while stderr carries bounded sanitized diagnostics.

| Operation | Required behavior |
| --- | --- |
| Initialize / negotiate | Declare protocol version, identity/digest, family, capabilities and supported schemas; reject incompatible major versions |
| Probe | Report availability, exact tool version, prerequisites, target applicability, and unsupported reasons without executing target code |
| Plan | Return immutable input refs, proposed jobs, required capabilities, predicted resources, and expected evidence; no side effects |
| Execute | Accept only an authorized job/lease with validated structured arguments and constrained artifact namespace |
| Result / event | Return correlation IDs, input digests, actual status, test counts/skips, usage, evidence refs, and limits; no direct finding-state mutation |
| Cancel / reconcile | Acknowledge cancellation separately from confirmed termination; query known execution ID after transport loss |
| Shutdown | Close channels, release resources, and return cleanup status; uncertain cleanup quarantines the worker |

These operation names describe contracts rather than fixed public method identifiers. Define formal schemas and compatibility fixtures before P4 SDK delivery. A new optional field is only backward compatible if older readers can safely ignore it; security-critical fields cannot be silently dropped. Reject unknown required capabilities and never downgrade an isolation requirement to satisfy version negotiation.

Extension callbacks to read context, request inference, fetch dependencies, or submit artifacts pass through the broker. No raw shell fallback, arbitrary host path, provider-key passthrough, or direct database access is allowed. If an upstream tool truly needs shell execution, the approved worker plan must confine that shell and its scripts to the target VM.

## Result and error semantics

Normalize unavailable prerequisites, unsupported target, denied permission, invalid input/schema, cancelled, timed out, infrastructure failure, tool failure, partial result, and successful execution as distinct outcomes. A nonzero tool exit can mean findings rather than failure; adapter-specific exit semantics must be documented and tested. Exit zero and missing test scripts cannot stand in for passing tests.

Retain raw/native output as restricted evidence alongside normalized records. Reject results with stale leases, changed source digests, unexpected artifacts, forged identity, or undeclared destinations. Reserve budgets before dispatch and reconcile observed consumption; an adapter cannot relabel cost as free.

## OSS-CRS interoperability

Evaluate OSS-CRS as a coarse-grained research-system adapter in a disposable worker. Map target identity, prepared images, campaign budgets, seeds/corpora, PoVs, patch attempts, and test outcomes into Sentra references. The adapter must not expose an upstream Docker socket or provider credentials to target code.

The upstream development guide permits a successful result when no project test script exists; Sentra must preserve this as skipped/incomplete verification. If required quotas, egress, isolation, or artifact semantics cannot be enforced, mark that configuration unsupported rather than trusting upstream orchestration implicitly. Compare against direct adapters before duplicating campaign machinery.

## MCP, skills, and API

MCP/API are frontends to the same core application services as the CLI. A skill is documentation/client guidance invoking Sentra; it is not a second engine or permission authority.

**Implemented (local stdio only).** `sentra mcp` serves the legacy, `initialize`-handshake era of MCP and negotiates revisions `2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05`: a supported requested revision is echoed, any other request is answered with `2025-11-25` ([2025-11-25 lifecycle, version negotiation](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle#version-negotiation)). Revision `2026-07-28` is the current published revision, but it is a handshake-less "modern" revision (per-request `_meta`, mandatory `server/discover`, `UnsupportedProtocolVersionError` -32022; [2026-07-28 versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)). Sentra does not implement it and never advertises it. A dual-era client that probes with `server/discover` receives -32601 and falls back to `initialize`, as the [2026-07-28 stdio binding](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio#backward-compatibility) specifies. Connection with the official TypeScript SDK client (`@modelcontextprotocol/sdk` 1.32.2, research date 2026-11-11) was tested: connect, `tools/list`, and `tools/call` succeed.

Transport and dispatch rules: one JSON-RPC message per line with a 1 MiB line quota enforced while reading (an oversized line is discarded unbuffered and answered with -32600 and `id: null`); invalid UTF-8 or JSON gets -32700 and the server keeps running; valid JSON that is not a request gets -32600; `id: null` is rejected because MCP forbids it; messages without an `id` are notifications and are never executed as requests; JSON-RPC batches are accepted only when `2025-03-26` was negotiated, because only that revision requires batch receipt. An unknown tool is a -32602 protocol error. Argument-validation and execution failures are tool results with `isError: true`. Successful payloads are returned as `structuredContent` with the same JSON serialized in one text block ([2025-11-25 tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)).

Tools (all read-only except `sentra_request_approval`, which records a request in process memory; none writes files):

| Tool | Backing service / status |
| --- | --- |
| `sentra_discover_workspace` | Lockfile inventory (`LocalWorkspace::inventory`) of a directory inside the launch root |
| `sentra_get_session_status` | Persisted session from the local store passed at launch (`--database`); tool error when no store is configured |
| `sentra_audit_dependencies` | Bundled pinned advisory sample; unsupported lockfile names are rejected |
| `sentra_list_findings` | Not implemented: the core persists no findings, so the tool always returns a `not_implemented` tool error |
| `sentra_propose_patch` | Digest of a proposed diff; never applied |
| `sentra_request_approval` | Unpredictable in-memory ticket; no grant path is exposed over MCP |
| `sentra_scan_code` | Heuristic SAST rules on a file or directory inside the launch root; missing, unreadable or out-of-root paths are tool errors |
| `sentra_codeql_ingest` | SARIF summary; nothing is persisted |
| `sentra_get_security_guidance`, `sentra_generate_prompt` | Bundled playbooks and prompt builders |

Filesystem paths are resolved against the server's launch root (the working directory, or the operator-selected workspace), canonicalized, and rejected when they resolve outside it. Skill and MCP-configuration installation is an operator action available only through the CLI (`sentra install`); it is not exposed to models.

### Skill installation and MCP registration (CLI, implemented)

`sentra install <target> [--global] [--skill <id>[,<id>...]]` copies the bundled third-party skills (each `SKILL.md` with every supporting file and its `LICENSE`; attribution in [NOTICE](../NOTICE)) as on-demand `<skills dir>/<id>/SKILL.md` trees. Nothing is appended to always-on rule files; blocks and flat files written by earlier Sentra versions are removed only when they still match the bundled playbook byte for byte, and are otherwise reported for manual review. `sentra install <target> --mcp` (also `sentra install mcp <target>` and `sentra mcp install <target>`) registers `<absolute path of the running sentra executable> mcp` (or `--command <path>`) under the server name `sentra`. Workspace scope writes inside `--workspace` (default: current directory), which must exist; `--global` writes to the user configuration resolved from `USERPROFILE`/`HOME`, `APPDATA`, `XDG_CONFIG_HOME` and the agent variables named below. Locations follow each vendor's documentation as checked on 2026-11-11; the per-target notes and sources are kept with the code in `crates/sentra-core/src/skills/installer.rs` and `crates/sentra-core/src/skills/mcp_config.rs`. Several products are moving targets (Windsurf is now Devin Desktop, Kimi CLI is archived, Trae's documentation renders client-side and its paths rest on third-party corroboration).

| Target | Skills: workspace / global | MCP config: workspace / global |
| --- | --- | --- |
| `claude` | `.claude/skills` / `~/.claude/skills` | `.mcp.json` / `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json`) |
| `antigravity` | `.agents/skills` / `~/.gemini/config/skills` | `.agents/mcp_config.json` / `~/.gemini/config/mcp_config.json` |
| `copilot` | `.github/skills` / `~/.copilot/skills` | `.github/mcp.json` and `.vscode/mcp.json` (`servers`) / `$COPILOT_HOME/mcp-config.json` (default `~/.copilot`) |
| `cursor` | `.cursor/skills` / `~/.cursor/skills` | `.cursor/mcp.json` / `~/.cursor/mcp.json` |
| `windsurf` | `.agents/skills` / `~/.agents/skills` | `.devin/mcp_config.json` / Cascade's `mcp_config.json` in `%APPDATA%\devin`, `$XDG_CONFIG_HOME/devin` or `~/.config/devin` (`~/.codeium/windsurf/mcp_config.json` is only read by opt-in editor discovery and is not written) |
| `cline` | `.cline/skills` / `~/.cline/skills` | unsupported / `$CLINE_MCP_SETTINGS_PATH`, else `~/.cline/data/settings/cline_mcp_settings.json` (`CLINE_DATA_DIR`, `CLINE_DIR` honoured) |
| `roo` | `.roo/skills` / `~/.roo/skills` | `.roo/mcp.json` / unsupported |
| `continue` | `.continue/rules/sentra-<id>.md` (`alwaysApply: false`) plus `.agents/skills` / unsupported | `.continue/mcpServers/sentra.yaml` / unsupported (snippet for `config.yaml`) |
| `aider` | `.agents/skills` plus `read:` entries in `.aider.conf.yml` / same under the home directory; `--skill` is required (`skill_selection_required`) because every `read:` file is loaded into every chat | no file-based MCP |
| `openhands`, `goose`, `warp`, `codex`, `zed`, `kimi` | `.agents/skills` / `~/.agents/skills` | see the rows below |
| `openhands` | (above) | no file-based MCP (UI/SDK only) |
| `goose` | (above) | unsupported / YAML `extensions` in `%APPDATA%\Block\goose\config\config.yaml` or `$XDG_CONFIG_HOME`/`~/.config/goose/config.yaml` |
| `warp` | (above) | `.warp/.mcp.json` / `~/.warp/.mcp.json` |
| `codex` | (above) | TOML `[mcp_servers.sentra]` in `.codex/config.toml` / `$CODEX_HOME/config.toml` (default `~/.codex`) |
| `zed` | (above) | `.zed/settings.json` / `%APPDATA%\Zed\settings.json`, `$XDG_CONFIG_HOME/zed` or `~/.config/zed` (`context_servers`) |
| `kimi` | (above) | `.kimi-code/mcp.json` / `$KIMI_CODE_HOME/mcp.json` (default `~/.kimi-code`) |
| `tabnine` | `.tabnine/agent/skills` / `~/.tabnine/agent/skills` | `.tabnine/mcp_servers.json` / `~/.tabnine/mcp_servers.json` |
| `junie` | `.junie/skills` / `~/.junie/skills` | `.junie/mcp/mcp.json` / `~/.junie/mcp/mcp.json` |
| `droid` | `.factory/skills` / `~/.factory/skills` | `.factory/mcp.json` / `~/.factory/mcp.json` |
| `kiro` | `.kiro/skills` / `~/.kiro/skills` | `.kiro/settings/mcp.json` / `~/.kiro/settings/mcp.json` |
| `amazonq` | `.amazonq/rules/sentra-<id>.md` pointer plus `.agents/skills` / unsupported | `.amazonq/mcp.json` / `~/.aws/amazonq/mcp.json` |
| `cody` | unsupported | no file-based MCP (snippet for the `cody.mcpServers` editor setting) |
| `devin` | `.devin/skills` / `%APPDATA%\devin\skills` (Windows), `$XDG_CONFIG_HOME/devin/skills` or `~/.config/devin/skills` | `.devin/mcp_config.json` / `mcp_config.json` in `%APPDATA%\devin`, `$XDG_CONFIG_HOME/devin` or `~/.config/devin` |
| `opencode` | `.opencode/skills` / `$XDG_CONFIG_HOME/opencode/skills` (default `~/.config`) | `mcp.servers` in `opencode.jsonc` or `opencode.json` / same under `~/.config/opencode` |
| `trae` | `.trae/skills` / `~/.trae/skills` | `.trae/mcp.json` / unsupported |
| `qwen` | `.qwen/skills` / `~/.qwen/skills` | `.qwen/settings.json` / `~/.qwen/settings.json` |
| `hermes` | `.hermes/skills` / `~/.hermes/skills` | unsupported / YAML `mcp_servers` in `~/.hermes/config.yaml` |
| `replit` | `.agents/skills` / unsupported | no file-based MCP (remote HTTPS servers via the UI) |
| `augment` | `.augment/skills` / `~/.augment/skills` | `.augment/settings.json` / `~/.augment/settings.json` |
| `amp` | `.agents/skills` / `~/.config/agents/skills` | `amp.mcpServers` in `.amp/settings.json` / `~/.config/amp/settings.json` |

`all` installs skills for every supported target and scope (Aider and Cody are skipped and reported) and registers MCP for every target that supports the scope; unsupported targets and scopes are listed as skipped, not failed.

Existing configuration files are never re-serialized. JSON and JSONC files (comments, trailing commas, a UTF-8 BOM, key order, number spelling and line endings) are edited surgically at the `sentra` entry; TOML and block-style YAML are edited only in layouts Sentra can change losslessly. Before an existing file changes, its previous content is copied to `<file>.bak` (or `<file>.bak.N`; for skill files `<skills dir>/.sentra-backups/<id>/<file>.bak`, outside the directory the agent loads as the skill) and the new content is written to a temporary file in the same directory and renamed into place; a rerun with identical content writes nothing. When a file cannot be edited losslessly (invalid syntax, UTF-16 or other non-UTF-8 encodings, unexpected structure, YAML anchors or flow style, ambiguous TOML), the file is left untouched and the command fails with the snippet to add by hand:

| Code | Exit | Meaning |
| --- | --- | --- |
| `invalid_target`, `invalid_arguments` | 2 | Unknown target, or `--skill` combined with MCP registration |
| `unsupported_target`, `mcp_unsupported_target`, `unsupported_scope` | 2 | No documented file location for this target or scope |
| `workspace_not_found`, `no_skills_selected`, `mcp_command_not_found` | 2 | Missing workspace directory, empty `--skill`, or a `--command` path that does not exist |
| `mcp_config_unparseable`, `mcp_config_unsupported_encoding`, `mcp_config_unexpected_shape`, `mcp_manual_step_required` | 4 | MCP config left untouched; `manual_step` carries the path, format, snippet and instructions |
| `manual_config_edit_required` | 6 | Skills were installed, but `.aider.conf.yml` needs the printed `read:` snippet |
| `skill_not_found` | 7 | Unknown skill id; nothing is written |
| `install_failed`, `mcp_install_io_failed`, `home_dir_unavailable`, `home_directory_unresolved`, `mcp_command_unresolved` | 5 | I/O failure or no usable home directory / executable path |

With `--json`, success reports go to stdout and errors to stderr as one JSON object (`schema_version`, `error`, `message`, plus details such as `unknown_skills` or `manual_step`). Residual risk: `~/.claude.json` is a large state file that Claude Code rewrites while running; Sentra re-reads it before the rename and retries, but cannot lock it, so register global Claude configuration while Claude Code is closed.

**Proposed, not implemented.** Further external use cases include session planning and cancellation, evidence and finding reads from a persisted store, and validation requests. Reading restricted artifacts still requires authorization. An external agent can request approval but cannot grant it on behalf of a human. Sensitive dispatch occurs only after the core validates a trusted human approval record; no MCP tool performs sensitive dispatch today.

Remote HTTP remains disabled until transport authentication, resource-scoped authorization, origin checks where relevant, SSRF/destination checks, rate limits, and audit controls pass. Follow the transport-specific authorization model; do not forward unrelated user tokens to downstream services. Tool annotations are descriptive metadata, not security enforcement.

## Conformance gate

Every supported adapter must pass fixtures for version negotiation, capability denial, deterministic input correlation, malformed/oversized output, cancellation, crash/restart, duplicate requests, stale results, unknown test status, secret canaries, and failed cleanup. Analysis adapters additionally need labeled positive/negative targets and native-to-normalized result checks. Execution adapters need the full containment suite; provider adapters need structured-output and usage/egress checks.

No plugin is considered supported merely because it starts successfully or lists a tool. Publish exact tested versions and limitations with each release.
