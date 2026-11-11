//! Terminal adapter for the local Core lifecycle. No SQL or execution authority.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::{
    ffi::OsString,
    io::{BufRead, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use sentra_core::{
    AdvisoryDatabase, CodeQlProbeReport, CodeQlSarifIngestResult, ContainmentReadiness,
    DEFAULT_INVENTORY_MAX_DEPTH, DEFAULT_MAX_LINE_BYTES, DiscoveredPlugin, FileDeltaKind,
    MAX_INVENTORY_DEPTH, McpServer, OsvDirectoryIngest, PluginCapability, PluginDriver,
    PluginError, PluginErrorKind, PluginExecutionOutput, PluginProbeOutput, RemediationPrPackage,
    SastReport, SessionId, SnapshotDiff, TaskId, TenantRecord, TimestampUtc, WorkerFleetManager,
    ingest_osv_directory_report,
    mcp::{LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, run_stdio},
    plugin::{
        CodeQlAnalyzeRequest, CodeQlHostError, CodeQlHostErrorKind, CodeQlHostLanguage,
        CodeQlLanguageStatus, CodeQlResultReport, CodeQlSarifError, CodeQlSuite,
        DEFAULT_CODEQL_MAX_RESULTS, DEFAULT_CODEQL_TIMEOUT_SECS, DiagnosticSeverity,
        DiscoveryDiagnostic, MAX_CODEQL_MAX_RESULTS, MAX_CODEQL_TIMEOUT_SECS, PluginSessionReport,
        analyze_workspace_with_codeql, default_plugin_dir, import_codeql_sarif,
        plugin_dir_env_diagnostic, resolve_plugin, scan_plugin_dirs,
    },
    research::SkillPromptError,
    service::{
        LocalAuditReport, LocalInventoryReport, LocalPatchReport, LocalRollbackReport,
        LocalWorkspace, LocalWorkspaceError, LocalWorkspaceErrorKind, LocalWorkspaceReport,
    },
    skills::{
        AgentTarget, McpBatchReport, McpFileAction, McpInstallError, McpInstallOptions,
        McpInstallReport, McpScope, McpTarget,
        installer::{FileStatus, InstallError, InstallReport},
    },
};

pub const HELP: &str = "Sentra local foundation\n\nUsage:\n  sentra init --workspace <directory> --database <file> [--json]\n  sentra status --database <file> [--workspace <directory>] [--json]\n  sentra session show <session-id> --database <file> [--workspace <directory>] [--json]\n  sentra recover --database <file> [--workspace <directory>] [--json]\n  sentra audit --database <file> [--workspace <directory>] [--json]\n  sentra inventory [--workspace <directory>] [--max-depth <n>] [--json]\n  sentra scan [--workspace <directory>] [--snippet <string>] [-] [--file-name <name>] [--database <file>] [--sarif <file>] [--json]\n  sentra patch apply --patch <file> --workspace <directory> [--target <file>] [--backup-dir <directory>] [--database <file>] [--dry-run] [--json]\n  sentra patch rollback --backup <file> --workspace <directory> --target <file> [--database <file>] [--json]\n  sentra install <target> [--global] [--skill <id>[,<id>...]] [--workspace <directory>] [--json]\n  sentra install <target> --mcp [--global] [--workspace <directory>] [--command <path>] [--json]\n  sentra install mcp <target> [--global] [--workspace <directory>] [--command <path>] [--json]\n  sentra mcp install <target> [--global] [--workspace <directory>] [--command <path>] [--json]\n  sentra skills list [--json]\n  sentra skills show <id> [--json]\n  sentra prompt <workflow> [--scope <path>] [--skills <id>[,<id>...]] [--json]\n  sentra tenant list --database <file> [--json]\n  sentra tenant add --id <id> --name <name> [--workspace <directory>] [--isolation <level>] --database <file> [--json]\n  sentra config show [--key <key>] [--database <file>] [--json]\n  sentra config set --key <key> --value <value> [--database <file>] [--json]\n  sentra config test --provider <name> [--api-key <key>] [--model <model>] [--json]\n  sentra fleet list [--json]\n  sentra fleet status [--json]\n  sentra plugin list [--dir <directory>] [--json]\n  sentra plugin probe (--id <id> | --manifest <file>) [--dir <directory>] [--workspace <directory>] [--json]\n  sentra plugin run (--id <id> | --manifest <file>) --capability <capability> [--args <json>] [--dir <directory>] [--workspace <directory>] [--json]\n  sentra sync-advisories --source <directory-or-file> [--json]\n  sentra propose-pr --database <file> [--workspace <directory>] [--output <file>] [--json]\n  sentra codeql [--workspace <directory>] [--sarif <file>] [--database <file>] [--json]\n  sentra codeql analyze --workspace <directory> --codeql <launcher> --work-dir <directory> --pack-cache <directory> --accept-codeql-terms [--language <id>]... [--suite code-scanning|security-extended] [--threads <n>] [--ram <mb>] [--timeout-secs <n>] [--allow-pack-download] [--max-results <n>] [--cancel-on-stdin-eof] [--json]\n  sentra codeql import --sarif <file> --workspace <directory> [--max-results <n>] [--json]\n  sentra diff --base <directory> --head <directory> [--json]\n  sentra verify-audit [--json]\n  sentra export sarif --database <file> [--workspace <directory>] [--output <file>] [--json]\n  sentra mcp [--workspace <directory>] [--database <file>]\n  sentra --help\n  sentra --version\n\nStorage must have an existing local parent outside the workspace.\nStatus/session/audit default to the current workspace directory; no upward search.\nInitialization records metadata only. No scanning, AI or target execution.\nAudit analyzes the lockfiles at the workspace root (Cargo, npm, yarn, pnpm, bun, deno, pip, poetry, go, composer, nuget, rubygems) against a small bundled pinned advisory sample, not a synchronized OSV or RustSec feed; is_stale reflects the sample's curation date. Advisories match by package name and version only (the ecosystem is not compared). Lockfiles that cannot be parsed are listed as not audited.\nInventory lists lockfiles found recursively (depth 6 by default; dependency, build and VCS directories skipped; links not followed) and their parsed packages with OSV ecosystem names. Read-only; nothing is executed.\nScan runs heuristic line-based pattern rules for secrets and code antipatterns on workspaces or snippets; --file-name labels a snippet and selects its language rules. Results are unverified candidates.\nPatch applies a single-file unified diff positionally with exact context; all hunks apply or nothing is written. --dry-run validates without writing. --database records PatchApplied/PatchRolledBack events in the local store.\nInstall copies the bundled third-party AppSec skills as on-demand <skills dir>/<id>/SKILL.md trees (with every supporting file) into the location each agent documents. Skill targets: claude, antigravity, copilot, cursor, windsurf, cline, roo, continue, aider, openhands, goose, tabnine, junie, warp, droid, kiro, codex, zed, amazonq, devin, opencode, trae, kimi, qwen, hermes, replit, augment, amp, or all. Cody has no documented skills location (unsupported_target); Amazon Q, Continue and Replit are workspace-only (unsupported_scope); Aider gets read: entries in .aider.conf.yml and requires --skill because it loads every listed file into every chat (skill_selection_required, exit 2; exit 6 with the snippet to add by hand when the file cannot be edited losslessly), and all skips Aider. Unknown --skill ids fail with skill_not_found (exit 7) before anything is written; changed files are backed up first (skill files to <skills dir>/.sentra-backups/<id>/, other files to <file>.bak).\nInstall --mcp registers the stdio MCP server (this executable's absolute path, or --command, with the argument mcp) in the config file each agent documents. MCP targets are the skill targets; aider, openhands, replit and cody have no file-based stdio MCP configuration (mcp_unsupported_target); cline, goose and hermes are global-only and roo, trae and continue are workspace-only (unsupported_scope). Existing files are edited in place (comments, key order and formatting kept) after a <file>.bak backup; a file that cannot be edited losslessly is left untouched and the command exits 4 with the snippet to add by hand. --skill cannot be combined with --mcp.\nSkills lists or inspects the bundled third-party skill playbooks (SKILL.md plus supporting files, licenses in NOTICE).\nPrompt renders AppSec prompt templates (threat-model, api-bola, patch-remediation, skill-audit, scout, verify); --skills appends the named playbooks to the workflow prompt, keeping its rules and expected schema, and unknown ids fail with skill_not_found (exit 7).\nTenant lists or adds operator-declared tenant rows (labels only; no isolation is provisioned). List is read-only and never seeds rows.\nConfig show and set read and write plain-text key/value rows in a system_settings table of --database (default data/sentra.db, relative to the current directory). The file and table are created if missing, but only inside an existing directory: when the parent directory does not exist, both fail with storage_or_service_failure (exit 5) and create nothing. No Sentra command reads these settings, and values, API keys included, are stored unencrypted. Config test is not implemented (the core CLI has no model-provider client): it exits 5 with not_implemented.\nFleet reports the in-process worker registry, which is empty because no worker registry source exists; containment readiness is never reported as ready without worker attestation.\nPlugin discovers adapters only in --dir or the default plugin directory (SENTRA_PLUGIN_DIR, else %APPDATA%/sentra/plugins on Windows, ~/Library/Application Support/sentra/plugins on macOS, $XDG_CONFIG_HOME/sentra/plugins or ~/.config/sentra/plugins elsewhere); the current directory and its parents are never searched and duplicate plugin ids are rejected. Probe and run start adapter code as a subprocess with the operator's privileges and an allowlisted environment; the time limit and frame/output quotas are enforced and the process tree is killed when the session ends, while declared memory and egress limits are not enforced. Run passes --workspace (default: current directory) to the adapter; its exit code, summary and evidence refs are adapter-reported.\nSync-advisories parses local OSV JSON (one file, or the top-level .json files of a directory) in memory and reports the advisory entries found. In a directory, unreadable or invalid files are counted as skipped; a single file that is not valid OSV JSON fails with invalid_advisory_feed (exit 4), and one that cannot be read with io_error (exit 5). Nothing is downloaded or persisted: audit, propose-pr and export sarif always use the bundled sample, and --database fails with not_implemented (exit 5).\nPropose-pr runs the dependency audit (bundled advisory sample, recorded as an audit task like audit) and prints one local draft pull request preview per match: title, a body that states which checks were not done, the lockfile the package came from, an illustrative version-bump diff that does not apply as-is, and a suggested gh command that is not run (it reads the body from <proposal id>.md; shell metacharacters in its title and branch are replaced with _). No branch, commit or pull request is created; --output writes the previews to a file.\nCodeql probes the workspace for languages and prints suggested CodeQL CLI commands (CodeQL is not run), or with --sarif parses a CodeQL SARIF file and reports its results. Nothing is uploaded and the parsed findings are not stored (with --workspace and --database, a completed task is recorded).\nCodeql analyze runs an operator-installed CodeQL CLI on this host (opt-in, ADR-0011) and refuses to start without --accept-codeql-terms: CodeQL is licensed under the GitHub CodeQL Terms and Conditions (LICENSE.md in its distribution), and Sentra does not check that your use is permitted. --codeql must be the codeql.exe of a CodeQL distribution on Windows (codeql.cmd and .bat files are refused) or its codeql launcher elsewhere. Only database create --build-mode=none is used: no build command, autobuild or build tracing, and the project is never built. actions, cpp, javascript, python and ruby are analyzed; go and swift (no build-mode none) and rust, csharp and java (their build-mode none extractors run project-controlled code: Cargo build scripts and procedural macros, dotnet restore, the project's Gradle wrapper or Maven) are reported as skipped. CodeQL's extractors still read and parse the untrusted code on this host, and the C/C++ and Python extractors start host compilers and the host Python. Each run gets a new run directory inside --work-dir, which every CodeQL step uses as its working directory, with an allowlisted environment (no tokens or keys), temporary and home directories inside the run directory, and the total --timeout-secs budget (default 1800; codeql version is also capped at 120 seconds); when the budget runs out the whole CodeQL process tree is killed (codeql_timeout, exit 5). --work-dir and --pack-cache are refused inside the workspace; on Unix they must belong to you and not be writable by group or others, and the run directory is created with mode 0700 (unsafe_directory, exit 4). On Windows a workspace, --work-dir or --pack-cache path containing & ^ ! or % is refused (invalid_workspace or unsafe_directory, exit 4), because CodeQL's extractor batch scripts expand those paths unquoted and cmd.exe would run part of the path as a command. With --cancel-on-stdin-eof the analysis is cancelled when standard input reaches end of file (for a parent process that keeps it open while it waits): the CodeQL process tree is killed and codeql_cancelled (exit 5) is returned. The run directory, databases included, is deleted afterwards. Query packs are read from the distribution or --pack-cache; only with --allow-pack-download does codeql pack download fetch a missing pack into --pack-cache (from the registry CodeQL is configured for, by default ghcr.io). Without it a language whose pack is missing is skipped, and codeql_query_pack_missing (exit 6) is returned when no language could run. Findings are candidate claims and are not stored.\nCodeql import normalizes a CodeQL SARIF file produced elsewhere (a local run, GitHub Actions; at most 64 MiB) into the same JSON as analyze. SARIF from other tools is rejected (sarif_not_codeql), and results whose path is absolute or outside the workspace are dropped and counted. Nothing is run, uploaded or stored.\nDiff compares base and head directory snapshots with pure-Rust hashing.\nVerify-audit is not implemented: no worker registry, secret-inheritance check or tamper-evident audit trail exists to assess, so it exits 5 with not_implemented instead of reporting gates.\nExport sarif runs the dependency audit (bundled advisory sample, recorded as an audit task like audit) and writes its results only as an OASIS SARIF v2.1.0 document to --output or stdout; SAST results are exported with scan --sarif. Nothing is uploaded.\nMcp runs the local stdio MCP server (legacy initialize-handshake revisions 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05; the 2026-07-28 revision is not implemented). Tools are read-only and confined to --workspace (default: current directory); --database enables persisted session status. Skill installation is not exposed over MCP; use sentra install. Mcp install is an alias of install mcp.\n";

/// Actions supported by the `sentra skills` command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkillsAction {
    /// Lists all built-in AppSec skills.
    List,
    /// Shows the full Markdown specification of a skill by ID.
    Show {
        /// Skill ID to inspect.
        id: String,
    },
}

/// Actions supported by the `sentra tenant` command.
pub enum TenantAction {
    List,
    Add {
        id: String,
        name: String,
        description: Option<String>,
        default_workspace: Option<String>,
        isolation_level: Option<String>,
    },
}

/// Actions supported by the `sentra config` command.
pub enum ConfigAction {
    Show {
        key: Option<String>,
    },
    Set {
        key: String,
        value: String,
    },
    Test {
        provider: String,
        api_key: Option<String>,
        model: Option<String>,
    },
}

/// Actions supported by the `sentra fleet` command.
pub enum FleetAction {
    List,
    Status,
}

/// Actions supported by the `sentra patch` command.
pub enum PatchAction {
    Apply {
        patch: PathBuf,
        workspace: PathBuf,
        target: Option<PathBuf>,
        backup_dir: Option<PathBuf>,
        database: Option<PathBuf>,
        /// Validate every hunk against the target and write nothing.
        dry_run: bool,
    },
    Rollback {
        backup: PathBuf,
        workspace: PathBuf,
        target: PathBuf,
        database: Option<PathBuf>,
    },
}

/// Actions supported by the `sentra plugin` command.
pub enum PluginAction {
    List {
        directory: Option<PathBuf>,
    },
    Probe {
        id: Option<String>,
        manifest: Option<PathBuf>,
        directory: Option<PathBuf>,
        workspace: Option<PathBuf>,
    },
    Run {
        id: Option<String>,
        manifest: Option<PathBuf>,
        directory: Option<PathBuf>,
        capability: String,
        arguments: Option<String>,
        workspace: Option<PathBuf>,
    },
}

/// Typed presentation command. Paths are untrusted until validated by Core.
pub enum Command {
    Help,
    Version,
    Init {
        workspace: PathBuf,
        database: PathBuf,
    },
    Status {
        workspace: Option<PathBuf>,
        database: PathBuf,
    },
    Session {
        id: SessionId,
        workspace: Option<PathBuf>,
        database: PathBuf,
    },
    Recover {
        workspace: Option<PathBuf>,
        database: PathBuf,
    },
    Audit {
        workspace: Option<PathBuf>,
        database: PathBuf,
    },
    Scan {
        workspace: Option<PathBuf>,
        snippet: Option<String>,
        stdin: bool,
        /// Snippet label (basename); selects language rules. Snippet/stdin only.
        file_name: Option<String>,
        database: Option<PathBuf>,
        sarif: Option<PathBuf>,
    },
    Inventory {
        workspace: Option<PathBuf>,
        max_depth: usize,
    },
    SyncAdvisories {
        source: PathBuf,
        database: Option<PathBuf>,
    },
    ProposePr {
        workspace: Option<PathBuf>,
        database: PathBuf,
        output: Option<PathBuf>,
    },
    Codeql {
        workspace: Option<PathBuf>,
        sarif: Option<PathBuf>,
        database: Option<PathBuf>,
    },
    /// Opt-in host analysis with an operator-installed CodeQL CLI (ADR-0011).
    CodeqlAnalyze(Box<CodeqlAnalyzeArgs>),
    /// Normalizes a CodeQL SARIF file produced elsewhere.
    CodeqlImport {
        sarif: PathBuf,
        workspace: PathBuf,
        max_results: usize,
    },
    Diff {
        base: PathBuf,
        head: PathBuf,
    },
    ExportSarif {
        workspace: Option<PathBuf>,
        database: PathBuf,
        output: Option<PathBuf>,
    },
    Tenant {
        action: TenantAction,
        database: PathBuf,
    },
    Config {
        action: ConfigAction,
        database: Option<PathBuf>,
    },
    Fleet {
        action: FleetAction,
    },
    Patch {
        action: PatchAction,
    },
    Plugin {
        action: PluginAction,
    },
    Install {
        target: String,
        global: bool,
        /// Register the MCP server instead of installing skills.
        mcp: bool,
        /// Comma-separated skill ids (skills only; rejected together with `mcp`).
        skill: Option<String>,
        workspace: Option<PathBuf>,
        /// Executable registered as the MCP server command (MCP only).
        command: Option<PathBuf>,
    },
    Skills {
        action: SkillsAction,
    },
    Prompt {
        workflow: String,
        scope: Option<String>,
        skills: Option<String>,
    },
    /// Local stdio MCP server confined to `workspace` (default: current directory).
    Mcp {
        workspace: Option<PathBuf>,
        database: Option<PathBuf>,
    },
    VerifyAudit,
}

/// Arguments of `sentra codeql analyze`. Paths are untrusted until validated by Core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeqlAnalyzeArgs {
    pub workspace: PathBuf,
    pub codeql: PathBuf,
    pub work_dir: PathBuf,
    pub pack_cache: PathBuf,
    /// `--accept-codeql-terms`; checked at execution so the refusal is explained.
    pub accept_terms: bool,
    pub languages: Vec<CodeQlHostLanguage>,
    pub suite: CodeQlSuite,
    pub threads: Option<u32>,
    pub ram_mb: Option<u32>,
    pub timeout_secs: u64,
    pub allow_pack_download: bool,
    pub max_results: usize,
    /// `--cancel-on-stdin-eof`: cancel the analysis when stdin reaches end of file.
    pub cancel_on_stdin_eof: bool,
}

pub struct Invocation {
    pub command: Command,
    pub json: bool,
}

/// Payload-free parse errors never echo untrusted arguments or paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    InvalidArguments,
}

/// Snippet labels are bare basenames: `^[A-Za-z0-9._-]{1,100}$`.
pub fn is_snippet_file_name(value: &str) -> bool {
    (1..=100).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Decimal depth in `0..=MAX_INVENTORY_DEPTH`; anything else is rejected, not clamped.
fn parse_max_depth(value: &str) -> Option<usize> {
    if value.is_empty() || value.len() > 3 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value
        .parse::<usize>()
        .ok()
        .filter(|depth| *depth <= MAX_INVENTORY_DEPTH)
}

/// Decimal integer in `min..=max`; anything else is rejected, not clamped.
fn parse_bounded(value: &str, min: u64, max: u64) -> Option<u64> {
    if value.is_empty() || value.len() > 12 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|n| (min..=max).contains(n))
}

/// Most `--language` flags accepted by `codeql analyze`.
const MAX_CODEQL_LANGUAGE_FLAGS: usize = 16;

/// Grammar of `codeql analyze` and `codeql import`. Every value flag may appear once
/// (`--language` may repeat); boolean flags take no value.
fn parse_codeql_subcommand(sub: &str, words: Vec<&str>) -> Result<Command, ParseError> {
    let invalid = || ParseError::InvalidArguments;
    let mut workspace = None;
    let mut codeql = None;
    let mut work_dir = None;
    let mut pack_cache = None;
    let mut sarif = None;
    let mut accept_terms = false;
    let mut allow_pack_download = false;
    let mut cancel_on_stdin_eof = false;
    let mut languages = Vec::new();
    let mut suite = None;
    let mut threads = None;
    let mut ram_mb = None;
    let mut timeout_secs = None;
    let mut max_results = None;
    let analyze = sub == "analyze";
    let mut rest = words.into_iter();
    while let Some(flag) = rest.next() {
        match flag {
            "--accept-codeql-terms" if analyze && !accept_terms => {
                accept_terms = true;
                continue;
            }
            "--allow-pack-download" if analyze && !allow_pack_download => {
                allow_pack_download = true;
                continue;
            }
            "--cancel-on-stdin-eof" if analyze && !cancel_on_stdin_eof => {
                cancel_on_stdin_eof = true;
                continue;
            }
            _ => {}
        }
        let value = rest.next().ok_or_else(invalid)?;
        if value.is_empty() || value.starts_with('-') {
            return Err(invalid());
        }
        let first = match flag {
            "--workspace" => workspace.replace(PathBuf::from(value)).is_none(),
            "--max-results" => {
                let n =
                    parse_bounded(value, 1, MAX_CODEQL_MAX_RESULTS as u64).ok_or_else(invalid)?;
                max_results.replace(n as usize).is_none()
            }
            "--sarif" if !analyze => sarif.replace(PathBuf::from(value)).is_none(),
            "--codeql" if analyze => codeql.replace(PathBuf::from(value)).is_none(),
            "--work-dir" if analyze => work_dir.replace(PathBuf::from(value)).is_none(),
            "--pack-cache" if analyze => pack_cache.replace(PathBuf::from(value)).is_none(),
            "--language" if analyze && languages.len() < MAX_CODEQL_LANGUAGE_FLAGS => {
                languages.push(CodeQlHostLanguage::parse(value).ok_or_else(invalid)?);
                true
            }
            "--suite" if analyze => suite
                .replace(CodeQlSuite::parse(value).ok_or_else(invalid)?)
                .is_none(),
            "--threads" if analyze => {
                let n = parse_bounded(value, 1, 256).ok_or_else(invalid)?;
                threads.replace(n as u32).is_none()
            }
            "--ram" if analyze => {
                let n = parse_bounded(value, 256, 4_194_304).ok_or_else(invalid)?;
                ram_mb.replace(n as u32).is_none()
            }
            "--timeout-secs" if analyze => {
                let n = parse_bounded(value, 1, MAX_CODEQL_TIMEOUT_SECS).ok_or_else(invalid)?;
                timeout_secs.replace(n).is_none()
            }
            _ => return Err(invalid()),
        };
        if !first {
            return Err(invalid());
        }
    }
    let workspace = workspace.ok_or_else(invalid)?;
    let max_results = max_results.unwrap_or(DEFAULT_CODEQL_MAX_RESULTS);
    if !analyze {
        return Ok(Command::CodeqlImport {
            sarif: sarif.ok_or_else(invalid)?,
            workspace,
            max_results,
        });
    }
    Ok(Command::CodeqlAnalyze(Box::new(CodeqlAnalyzeArgs {
        workspace,
        codeql: codeql.ok_or_else(invalid)?,
        work_dir: work_dir.ok_or_else(invalid)?,
        pack_cache: pack_cache.ok_or_else(invalid)?,
        accept_terms,
        languages,
        suite: suite.unwrap_or_default(),
        threads,
        ram_mb,
        timeout_secs: timeout_secs.unwrap_or(DEFAULT_CODEQL_TIMEOUT_SECS),
        allow_pack_download,
        max_results,
        cancel_on_stdin_eof,
    })))
}

/// Grammar shared by `install <target> [--mcp]`, `install mcp <target>` and
/// `mcp install <target>`. Every flag may appear once; `--command` only applies
/// to MCP registration. `--skill` is accepted here so that combining it with
/// MCP registration fails with an explanatory error instead of a bare parse error.
fn parse_install(words: Vec<&str>, mut mcp: bool) -> Result<Command, ParseError> {
    let invalid = || ParseError::InvalidArguments;
    let mut target = None;
    let mut global = false;
    let mut skill = None;
    let mut workspace = None;
    let mut command = None;
    let mut rest = words.into_iter();
    while let Some(arg) = rest.next() {
        match arg {
            "--global" | "-g" if !global => global = true,
            "--mcp" if !mcp => mcp = true,
            "mcp" if !mcp && target.is_none() => mcp = true,
            "--skill" | "--workspace" | "--command" => {
                let value = rest.next().ok_or_else(invalid)?;
                if value.is_empty() || value.starts_with('-') {
                    return Err(invalid());
                }
                let first = match arg {
                    "--skill" => skill.replace(value.to_string()).is_none(),
                    "--workspace" => workspace.replace(PathBuf::from(value)).is_none(),
                    _ => command.replace(PathBuf::from(value)).is_none(),
                };
                if !first {
                    return Err(invalid());
                }
            }
            _ if !arg.starts_with('-') && target.is_none() => target = Some(arg.to_string()),
            _ => return Err(invalid()),
        }
    }
    if command.is_some() && !mcp {
        return Err(invalid());
    }
    Ok(Command::Install {
        target: target.ok_or_else(invalid)?,
        global,
        mcp,
        skill,
        workspace,
        command,
    })
}

/// Small fixed command grammar; no shell evaluation, plugins or environment
/// configuration. UTF-8 arguments only, maximum 64 arguments, duplicates deny.
pub fn parse(arguments: &[OsString]) -> Result<Invocation, ParseError> {
    let invalid = || ParseError::InvalidArguments;
    if arguments.len() > 64 {
        return Err(invalid());
    }
    let mut words = arguments
        .iter()
        .map(|s| s.to_str().ok_or_else(invalid))
        .collect::<Result<Vec<_>, _>>()?;
    let json_count = words.iter().filter(|s| **s == "--json").count();
    if json_count > 1 {
        return Err(invalid());
    }
    let json = json_count == 1;
    words.retain(|s| *s != "--json");
    if words.is_empty() || words == ["--help"] || words == ["help"] {
        return Ok(Invocation {
            command: Command::Help,
            json,
        });
    }
    if words == ["--version"] {
        return Ok(Invocation {
            command: Command::Version,
            json,
        });
    }
    let name = words.remove(0);
    if !matches!(
        name,
        "init"
            | "status"
            | "session"
            | "recover"
            | "audit"
            | "inventory"
            | "scan"
            | "sync-advisories"
            | "propose-pr"
            | "codeql"
            | "diff"
            | "mcp"
            | "verify-audit"
            | "export"
            | "patch"
            | "tenant"
            | "config"
            | "fleet"
            | "plugin"
            | "install"
            | "skills"
            | "prompt"
    ) {
        return Err(invalid());
    }
    if words == ["--help"] {
        return Ok(Invocation {
            command: Command::Help,
            json,
        });
    }
    if name == "inventory" {
        let mut workspace = None;
        let mut max_depth = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || value.starts_with('-') {
                return Err(invalid());
            }
            match flag {
                "--workspace" if workspace.is_none() => workspace = Some(PathBuf::from(value)),
                "--max-depth" if max_depth.is_none() => {
                    max_depth = Some(parse_max_depth(value).ok_or_else(invalid)?)
                }
                _ => return Err(invalid()),
            }
        }
        return Ok(Invocation {
            command: Command::Inventory {
                workspace,
                max_depth: max_depth.unwrap_or(DEFAULT_INVENTORY_MAX_DEPTH),
            },
            json,
        });
    }
    if name == "scan" {
        let mut workspace = None;
        let mut snippet = None;
        let mut stdin = false;
        let mut file_name = None;
        let mut database = None;
        let mut sarif = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            if flag == "-" {
                if stdin {
                    return Err(invalid());
                }
                stdin = true;
                continue;
            }
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || (value.starts_with('-') && flag != "--snippet") {
                return Err(invalid());
            }
            match flag {
                "--workspace" if workspace.is_none() => workspace = Some(PathBuf::from(value)),
                "--snippet" if snippet.is_none() => snippet = Some(value.to_string()),
                "--file-name" if file_name.is_none() && is_snippet_file_name(value) => {
                    file_name = Some(value.to_string())
                }
                "--database" if database.is_none() => database = Some(PathBuf::from(value)),
                "--sarif" if sarif.is_none() => sarif = Some(PathBuf::from(value)),
                _ => return Err(invalid()),
            }
        }
        if workspace.is_none() && snippet.is_none() && !stdin {
            return Err(invalid());
        }
        // A file name only labels in-memory snippet content; it never names a path.
        if file_name.is_some() && (workspace.is_some() || (snippet.is_none() && !stdin)) {
            return Err(invalid());
        }
        return Ok(Invocation {
            command: Command::Scan {
                workspace,
                snippet,
                stdin,
                file_name,
                database,
                sarif,
            },
            json,
        });
    }
    if name == "patch" {
        if words.is_empty() {
            return Err(invalid());
        }
        let sub = words.remove(0);
        if sub == "--help" {
            return Ok(Invocation {
                command: Command::Help,
                json,
            });
        }
        let mut patch = None;
        let mut workspace = None;
        let mut target = None;
        let mut backup = None;
        let mut backup_dir = None;
        let mut database = None;
        let mut dry_run = false;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            if flag == "--dry-run" {
                if dry_run || sub != "apply" {
                    return Err(invalid());
                }
                dry_run = true;
                continue;
            }
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || value.starts_with('-') {
                return Err(invalid());
            }
            match flag {
                "--patch" if patch.is_none() => patch = Some(PathBuf::from(value)),
                "--workspace" if workspace.is_none() => workspace = Some(PathBuf::from(value)),
                "--target" if target.is_none() => target = Some(PathBuf::from(value)),
                "--backup" if backup.is_none() => backup = Some(PathBuf::from(value)),
                "--backup-dir" if backup_dir.is_none() => backup_dir = Some(PathBuf::from(value)),
                "--database" if database.is_none() => database = Some(PathBuf::from(value)),
                _ => return Err(invalid()),
            }
        }
        match sub {
            "apply" => {
                let patch = patch.ok_or_else(invalid)?;
                let workspace = workspace.ok_or_else(invalid)?;
                return Ok(Invocation {
                    command: Command::Patch {
                        action: PatchAction::Apply {
                            patch,
                            workspace,
                            target,
                            backup_dir,
                            database,
                            dry_run,
                        },
                    },
                    json,
                });
            }
            "rollback" => {
                let backup = backup.ok_or_else(invalid)?;
                let workspace = workspace.ok_or_else(invalid)?;
                let target = target.ok_or_else(invalid)?;
                return Ok(Invocation {
                    command: Command::Patch {
                        action: PatchAction::Rollback {
                            backup,
                            workspace,
                            target,
                            database,
                        },
                    },
                    json,
                });
            }
            _ => return Err(invalid()),
        }
    }
    if name == "tenant" {
        if words.is_empty() {
            return Err(invalid());
        }
        let sub = words.remove(0);
        if sub == "--help" {
            return Ok(Invocation {
                command: Command::Help,
                json,
            });
        }
        let mut database = None;
        let mut id = None;
        let mut t_name = None;
        let mut description = None;
        let mut default_workspace = None;
        let mut isolation_level = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || value.starts_with('-') {
                return Err(invalid());
            }
            match flag {
                "--database" if database.is_none() => database = Some(PathBuf::from(value)),
                "--id" if id.is_none() => id = Some(value.to_string()),
                "--name" if t_name.is_none() => t_name = Some(value.to_string()),
                "--description" if description.is_none() => description = Some(value.to_string()),
                "--workspace" if default_workspace.is_none() => {
                    default_workspace = Some(value.to_string())
                }
                "--isolation" if isolation_level.is_none() => {
                    isolation_level = Some(value.to_string())
                }
                _ => return Err(invalid()),
            }
        }
        let database = database.ok_or_else(invalid)?;
        match sub {
            "list" => {
                return Ok(Invocation {
                    command: Command::Tenant {
                        action: TenantAction::List,
                        database,
                    },
                    json,
                });
            }
            "add" => {
                let id = id.ok_or_else(invalid)?;
                let name = t_name.ok_or_else(invalid)?;
                return Ok(Invocation {
                    command: Command::Tenant {
                        action: TenantAction::Add {
                            id,
                            name,
                            description,
                            default_workspace,
                            isolation_level,
                        },
                        database,
                    },
                    json,
                });
            }
            _ => return Err(invalid()),
        }
    }
    if name == "config" {
        if words.is_empty() {
            return Err(invalid());
        }
        let sub = words.remove(0);
        if sub == "--help" {
            return Ok(Invocation {
                command: Command::Help,
                json,
            });
        }
        let mut database = None;
        let mut key = None;
        let mut val = None;
        let mut provider = None;
        let mut api_key = None;
        let mut model = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || (value.starts_with('-') && flag != "--value") {
                return Err(invalid());
            }
            match flag {
                "--database" if database.is_none() => database = Some(PathBuf::from(value)),
                "--key" if key.is_none() => key = Some(value.to_string()),
                "--value" if val.is_none() => val = Some(value.to_string()),
                "--provider" if provider.is_none() => provider = Some(value.to_string()),
                "--api-key" if api_key.is_none() => api_key = Some(value.to_string()),
                "--model" if model.is_none() => model = Some(value.to_string()),
                _ => return Err(invalid()),
            }
        }
        match sub {
            "show" => {
                return Ok(Invocation {
                    command: Command::Config {
                        action: ConfigAction::Show { key },
                        database,
                    },
                    json,
                });
            }
            "set" => {
                let key = key.ok_or_else(invalid)?;
                let value = val.ok_or_else(invalid)?;
                return Ok(Invocation {
                    command: Command::Config {
                        action: ConfigAction::Set { key, value },
                        database,
                    },
                    json,
                });
            }
            "test" => {
                let provider = provider.ok_or_else(invalid)?;
                return Ok(Invocation {
                    command: Command::Config {
                        action: ConfigAction::Test {
                            provider,
                            api_key,
                            model,
                        },
                        database,
                    },
                    json,
                });
            }
            _ => return Err(invalid()),
        }
    }
    if name == "fleet" {
        let sub = if words.is_empty() {
            "status"
        } else {
            words.remove(0)
        };
        if sub == "--help" {
            return Ok(Invocation {
                command: Command::Help,
                json,
            });
        }
        if !words.is_empty() {
            return Err(invalid());
        }
        let action = match sub {
            "list" => FleetAction::List,
            "status" => FleetAction::Status,
            _ => return Err(invalid()),
        };
        return Ok(Invocation {
            command: Command::Fleet { action },
            json,
        });
    }
    if name == "sync-advisories" {
        let mut source = None;
        let mut database = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || value.starts_with('-') {
                return Err(invalid());
            }
            match flag {
                "--source" if source.is_none() => source = Some(PathBuf::from(value)),
                "--database" if database.is_none() => database = Some(PathBuf::from(value)),
                _ => return Err(invalid()),
            }
        }
        let source = source.ok_or_else(invalid)?;
        return Ok(Invocation {
            command: Command::SyncAdvisories { source, database },
            json,
        });
    }
    if name == "propose-pr" {
        let mut workspace = None;
        let mut database = None;
        let mut output = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || value.starts_with('-') {
                return Err(invalid());
            }
            match flag {
                "--workspace" if workspace.is_none() => workspace = Some(PathBuf::from(value)),
                "--database" if database.is_none() => database = Some(PathBuf::from(value)),
                "--output" if output.is_none() => output = Some(PathBuf::from(value)),
                _ => return Err(invalid()),
            }
        }
        let database = database.ok_or_else(invalid)?;
        return Ok(Invocation {
            command: Command::ProposePr {
                workspace,
                database,
                output,
            },
            json,
        });
    }
    if name == "codeql" {
        if let Some(sub @ ("analyze" | "import")) = words.first().copied() {
            words.remove(0);
            if words == ["--help"] {
                return Ok(Invocation {
                    command: Command::Help,
                    json,
                });
            }
            return Ok(Invocation {
                command: parse_codeql_subcommand(sub, words)?,
                json,
            });
        }
        let mut workspace = None;
        let mut sarif = None;
        let mut database = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || value.starts_with('-') {
                return Err(invalid());
            }
            match flag {
                "--workspace" if workspace.is_none() => workspace = Some(PathBuf::from(value)),
                "--sarif" if sarif.is_none() => sarif = Some(PathBuf::from(value)),
                "--database" if database.is_none() => database = Some(PathBuf::from(value)),
                _ => return Err(invalid()),
            }
        }
        if workspace.is_none() && sarif.is_none() {
            return Err(invalid());
        }
        return Ok(Invocation {
            command: Command::Codeql {
                workspace,
                sarif,
                database,
            },
            json,
        });
    }
    if name == "export" {
        if words.is_empty() || words.remove(0) != "sarif" {
            return Err(invalid());
        }
        if words == ["--help"] {
            return Ok(Invocation {
                command: Command::Help,
                json,
            });
        }
        let mut workspace = None;
        let mut database = None;
        let mut output = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || value.starts_with('-') {
                return Err(invalid());
            }
            match flag {
                "--workspace" if workspace.is_none() => workspace = Some(PathBuf::from(value)),
                "--database" if database.is_none() => database = Some(PathBuf::from(value)),
                "--output" if output.is_none() => output = Some(PathBuf::from(value)),
                _ => return Err(invalid()),
            }
        }
        let database = database.ok_or_else(invalid)?;
        return Ok(Invocation {
            command: Command::ExportSarif {
                workspace,
                database,
                output,
            },
            json,
        });
    }
    if name == "mcp" {
        if words.first().copied() == Some("install") {
            words.remove(0);
            return Ok(Invocation {
                command: parse_install(words, true)?,
                json,
            });
        }
        let mut workspace = None;
        let mut database = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || value.starts_with('-') {
                return Err(invalid());
            }
            match flag {
                "--workspace" if workspace.is_none() => workspace = Some(PathBuf::from(value)),
                "--database" if database.is_none() => database = Some(PathBuf::from(value)),
                _ => return Err(invalid()),
            }
        }
        return Ok(Invocation {
            command: Command::Mcp {
                workspace,
                database,
            },
            json,
        });
    }
    if name == "verify-audit" {
        if !words.is_empty() {
            return Err(invalid());
        }
        return Ok(Invocation {
            command: Command::VerifyAudit,
            json,
        });
    }
    if name == "diff" {
        let mut base = None;
        let mut head = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || value.starts_with('-') {
                return Err(invalid());
            }
            match flag {
                "--base" if base.is_none() => base = Some(PathBuf::from(value)),
                "--head" if head.is_none() => head = Some(PathBuf::from(value)),
                _ => return Err(invalid()),
            }
        }
        let base = base.ok_or_else(invalid)?;
        let head = head.ok_or_else(invalid)?;
        return Ok(Invocation {
            command: Command::Diff { base, head },
            json,
        });
    }
    if name == "plugin" {
        if words.is_empty() {
            return Err(invalid());
        }
        let sub = words.remove(0);
        if sub == "--help" {
            return Ok(Invocation {
                command: Command::Help,
                json,
            });
        }
        let mut id = None;
        let mut manifest = None;
        let mut directory = None;
        let mut workspace = None;
        let mut capability = None;
        let mut arguments = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || (value.starts_with('-') && flag != "--args") {
                return Err(invalid());
            }
            match flag {
                "--id" if id.is_none() => id = Some(value.to_string()),
                "--manifest" if manifest.is_none() => manifest = Some(PathBuf::from(value)),
                "--dir" if directory.is_none() => directory = Some(PathBuf::from(value)),
                "--workspace" if workspace.is_none() => workspace = Some(PathBuf::from(value)),
                "--capability" if capability.is_none() => capability = Some(value.to_string()),
                "--args" if arguments.is_none() => arguments = Some(value.to_string()),
                _ => return Err(invalid()),
            }
        }
        match sub {
            "list" => {
                return Ok(Invocation {
                    command: Command::Plugin {
                        action: PluginAction::List { directory },
                    },
                    json,
                });
            }
            "probe" => {
                if id.is_none() && manifest.is_none() {
                    return Err(invalid());
                }
                return Ok(Invocation {
                    command: Command::Plugin {
                        action: PluginAction::Probe {
                            id,
                            manifest,
                            directory,
                            workspace,
                        },
                    },
                    json,
                });
            }
            "run" => {
                if (id.is_none() && manifest.is_none()) || capability.is_none() {
                    return Err(invalid());
                }
                return Ok(Invocation {
                    command: Command::Plugin {
                        action: PluginAction::Run {
                            id,
                            manifest,
                            directory,
                            capability: capability.unwrap(),
                            arguments,
                            workspace,
                        },
                    },
                    json,
                });
            }
            _ => return Err(invalid()),
        }
    }
    if name == "install" {
        return Ok(Invocation {
            command: parse_install(words, false)?,
            json,
        });
    }
    if name == "skills" {
        if words.is_empty() {
            return Ok(Invocation {
                command: Command::Skills {
                    action: SkillsAction::List,
                },
                json,
            });
        }
        let sub = words.remove(0);
        match sub {
            "list" => {
                if !words.is_empty() {
                    return Err(invalid());
                }
                return Ok(Invocation {
                    command: Command::Skills {
                        action: SkillsAction::List,
                    },
                    json,
                });
            }
            "show" => {
                if words.is_empty() {
                    return Err(invalid());
                }
                let id = words.remove(0);
                if !words.is_empty() || id.starts_with('-') {
                    return Err(invalid());
                }
                return Ok(Invocation {
                    command: Command::Skills {
                        action: SkillsAction::Show { id: id.to_string() },
                    },
                    json,
                });
            }
            _ => return Err(invalid()),
        }
    }
    if name == "prompt" {
        if words.is_empty() {
            return Err(invalid());
        }
        let workflow = words.remove(0);
        if workflow.starts_with('-') {
            return Err(invalid());
        }
        let mut scope = None;
        let mut skills = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            let slot = match flag {
                "--scope" | "--target" => &mut scope,
                "--skills" | "--skill" => &mut skills,
                _ => return Err(invalid()),
            };
            let val = rest.next().ok_or_else(invalid)?;
            if val.is_empty() || val.starts_with('-') || slot.is_some() {
                return Err(invalid());
            }
            *slot = Some(val.to_string());
        }
        return Ok(Invocation {
            command: Command::Prompt {
                workflow: workflow.to_string(),
                scope,
                skills,
            },
            json,
        });
    }
    let id = if name == "session" {
        if words.len() < 2 || words.remove(0) != "show" {
            return Err(invalid());
        }
        let text = words.remove(0);
        // Domain parsing tolerates whitespace; the CLI grammar is deliberately exact.
        if text.trim() != text {
            return Err(invalid());
        }
        Some(text.parse::<SessionId>().map_err(|_| invalid())?)
    } else {
        None
    };
    let mut workspace = None;
    let mut database = None;
    let mut rest = words.into_iter();
    while let Some(flag) = rest.next() {
        let value = rest.next().ok_or_else(invalid)?;
        if value.is_empty() || value.starts_with('-') {
            return Err(invalid());
        }
        match flag {
            "--workspace" if workspace.is_none() => workspace = Some(PathBuf::from(value)),
            "--database" if database.is_none() => database = Some(PathBuf::from(value)),
            _ => return Err(invalid()),
        }
    }
    let database = database.ok_or_else(invalid)?;
    let command = match name {
        "init" => Command::Init {
            workspace: workspace.ok_or_else(invalid)?,
            database,
        },
        "status" => Command::Status {
            workspace,
            database,
        },
        "session" => Command::Session {
            id: id.ok_or_else(invalid)?,
            workspace,
            database,
        },
        "recover" => Command::Recover {
            workspace,
            database,
        },
        "audit" => Command::Audit {
            workspace,
            database,
        },
        _ => return Err(invalid()),
    };
    Ok(Invocation { command, json })
}

/// Deterministic process result. Output contains only controlled text, typed IDs,
/// enum names and numeric counters; no paths, revisions, operators or payloads.
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: u8,
}

fn error(code: &'static str, exit_code: u8, json: bool) -> Response {
    let stderr = if json {
        format!("{{\"schema_version\":1,\"error\":\"{code}\"}}\n")
    } else {
        format!("error: {code}\n")
    };
    Response {
        stdout: String::new(),
        stderr,
        exit_code,
    }
}

/// Error with an explanation and machine-readable details. JSON mode prints one
/// object on stderr: `{schema_version, error, message, ...details}` (details never
/// override the first three keys); text mode prints `error: <code>` and the message.
fn detailed_error(
    code: &str,
    exit_code: u8,
    json: bool,
    message: &str,
    details: serde_json::Value,
) -> Response {
    let stderr = if json {
        let body = serde_json::json!({
            "schema_version": 1,
            "error": code,
            "message": message,
        });
        json_text(&merge_json(body, details))
    } else {
        format!("error: {code}\n{message}\n")
    };
    Response {
        stdout: String::new(),
        stderr,
        exit_code,
    }
}

/// Exit status of `not_implemented`: the command parses but has no real implementation, so
/// it fails instead of printing a result that was never computed.
const NOT_IMPLEMENTED_EXIT: u8 = 5;

/// `not_implemented` error (exit 5) naming the command and what is missing. JSON mode
/// prints `{schema_version, error, message, command}` on stderr like other detailed errors.
fn not_implemented(command: &str, message: &str, json: bool) -> Response {
    detailed_error(
        "not_implemented",
        NOT_IMPLEMENTED_EXIT,
        json,
        message,
        serde_json::json!({ "command": command }),
    )
}

/// One JSON document followed by a newline (serde_json escapes every string).
fn json_text(value: &impl serde::Serialize) -> String {
    match serde_json::to_string(value) {
        Ok(text) => format!("{text}\n"),
        Err(_) => "{\"schema_version\":1,\"error\":\"serialization_failed\"}\n".to_string(),
    }
}

/// Core exit codes are small positive integers; anything else maps to 5 (failure).
fn exit_status(code: i32) -> u8 {
    u8::try_from(code).ok().filter(|c| *c != 0).unwrap_or(5)
}

fn core_error(source: LocalWorkspaceError, json: bool) -> Response {
    let (code, exit) = match source.kind {
        LocalWorkspaceErrorKind::Workspace => ("invalid_workspace", 4),
        LocalWorkspaceErrorKind::StorageLocation => ("invalid_storage_location", 4),
        LocalWorkspaceErrorKind::WorkspaceMismatch => ("workspace_mismatch", 4),
        LocalWorkspaceErrorKind::Incomplete => ("incomplete_storage", 6),
        LocalWorkspaceErrorKind::SessionNotFound => ("session_not_found", 7),
        LocalWorkspaceErrorKind::Persistence | LocalWorkspaceErrorKind::Service => {
            ("storage_or_service_failure", 5)
        }
        LocalWorkspaceErrorKind::InvalidRequest => ("invalid_arguments", 2),
        LocalWorkspaceErrorKind::InvalidPatch => ("invalid_patch", 4),
        LocalWorkspaceErrorKind::PatchDoesNotApply => ("patch_does_not_apply", 4),
        LocalWorkspaceErrorKind::PatchTarget => ("invalid_patch_target", 4),
        LocalWorkspaceErrorKind::PatchBackup => ("invalid_backup", 4),
        LocalWorkspaceErrorKind::Io => ("io_error", 5),
    };
    error(code, exit, json)
}

fn absolute(path: &Path, cwd: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

/// Plugin directories to scan: `--dir` when given, otherwise the operator's single
/// documented default directory. The current directory, its parents and the
/// repository examples are never searched implicitly.
fn plugin_dirs(cwd: &Path, directory: Option<&Path>, json: bool) -> Result<Vec<PathBuf>, Response> {
    if let Some(dir) = directory {
        return Ok(vec![absolute(dir, cwd)]);
    }
    match default_plugin_dir() {
        Some(dir) => Ok(vec![dir]),
        None => Err(detailed_error(
            "plugin_dir_unavailable",
            2,
            json,
            "no plugin directory: pass --dir or set SENTRA_PLUGIN_DIR to an absolute path",
            serde_json::json!({}),
        )),
    }
}

/// Maps a plugin failure to its stable code and exit status, with the sanitized
/// reason and the host-observed facts of the adapter process when one was started.
fn plugin_error(err: &PluginError, session: Option<&PluginSessionReport>, json: bool) -> Response {
    let exit = match err.kind() {
        PluginErrorKind::InvalidManifest { .. }
        | PluginErrorKind::DuplicatePluginId { .. }
        | PluginErrorKind::ExecutableRejected { .. } => 4,
        PluginErrorKind::PluginNotFound { .. } => 7,
        PluginErrorKind::InvalidWorkspace { .. } => 2,
        _ => 5,
    };
    let mut details = serde_json::json!({ "reason": err.reason() });
    if let (Some(session), Some(object)) = (session, details.as_object_mut()) {
        object.insert(
            "process_exit_code".into(),
            serde_json::json!(session.process_exit_code),
        );
        object.insert("timed_out".into(), session.timed_out.into());
        object.insert("killed_by_host".into(), session.killed_by_host.into());
    }
    detailed_error(err.code(), exit, json, err.reason(), details)
}

/// Loads the plugin named by `--manifest` or resolved by `--id` in the plugin directories.
fn select_plugin(
    id: Option<String>,
    manifest: Option<PathBuf>,
    directory: Option<&Path>,
    cwd: &Path,
    json: bool,
) -> Result<DiscoveredPlugin, Response> {
    if let Some(man_path) = manifest {
        return DiscoveredPlugin::from_manifest_file(absolute(&man_path, cwd))
            .map_err(|e| plugin_error(&e, None, json));
    }
    let Some(plugin_id) = id else {
        return Err(error("invalid_arguments", 2, json));
    };
    let dirs = plugin_dirs(cwd, directory, json)?;
    resolve_plugin(&dirs, &plugin_id).map_err(|e| {
        if !matches!(e.kind(), PluginErrorKind::PluginNotFound { .. }) {
            return plugin_error(&e, None, json);
        }
        // A manifest that failed validation is skipped by discovery; point at it
        // instead of only reporting that no manifest declares the id.
        let skipped: Vec<serde_json::Value> = scan_plugin_dirs(&dirs)
            .diagnostics
            .iter()
            .filter(|d| d.severity == DiagnosticSeverity::Error)
            .map(|d| {
                serde_json::json!({
                    "path": display_path(&d.path),
                    "code": d.code,
                    "message": d.message,
                })
            })
            .collect();
        let mut message = e.reason().to_string();
        if !skipped.is_empty() {
            message.push_str(&format!(
                "; {} manifest(s) in the plugin directories were skipped because they are invalid (see `sentra plugin list`)",
                skipped.len()
            ));
        }
        detailed_error(
            e.code(),
            7,
            json,
            &message,
            serde_json::json!({ "reason": e.reason(), "skipped_manifests": skipped }),
        )
    })
}

/// Run an invocation against standard in-memory buffer handling.
pub fn run(arguments: &[OsString], cwd: &Path) -> Response {
    let mut stdin_empty = std::io::empty();
    run_with_input(arguments, cwd, &mut stdin_empty)
}

/// Run an invocation reading any required interactive data from the provided input stream.
pub fn run_with_input(arguments: &[OsString], cwd: &Path, input: &mut impl BufRead) -> Response {
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let exit_code = run_stream(arguments, cwd, input, &mut stdout_buf, &mut stderr_buf);
    Response {
        stdout: String::from_utf8(stdout_buf).unwrap_or_default(),
        stderr: String::from_utf8(stderr_buf).unwrap_or_default(),
        exit_code,
    }
}

/// Streaming execution router supporting interactive stdio MCP servers and line-buffered outputs.
pub fn run_stream<R, W, E>(
    arguments: &[OsString],
    cwd: &Path,
    input: &mut R,
    output: &mut W,
    err_output: &mut E,
) -> u8
where
    R: BufRead,
    W: Write,
    E: Write,
{
    let invocation = match parse(arguments) {
        Ok(value) => value,
        Err(_) => {
            let resp = error(
                "invalid_arguments",
                2,
                arguments.iter().any(|s| s == "--json"),
            );
            let _ = err_output.write_all(resp.stderr.as_bytes());
            return resp.exit_code;
        }
    };

    if let Command::Mcp {
        workspace,
        database,
    } = &invocation.command
    {
        // stdout carries only JSON-RPC lines; startup errors go to stderr.
        let mut server = McpServer::new(SessionId::new());
        let launch_root = absolute(workspace.as_deref().unwrap_or(cwd), cwd);
        if workspace.is_some() && !launch_root.is_dir() {
            let resp = error("invalid_workspace", 4, invocation.json);
            let _ = err_output.write_all(resp.stderr.as_bytes());
            return resp.exit_code;
        }
        if !launch_root.as_os_str().is_empty() {
            server = server.with_launch_root(launch_root);
        }
        if let Some(db) = database {
            server = server.with_database(absolute(db, cwd));
        }
        // Lines are read with a streaming byte quota; oversized lines and invalid
        // UTF-8 are answered with JSON-RPC errors and the server keeps serving.
        // Only stdin/stdout I/O failures end the loop with exit 8.
        return match run_stdio(&mut server, input, output, DEFAULT_MAX_LINE_BYTES) {
            Ok(()) => 0,
            Err(_) => 8,
        };
    }

    if let Command::Scan {
        stdin: true,
        file_name,
        sarif,
        ..
    } = &invocation.command
    {
        let mut stdin_content = String::new();
        if input.read_to_string(&mut stdin_content).is_err() {
            return 8;
        }
        let response = execute_scan_snippet(
            &stdin_content,
            file_name.as_deref(),
            sarif.as_deref(),
            cwd,
            invocation.json,
        );
        if !response.stdout.is_empty()
            && (output.write_all(response.stdout.as_bytes()).is_err() || output.flush().is_err())
        {
            return 8;
        }
        if !response.stderr.is_empty()
            && (err_output.write_all(response.stderr.as_bytes()).is_err()
                || err_output.flush().is_err())
        {
            return 8;
        }
        return response.exit_code;
    }

    let response = execute_invocation(invocation, cwd);
    if !response.stdout.is_empty()
        && (output.write_all(response.stdout.as_bytes()).is_err() || output.flush().is_err())
    {
        return 8;
    }
    if !response.stderr.is_empty()
        && (err_output.write_all(response.stderr.as_bytes()).is_err()
            || err_output.flush().is_err())
    {
        return 8;
    }
    response.exit_code
}

fn execute_invocation(invocation: Invocation, cwd: &Path) -> Response {
    let json = invocation.json;
    match invocation.command {
        Command::Help => Response {
            stdout: if json {
                json_text(&serde_json::json!({
                    "schema_version": 1,
                    "commands": [
                        "init", "status", "session show", "recover", "audit", "inventory",
                        "scan", "patch", "install", "skills", "prompt", "tenant", "config",
                        "fleet", "plugin", "sync-advisories", "propose-pr", "codeql",
                        "codeql analyze", "codeql import", "diff",
                        "verify-audit", "export sarif", "mcp",
                    ],
                    "mcp_protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
                    "mcp_latest_protocol_version": LATEST_PROTOCOL_VERSION,
                    "skill_targets": AgentTarget::CONCRETE.map(|t| t.as_str()),
                    "mcp_targets": McpTarget::ALL.map(McpTarget::as_str),
                    "offline": true,
                    "untrusted_execution": false,
                }))
            } else {
                HELP.into()
            },
            stderr: String::new(),
            exit_code: 0,
        },
        Command::Version => Response {
            stdout: if json {
                format!(
                    "{{\"schema_version\":1,\"version\":\"{}\"}}\n",
                    env!("CARGO_PKG_VERSION")
                )
            } else {
                format!("sentra {}\n", env!("CARGO_PKG_VERSION"))
            },
            stderr: String::new(),
            exit_code: 0,
        },
        Command::Init {
            workspace,
            database,
        } => {
            let res =
                LocalWorkspace::initialize(&absolute(&workspace, cwd), &absolute(&database, cwd));
            match res {
                Ok(report) => render("init", report, json),
                Err(source) => core_error(source, json),
            }
        }
        Command::Status {
            workspace,
            database,
        } => {
            let res = LocalWorkspace::status(
                &absolute(workspace.as_deref().unwrap_or(cwd), cwd),
                &absolute(&database, cwd),
            );
            match res {
                Ok(report) => render("status", report, json),
                Err(source) => core_error(source, json),
            }
        }
        Command::Session {
            id,
            workspace,
            database,
        } => {
            let res = LocalWorkspace::session(
                &absolute(workspace.as_deref().unwrap_or(cwd), cwd),
                &absolute(&database, cwd),
                id,
            );
            match res {
                Ok(report) => render("session", report, json),
                Err(source) => core_error(source, json),
            }
        }
        Command::Recover {
            workspace,
            database,
        } => {
            let res = LocalWorkspace::recover(
                &absolute(workspace.as_deref().unwrap_or(cwd), cwd),
                &absolute(&database, cwd),
            );
            match res {
                Ok(report) => render("recover", report, json),
                Err(source) => core_error(source, json),
            }
        }
        Command::Audit {
            workspace,
            database,
        } => {
            let advisory_db = AdvisoryDatabase::default_pinned();
            let ws_path = absolute(workspace.as_deref().unwrap_or(cwd), cwd);
            let db_path = absolute(&database, cwd);
            match LocalWorkspace::audit_dependencies(&ws_path, &db_path, &advisory_db) {
                Ok(report) => render_audit(report, &advisory_db, json),
                Err(source) => core_error(source, json),
            }
        }
        Command::Inventory {
            workspace,
            max_depth,
        } => {
            let ws_path = absolute(workspace.as_deref().unwrap_or(cwd), cwd);
            match LocalWorkspace::inventory(&ws_path, max_depth) {
                Ok(report) => render_inventory(&report, json),
                Err(source) => core_error(source, json),
            }
        }
        Command::Scan {
            workspace,
            snippet,
            stdin,
            file_name,
            database,
            sarif,
        } => {
            if stdin {
                return error("stdin_scan_requires_input_stream", 2, json);
            }
            if let Some(code) = snippet {
                return execute_scan_snippet(
                    &code,
                    file_name.as_deref(),
                    sarif.as_deref(),
                    cwd,
                    json,
                );
            }
            let ws = match workspace {
                Some(w) => w,
                None => return error("invalid_arguments", 2, json),
            };
            let ws_path = absolute(&ws, cwd);
            if let Some(sarif_out) = sarif {
                let db_path_opt = database.as_ref().map(|d| absolute(d, cwd));
                match LocalWorkspace::export_scan_sarif(&ws_path, db_path_opt.as_deref()) {
                    Ok(sarif_json) => {
                        let out_path = absolute(&sarif_out, cwd);
                        match std::fs::write(&out_path, sarif_json.as_bytes()) {
                            Ok(_) => {
                                let stdout = if json {
                                    "{\"schema_version\":1,\"command\":\"scan\",\"status\":\"success\",\"sarif_written\":true,\"untrusted_execution\":false}\n".to_string()
                                } else {
                                    "Sentra SAST scan: SARIF export written successfully\nUntrusted execution: disabled\n".to_string()
                                };
                                Response {
                                    stdout,
                                    stderr: String::new(),
                                    exit_code: 0,
                                }
                            }
                            Err(_) => error("io_error", 5, json),
                        }
                    }
                    Err(source) => core_error(source, json),
                }
            } else if let Some(db) = database {
                let db_path = absolute(&db, cwd);
                match LocalWorkspace::scan_source(&ws_path, &db_path) {
                    Ok(report) => render_scan(&report.sast_report, json),
                    Err(source) => core_error(source, json),
                }
            } else {
                match LocalWorkspace::scan_source_direct(&ws_path) {
                    Ok(report) => render_scan(&report, json),
                    Err(source) => core_error(source, json),
                }
            }
        }
        Command::SyncAdvisories { source, database } => {
            if database.is_some() {
                return not_implemented(
                    "sync-advisories",
                    "sync-advisories cannot persist advisories: the store has no advisory table, so --database is not supported. Without --database it only checks that local OSV JSON parses; audit, propose-pr and export sarif always use the bundled pinned advisory sample.",
                    json,
                );
            }
            let src_path = absolute(&source, cwd);
            // Parsed into a throwaway in-memory database: nothing reads it afterwards.
            let mut db = AdvisoryDatabase::empty(TimestampUtc::now());
            let parsed = if src_path.is_dir() {
                ingest_osv_directory_report(&mut db, &src_path).map(|report| (true, report))
            } else {
                match std::fs::read_to_string(&src_path) {
                    Ok(content) => db.ingest_osv_payload(&content).map(|entries| {
                        let report = OsvDirectoryIngest {
                            advisory_entries: entries,
                            files_parsed: 1,
                            files_skipped: 0,
                        };
                        (false, report)
                    }),
                    Err(_) => return error("io_error", 5, json),
                }
            };
            match parsed {
                Ok((directory, report)) => render_sync_advisories(directory, &report, json),
                Err(_) => error("invalid_advisory_feed", 4, json),
            }
        }
        Command::ProposePr {
            workspace,
            database,
            output,
        } => {
            let ws_path = absolute(workspace.as_deref().unwrap_or(cwd), cwd);
            let db_path = absolute(&database, cwd);
            let advisory_db = AdvisoryDatabase::default_pinned();
            let advisory_source = pinned_advisory_source(&advisory_db);
            match LocalWorkspace::propose_remediations(
                &ws_path,
                &db_path,
                &advisory_db,
                &advisory_source,
            ) {
                Ok(proposals) => {
                    if let Some(out_file) = output {
                        let out_path = absolute(&out_file, cwd);
                        let rendered_text = if json {
                            serde_json::to_string_pretty(&proposals).unwrap_or_default()
                        } else {
                            proposals
                                .iter()
                                .map(|p| p.body_markdown.as_str())
                                .collect::<Vec<_>>()
                                .join("\n\n---\n\n")
                        };
                        match std::fs::write(&out_path, rendered_text.as_bytes()) {
                            Ok(_) => {
                                let stdout = if json {
                                    json_text(&serde_json::json!({
                                        "schema_version": 1,
                                        "command": "propose-pr",
                                        "status": "success",
                                        "count": proposals.len(),
                                        "written": true,
                                        "local_preview_only": true,
                                        "pull_requests_created": false,
                                        "advisory_db_source": ADVISORY_DB_SOURCE,
                                        "advisory_db_records": advisory_db.advisory_count(),
                                    }))
                                } else {
                                    format!(
                                        "Sentra remediation previews: {} written to {}\nLocal preview only: no branch, commit or pull request was created\nAdvisory database: bundled pinned sample ({} records); not a synchronized OSV or RustSec feed\n",
                                        proposals.len(),
                                        out_path.display(),
                                        advisory_db.advisory_count(),
                                    )
                                };
                                Response {
                                    stdout,
                                    stderr: String::new(),
                                    exit_code: 0,
                                }
                            }
                            Err(_) => error("io_error", 5, json),
                        }
                    } else {
                        render_propose_pr(&proposals, &advisory_db, json)
                    }
                }
                Err(source) => core_error(source, json),
            }
        }
        Command::Codeql {
            workspace,
            sarif,
            database,
        } => {
            if let Some(sarif_file) = sarif {
                let sarif_path = absolute(&sarif_file, cwd);
                let ws_path = workspace.map(|w| absolute(&w, cwd));
                let db_path = database.map(|d| absolute(&d, cwd));
                match LocalWorkspace::ingest_codeql_sarif(
                    ws_path.as_deref(),
                    db_path.as_deref(),
                    &sarif_path,
                ) {
                    Ok(result) => render_codeql_ingest(&result, json),
                    Err(source) => core_error(source, json),
                }
            } else if let Some(ws) = workspace {
                let ws_path = absolute(&ws, cwd);
                match LocalWorkspace::probe_codeql(&ws_path) {
                    Ok(probe) => render_codeql_probe(&probe, json),
                    Err(source) => core_error(source, json),
                }
            } else {
                error("invalid_arguments", 2, json)
            }
        }
        Command::CodeqlAnalyze(args) => {
            let request = CodeQlAnalyzeRequest {
                workspace: absolute(&args.workspace, cwd),
                codeql: absolute(&args.codeql, cwd),
                work_dir: absolute(&args.work_dir, cwd),
                pack_cache: absolute(&args.pack_cache, cwd),
                terms_accepted: args.accept_terms,
                languages: args.languages,
                suite: args.suite,
                threads: args.threads,
                ram_mb: args.ram_mb,
                timeout: Duration::from_secs(args.timeout_secs),
                allow_pack_download: args.allow_pack_download,
                max_results: args.max_results,
                cancel: args.cancel_on_stdin_eof.then(cancel_when_stdin_closes),
            };
            match analyze_workspace_with_codeql(&request) {
                Ok(report) => render_codeql_report(&report, json),
                Err(err) => codeql_host_error(&err, json),
            }
        }
        Command::CodeqlImport {
            sarif,
            workspace,
            max_results,
        } => {
            let ws_path = absolute(&workspace, cwd);
            let Some(ws_path) = std::fs::canonicalize(&ws_path).ok().filter(|w| w.is_dir()) else {
                return detailed_error(
                    "invalid_workspace",
                    4,
                    json,
                    "the workspace is not an accessible directory",
                    serde_json::json!({}),
                );
            };
            match import_codeql_sarif(&absolute(&sarif, cwd), &ws_path, max_results) {
                Ok(report) => render_codeql_report(&report, json),
                Err(err) => codeql_sarif_error(&err, json),
            }
        }
        Command::Diff { base, head } => {
            let base_path = absolute(&base, cwd);
            let head_path = absolute(&head, cwd);
            match LocalWorkspace::diff(&base_path, &head_path) {
                Ok(diff) => render_diff(&diff, json),
                Err(source) => core_error(source, json),
            }
        }
        // There is nothing real to assess: the worker registry is empty and no secret-
        // inheritance or audit-trail tamper-evidence check exists. Earlier builds assessed a
        // built-in fixture worker with gates hard-coded to pass and reported `approved`.
        Command::VerifyAudit => not_implemented(
            "verify-audit",
            "verify-audit is not implemented: there is no worker registry to assess, and no secret-inheritance or audit-trail tamper-evidence check exists, so no multi-user hosting gate can be evaluated.",
            json,
        ),
        Command::ExportSarif {
            workspace,
            database,
            output,
        } => {
            let advisory_db = AdvisoryDatabase::default_pinned();
            let ws_path = absolute(workspace.as_deref().unwrap_or(cwd), cwd);
            let db_path = absolute(&database, cwd);
            match LocalWorkspace::export_audit_sarif(&ws_path, &db_path, &advisory_db) {
                Ok(sarif_json) => {
                    if let Some(out_file) = output {
                        let out_path = absolute(&out_file, cwd);
                        match std::fs::write(&out_path, sarif_json.as_bytes()) {
                            Ok(_) => {
                                let stdout = if json {
                                    "{\"schema_version\":1,\"command\":\"export sarif\",\"status\":\"success\",\"written\":true,\"untrusted_execution\":false}\n".to_string()
                                } else {
                                    "Sentra SARIF export: successfully written\nUntrusted execution: disabled\n".to_string()
                                };
                                Response {
                                    stdout,
                                    stderr: String::new(),
                                    exit_code: 0,
                                }
                            }
                            Err(_) => error("io_error", 5, json),
                        }
                    } else {
                        let stdout = if sarif_json.ends_with('\n') {
                            sarif_json
                        } else {
                            format!("{sarif_json}\n")
                        };
                        Response {
                            stdout,
                            stderr: String::new(),
                            exit_code: 0,
                        }
                    }
                }
                Err(source) => core_error(source, json),
            }
        }
        Command::Patch { action } => match action {
            PatchAction::Apply {
                patch,
                workspace,
                target,
                backup_dir,
                database,
                dry_run,
            } => {
                let ws_path = absolute(&workspace, cwd);
                let patch_path = absolute(&patch, cwd);
                let target_path = target.as_ref().map(|t| {
                    if t.is_absolute() {
                        t.strip_prefix(&ws_path).unwrap_or(t).to_path_buf()
                    } else {
                        t.clone()
                    }
                });
                let backup_path = backup_dir.as_ref().map(|b| absolute(b, cwd));
                let db_path = database.as_ref().map(|d| absolute(d, cwd));
                match LocalWorkspace::apply_patch(
                    &ws_path,
                    &patch_path,
                    target_path.as_deref(),
                    backup_path.as_deref(),
                    db_path.as_deref(),
                    dry_run,
                ) {
                    Ok(report) => render_patch_apply(&report, json),
                    Err(source) => core_error(source, json),
                }
            }
            PatchAction::Rollback {
                backup,
                workspace,
                target,
                database,
            } => {
                let ws_path = absolute(&workspace, cwd);
                let backup_path = absolute(&backup, cwd);
                let target_path = if target.is_absolute() {
                    target
                        .strip_prefix(&ws_path)
                        .unwrap_or(&target)
                        .to_path_buf()
                } else {
                    target.clone()
                };
                let db_path = database.as_ref().map(|d| absolute(d, cwd));
                match LocalWorkspace::rollback_patch(
                    &ws_path,
                    &backup_path,
                    &target_path,
                    db_path.as_deref(),
                ) {
                    Ok(report) => render_patch_rollback(&report, json),
                    Err(source) => core_error(source, json),
                }
            }
        },
        Command::Tenant { action, database } => {
            let db_path = absolute(&database, cwd);
            match action {
                TenantAction::List => match LocalWorkspace::list_tenants(&db_path) {
                    Ok(tenants) => render_tenant_list(&tenants, json),
                    Err(source) => core_error(source, json),
                },
                TenantAction::Add {
                    id,
                    name,
                    description,
                    default_workspace,
                    isolation_level,
                } => match LocalWorkspace::add_tenant(
                    &db_path,
                    &id,
                    &name,
                    description.as_deref(),
                    default_workspace.as_deref(),
                    isolation_level.as_deref(),
                ) {
                    Ok(tenant) => render_tenant_add(&tenant, json),
                    Err(source) => core_error(source, json),
                },
            }
        }
        Command::Config { action, database } => match action {
            ConfigAction::Show { key } => {
                let db_path = absolute(
                    &database.unwrap_or_else(|| PathBuf::from("data/sentra.db")),
                    cwd,
                );
                match LocalWorkspace::get_config(&db_path, key.as_deref()) {
                    Ok(settings) => render_config_show(&settings, json),
                    Err(source) => core_error(source, json),
                }
            }
            ConfigAction::Set { key, value } => {
                let db_path = absolute(
                    &database.unwrap_or_else(|| PathBuf::from("data/sentra.db")),
                    cwd,
                );
                match LocalWorkspace::set_config(&db_path, &key, &value) {
                    Ok(_) => render_config_set(&key, &value, json),
                    Err(source) => core_error(source, json),
                }
            }
            // No provider client exists in the core CLI. Earlier builds printed a fixed
            // `connected` result (HTTP 200, 23 ms) without contacting anything.
            ConfigAction::Test { .. } => not_implemented(
                "config test",
                "config test is not implemented: the core CLI has no model-provider client, so no provider connection, API key or model can be checked.",
                json,
            ),
        },
        Command::Fleet { action } => {
            let fleet = LocalWorkspace::fleet_manager();
            match action {
                FleetAction::List => render_fleet_list(&fleet, json),
                FleetAction::Status => render_fleet_status(&fleet, json),
            }
        }
        Command::Plugin { action } => match action {
            PluginAction::List { directory } => {
                let dirs = match plugin_dirs(cwd, directory.as_deref(), json) {
                    Ok(dirs) => dirs,
                    Err(response) => return response,
                };
                let mut discovery = scan_plugin_dirs(&dirs);
                if directory.is_none()
                    && let Some(ignored) = plugin_dir_env_diagnostic()
                {
                    discovery.diagnostics.insert(0, ignored);
                }
                render_plugin_list(&dirs, &discovery.plugins, &discovery.diagnostics, json)
            }
            PluginAction::Probe {
                id,
                manifest,
                directory,
                workspace,
            } => {
                let plugin = match select_plugin(id, manifest, directory.as_deref(), cwd, json) {
                    Ok(plugin) => plugin,
                    Err(response) => return response,
                };
                let ws_path = absolute(workspace.as_deref().unwrap_or(cwd), cwd);
                let mut driver = match PluginDriver::new(plugin) {
                    Ok(d) => d,
                    Err(e) => return plugin_error(&e, None, json),
                };
                match driver.probe(&ws_path) {
                    Ok(report) => render_plugin_probe(&report, json),
                    Err(e) => plugin_error(&e, driver.last_session(), json),
                }
            }
            PluginAction::Run {
                id,
                manifest,
                directory,
                capability,
                arguments,
                workspace,
            } => {
                let plugin = match select_plugin(id, manifest, directory.as_deref(), cwd, json) {
                    Ok(plugin) => plugin,
                    Err(response) => return response,
                };

                let cap = match capability.parse::<PluginCapability>() {
                    Ok(c) => c,
                    Err(_) => return error("invalid_capability", 2, json),
                };

                let args: serde_json::Value = if let Some(raw_args) = arguments {
                    match serde_json::from_str(&raw_args) {
                        Ok(val) => val,
                        Err(_) => return error("invalid_arguments_json", 2, json),
                    }
                } else {
                    serde_json::json!({})
                };

                let ws_path = absolute(workspace.as_deref().unwrap_or(cwd), cwd);
                let mut driver = match PluginDriver::new(plugin) {
                    Ok(d) => d,
                    Err(e) => return plugin_error(&e, None, json),
                };

                let task_id = format!("task-{}", SessionId::new());
                match driver.execute_in_workspace(&ws_path, &task_id, cap, args) {
                    Ok(report) => render_plugin_run(&report, driver.last_session(), json),
                    Err(e) => plugin_error(&e, driver.last_session(), json),
                }
            }
        },
        Command::Install {
            target,
            global,
            mcp,
            skill,
            workspace,
            command,
        } => {
            if mcp && skill.is_some() {
                return detailed_error(
                    "invalid_arguments",
                    2,
                    json,
                    "--skill cannot be combined with --mcp; run the skill install and the MCP registration separately",
                    serde_json::json!({ "command": "install" }),
                );
            }
            let ws_path = absolute(workspace.as_deref().unwrap_or(cwd), cwd);
            if mcp {
                execute_mcp_install(&target, global, ws_path, command.as_deref(), cwd, json)
            } else {
                execute_skill_install(&target, global, &ws_path, skill.as_deref(), json)
            }
        }
        Command::Skills { action } => match action {
            SkillsAction::List => {
                let skills = sentra_core::skills::list_builtin_skills();
                render_skills_list(skills, json)
            }
            SkillsAction::Show { id } => match sentra_core::skills::find_skill_by_id(&id) {
                Some(skill) => render_skill_show(skill, json),
                None => detailed_error(
                    "skill_not_found",
                    7,
                    json,
                    "no bundled skill has this id; run `sentra skills list`",
                    serde_json::json!({ "command": "skills show" }),
                ),
            },
        },
        Command::Prompt {
            workflow,
            scope,
            skills,
        } => render_prompt(
            &workflow,
            scope.as_deref().unwrap_or("workspace"),
            skills.as_deref(),
            json,
        ),
        Command::Mcp { .. } => unreachable!("handled in run_stream"),
    }
}

fn render_diff(diff: &SnapshotDiff, json: bool) -> Response {
    let stdout = if json {
        let summary_json = serde_json::to_string(&diff.summary).unwrap_or_default();
        let deltas_json = serde_json::to_string(&diff.deltas).unwrap_or_default();
        format!(
            "{{\"schema_version\":1,\"command\":\"diff\",\"base_aggregate_digest\":\"{}\",\"head_aggregate_digest\":\"{}\",\"summary\":{},\"deltas\":{},\"untrusted_execution\":false}}\n",
            diff.base_aggregate_digest, diff.head_aggregate_digest, summary_json, deltas_json,
        )
    } else {
        let mut text = format!(
            "Sentra snapshot diff: completed\nBase digest: {}\nHead digest: {}\nFiles added: {}\nFiles modified: {}\nFiles deleted: {}\nFiles renamed: {}\nFiles unchanged: {}\nRust files changed: {}\nNet bytes delta: {}\n",
            diff.base_aggregate_digest,
            diff.head_aggregate_digest,
            diff.summary.added_files,
            diff.summary.modified_files,
            diff.summary.deleted_files,
            diff.summary.renamed_files,
            diff.summary.unchanged_files,
            diff.summary.rust_files_changed,
            diff.summary.net_bytes_delta,
        );
        for delta in diff.changed_deltas() {
            match &delta.kind {
                FileDeltaKind::Renamed { from_path } => {
                    text.push_str(&format!(
                        "  [renamed] {} (from {})\n",
                        delta.path, from_path
                    ));
                }
                _ => {
                    text.push_str(&format!("  [{}] {}\n", delta.kind.as_str(), delta.path));
                }
            }
        }
        text.push_str("Untrusted execution: disabled\n");
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn scope_label(global: bool) -> &'static str {
    if global {
        "global (user-wide)"
    } else {
        "workspace (project)"
    }
}

/// `all` / `*` expand to every target; everything else names one target.
fn is_all_target(target: &str) -> bool {
    let target = target.trim();
    target == "*" || target.eq_ignore_ascii_case("all")
}

/// Merges `extra` into a JSON object without overriding existing keys.
fn merge_json(mut base: serde_json::Value, extra: serde_json::Value) -> serde_json::Value {
    if let (Some(object), serde_json::Value::Object(extra)) = (base.as_object_mut(), extra) {
        for (key, value) in extra {
            object.entry(key).or_insert(value);
        }
    }
    base
}

fn execute_skill_install(
    target: &str,
    global: bool,
    ws_path: &Path,
    skill: Option<&str>,
    json: bool,
) -> Response {
    let Some(agent_target) = AgentTarget::parse(target) else {
        return detailed_error(
            "invalid_target",
            2,
            json,
            "unknown skill target; run `sentra --help` for the list of targets",
            serde_json::json!({
                "command": "install",
                "targets": AgentTarget::CONCRETE.map(|t| t.as_str()),
            }),
        );
    };
    // Every id is resolved before anything is written.
    let result = match skill {
        Some(ids) => {
            sentra_core::skills::install_selected_skills(&[ids], agent_target, global, ws_path)
        }
        None => sentra_core::skills::install_all_skills(agent_target, global, ws_path),
    };
    match result {
        Ok(report) => render_install(&report, json),
        Err(err) => install_error(&err, json),
    }
}

/// Skill installation failure. JSON mode prints the core error body on stderr.
/// A required manual config edit (Aider) still prints the install summary on
/// stdout, because the skills themselves were installed.
fn install_error(err: &InstallError, json: bool) -> Response {
    let exit_code = exit_status(err.exit_code());
    if json {
        return Response {
            stdout: String::new(),
            stderr: json_text(&err.to_json()),
            exit_code,
        };
    }
    let mut stderr = format!("error: {}\n{err}\n", err.code());
    let stdout = match err {
        InstallError::ManualStepRequired { report, .. } => {
            render_install_text(report, "incomplete (manual config edit required)")
        }
        InstallError::SkillNotFound { .. } => {
            stderr.push_str("Run `sentra skills list` for the bundled skill ids.\n");
            String::new()
        }
        _ => String::new(),
    };
    Response {
        stdout,
        stderr,
        exit_code,
    }
}

fn render_install(report: &InstallReport, json: bool) -> Response {
    let stdout = if json {
        json_text(&report.to_json())
    } else {
        render_install_text(report, "success")
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_install_text(report: &InstallReport, status: &str) -> String {
    let mut text = format!(
        "Sentra AppSec skill installation: {status}\nTarget: {}\nScope: {}\nDestination: {}\nInstalled skills: {} ({} files)\n",
        report.target.as_str(),
        scope_label(report.is_global),
        display_path(&report.destination_dir),
        report.skills.len(),
        report.installed_files.len(),
    );
    for file in report.written_files() {
        text.push_str(&format!(
            "  [{}] {}",
            file.status.as_str(),
            display_path(&file.path)
        ));
        if let Some(backup) = &file.backup {
            text.push_str(&format!(" (backup: {})", display_path(backup)));
        }
        text.push('\n');
    }
    let unchanged = report
        .files
        .iter()
        .filter(|file| file.status == FileStatus::Unchanged)
        .count();
    if unchanged > 0 {
        text.push_str(&format!("Unchanged files: {unchanged}\n"));
    }
    for outcome in &report.targets {
        if let Some(reason) = &outcome.skipped {
            text.push_str(&format!(
                "  [skipped] {}: {reason}\n",
                outcome.target.as_str()
            ));
        }
    }
    for item in &report.legacy {
        text.push_str(&format!(
            "  [{}] {} (skill {})",
            item.action.as_str(),
            display_path(&item.path),
            item.skill_id
        ));
        if let Some(backup) = &item.backup {
            text.push_str(&format!(" (backup: {})", display_path(backup)));
        }
        if item.action.needs_manual_review() {
            text.push_str(" - edited by hand; review and remove it manually");
        }
        text.push('\n');
    }
    for note in &report.notes {
        text.push_str(&format!("Note: {note}\n"));
    }
    text
}

/// The executable to register: bare names stay as given (resolved by the agent's
/// PATH lookup); paths are made absolute against the invocation directory.
fn registered_command(command: &Path, cwd: &Path) -> PathBuf {
    let bare = command.components().count() == 1 && !command.is_absolute();
    if bare {
        command.to_path_buf()
    } else {
        absolute(command, cwd)
    }
}

fn execute_mcp_install(
    target: &str,
    global: bool,
    ws_path: PathBuf,
    command: Option<&Path>,
    cwd: &Path,
    json: bool,
) -> Response {
    let single = if is_all_target(target) {
        None
    } else {
        match McpTarget::parse(target) {
            Some(target) => Some(target),
            None => {
                return detailed_error(
                    "invalid_target",
                    2,
                    json,
                    "unknown MCP target; run `sentra --help` for the list of targets",
                    serde_json::json!({
                        "command": "install",
                        "mcp": true,
                        "targets": McpTarget::ALL.map(McpTarget::as_str),
                    }),
                );
            }
        }
    };
    let scope = McpScope::from_global(global);
    if scope == McpScope::Workspace && !ws_path.is_dir() {
        return detailed_error(
            "workspace_not_found",
            2,
            json,
            &format!(
                "workspace directory {} does not exist",
                display_path(&ws_path)
            ),
            serde_json::json!({ "command": "install", "mcp": true, "path": display_path(&ws_path) }),
        );
    }
    let command = command.map(|c| registered_command(c, cwd));
    // A path (not a bare name looked up on PATH) must name an existing file.
    if let Some(path) = command
        .as_deref()
        .filter(|p| p.components().count() > 1 && !p.is_file())
    {
        return detailed_error(
            "mcp_command_not_found",
            2,
            json,
            &format!("--command {} is not an existing file", display_path(path)),
            serde_json::json!({ "command": "install", "mcp": true, "path": display_path(path) }),
        );
    }
    let mut options = McpInstallOptions::new(scope, ws_path);
    options.command = command;
    match single {
        Some(target) => match sentra_core::skills::install_mcp_server(target, &options) {
            Ok(report) => render_mcp_install(&report, json),
            Err(err) => mcp_install_error(target, &err, json),
        },
        None => render_mcp_batch(&sentra_core::skills::install_mcp_server_all(&options), json),
    }
}

fn mcp_action_label(action: McpFileAction) -> &'static str {
    match action {
        McpFileAction::Created => "created",
        McpFileAction::Updated => "updated",
        McpFileAction::Unchanged => "unchanged",
    }
}

/// `[action] path (backup: ...)` lines for every file of one target.
fn mcp_file_lines(report: &McpInstallReport, indent: &str) -> String {
    let mut text = String::new();
    for file in &report.files {
        text.push_str(&format!(
            "{indent}[{}] {}",
            mcp_action_label(file.action),
            display_path(&file.path)
        ));
        if let Some(backup) = &file.backup_file {
            text.push_str(&format!(" (backup: {})", display_path(backup)));
        }
        text.push('\n');
    }
    text
}

fn render_mcp_install(report: &McpInstallReport, json: bool) -> Response {
    let stdout = if json {
        // `command` names the CLI command in every envelope, so the registered
        // executable is reported as `server_command`.
        let mut body = serde_json::to_value(report).unwrap_or_default();
        if let Some(object) = body.as_object_mut()
            && let Some(executable) = object.remove("command")
        {
            object.insert("server_command".into(), executable);
        }
        let envelope = serde_json::json!({
            "schema_version": 1,
            "command": "install",
            "mcp": true,
        });
        json_text(&merge_json(envelope, body))
    } else {
        let mut text = format!(
            "Sentra MCP server registration: {}\nTarget: {}\nScope: {}\nServer: \"{}\" -> {} {}\nFiles:\n",
            mcp_action_label(report.action),
            report.target,
            scope_label(report.is_global),
            report.server_name,
            report.command,
            report.args.join(" "),
        );
        text.push_str(&mcp_file_lines(report, "  "));
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

/// Human-readable manual step: what to do, which file, and the exact snippet.
fn manual_step_text(err: &McpInstallError) -> String {
    match err.manual_step() {
        Some(step) => format!(
            "Manual step: {}\nFile: {}\n----- snippet -----\n{}{}----- end snippet -----\n",
            step.instructions,
            display_path(&step.path),
            step.snippet,
            if step.snippet.ends_with('\n') {
                ""
            } else {
                "\n"
            },
        ),
        None => String::new(),
    }
}

fn mcp_install_error(target: McpTarget, err: &McpInstallError, json: bool) -> Response {
    let stderr = if json {
        let envelope = serde_json::json!({
            "schema_version": 1,
            "command": "install",
            "mcp": true,
            "target": target.as_str(),
            "error": err.code(),
        });
        json_text(&merge_json(envelope, err.to_json()))
    } else {
        format!("error: {}: {err}\n{}", err.code(), manual_step_text(err))
    };
    Response {
        stdout: String::new(),
        stderr,
        exit_code: err.exit_code(),
    }
}

/// `install mcp all`: installed, skipped (target or scope without file-based MCP)
/// and failed targets. The report goes to stdout; failures exit non-zero with the
/// first failure's exit code, and their manual steps go to stderr in text mode.
fn render_mcp_batch(batch: &McpBatchReport, json: bool) -> Response {
    let exit_code = batch
        .failed
        .first()
        .map_or(0, |issue| issue.error.exit_code());
    if json {
        let envelope = serde_json::json!({
            "schema_version": 1,
            "command": "install",
            "mcp": true,
            "target": "all",
            "success": batch.is_success(),
        });
        return Response {
            stdout: json_text(&merge_json(
                envelope,
                serde_json::to_value(batch).unwrap_or_default(),
            )),
            stderr: String::new(),
            exit_code,
        };
    }
    let mut stdout = format!(
        "Sentra MCP server registration (all targets): {}\nScope: {}\nInstalled: {}  Skipped: {}  Failed: {}\n",
        if batch.is_success() {
            "success"
        } else {
            "failed for some targets"
        },
        scope_label(batch.scope == McpScope::Global),
        batch.installed.len(),
        batch.skipped.len(),
        batch.failed.len(),
    );
    for report in &batch.installed {
        stdout.push_str(&format!("  {}:\n", report.target));
        stdout.push_str(&mcp_file_lines(report, "    "));
    }
    for issue in &batch.skipped {
        stdout.push_str(&format!(
            "  [skipped] {}: {}\n",
            issue.target,
            issue.error.code()
        ));
    }
    let mut stderr = String::new();
    for issue in &batch.failed {
        stderr.push_str(&format!(
            "error: {}: {}: {}\n{}",
            issue.target,
            issue.error.code(),
            issue.error,
            manual_step_text(&issue.error)
        ));
    }
    Response {
        stdout,
        stderr,
        exit_code,
    }
}

fn render_skills_list(skills: &[sentra_core::skills::SkillDefinition], json: bool) -> Response {
    let stdout = if json {
        let items: Vec<serde_json::Value> = skills
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "name": s.name,
                    "category": s.category.as_str(),
                    "description": s.description,
                    "tags": s.tags,
                })
            })
            .collect();
        json_text(&serde_json::json!({
            "schema_version": 1,
            "command": "skills list",
            "count": items.len(),
            "skills": items,
        }))
    } else {
        let mut text = format!(
            "Sentra Built-in AppSec Skills ({} available):\n\n",
            skills.len()
        );
        for s in skills {
            text.push_str(&format!(
                "  • {:<32} [{}] - {}\n",
                s.id,
                s.category.as_str(),
                s.description
            ));
        }
        text.push_str("\nInstall skills into your AI assistant using: sentra install <target|all> [--skill <id>] [--global] (targets: sentra --help)\n");
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_skill_show(skill: &sentra_core::skills::SkillDefinition, json: bool) -> Response {
    let stdout = if json {
        json_text(&serde_json::json!({
            "schema_version": 1,
            "command": "skills show",
            "id": skill.id,
            "name": skill.name,
            "category": skill.category.as_str(),
            "description": skill.description,
            "tags": skill.tags,
            "files": skill.files().iter().map(|(path, _)| *path).collect::<Vec<_>>(),
            "content": skill.content,
        }))
    } else {
        format!("{}\n", skill.content)
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn prompt_skill_error(err: &SkillPromptError, json: bool) -> Response {
    let SkillPromptError::UnknownSkills { ids } = err;
    let available: Vec<&str> = sentra_core::skills::list_builtin_skills()
        .iter()
        .map(|skill| skill.id)
        .collect();
    let mut response = detailed_error(
        err.code(),
        exit_status(err.exit_code()),
        json,
        &err.to_string(),
        serde_json::json!({
            "command": "prompt",
            "unknown_skills": ids,
            "available_skills": available,
        }),
    );
    if !json {
        response
            .stderr
            .push_str("Run `sentra skills list` for the bundled skill ids.\n");
    }
    response
}

fn render_prompt(workflow: &str, scope: &str, skills: Option<&str>, json: bool) -> Response {
    let (name, role, prompt) = match workflow.to_ascii_lowercase().as_str() {
        "scout" | "recon" | "reconnaissance" => {
            let p = sentra_core::research::ScoutPromptBuilder::build_reconnaissance_prompt(
                scope,
                "General repository surface mapping and trust boundary analysis",
            );
            (
                "Surface Reconnaissance (Scout)",
                sentra_core::research::ResearchRole::Scout,
                p,
            )
        }
        "threat-model" | "threat-modeling" | "stride" => {
            let p =
                sentra_core::research::ThreatModelingPromptBuilder::build_stride_assessment_prompt(
                    ".",
                    scope,
                    "Web application with database, cache, and authentication services",
                );
            (
                "Threat Modeling (STRIDE)",
                sentra_core::research::ResearchRole::Scout,
                p,
            )
        }
        "api-bola" | "bola" | "idor" | "api" => {
            let p = sentra_core::research::ApiSecurityPromptBuilder::build_bola_audit_prompt(
                scope,
                "GET",
                "// Inspect route handler for tenant ID authorization filtering",
            );
            (
                "API BOLA/IDOR Analysis",
                sentra_core::research::ResearchRole::Analyst,
                p,
            )
        }
        "patch-remediation" | "patch" | "fix" => {
            let p =
                sentra_core::research::PatchSynthesisPromptBuilder::build_three_tier_patch_prompt(
                    "Autonomous Remediation",
                    "CWE-89",
                    scope,
                    "// Unvalidated input flows into query/execution sink",
                );
            (
                "Three-Tier Patch Synthesis (ADR-0004)",
                sentra_core::research::ResearchRole::PatchAuthor,
                p,
            )
        }
        "skill-audit" | "agent-safety" => {
            let p = sentra_core::research::AgentSkillAuditPromptBuilder::build_skill_safety_prompt(
                scope,
                "// Skill instruction payload to evaluate for prompt injection or data leakage",
            );
            (
                "Agent Skill Safety Audit",
                sentra_core::research::ResearchRole::Analyst,
                p,
            )
        }
        "verify" | "verification" | "verifier" => {
            let p =
                sentra_core::research::VerificationPromptBuilder::build_dual_state_verification_prompt(
                    scope,
                    "// Test harness proving exploitability on unpatched state",
                    "// Candidate unified git diff remediating root cause",
                    "// Sandbox execution log verifying baseline failure and patch success",
                );
            (
                "Independent Dual-State Verification",
                sentra_core::research::ResearchRole::IndependentVerifier,
                p,
            )
        }
        _ => {
            return detailed_error(
                "unknown_workflow",
                2,
                json,
                "unknown prompt workflow; expected scout, threat-model, api-bola, patch-remediation, skill-audit or verify",
                serde_json::json!({
                    "command": "prompt",
                    "workflows": ["scout", "threat-model", "api-bola", "patch-remediation", "skill-audit", "verify"],
                }),
            );
        }
    };

    let requested: Vec<&str> = skills
        .map(|s| s.split(',').map(str::trim).collect())
        .unwrap_or_default();
    // The playbooks are appended to the workflow's own prompt, so its grounding
    // rules and expected schema stay in force; ids are de-duplicated and unknown
    // ids are rejected instead of silently dropped.
    let (final_prompt, skill_ids) =
        match sentra_core::research::SkillPromptComposer::augment_prompt_with_ids(
            prompt, &requested,
        ) {
            Ok(value) => value,
            Err(err) => return prompt_skill_error(&err, json),
        };

    let stdout = if json {
        let val = serde_json::json!({
            "schema_version": 1,
            "command": "prompt",
            "workflow": workflow,
            "role": role.as_str(),
            "name": name,
            "scope": scope,
            "skills": skill_ids,
            "system_prompt": final_prompt.system_prompt,
            "user_prompt": final_prompt.user_prompt,
            "expected_schema": final_prompt.expected_schema,
            "composite_prompt": final_prompt.to_composite_prompt(),
        });
        format!(
            "{}\n",
            serde_json::to_string_pretty(&val).unwrap_or_default()
        )
    } else {
        let mut text = format!(
            "--- [Sentra Cognitive Prompt Contract: {}] ---\nRole: {}\nScope: {}\n",
            name,
            role.as_str(),
            scope
        );
        if !skill_ids.is_empty() {
            text.push_str(&format!(
                "Injected AppSec Skills: {}\n",
                skill_ids.join(", ")
            ));
        }
        text.push_str("\n--- [System Persona & Guidelines] ---\n");
        text.push_str(&final_prompt.system_prompt);
        text.push_str("\n\n--- [Task Instructions] ---\n");
        text.push_str(&final_prompt.user_prompt);
        if let Some(schema) = &final_prompt.expected_schema {
            text.push_str("\n\n--- [Expected Structured Schema] ---\n");
            text.push_str(schema);
        }
        text.push('\n');
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

/// Source label for the bundled advisory set: a small hand-written sample, not a feed.
const ADVISORY_DB_SOURCE: &str = "bundled_pinned_sample";

/// Human description of the bundled advisory set, quoted in remediation preview bodies.
fn pinned_advisory_source(advisory_db: &AdvisoryDatabase) -> String {
    format!(
        "Sentra's bundled pinned advisory sample ({} records, curated {}), not a synchronized OSV, RustSec or GHSA feed",
        advisory_db.advisory_count(),
        advisory_db.updated_at().to_rfc3339()
    )
}

/// `a, b` or `none`.
fn list_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn render_audit(report: LocalAuditReport, advisory_db: &AdvisoryDatabase, json: bool) -> Response {
    let advisory_db_updated_at = advisory_db.updated_at().to_rfc3339();
    let stdout = if json {
        let findings: Vec<serde_json::Value> = report
            .candidate_findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "id": f.id().to_string(),
                    "title": f.title(),
                    "severity": f.severity().as_str(),
                    "reachability": f.reachability().as_str(),
                    "status": f.status().as_str(),
                    "lockfile": f.location().map(|l| l.path.as_str()),
                })
            })
            .collect();
        json_text(&serde_json::json!({
            "schema_version": 1,
            "command": "audit",
            "session_id": report.session_id.to_string(),
            "task_id": report.task_id.to_string(),
            "packages_audited": report.audit_result.packages_audited,
            "vulnerable_packages": report.audit_result.vulnerable_packages,
            "is_stale": report.audit_result.is_stale,
            "advisory_db_source": ADVISORY_DB_SOURCE,
            "advisory_db_records": advisory_db.advisory_count(),
            "advisory_db_updated_at": advisory_db_updated_at,
            "lockfiles_audited": report.lockfiles,
            "lockfiles_unparsed": report.unparsed_lockfiles,
            "unknown_version_packages": report.audit_result.unknown_version_packages,
            "findings": findings,
            "untrusted_execution": false,
        }))
    } else {
        let mut text = format!(
            "Sentra dependency audit: completed\nSession: {}\nTask: {}\nLockfiles audited: {}\n",
            report.session_id,
            report.task_id,
            list_or_none(&report.lockfiles),
        );
        if !report.unparsed_lockfiles.is_empty() {
            text.push_str(&format!(
                "Lockfiles not parsed (their packages were not audited): {}\n",
                report.unparsed_lockfiles.join(", ")
            ));
        }
        text.push_str(&format!(
            "Packages audited: {}\nVulnerable packages: {}\nAdvisory database: bundled pinned sample ({} records, curated {}); not a synchronized OSV or RustSec feed\nAdvisory database stale: {}\n",
            report.audit_result.packages_audited,
            report.audit_result.vulnerable_packages,
            advisory_db.advisory_count(),
            advisory_db_updated_at,
            report.audit_result.is_stale
        ));
        for f in &report.candidate_findings {
            text.push_str(&format!(
                "\n[{}] {}\n  Lockfile: {}\n  Reachability: {}\n  Status: {}\n",
                f.severity().as_str(),
                f.title(),
                f.location().map_or("unknown", |l| l.path.as_str()),
                f.reachability().as_str(),
                f.status().as_str(),
            ));
        }
        text.push_str("Untrusted execution: disabled\n");
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_scan(report: &SastReport, json: bool) -> Response {
    let stdout = if json {
        let matches_json = serde_json::to_string(
            &report
                .matches
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "rule_id": m.rule.id,
                        "rule_name": m.rule.name,
                        "category": m.rule.category.as_str(),
                        "severity": m.rule.severity.as_str(),
                        "cwe": m.rule.cwe_id,
                        "file_path": m.file_path,
                        "line_number": m.line_number,
                        "snippet": m.snippet,
                        "rationale": m.rationale,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default();

        format!(
            "{{\"schema_version\":1,\"command\":\"scan\",\"files_scanned\":{},\"signals_found\":{},\"matches\":{},\"untrusted_execution\":false}}\n",
            report.files_scanned,
            report.matches.len(),
            matches_json,
        )
    } else {
        let mut text = format!(
            "Sentra SAST scan: completed\nFiles scanned: {}\nSignals found: {}\nUntrusted execution: disabled\n",
            report.files_scanned,
            report.matches.len()
        );
        for m in &report.matches {
            text.push_str(&format!(
                "  [{}] {:<8} {}:{} -> {}\n      CWE: {} | {}\n",
                m.rule.id,
                m.rule.severity.as_str(),
                m.file_path,
                m.line_number,
                m.snippet,
                m.rule.cwe_id,
                m.rule.name
            ));
        }
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_sync_advisories(directory: bool, report: &OsvDirectoryIngest, json: bool) -> Response {
    let source_kind = if directory { "directory" } else { "file" };
    let stdout = if json {
        json_text(&serde_json::json!({
            "schema_version": 1,
            "command": "sync-advisories",
            "source_kind": source_kind,
            "advisory_entries_parsed": report.advisory_entries,
            "files_parsed": report.files_parsed,
            "files_skipped": report.files_skipped,
            "persisted": false,
            "message": "Parsed in memory only; nothing was downloaded or stored. audit, propose-pr and export sarif use the bundled pinned advisory sample.",
            "untrusted_execution": false,
        }))
    } else {
        format!(
            "Sentra OSV advisory parse: completed; nothing was persisted\nSource: {}\nAdvisory entries parsed: {} (one per affected package)\nFiles parsed: {}\nFiles skipped (unreadable or invalid): {}\nPersisted: no (no advisory store exists; audit, propose-pr and export sarif use the bundled pinned advisory sample)\nUntrusted execution: disabled\n",
            if directory {
                "directory (top-level .json files)"
            } else {
                "file"
            },
            report.advisory_entries,
            report.files_parsed,
            report.files_skipped,
        )
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_propose_pr(
    proposals: &[RemediationPrPackage],
    advisory_db: &AdvisoryDatabase,
    json: bool,
) -> Response {
    let stdout = if json {
        json_text(&serde_json::json!({
            "schema_version": 1,
            "command": "propose-pr",
            "proposals_count": proposals.len(),
            "proposals": proposals,
            "is_draft_only": true,
            "local_preview_only": true,
            "pull_requests_created": false,
            "patch_diffs_illustrative": true,
            "advisory_db_source": ADVISORY_DB_SOURCE,
            "advisory_db_records": advisory_db.advisory_count(),
            "advisory_db_updated_at": advisory_db.updated_at().to_rfc3339(),
            "untrusted_execution": false,
        }))
    } else {
        let mut text = format!(
            "Sentra remediation PR previews: {}\nLocal preview only: no branch, commit or pull request was created, and the suggested commands were not run\nAdvisory database: bundled pinned sample ({} records, curated {}); not a synchronized OSV or RustSec feed\nPatch diffs: illustrative version bumps; they do not apply as-is\nUntrusted execution: disabled\n\n",
            proposals.len(),
            advisory_db.advisory_count(),
            advisory_db.updated_at().to_rfc3339(),
        );
        for (idx, p) in proposals.iter().enumerate() {
            text.push_str(&format!(
                "Preview #{}: [{}]\n  Target: {}\n  Suggested branch (not created): {}\n  Title:  {}\n  Suggested command (not run; it needs the branch on the remote and the preview body saved as {}.md, see body_markdown in the --json output):\n    {}\n\n",
                idx + 1,
                p.proposal_id,
                p.target_component,
                p.branch_name,
                p.title,
                p.proposal_id,
                p.gh_command
            ));
        }
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_codeql_probe(probe: &CodeQlProbeReport, json: bool) -> Response {
    let stdout = if json {
        let langs_json = probe
            .detected_languages
            .iter()
            .map(|(l, c)| {
                format!(
                    "{{\"language\":\"{}\",\"files_count\":{}}}",
                    l.as_codeql_identifier(),
                    c
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let primary_str = probe
            .primary_language
            .map(|p| format!("\"{}\"", p.as_codeql_identifier()))
            .unwrap_or_else(|| "null".to_string());
        let create_str = probe
            .database_create_command
            .as_ref()
            .map(|c| format!("\"{}\"", c.replace('\\', "/")))
            .unwrap_or_else(|| "null".to_string());
        let analyze_str = probe
            .database_analyze_command
            .as_ref()
            .map(|c| format!("\"{}\"", c.replace('\\', "/")))
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"schema_version\":1,\"command\":\"codeql\",\"mode\":\"probe\",\"workspace\":\"{}\",\"primary_language\":{},\"detected_languages\":[{}],\"database_create_command\":{},\"database_analyze_command\":{},\"untrusted_execution\":false}}\n",
            probe.workspace_root, primary_str, langs_json, create_str, analyze_str
        )
    } else {
        let mut text = format!(
            "Sentra CodeQL workspace probe: completed\nWorkspace: {}\n",
            probe.workspace_root
        );
        if let Some(primary) = probe.primary_language {
            text.push_str(&format!("Primary language: {}\n", primary));
        }
        text.push_str("Detected languages:\n");
        for (lang, count) in &probe.detected_languages {
            text.push_str(&format!(
                "  - {:<12} ({} files)\n",
                lang.as_codeql_identifier(),
                count
            ));
        }
        if let Some(create) = &probe.database_create_command {
            text.push_str(&format!("CodeQL Database Create:\n  {}\n", create));
        }
        if let Some(analyze) = &probe.database_analyze_command {
            text.push_str(&format!("CodeQL Database Analyze:\n  {}\n", analyze));
        }
        text.push_str("Untrusted execution: disabled\n");
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_codeql_ingest(result: &CodeQlSarifIngestResult, json: bool) -> Response {
    let stdout = if json {
        let rules_json = result
            .rules_identified
            .iter()
            .map(|r| format!("\"{}\"", r.replace('"', "\\\"")))
            .collect::<Vec<_>>()
            .join(",");
        let highest_str = result
            .highest_severity
            .map(|s| format!("\"{}\"", s.as_str()))
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"schema_version\":1,\"command\":\"codeql\",\"mode\":\"ingest\",\"total_sarif_results\":{},\"candidate_findings_parsed\":{},\"findings_stored\":false,\"taint_traces_extracted\":{},\"highest_severity\":{},\"rules\":[{}],\"untrusted_execution\":false}}\n",
            result.total_sarif_results,
            result.findings.len(),
            result.taint_traces_extracted,
            highest_str,
            rules_json
        )
    } else {
        let mut text = format!(
            "Sentra CodeQL analysis ingestion: completed\nTotal SARIF results: {}\nCandidate findings parsed (not stored): {}\nTaint traces extracted: {}\nHighest severity: {}\nRules identified: {}\n\n",
            result.total_sarif_results,
            result.findings.len(),
            result.taint_traces_extracted,
            result
                .highest_severity
                .map(|s| s.as_str())
                .unwrap_or("NONE"),
            result.rules_identified.join(", ")
        );
        for f in &result.findings {
            let loc_str = f
                .location()
                .map(|l| {
                    if let Some(line) = l.start_line {
                        format!("{}:{}", l.path, line)
                    } else {
                        l.path.clone()
                    }
                })
                .unwrap_or_else(|| "unknown".to_string());

            text.push_str(&format!(
                "  [{}] {:<8} {} -> {}\n",
                f.id(),
                f.severity().as_str(),
                loc_str,
                f.title()
            ));
        }
        text.push_str("Untrusted execution: disabled\n");
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

/// A flag that becomes true once standard input reaches end of file (or fails).
///
/// A parent process that keeps the pipe open while it waits closes it to cancel; the
/// pipe also closes when the parent dies, so CodeQL never outlives it unnoticed.
fn cancel_when_stdin_closes() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let set = Arc::clone(&flag);
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut buffer = [0_u8; 256];
        while matches!(stdin.read(&mut buffer), Ok(n) if n > 0) {}
        set.store(true, Ordering::SeqCst);
    });
    flag
}

/// Maps a host analysis failure to its error code, exit status and the partial report.
fn codeql_host_error(err: &CodeQlHostError, json: bool) -> Response {
    let exit = match err.kind {
        CodeQlHostErrorKind::TermsNotAccepted
        | CodeQlHostErrorKind::InvalidWorkspace
        | CodeQlHostErrorKind::WorkDirInsideWorkspace
        | CodeQlHostErrorKind::PackCacheInsideWorkspace
        | CodeQlHostErrorKind::UnsafeDirectory => 4,
        CodeQlHostErrorKind::NotFound => 7,
        CodeQlHostErrorKind::QueryPackMissing => 6,
        CodeQlHostErrorKind::Timeout
        | CodeQlHostErrorKind::Failed
        | CodeQlHostErrorKind::Cancelled
        | CodeQlHostErrorKind::Io => 5,
    };
    let details = match &err.report {
        Some(report) => serde_json::json!({
            "command": "codeql analyze",
            "codeql_version": report.codeql_version,
            "target_code_executed": false,
            "languages": report.languages,
            "warnings": report.warnings,
        }),
        None => serde_json::json!({
            "command": "codeql analyze",
            "target_code_executed": false,
        }),
    };
    let mut response = detailed_error(err.kind.code(), exit, json, &err.message, details);
    if !json && let Some(report) = &err.report {
        response.stderr.push_str(&codeql_language_lines(report));
    }
    response
}

/// Maps a rejected SARIF document to its error code and exit status.
fn codeql_sarif_error(err: &CodeQlSarifError, json: bool) -> Response {
    let exit = match err {
        CodeQlSarifError::Io(_) => 5,
        _ => 4,
    };
    let details = match err {
        CodeQlSarifError::TooLarge { size, limit } => {
            serde_json::json!({ "command": "codeql import", "size_bytes": size, "limit_bytes": limit })
        }
        _ => serde_json::json!({ "command": "codeql import" }),
    };
    detailed_error(err.code(), exit, json, &err.to_string(), details)
}

fn codeql_language_lines(report: &CodeQlResultReport) -> String {
    let mut text = String::new();
    if report.languages.is_empty() {
        return text;
    }
    text.push_str("Languages:\n");
    for outcome in &report.languages {
        let status = match outcome.status {
            CodeQlLanguageStatus::Analyzed => "analyzed",
            CodeQlLanguageStatus::Skipped => "skipped",
            CodeQlLanguageStatus::Failed => "failed",
        };
        let mut line = format!("  - {:<11} {status}", outcome.language);
        if outcome.status == CodeQlLanguageStatus::Analyzed {
            line.push_str(&format!(" ({} results", outcome.results));
            if let Some(ms) = outcome.duration_ms {
                line.push_str(&format!(", {:.1} s", ms as f64 / 1000.0));
            }
            line.push(')');
        }
        if let Some(reason) = &outcome.reason {
            line.push_str(&format!(": {reason}"));
        }
        line.push('\n');
        text.push_str(&line);
    }
    text
}

fn render_codeql_report(report: &CodeQlResultReport, json: bool) -> Response {
    if json {
        return json_line(report);
    }
    let import = report.command == "codeql import";
    let mut text = if import {
        "Sentra CodeQL SARIF import: completed (Sentra did not run CodeQL)\n".to_string()
    } else {
        "Sentra CodeQL host analysis: completed\n".to_string()
    };
    text.push_str(&format!("Workspace: {}\n", report.workspace));
    if import {
        if let Some(tool) = &report.source_tool {
            text.push_str(&format!(
                "SARIF produced by: {} {}\n",
                tool.name,
                tool.version.as_deref().unwrap_or("(version not stated)")
            ));
        }
    } else {
        text.push_str(&format!(
            "CodeQL version: {}\nSuite: {}\nPack download allowed: {}\n",
            report.codeql_version.as_deref().unwrap_or("unknown"),
            report.suite.as_deref().unwrap_or("-"),
            if report.pack_download_allowed {
                "yes"
            } else {
                "no"
            }
        ));
    }
    text.push_str(&codeql_language_lines(report));
    text.push_str(&format!(
        "Findings (candidate claims, not stored): {} of {} results ({} outside the workspace dropped{})\n",
        report.findings.len(),
        report.results_total,
        report.results_outside_workspace,
        if report.truncated { ", truncated at --max-results" } else { "" }
    ));
    for finding in report.findings.iter().take(50) {
        let message: String = finding
            .message
            .lines()
            .next()
            .unwrap_or_default()
            .chars()
            .take(160)
            .collect();
        text.push_str(&format!(
            "  [{:<8}] {}:{} {} - {}\n",
            finding.severity.as_str(),
            finding.path,
            finding.start_line,
            finding.rule_id,
            message
        ));
    }
    if report.findings.len() > 50 {
        text.push_str(&format!(
            "  ... {} more (use --json for all)\n",
            report.findings.len() - 50
        ));
    }
    if !report.warnings.is_empty() {
        text.push_str("Warnings:\n");
        for warning in &report.warnings {
            text.push_str(&format!("  - {warning}\n"));
        }
    }
    if !import {
        text.push_str("Target code executed: no (CodeQL build-mode none only; see ADR-0011)\n");
    }
    Response {
        stdout: text,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render(operation: &str, report: LocalWorkspaceReport, json: bool) -> Response {
    let exit_code = if report.initialized { 0 } else { 3 };
    let stdout = if let Some(session) = report.session {
        // Every string interpolated into JSON has a constrained domain alphabet.
        // Arbitrary target metadata is intentionally absent; no ad-hoc JSON escaping.
        if json {
            format!(
                "{{\"schema_version\":1,\"command\":\"{operation}\",\"initialized\":true,\"created\":{},\"project_id\":\"{}\",\"session_id\":\"{}\",\"state\":\"{}\",\"classification_floor\":\"{}\",\"context_generation\":{},\"created_at\":\"{}\",\"budget_limit_micro_usd\":{},\"budget_used_micro_usd\":{},\"untrusted_execution\":false}}\n",
                report.created,
                session.session_id,
                session.session_id,
                session.state.as_str(),
                session.classification_floor.as_str(),
                session.context_generation,
                session.created_at,
                session.budget_limit.as_micro_usd(),
                session.budget_used.as_micro_usd()
            )
        } else {
            format!(
                "Sentra workspace: initialized\nLocal project: {}\nSession: {}\nState: {}\nClassification floor: {}\nContext generation: {}\nCreated: {}\nBudget limit (micro-USD): {}\nBudget used/reserved (micro-USD): {}\nNew context: {}\nUntrusted execution: disabled\n",
                session.session_id,
                session.session_id,
                session.state.as_str(),
                session.classification_floor.as_str(),
                session.context_generation,
                session.created_at,
                session.budget_limit.as_micro_usd(),
                session.budget_used.as_micro_usd(),
                report.created
            )
        }
    } else if json {
        format!(
            "{{\"schema_version\":1,\"command\":\"{operation}\",\"initialized\":false,\"created\":false,\"session_id\":null,\"project_id\":null,\"untrusted_execution\":false}}\n"
        )
    } else {
        "Sentra workspace: not initialized for the selected storage\nUntrusted execution: disabled\n".into()
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code,
    }
}

fn execute_scan_snippet(
    code: &str,
    file_name: Option<&str>,
    sarif: Option<&Path>,
    cwd: &Path,
    json: bool,
) -> Response {
    let report = LocalWorkspace::scan_snippet(code, file_name);
    if let Some(sarif_out) = sarif {
        let now = TimestampUtc::now();
        let findings = report.to_candidate_findings(SessionId::new(), TaskId::new(), now);
        match sentra_core::generate_sarif_json(&findings, env!("CARGO_PKG_VERSION")) {
            Ok(sarif_json) => {
                let out_path = absolute(sarif_out, cwd);
                match std::fs::write(&out_path, sarif_json.as_bytes()) {
                    Ok(_) => Response {
                        stdout: if json {
                            "{\"schema_version\":1,\"command\":\"scan\",\"status\":\"success\",\"sarif_written\":true,\"untrusted_execution\":false}\n".to_string()
                        } else {
                            "Sentra SAST scan: SARIF export written successfully\nUntrusted execution: disabled\n".to_string()
                        },
                        stderr: String::new(),
                        exit_code: 0,
                    },
                    Err(_) => error("io_error", 5, json),
                }
            }
            Err(_) => error("sarif_generation_failed", 5, json),
        }
    } else {
        render_scan(&report, json)
    }
}

/// Display form of a path: no Windows `\\?\` verbatim prefix, forward slashes.
fn display_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    let plain = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        text.into_owned()
    };
    plain.replace('\\', "/")
}

fn json_line(value: &impl serde::Serialize) -> Response {
    match serde_json::to_string(value) {
        Ok(text) => Response {
            stdout: format!("{text}\n"),
            stderr: String::new(),
            exit_code: 0,
        },
        Err(_) => error("serialization_failed", 5, true),
    }
}

#[derive(serde::Serialize)]
struct InventoryJson<'a> {
    schema_version: u8,
    command: &'static str,
    workspace: String,
    lockfiles: &'a [sentra_core::InventoryLockfile],
    packages: &'a [sentra_core::InventoryPackage],
    total_packages: usize,
    truncated: bool,
    untrusted_execution: bool,
}

fn render_inventory(report: &LocalInventoryReport, json: bool) -> Response {
    let inventory = &report.inventory;
    let workspace = display_path(&report.workspace_root);
    if json {
        return json_line(&InventoryJson {
            schema_version: 1,
            command: "inventory",
            workspace,
            lockfiles: &inventory.lockfiles,
            packages: &inventory.packages,
            total_packages: inventory.total_packages,
            truncated: inventory.truncated,
            untrusted_execution: false,
        });
    }
    let mut text = format!(
        "Sentra dependency inventory: completed\nWorkspace: {workspace}\nLockfiles: {}\nPackages: {}\nTruncated: {}\n",
        inventory.lockfiles.len(),
        inventory.total_packages,
        inventory.truncated
    );
    for lockfile in &inventory.lockfiles {
        match &lockfile.parse_error {
            Some(reason) => text.push_str(&format!(
                "  {} ({}): not parsed - {reason}\n",
                lockfile.path, lockfile.ecosystem
            )),
            None => text.push_str(&format!(
                "  {} ({}): {} packages\n",
                lockfile.path, lockfile.ecosystem, lockfile.packages
            )),
        }
    }
    text.push_str("Untrusted execution: disabled\n");
    Response {
        stdout: text,
        stderr: String::new(),
        exit_code: 0,
    }
}

#[derive(serde::Serialize)]
struct PatchApplyJson<'a> {
    schema_version: u8,
    command: &'static str,
    status: &'static str,
    dry_run: bool,
    target_path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_path: Option<Option<String>>,
    already_patched: bool,
    hunks: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_recorded: Option<bool>,
    patch_sha256: &'a str,
    pre_image_sha256: &'a str,
    post_image_sha256: &'a str,
    untrusted_execution: bool,
}

fn render_patch_apply(report: &LocalPatchReport, json: bool) -> Response {
    let result = &report.result;
    let backup = result.backup_path.clone();
    if json {
        return json_line(&PatchApplyJson {
            schema_version: 1,
            command: "patch apply",
            status: "success",
            dry_run: result.dry_run,
            target_path: &result.target_path,
            backup_path: (!result.dry_run).then(|| backup.clone()),
            already_patched: result.already_patched,
            hunks: result.hunks,
            audit_recorded: (!result.dry_run).then_some(report.audit_recorded),
            patch_sha256: &result.patch_sha256,
            pre_image_sha256: &result.pre_image_sha256,
            post_image_sha256: &result.post_image_sha256,
            untrusted_execution: false,
        });
    }
    let stdout = if result.dry_run {
        format!(
            "Sentra patch apply (dry run): patch applies; nothing was written\nTarget file: {}\nHunks: {}\nAlready in patched state: {}\nUntrusted execution: disabled\n",
            result.target_path, result.hunks, result.already_patched,
        )
    } else {
        format!(
            "Sentra patch apply: success\nTarget file: {}\nHunks: {}\nBackup path: {}\nAlready in patched state: {}\nAudit event recorded: {}\nUntrusted execution: disabled\n",
            result.target_path,
            result.hunks,
            backup.as_deref().unwrap_or("none"),
            result.already_patched,
            report.audit_recorded,
        )
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

#[derive(serde::Serialize)]
struct PatchRollbackJson<'a> {
    schema_version: u8,
    command: &'static str,
    status: &'static str,
    target_path: &'a str,
    restored_from: String,
    audit_recorded: bool,
    pre_image_sha256: &'a str,
    post_image_sha256: &'a str,
    untrusted_execution: bool,
}

fn render_patch_rollback(report: &LocalRollbackReport, json: bool) -> Response {
    let result = &report.result;
    let restored_from = result.restored_from.clone();
    if json {
        return json_line(&PatchRollbackJson {
            schema_version: 1,
            command: "patch rollback",
            status: "success",
            target_path: &result.target_path,
            restored_from,
            audit_recorded: report.audit_recorded,
            pre_image_sha256: &result.pre_image_sha256,
            post_image_sha256: &result.post_image_sha256,
            untrusted_execution: false,
        });
    }
    Response {
        stdout: format!(
            "Sentra patch rollback: success\nTarget file: {}\nRestored from: {}\nAudit event recorded: {}\nUntrusted execution: disabled\n",
            result.target_path, restored_from, report.audit_recorded,
        ),
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_tenant_list(tenants: &[TenantRecord], json: bool) -> Response {
    let stdout = if json {
        let rows_json = serde_json::to_string(tenants).unwrap_or_default();
        format!(
            "{{\"schema_version\":1,\"command\":\"tenant list\",\"total\":{},\"tenants\":{},\"untrusted_execution\":false}}\n",
            tenants.len(),
            rows_json,
        )
    } else {
        let mut text = format!("Sentra registered tenants (total: {})\n", tenants.len());
        for t in tenants {
            text.push_str(&format!(
                "  [{}] {} (workspace: {}, isolation: {})\n",
                t.tenant_id, t.name, t.default_workspace, t.isolation_level
            ));
        }
        text.push_str("Untrusted execution: disabled\n");
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_tenant_add(tenant: &TenantRecord, json: bool) -> Response {
    let stdout = if json {
        let row_json = serde_json::to_string(tenant).unwrap_or_default();
        format!(
            "{{\"schema_version\":1,\"command\":\"tenant add\",\"status\":\"created\",\"tenant\":{},\"untrusted_execution\":false}}\n",
            row_json,
        )
    } else {
        format!(
            "Sentra tenant registered: success\nID: {}\nName: {}\nWorkspace: {}\nIsolation: {}\nCreated at: {}\nUntrusted execution: disabled\n",
            tenant.tenant_id,
            tenant.name,
            tenant.default_workspace,
            tenant.isolation_level,
            tenant.created_at,
        )
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_config_show(settings: &[(String, String)], json: bool) -> Response {
    let stdout = if json {
        let mut map = serde_json::Map::new();
        for (k, v) in settings {
            map.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        let settings_json = serde_json::Value::Object(map).to_string();
        format!(
            "{{\"schema_version\":1,\"command\":\"config show\",\"count\":{},\"settings\":{},\"untrusted_execution\":false}}\n",
            settings.len(),
            settings_json,
        )
    } else {
        let mut text = format!("Sentra system settings (count: {})\n", settings.len());
        for (k, v) in settings {
            text.push_str(&format!("  {} = {}\n", k, v));
        }
        text.push_str("Untrusted execution: disabled\n");
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_config_set(key: &str, value: &str, json: bool) -> Response {
    let stdout = if json {
        format!(
            "{{\"schema_version\":1,\"command\":\"config set\",\"status\":\"updated\",\"key\":\"{}\",\"value\":\"{}\",\"untrusted_execution\":false}}\n",
            key.replace('"', "\\\""),
            value.replace('"', "\\\""),
        )
    } else {
        format!(
            "Sentra configuration updated: success\nKey: {}\nValue: {}\nUntrusted execution: disabled\n",
            key, value
        )
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_fleet_list(fleet: &WorkerFleetManager, json: bool) -> Response {
    let stdout = if json {
        let workers = fleet
            .iter_workers()
            .map(|w| {
                serde_json::json!({
                    "worker_id": w.worker_id.as_str(),
                    "endpoint_url": w.endpoint_url,
                    "architecture": format!("{:?}", w.architecture),
                    "containment": format!("{:?}", w.containment),
                    "egress_policy": format!("{:?}", w.egress_policy),
                    "state": format!("{:?}", w.state),
                    "last_heartbeat": w.last_heartbeat.to_string(),
                })
            })
            .collect::<Vec<_>>();
        let workers_json = serde_json::to_string(&workers).unwrap_or_default();
        format!(
            "{{\"schema_version\":1,\"command\":\"fleet list\",\"total\":{},\"workers\":{},\"untrusted_execution\":false}}\n",
            fleet.total_workers(),
            workers_json,
        )
    } else {
        let mut text = format!(
            "Sentra remote worker fleet (total: {})\n",
            fleet.total_workers()
        );
        for w in fleet.iter_workers() {
            text.push_str(&format!(
                "  [{}] {:?} | {:?} | {:?} | {:?} | {}\n",
                w.worker_id.as_str(),
                w.architecture,
                w.containment,
                w.egress_policy,
                w.state,
                w.endpoint_url
            ));
        }
        text.push_str("Untrusted execution: disabled\n");
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_fleet_status(fleet: &WorkerFleetManager, json: bool) -> Response {
    let readiness = fleet.containment_readiness();
    let stdout = if json {
        format!(
            "{{\"schema_version\":1,\"command\":\"fleet status\",\"total_workers\":{},\"available_workers\":{},\"active_leases\":{},\"quarantined_workers\":{},\"containment_ready\":{},\"containment_status\":\"{}\",\"untrusted_execution\":false}}\n",
            fleet.total_workers(),
            fleet.available_workers(),
            fleet.active_leases(),
            fleet.quarantined_workers(),
            readiness.is_ready(),
            readiness.as_str(),
        )
    } else {
        let readiness_text = match readiness {
            ContainmentReadiness::NoWorkers => "not ready (no workers registered)",
            ContainmentReadiness::Unattested => {
                "not ready (declared containment levels are not attested)"
            }
        };
        format!(
            "Sentra remote worker fleet status:\nTotal workers: {}\nAvailable workers: {}\nActive leases: {}\nQuarantined workers: {}\nContainment readiness: {}\nUntrusted execution: disabled\n",
            fleet.total_workers(),
            fleet.available_workers(),
            fleet.active_leases(),
            fleet.quarantined_workers(),
            readiness_text,
        )
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

#[derive(serde::Serialize)]
struct PluginQuotasJson {
    max_memory_mib: u32,
    max_execution_time_secs: u32,
    max_frame_bytes: usize,
    max_total_output_bytes: usize,
}

/// Which declared manifest limits the plugin host actually enforces.
#[derive(serde::Serialize)]
struct PluginEnforcementJson {
    max_execution_time_secs: bool,
    max_frame_bytes: bool,
    max_total_output_bytes: bool,
    max_memory_mib: bool,
    egress_policy: bool,
}

const PLUGIN_ENFORCEMENT: PluginEnforcementJson = PluginEnforcementJson {
    max_execution_time_secs: true,
    max_frame_bytes: true,
    max_total_output_bytes: true,
    max_memory_mib: false,
    egress_policy: false,
};

#[derive(serde::Serialize)]
struct PluginListEntryJson<'a> {
    id: &'a str,
    name: &'a str,
    version: String,
    family: &'static str,
    manifest_path: String,
    executable_path: String,
    capabilities: Vec<&'a str>,
    egress_policy: String,
    quotas: PluginQuotasJson,
    enforced: PluginEnforcementJson,
}

#[derive(serde::Serialize)]
struct PluginDiagnosticJson<'a> {
    path: String,
    severity: &'static str,
    code: &'a str,
    message: &'a str,
}

#[derive(serde::Serialize)]
struct PluginListJson<'a> {
    schema_version: u8,
    command: &'static str,
    action: &'static str,
    directories: Vec<String>,
    count: usize,
    plugins: Vec<PluginListEntryJson<'a>>,
    /// True when a diagnostic has severity `error` (an entry was skipped).
    has_errors: bool,
    diagnostics: Vec<PluginDiagnosticJson<'a>>,
}

fn diagnostics_have_errors(diagnostics: &[DiscoveryDiagnostic]) -> bool {
    diagnostics
        .iter()
        .any(|d| d.severity == DiagnosticSeverity::Error)
}

fn diagnostic_severity(diagnostic: &DiscoveryDiagnostic) -> &'static str {
    match diagnostic.severity {
        sentra_core::plugin::DiagnosticSeverity::Warning => "warning",
        sentra_core::plugin::DiagnosticSeverity::Error => "error",
    }
}

#[derive(serde::Serialize)]
struct PluginProbeJson<'a> {
    schema_version: u8,
    command: &'static str,
    action: &'static str,
    plugin_id: &'a str,
    name: &'a str,
    applicable: bool,
    details: &'a str,
    unsupported_reason: Option<&'a str>,
    capabilities: Vec<&'a str>,
}

/// Fields a plugin run reports that come from the adapter, not from the host.
const ADAPTER_REPORTED_RUN_FIELDS: [&str; 3] = ["exit_code", "summary", "evidence_refs"];

#[derive(serde::Serialize)]
struct PluginRunJson<'a> {
    schema_version: u8,
    command: &'static str,
    action: &'static str,
    plugin_id: &'a str,
    task_id: &'a str,
    capability: &'a str,
    exit_code: i32,
    summary: &'a str,
    evidence_refs: &'a [String],
    adapter_reported: [&'static str; 3],
    process_exit_code: Option<i32>,
    workspace_root: Option<String>,
}

fn render_plugin_list(
    dirs: &[PathBuf],
    plugins: &[DiscoveredPlugin],
    diagnostics: &[DiscoveryDiagnostic],
    json: bool,
) -> Response {
    if json {
        let entries = plugins
            .iter()
            .map(|p| PluginListEntryJson {
                id: &p.manifest.id,
                name: &p.manifest.name,
                version: p.manifest.version.to_string(),
                family: p.manifest.family.as_str(),
                manifest_path: display_path(&p.manifest_path),
                executable_path: p.manifest.executable_path.replace('\\', "/"),
                capabilities: p
                    .manifest
                    .declared_capabilities
                    .iter()
                    .map(|c| c.as_str())
                    .collect(),
                egress_policy: format!("{:?}", p.manifest.egress_policy),
                quotas: PluginQuotasJson {
                    max_memory_mib: p.manifest.quotas.max_memory_mib,
                    max_execution_time_secs: p.manifest.quotas.max_execution_time_secs,
                    max_frame_bytes: p.manifest.quotas.max_frame_bytes,
                    max_total_output_bytes: p.manifest.quotas.max_total_output_bytes,
                },
                enforced: PLUGIN_ENFORCEMENT,
            })
            .collect();
        let diagnostic_entries = diagnostics
            .iter()
            .map(|d| PluginDiagnosticJson {
                path: display_path(&d.path),
                severity: diagnostic_severity(d),
                code: &d.code,
                message: &d.message,
            })
            .collect();
        json_line(&PluginListJson {
            schema_version: 1,
            command: "plugin",
            action: "list",
            directories: dirs.iter().map(|d| display_path(d)).collect(),
            count: plugins.len(),
            plugins: entries,
            has_errors: diagnostics_have_errors(diagnostics),
            diagnostics: diagnostic_entries,
        })
    } else {
        let directories: Vec<String> = dirs.iter().map(|d| display_path(d)).collect();
        let mut out = format!(
            "Sentra discovered plugins (count: {}):\nPlugin directories: {}\n",
            plugins.len(),
            directories.join(", ")
        );
        for p in plugins {
            let caps: Vec<&str> = p
                .manifest
                .declared_capabilities
                .iter()
                .map(|c| c.as_str())
                .collect();
            out.push_str(&format!(
                "  • {} v{} ({})\n    Manifest: {}\n    Capabilities: {}\n    Time limit: {}s (enforced)\n    Memory: {} MiB (declared, not enforced)\n    Egress: {:?} (declared, not enforced)\n\n",
                p.manifest.id,
                p.manifest.version,
                p.manifest.family.as_str(),
                display_path(&p.manifest_path),
                caps.join(", "),
                p.manifest.quotas.max_execution_time_secs,
                p.manifest.quotas.max_memory_mib,
                p.manifest.egress_policy
            ));
        }
        if !diagnostics.is_empty() {
            out.push_str("Diagnostics:\n");
            for d in diagnostics {
                out.push_str(&format!(
                    "  [{}] {}: {} ({})\n",
                    diagnostic_severity(d),
                    d.code,
                    d.message,
                    display_path(&d.path)
                ));
            }
        }
        Response {
            stdout: out,
            stderr: String::new(),
            exit_code: 0,
        }
    }
}

fn render_plugin_probe(output: &PluginProbeOutput, json: bool) -> Response {
    if json {
        json_line(&PluginProbeJson {
            schema_version: 1,
            command: "plugin",
            action: "probe",
            plugin_id: &output.plugin_id,
            name: &output.name,
            applicable: output.applicable,
            details: &output.details,
            unsupported_reason: output.unsupported_reason.as_deref(),
            capabilities: output.capabilities.iter().map(|c| c.as_str()).collect(),
        })
    } else {
        let caps: Vec<&str> = output.capabilities.iter().map(|c| c.as_str()).collect();
        let mut out = format!(
            "Sentra plugin probe: completed\nPlugin: {} ({})\nApplicable: {}\nDetails: {}\nCapabilities: {}\n",
            output.plugin_id,
            output.name,
            output.applicable,
            output.details,
            caps.join(", ")
        );
        if let Some(reason) = &output.unsupported_reason {
            out.push_str(&format!("Unsupported Reason: {}\n", reason));
        }
        Response {
            stdout: out,
            stderr: String::new(),
            exit_code: 0,
        }
    }
}

fn render_plugin_run(
    output: &PluginExecutionOutput,
    session: Option<&PluginSessionReport>,
    json: bool,
) -> Response {
    let process_exit_code = session.and_then(|s| s.process_exit_code);
    let workspace_root = session
        .and_then(|s| s.workspace_root.as_deref())
        .map(|root| display_path(Path::new(root)));
    if json {
        json_line(&PluginRunJson {
            schema_version: 1,
            command: "plugin",
            action: "run",
            plugin_id: &output.plugin_id,
            task_id: &output.task_id,
            capability: output.capability.as_str(),
            exit_code: output.exit_code,
            summary: &output.summary,
            evidence_refs: &output.evidence_refs,
            adapter_reported: ADAPTER_REPORTED_RUN_FIELDS,
            process_exit_code,
            workspace_root,
        })
    } else {
        Response {
            stdout: format!(
                "Sentra plugin execution: completed\nPlugin: {}\nTask ID: {}\nCapability: {}\nWorkspace: {}\nExit Code (adapter-reported): {}\nProcess exit code (host-observed): {}\nSummary (adapter-reported): {}\nEvidence Refs (adapter-reported labels): {}\n",
                output.plugin_id,
                output.task_id,
                output.capability.as_str(),
                workspace_root.as_deref().unwrap_or("none"),
                output.exit_code,
                process_exit_code.map_or_else(|| "unknown".to_string(), |c| c.to_string()),
                output.summary,
                if output.evidence_refs.is_empty() {
                    "none".to_string()
                } else {
                    output.evidence_refs.join(", ")
                }
            ),
            stderr: String::new(),
            exit_code: 0,
        }
    }
}

#[cfg(test)]
mod plugin_json_tests {
    use super::*;

    /// Backslashes, both quote kinds, a newline, a tab and a control character.
    const TRICKY: &str = "C:\\work\\repo \"quoted\" 'single'\nsecond line\ttab \u{1} end";

    fn single_json_line(response: &Response) -> serde_json::Value {
        assert_eq!(response.exit_code, 0);
        assert!(response.stderr.is_empty());
        assert!(response.stdout.ends_with('\n'));
        assert_eq!(response.stdout.matches('\n').count(), 1, "one JSON line");
        serde_json::from_str(&response.stdout).expect("valid JSON")
    }

    #[test]
    fn plugin_list_json_escapes_manifest_strings_and_keeps_shape() {
        let manifest: sentra_core::PluginManifest = serde_json::from_value(serde_json::json!({
            "id": "org.example.\"esc\\aped\"",
            "name": TRICKY,
            "version": "1.2.3",
            "interface_version": 1,
            "family": "analysis_tool",
            "executable_path": "C:\\tools\\scan.exe --rule \"x\"\n",
            "declared_capabilities": ["static_analysis", "dependency_audit"],
            "quotas": {
                "max_memory_mib": 256,
                "max_execution_time_secs": 30,
                "max_frame_bytes": 1024,
                "max_total_output_bytes": 4096
            },
            "egress_policy": "strictly_denied"
        }))
        .unwrap();
        let plugin = DiscoveredPlugin {
            manifest,
            manifest_path: PathBuf::from(r"\\?\C:\plugins\scan dir\manifest.json"),
            adapter_dir: PathBuf::from(r"\\?\C:\plugins\scan dir"),
        };
        let dirs = [PathBuf::from(r"\\?\C:\plugins")];
        let diagnostics = [DiscoveryDiagnostic {
            path: PathBuf::from(r"C:\plugins\broken\manifest.json"),
            severity: sentra_core::plugin::DiagnosticSeverity::Error,
            code: "manifest_invalid_json".to_string(),
            message: TRICKY.to_string(),
        }];
        let response = render_plugin_list(&dirs, std::slice::from_ref(&plugin), &diagnostics, true);
        assert!(response.stdout.starts_with(
            "{\"schema_version\":1,\"command\":\"plugin\",\"action\":\"list\",\"directories\":[\"C:/plugins\"],\"count\":1,\"plugins\":[{\"id\":"
        ));
        let json = single_json_line(&response);
        assert_eq!(
            json,
            serde_json::json!({
                "schema_version": 1,
                "command": "plugin",
                "action": "list",
                "directories": ["C:/plugins"],
                "count": 1,
                "plugins": [{
                    "id": "org.example.\"esc\\aped\"",
                    "name": TRICKY,
                    "version": "1.2.3",
                    "family": "analysis_tool",
                    "manifest_path": "C:/plugins/scan dir/manifest.json",
                    "executable_path": "C:/tools/scan.exe --rule \"x\"\n",
                    "capabilities": ["static_analysis", "dependency_audit"],
                    "egress_policy": "StrictlyDenied",
                    "quotas": {
                        "max_memory_mib": 256,
                        "max_execution_time_secs": 30,
                        "max_frame_bytes": 1024,
                        "max_total_output_bytes": 4096
                    },
                    "enforced": {
                        "max_execution_time_secs": true,
                        "max_frame_bytes": true,
                        "max_total_output_bytes": true,
                        "max_memory_mib": false,
                        "egress_policy": false
                    }
                }],
                "has_errors": true,
                "diagnostics": [{
                    "path": "C:/plugins/broken/manifest.json",
                    "severity": "error",
                    "code": "manifest_invalid_json",
                    "message": TRICKY
                }]
            })
        );

        let empty = single_json_line(&render_plugin_list(&dirs, &[], &[], true));
        assert_eq!(empty["count"], 0);
        assert_eq!(empty["plugins"], serde_json::json!([]));
        assert_eq!(empty["diagnostics"], serde_json::json!([]));
        assert_eq!(empty["has_errors"], false);

        let text = render_plugin_list(&dirs, std::slice::from_ref(&plugin), &diagnostics, false);
        assert!(
            text.stdout
                .contains("Egress: StrictlyDenied (declared, not enforced)")
        );
        assert!(text.stdout.contains("[error] manifest_invalid_json"));
    }

    #[test]
    fn plugin_probe_json_escapes_adapter_strings_and_keeps_shape() {
        let output = PluginProbeOutput {
            plugin_id: "org.example.\"id\\x".to_string(),
            name: TRICKY.to_string(),
            interface_version: 1,
            capabilities: vec![
                PluginCapability::StaticAnalysis,
                PluginCapability::Custom(TRICKY.to_string()),
            ],
            applicable: false,
            details: TRICKY.to_string(),
            unsupported_reason: Some(TRICKY.to_string()),
        };
        let response = render_plugin_probe(&output, true);
        assert!(response.stdout.starts_with(
            "{\"schema_version\":1,\"command\":\"plugin\",\"action\":\"probe\",\"plugin_id\":"
        ));
        assert_eq!(
            single_json_line(&response),
            serde_json::json!({
                "schema_version": 1,
                "command": "plugin",
                "action": "probe",
                "plugin_id": "org.example.\"id\\x",
                "name": TRICKY,
                "applicable": false,
                "details": TRICKY,
                "unsupported_reason": TRICKY,
                "capabilities": ["static_analysis", TRICKY]
            })
        );

        let applicable = PluginProbeOutput {
            applicable: true,
            unsupported_reason: None,
            ..output
        };
        let json = single_json_line(&render_plugin_probe(&applicable, true));
        assert_eq!(json["applicable"], true);
        assert!(json["unsupported_reason"].is_null());
    }

    #[test]
    fn plugin_run_json_escapes_adapter_strings_and_keeps_shape() {
        let output = PluginExecutionOutput {
            plugin_id: "org.example.\"id\\x".to_string(),
            task_id: "task-1".to_string(),
            capability: PluginCapability::Custom(TRICKY.to_string()),
            exit_code: -3,
            summary: TRICKY.to_string(),
            evidence_refs: vec!["sha256:abc".to_string(), TRICKY.to_string()],
        };
        let session = PluginSessionReport {
            resolved_executable: PathBuf::from(r"C:\tools\bun.exe"),
            args: vec!["adapter.ts".to_string()],
            workspace_root: Some(r"C:\work\repo".to_string()),
            process_exit_code: Some(0),
            killed_by_host: false,
            timed_out: false,
            stderr_bytes: 0,
            stderr_tail: String::new(),
        };
        let response = render_plugin_run(&output, Some(&session), true);
        assert!(response.stdout.starts_with(
            "{\"schema_version\":1,\"command\":\"plugin\",\"action\":\"run\",\"plugin_id\":"
        ));
        assert_eq!(
            single_json_line(&response),
            serde_json::json!({
                "schema_version": 1,
                "command": "plugin",
                "action": "run",
                "plugin_id": "org.example.\"id\\x",
                "task_id": "task-1",
                "capability": TRICKY,
                "exit_code": -3,
                "summary": TRICKY,
                "evidence_refs": ["sha256:abc", TRICKY],
                "adapter_reported": ["exit_code", "summary", "evidence_refs"],
                "process_exit_code": 0,
                "workspace_root": "C:/work/repo"
            })
        );

        let without_session = single_json_line(&render_plugin_run(&output, None, true));
        assert!(without_session["process_exit_code"].is_null());
        assert!(without_session["workspace_root"].is_null());

        let text = render_plugin_run(&output, Some(&session), false).stdout;
        assert!(text.contains("Exit Code (adapter-reported): -3"));
        assert!(text.contains("Process exit code (host-observed): 0"));
        assert!(text.contains("Workspace: C:/work/repo"));
    }

    #[test]
    fn install_parser_rejects_duplicates_and_misplaced_flags() {
        let parse_words = |words: &[&str]| {
            parse(
                &words
                    .iter()
                    .map(std::ffi::OsString::from)
                    .collect::<Vec<_>>(),
            )
        };
        let parsed = parse_words(&["install", "mcp", "claude", "--command", "sentra"]).unwrap();
        assert!(matches!(
            parsed.command,
            Command::Install { mcp: true, command: Some(ref c), .. } if c == Path::new("sentra")
        ));
        let parsed = parse_words(&["mcp", "install", "zed", "--global"]).unwrap();
        assert!(matches!(
            parsed.command,
            Command::Install {
                mcp: true,
                global: true,
                ..
            }
        ));
        // --skill with MCP parses, so execution can explain the conflict.
        assert!(parse_words(&["install", "claude", "--mcp", "--skill", "x"]).is_ok());
        for words in [
            &["install", "claude", "--global", "--global"][..],
            &["install", "claude", "--skill", "a", "--skill", "b"],
            &["install", "claude", "--workspace", "a", "--workspace", "b"],
            &["install", "claude", "--command", "sentra"],
            &["install", "mcp", "claude", "--mcp"],
            &["install", "claude", "cursor"],
            &["install"],
            &["mcp", "install"],
            &["mcp", "unexpected"],
            &["mcp", "--workspace"],
            &["mcp", "--database", "a", "--database", "b"],
            &["prompt", "scout", "--skills", "a", "--skills", "b"],
        ] {
            assert!(parse_words(words).is_err(), "{words:?}");
        }
        let parsed = parse_words(&["mcp", "--workspace", "ws", "--database", "db"]).unwrap();
        assert!(matches!(
            parsed.command,
            Command::Mcp { workspace: Some(ref w), database: Some(ref d) }
                if w == Path::new("ws") && d == Path::new("db")
        ));
    }

    #[test]
    fn mcp_command_override_is_absolute_unless_bare() {
        let cwd = Path::new("/work");
        assert_eq!(
            registered_command(Path::new("sentra"), cwd),
            PathBuf::from("sentra")
        );
        assert_eq!(
            registered_command(Path::new("bin/sentra"), cwd),
            Path::new("/work").join("bin/sentra")
        );
        assert!(is_all_target("ALL") && is_all_target("*") && !is_all_target("claude"));
    }
}
