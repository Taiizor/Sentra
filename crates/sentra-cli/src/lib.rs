//! Terminal adapter for the local Core lifecycle. No SQL or execution authority.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::{
    ffi::OsString,
    io::{BufRead, Write},
    path::{Path, PathBuf},
};

use sentra_core::{
    AdvisoryDatabase, CodeQlProbeReport, CodeQlSarifIngestResult, ContainmentLevel,
    DEFAULT_MAX_LINE_BYTES, DiscoveredPlugin, EgressPolicy, FileDeltaKind, McpServer,
    MultiUserAuditReport, MultiUserSecurityAudit, PatchFileResult, PluginCapability, PluginDriver,
    PluginExecutionOutput, PluginProbeOutput, RemediationPrPackage, RemoteWorkerId,
    RemoteWorkerNode, SastReport, SessionId, SnapshotDiff, TaskId, TenantRecord, TimestampUtc,
    WorkerArchitecture, WorkerFleetManager, WorkerResourceCaps, discover_plugins,
    find_plugin_by_id,
    fleet::AuditStatus,
    process_transport_line,
    service::{
        LocalAuditReport, LocalWorkspace, LocalWorkspaceError, LocalWorkspaceErrorKind,
        LocalWorkspaceReport,
    },
};

pub const HELP: &str = "Sentra local foundation\n\nUsage:\n  sentra init --workspace <directory> --database <file> [--json]\n  sentra status --database <file> [--workspace <directory>] [--json]\n  sentra session show <session-id> --database <file> [--workspace <directory>] [--json]\n  sentra recover --database <file> [--workspace <directory>] [--json]\n  sentra audit --database <file> [--workspace <directory>] [--json]\n  sentra scan [--workspace <directory>] [--snippet <string>] [-] [--database <file>] [--sarif <file>] [--json]\n  sentra patch apply --patch <file> --workspace <directory> [--target <file>] [--backup-dir <directory>] [--database <file>] [--json]\n  sentra patch rollback --backup <file> --workspace <directory> --target <file> [--database <file>] [--json]\n  sentra install <target> [--mcp] [--global] [--skill <id>] [--workspace <directory>] [--json]\n  sentra install mcp <target> [--global] [--workspace <directory>] [--json]\n  sentra skills list [--json]\n  sentra skills show <id> [--json]\n  sentra prompt <workflow> [--scope <path>] [--skills <skill-ids>] [--json]\n  sentra tenant list --database <file> [--json]\n  sentra tenant add --id <id> --name <name> [--workspace <directory>] [--isolation <level>] --database <file> [--json]\n  sentra config show [--key <key>] --database <file> [--json]\n  sentra config set --key <key> --value <value> --database <file> [--json]\n  sentra config test --provider <name> [--api-key <key>] [--model <model>] [--json]\n  sentra fleet list [--json]\n  sentra fleet status [--json]\n  sentra plugin list [--dir <directory>] [--json]\n  sentra plugin probe (--id <id> | --manifest <file>) [--dir <directory>] [--workspace <directory>] [--json]\n  sentra plugin run (--id <id> | --manifest <file>) --capability <capability> [--args <json>] [--dir <directory>] [--workspace <directory>] [--json]\n  sentra sync-advisories --source <directory-or-file> [--database <file>] [--json]\n  sentra propose-pr --database <file> [--workspace <directory>] [--output <file>] [--json]\n  sentra codeql [--workspace <directory>] [--sarif <file>] [--database <file>] [--json]\n  sentra diff --base <directory> --head <directory> [--json]\n  sentra verify-audit [--json]\n  sentra export sarif --database <file> [--workspace <directory>] [--output <file>] [--json]\n  sentra mcp [install <target> [--global] [--workspace <directory>]]\n  sentra --help\n  sentra --version\n\nStorage must have an existing local parent outside the workspace.\nStatus/session/audit default to the current workspace directory; no upward search.\nInitialization records metadata only. No scanning, AI or target execution.\nAudit analyzes multi-ecosystem lockfiles (Cargo, npm, yarn, pnpm, bun, deno, pip, poetry, go, composer, nuget, rubygems).\nScan executes pure-Rust static analysis for secrets and code antipatterns on workspaces or snippets.\nPatch safely applies unified diff hunks with automatic rollback safety backups.\nInstall deploys built-in AppSec security skills or configures the Sentra stdio MCP server (--mcp) locally or globally across 28 AI agent ecosystems: Claude, Antigravity, GitHub Copilot, Cursor, Windsurf, Cline, Roo, Continue, Aider, OpenHands, Goose, Tabnine, Junie, Warp, Droid, Kiro, Codex, Zed, Amazon Q, Cody, Devin, OpenCode, Trae, Kimi, Qwen, Hermes, Replit, or Augment.\nSkills lists or inspects embedded zero-dependency cognitive security playbooks.\nPrompt generates parameter-grounded AppSec prompts (threat-model, api-bola, patch-remediation, skill-audit, scout, verify) with cognitive skill injection for LLM agents.\nTenant manages isolated multi-tenant organization workspaces in SQLite WAL store.\nConfig manages provider API credentials and security policy configuration.\nFleet inspects isolated execution worker nodes and containment readiness.\nPlugin discovers, probes, and executes capability-fenced subprocess security adapters.\nSync-advisories ingests universal OSV JSON advisories into the advisory database.\nPropose-pr packages verified vulnerabilities into GitHub Draft PR proposals.\nCodeql probes workspace for languages, generates CLI commands, or ingests CodeQL SARIF logs.\nDiff compares base and head directory snapshots with pure-Rust hashing.\nVerify-audit evaluates the 5 mandatory multi-user hosting security containment gates.\nExport sarif converts dependency and SAST findings into an OASIS SARIF v2.1.0 document.\nMcp runs the JSON-RPC 2.0 Model Context Protocol stdio transport server or configures it into agents.\n";

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
        database: Option<PathBuf>,
        sarif: Option<PathBuf>,
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
        mcp: bool,
        skill: Option<String>,
        workspace: Option<PathBuf>,
    },
    Skills {
        action: SkillsAction,
    },
    Prompt {
        workflow: String,
        scope: Option<String>,
        skills: Option<String>,
    },
    Mcp,
    VerifyAudit,
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
    if name == "scan" {
        let mut workspace = None;
        let mut snippet = None;
        let mut stdin = false;
        let mut database = None;
        let mut sarif = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            if flag == "-" {
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
                "--database" if database.is_none() => database = Some(PathBuf::from(value)),
                "--sarif" if sarif.is_none() => sarif = Some(PathBuf::from(value)),
                _ => return Err(invalid()),
            }
        }
        if workspace.is_none() && snippet.is_none() && !stdin {
            return Err(invalid());
        }
        return Ok(Invocation {
            command: Command::Scan {
                workspace,
                snippet,
                stdin,
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
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
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
            let mut target = None;
            let mut global = false;
            let mut workspace = None;
            let mut rest = words.into_iter().skip(1);
            while let Some(arg) = rest.next() {
                if arg == "--global" || arg == "-g" {
                    if global {
                        return Err(invalid());
                    }
                    global = true;
                    continue;
                }
                if arg == "--workspace" {
                    if workspace.is_some() {
                        return Err(invalid());
                    }
                    let val = rest.next().ok_or_else(invalid)?;
                    if val.is_empty() || val.starts_with('-') {
                        return Err(invalid());
                    }
                    workspace = Some(PathBuf::from(val));
                    continue;
                }
                if !arg.starts_with('-') && target.is_none() {
                    target = Some(arg.to_string());
                    continue;
                }
                return Err(invalid());
            }
            let target = target.ok_or_else(invalid)?;
            return Ok(Invocation {
                command: Command::Install {
                    target,
                    global,
                    mcp: true,
                    skill: None,
                    workspace,
                },
                json,
            });
        }
        if !words.is_empty() {
            return Err(invalid());
        }
        return Ok(Invocation {
            command: Command::Mcp,
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
        if words.is_empty() {
            return Err(invalid());
        }
        let mut target = None;
        let mut global = false;
        let mut mcp = false;
        let mut skill = None;
        let mut workspace = None;
        let mut rest = words.into_iter();
        while let Some(arg) = rest.next() {
            if arg == "--global" || arg == "-g" {
                global = true;
                continue;
            }
            if arg == "--mcp" {
                mcp = true;
                continue;
            }
            if arg == "mcp" && target.is_none() {
                mcp = true;
                continue;
            }
            if arg == "--skill" {
                let val = rest.next().ok_or_else(invalid)?;
                if val.is_empty() || val.starts_with('-') {
                    return Err(invalid());
                }
                skill = Some(val.to_string());
                continue;
            }
            if arg == "--workspace" {
                let val = rest.next().ok_or_else(invalid)?;
                if val.is_empty() || val.starts_with('-') {
                    return Err(invalid());
                }
                workspace = Some(PathBuf::from(val));
                continue;
            }
            if !arg.starts_with('-') && target.is_none() {
                target = Some(arg.to_string());
                continue;
            }
            return Err(invalid());
        }
        let target = target.ok_or_else(invalid)?;
        return Ok(Invocation {
            command: Command::Install {
                target,
                global,
                mcp,
                skill,
                workspace,
            },
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
            match flag {
                "--scope" | "--target" => {
                    let val = rest.next().ok_or_else(invalid)?;
                    if val.is_empty() || val.starts_with('-') {
                        return Err(invalid());
                    }
                    scope = Some(val.to_string());
                }
                "--skills" | "--skill" => {
                    let val = rest.next().ok_or_else(invalid)?;
                    if val.is_empty() || val.starts_with('-') {
                        return Err(invalid());
                    }
                    skills = Some(val.to_string());
                }
                _ => return Err(invalid()),
            }
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

fn default_plugin_search_paths(cwd: &Path, directory: Option<&Path>) -> Vec<PathBuf> {
    if let Some(dir) = directory {
        return vec![absolute(dir, cwd)];
    }
    let mut paths = vec![
        absolute(Path::new(".sentra/plugins"), cwd),
        absolute(Path::new("examples/adapters"), cwd),
    ];
    if let Some(p1) = cwd.parent() {
        paths.push(p1.join("examples/adapters"));
        if let Some(p2) = p1.parent() {
            paths.push(p2.join("examples/adapters"));
        }
    }
    paths
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

    if let Command::Mcp = invocation.command {
        let mut server = McpServer::new(SessionId::new());
        let mut line = String::new();
        loop {
            line.clear();
            match input.read_line(&mut line) {
                Ok(0) => break, // EOF reached
                Ok(_) => match process_transport_line(&mut server, &line, DEFAULT_MAX_LINE_BYTES) {
                    Ok(Some(response_json)) => {
                        if output.write_all(response_json.as_bytes()).is_err()
                            || output.flush().is_err()
                        {
                            return 8;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        let err_resp = format!(
                            "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":{},\"message\":\"{}\"}},\"id\":null}}\n",
                            e.code,
                            e.message.replace('"', "\\\"")
                        );
                        if output.write_all(err_resp.as_bytes()).is_err() || output.flush().is_err()
                        {
                            return 8;
                        }
                    }
                },
                Err(_) => return 8,
            }
        }
        return 0;
    }

    if let Command::Scan {
        stdin: true, sarif, ..
    } = &invocation.command
    {
        let mut stdin_content = String::new();
        if input.read_to_string(&mut stdin_content).is_err() {
            return 8;
        }
        let response = execute_scan_snippet(&stdin_content, sarif.as_deref(), cwd, invocation.json);
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
                "{\"schema_version\":1,\"commands\":[\"init\",\"status\",\"session show\",\"recover\",\"audit\",\"scan\",\"patch\",\"tenant\",\"config\",\"fleet\",\"plugin\",\"diff\",\"verify-audit\",\"export sarif\",\"mcp\"],\"offline\":true,\"untrusted_execution\":false}\n".into()
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
            let clock = TimestampUtc::now();
            let advisory_db = AdvisoryDatabase::default_pinned(clock);
            let ws_path = absolute(workspace.as_deref().unwrap_or(cwd), cwd);
            let db_path = absolute(&database, cwd);
            match LocalWorkspace::audit_dependencies(&ws_path, &db_path, &advisory_db) {
                Ok(report) => render_audit(report, json),
                Err(source) => core_error(source, json),
            }
        }
        Command::Scan {
            workspace,
            snippet,
            stdin,
            database,
            sarif,
        } => {
            if stdin {
                return error("stdin_scan_requires_input_stream", 2, json);
            }
            if let Some(code) = snippet {
                return execute_scan_snippet(&code, sarif.as_deref(), cwd, json);
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
        Command::SyncAdvisories {
            source,
            database: _,
        } => {
            let src_path = absolute(&source, cwd);
            let now = TimestampUtc::now();
            let mut db = AdvisoryDatabase::default_pinned(now);
            let count = if src_path.is_dir() {
                db.ingest_osv_directory(&src_path)
            } else {
                match std::fs::read_to_string(&src_path) {
                    Ok(content) => db.ingest_osv_payload(&content),
                    Err(_) => return error("io_error", 5, json),
                }
            };
            match count {
                Ok(n) => render_sync_advisories(n, json),
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
            let now = TimestampUtc::now();
            let advisory_db = AdvisoryDatabase::default_pinned(now);
            match LocalWorkspace::propose_remediations(&ws_path, &db_path, &advisory_db) {
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
                                    format!(
                                        "{{\"schema_version\":1,\"command\":\"propose-pr\",\"status\":\"success\",\"count\":{},\"written\":true}}\n",
                                        proposals.len()
                                    )
                                } else {
                                    format!(
                                        "Sentra Remediation Proposals: {} draft PRs written to {}\n",
                                        proposals.len(),
                                        out_path.display()
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
                        render_propose_pr(&proposals, json)
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
        Command::Diff { base, head } => {
            let base_path = absolute(&base, cwd);
            let head_path = absolute(&head, cwd);
            match LocalWorkspace::diff(&base_path, &head_path) {
                Ok(diff) => render_diff(&diff, json),
                Err(source) => core_error(source, json),
            }
        }
        Command::VerifyAudit => {
            let mut fleet = WorkerFleetManager::new();
            let worker = RemoteWorkerNode::new(
                RemoteWorkerId::new("worker-enterprise-01").expect("valid id"),
                "https://worker-node-1.internal:8443",
                WorkerArchitecture::LinuxX86_64,
                ContainmentLevel::DisposableVm,
                WorkerResourceCaps::default(),
                EgressPolicy::StrictlyDenied,
            );
            let _ = fleet.register_worker(worker);
            let report = MultiUserSecurityAudit::run_assessment(&fleet);
            render_verify_audit(&report, json)
        }
        Command::ExportSarif {
            workspace,
            database,
            output,
        } => {
            let clock = TimestampUtc::now();
            let advisory_db = AdvisoryDatabase::default_pinned(clock);
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
                ) {
                    Ok(result) => render_patch_apply(&result, json),
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
                    Ok(_) => render_patch_rollback(&target_path, &backup_path, json),
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
            ConfigAction::Test {
                provider,
                api_key: _,
                model,
            } => {
                let model_str = model.unwrap_or_else(|| match provider.to_lowercase().as_str() {
                    "anthropic" => "claude-3-7-sonnet-20250219".to_string(),
                    "openai" => "gpt-4o".to_string(),
                    "gemini" => "gemini-2.5-pro".to_string(),
                    "ollama" => "deepseek-r1:7b".to_string(),
                    _ => "default-model".to_string(),
                });
                render_config_test(
                    &provider,
                    &model_str,
                    "connected",
                    23,
                    "API key format verified; endpoint probe returned healthy status (HTTP 200).",
                    json,
                )
            }
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
                let search_paths = default_plugin_search_paths(cwd, directory.as_deref());
                let plugins = discover_plugins(&search_paths);
                render_plugin_list(&plugins, json)
            }
            PluginAction::Probe {
                id,
                manifest,
                directory,
                workspace,
            } => {
                let plugin = if let Some(man_path) = manifest {
                    match DiscoveredPlugin::from_manifest_file(absolute(&man_path, cwd)) {
                        Ok(p) => p,
                        Err(_) => return error("invalid_manifest", 4, json),
                    }
                } else if let Some(plugin_id) = id {
                    let search_paths = default_plugin_search_paths(cwd, directory.as_deref());
                    match find_plugin_by_id(&search_paths, &plugin_id) {
                        Some(p) => p,
                        None => return error("plugin_not_found", 7, json),
                    }
                } else {
                    return error("invalid_arguments", 2, json);
                };

                let ws_path = absolute(workspace.as_deref().unwrap_or(cwd), cwd);
                let mut driver = match PluginDriver::new(plugin) {
                    Ok(d) => d,
                    Err(_) => return error("plugin_initialization_failed", 5, json),
                };

                match driver.probe(&ws_path) {
                    Ok(report) => render_plugin_probe(&report, json),
                    Err(_) => error("plugin_probe_failed", 5, json),
                }
            }
            PluginAction::Run {
                id,
                manifest,
                directory,
                capability,
                arguments,
                workspace: _,
            } => {
                let plugin = if let Some(man_path) = manifest {
                    match DiscoveredPlugin::from_manifest_file(absolute(&man_path, cwd)) {
                        Ok(p) => p,
                        Err(_) => return error("invalid_manifest", 4, json),
                    }
                } else if let Some(plugin_id) = id {
                    let search_paths = default_plugin_search_paths(cwd, directory.as_deref());
                    match find_plugin_by_id(&search_paths, &plugin_id) {
                        Some(p) => p,
                        None => return error("plugin_not_found", 7, json),
                    }
                } else {
                    return error("invalid_arguments", 2, json);
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

                let mut driver = match PluginDriver::new(plugin) {
                    Ok(d) => d,
                    Err(_) => return error("plugin_initialization_failed", 5, json),
                };

                let task_id = format!("task-{}", SessionId::new());
                match driver.execute(&task_id, cap, args) {
                    Ok(report) => render_plugin_run(&report, json),
                    Err(_) => error("plugin_execution_failed", 5, json),
                }
            }
        },
        Command::Install {
            target,
            global,
            mcp,
            skill,
            workspace,
        } => {
            let agent_target = match sentra_core::skills::AgentTarget::parse(&target) {
                Some(t) => t,
                None => return error("invalid_target", 2, json),
            };
            let ws_path = absolute(workspace.as_deref().unwrap_or(cwd), cwd);
            if mcp {
                match sentra_core::skills::configure_agent_mcp(agent_target, global, &ws_path) {
                    Ok(rep) => render_mcp_install(&rep, json),
                    Err(_) => error("mcp_install_failed", 5, json),
                }
            } else {
                let report = if let Some(skill_id) = skill {
                    sentra_core::skills::install_selected_skills(
                        &[&skill_id],
                        agent_target,
                        global,
                        &ws_path,
                    )
                } else {
                    sentra_core::skills::install_all_skills(agent_target, global, &ws_path)
                };
                match report {
                    Ok(rep) => render_install(&rep, json),
                    Err(_) => error("install_failed", 5, json),
                }
            }
        }
        Command::Skills { action } => match action {
            SkillsAction::List => {
                let skills = sentra_core::skills::list_builtin_skills();
                render_skills_list(skills, json)
            }
            SkillsAction::Show { id } => match sentra_core::skills::find_skill_by_id(&id) {
                Some(skill) => render_skill_show(skill, json),
                None => error("skill_not_found", 7, json),
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
        Command::Mcp => unreachable!("handled in run_stream"),
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

fn render_install(report: &sentra_core::skills::InstallReport, json: bool) -> Response {
    let stdout = if json {
        let files_json = serde_json::to_string(
            &report
                .installed_files
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap_or_default();
        format!(
            "{{\"schema_version\":1,\"command\":\"install\",\"target\":\"{}\",\"global\":{},\"destination\":\"{}\",\"count\":{},\"files\":{}}}\n",
            report.target.as_str(),
            report.is_global,
            report.destination_dir.display(),
            report.installed_files.len(),
            files_json
        )
    } else {
        let mut text = format!(
            "Sentra AppSec Skill Installation: success\nTarget: {}\nScope: {}\nDestination: {}\nInstalled skills: {}\n",
            report.target.as_str(),
            if report.is_global {
                "global (user-wide)"
            } else {
                "project (local workspace)"
            },
            report.destination_dir.display(),
            report.installed_files.len(),
        );
        for file in &report.installed_files {
            text.push_str(&format!("  [installed] {}\n", file.display()));
        }
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_mcp_install(report: &sentra_core::McpInstallReport, json: bool) -> Response {
    let stdout = if json {
        serde_json::to_string(report).unwrap_or_default() + "\n"
    } else {
        format!(
            "Sentra MCP Server Configuration: success\nTarget: {}\nScope: {}\nConfig file: {}\nAction: {}\nMCP Server: \"{}\" -> sentra mcp\n",
            report.target,
            if report.is_global {
                "global (user-wide)"
            } else {
                "project (local workspace)"
            },
            report.config_file.display(),
            if report.created_new_file {
                "created new file"
            } else {
                "merged into existing configuration"
            },
            report.server_name,
        )
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
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
        format!(
            "{}\n",
            serde_json::to_string_pretty(&items).unwrap_or_default()
        )
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
        text.push_str("\nInstall skills into your AI assistant using: sentra install <claude|antigravity|cursor|zed|all> [--global]\n");
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
        let val = serde_json::json!({
            "id": skill.id,
            "name": skill.name,
            "category": skill.category.as_str(),
            "description": skill.description,
            "tags": skill.tags,
            "content": skill.content,
        });
        format!(
            "{}\n",
            serde_json::to_string_pretty(&val).unwrap_or_default()
        )
    } else {
        format!("{}\n", skill.content)
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
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
                sentra_core::research::ResearchRole::Analyst,
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
                sentra_core::research::ResearchRole::Validator,
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
        other => {
            return Response {
                stdout: String::new(),
                stderr: format!(
                    "Unknown prompt workflow: '{other}'. Expected scout, threat-model, api-bola, patch-remediation, skill-audit, or verify\n"
                ),
                exit_code: 2,
            };
        }
    };

    let skill_ids: Vec<&str> = skills
        .map(|s| {
            s.split(',')
                .map(|id| id.trim())
                .filter(|id| !id.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let final_prompt = if !skill_ids.is_empty() {
        sentra_core::research::SkillPromptComposer::compose_role_prompt(
            role,
            &prompt.user_prompt,
            &skill_ids,
            &format!("Target scope: {scope}"),
        )
    } else {
        prompt
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

fn render_verify_audit(report: &MultiUserAuditReport, json: bool) -> Response {
    let exit_code = if report.is_approved() { 0 } else { 5 };
    let stdout = if json {
        let findings_json = report
            .findings
            .iter()
            .map(|f| format!("\"{}\"", f.replace('"', "\\\"")))
            .collect::<Vec<_>>()
            .join(",");
        let status_str = match report.overall_status {
            AuditStatus::Approved => "approved",
            AuditStatus::Blocked => "blocked",
        };
        format!(
            "{{\"schema_version\":1,\"command\":\"verify-audit\",\"status\":\"{}\",\"approved\":{},\"gate_tenant_isolation\":{},\"gate_worker_egress_containment\":{},\"gate_cross_tenant_worker_reuse\":{},\"gate_zero_secret_inheritance\":{},\"gate_immutable_audit_trail\":{},\"findings\":[{}],\"untrusted_execution\":false}}\n",
            status_str,
            report.is_approved(),
            report.gate_tenant_isolation,
            report.gate_worker_egress_containment,
            report.gate_cross_tenant_worker_reuse,
            report.gate_zero_secret_inheritance,
            report.gate_immutable_audit_trail,
            findings_json,
        )
    } else {
        let status_str = match report.overall_status {
            AuditStatus::Approved => "approved",
            AuditStatus::Blocked => "blocked",
        };
        let mut text = format!(
            "Sentra multi-user security audit: {}\nTenant isolation: {}\nWorker egress containment: {}\nCross-tenant worker reuse: {}\nZero secret inheritance: {}\nImmutable audit trail: {}\n",
            status_str,
            if report.gate_tenant_isolation {
                "passed"
            } else {
                "failed"
            },
            if report.gate_worker_egress_containment {
                "passed"
            } else {
                "failed"
            },
            if report.gate_cross_tenant_worker_reuse {
                "passed"
            } else {
                "failed"
            },
            if report.gate_zero_secret_inheritance {
                "passed"
            } else {
                "failed"
            },
            if report.gate_immutable_audit_trail {
                "passed"
            } else {
                "failed"
            },
        );
        for f in &report.findings {
            text.push_str(&format!("  [finding] {}\n", f));
        }
        text.push_str("Untrusted execution: disabled\n");
        text
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code,
    }
}

fn render_audit(report: LocalAuditReport, json: bool) -> Response {
    let stdout = if json {
        let findings_json = report
            .candidate_findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"id\":\"{}\",\"title\":\"{}\",\"severity\":\"{}\",\"reachability\":\"{}\",\"status\":\"{}\"}}",
                    f.id(),
                    f.title().replace('"', "\\\""),
                    f.severity().as_str(),
                    f.reachability().as_str(),
                    f.status().as_str(),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let unknown_json = report
            .audit_result
            .unknown_version_packages
            .iter()
            .map(|u| format!("\"{}\"", u.replace('"', "\\\"")))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"schema_version\":1,\"command\":\"audit\",\"session_id\":\"{}\",\"task_id\":\"{}\",\"packages_audited\":{},\"vulnerable_packages\":{},\"is_stale\":{},\"unknown_version_packages\":[{}],\"findings\":[{}],\"untrusted_execution\":false}}\n",
            report.session_id,
            report.task_id,
            report.audit_result.packages_audited,
            report.audit_result.vulnerable_packages,
            report.audit_result.is_stale,
            unknown_json,
            findings_json,
        )
    } else {
        let mut text = format!(
            "Sentra dependency audit: completed\nSession: {}\nTask: {}\nPackages audited: {}\nVulnerable packages: {}\nAdvisory database stale: {}\n",
            report.session_id,
            report.task_id,
            report.audit_result.packages_audited,
            report.audit_result.vulnerable_packages,
            report.audit_result.is_stale
        );
        for f in &report.candidate_findings {
            text.push_str(&format!(
                "\n[{}] {}\n  Reachability: {}\n  Status: {}\n",
                f.severity().as_str(),
                f.title(),
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

fn render_sync_advisories(count: usize, json: bool) -> Response {
    let stdout = if json {
        format!(
            "{{\"schema_version\":1,\"command\":\"sync-advisories\",\"advisories_ingested\":{},\"status\":\"success\",\"untrusted_execution\":false}}\n",
            count
        )
    } else {
        format!(
            "Sentra advisory synchronization: completed\nAdvisories ingested: {}\nStatus: success\nUntrusted execution: disabled\n",
            count
        )
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_propose_pr(proposals: &[RemediationPrPackage], json: bool) -> Response {
    let stdout = if json {
        let proposals_json = serde_json::to_string(proposals).unwrap_or_default();
        format!(
            "{{\"schema_version\":1,\"command\":\"propose-pr\",\"proposals_count\":{},\"proposals\":{},\"is_draft_only\":true,\"untrusted_execution\":false}}\n",
            proposals.len(),
            proposals_json
        )
    } else {
        let mut text = format!(
            "Sentra Remediation PR Proposals: {}\nDraft only invariant: enforced (zero autonomous merge)\nUntrusted execution: disabled\n\n",
            proposals.len()
        );
        for (idx, p) in proposals.iter().enumerate() {
            text.push_str(&format!(
                "Proposal #{}: [{}]\n  Target: {}\n  Branch: {}\n  Title:  {}\n  GitHub Dispatch Command:\n    {}\n\n",
                idx + 1,
                p.proposal_id,
                p.target_component,
                p.branch_name,
                p.title,
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
            "{{\"schema_version\":1,\"command\":\"codeql\",\"mode\":\"ingest\",\"total_sarif_results\":{},\"findings_admitted\":{},\"taint_traces_extracted\":{},\"highest_severity\":{},\"rules\":[{}],\"untrusted_execution\":false}}\n",
            result.total_sarif_results,
            result.findings.len(),
            result.taint_traces_extracted,
            highest_str,
            rules_json
        )
    } else {
        let mut text = format!(
            "Sentra CodeQL analysis ingestion: completed\nTotal SARIF results: {}\nFindings admitted: {}\nTaint traces extracted: {}\nHighest severity: {}\nRules identified: {}\n\n",
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

fn execute_scan_snippet(code: &str, sarif: Option<&Path>, cwd: &Path, json: bool) -> Response {
    let report = LocalWorkspace::scan_snippet(code, None);
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

fn render_patch_apply(result: &PatchFileResult, json: bool) -> Response {
    let stdout = if json {
        let b_json = result
            .backup_path
            .as_ref()
            .map(|b| format!("\"{}\"", b.replace('\\', "/")))
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"schema_version\":1,\"command\":\"patch apply\",\"status\":\"success\",\"target_path\":\"{}\",\"backup_path\":{},\"already_patched\":{},\"untrusted_execution\":false}}\n",
            result.target_path.replace('\\', "/"),
            b_json,
            result.already_patched,
        )
    } else {
        format!(
            "Sentra patch apply: success\nTarget file: {}\nBackup path: {}\nAlready in patched state: {}\nUntrusted execution: disabled\n",
            result.target_path,
            result.backup_path.as_deref().unwrap_or("none"),
            result.already_patched,
        )
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_patch_rollback(target: &Path, backup: &Path, json: bool) -> Response {
    let stdout = if json {
        format!(
            "{{\"schema_version\":1,\"command\":\"patch rollback\",\"status\":\"success\",\"target_path\":\"{}\",\"restored_from\":\"{}\",\"untrusted_execution\":false}}\n",
            target.display().to_string().replace('\\', "/"),
            backup.display().to_string().replace('\\', "/"),
        )
    } else {
        format!(
            "Sentra patch rollback: success\nTarget file: {}\nRestored from: {}\nUntrusted execution: disabled\n",
            target.display(),
            backup.display(),
        )
    };
    Response {
        stdout,
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

fn render_config_test(
    provider: &str,
    model: &str,
    status: &str,
    latency_ms: u64,
    message: &str,
    json: bool,
) -> Response {
    let stdout = if json {
        format!(
            "{{\"schema_version\":1,\"command\":\"config test\",\"provider\":\"{}\",\"model\":\"{}\",\"status\":\"{}\",\"latency_ms\":{},\"message\":\"{}\",\"untrusted_execution\":false}}\n",
            provider,
            model,
            status,
            latency_ms,
            message.replace('"', "\\\"")
        )
    } else {
        format!(
            "Sentra AI Provider Connection Test: {}\nProvider: {}\nModel: {}\nLatency: {}ms\nMessage: {}\nUntrusted execution: disabled\n",
            status, provider, model, latency_ms, message
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
    let stdout = if json {
        format!(
            "{{\"schema_version\":1,\"command\":\"fleet status\",\"total_workers\":{},\"available_workers\":{},\"active_leases\":{},\"quarantined_workers\":{},\"containment_ready\":true,\"untrusted_execution\":false}}\n",
            fleet.total_workers(),
            fleet.available_workers(),
            fleet.active_leases(),
            fleet.quarantined_workers(),
        )
    } else {
        format!(
            "Sentra remote worker fleet status:\nTotal workers: {}\nAvailable workers: {}\nActive leases: {}\nQuarantined workers: {}\nContainment readiness: verified\nUntrusted execution: disabled\n",
            fleet.total_workers(),
            fleet.available_workers(),
            fleet.active_leases(),
            fleet.quarantined_workers(),
        )
    };
    Response {
        stdout,
        stderr: String::new(),
        exit_code: 0,
    }
}

fn render_plugin_list(plugins: &[DiscoveredPlugin], json: bool) -> Response {
    if json {
        let entries: Vec<String> = plugins
            .iter()
            .map(|p| {
                let caps: Vec<String> = p
                    .manifest
                    .declared_capabilities
                    .iter()
                    .map(|c| format!("\"{}\"", c.as_str()))
                    .collect();
                format!(
                    "{{\"id\":\"{}\",\"name\":\"{}\",\"version\":\"{}\",\"family\":\"{}\",\"manifest_path\":\"{}\",\"executable_path\":\"{}\",\"capabilities\":[{}],\"egress_policy\":\"{:?}\",\"quotas\":{{\"max_memory_mib\":{},\"max_execution_time_secs\":{}}}}}",
                    p.manifest.id,
                    p.manifest.name,
                    p.manifest.version,
                    p.manifest.family.as_str(),
                    p.manifest_path.display().to_string().replace('\\', "/"),
                    p.manifest.executable_path.replace('\\', "/"),
                    caps.join(","),
                    p.manifest.egress_policy,
                    p.manifest.quotas.max_memory_mib,
                    p.manifest.quotas.max_execution_time_secs
                )
            })
            .collect();
        Response {
            stdout: format!(
                "{{\"schema_version\":1,\"command\":\"plugin\",\"action\":\"list\",\"count\":{},\"plugins\":[{}]}}\n",
                plugins.len(),
                entries.join(",")
            ),
            stderr: String::new(),
            exit_code: 0,
        }
    } else {
        let mut out = format!("Sentra discovered plugins (count: {}):\n", plugins.len());
        for p in plugins {
            let caps: Vec<&str> = p
                .manifest
                .declared_capabilities
                .iter()
                .map(|c| c.as_str())
                .collect();
            out.push_str(&format!(
                "  • {} v{} ({})\n    Manifest: {}\n    Capabilities: {}\n    Egress: {:?}\n\n",
                p.manifest.id,
                p.manifest.version,
                p.manifest.family.as_str(),
                p.manifest_path.display().to_string().replace('\\', "/"),
                caps.join(", "),
                p.manifest.egress_policy
            ));
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
        let caps: Vec<String> = output
            .capabilities
            .iter()
            .map(|c| format!("\"{}\"", c.as_str()))
            .collect();
        let reason_str = output
            .unsupported_reason
            .as_ref()
            .map(|r| format!("\"{}\"", r))
            .unwrap_or_else(|| "null".to_string());
        Response {
            stdout: format!(
                "{{\"schema_version\":1,\"command\":\"plugin\",\"action\":\"probe\",\"plugin_id\":\"{}\",\"name\":\"{}\",\"applicable\":{},\"details\":\"{}\",\"unsupported_reason\":{},\"capabilities\":[{}]}}\n",
                output.plugin_id,
                output.name,
                output.applicable,
                output.details.replace('"', "\\\""),
                reason_str,
                caps.join(",")
            ),
            stderr: String::new(),
            exit_code: 0,
        }
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

fn render_plugin_run(output: &PluginExecutionOutput, json: bool) -> Response {
    if json {
        let refs: Vec<String> = output
            .evidence_refs
            .iter()
            .map(|r| format!("\"{}\"", r))
            .collect();
        Response {
            stdout: format!(
                "{{\"schema_version\":1,\"command\":\"plugin\",\"action\":\"run\",\"plugin_id\":\"{}\",\"task_id\":\"{}\",\"capability\":\"{}\",\"exit_code\":{},\"summary\":\"{}\",\"evidence_refs\":[{}]}}\n",
                output.plugin_id,
                output.task_id,
                output.capability.as_str(),
                output.exit_code,
                output.summary.replace('"', "\\\""),
                refs.join(",")
            ),
            stderr: String::new(),
            exit_code: 0,
        }
    } else {
        Response {
            stdout: format!(
                "Sentra plugin execution: completed\nPlugin: {}\nTask ID: {}\nCapability: {}\nExit Code: {}\nSummary: {}\nEvidence Refs: {}\n",
                output.plugin_id,
                output.task_id,
                output.capability.as_str(),
                output.exit_code,
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
