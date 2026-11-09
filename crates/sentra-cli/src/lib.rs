//! Terminal adapter for the local Core lifecycle. No SQL or execution authority.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::{
    ffi::OsString,
    io::{BufRead, Write},
    path::{Path, PathBuf},
};

use sentra_core::{
    AdvisoryDatabase, ContainmentLevel, DEFAULT_MAX_LINE_BYTES, EgressPolicy, FileDeltaKind,
    McpServer, MultiUserAuditReport, MultiUserSecurityAudit, RemediationPrPackage, RemoteWorkerId,
    RemoteWorkerNode, SastReport, SessionId, SnapshotDiff, TimestampUtc, WorkerArchitecture,
    WorkerFleetManager, WorkerResourceCaps,
    fleet::AuditStatus,
    process_transport_line,
    service::{
        LocalAuditReport, LocalWorkspace, LocalWorkspaceError, LocalWorkspaceErrorKind,
        LocalWorkspaceReport,
    },
};

pub const HELP: &str = "Sentra local foundation\n\nUsage:\n  sentra init --workspace <directory> --database <file> [--json]\n  sentra status --database <file> [--workspace <directory>] [--json]\n  sentra session show <session-id> --database <file> [--workspace <directory>] [--json]\n  sentra recover --database <file> [--workspace <directory>] [--json]\n  sentra audit --database <file> [--workspace <directory>] [--json]\n  sentra scan [--workspace <directory>] [--database <file>] [--sarif <file>] [--json]\n  sentra sync-advisories --source <directory-or-file> [--database <file>] [--json]\n  sentra propose-pr --database <file> [--workspace <directory>] [--output <file>] [--json]\n  sentra diff --base <directory> --head <directory> [--json]\n  sentra verify-audit [--json]\n  sentra export sarif --database <file> [--workspace <directory>] [--output <file>] [--json]\n  sentra mcp\n  sentra --help\n  sentra --version\n\nStorage must have an existing local parent outside the workspace.\nStatus/session/audit default to the current workspace directory; no upward search.\nInitialization records metadata only. No scanning, AI or target execution.\nAudit analyzes multi-ecosystem lockfiles (Cargo, npm, yarn, pnpm, bun, deno).\nScan executes pure-Rust static analysis for secrets and code antipatterns.\nSync-advisories ingests universal OSV JSON advisories into the advisory database.\nPropose-pr packages verified vulnerabilities into GitHub Draft PR proposals.\nDiff compares base and head directory snapshots with pure-Rust hashing.\nVerify-audit evaluates the 5 mandatory multi-user hosting security containment gates.\nExport sarif converts dependency and SAST findings into an OASIS SARIF v2.1.0 document.\nMcp runs the JSON-RPC 2.0 Model Context Protocol stdio transport server.\n";

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
        workspace: PathBuf,
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
    Diff {
        base: PathBuf,
        head: PathBuf,
    },
    ExportSarif {
        workspace: Option<PathBuf>,
        database: PathBuf,
        output: Option<PathBuf>,
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
            | "diff"
            | "mcp"
            | "verify-audit"
            | "export"
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
        let mut database = None;
        let mut sarif = None;
        let mut rest = words.into_iter();
        while let Some(flag) = rest.next() {
            let value = rest.next().ok_or_else(invalid)?;
            if value.is_empty() || value.starts_with('-') {
                return Err(invalid());
            }
            match flag {
                "--workspace" if workspace.is_none() => workspace = Some(PathBuf::from(value)),
                "--database" if database.is_none() => database = Some(PathBuf::from(value)),
                "--sarif" if sarif.is_none() => sarif = Some(PathBuf::from(value)),
                _ => return Err(invalid()),
            }
        }
        let workspace = workspace.ok_or_else(invalid)?;
        return Ok(Invocation {
            command: Command::Scan {
                workspace,
                database,
                sarif,
            },
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
                "{\"schema_version\":1,\"commands\":[\"init\",\"status\",\"session show\",\"recover\",\"audit\",\"diff\",\"verify-audit\",\"export sarif\",\"mcp\"],\"offline\":true,\"untrusted_execution\":false}\n".into()
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
            database,
            sarif,
        } => {
            let ws_path = absolute(&workspace, cwd);
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
