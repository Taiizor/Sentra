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
    McpServer, MultiUserAuditReport, MultiUserSecurityAudit, RemoteWorkerId, RemoteWorkerNode,
    SessionId, SnapshotDiff, TimestampUtc, WorkerArchitecture, WorkerFleetManager,
    WorkerResourceCaps,
    fleet::AuditStatus,
    process_transport_line,
    service::{
        LocalAuditReport, LocalWorkspace, LocalWorkspaceError, LocalWorkspaceErrorKind,
        LocalWorkspaceReport,
    },
};

pub const HELP: &str = "Sentra local foundation\n\nUsage:\n  sentra init --workspace <directory> --database <file> [--json]\n  sentra status --database <file> [--workspace <directory>] [--json]\n  sentra session show <session-id> --database <file> [--workspace <directory>] [--json]\n  sentra recover --database <file> [--workspace <directory>] [--json]\n  sentra audit --database <file> [--workspace <directory>] [--json]\n  sentra diff --base <directory> --head <directory> [--json]\n  sentra verify-audit [--json]\n  sentra mcp\n  sentra --help\n  sentra --version\n\nStorage must have an existing local parent outside the workspace.\nStatus/session/audit default to the current workspace directory; no upward search.\nInitialization records metadata only. No scanning, AI or target execution.\nAudit analyzes Cargo.lock dependencies against pinned security advisories.\nDiff compares base and head directory snapshots with pure-Rust hashing.\nVerify-audit evaluates the 5 mandatory multi-user hosting security containment gates.\nMcp runs the JSON-RPC 2.0 Model Context Protocol stdio transport server.\n";

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
    Diff {
        base: PathBuf,
        head: PathBuf,
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
        "init" | "status" | "session" | "recover" | "audit" | "diff" | "mcp" | "verify-audit"
    ) {
        return Err(invalid());
    }
    if words == ["--help"] {
        return Ok(Invocation {
            command: Command::Help,
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
                "{\"schema_version\":1,\"commands\":[\"init\",\"status\",\"session show\",\"recover\",\"audit\",\"diff\",\"verify-audit\",\"mcp\"],\"offline\":true,\"untrusted_execution\":false}\n".into()
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
