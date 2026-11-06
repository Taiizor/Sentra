//! Terminal adapter for the local Core lifecycle. No SQL or execution authority.

#![forbid(unsafe_code)]
#![deny(clippy::all)]

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use sentra_core::{
    SessionId,
    service::{LocalWorkspace, LocalWorkspaceError, LocalWorkspaceErrorKind, LocalWorkspaceReport},
};

pub const HELP: &str = "Sentra local foundation\n\nUsage:\n  sentra init --workspace <directory> --database <file> [--json]\n  sentra status --database <file> [--workspace <directory>] [--json]\n  sentra session show <session-id> --database <file> [--workspace <directory>] [--json]\n  sentra --help\n  sentra --version\n\nStorage must have an existing local parent outside the workspace.\nStatus/session default to the current workspace directory; no upward search.\nInitialization records metadata only. No scanning, AI or target execution.\n";

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
    if !matches!(name, "init" | "status" | "session") {
        return Err(invalid());
    }
    if words == ["--help"] {
        return Ok(Invocation {
            command: Command::Help,
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

/// Execute only initialization/inspection through the Core local facade.
pub fn run(arguments: &[OsString], cwd: &Path) -> Response {
    let invocation = match parse(arguments) {
        Ok(value) => value,
        Err(_) => {
            return error(
                "invalid_arguments",
                2,
                arguments.iter().any(|s| s == "--json"),
            );
        }
    };
    let json = invocation.json;
    let (operation, result) = match invocation.command {
        Command::Help => {
            return Response {
                stdout: if json {
                    "{\"schema_version\":1,\"commands\":[\"init\",\"status\",\"session show\"],\"offline\":true,\"untrusted_execution\":false}\n".into()
                } else {
                    HELP.into()
                },
                stderr: String::new(),
                exit_code: 0,
            };
        }
        Command::Version => {
            return Response {
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
            };
        }
        Command::Init {
            workspace,
            database,
        } => (
            "init",
            LocalWorkspace::initialize(&absolute(&workspace, cwd), &absolute(&database, cwd)),
        ),
        Command::Status {
            workspace,
            database,
        } => (
            "status",
            LocalWorkspace::status(
                &absolute(workspace.as_deref().unwrap_or(cwd), cwd),
                &absolute(&database, cwd),
            ),
        ),
        Command::Session {
            id,
            workspace,
            database,
        } => (
            "session",
            LocalWorkspace::session(
                &absolute(workspace.as_deref().unwrap_or(cwd), cwd),
                &absolute(&database, cwd),
                id,
            ),
        ),
    };
    match result {
        Ok(report) => render(operation, report, json),
        Err(source) => core_error(source, json),
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
