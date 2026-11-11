//! Supervised subprocess driver and lifecycle execution engine (REQ-F16, EXTENSIONS.md).
//!
//! Each probe or execute starts one adapter process and runs
//! `initialize -> probe|execute -> shutdown` under these host-enforced limits:
//! - a session deadline from `quotas.max_execution_time_secs` (clamped to one hour), with
//!   the handshake additionally bounded by [`HANDSHAKE_TIMEOUT`];
//! - bounded stdout line reads (`quotas.max_frame_bytes`) and a cumulative
//!   stdout + stderr ceiling (`quotas.max_total_output_bytes`), with stderr always drained;
//! - a cleared environment except [`crate::plugin::process::ADAPTER_ENV_ALLOWLIST`]
//!   (plus [`crate::plugin::process::CONTAINMENT_ENV`] on Linux and macOS);
//! - the process tree is killed on every exit path, before the adapter's stdin is closed;
//!   descendants of an adapter that already exited are reached through a kill-on-close
//!   Job Object on Windows and through the process group and the containment marker on
//!   Linux and macOS (see `process.rs` for the fallbacks and residual risks).
//!
//! Memory and egress quotas are declared by the manifest but not enforced.

use std::{
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{
    SecurityClassification, SessionId,
    plugin::{
        discovery::DiscoveredPlugin,
        error::PluginError,
        host::{HostStatus, PluginHost, response_name},
        manifest::PluginCapability,
        process::{AdapterProcess, PumpEvent, adapter_environment, resolve_adapter_command},
        protocol::{PluginRequest, PluginResponse, decode_frame, encode_frame},
    },
    workspace::WorkspaceBoundary,
};

/// Longest wait for `initialize_ack`, within the session deadline.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Longest wait for `shutdown_ack` before the process tree is killed.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// How long an adapter that closed stdout may take to report its exit code.
const EXIT_GRACE: Duration = Duration::from_millis(500);

/// Structured outcome of a plugin probe operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginProbeOutput {
    /// Confirmed plugin identifier.
    pub plugin_id: String,
    /// Human-readable name.
    pub name: String,
    /// Interface protocol version.
    pub interface_version: u32,
    /// Capabilities the adapter acknowledged.
    pub capabilities: Vec<PluginCapability>,
    /// Adapter-reported applicability.
    pub applicable: bool,
    /// Adapter-reported details.
    pub details: String,
    /// Adapter-reported reason when not applicable.
    pub unsupported_reason: Option<String>,
}

/// Structured outcome of a plugin execution task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginExecutionOutput {
    /// Target plugin identifier.
    pub plugin_id: String,
    /// Host-generated task identifier (the adapter echoed it).
    pub task_id: String,
    /// Exercised capability.
    pub capability: PluginCapability,
    /// Adapter-reported outcome code; the real process status is in
    /// [`PluginSessionReport::process_exit_code`].
    pub exit_code: i32,
    /// Adapter-reported summary.
    pub summary: String,
    /// Adapter-reported evidence labels; never resolved or admitted as evidence.
    pub evidence_refs: Vec<String>,
}

/// Host-observed facts about the most recent adapter process.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSessionReport {
    /// Absolute program that was started.
    pub resolved_executable: PathBuf,
    /// Arguments passed to it.
    pub args: Vec<String>,
    /// Workspace root sent to the adapter, if any.
    pub workspace_root: Option<String>,
    /// Real process exit code (`None` when killed by a signal or unknown).
    pub process_exit_code: Option<i32>,
    /// The host had to kill the adapter because it had not exited by itself.
    pub killed_by_host: bool,
    /// The session deadline expired.
    pub timed_out: bool,
    /// Total bytes the adapter wrote to stderr.
    pub stderr_bytes: usize,
    /// Last bytes of stderr (lossy UTF-8, at most 16 KiB); adapter-controlled text.
    pub stderr_tail: String,
}

/// Supervised subprocess session executing commands over stdio pipes.
pub struct PluginDriver {
    plugin: DiscoveredPlugin,
    host: PluginHost,
    last_session: Option<PluginSessionReport>,
}

impl PluginDriver {
    /// Prepares a new driver session for a discovered plugin.
    pub fn new(plugin: DiscoveredPlugin) -> Result<Self, PluginError> {
        let host = PluginHost::new(plugin.manifest.clone())?;
        Ok(Self {
            plugin,
            host,
            last_session: None,
        })
    }

    /// Accessor for the underlying discovered plugin.
    pub fn plugin(&self) -> &DiscoveredPlugin {
        &self.plugin
    }

    /// Host-observed report of the most recent adapter process, also after a failure.
    ///
    /// `None` when no process was started (for example the executable was rejected).
    pub fn last_session(&self) -> Option<&PluginSessionReport> {
        self.last_session.as_ref()
    }

    /// Probes the adapter for capability and workspace applicability.
    ///
    /// This starts the adapter process: adapter code runs with the operator's privileges.
    pub fn probe(&mut self, workspace_root: &Path) -> Result<PluginProbeOutput, PluginError> {
        let workspace = validate_workspace_root(workspace_root)?;
        let plugin_id = self.plugin.manifest.id.clone();
        let name = self.plugin.manifest.name.clone();
        let interface_version = self.host.supported_interface_version;

        self.run_session(Some(workspace.clone()), "probe", |host, session| {
            let response = session.request(
                host,
                &PluginRequest::Probe {
                    workspace_root: workspace,
                },
            )?;
            match response {
                PluginResponse::ProbeResult {
                    applicable,
                    details,
                    unsupported_reason,
                } => Ok(PluginProbeOutput {
                    plugin_id,
                    name,
                    interface_version,
                    capabilities: host.negotiated_capabilities.clone(),
                    applicable,
                    details,
                    unsupported_reason,
                }),
                PluginResponse::Error { code, message } => {
                    Err(PluginError::adapter_reported(code, message))
                }
                other => {
                    host.status = HostStatus::Quarantined;
                    Err(PluginError::protocol_violation(format!(
                        "Unexpected probe response: {}",
                        response_name(&other)
                    )))
                }
            }
        })
    }

    /// Executes an authorized task with a validated workspace root in the Execute frame.
    pub fn execute_in_workspace(
        &mut self,
        workspace_root: &Path,
        task_id: &str,
        capability: PluginCapability,
        arguments: serde_json::Value,
    ) -> Result<PluginExecutionOutput, PluginError> {
        let workspace = validate_workspace_root(workspace_root)?;
        self.execute_inner(Some(workspace), task_id, capability, arguments)
    }

    /// Executes an authorized task without a workspace root (the Execute frame omits
    /// `workspace_root`). Prefer [`PluginDriver::execute_in_workspace`].
    pub fn execute(
        &mut self,
        task_id: &str,
        capability: PluginCapability,
        arguments: serde_json::Value,
    ) -> Result<PluginExecutionOutput, PluginError> {
        self.execute_inner(None, task_id, capability, arguments)
    }

    fn execute_inner(
        &mut self,
        workspace_root: Option<String>,
        task_id: &str,
        capability: PluginCapability,
        arguments: serde_json::Value,
    ) -> Result<PluginExecutionOutput, PluginError> {
        // Capability fence and replay check before any adapter code runs.
        self.host.authorize_execute(task_id, &capability)?;
        let plugin_id = self.plugin.manifest.id.clone();

        self.run_session(workspace_root.clone(), "execute", |host, session| {
            host.prepare_execute(task_id, &capability)?;
            let response = session.request(
                host,
                &PluginRequest::Execute {
                    task_id: task_id.to_string(),
                    lease_id: format!("lease-{task_id}"),
                    capability: capability.clone(),
                    workspace_root,
                    arguments,
                },
            )?;
            host.complete_execute()?;
            match response {
                PluginResponse::ExecuteResult {
                    task_id: returned_task_id,
                    exit_code,
                    evidence_refs,
                    summary,
                } => {
                    if let Err(error) = PluginHost::validate_execute_result(
                        task_id,
                        &returned_task_id,
                        &evidence_refs,
                    ) {
                        host.status = HostStatus::Quarantined;
                        return Err(error);
                    }
                    Ok(PluginExecutionOutput {
                        plugin_id,
                        task_id: task_id.to_string(),
                        capability,
                        exit_code,
                        summary,
                        evidence_refs,
                    })
                }
                PluginResponse::Error { code, message } => {
                    Err(PluginError::adapter_reported(code, message))
                }
                other => {
                    host.status = HostStatus::Quarantined;
                    Err(PluginError::protocol_violation(format!(
                        "Unexpected execute response: {}",
                        response_name(&other)
                    )))
                }
            }
        })
    }

    /// Starts the adapter, performs the handshake, runs `operation`, shuts the adapter
    /// down and records the session report. The process tree is killed on every path.
    fn run_session<T>(
        &mut self,
        workspace_root: Option<String>,
        phase: &'static str,
        operation: impl FnOnce(&mut PluginHost, &mut Session) -> Result<T, PluginError>,
    ) -> Result<T, PluginError> {
        self.last_session = None;
        self.host.begin_session();

        let manifest = &self.plugin.manifest;
        let env = adapter_environment(std::env::vars_os());
        let argv = manifest.command_argv()?;
        let command = resolve_adapter_command(&argv, &self.plugin.adapter_dir, &env)?;
        let limit = manifest.quotas.execution_timeout();
        let max_frame_bytes = manifest.quotas.max_frame_bytes;

        let process =
            AdapterProcess::spawn(&command, &self.plugin.adapter_dir, &env, max_frame_bytes)?;
        let started = Instant::now();
        let mut session = Session {
            process,
            deadline: started + limit,
            limit,
            max_frame_bytes,
            phase: "initialize",
            timed_out: false,
        };

        let outcome = session
            .handshake(&mut self.host, started + HANDSHAKE_TIMEOUT.min(limit))
            .and_then(|()| {
                session.phase = phase;
                operation(&mut self.host, &mut session)
            });
        if outcome.is_ok() {
            session.shutdown(&mut self.host);
        }
        let summary = session.process.finish();
        if self.host.status != HostStatus::Quarantined {
            self.host.status = HostStatus::Terminated;
        }
        self.last_session = Some(PluginSessionReport {
            resolved_executable: command.program,
            args: command.args,
            workspace_root,
            process_exit_code: summary.exit_code,
            killed_by_host: summary.killed_by_host,
            timed_out: session.timed_out,
            stderr_bytes: summary.stderr_bytes,
            stderr_tail: summary.stderr_tail,
        });
        outcome
    }
}

/// One running adapter process plus its deadline bookkeeping.
struct Session {
    process: AdapterProcess,
    deadline: Instant,
    limit: Duration,
    max_frame_bytes: usize,
    phase: &'static str,
    timed_out: bool,
}

impl Session {
    fn handshake(&mut self, host: &mut PluginHost, deadline: Instant) -> Result<(), PluginError> {
        self.process
            .send(encode_frame(&host.create_initialize_request())?);
        let ack = self.read_response(host, deadline.min(self.deadline))?;
        host.negotiate_handshake(&ack)
    }

    /// Sends a request and waits for its response within the session deadline.
    fn request(
        &mut self,
        host: &mut PluginHost,
        request: &PluginRequest,
    ) -> Result<PluginResponse, PluginError> {
        self.process.send(encode_frame(request)?);
        self.read_response(host, self.deadline)
    }

    /// Reads the next frame, counting stdout and stderr against the quotas.
    fn read_response(
        &mut self,
        host: &mut PluginHost,
        deadline: Instant,
    ) -> Result<PluginResponse, PluginError> {
        loop {
            let Some(event) = self.process.next_event(deadline) else {
                self.timed_out = true;
                host.status = HostStatus::Quarantined;
                let waited = if deadline >= self.deadline {
                    self.limit
                } else {
                    HANDSHAKE_TIMEOUT
                };
                return Err(PluginError::timeout(self.phase, waited.as_secs()));
            };
            match event {
                PumpEvent::Stderr(bytes) => host.record_stderr_bytes(bytes)?,
                PumpEvent::Frame(line) => {
                    host.record_output_frame(line.len())?;
                    let text = std::str::from_utf8(&line).map_err(|_| {
                        host.status = HostStatus::Quarantined;
                        PluginError::protocol_violation("frame is not valid UTF-8")
                    })?;
                    return decode_frame(text, self.max_frame_bytes).inspect_err(|_| {
                        host.status = HostStatus::Quarantined;
                    });
                }
                PumpEvent::FrameTooLarge(bytes) => {
                    host.status = HostStatus::Quarantined;
                    return Err(PluginError::frame_too_large(bytes, self.max_frame_bytes));
                }
                PumpEvent::StdoutClosed => {
                    let code = self.process.exit_code_within(EXIT_GRACE);
                    return Err(host.handle_process_crash(code));
                }
                PumpEvent::StdoutFailed(reason) => {
                    host.status = HostStatus::Quarantined;
                    return Err(PluginError::protocol_violation(format!(
                        "failed to read adapter stdout: {reason}"
                    )));
                }
            }
        }
    }

    /// Best-effort graceful shutdown bounded by [`SHUTDOWN_GRACE`].
    fn shutdown(&mut self, host: &mut PluginHost) {
        let Ok(frame) = encode_frame(&PluginRequest::Shutdown) else {
            return;
        };
        self.process.send(frame);
        let saved = (self.deadline, self.phase, self.timed_out, host.status);
        self.deadline = Instant::now() + SHUTDOWN_GRACE;
        self.phase = "shutdown";
        let acknowledged = matches!(
            self.read_response(host, self.deadline),
            Ok(PluginResponse::ShutdownAck)
        );
        // A missing or late shutdown_ack is not an operation failure; the tree is
        // killed by the caller either way, while the adapter is still alive.
        (self.deadline, self.phase, self.timed_out, host.status) = saved;
        if acknowledged {
            // The adapter may exit on its own now; make sure its descendants cannot
            // outlive it (see `AdapterProcess::settle_after_shutdown_ack`).
            self.process.settle_after_shutdown_ack(EXIT_GRACE);
        }
    }
}

/// Validates a workspace root with [`WorkspaceBoundary`] and returns its canonical path
/// as sent to adapters (without the Windows `\\?\` prefix).
///
/// `..` components are folded only across real directories (never across a link or
/// junction), so the boundary still checks every component the operating system would
/// traverse.
pub fn validate_workspace_root(workspace_root: &Path) -> Result<String, PluginError> {
    let folded = fold_parent_dirs(workspace_root)?;
    let shown = crate::skills::install_text::display_path(workspace_root);
    match std::fs::metadata(&folded) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(PluginError::invalid_workspace(format!(
                "'{shown}': directory does not exist"
            )));
        }
        Err(e) => {
            return Err(PluginError::invalid_workspace(format!(
                "'{shown}': cannot be read ({e})"
            )));
        }
        Ok(meta) if !meta.is_dir() => {
            return Err(PluginError::invalid_workspace(format!(
                "'{shown}': not a directory"
            )));
        }
        Ok(_) => {}
    }
    let boundary =
        WorkspaceBoundary::establish(&folded, SessionId::new(), SecurityClassification::Internal)
            .map_err(|_| {
                PluginError::invalid_workspace(format!(
                    "'{shown}': not an acceptable local workspace directory (links, junctions and special files are rejected)"
                ))
            })?;
    let canonical =
        crate::plugin::process::strip_verbatim(boundary.root().canonical_path().to_path_buf());
    canonical.to_str().map(str::to_owned).ok_or_else(|| {
        PluginError::invalid_workspace(format!("'{}' is not valid Unicode", canonical.display()))
    })
}

/// Drops `.` and folds `..` lexically after checking that each folded entry is a real
/// directory rather than a symbolic link or junction.
fn fold_parent_dirs(path: &Path) -> Result<PathBuf, PluginError> {
    if !path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Ok(path.to_path_buf());
    }
    // Not `std::path::absolute`: on Windows it folds `..` without looking at the disk.
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| PluginError::invalid_workspace(format!("'{}': {e}", path.display())))?
            .join(path)
    };
    let mut folded = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let real_dir = std::fs::symlink_metadata(&folded)
                    .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink());
                // Never fold the root itself away.
                if !real_dir || folded.parent().is_none() || !folded.pop() {
                    return Err(PluginError::invalid_workspace(format!(
                        "'{}': '..' may only follow a real directory",
                        path.display()
                    )));
                }
            }
            other => folded.push(other),
        }
    }
    Ok(folded)
}
