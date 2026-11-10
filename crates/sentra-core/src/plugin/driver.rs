//! Supervised subprocess driver and lifecycle execution engine (REQ-F16, EXTENSIONS.md).

use std::{
    io::{BufRead, BufReader, Write},
    path::Path,
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};

use crate::plugin::{
    discovery::DiscoveredPlugin,
    error::PluginError,
    host::PluginHost,
    manifest::PluginCapability,
    protocol::{PluginRequest, PluginResponse, decode_frame, encode_frame},
};

/// Structured outcome of a plugin probe operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginProbeOutput {
    /// Confirmed plugin identifier.
    pub plugin_id: String,
    /// Human-readable name.
    pub name: String,
    /// Interface protocol version.
    pub interface_version: u32,
    /// Supported capabilities.
    pub capabilities: Vec<PluginCapability>,
    /// Whether the target codebase is applicable.
    pub applicable: bool,
    /// Probe details and diagnostics.
    pub details: String,
    /// Unsupported reason if not applicable.
    pub unsupported_reason: Option<String>,
}

/// Structured outcome of a plugin execution task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginExecutionOutput {
    /// Target plugin identifier.
    pub plugin_id: String,
    /// Associated task identifier.
    pub task_id: String,
    /// Exercised capability.
    pub capability: PluginCapability,
    /// Process exit code.
    pub exit_code: i32,
    /// Concise summary of findings.
    pub summary: String,
    /// Generated evidence references.
    pub evidence_refs: Vec<String>,
}

/// Supervised subprocess session executing commands over stdio pipes.
pub struct PluginDriver {
    plugin: DiscoveredPlugin,
    host: PluginHost,
}

impl PluginDriver {
    /// Prepares a new driver session for a discovered plugin.
    pub fn new(plugin: DiscoveredPlugin) -> Result<Self, PluginError> {
        let host = PluginHost::new(plugin.manifest.clone())?;
        Ok(Self { plugin, host })
    }

    /// Accessor for the underlying discovered plugin.
    pub fn plugin(&self) -> &DiscoveredPlugin {
        &self.plugin
    }

    /// Helper to parse the executable path into binary and arguments.
    fn parse_command_args(&self) -> Result<(String, Vec<String>), PluginError> {
        let parts: Vec<String> = self
            .plugin
            .manifest
            .executable_path
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if parts.is_empty() {
            return Err(PluginError::invalid_manifest(
                "Executable path cannot be empty",
            ));
        }

        let cmd = parts[0].clone();
        let args = parts[1..].to_vec();
        Ok((cmd, args))
    }

    /// Spawns the adapter child process with piped stdio.
    fn spawn_child(&self) -> Result<std::process::Child, PluginError> {
        let (cmd, args) = self.parse_command_args()?;

        let attempt = Command::new(&cmd)
            .args(&args)
            .current_dir(&self.plugin.adapter_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        match attempt {
            Ok(child) => Ok(child),
            Err(e) if cmd == "python" => Command::new("python3")
                .args(&args)
                .current_dir(&self.plugin.adapter_dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|_| {
                    PluginError::protocol_violation(format!(
                        "Failed to spawn adapter subprocess '{cmd}/python3' in '{}': {e}",
                        self.plugin.adapter_dir.display()
                    ))
                }),
            Err(e) if cmd == "python3" => Command::new("python")
                .args(&args)
                .current_dir(&self.plugin.adapter_dir)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|_| {
                    PluginError::protocol_violation(format!(
                        "Failed to spawn adapter subprocess '{cmd}/python' in '{}': {e}",
                        self.plugin.adapter_dir.display()
                    ))
                }),
            Err(e) => Err(PluginError::protocol_violation(format!(
                "Failed to spawn adapter subprocess '{cmd}' in '{}': {e}",
                self.plugin.adapter_dir.display()
            ))),
        }
    }

    /// Reads a single line from the child process stdout, tracks quota, and decodes frame.
    fn read_response(
        host: &mut PluginHost,
        reader: &mut BufReader<std::process::ChildStdout>,
    ) -> Result<PluginResponse, PluginError> {
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line).map_err(|e| {
            PluginError::protocol_violation(format!("Failed to read stdout from adapter: {e}"))
        })?;

        if bytes_read == 0 {
            return Err(PluginError::process_crash(None));
        }

        host.record_output_frame(bytes_read)?;
        decode_frame(&line, host.manifest.quotas.max_frame_bytes)
    }

    /// Writes a single protocol request frame to child stdin.
    fn write_request(
        writer: &mut std::process::ChildStdin,
        req: &PluginRequest,
    ) -> Result<(), PluginError> {
        let frame = encode_frame(req)?;
        writer.write_all(frame.as_bytes()).map_err(|e| {
            PluginError::protocol_violation(format!("Failed to write to adapter stdin: {e}"))
        })?;
        writer.flush().map_err(|e| {
            PluginError::protocol_violation(format!("Failed to flush adapter stdin: {e}"))
        })?;
        Ok(())
    }

    /// Probes the adapter for capability and workspace applicability.
    pub fn probe(&mut self, workspace_root: &Path) -> Result<PluginProbeOutput, PluginError> {
        let mut child = self.spawn_child()?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            PluginError::protocol_violation("Failed to capture adapter stdin pipe")
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            PluginError::protocol_violation("Failed to capture adapter stdout pipe")
        })?;
        let mut reader = BufReader::new(stdout);

        // 1. Initialize Handshake
        let init_req = self.host.create_initialize_request();
        Self::write_request(&mut stdin, &init_req)?;
        let init_resp = Self::read_response(&mut self.host, &mut reader)?;
        self.host.negotiate_handshake(&init_resp)?;

        let (confirmed_caps, interface_ver) = match &init_resp {
            PluginResponse::InitializeAck {
                capabilities,
                interface_version,
                ..
            } => (capabilities.clone(), *interface_version),
            _ => (self.plugin.manifest.declared_capabilities.clone(), 1),
        };

        // 2. Probe Request
        let ws_str = workspace_root.display().to_string();
        let probe_req = PluginRequest::Probe {
            workspace_root: ws_str,
        };
        Self::write_request(&mut stdin, &probe_req)?;
        let probe_resp = Self::read_response(&mut self.host, &mut reader)?;

        // 3. Graceful Shutdown
        let _ = Self::write_request(&mut stdin, &PluginRequest::Shutdown);
        let _ = Self::read_response(&mut self.host, &mut reader);
        let _ = child.kill();
        let _ = child.wait();

        match probe_resp {
            PluginResponse::ProbeResult {
                applicable,
                details,
                unsupported_reason,
            } => Ok(PluginProbeOutput {
                plugin_id: self.plugin.manifest.id.clone(),
                name: self.plugin.manifest.name.clone(),
                interface_version: interface_ver,
                capabilities: confirmed_caps,
                applicable,
                details,
                unsupported_reason,
            }),
            PluginResponse::Error { code, message } => Err(PluginError::protocol_violation(
                format!("Adapter reported probe error {code}: {message}"),
            )),
            other => Err(PluginError::protocol_violation(format!(
                "Unexpected probe response: {other:?}"
            ))),
        }
    }

    /// Executes an authorized task on the adapter subprocess.
    pub fn execute(
        &mut self,
        task_id: &str,
        capability: PluginCapability,
        arguments: serde_json::Value,
    ) -> Result<PluginExecutionOutput, PluginError> {
        let mut child = self.spawn_child()?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            PluginError::protocol_violation("Failed to capture adapter stdin pipe")
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            PluginError::protocol_violation("Failed to capture adapter stdout pipe")
        })?;
        let mut reader = BufReader::new(stdout);

        // 1. Initialize Handshake
        let init_req = self.host.create_initialize_request();
        Self::write_request(&mut stdin, &init_req)?;
        let init_resp = Self::read_response(&mut self.host, &mut reader)?;
        self.host.negotiate_handshake(&init_resp)?;

        // 2. Prepare execution state
        self.host.prepare_execute(task_id, &capability)?;

        // 3. Execute Request
        let exec_req = PluginRequest::Execute {
            task_id: task_id.to_string(),
            lease_id: format!("lease-{task_id}"),
            capability: capability.clone(),
            arguments,
        };
        Self::write_request(&mut stdin, &exec_req)?;
        let exec_resp = Self::read_response(&mut self.host, &mut reader)?;

        // 4. Mark complete & Graceful Shutdown
        let _ = self.host.complete_execute();
        let _ = Self::write_request(&mut stdin, &PluginRequest::Shutdown);
        let _ = Self::read_response(&mut self.host, &mut reader);
        let _ = child.kill();
        let _ = child.wait();

        match exec_resp {
            PluginResponse::ExecuteResult {
                exit_code,
                evidence_refs,
                summary,
                ..
            } => Ok(PluginExecutionOutput {
                plugin_id: self.plugin.manifest.id.clone(),
                task_id: task_id.to_string(),
                capability,
                exit_code,
                summary,
                evidence_refs,
            }),
            PluginResponse::Error { code, message } => Err(PluginError::protocol_violation(
                format!("Adapter execution error {code}: {message}"),
            )),
            other => Err(PluginError::protocol_violation(format!(
                "Unexpected execute response: {other:?}"
            ))),
        }
    }
}
