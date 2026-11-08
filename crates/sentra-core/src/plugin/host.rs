//! Host orchestrator managing plugin lifecycle, capability fencing, and quota boundaries (REQ-F16, EXTENSIONS.md).

use std::collections::HashSet;

use crate::plugin::{
    error::PluginError,
    manifest::{PluginCapability, PluginManifest},
    protocol::{PluginRequest, PluginResponse},
};

/// Operational state of a supervised plugin subprocess.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostStatus {
    /// Subprocess spawned but handshake not yet negotiated.
    Uninitialized,
    /// Handshake completed; adapter ready for probe, plan, or execution.
    Ready,
    /// Currently executing an authorized job lease.
    Executing,
    /// Process exited or was explicitly shut down.
    Terminated,
    /// Process breached policy or failed cleanup; quarantined.
    Quarantined,
}

/// Host supervisor governing an external or local plugin subprocess (REQ-F16).
#[derive(Clone, Debug)]
pub struct PluginHost {
    /// Associated plugin manifest.
    pub manifest: PluginManifest,
    /// Current operational status.
    pub status: HostStatus,
    /// Host supported interface major version.
    pub supported_interface_version: u32,
    /// Set of already executed task IDs for replay protection.
    pub executed_task_ids: HashSet<String>,
    /// Cumulative output bytes observed across stdout and stderr.
    pub cumulative_output_bytes: usize,
}

impl PluginHost {
    /// Initializes a plugin host from an authorized manifest.
    pub fn new(manifest: PluginManifest) -> Result<Self, PluginError> {
        manifest.validate()?;
        Ok(Self {
            manifest,
            status: HostStatus::Uninitialized,
            supported_interface_version: 1,
            executed_task_ids: HashSet::new(),
            cumulative_output_bytes: 0,
        })
    }

    /// Generates the initial handshake request for the plugin.
    pub fn create_initialize_request(&self) -> PluginRequest {
        PluginRequest::Initialize {
            host_version: self.supported_interface_version,
        }
    }

    /// Negotiates the version handshake from the plugin's response.
    ///
    /// Rejects incompatible interface versions or undeclared plugin capabilities.
    pub fn negotiate_handshake(&mut self, response: &PluginResponse) -> Result<(), PluginError> {
        match response {
            PluginResponse::InitializeAck {
                plugin_id,
                interface_version,
                capabilities,
            } => {
                // 1. Interface version compatibility check
                if *interface_version != self.supported_interface_version {
                    self.status = HostStatus::Quarantined;
                    return Err(PluginError::incompatible_version(
                        self.supported_interface_version,
                        *interface_version,
                    ));
                }

                // 2. Identity match check
                if plugin_id != &self.manifest.id {
                    self.status = HostStatus::Quarantined;
                    return Err(PluginError::invalid_manifest(format!(
                        "Plugin ID mismatch: expected '{}', received '{plugin_id}'",
                        self.manifest.id
                    )));
                }

                // 3. Capabilities must be declared in manifest
                for cap in capabilities {
                    if !self.manifest.supports_capability(cap) {
                        self.status = HostStatus::Quarantined;
                        return Err(PluginError::undeclared_capability(format!("{cap:?}")));
                    }
                }

                self.status = HostStatus::Ready;
                Ok(())
            }
            PluginResponse::Error { code, message } => {
                self.status = HostStatus::Quarantined;
                Err(PluginError::protocol_violation(format!(
                    "Plugin initialization failed with error {code}: {message}"
                )))
            }
            other => {
                self.status = HostStatus::Quarantined;
                Err(PluginError::protocol_violation(format!(
                    "Expected InitializeAck, received {other:?}"
                )))
            }
        }
    }

    /// Validates pre-dispatch authorization, capability clearance, and replay protection (REQ-S02).
    pub fn prepare_execute(
        &mut self,
        task_id: &str,
        capability: &PluginCapability,
    ) -> Result<(), PluginError> {
        if self.status != HostStatus::Ready {
            return Err(PluginError::protocol_violation(format!(
                "Cannot execute job: host is in status {:?}",
                self.status
            )));
        }

        // 1. Capability fencing: Undeclared capability rejected (REQ-F16)
        if !self.manifest.supports_capability(capability) {
            return Err(PluginError::undeclared_capability(format!(
                "{capability:?}"
            )));
        }

        // 2. Replay protection: Task cannot be dispatched more than once (REQ-S02)
        if self.executed_task_ids.contains(task_id) {
            return Err(PluginError::replay_rejected(task_id));
        }

        self.executed_task_ids.insert(task_id.to_string());
        self.status = HostStatus::Executing;
        Ok(())
    }

    /// Validates an incoming stdout/stderr frame and tracks cumulative quotas (REQ-S06).
    pub fn record_output_frame(&mut self, frame_bytes: usize) -> Result<(), PluginError> {
        // Frame byte limit check
        if frame_bytes > self.manifest.quotas.max_frame_bytes {
            self.status = HostStatus::Quarantined;
            return Err(PluginError::output_quota_exceeded(
                frame_bytes,
                self.manifest.quotas.max_frame_bytes,
            ));
        }

        // Cumulative output limit check
        let new_total = self.cumulative_output_bytes.saturating_add(frame_bytes);
        if new_total > self.manifest.quotas.max_total_output_bytes {
            self.status = HostStatus::Quarantined;
            return Err(PluginError::output_quota_exceeded(
                new_total,
                self.manifest.quotas.max_total_output_bytes,
            ));
        }

        self.cumulative_output_bytes = new_total;
        Ok(())
    }

    /// Concludes an active execution and returns the host to ready status.
    pub fn complete_execute(&mut self) -> Result<(), PluginError> {
        if self.status != HostStatus::Executing {
            return Err(PluginError::protocol_violation(format!(
                "Cannot complete execution: host is in status {:?}",
                self.status
            )));
        }
        self.status = HostStatus::Ready;
        Ok(())
    }

    /// Handles unexpected process crashes or non-zero terminations cleanly.
    pub fn handle_process_crash(&mut self, exit_code: Option<i32>) -> PluginError {
        self.status = HostStatus::Terminated;
        PluginError::process_crash(exit_code)
    }

    /// Checks if a given error indicates that the plugin was quarantined.
    pub fn is_quarantined(&self) -> bool {
        self.status == HostStatus::Quarantined
    }
}
