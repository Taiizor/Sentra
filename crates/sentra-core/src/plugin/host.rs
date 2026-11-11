//! Host orchestrator managing plugin lifecycle, capability fencing, and quota boundaries (REQ-F16, EXTENSIONS.md).

use std::collections::HashSet;

use crate::plugin::{
    error::PluginError,
    manifest::{PLUGIN_INTERFACE_VERSION, PluginCapability, PluginManifest},
    protocol::{PluginRequest, PluginResponse},
};

/// Most evidence labels accepted in one `execute_result`.
pub const MAX_EVIDENCE_REFS: usize = 1_024;

/// Longest accepted task identifier.
const MAX_TASK_ID_LEN: usize = 128;

/// Longest accepted evidence label value (after the scheme).
const MAX_EVIDENCE_VALUE_LEN: usize = 256;

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
    /// Task IDs already dispatched by this host instance (replay protection within the
    /// lifetime of this value only; nothing is persisted).
    pub executed_task_ids: HashSet<String>,
    /// Cumulative output bytes observed across stdout frames and stderr in this session.
    pub cumulative_output_bytes: usize,
    /// Capabilities the adapter acknowledged in the current session's handshake.
    pub negotiated_capabilities: Vec<PluginCapability>,
}

impl PluginHost {
    /// Initializes a plugin host from an authorized manifest.
    pub fn new(manifest: PluginManifest) -> Result<Self, PluginError> {
        manifest.validate()?;
        Ok(Self {
            manifest,
            status: HostStatus::Uninitialized,
            supported_interface_version: PLUGIN_INTERFACE_VERSION,
            executed_task_ids: HashSet::new(),
            cumulative_output_bytes: 0,
            negotiated_capabilities: Vec::new(),
        })
    }

    /// Resets per-process state before a new adapter process is started.
    ///
    /// Output accounting and the negotiated capability set are per session; the replay
    /// set is kept for the lifetime of the host.
    pub fn begin_session(&mut self) {
        self.status = HostStatus::Uninitialized;
        self.cumulative_output_bytes = 0;
        self.negotiated_capabilities.clear();
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
                // The manifest is valid; the adapter is the one misbehaving.
                if plugin_id != &self.manifest.id {
                    self.status = HostStatus::Quarantined;
                    return Err(PluginError::identity_mismatch(&self.manifest.id, plugin_id));
                }

                // 3. Capabilities must be declared in manifest
                for cap in capabilities {
                    if !self.manifest.supports_capability(cap) {
                        self.status = HostStatus::Quarantined;
                        return Err(PluginError::undeclared_capability(cap.as_str()));
                    }
                }

                self.negotiated_capabilities = capabilities.clone();
                self.status = HostStatus::Ready;
                Ok(())
            }
            PluginResponse::Error { code, message } => {
                self.status = HostStatus::Quarantined;
                Err(PluginError::adapter_reported(
                    *code,
                    format!("initialization failed: {message}"),
                ))
            }
            other => {
                self.status = HostStatus::Quarantined;
                Err(PluginError::protocol_violation(format!(
                    "Expected InitializeAck, received {}",
                    response_name(other)
                )))
            }
        }
    }

    /// Checks a task before any adapter process is started (REQ-F16, REQ-S02).
    ///
    /// The capability must be declared in the manifest and the task id must be well
    /// formed and not yet dispatched by this host. Nothing is recorded; the replay set is
    /// updated by [`PluginHost::prepare_execute`] once the task is actually dispatched.
    pub fn authorize_execute(
        &self,
        task_id: &str,
        capability: &PluginCapability,
    ) -> Result<(), PluginError> {
        if !is_valid_task_id(task_id) {
            return Err(PluginError::protocol_violation(format!(
                "task id must be 1-{MAX_TASK_ID_LEN} characters of [A-Za-z0-9._:-]"
            )));
        }
        if !self.manifest.supports_capability(capability) {
            return Err(PluginError::undeclared_capability(capability.as_str()));
        }
        if self.executed_task_ids.contains(task_id) {
            return Err(PluginError::replay_rejected(task_id));
        }
        Ok(())
    }

    /// Validates pre-dispatch authorization, capability clearance, and replay protection (REQ-S02).
    ///
    /// After a handshake the capability must also be one the adapter acknowledged.
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

        // 1. Capability fencing against the manifest (REQ-F16)
        self.authorize_execute(task_id, capability)?;

        // 2. Capability fencing against the negotiated set
        if !self.negotiated_capabilities.contains(capability) {
            return Err(PluginError::undeclared_capability(capability.as_str()));
        }

        self.executed_task_ids.insert(task_id.to_string());
        self.status = HostStatus::Executing;
        Ok(())
    }

    /// Validates an incoming stdout frame and tracks cumulative quotas (REQ-S06).
    pub fn record_output_frame(&mut self, frame_bytes: usize) -> Result<(), PluginError> {
        // Frame byte limit check
        if frame_bytes > self.manifest.quotas.max_frame_bytes {
            self.status = HostStatus::Quarantined;
            return Err(PluginError::frame_too_large(
                frame_bytes,
                self.manifest.quotas.max_frame_bytes,
            ));
        }
        self.record_total_output(frame_bytes)
    }

    /// Counts drained stderr bytes against the cumulative output quota (REQ-S06).
    pub fn record_stderr_bytes(&mut self, bytes: usize) -> Result<(), PluginError> {
        self.record_total_output(bytes)
    }

    fn record_total_output(&mut self, bytes: usize) -> Result<(), PluginError> {
        let new_total = self.cumulative_output_bytes.saturating_add(bytes);
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

    /// Checks that an `execute_result` belongs to the dispatched task and that every
    /// adapter-reported evidence label is well formed.
    ///
    /// Labels are opaque strings `<scheme>:<value>`; paths, URLs with `/` and `..`
    /// segments are rejected. They are never resolved or admitted as evidence.
    pub fn validate_execute_result(
        expected_task_id: &str,
        returned_task_id: &str,
        evidence_refs: &[String],
    ) -> Result<(), PluginError> {
        if returned_task_id != expected_task_id {
            return Err(PluginError::result_mismatch(format!(
                "execute_result task_id '{returned_task_id}' does not match the dispatched task '{expected_task_id}'"
            )));
        }
        if evidence_refs.len() > MAX_EVIDENCE_REFS {
            return Err(PluginError::result_mismatch(format!(
                "{} evidence references exceed the limit of {MAX_EVIDENCE_REFS}",
                evidence_refs.len()
            )));
        }
        if let Some(bad) = evidence_refs.iter().find(|r| !is_valid_evidence_ref(r)) {
            return Err(PluginError::result_mismatch(format!(
                "evidence reference '{bad}' is not a '<scheme>:<value>' label"
            )));
        }
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

/// Whether a task id is 1-128 characters of `[A-Za-z0-9._:-]`.
pub fn is_valid_task_id(task_id: &str) -> bool {
    !task_id.is_empty()
        && task_id.len() <= MAX_TASK_ID_LEN
        && task_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Whether an adapter-reported evidence label has the form `<scheme>:<value>`.
///
/// Scheme: 1-32 characters of `[a-z0-9+.-]` starting with a letter. Value: 1-256
/// characters of `[A-Za-z0-9._:+=@-]` without a `..` sequence.
pub fn is_valid_evidence_ref(evidence_ref: &str) -> bool {
    let Some((scheme, value)) = evidence_ref.split_once(':') else {
        return false;
    };
    let scheme_ok = !scheme.is_empty()
        && scheme.len() <= 32
        && scheme
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase())
        && scheme.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'.' | b'-')
        });
    let value_ok = !value.is_empty()
        && value.len() <= MAX_EVIDENCE_VALUE_LEN
        && !value.contains("..")
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'+' | b'=' | b'@' | b'-')
        });
    scheme_ok && value_ok
}

/// Short variant name of a response, without echoing adapter-controlled payloads.
pub(crate) fn response_name(response: &PluginResponse) -> &'static str {
    match response {
        PluginResponse::InitializeAck { .. } => "initialize_ack",
        PluginResponse::ProbeResult { .. } => "probe_result",
        PluginResponse::PlanResult { .. } => "plan_result",
        PluginResponse::ExecuteResult { .. } => "execute_result",
        PluginResponse::CancelAck { .. } => "cancel_ack",
        PluginResponse::ShutdownAck => "shutdown_ack",
        PluginResponse::Error { .. } => "error",
    }
}
