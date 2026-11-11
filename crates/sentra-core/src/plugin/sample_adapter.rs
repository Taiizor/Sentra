//! Deterministic reference adapter used for SDK conformance and adversarial testing (REQ-F16).

use crate::plugin::{
    manifest::PluginCapability,
    protocol::{PluginRequest, PluginResponse},
};

/// Operating mode for the sample adapter to test conformance and error handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleAdapterMode {
    /// Normal conformant operation.
    Standard,
    /// Simulates a plugin declaring an incompatible major interface version.
    IncompatibleVersion,
    /// Simulates a plugin attempting to declare an undeclared capability.
    UndeclaredCapability,
    /// Simulates a plugin emitting an oversized frame breaching quotas.
    OversizedOutput,
    /// Simulates a plugin that crashes during execution.
    CrashDuringExecution,
}

/// In-memory reference adapter implementing the subprocess protocol state machine.
#[derive(Clone, Debug)]
pub struct SampleAdapter {
    /// Active operating mode.
    pub mode: SampleAdapterMode,
    /// Associated plugin identifier.
    pub plugin_id: String,
}

impl SampleAdapter {
    /// Creates a new sample adapter in standard conformant mode.
    pub fn new(plugin_id: impl Into<String>) -> Self {
        Self {
            mode: SampleAdapterMode::Standard,
            plugin_id: plugin_id.into(),
        }
    }

    /// Creates a sample adapter configured in a specific test mode.
    pub fn with_mode(plugin_id: impl Into<String>, mode: SampleAdapterMode) -> Self {
        Self {
            mode,
            plugin_id: plugin_id.into(),
        }
    }

    /// Handles an incoming protocol request and returns the appropriate response.
    pub fn handle_request(&self, request: &PluginRequest) -> PluginResponse {
        match request {
            PluginRequest::Initialize { host_version: _ } => {
                let interface_version = match self.mode {
                    SampleAdapterMode::IncompatibleVersion => 999, // Incompatible version
                    _ => 1,
                };

                let capabilities = match self.mode {
                    SampleAdapterMode::UndeclaredCapability => {
                        vec![PluginCapability::Custom(
                            "unauthorized_root_exec".to_string(),
                        )]
                    }
                    _ => vec![
                        PluginCapability::SourceDiscovery,
                        PluginCapability::StaticAnalysis,
                    ],
                };

                PluginResponse::InitializeAck {
                    plugin_id: self.plugin_id.clone(),
                    interface_version,
                    capabilities,
                }
            }
            PluginRequest::Probe { workspace_root } => PluginResponse::ProbeResult {
                applicable: !workspace_root.contains("unsupported"),
                details: "Sample Static Analysis Tool v1.0.0".to_string(),
                unsupported_reason: if workspace_root.contains("unsupported") {
                    Some("Target directory marked unsupported".to_string())
                } else {
                    None
                },
            },
            PluginRequest::Plan { input_ref } => PluginResponse::PlanResult {
                input_refs: vec![input_ref.clone()],
                predicted_cost_micro_usd: 100_000,
                required_capabilities: vec![PluginCapability::StaticAnalysis],
            },
            PluginRequest::Execute {
                task_id,
                lease_id: _,
                capability: _,
                arguments,
                ..
            } => {
                match self.mode {
                    SampleAdapterMode::OversizedOutput => {
                        // Produce an oversized response string
                        let large_payload = "A".repeat(2_000_000); // 2 MiB > 1 MiB limit
                        PluginResponse::ExecuteResult {
                            task_id: task_id.clone(),
                            exit_code: 0,
                            evidence_refs: vec![],
                            summary: large_payload,
                        }
                    }
                    SampleAdapterMode::CrashDuringExecution => PluginResponse::Error {
                        code: 139, // SIGSEGV equivalent
                        message: "Process terminated with fatal signal 11 (SIGSEGV)".to_string(),
                    },
                    _ => {
                        let arg_str = arguments.to_string();
                        PluginResponse::ExecuteResult {
                            task_id: task_id.clone(),
                            exit_code: 0,
                            evidence_refs: vec![format!("sha256:evidence-{}", task_id)],
                            summary: format!(
                                "Analysis complete on args (length: {})",
                                arg_str.len()
                            ),
                        }
                    }
                }
            }
            PluginRequest::Cancel { task_id } => PluginResponse::CancelAck {
                task_id: task_id.clone(),
                terminated: true,
            },
            PluginRequest::Shutdown => PluginResponse::ShutdownAck,
        }
    }
}
