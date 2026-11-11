//! Supervised subprocess message protocol, JSON framing, and operation schemas (REQ-F16, EXTENSIONS.md).

use serde::{Deserialize, Serialize};

use crate::plugin::{error::PluginError, manifest::PluginCapability};

/// High-level operation requests dispatched by the host orchestrator to a plugin subprocess.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum PluginRequest {
    /// Initial handshake negotiating interface version and capabilities.
    Initialize {
        /// Orchestrator host protocol version.
        host_version: u32,
    },
    /// Asks the adapter whether it applies to a workspace. The adapter process runs
    /// with the operator's privileges while answering.
    Probe {
        /// Canonical workspace root path.
        workspace_root: String,
    },
    /// Returns proposed jobs, input refs, and required capabilities without side effects.
    Plan {
        /// Input manifest reference.
        input_ref: String,
    },
    /// Dispatches an authorized execution job.
    Execute {
        /// Associated task identifier; the adapter must echo it in `execute_result`.
        task_id: String,
        /// Dynamic authorization lease identifier.
        lease_id: String,
        /// Required capability being exercised.
        capability: PluginCapability,
        /// Canonical workspace root validated by the host, when the caller supplied one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        workspace_root: Option<String>,
        /// Structured execution arguments.
        arguments: serde_json::Value,
    },
    /// Requests premature cancellation of an active task.
    Cancel {
        /// Target task identifier.
        task_id: String,
    },
    /// Requests clean subprocess shutdown and cleanup.
    Shutdown,
}

/// Structured response messages emitted by a plugin subprocess over stdout.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PluginResponse {
    /// Successful initialization acknowledging negotiated capabilities.
    InitializeAck {
        /// Confirmed plugin identifier.
        plugin_id: String,
        /// Interface version supported by the plugin.
        interface_version: u32,
        /// Capabilities offered by the plugin.
        capabilities: Vec<PluginCapability>,
    },
    /// Probe findings indicating applicability or unsupported gap.
    ProbeResult {
        /// Whether the target codebase is supported by this adapter.
        applicable: bool,
        /// Diagnostic details or tool version info.
        details: String,
        /// Reason if unsupported.
        unsupported_reason: Option<String>,
    },
    /// Proposed execution plan with estimated resources.
    PlanResult {
        /// Ingested input references.
        input_refs: Vec<String>,
        /// Estimated cost in micro-USD.
        predicted_cost_micro_usd: u64,
        /// Capabilities required during execution.
        required_capabilities: Vec<PluginCapability>,
    },
    /// Execution outcome with exit code and evidence references (all adapter-reported).
    ExecuteResult {
        /// Target task identifier; must equal the request's task id.
        task_id: String,
        /// Adapter-reported outcome code (0 = success); not the process exit status.
        exit_code: i32,
        /// Adapter-reported evidence labels; never resolved or admitted as evidence.
        evidence_refs: Vec<String>,
        /// Concise summary of findings or results.
        summary: String,
    },
    /// Confirmation of task cancellation.
    CancelAck {
        /// Target task identifier.
        task_id: String,
        /// Whether the execution thread/process was confirmed terminated.
        terminated: bool,
    },
    /// Clean shutdown confirmation.
    ShutdownAck,
    /// Protocol or execution error response.
    Error {
        /// Numeric error code.
        code: i32,
        /// Human-readable error message.
        message: String,
    },
}

/// Encodes a protocol message as a single-line newline-delimited JSON frame.
pub fn encode_frame<T: Serialize>(message: &T) -> Result<String, PluginError> {
    let mut json = serde_json::to_string(message).map_err(|e| {
        PluginError::protocol_violation(format!("Failed to serialize protocol frame: {e}"))
    })?;

    // Strictly ensure no unescaped newlines inside the JSON body
    if json.contains('\n') || json.contains('\r') {
        json = json.replace('\r', "").replace('\n', " ");
    }

    json.push('\n');
    Ok(json)
}

/// Decodes and validates a single-line newline-delimited JSON frame against quota bounds.
pub fn decode_frame<'a, T: Deserialize<'a>>(
    line: &'a str,
    max_frame_bytes: usize,
) -> Result<T, PluginError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Err(PluginError::protocol_violation("Empty frame received"));
    }

    if trimmed.len() > max_frame_bytes {
        return Err(PluginError::frame_too_large(trimmed.len(), max_frame_bytes));
    }

    serde_json::from_str(trimmed).map_err(|e| {
        PluginError::protocol_violation(format!("Failed to parse JSON protocol frame: {e}"))
    })
}
