//! JSON-RPC 2.0 message schemas, tool definitions, and transport gating (MCP Revision 2026-07-28, REQ-F17, ADR-0005).

use serde::{Deserialize, Serialize};

use crate::mcp::error::McpErrorObject;

/// Unique request identifier in JSON-RPC 2.0 (string or integer).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// Integer request identifier.
    Number(i64),
    /// String request identifier.
    String(String),
}

/// JSON-RPC 2.0 compliant request envelope received over the transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRequest {
    /// Protocol version string (MUST be "2.0").
    pub jsonrpc: String,
    /// Request correlation identifier.
    pub id: Option<RequestId>,
    /// Target method to invoke.
    pub method: String,
    /// Optional parameter payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 compliant response envelope returned to the client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpResponse {
    /// Protocol version string ("2.0").
    pub jsonrpc: String,
    /// Request correlation identifier matching the request.
    pub id: Option<RequestId>,
    /// Result payload if call succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error object if call failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpErrorObject>,
}

impl McpResponse {
    /// Creates a successful response envelope.
    pub fn success(id: Option<RequestId>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Creates an error response envelope.
    pub fn error(id: Option<RequestId>, error: McpErrorObject) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// Specification of an exposed application tool callable by an external model or agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Unique name of the tool (prefixed with `sentra_`).
    pub name: String,
    /// Human and model-readable description of tool capabilities.
    pub description: String,
    /// JSON Schema object describing the expected input parameters.
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// Verifies that the transport mechanism conforms to isolation boundaries (ADR-0005, EXTENSIONS.md).
///
/// Local stdio is the sole permitted transport in Phase 4.
/// Remote HTTP remains strictly disabled until authentication, authorization, and SSRF gates pass.
pub fn verify_transport_allowed(transport: &str) -> Result<(), McpErrorObject> {
    match transport.to_ascii_lowercase().as_str() {
        "stdio" => Ok(()),
        "http" | "https" => Err(McpErrorObject::policy_denied(
            "Remote HTTP transport remains disabled until authentication and SSRF protection gates pass (ADR-0005)",
        )),
        other => Err(McpErrorObject::policy_denied(format!(
            "Unsupported MCP transport: '{other}'. Local stdio is the sole permitted transport"
        ))),
    }
}

/// Returns the 6 canonical tool definitions exposed by the Sentra MCP server.
pub fn canonical_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "sentra_discover_workspace".to_string(),
            description: "Performs deterministic, metadata-only source discovery and component enumeration without executing target code (REQ-F01).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "workspace_root": {
                        "type": "string",
                        "description": "Path to the target workspace root directory"
                    }
                },
                "required": ["workspace_root"]
            }),
        },
        ToolDefinition {
            name: "sentra_get_session_status".to_string(),
            description: "Inspects active session state, current operating mode, and settled budget micro-USD metrics (REQ-F14).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        },
        ToolDefinition {
            name: "sentra_audit_dependencies".to_string(),
            description: "Audits Cargo.lock dependencies against the pinned RustSec advisory database (REQ-F07).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "cargo_lock_content": {
                        "type": "string",
                        "description": "Content of the Cargo.lock file to inspect"
                    }
                },
                "required": ["cargo_lock_content"]
            }),
        },
        ToolDefinition {
            name: "sentra_list_findings".to_string(),
            description: "Retrieves normalized candidate, validated, and inconclusive security findings with status transition reasons (REQ-F05, REQ-F06).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "min_severity": {
                        "type": "string",
                        "enum": ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "description": "Optional minimum severity filter"
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "sentra_propose_patch".to_string(),
            description: "Proposes a candidate unified diff patch against a base revision with an expected test oracle (REQ-F11).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "base_revision": {
                        "type": "string",
                        "description": "Base Git commit or snapshot revision SHA-256"
                    },
                    "patch_diff": {
                        "type": "string",
                        "description": "Unified diff text representing the proposed remediating changes"
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Explanatory rationale for the patch"
                    }
                },
                "required": ["base_revision", "patch_diff", "rationale"]
            }),
        },
        ToolDefinition {
            name: "sentra_request_approval".to_string(),
            description: "Submits a human approval request for sensitive actions (e.g. checkout mutation, external dispatch). External agents CANNOT approve their own requests (REQ-S02, REQ-S10).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action_name": {
                        "type": "string",
                        "description": "Name of the sensitive action requiring approval"
                    },
                    "action_summary": {
                        "type": "string",
                        "description": "Human-readable summary of the proposed action"
                    }
                },
                "required": ["action_name", "action_summary"]
            }),
        },
    ]
}
