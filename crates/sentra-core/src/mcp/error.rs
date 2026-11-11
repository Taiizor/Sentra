//! Strongly-typed error objects and JSON-RPC 2.0 error codes for the Model Context Protocol (REQ-F17).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Standard JSON-RPC 2.0 codes plus Sentra implementation-defined server error codes
/// (the JSON-RPC 2.0 reserved range -32000 to -32099). Sentra speaks the legacy MCP
/// handshake era (2025-11-25 and earlier); see [`crate::mcp::protocol`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpErrorCode {
    /// Invalid JSON was received by the server (-32700).
    ParseError = -32700,
    /// The JSON sent is not a valid Request object (-32600).
    InvalidRequest = -32600,
    /// The method does not exist / is not available (-32601).
    MethodNotFound = -32601,
    /// Invalid method parameter(s) (-32602).
    InvalidParams = -32602,
    /// Internal JSON-RPC / server error (-32603).
    InternalError = -32603,
    /// Caller is not authorized for the requested operation (-32001).
    Unauthorized = -32001,
    /// Operation denied by security policy or boundary constraint (-32002).
    PolicyDenied = -32002,
    /// Action requires explicit human approval before execution (-32003).
    HumanApprovalRequired = -32003,
    /// Server handshake has not been initialized (-32004).
    ServerNotInitialized = -32004,
    /// Requested resource or finding was not found (-32005).
    ResourceNotFound = -32005,
}

impl McpErrorCode {
    /// Returns the integer code value.
    pub const fn code(&self) -> i32 {
        *self as i32
    }
}

/// JSON-RPC 2.0 compliant error object returned in failed responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpErrorObject {
    /// Numeric error code.
    pub code: i32,
    /// Short description of the error.
    pub message: String,
    /// Optional structured diagnostic data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl McpErrorObject {
    /// Constructs a new error object.
    pub fn new(code: McpErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.code(),
            message: message.into(),
            data: None,
        }
    }

    /// Constructs an error object with attached diagnostic data.
    pub fn with_data(
        code: McpErrorCode,
        message: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        Self {
            code: code.code(),
            message: message.into(),
            data: Some(data),
        }
    }

    /// Helper for parse error (-32700).
    pub fn parse_error(details: impl Into<String>) -> Self {
        Self::new(
            McpErrorCode::ParseError,
            format!("Parse error: {}", details.into()),
        )
    }

    /// Helper for invalid request (-32600).
    pub fn invalid_request(details: impl Into<String>) -> Self {
        Self::new(McpErrorCode::InvalidRequest, details)
    }

    /// Helper for method not found (-32601).
    pub fn method_not_found(method: impl Into<String>) -> Self {
        let m = method.into();
        Self::new(
            McpErrorCode::MethodNotFound,
            format!("Method '{m}' not found"),
        )
    }

    /// Helper for an unknown tool name in `tools/call` (-32602), as in the MCP tools
    /// specification example (`"Unknown tool: invalid_tool_name"`).
    pub fn unknown_tool(name: impl Into<String>) -> Self {
        let n = name.into();
        Self::new(McpErrorCode::InvalidParams, format!("Unknown tool: {n}"))
    }

    /// Helper for invalid parameters (-32602).
    pub fn invalid_params(details: impl Into<String>) -> Self {
        Self::new(McpErrorCode::InvalidParams, details)
    }

    /// Helper for policy denied (-32002).
    pub fn policy_denied(details: impl Into<String>) -> Self {
        Self::new(McpErrorCode::PolicyDenied, details)
    }

    /// Helper for human approval required (-32003).
    pub fn human_approval_required(action: impl Into<String>) -> Self {
        let a = action.into();
        Self::new(
            McpErrorCode::HumanApprovalRequired,
            format!("Action '{a}' requires explicit human approval before execution"),
        )
    }

    /// Helper for uninitialized server (-32004).
    pub fn server_not_initialized() -> Self {
        Self::new(
            McpErrorCode::ServerNotInitialized,
            "Server must be initialized before dispatching tool calls",
        )
    }

    /// Helper for internal error (-32603).
    pub fn internal_error(details: impl Into<String>) -> Self {
        Self::new(McpErrorCode::InternalError, details)
    }
}

impl fmt::Display for McpErrorObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for McpErrorObject {}
