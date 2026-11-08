//! Supervised stdio transport framing and line processing for MCP (REQ-F17, ADR-0005).

use crate::mcp::{error::McpErrorObject, protocol::McpRequest, server::McpServer};

/// Maximum allowed byte size for a single stdio line in the MCP transport (1 MiB ceiling).
pub const DEFAULT_MAX_LINE_BYTES: usize = 1_048_576;

/// Processes a single stdio line, dispatching the JSON-RPC request to the MCP server.
///
/// Enforces quota byte limits and returns single-line newline-delimited JSON.
pub fn process_transport_line(
    server: &mut McpServer,
    line: &str,
    max_line_bytes: usize,
) -> Result<Option<String>, McpErrorObject> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    // 1. Quota check on incoming line
    if trimmed.len() > max_line_bytes {
        let err_resp = crate::mcp::protocol::McpResponse::error(
            None,
            McpErrorObject::invalid_request(format!(
                "Incoming line length {} bytes exceeded maximum quota of {} bytes",
                trimmed.len(),
                max_line_bytes
            )),
        );
        let mut json = serde_json::to_string(&err_resp).map_err(|e| {
            McpErrorObject::parse_error(format!("Failed to serialize error response: {e}"))
        })?;
        json.push('\n');
        return Ok(Some(json));
    }

    // 2. Parse JSON-RPC request
    let request: McpRequest = match serde_json::from_str(trimmed) {
        Ok(req) => req,
        Err(e) => {
            let err_resp = crate::mcp::protocol::McpResponse::error(
                None,
                McpErrorObject::parse_error(format!("Malformed JSON: {e}")),
            );
            let mut json = serde_json::to_string(&err_resp).map_err(|e| {
                McpErrorObject::parse_error(format!("Failed to serialize error response: {e}"))
            })?;
            json.push('\n');
            return Ok(Some(json));
        }
    };

    // 3. Dispatch to server
    let is_notification = request.id.is_none();
    let response = server.handle_request(request);

    // Per JSON-RPC 2.0 specification, do not respond to notifications
    if is_notification {
        return Ok(None);
    }

    // 4. Encode response
    let mut out_json = serde_json::to_string(&response)
        .map_err(|e| McpErrorObject::parse_error(format!("Failed to serialize response: {e}")))?;

    if out_json.contains('\n') || out_json.contains('\r') {
        out_json = out_json.replace('\r', "").replace('\n', " ");
    }
    out_json.push('\n');

    Ok(Some(out_json))
}
