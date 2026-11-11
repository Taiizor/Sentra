//! Supervised stdio transport framing and message classification for MCP (REQ-F17, ADR-0005).
//!
//! Framing follows the MCP stdio binding: one JSON-RPC message per newline-delimited
//! line, UTF-8 encoded, with no embedded newlines in output. Lines are read with a hard
//! byte quota *while streaming*, so an oversized line is discarded without being
//! buffered. Classification follows JSON-RPC 2.0 and the MCP base protocol:
//!
//! * unparseable bytes or invalid UTF-8 -> `-32700` with `id: null`;
//! * valid JSON that is not a valid request/notification -> `-32600` (the id is echoed
//!   when it is a valid string or integer, otherwise `null`);
//! * `id: null` -> `-32600` (MCP: "the ID MUST NOT be null");
//! * notifications (no `id`) are never executed as requests and never answered;
//! * responses sent by the client are ignored (this server issues no requests);
//! * arrays are JSON-RPC batches, accepted only when revision `2025-03-26` was
//!   negotiated (the only supported revision that requires batch receipt).

use std::io::{self, BufRead, ErrorKind, Write};

use serde_json::{Map, Value};

use crate::mcp::{
    error::McpErrorObject,
    protocol::{BATCH_PROTOCOL_VERSION, McpRequest, McpResponse, RequestId},
    server::McpServer,
};

/// Maximum allowed byte size for a single stdio line in the MCP transport (1 MiB ceiling).
pub const DEFAULT_MAX_LINE_BYTES: usize = 1_048_576;

/// Fallback line emitted only if serializing a response unexpectedly fails.
const SERIALIZATION_FAILURE_LINE: &str = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"Failed to serialize response\"}}\n";

/// One framed line read from the transport by [`read_bounded_line`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportLine {
    /// The stream reached end-of-file before any byte of a new line.
    Eof,
    /// A complete line (or the final unterminated line) without its `\n` / `\r\n`.
    Line(Vec<u8>),
    /// The line exceeded the quota; its bytes were consumed and discarded unbuffered.
    Oversized {
        /// Total bytes consumed for the discarded line, including the terminator.
        consumed_bytes: usize,
    },
}

/// Reads one newline-delimited line, holding at most `max_line_bytes` in memory.
///
/// Once the line content exceeds the quota, the remainder is consumed from the
/// reader's buffer chunk by chunk (never accumulated) until the terminating newline or
/// EOF, and [`TransportLine::Oversized`] is returned.
pub fn read_bounded_line<R>(reader: &mut R, max_line_bytes: usize) -> io::Result<TransportLine>
where
    R: BufRead + ?Sized,
{
    let mut line = Vec::new();
    let mut consumed = 0usize;
    let mut oversized = false;
    loop {
        let available = match reader.fill_buf() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            if consumed == 0 {
                return Ok(TransportLine::Eof);
            }
            break;
        }
        let newline = available.iter().position(|&byte| byte == b'\n');
        let (content_len, chunk_len) = match newline {
            Some(index) => (index, index + 1),
            None => (available.len(), available.len()),
        };
        if !oversized {
            if line.len().saturating_add(content_len) > max_line_bytes {
                oversized = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(&available[..content_len]);
            }
        }
        reader.consume(chunk_len);
        consumed = consumed.saturating_add(chunk_len);
        if newline.is_some() {
            break;
        }
    }
    if oversized {
        return Ok(TransportLine::Oversized {
            consumed_bytes: consumed,
        });
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(TransportLine::Line(line))
}

/// Serves MCP over a newline-delimited byte stream until EOF.
///
/// Every line is answered (or deliberately not answered, for notifications) before
/// the next is read. Oversized lines get a `-32600` error with `id: null` (the id
/// cannot be recovered without buffering the line) and invalid UTF-8 gets `-32700`;
/// neither stops the server. Only I/O failures of `reader` or `writer` end the loop
/// with an error.
pub fn run_stdio<R, W>(
    server: &mut McpServer,
    reader: &mut R,
    writer: &mut W,
    max_line_bytes: usize,
) -> io::Result<()>
where
    R: BufRead + ?Sized,
    W: Write + ?Sized,
{
    loop {
        let outgoing = match read_bounded_line(reader, max_line_bytes)? {
            TransportLine::Eof => return Ok(()),
            TransportLine::Line(bytes) => process_transport_bytes(server, &bytes),
            TransportLine::Oversized { consumed_bytes } => {
                Some(oversized_line_response(consumed_bytes, max_line_bytes))
            }
        };
        if let Some(line) = outgoing {
            writer.write_all(line.as_bytes())?;
            writer.flush()?;
        }
    }
}

/// Processes one framed line given as raw bytes; returns the newline-terminated
/// response line, or `None` when nothing must be sent (blank line, notification,
/// client response, or a batch made only of notifications).
pub fn process_transport_bytes(server: &mut McpServer, line: &[u8]) -> Option<String> {
    match std::str::from_utf8(line) {
        Ok(text) => process_message_text(server, text),
        Err(_) => Some(encode(&McpResponse::error(
            None,
            McpErrorObject::parse_error("message is not valid UTF-8"),
        ))),
    }
}

/// Processes a single stdio line, dispatching the JSON-RPC message to the MCP server.
///
/// Kept for callers that already hold the whole line as text. The quota is enforced on
/// the given line; prefer [`run_stdio`] / [`read_bounded_line`], which enforce it before
/// buffering. Always returns `Ok`; the `Result` is retained for API compatibility.
pub fn process_transport_line(
    server: &mut McpServer,
    line: &str,
    max_line_bytes: usize,
) -> Result<Option<String>, McpErrorObject> {
    let content = line.strip_suffix('\n').unwrap_or(line);
    let content = content.strip_suffix('\r').unwrap_or(content);
    if content.len() > max_line_bytes {
        return Ok(Some(oversized_line_response(line.len(), max_line_bytes)));
    }
    Ok(process_message_text(server, content))
}

fn oversized_line_response(consumed_bytes: usize, max_line_bytes: usize) -> String {
    encode(&McpResponse::error(
        None,
        McpErrorObject::invalid_request(format!(
            "Incoming line of {consumed_bytes} bytes exceeded the maximum quota of {max_line_bytes} bytes and was discarded"
        )),
    ))
}

fn process_message_text(server: &mut McpServer, text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let value: Value = match serde_json::from_str(trimmed) {
        Ok(value) => value,
        Err(error) => {
            return Some(encode(&McpResponse::error(
                None,
                McpErrorObject::parse_error(format!("Malformed JSON: {error}")),
            )));
        }
    };
    match value {
        Value::Array(items) => dispatch_batch(server, items),
        other => dispatch_single(server, other).map(|response| encode(&response)),
    }
}

fn dispatch_batch(server: &mut McpServer, items: Vec<Value>) -> Option<String> {
    if items.is_empty() {
        return Some(encode(&McpResponse::error(
            None,
            McpErrorObject::invalid_request("Empty JSON-RPC batch"),
        )));
    }
    if server.negotiated_protocol_version() != Some(BATCH_PROTOCOL_VERSION) {
        return Some(encode(&McpResponse::error(
            None,
            McpErrorObject::invalid_request(
                "JSON-RPC batches are not supported by the negotiated MCP protocol revision",
            ),
        )));
    }
    let mut responses = Vec::new();
    for item in items {
        let response = if is_initialize(&item) {
            Some(McpResponse::error(
                valid_id(&item),
                McpErrorObject::invalid_request(
                    "The initialize request MUST NOT be part of a JSON-RPC batch",
                ),
            ))
        } else {
            dispatch_single(server, item)
        };
        responses.extend(response);
    }
    if responses.is_empty() {
        return None;
    }
    match serde_json::to_string(&responses) {
        Ok(mut json) => {
            json.push('\n');
            Some(json)
        }
        Err(_) => Some(SERIALIZATION_FAILURE_LINE.to_string()),
    }
}

/// Classifies and dispatches one non-batch JSON value.
fn dispatch_single(server: &mut McpServer, value: Value) -> Option<McpResponse> {
    let Value::Object(map) = value else {
        return Some(McpResponse::error(
            None,
            McpErrorObject::invalid_request("A JSON-RPC message must be a JSON object"),
        ));
    };
    if !map.contains_key("method") && (map.contains_key("result") || map.contains_key("error")) {
        // A response from the client. This server never sends requests, so there is
        // nothing to correlate, and JSON-RPC forbids replying to a response.
        return None;
    }
    let id = match classify_id(&map) {
        IdField::Absent => None,
        IdField::Valid(id) => Some(id),
        IdField::Null => {
            return Some(McpResponse::error(
                None,
                McpErrorObject::invalid_request(
                    "Request id must be a string or integer; MCP forbids a null id",
                ),
            ));
        }
        IdField::Invalid => {
            return Some(McpResponse::error(
                None,
                McpErrorObject::invalid_request("Request id must be a string or integer"),
            ));
        }
    };

    if map.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(McpResponse::error(
            id,
            McpErrorObject::invalid_request(
                "Invalid or missing 'jsonrpc' member; expected \"2.0\"",
            ),
        ));
    }

    let Some(method_value) = map.get("method") else {
        return Some(McpResponse::error(
            id,
            McpErrorObject::invalid_request("Missing 'method' member"),
        ));
    };
    let Some(method) = method_value.as_str() else {
        return Some(McpResponse::error(
            id,
            McpErrorObject::invalid_request("'method' must be a string"),
        ));
    };

    let params = map.get("params").cloned();
    if let Some(params) = &params
        && !params.is_object()
        && !params.is_array()
    {
        return Some(McpResponse::error(
            id,
            McpErrorObject::invalid_request("'params' must be an object or an array"),
        ));
    }

    match id {
        None => {
            server.handle_notification(method, params.as_ref());
            None
        }
        Some(id) => Some(server.handle_request(McpRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(id),
            method: method.to_string(),
            params,
        })),
    }
}

enum IdField {
    Absent,
    Null,
    Valid(RequestId),
    Invalid,
}

fn classify_id(map: &Map<String, Value>) -> IdField {
    match map.get("id") {
        None => IdField::Absent,
        Some(Value::Null) => IdField::Null,
        Some(Value::String(text)) => IdField::Valid(RequestId::String(text.clone())),
        Some(Value::Number(number)) => match number.as_i64() {
            Some(integer) => IdField::Valid(RequestId::Number(integer)),
            None => IdField::Invalid,
        },
        Some(_) => IdField::Invalid,
    }
}

fn valid_id(value: &Value) -> Option<RequestId> {
    match value {
        Value::Object(map) => match classify_id(map) {
            IdField::Valid(id) => Some(id),
            _ => None,
        },
        _ => None,
    }
}

fn is_initialize(value: &Value) -> bool {
    value.get("method").and_then(Value::as_str) == Some("initialize")
}

/// Serializes a response as one newline-terminated line. `serde_json` escapes control
/// characters inside strings, so the output never contains an embedded newline.
fn encode(response: &McpResponse) -> String {
    match serde_json::to_string(response) {
        Ok(mut json) => {
            json.push('\n');
            json
        }
        Err(_) => SERIALIZATION_FAILURE_LINE.to_string(),
    }
}
