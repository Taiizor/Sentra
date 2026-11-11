//! Model Context Protocol (MCP) server, stdio transport, and shared application services boundary (REQ-F17, ADR-0005, EXTENSIONS.md).
//!
//! Sentra serves the legacy initialize-handshake MCP revisions (2025-11-25, 2025-06-18,
//! 2025-03-26, 2024-11-05) over local stdio. The handshake-less 2026-07-28 revision is
//! not implemented and never advertised.

pub mod error;
pub mod protocol;
pub mod server;
pub mod transport;

pub use error::{McpErrorCode, McpErrorObject};
pub use protocol::{
    BATCH_PROTOCOL_VERSION, LATEST_PROTOCOL_VERSION, McpRequest, McpResponse, RequestId,
    SUPPORTED_PROTOCOL_VERSIONS, ToolAnnotations, ToolDefinition, canonical_tool_definitions,
    negotiate_protocol_version, verify_transport_allowed,
};
pub use server::{McpServer, SERVER_NAME};
pub use transport::{
    DEFAULT_MAX_LINE_BYTES, TransportLine, process_transport_bytes, process_transport_line,
    read_bounded_line, run_stdio,
};
