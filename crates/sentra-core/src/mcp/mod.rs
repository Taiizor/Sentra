//! Model Context Protocol (MCP) server, stdio transport, and shared application services boundary (REQ-F17, ADR-0005, EXTENSIONS.md).

pub mod error;
pub mod protocol;
pub mod server;
pub mod transport;

pub use error::{McpErrorCode, McpErrorObject};
pub use protocol::{
    McpRequest, McpResponse, RequestId, ToolDefinition, canonical_tool_definitions,
    verify_transport_allowed,
};
pub use server::McpServer;
pub use transport::{DEFAULT_MAX_LINE_BYTES, process_transport_line};
