//! JSON-RPC 2.0 message schemas, protocol revision negotiation, tool definitions, and
//! transport gating for the Model Context Protocol (REQ-F17, ADR-0005).
//!
//! Sentra implements the *legacy* (initialize-handshake) era of MCP: revisions
//! `2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05`. The handshake-less
//! *modern* revision `2026-07-28` (per-request `_meta`, `server/discover`,
//! `UnsupportedProtocolVersionError` -32022) is published but NOT implemented, so
//! the server never advertises it. Dual-era clients probing with `server/discover`
//! receive a non-modern error (-32601) and fall back to `initialize`, as the
//! 2026-07-28 stdio binding specifies.
//! Source: <https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning>.

use serde::{Deserialize, Serialize};

use crate::mcp::error::McpErrorObject;

/// Latest MCP protocol revision this server implements (legacy handshake era).
pub const LATEST_PROTOCOL_VERSION: &str = "2025-11-25";

/// Officially published legacy MCP revisions this server can negotiate, newest first.
///
/// Source: <https://modelcontextprotocol.io/llms.txt> (specification revisions
/// 2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25; 2026-07-28 is modern-only).
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 4] =
    ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// The only negotiated revision whose base protocol requires receiving JSON-RPC
/// batches (2025-03-26 "MUST support receiving JSON-RPC batches"; removed in 2025-06-18).
pub const BATCH_PROTOCOL_VERSION: &str = "2025-03-26";

/// Negotiates the protocol revision for a legacy `initialize` request.
///
/// Per the 2025-11-25 lifecycle: when the server supports the requested revision it
/// MUST respond with the same revision; otherwise it responds with the latest
/// revision it supports.
pub fn negotiate_protocol_version(requested: &str) -> &'static str {
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .find(|supported| *supported == requested)
        .unwrap_or(LATEST_PROTOCOL_VERSION)
}

/// Unique request identifier in JSON-RPC 2.0 (string or integer; MCP forbids null).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// Integer request identifier.
    Number(i64),
    /// String request identifier.
    String(String),
}

/// JSON-RPC 2.0 request envelope received over the transport.
///
/// `id: None` marks a notification. [`crate::mcp::McpServer::handle_request`] refuses
/// to execute notifications; the transport routes them to
/// [`crate::mcp::McpServer::handle_notification`] instead.
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

/// JSON-RPC 2.0 response envelope returned to the client.
///
/// `id: None` serializes as `"id": null`, which JSON-RPC 2.0 requires when the id of
/// an invalid request or unparseable message cannot be determined.
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

/// Behavioural hints for a tool (MCP `ToolAnnotations`, revision 2025-03-26 and later).
///
/// Annotations are descriptive metadata for clients, never a security boundary; the
/// server enforces confinement and approval itself.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    /// Human-readable display title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// True when the tool does not modify its environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    /// True when a non-read-only tool may perform destructive updates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    /// True when repeated calls with the same arguments have no additional effect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    /// True when the tool interacts with an open world of external entities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

impl ToolAnnotations {
    /// Read-only, closed-world tool that only inspects local inputs.
    pub fn read_only(title: &str) -> Self {
        Self {
            title: Some(title.to_string()),
            read_only_hint: Some(true),
            destructive_hint: None,
            idempotent_hint: Some(true),
            open_world_hint: Some(false),
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
    /// Behavioural hints (descriptive only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

/// Verifies that the transport mechanism conforms to isolation boundaries (ADR-0005, EXTENSIONS.md).
///
/// Local stdio is the primary permitted transport.
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

/// Generate-prompt roles accepted by `sentra_generate_prompt` (schema enum).
pub const PROMPT_ROLES: [&str; 5] = ["scout", "analyst", "validator", "patch_author", "verifier"];

/// Generate-prompt workflows accepted by `sentra_generate_prompt` (schema enum).
pub const PROMPT_WORKFLOWS: [&str; 7] = [
    "general",
    "threat-model",
    "api-bola",
    "patch-remediation",
    "skill-audit",
    "scout",
    "verify",
];

/// Returns the canonical tool definitions exposed by the Sentra MCP server.
///
/// Every tool is backed by a core service or reports an explicit tool error; none
/// writes to the filesystem. Skill and MCP-config installation is an operator action
/// available only through the CLI (`sentra install`), never to a model.
pub fn canonical_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "sentra_discover_workspace".to_string(),
            description: "Read-only lockfile inventory of a directory inside the server's launch root: lists discovered lockfiles (workspace-relative paths, format, OSV ecosystem, package counts, parse errors). Nothing is executed or written; links are not followed (REQ-F01).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "workspace_root": {
                        "type": "string",
                        "description": "Directory to inventory, relative to the server's launch root (absolute paths must also resolve inside it). Defaults to the launch root."
                    },
                    "max_depth": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": crate::advisory::MAX_INVENTORY_DEPTH,
                        "description": "Maximum directory depth to walk. Defaults to 6."
                    }
                }
            }),
            annotations: Some(ToolAnnotations::read_only("Discover workspace lockfiles")),
        },
        ToolDefinition {
            name: "sentra_get_session_status".to_string(),
            description: "Reports the persisted Sentra session (state, classification floor, context generation, budget micro-USD) for the launch root from the local store passed at launch (`sentra mcp --database <file>`). Returns a tool error when no store is configured (REQ-F14).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {}
            }),
            annotations: Some(ToolAnnotations::read_only("Get persisted session status")),
        },
        ToolDefinition {
            name: "sentra_audit_dependencies".to_string(),
            description: "Audits lockfile content (Cargo.lock, package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock, deno.lock, requirements.txt, poetry.lock, Pipfile.lock, go.sum, composer.lock, packages.lock.json, Gemfile.lock) against the small bundled pinned advisory sample (REQ-F07). It is not a synchronized OSV or RustSec feed; the result reports the sample's curation date and whether it is stale.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "lockfile_content": {
                        "type": "string",
                        "description": "Content of the lockfile to inspect (must not be empty; content that is not a lockfile of the named kind is rejected with lockfile_parse_failed)"
                    },
                    "lockfile_name": {
                        "type": "string",
                        "description": "Lockfile filename that selects the parser (e.g. package-lock.json, bun.lock). Defaults to Cargo.lock; unsupported names are rejected."
                    }
                },
                "required": ["lockfile_content"]
            }),
            annotations: Some(ToolAnnotations::read_only("Audit dependencies")),
        },
        ToolDefinition {
            name: "sentra_list_findings".to_string(),
            description: "Not implemented: Sentra Core does not persist findings yet, so this tool always returns a tool error explaining that no finding store exists. Use sentra_scan_code or sentra_audit_dependencies for on-demand, unverified candidate signals (REQ-F05, REQ-F06).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "min_severity": {
                        "type": "string",
                        "enum": ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "description": "Optional minimum severity filter"
                    }
                }
            }),
            annotations: Some(ToolAnnotations::read_only("List persisted findings")),
        },
        ToolDefinition {
            name: "sentra_propose_patch".to_string(),
            description: "Records a candidate unified diff proposal against a base revision and returns its content digest. The patch is never applied to any checkout (REQ-F11).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "base_revision": {
                        "type": "string",
                        "description": "Base Git commit or snapshot revision identifier"
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
            annotations: Some(ToolAnnotations::read_only("Propose patch")),
        },
        ToolDefinition {
            name: "sentra_request_approval".to_string(),
            description: "Records a human approval request for a sensitive action in this server process's memory and returns an unpredictable ticket. External agents CANNOT approve their own requests, and no operator grant path is exposed over MCP (REQ-S02, REQ-S10).".to_string(),
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
            annotations: Some(ToolAnnotations {
                title: Some("Request human approval".to_string()),
                read_only_hint: Some(false),
                destructive_hint: Some(false),
                idempotent_hint: Some(false),
                open_world_hint: Some(false),
            }),
        },
        ToolDefinition {
            name: "sentra_scan_code".to_string(),
            description: "Scans a file or directory inside the server's launch root for secrets, API tokens, and code antipatterns using heuristic line-based rules. Paths outside the launch root, missing paths and unreadable files return a tool error. Results are unverified candidates (REQ-F05).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File or directory to scan, relative to the server's launch root (absolute paths must also resolve inside it). Defaults to the launch root."
                    }
                }
            }),
            annotations: Some(ToolAnnotations::read_only("Scan code")),
        },
        ToolDefinition {
            name: "sentra_codeql_ingest".to_string(),
            description: "Parses GitHub CodeQL SARIF v2.1.0 content and summarizes its results and interprocedural taint flows (REQ-F05, REQ-F16). Nothing is persisted.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "sarif_content": {
                        "type": "string",
                        "description": "Raw JSON content of the CodeQL SARIF v2.1.0 report"
                    }
                },
                "required": ["sarif_content"]
            }),
            annotations: Some(ToolAnnotations::read_only("Ingest CodeQL SARIF")),
        },
        ToolDefinition {
            name: "sentra_get_security_guidance".to_string(),
            description: "Retrieves a bundled AppSec playbook by skill identifier or search keyword (REQ-F17).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "topic": {
                        "type": "string",
                        "description": "Skill identifier or search keyword (e.g. 'api-security-testing', 'threat-model', 'auth-patterns', 'golang-security', 'django-security', 'ci-cd-security')"
                    }
                },
                "required": ["topic"]
            }),
            annotations: Some(ToolAnnotations::read_only("Get security guidance")),
        },
        ToolDefinition {
            name: "sentra_generate_prompt".to_string(),
            description: "Generates role-grounded AppSec prompts (STRIDE threat models, BOLA analyses, 3-tier patch remediation requests, skill audits, reconnaissance, verification) with optional bundled-skill injection (REQ-F04, REQ-F17).".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "role": {
                        "type": "string",
                        "enum": PROMPT_ROLES,
                        "description": "AppSec research persona/role for the general workflow (default analyst). Other workflows use a fixed persona (scout and threat-model: scout; api-bola and skill-audit: analyst; patch-remediation: patch_author; verify: verifier); a different role is rejected. The result reports the persona actually used."
                    },
                    "workflow": {
                        "type": "string",
                        "enum": PROMPT_WORKFLOWS,
                        "description": "Target AppSec reasoning workflow. Defaults to general."
                    },
                    "scope": {
                        "type": "string",
                        "description": "Optional file path, endpoint, or component under evaluation"
                    },
                    "skills": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional bundled skill IDs to inject into the system prompt (e.g. ['golang-security', 'auth-implementation-patterns'])"
                    },
                    "context": {
                        "type": "string",
                        "description": "Optional architectural description, code snippet, or test evidence"
                    }
                }
            }),
            annotations: Some(ToolAnnotations::read_only("Generate AppSec prompt")),
        },
    ]
}
