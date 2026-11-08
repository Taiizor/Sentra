//! Model Context Protocol (MCP) server managing JSON-RPC dispatch, tool execution,
//! and human approval policy gates (REQ-F17, ADR-0005, EXTENSIONS.md).

use std::collections::{HashMap, HashSet};

use crate::{
    advisory::{AdvisoryDatabase, parse_cargo_lock},
    common::crypto::sha256_prefixed,
    domain::{TimestampUtc, id::SessionId},
    mcp::{
        error::{McpErrorCode, McpErrorObject},
        protocol::{McpRequest, McpResponse, ToolDefinition, canonical_tool_definitions},
    },
};

/// Local stdio Model Context Protocol server exposing Sentra Core services (REQ-F17).
#[derive(Clone, Debug)]
pub struct McpServer {
    /// Active research session identifier.
    pub session_id: SessionId,
    /// Protocol handshake initialization state.
    pub initialized: bool,
    /// Set of human-approved action tickets.
    pub human_approved_tickets: HashSet<String>,
    /// Pending approval requests awaiting human operator review.
    pub pending_approval_requests: HashMap<String, String>,
    /// Registered tool definitions.
    pub tools: Vec<ToolDefinition>,
}

impl McpServer {
    /// Creates a new MCP server for the specified session.
    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            initialized: false,
            human_approved_tickets: HashSet::new(),
            pending_approval_requests: HashMap::new(),
            tools: canonical_tool_definitions(),
        }
    }

    /// Grants human operator approval for a pending approval ticket (REQ-S02, REQ-S10).
    pub fn admit_human_approval(&mut self, ticket: impl Into<String>) {
        self.human_approved_tickets.insert(ticket.into());
    }

    /// Dispatches an incoming JSON-RPC 2.0 MCP request and returns a compliant response.
    pub fn handle_request(&mut self, request: McpRequest) -> McpResponse {
        let req_id = request.id;

        // 1. JSON-RPC version check
        if request.jsonrpc != "2.0" {
            return McpResponse::error(
                req_id,
                McpErrorObject::invalid_request(
                    "Invalid JSON-RPC protocol version; expected '2.0'",
                ),
            );
        }

        // 2. Method dispatch
        match request.method.as_str() {
            "initialize" => {
                self.initialized = true;
                McpResponse::success(
                    req_id,
                    serde_json::json!({
                        "protocolVersion": "2026-07-28",
                        "serverInfo": {
                            "name": "sentra-mcp",
                            "version": "0.1.0"
                        },
                        "capabilities": {
                            "tools": {
                                "listChanged": false
                            }
                        }
                    }),
                )
            }
            "notifications/initialized" => {
                // Client initialized notification; acknowledge with empty result
                McpResponse::success(req_id, serde_json::json!({}))
            }
            "ping" => McpResponse::success(req_id, serde_json::json!({})),
            "tools/list" => {
                if !self.initialized {
                    return McpResponse::error(req_id, McpErrorObject::server_not_initialized());
                }
                McpResponse::success(
                    req_id,
                    serde_json::json!({
                        "tools": self.tools
                    }),
                )
            }
            "tools/call" => {
                if !self.initialized {
                    return McpResponse::error(req_id, McpErrorObject::server_not_initialized());
                }

                let params = match request.params {
                    Some(serde_json::Value::Object(map)) => map,
                    _ => {
                        return McpResponse::error(
                            req_id,
                            McpErrorObject::invalid_params("Expected object payload for 'params'"),
                        );
                    }
                };

                let tool_name = match params.get("name").and_then(|v| v.as_str()) {
                    Some(n) => n,
                    None => {
                        return McpResponse::error(
                            req_id,
                            McpErrorObject::invalid_params(
                                "Missing or invalid 'name' in tool call",
                            ),
                        );
                    }
                };

                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));

                match self.execute_tool(tool_name, arguments) {
                    Ok(result) => McpResponse::success(req_id, result),
                    Err(err) => McpResponse::error(req_id, err),
                }
            }
            unknown => McpResponse::error(req_id, McpErrorObject::method_not_found(unknown)),
        }
    }

    /// Executes an individual tool call enforcing authorization and human approval gates (REQ-F17).
    fn execute_tool(
        &mut self,
        name: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, McpErrorObject> {
        match name {
            "sentra_discover_workspace" => {
                let root = args
                    .get("workspace_root")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        McpErrorObject::invalid_params("Missing required 'workspace_root' argument")
                    })?;

                Ok(serde_json::json!({
                    "workspace_root": root,
                    "status": "Discovered",
                    "components": ["crates/sentra-core", "crates/sentra-cli"],
                    "discovery_mode": "metadata_only",
                    "target_code_executed": false
                }))
            }
            "sentra_get_session_status" => Ok(serde_json::json!({
                "session_id": self.session_id.to_string(),
                "state": "Scoped",
                "operating_mode": "ContinuousReview",
                "budget_reserved_micro_usd": 0,
                "budget_spent_micro_usd": 0
            })),
            "sentra_audit_dependencies" => {
                let lock_content = args
                    .get("cargo_lock_content")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        McpErrorObject::invalid_params(
                            "Missing required 'cargo_lock_content' argument",
                        )
                    })?;

                let packages = parse_cargo_lock(lock_content).map_err(|e| {
                    McpErrorObject::new(
                        McpErrorCode::InvalidParams,
                        format!("Failed to parse Cargo.lock: {e}"),
                    )
                })?;

                let now = TimestampUtc::now();
                let db = AdvisoryDatabase::default_pinned(now);
                let audit_result = db
                    .audit_packages(&packages, now, 30)
                    .map_err(|e| McpErrorObject::internal_error(format!("Audit failed: {e}")))?;

                Ok(serde_json::json!({
                    "packages_audited": audit_result.packages_audited,
                    "vulnerabilities_found": audit_result.matches.len(),
                    "advisories_matched": audit_result.matches.iter().map(|f| &f.advisory.id).collect::<Vec<_>>()
                }))
            }
            "sentra_list_findings" => Ok(serde_json::json!({
                "session_id": self.session_id.to_string(),
                "findings": []
            })),
            "sentra_propose_patch" => {
                let base_rev = args
                    .get("base_revision")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        McpErrorObject::invalid_params("Missing required 'base_revision' argument")
                    })?;
                let diff = args
                    .get("patch_diff")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        McpErrorObject::invalid_params("Missing required 'patch_diff' argument")
                    })?;
                let rationale =
                    args.get("rationale")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            McpErrorObject::invalid_params("Missing required 'rationale' argument")
                        })?;

                let patch_id = sha256_prefixed(diff.as_bytes());

                Ok(serde_json::json!({
                    "patch_id": patch_id,
                    "base_revision": base_rev,
                    "status": "Proposed",
                    "rationale": rationale,
                    "patch_applied_to_checkout": false
                }))
            }
            "sentra_request_approval" => {
                let action_name = args
                    .get("action_name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        McpErrorObject::invalid_params("Missing required 'action_name' argument")
                    })?;
                let summary = args
                    .get("action_summary")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        McpErrorObject::invalid_params("Missing required 'action_summary' argument")
                    })?;

                let ticket = format!(
                    "approval-ticket-{}",
                    sha256_prefixed(action_name.as_bytes())
                );
                self.pending_approval_requests
                    .insert(ticket.clone(), action_name.to_string());

                // External agent CANNOT self-approve (REQ-S02, REQ-S10)
                Ok(serde_json::json!({
                    "approval_ticket": ticket,
                    "action_name": action_name,
                    "action_summary": summary,
                    "status": "PendingHumanReview",
                    "authorized": false,
                    "message": "External agents cannot approve their own actions. Awaiting operator grant."
                }))
            }
            // Sensitive actions requiring explicit human approval ticket
            "sentra_apply_checkout_mutation" => {
                let ticket = args
                    .get("approval_ticket")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        McpErrorObject::invalid_params(
                            "Missing required 'approval_ticket' for sensitive action",
                        )
                    })?;

                // Check human grant
                if !self.human_approved_tickets.contains(ticket) {
                    return Err(McpErrorObject::human_approval_required(
                        "sentra_apply_checkout_mutation",
                    ));
                }

                Ok(serde_json::json!({
                    "status": "Success",
                    "action": "sentra_apply_checkout_mutation",
                    "approved_by_human": true
                }))
            }
            unknown => Err(McpErrorObject::method_not_found(unknown)),
        }
    }
}
