//! Model Context Protocol (MCP) server managing JSON-RPC dispatch, tool execution,
//! filesystem confinement, and human approval policy gates (REQ-F17, ADR-0005, EXTENSIONS.md).
//!
//! The server implements the legacy initialize-handshake era of MCP (see
//! [`crate::mcp::protocol`]). Tool results follow the 2025-11-25 tools specification:
//! the payload is returned once as `structuredContent` and once serialized in a text
//! content block; argument validation and execution failures are tool results with
//! `isError: true`, while unknown tools and malformed requests are JSON-RPC errors.

use std::{
    collections::{HashMap, HashSet},
    hash::BuildHasher,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use serde_json::{Map, Value, json};

use crate::{
    advisory::{
        AdvisoryDatabase, DEFAULT_INVENTORY_MAX_DEPTH, LockfileKind, MAX_INVENTORY_DEPTH,
        parse_lockfile_content,
    },
    common::crypto::sha256_prefixed,
    domain::{
        TimestampUtc,
        id::{SessionId, TaskId},
    },
    mcp::{
        error::{McpErrorCode, McpErrorObject},
        protocol::{
            LATEST_PROTOCOL_VERSION, McpRequest, McpResponse, SUPPORTED_PROTOCOL_VERSIONS,
            ToolDefinition, canonical_tool_definitions, negotiate_protocol_version,
        },
    },
    research::{
        AgentSkillAuditPromptBuilder, ApiSecurityPromptBuilder, PatchSynthesisPromptBuilder,
        ResearchRole, ScoutPromptBuilder, SkillPromptComposer, ThreatModelingPromptBuilder,
        VerificationPromptBuilder,
    },
    sast::{MAX_SCANNABLE_FILE_BYTES, SastMatch, SastScanner},
    service::LocalWorkspace,
};

/// Server implementation name reported in `serverInfo`.
pub const SERVER_NAME: &str = "sentra-mcp";

/// Local stdio Model Context Protocol server exposing Sentra Core services (REQ-F17).
///
/// Filesystem-reading tools are confined to the *launch root* (the operator-selected
/// workspace, by default the process working directory). No tool writes files.
#[derive(Clone, Debug)]
pub struct McpServer {
    /// Ephemeral identifier of this server process (not a persisted session).
    pub session_id: SessionId,
    /// True once an `initialize` request has been answered.
    pub initialized: bool,
    /// Approval tickets granted by a trusted, in-process operator surface.
    pub human_approved_tickets: HashSet<String>,
    /// Pending approval requests (ticket -> action name) awaiting operator review.
    pub pending_approval_requests: HashMap<String, String>,
    /// Registered tool definitions.
    pub tools: Vec<ToolDefinition>,
    launch_root: PathBuf,
    database: Option<PathBuf>,
    negotiated_protocol_version: Option<&'static str>,
    approval_sequence: u64,
}

/// Tool-level failure reported as a `CallToolResult` with `isError: true`.
#[derive(Debug)]
struct ToolError {
    code: &'static str,
    message: String,
}

impl ToolError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new("invalid_argument", message)
    }
}

type ToolResult = Result<Value, ToolError>;

impl McpServer {
    /// Creates a server whose launch root is the current working directory and which
    /// has no local store configured.
    pub fn new(session_id: SessionId) -> Self {
        let launch_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self {
            session_id,
            initialized: false,
            human_approved_tickets: HashSet::new(),
            pending_approval_requests: HashMap::new(),
            tools: canonical_tool_definitions(),
            launch_root,
            database: None,
            negotiated_protocol_version: None,
            approval_sequence: 0,
        }
    }

    /// Sets the launch root that confines every filesystem path a tool may read.
    pub fn with_launch_root(mut self, launch_root: impl Into<PathBuf>) -> Self {
        self.launch_root = launch_root.into();
        self
    }

    /// Sets the local store used to report persisted session state.
    pub fn with_database(mut self, database: impl Into<PathBuf>) -> Self {
        self.database = Some(database.into());
        self
    }

    /// Launch root confining filesystem-reading tools.
    pub fn launch_root(&self) -> &Path {
        &self.launch_root
    }

    /// Local store used for persisted session status, when configured.
    pub fn database(&self) -> Option<&Path> {
        self.database.as_deref()
    }

    /// Protocol revision agreed in the last `initialize` exchange.
    pub fn negotiated_protocol_version(&self) -> Option<&'static str> {
        self.negotiated_protocol_version
    }

    /// Grants operator approval for a ticket previously issued by
    /// `sentra_request_approval` in this process (REQ-S02, REQ-S10).
    ///
    /// This is an in-process API for a trusted host; it is not reachable over MCP.
    /// Returns `false` (and grants nothing) for tickets this server never issued.
    pub fn admit_human_approval(&mut self, ticket: impl Into<String>) -> bool {
        let ticket = ticket.into();
        if !self.pending_approval_requests.contains_key(&ticket) {
            return false;
        }
        self.human_approved_tickets.insert(ticket);
        true
    }

    /// True when the ticket was issued by this server and granted by an operator.
    pub fn is_human_approved(&self, ticket: &str) -> bool {
        self.human_approved_tickets.contains(ticket)
    }

    /// Handles a client notification. Notifications never execute request methods
    /// (an id-less `tools/call` or `initialize` is ignored) and never produce output.
    pub fn handle_notification(&mut self, method: &str, params: Option<&Value>) {
        // `notifications/initialized` completes the handshake (requests are already
        // accepted once `initialize` was answered) and `notifications/cancelled` has
        // nothing to cancel because requests are processed synchronously. Every other
        // notification, including a request method sent without an id, is ignored.
        let _ = (method, params);
    }

    /// Dispatches a JSON-RPC 2.0 MCP request and returns its response.
    ///
    /// A request without an id is a notification and is refused here without being
    /// executed; transports route notifications to [`Self::handle_notification`].
    pub fn handle_request(&mut self, request: McpRequest) -> McpResponse {
        let McpRequest {
            jsonrpc,
            id,
            method,
            params,
        } = request;

        if jsonrpc != "2.0" {
            return McpResponse::error(
                id,
                McpErrorObject::invalid_request(
                    "Invalid JSON-RPC protocol version; expected '2.0'",
                ),
            );
        }
        if id.is_none() {
            return McpResponse::error(
                None,
                McpErrorObject::invalid_request(
                    "Notifications (messages without an id) cannot invoke request methods",
                ),
            );
        }

        match method.as_str() {
            // The handshake happens once per connection; a second initialize must not
            // renegotiate the revision (and with it batch support) mid-session.
            "initialize" if self.initialized => McpResponse::error(
                id,
                McpErrorObject::invalid_request(format!(
                    "Server is already initialized (protocol revision {}); initialize may be sent only once per connection",
                    self.negotiated_protocol_version
                        .unwrap_or(LATEST_PROTOCOL_VERSION)
                )),
            ),
            "initialize" => match self.initialize(params.as_ref()) {
                Ok(result) => McpResponse::success(id, result),
                Err(error) => McpResponse::error(id, error),
            },
            "ping" => McpResponse::success(id, json!({})),
            "tools/list" => {
                if !self.initialized {
                    return McpResponse::error(id, McpErrorObject::server_not_initialized());
                }
                McpResponse::success(id, json!({ "tools": self.tools }))
            }
            "tools/call" => {
                if !self.initialized {
                    return McpResponse::error(id, McpErrorObject::server_not_initialized());
                }
                match self.call_tool(params) {
                    Ok(result) => McpResponse::success(id, result),
                    Err(error) => McpResponse::error(id, error),
                }
            }
            notification if notification.starts_with("notifications/") => McpResponse::error(
                id,
                McpErrorObject::invalid_request("Notifications must not carry an id"),
            ),
            unknown => McpResponse::error(id, McpErrorObject::method_not_found(unknown)),
        }
    }

    fn initialize(&mut self, params: Option<&Value>) -> Result<Value, McpErrorObject> {
        let requested = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                McpErrorObject::with_data(
                    McpErrorCode::InvalidParams,
                    "initialize requires a string 'protocolVersion' parameter",
                    json!({ "supported": SUPPORTED_PROTOCOL_VERSIONS }),
                )
            })?;
        let negotiated = negotiate_protocol_version(requested);
        self.negotiated_protocol_version = Some(negotiated);
        self.initialized = true;
        Ok(json!({
            "protocolVersion": negotiated,
            "capabilities": {
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": env!("CARGO_PKG_VERSION")
            },
            "instructions": format!(
                "Sentra local MCP server (initialize-handshake revisions up to {LATEST_PROTOCOL_VERSION}; the handshake-less 2026-07-28 revision is not implemented). Filesystem tools are read-only and confined to the server's launch root. Scanner and audit results are unverified candidate signals, not validated findings."
            )
        }))
    }

    fn call_tool(&mut self, params: Option<Value>) -> Result<Value, McpErrorObject> {
        let Some(Value::Object(mut params)) = params else {
            return Err(McpErrorObject::invalid_params(
                "tools/call requires an object 'params'",
            ));
        };
        let name = match params.remove("name") {
            Some(Value::String(name)) => name,
            _ => {
                return Err(McpErrorObject::invalid_params(
                    "Missing or invalid 'name' in tool call",
                ));
            }
        };
        let arguments = match params.remove("arguments") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(arguments)) => arguments,
            Some(_) => {
                return Err(McpErrorObject::invalid_params(
                    "'arguments' must be an object",
                ));
            }
        };
        if !self.tools.iter().any(|tool| tool.name == name) {
            return Err(McpErrorObject::unknown_tool(name));
        }
        Ok(call_tool_result(self.execute_tool(&name, &arguments)))
    }

    /// Executes a listed tool. Every outcome is a tool result; nothing here is a
    /// protocol error.
    fn execute_tool(&mut self, name: &str, args: &Map<String, Value>) -> ToolResult {
        match name {
            "sentra_discover_workspace" => self.discover_workspace(args),
            "sentra_get_session_status" => self.session_status(),
            "sentra_audit_dependencies" => audit_dependencies(args),
            "sentra_list_findings" => Err(ToolError::new(
                "not_implemented",
                "Sentra Core does not persist findings yet, so there is no finding store to list. Use sentra_scan_code or sentra_audit_dependencies for on-demand, unverified candidate signals.",
            )),
            "sentra_propose_patch" => propose_patch(args),
            "sentra_request_approval" => self.request_approval(args),
            "sentra_scan_code" => self.scan_code(args),
            "sentra_codeql_ingest" => self.codeql_ingest(args),
            "sentra_get_security_guidance" => security_guidance(args),
            "sentra_generate_prompt" => generate_prompt(args),
            other => Err(ToolError::new(
                "not_implemented",
                format!("Tool '{other}' is listed but has no implementation"),
            )),
        }
    }

    /// Resolves `requested` (relative to the launch root, or absolute) to a canonical
    /// existing path inside the canonical launch root. Returns `(root, path)`.
    fn confine(&self, requested: Option<&str>) -> Result<(PathBuf, PathBuf), ToolError> {
        let root = std::fs::canonicalize(&self.launch_root).map_err(|_| {
            ToolError::new(
                "launch_root_unavailable",
                "The server's launch root cannot be resolved; restart the server from an existing workspace directory",
            )
        })?;
        let requested = requested.filter(|p| !p.is_empty());
        let candidate = match requested {
            None => root.clone(),
            Some(path) => root.join(path),
        };
        let shown = requested.unwrap_or(".");
        let resolved = std::fs::canonicalize(&candidate).map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                ToolError::new("path_not_found", format!("Path '{shown}' does not exist"))
            } else {
                ToolError::new(
                    "path_unreadable",
                    format!("Path '{shown}' cannot be resolved"),
                )
            }
        })?;
        if !resolved.starts_with(&root) {
            return Err(ToolError::new(
                "path_outside_launch_root",
                format!("Path '{shown}' resolves outside the server's launch root"),
            ));
        }
        Ok((root, resolved))
    }

    fn discover_workspace(&self, args: &Map<String, Value>) -> ToolResult {
        let requested = optional_str(args, "workspace_root")?;
        let max_depth = match optional_u64(args, "max_depth")? {
            None => DEFAULT_INVENTORY_MAX_DEPTH,
            Some(depth) => usize::try_from(depth)
                .ok()
                .filter(|depth| *depth <= MAX_INVENTORY_DEPTH)
                .ok_or_else(|| {
                    ToolError::invalid_argument(format!(
                        "'max_depth' must be between 0 and {MAX_INVENTORY_DEPTH}"
                    ))
                })?,
        };
        let (root, directory) = self.confine(requested)?;
        if !directory.is_dir() {
            return Err(ToolError::new(
                "not_a_directory",
                format!(
                    "Path '{}' is not a directory",
                    relative_display(&root, &directory)
                ),
            ));
        }
        let report = LocalWorkspace::inventory(&directory, max_depth).map_err(|error| {
            ToolError::new(
                "discovery_failed",
                format!("Workspace discovery failed ({:?})", error.kind),
            )
        })?;
        let inventory = report.inventory;
        Ok(json!({
            "workspace_root": relative_display(&root, &directory),
            "discovery_mode": "lockfile_inventory",
            "max_depth": max_depth,
            "target_code_executed": false,
            "lockfile_count": inventory.lockfiles.len(),
            "lockfiles": inventory.lockfiles,
            "total_packages": inventory.total_packages,
            "truncated": inventory.truncated
        }))
    }

    fn session_status(&self) -> ToolResult {
        let Some(database) = &self.database else {
            return Err(ToolError::new(
                "database_not_configured",
                "No local store is configured for this server. Launch it with `sentra mcp --database <file>` (the store must live outside the workspace) to report persisted session state.",
            ));
        };
        let report = LocalWorkspace::status(&self.launch_root, database).map_err(|error| {
            ToolError::new(
                "session_status_failed",
                format!("Reading the local store failed ({:?})", error.kind),
            )
        })?;
        Ok(match report.session {
            Some(session) => json!({
                "initialized": true,
                "source": "local_store",
                "session_id": session.session_id.to_string(),
                "state": session.state.as_str(),
                "classification_floor": session.classification_floor.as_str(),
                "context_generation": session.context_generation,
                "created_at": session.created_at.to_string(),
                "budget_limit_micro_usd": session.budget_limit.as_micro_usd(),
                "budget_used_micro_usd": session.budget_used.as_micro_usd()
            }),
            None => json!({
                "initialized": false,
                "source": "local_store",
                "session_id": null,
                "message": "The configured store holds no session for the launch root; run `sentra init` first."
            }),
        })
    }

    fn request_approval(&mut self, args: &Map<String, Value>) -> ToolResult {
        let action_name = required_str(args, "action_name")?;
        let summary = required_str(args, "action_summary")?;
        let ticket = self.issue_ticket(action_name, summary);
        self.pending_approval_requests
            .insert(ticket.clone(), action_name.to_string());

        // External agents CANNOT self-approve (REQ-S02, REQ-S10).
        Ok(json!({
            "approval_ticket": ticket,
            "action_name": action_name,
            "action_summary": summary,
            "status": "PendingHumanReview",
            "authorized": false,
            "persisted": false,
            "message": "Recorded in this server process only. External agents cannot approve their own actions, and no operator grant path is exposed over MCP."
        }))
    }

    /// Issues an unpredictable, unique ticket. Not a credential: granting requires the
    /// in-process operator API.
    fn issue_ticket(&mut self, action_name: &str, summary: &str) -> String {
        self.approval_sequence = self.approval_sequence.wrapping_add(1);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        // `RandomState` keys are seeded from OS randomness per process.
        let entropy = std::collections::hash_map::RandomState::new().hash_one((
            self.approval_sequence,
            nanos,
            action_name,
        ));
        let material = format!(
            "{}\n{}\n{nanos}\n{entropy}\n{action_name}\n{summary}",
            self.session_id, self.approval_sequence
        );
        format!("approval-ticket-{}", sha256_prefixed(material.as_bytes()))
    }

    fn scan_code(&self, args: &Map<String, Value>) -> ToolResult {
        let requested = optional_str(args, "path")?;
        let (root, target) = self.confine(requested)?;
        let shown = relative_display(&root, &target);
        let scanner = SastScanner::new();
        let (files_scanned, matches) = if target.is_file() {
            let size = std::fs::metadata(&target)
                .map_err(|_| ToolError::new("read_failed", format!("Cannot read '{shown}'")))?
                .len();
            if size > MAX_SCANNABLE_FILE_BYTES {
                return Err(ToolError::new(
                    "file_too_large",
                    format!("'{shown}' exceeds the {MAX_SCANNABLE_FILE_BYTES}-byte scan limit"),
                ));
            }
            let content = std::fs::read_to_string(&target).map_err(|error| {
                if error.kind() == ErrorKind::InvalidData {
                    ToolError::new("read_failed", format!("'{shown}' is not UTF-8 text"))
                } else {
                    ToolError::new("read_failed", format!("Cannot read '{shown}'"))
                }
            })?;
            (1, scanner.scan_content(&shown, &content))
        } else if target.is_dir() {
            let report = scanner.scan_workspace(&target).map_err(|_| {
                ToolError::new(
                    "read_failed",
                    format!("Scanning '{shown}' failed while reading the directory tree"),
                )
            })?;
            let prefix = if shown == "." {
                String::new()
            } else {
                format!("{shown}/")
            };
            let matches = report
                .matches
                .into_iter()
                .map(|m| SastMatch {
                    file_path: format!("{prefix}{}", m.file_path.replace('\\', "/")),
                    ..m
                })
                .collect();
            (report.files_scanned, matches)
        } else {
            return Err(ToolError::new(
                "unsupported_path_type",
                format!("'{shown}' is neither a regular file nor a directory"),
            ));
        };
        Ok(json!({
            "path": shown,
            "files_scanned": files_scanned,
            "signals_found": matches.len(),
            "matches": matches.iter().map(|m| json!({
                "rule_id": m.rule.id,
                "severity": m.rule.severity.as_str(),
                "cwe": m.rule.cwe_id,
                "file": m.file_path,
                "line": m.line_number,
                "snippet": m.snippet
            })).collect::<Vec<_>>()
        }))
    }

    fn codeql_ingest(&self, args: &Map<String, Value>) -> ToolResult {
        let sarif_content = required_str(args, "sarif_content")?;
        let result = crate::plugin::codeql::ingest_codeql_sarif_payload(
            sarif_content,
            &self.session_id,
            TaskId::new(),
            TimestampUtc::now(),
        )
        .map_err(|error| {
            ToolError::new(
                "sarif_ingest_failed",
                format!("CodeQL SARIF ingest failed: {error}"),
            )
        })?;
        Ok(json!({
            "total_sarif_results": result.total_sarif_results,
            "findings_admitted": result.findings.len(),
            "taint_traces_extracted": result.taint_traces_extracted,
            "rules": result.rules_identified,
            "highest_severity": result.highest_severity.map(|s| s.to_string()),
            "persisted": false
        }))
    }
}

/// Builds a `CallToolResult`: structured payload plus its serialized text, or an
/// `isError` result whose text is the human-readable message.
fn call_tool_result(outcome: ToolResult) -> Value {
    match outcome {
        Ok(payload) => {
            let text = serde_json::to_string(&payload).unwrap_or_default();
            json!({
                "content": [{ "type": "text", "text": text }],
                "structuredContent": payload,
                "isError": false
            })
        }
        Err(error) => json!({
            "content": [{ "type": "text", "text": format!("{}: {}", error.code, error.message) }],
            "structuredContent": { "error": error.code, "message": error.message },
            "isError": true
        }),
    }
}

fn audit_dependencies(args: &Map<String, Value>) -> ToolResult {
    // `cargo_lock_content` is an unadvertised legacy alias kept for older callers.
    let content = match optional_str(args, "lockfile_content")? {
        Some(content) => content,
        None => optional_str(args, "cargo_lock_content")?.ok_or_else(|| {
            ToolError::invalid_argument("Missing required 'lockfile_content' argument")
        })?,
    };
    if content.trim().is_empty() {
        return Err(ToolError::invalid_argument(
            "'lockfile_content' is empty; pass the full lockfile text",
        ));
    }
    let name = optional_str(args, "lockfile_name")?.unwrap_or("Cargo.lock");
    let kind = LockfileKind::detect_from_filename(name).ok_or_else(|| {
        ToolError::new(
            "unsupported_lockfile",
            format!(
                "Unsupported lockfile name '{name}'. Supported: {}",
                LockfileKind::ALL_FILENAMES.join(", ")
            ),
        )
    })?;
    let packages = parse_lockfile_content(kind, content).map_err(|error| {
        ToolError::new(
            "lockfile_parse_failed",
            format!("Failed to parse {name}: {error}"),
        )
    })?;
    let db = AdvisoryDatabase::default_pinned();
    let audit = db
        .audit_packages(&packages, TimestampUtc::now(), 30)
        .map_err(|error| ToolError::new("audit_failed", format!("Audit failed: {error}")))?;
    Ok(json!({
        "lockfile_audited": name,
        "packages_audited": audit.packages_audited,
        "vulnerabilities_found": audit.matches.len(),
        "advisories_matched": audit.matches.iter().map(|m| &m.advisory.id).collect::<Vec<_>>(),
        "advisory_db_source": "bundled_pinned_sample",
        "advisory_db_records": db.advisory_count(),
        "advisory_db_updated_at": db.updated_at().to_rfc3339(),
        "is_stale": audit.is_stale
    }))
}

fn propose_patch(args: &Map<String, Value>) -> ToolResult {
    let base_revision = required_str(args, "base_revision")?;
    let diff = required_str(args, "patch_diff")?;
    let rationale = required_str(args, "rationale")?;
    Ok(json!({
        "patch_id": sha256_prefixed(diff.as_bytes()),
        "base_revision": base_revision,
        "status": "Proposed",
        "rationale": rationale,
        "persisted": false,
        "patch_applied_to_checkout": false
    }))
}

fn security_guidance(args: &Map<String, Value>) -> ToolResult {
    let topic = required_str(args, "topic")?;
    if let Some(skill) = crate::skills::find_skill_by_id(topic) {
        return Ok(json!({
            "found": true,
            "skill_id": skill.id,
            "name": skill.name,
            "category": skill.category.as_str(),
            "description": skill.description,
            "tags": skill.tags,
            "playbook": skill.content,
        }));
    }
    let results = crate::skills::search_skills(topic);
    if let Some(first) = results.first() {
        return Ok(json!({
            "found": true,
            "matched_query": topic,
            "total_matches": results.len(),
            "skill_id": first.id,
            "name": first.name,
            "category": first.category.as_str(),
            "description": first.description,
            "tags": first.tags,
            "playbook": first.content,
            "other_matches": results.iter().skip(1).map(|s| s.id).collect::<Vec<_>>()
        }));
    }
    Ok(json!({
        "found": false,
        "query": topic,
        "available_skills": crate::skills::list_builtin_skills().iter().map(|s| s.id).collect::<Vec<_>>()
    }))
}

/// Canonical workflow names plus accepted aliases.
fn canonical_workflow(workflow: &str) -> Option<&'static str> {
    Some(match workflow {
        "general" => "general",
        "threat-model" | "stride" => "threat-model",
        "api-bola" | "bola" | "idor" => "api-bola",
        "patch-remediation" | "patch" => "patch-remediation",
        "skill-audit" | "agent-safety" => "skill-audit",
        "scout" => "scout",
        "verify" | "verification" => "verify",
        _ => return None,
    })
}

/// Persona each workflow's prompt builder uses (see `research::prompt`); only the
/// `general` workflow takes its persona from the `role` argument.
fn role_for_workflow(workflow: &str) -> ResearchRole {
    match workflow {
        "scout" | "threat-model" => ResearchRole::Scout,
        "patch-remediation" => ResearchRole::PatchAuthor,
        "verify" => ResearchRole::IndependentVerifier,
        _ => ResearchRole::Analyst,
    }
}

fn parse_role(role: &str) -> Option<ResearchRole> {
    Some(match role.to_ascii_lowercase().as_str() {
        "scout" | "recon" => ResearchRole::Scout,
        "analyst" => ResearchRole::Analyst,
        "validator" => ResearchRole::Validator,
        "patch_author" | "patch" => ResearchRole::PatchAuthor,
        "verifier" | "independent_verifier" => ResearchRole::IndependentVerifier,
        _ => return None,
    })
}

fn generate_prompt(args: &Map<String, Value>) -> ToolResult {
    let workflow_arg = optional_str(args, "workflow")?.unwrap_or("general");
    let workflow = canonical_workflow(workflow_arg).ok_or_else(|| {
        ToolError::invalid_argument(format!(
            "Unknown workflow '{workflow_arg}'. Expected one of: {}",
            crate::mcp::protocol::PROMPT_WORKFLOWS.join(", ")
        ))
    })?;
    let fixed_role = role_for_workflow(workflow);
    let role = match optional_str(args, "role")? {
        None => fixed_role,
        Some(role) => {
            let parsed = parse_role(role).ok_or_else(|| {
                ToolError::invalid_argument(format!(
                    "Unknown role '{role}'. Expected one of: {}",
                    crate::mcp::protocol::PROMPT_ROLES.join(", ")
                ))
            })?;
            // Workflow templates carry their own persona; reporting a different
            // role than the one in the prompt would mislead the caller.
            if workflow != "general" && parsed != fixed_role {
                return Err(ToolError::invalid_argument(format!(
                    "'role' applies only to the 'general' workflow; workflow '{workflow}' always uses role '{}'",
                    fixed_role.as_str()
                )));
            }
            parsed
        }
    };
    let scope = optional_str(args, "scope")?.unwrap_or(".");
    let context = optional_str(args, "context")?.unwrap_or("");
    let skill_ids: Vec<&str> = match args.get("skills") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().ok_or_else(|| {
                    ToolError::invalid_argument("'skills' must be an array of strings")
                })
            })
            .collect::<Result<_, _>>()?,
        Some(_) => {
            return Err(ToolError::invalid_argument(
                "'skills' must be an array of strings",
            ));
        }
    };
    let or_default = |fallback: &'static str| {
        if context.is_empty() {
            fallback
        } else {
            context
        }
    };

    let prompt = match workflow {
        "scout" => ScoutPromptBuilder::build_reconnaissance_prompt(
            scope,
            or_default("General repository surface mapping"),
        ),
        "threat-model" => ThreatModelingPromptBuilder::build_stride_assessment_prompt(
            ".",
            scope,
            or_default("Target component and surrounding system architecture"),
        ),
        "api-bola" => ApiSecurityPromptBuilder::build_bola_audit_prompt(
            scope,
            "GET/POST",
            or_default("// Route handler under authorization review"),
        ),
        "patch-remediation" => PatchSynthesisPromptBuilder::build_three_tier_patch_prompt(
            "Autonomous Security Remediation",
            "CWE-Security",
            scope,
            or_default("// Vulnerable code segment requiring root cause fix"),
        ),
        "skill-audit" => AgentSkillAuditPromptBuilder::build_skill_safety_prompt(scope, context),
        "verify" => VerificationPromptBuilder::build_dual_state_verification_prompt(
            scope,
            "// Baseline reproduction test",
            "// Candidate unified git diff",
            or_default("// Isolated execution evidence"),
        ),
        _ => SkillPromptComposer::compose_role_prompt(
            role,
            &format!("Perform specialized security evaluation on: {scope}"),
            &[],
            context,
        ),
    };
    // Playbooks are appended to the workflow's own prompt, so its grounding rules and
    // expected schema stay in force; ids are de-duplicated and unknown ids rejected.
    let (prompt, skill_ids) = SkillPromptComposer::augment_prompt_with_ids(prompt, &skill_ids)
        .map_err(|err| ToolError::new(err.code(), err.to_string()))?;

    Ok(json!({
        "role": role.as_str(),
        "workflow": workflow,
        "scope": scope,
        "skills": skill_ids,
        "system_prompt": prompt.system_prompt,
        "user_prompt": prompt.user_prompt,
        "expected_schema": prompt.expected_schema,
        "composite_prompt": prompt.to_composite_prompt(),
    }))
}

/// Optional string argument; `null` counts as absent, any other type is rejected.
fn optional_str<'a>(args: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(ToolError::invalid_argument(format!(
            "'{key}' must be a string"
        ))),
    }
}

fn required_str<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, ToolError> {
    optional_str(args, key)?
        .ok_or_else(|| ToolError::invalid_argument(format!("Missing required '{key}' argument")))
}

fn optional_u64(args: &Map<String, Value>, key: &str) -> Result<Option<u64>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            ToolError::invalid_argument(format!("'{key}' must be a non-negative integer"))
        }),
    }
}

/// Launch-root-relative display path with forward slashes (`.` for the root itself).
fn relative_display(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(relative) if relative.as_os_str().is_empty() => ".".to_string(),
        Ok(relative) => relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"),
        Err(_) => ".".to_string(),
    }
}
