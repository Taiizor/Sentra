//! Conformance and integration tests for the Model Context Protocol (MCP over stdio)
//! server (REQ-F17, ADR-0005, EXTENSIONS.md § MCP, skills, and API).
//!
//! Protocol references: MCP 2025-11-25 lifecycle (version negotiation), base protocol
//! (ids, notifications), tools (structuredContent, isError, unknown tool -32602), and the
//! 2025-03-26 base protocol (batch receipt).

use std::{
    io::{BufReader, Cursor, Read},
    path::{Path, PathBuf},
};

use sentra_core::mcp::{
    LATEST_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, TransportLine, process_transport_bytes,
    read_bounded_line, run_stdio,
};
use sentra_core::{
    DEFAULT_MAX_LINE_BYTES, LocalWorkspace, McpErrorCode, McpRequest, McpServer, RequestId,
    SessionId, process_transport_line, verify_transport_allowed,
};
use serde_json::{Value, json};

/// Unique temporary directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("sentra-mcp-{label}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(id: i64, method: &str, params: Option<Value>) -> McpRequest {
    McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(id)),
        method: method.to_string(),
        params,
    }
}

fn initialized_server(root: &Path) -> McpServer {
    let mut server = McpServer::new(SessionId::from_sequence(1)).with_launch_root(root);
    let res = server.handle_request(request(
        0,
        "initialize",
        Some(json!({
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "test-client", "version": "1.0.0" }
        })),
    ));
    assert!(res.error.is_none());
    server
}

/// Calls a tool and returns the `CallToolResult` object.
fn call_tool(server: &mut McpServer, name: &str, arguments: Value) -> Value {
    let res = server.handle_request(request(
        7,
        "tools/call",
        Some(json!({ "name": name, "arguments": arguments })),
    ));
    assert!(
        res.error.is_none(),
        "unexpected protocol error: {:?}",
        res.error
    );
    res.result.expect("CallToolResult")
}

fn assert_tool_ok(result: &Value) -> &Value {
    assert_eq!(result["isError"], false, "tool failed: {result}");
    let structured = &result["structuredContent"];
    assert!(structured.is_object());
    // The text block carries the same payload serialized (2025-11-25 tools spec).
    let text = result["content"][0]["text"].as_str().expect("text block");
    assert_eq!(result["content"][0]["type"], "text");
    let reparsed: Value = serde_json::from_str(text).expect("text is serialized JSON");
    assert_eq!(&reparsed, structured);
    structured
}

fn assert_tool_error(result: &Value, code: &str) {
    assert_eq!(result["isError"], true, "expected tool error: {result}");
    assert_eq!(result["structuredContent"]["error"], code, "{result}");
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with(code)
    );
}

#[test]
fn initialize_echoes_every_supported_revision() {
    assert_eq!(
        SUPPORTED_PROTOCOL_VERSIONS,
        ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
    );
    for version in SUPPORTED_PROTOCOL_VERSIONS {
        let mut server = McpServer::new(SessionId::from_sequence(1));
        assert!(!server.initialized);
        let res = server.handle_request(request(
            1,
            "initialize",
            Some(json!({
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "1.0.0" }
            })),
        ));
        assert_eq!(res.id, Some(RequestId::Number(1)));
        let result = res.result.expect("initialize result");
        assert_eq!(result["protocolVersion"], version);
        assert_eq!(result["serverInfo"]["name"], "sentra-mcp");
        assert!(result["serverInfo"]["version"].is_string());
        assert_eq!(result["capabilities"]["tools"]["listChanged"], false);
        assert!(server.initialized);
        assert_eq!(server.negotiated_protocol_version(), Some(version));
    }
}

#[test]
fn initialize_answers_latest_legacy_revision_for_unsupported_requests() {
    // 2026-07-28 is a published *modern* (handshake-less) revision that Sentra does not
    // implement, so a legacy initialize asking for it gets the latest legacy revision.
    for requested in ["2026-07-28", "1900-01-01", "2024-10-07"] {
        let mut server = McpServer::new(SessionId::from_sequence(1));
        let res = server.handle_request(request(
            1,
            "initialize",
            Some(json!({ "protocolVersion": requested, "capabilities": {} })),
        ));
        let result = res.result.expect("initialize result");
        assert_eq!(result["protocolVersion"], "2025-11-25");
    }

    let mut server = McpServer::new(SessionId::from_sequence(1));
    let res = server.handle_request(request(1, "initialize", Some(json!({}))));
    let err = res
        .error
        .expect("missing protocolVersion is invalid params");
    assert_eq!(err.code, McpErrorCode::InvalidParams.code());
    assert!(!server.initialized);
}

#[test]
fn modern_discover_probe_gets_non_modern_error() {
    // Dual-era clients fall back to initialize on any non-modern error (-32022 is modern).
    let mut server = McpServer::new(SessionId::from_sequence(1));
    let res = server.handle_request(request(1, "server/discover", Some(json!({}))));
    assert_eq!(res.error.unwrap().code, McpErrorCode::MethodNotFound.code());
}

#[test]
fn uninitialized_server_fails_closed() {
    let mut server = McpServer::new(SessionId::from_sequence(2));
    let res = server.handle_request(request(42, "tools/list", None));
    assert!(res.result.is_none());
    assert_eq!(
        res.error.unwrap().code,
        McpErrorCode::ServerNotInitialized.code()
    );
    // ping is allowed before initialization.
    assert!(
        server
            .handle_request(request(43, "ping", None))
            .error
            .is_none()
    );
}

#[test]
fn tools_list_is_honest_and_write_free() {
    let tmp = TempDir::new("list");
    let mut server = initialized_server(tmp.path());
    let res = server.handle_request(request(3, "tools/list", None));
    let tools = res.result.expect("tools result")["tools"]
        .as_array()
        .expect("tools array")
        .clone();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(
        names,
        [
            "sentra_discover_workspace",
            "sentra_get_session_status",
            "sentra_audit_dependencies",
            "sentra_list_findings",
            "sentra_propose_patch",
            "sentra_request_approval",
            "sentra_scan_code",
            "sentra_codeql_ingest",
            "sentra_get_security_guidance",
            "sentra_generate_prompt",
        ]
    );
    for tool in &tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(tool["inputSchema"]["properties"].is_object());
        // Every required property is declared.
        if let Some(required) = tool["inputSchema"]["required"].as_array() {
            for key in required {
                assert!(
                    tool["inputSchema"]["properties"][key.as_str().unwrap()].is_object(),
                    "{tool}"
                );
            }
        }
        let read_only = tool["annotations"]["readOnlyHint"].as_bool().unwrap();
        assert_eq!(
            read_only,
            tool["name"] != "sentra_request_approval",
            "{tool}"
        );
        assert_eq!(tool["annotations"]["openWorldHint"], false);
    }
    let audit = tools
        .iter()
        .find(|t| t["name"] == "sentra_audit_dependencies")
        .unwrap();
    assert_eq!(
        audit["inputSchema"]["required"],
        json!(["lockfile_content"])
    );
}

#[test]
fn unknown_and_removed_tools_are_invalid_params() {
    let tmp = TempDir::new("unknown");
    let mut server = initialized_server(tmp.path());
    for name in [
        "no_such_tool",
        "sentra_install_skills",
        "sentra_apply_checkout_mutation",
    ] {
        let res = server.handle_request(request(
            9,
            "tools/call",
            Some(json!({ "name": name, "arguments": { "target": "claude", "global": true } })),
        ));
        let err = res.error.expect("protocol error");
        assert_eq!(err.code, McpErrorCode::InvalidParams.code());
        assert_eq!(err.message, format!("Unknown tool: {name}"));
    }
    // sentra_install_skills wrote nothing into the launch root.
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);

    // Malformed tools/call params are protocol errors too.
    let res = server.handle_request(request(10, "tools/call", Some(json!({ "arguments": {} }))));
    assert_eq!(res.error.unwrap().code, McpErrorCode::InvalidParams.code());
    let res = server.handle_request(request(
        11,
        "tools/call",
        Some(json!({ "name": "sentra_scan_code", "arguments": [1] })),
    ));
    assert_eq!(res.error.unwrap().code, McpErrorCode::InvalidParams.code());
}

#[test]
fn discover_workspace_reads_real_inventory_inside_launch_root() {
    let tmp = TempDir::new("discover");
    let root = tmp.path().join("ws");
    std::fs::create_dir_all(root.join("app")).unwrap();
    std::fs::write(
        root.join("app").join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"atty\"\nversion = \"0.2.11\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    )
    .unwrap();
    let mut server = initialized_server(&root);

    let result = call_tool(&mut server, "sentra_discover_workspace", json!({}));
    let payload = assert_tool_ok(&result);
    assert_eq!(payload["workspace_root"], ".");
    assert_eq!(payload["target_code_executed"], false);
    assert_eq!(payload["lockfile_count"], 1);
    assert_eq!(payload["lockfiles"][0]["path"], "app/Cargo.lock");
    assert_eq!(payload["total_packages"], 1);

    let result = call_tool(
        &mut server,
        "sentra_discover_workspace",
        json!({ "workspace_root": "app" }),
    );
    assert_eq!(assert_tool_ok(&result)["workspace_root"], "app");

    // An empty directory reports no components instead of invented ones.
    std::fs::create_dir_all(root.join("empty")).unwrap();
    let result = call_tool(
        &mut server,
        "sentra_discover_workspace",
        json!({ "workspace_root": "empty" }),
    );
    assert_eq!(assert_tool_ok(&result)["lockfile_count"], 0);

    let result = call_tool(
        &mut server,
        "sentra_discover_workspace",
        json!({ "workspace_root": "missing" }),
    );
    assert_tool_error(&result, "path_not_found");

    let outside = tmp.path().to_string_lossy().into_owned();
    let result = call_tool(
        &mut server,
        "sentra_discover_workspace",
        json!({ "workspace_root": outside }),
    );
    assert_tool_error(&result, "path_outside_launch_root");
    let result = call_tool(
        &mut server,
        "sentra_discover_workspace",
        json!({ "workspace_root": "../" }),
    );
    assert_tool_error(&result, "path_outside_launch_root");

    let result = call_tool(
        &mut server,
        "sentra_discover_workspace",
        json!({ "workspace_root": 42 }),
    );
    assert_tool_error(&result, "invalid_argument");
    let result = call_tool(
        &mut server,
        "sentra_discover_workspace",
        json!({ "max_depth": 999 }),
    );
    assert_tool_error(&result, "invalid_argument");
}

#[test]
fn session_status_reads_the_persisted_store_or_reports_why_not() {
    let tmp = TempDir::new("session");
    let workspace = tmp.path().join("ws");
    let store = tmp.path().join("store");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(&store).unwrap();
    let database = store.join("sentra.db");

    // Without a configured store the tool refuses to invent state.
    let mut server = initialized_server(&workspace);
    let result = call_tool(&mut server, "sentra_get_session_status", json!({}));
    assert_tool_error(&result, "database_not_configured");

    let init = LocalWorkspace::initialize(&workspace, &database).expect("init store");
    let persisted = init.session.expect("persisted session");

    let mut server = initialized_server(&workspace).with_database(&database);
    let result = call_tool(&mut server, "sentra_get_session_status", json!({}));
    let payload = assert_tool_ok(&result);
    assert_eq!(payload["initialized"], true);
    assert_eq!(payload["source"], "local_store");
    assert_eq!(payload["session_id"], persisted.session_id.to_string());
    assert_eq!(payload["state"], persisted.state.as_str());
    assert_eq!(
        payload["budget_used_micro_usd"],
        persisted.budget_used.as_micro_usd()
    );
}

#[test]
fn list_findings_states_that_no_finding_store_exists() {
    let tmp = TempDir::new("findings");
    let mut server = initialized_server(tmp.path());
    let result = call_tool(&mut server, "sentra_list_findings", json!({}));
    assert_tool_error(&result, "not_implemented");
    assert!(
        result["structuredContent"]["message"]
            .as_str()
            .unwrap()
            .contains("does not persist findings")
    );
}

#[test]
fn audit_dependencies_uses_structured_content_and_tool_errors() {
    let tmp = TempDir::new("audit");
    let mut server = initialized_server(tmp.path());
    let cargo_lock = "version = 3\n\n[[package]]\nname = \"atty\"\nversion = \"0.2.11\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";

    let result = call_tool(
        &mut server,
        "sentra_audit_dependencies",
        json!({ "lockfile_content": cargo_lock }),
    );
    // No duplicated top-level payload: only the CallToolResult members.
    assert!(result.get("packages_audited").is_none());
    let payload = assert_tool_ok(&result);
    assert_eq!(payload["packages_audited"], 1);
    assert_eq!(payload["vulnerabilities_found"], 1);
    assert!(
        payload["advisories_matched"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "RUSTSEC-2021-0145")
    );
    let pinned = sentra_core::AdvisoryDatabase::default_pinned();
    assert_eq!(payload["advisory_db_source"], "bundled_pinned_sample");
    assert_eq!(payload["advisory_db_records"], pinned.advisory_count());
    assert_eq!(
        payload["advisory_db_updated_at"],
        "2026-11-08T23:43:22.000Z"
    );
    assert_eq!(
        payload["is_stale"],
        pinned.is_stale(sentra_core::TimestampUtc::now(), 30)
    );

    // The unadvertised legacy alias still works.
    let result = call_tool(
        &mut server,
        "sentra_audit_dependencies",
        json!({ "cargo_lock_content": cargo_lock }),
    );
    assert_eq!(assert_tool_ok(&result)["packages_audited"], 1);

    let result = call_tool(&mut server, "sentra_audit_dependencies", json!({}));
    assert_tool_error(&result, "invalid_argument");
    let result = call_tool(
        &mut server,
        "sentra_audit_dependencies",
        json!({ "lockfile_content": cargo_lock, "lockfile_name": "weird.txt" }),
    );
    assert_tool_error(&result, "unsupported_lockfile");
    let result = call_tool(
        &mut server,
        "sentra_audit_dependencies",
        json!({ "lockfile_content": "{ not json", "lockfile_name": "package-lock.json" }),
    );
    assert_tool_error(&result, "lockfile_parse_failed");
}

#[test]
fn propose_patch_never_touches_the_checkout() {
    let tmp = TempDir::new("patch");
    let mut server = initialized_server(tmp.path());
    let diff = "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,3 +1,4 @@\n+// bounds check\n";
    let result = call_tool(
        &mut server,
        "sentra_propose_patch",
        json!({
            "base_revision": "git-commit-abc1234",
            "patch_diff": diff,
            "rationale": "Fixes CWE-120 buffer boundary violation"
        }),
    );
    let payload = assert_tool_ok(&result);
    assert_eq!(payload["status"], "Proposed");
    assert_eq!(payload["base_revision"], "git-commit-abc1234");
    assert_eq!(payload["patch_applied_to_checkout"], false);
    assert!(payload["patch_id"].is_string());

    let result = call_tool(
        &mut server,
        "sentra_propose_patch",
        json!({ "base_revision": "x", "patch_diff": diff }),
    );
    assert_tool_error(&result, "invalid_argument");
}

#[test]
fn external_agent_cannot_self_approve_and_tickets_are_unpredictable() {
    let tmp = TempDir::new("approval");
    let mut server = initialized_server(tmp.path());
    let args = json!({
        "action_name": "git_checkout_mutation",
        "action_summary": "Mutate host repository files"
    });
    let first = call_tool(&mut server, "sentra_request_approval", args.clone());
    let second = call_tool(&mut server, "sentra_request_approval", args);
    let first = assert_tool_ok(&first).clone();
    let second = assert_tool_ok(&second).clone();
    assert_eq!(first["status"], "PendingHumanReview");
    assert_eq!(first["authorized"], false);
    assert_eq!(first["persisted"], false);
    let ticket = first["approval_ticket"].as_str().unwrap();
    assert!(ticket.starts_with("approval-ticket-sha256:"));
    assert_ne!(first["approval_ticket"], second["approval_ticket"]);

    // Nothing is auto-approved, and only issued tickets can be granted in-process.
    assert!(!server.is_human_approved(ticket));
    assert!(!server.admit_human_approval("approval-ticket-forged"));
    assert!(!server.is_human_approved("approval-ticket-forged"));
    assert!(server.admit_human_approval(ticket));
    assert!(server.is_human_approved(ticket));
}

#[test]
fn transport_policy_gating() {
    assert!(verify_transport_allowed("stdio").is_ok());
    for transport in ["http", "https", "tcp"] {
        assert_eq!(
            verify_transport_allowed(transport).unwrap_err().code,
            McpErrorCode::PolicyDenied.code()
        );
    }
}

fn line_json(server: &mut McpServer, line: &str) -> Option<Value> {
    process_transport_line(server, line, DEFAULT_MAX_LINE_BYTES)
        .unwrap()
        .map(|out| {
            assert!(out.ends_with('\n'));
            assert_eq!(out.matches('\n').count(), 1, "single-line framing");
            serde_json::from_str(&out).expect("valid JSON response")
        })
}

#[test]
fn transport_classifies_messages_per_json_rpc() {
    let mut server = McpServer::new(SessionId::from_sequence(9));

    assert_eq!(line_json(&mut server, "   \n"), None);

    // Oversized line: -32600 with id null.
    let out = process_transport_line(&mut server, &"a".repeat(150), 100)
        .unwrap()
        .unwrap();
    let parsed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed["error"]["code"], McpErrorCode::InvalidRequest.code());
    assert_eq!(parsed["id"], Value::Null);

    // Parse error: -32700 with id null.
    let parsed = line_json(&mut server, r#"{"jsonrpc":"2.0", invalid_json"#).unwrap();
    assert_eq!(parsed["error"]["code"], McpErrorCode::ParseError.code());
    assert_eq!(parsed["id"], Value::Null);

    // Valid JSON that is not a request: -32600, id echoed when valid.
    let parsed = line_json(&mut server, r#"{"jsonrpc":"2.0","id":32}"#).unwrap();
    assert_eq!(parsed["error"]["code"], McpErrorCode::InvalidRequest.code());
    assert_eq!(parsed["id"], 32);
    let parsed = line_json(&mut server, r#"{"id":33,"method":"ping"}"#).unwrap();
    assert_eq!(parsed["error"]["code"], McpErrorCode::InvalidRequest.code());
    assert_eq!(parsed["id"], 33);
    for invalid in [
        r#"[]"#,
        r#"42"#,
        r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":34,"method":"ping","params":"x"}"#,
    ] {
        let parsed = line_json(&mut server, invalid).unwrap();
        assert_eq!(
            parsed["error"]["code"],
            McpErrorCode::InvalidRequest.code(),
            "{invalid}"
        );
    }
    // Batches are refused unless 2025-03-26 was negotiated.
    let parsed = line_json(&mut server, r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#).unwrap();
    assert_eq!(parsed["error"]["code"], McpErrorCode::InvalidRequest.code());

    // Client responses are ignored.
    assert_eq!(
        line_json(&mut server, r#"{"jsonrpc":"2.0","id":5,"result":{}}"#),
        None
    );
    assert_eq!(
        line_json(
            &mut server,
            r#"{"jsonrpc":"2.0","id":null,"error":{"code":-1,"message":"x"}}"#
        ),
        None
    );

    // An id-less initialize is a notification: no reply and no state change.
    assert_eq!(
        line_json(
            &mut server,
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#
        ),
        None
    );
    assert!(!server.initialized);

    // Real handshake.
    let parsed = line_json(
        &mut server,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
    )
    .unwrap();
    assert_eq!(parsed["id"], 1);
    assert_eq!(parsed["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        line_json(
            &mut server,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        ),
        None
    );

    // An id-less tools/call is never executed.
    assert_eq!(
        line_json(
            &mut server,
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"sentra_request_approval","arguments":{"action_name":"a","action_summary":"b"}}}"#
        ),
        None
    );
    assert!(server.pending_approval_requests.is_empty());

    // A notification method sent with an id is an invalid request.
    let parsed = line_json(
        &mut server,
        r#"{"jsonrpc":"2.0","id":"n","method":"notifications/initialized"}"#,
    )
    .unwrap();
    assert_eq!(parsed["id"], "n");
    assert_eq!(parsed["error"]["code"], McpErrorCode::InvalidRequest.code());
}

#[test]
fn batches_are_served_only_for_revision_2025_03_26() {
    let mut server = McpServer::new(SessionId::from_sequence(9));
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}"#;
    assert!(line_json(&mut server, init).is_some());
    let batch = r#"[{"jsonrpc":"2.0","id":2,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":3,"method":"tools/list"},{"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}]"#;
    let out = process_transport_line(&mut server, batch, DEFAULT_MAX_LINE_BYTES)
        .unwrap()
        .unwrap();
    let parsed: Value = serde_json::from_str(&out).unwrap();
    let responses = parsed.as_array().expect("batch response array");
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[0]["id"], 2);
    assert_eq!(responses[1]["id"], 3);
    assert!(responses[1]["result"]["tools"].is_array());
    assert_eq!(responses[2]["id"], 4);
    assert_eq!(
        responses[2]["error"]["code"],
        McpErrorCode::InvalidRequest.code()
    );
    // A batch of notifications only produces no output.
    let only_notifications = r#"[{"jsonrpc":"2.0","method":"notifications/initialized"}]"#;
    assert_eq!(line_json(&mut server, only_notifications), None);
}

#[test]
fn bounded_reader_discards_oversized_lines_without_buffering_them() {
    // 3 MiB line streamed through an 8 KiB buffer with a 1 KiB quota.
    let huge = std::io::repeat(b'x').take(3 * 1024 * 1024);
    let tail = Cursor::new(b"\r\n{\"ok\":1}\r\nlast".to_vec());
    let mut reader = BufReader::with_capacity(8 * 1024, huge.chain(tail));
    match read_bounded_line(&mut reader, 1024).unwrap() {
        TransportLine::Oversized { consumed_bytes } => {
            assert_eq!(consumed_bytes, 3 * 1024 * 1024 + 2);
        }
        other => panic!("expected oversized, got {other:?}"),
    }
    assert_eq!(
        read_bounded_line(&mut reader, 1024).unwrap(),
        TransportLine::Line(b"{\"ok\":1}".to_vec())
    );
    assert_eq!(
        read_bounded_line(&mut reader, 1024).unwrap(),
        TransportLine::Line(b"last".to_vec())
    );
    assert_eq!(
        read_bounded_line(&mut reader, 1024).unwrap(),
        TransportLine::Eof
    );

    // Exactly at the quota is accepted.
    let mut reader = Cursor::new(b"abcd\n".to_vec());
    assert_eq!(
        read_bounded_line(&mut reader, 4).unwrap(),
        TransportLine::Line(b"abcd".to_vec())
    );
}

#[test]
fn run_stdio_survives_invalid_utf8_and_oversized_lines() {
    let mut input = Vec::new();
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
    input.extend_from_slice(&[0x7B, 0xFF, 0xFE, 0x7D, b'\n']);
    input.extend_from_slice(&vec![b' '; 300]);
    input.extend_from_slice(b"{}\n");
    input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}");
    let mut server = McpServer::new(SessionId::from_sequence(9));
    let mut output = Vec::new();
    run_stdio(&mut server, &mut Cursor::new(input), &mut output, 256).unwrap();

    let text = String::from_utf8(output).unwrap();
    let lines: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[0]["id"], 1);
    assert_eq!(lines[1]["error"]["code"], McpErrorCode::ParseError.code());
    assert_eq!(lines[1]["id"], Value::Null);
    assert_eq!(
        lines[2]["error"]["code"],
        McpErrorCode::InvalidRequest.code()
    );
    assert_eq!(lines[3]["id"], 2);
    assert!(lines[3]["result"].is_object());

    assert_eq!(
        process_transport_bytes(&mut server, &[0xC3, 0x28]).map(|s| serde_json::from_str::<Value>(
            &s
        )
        .unwrap()["error"]["code"]
            .clone()),
        Some(json!(McpErrorCode::ParseError.code()))
    );
}

#[test]
fn scan_code_is_confined_and_reports_io_failures() {
    let tmp = TempDir::new("scan");
    let root = tmp.path().join("ws");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src").join("config.py"),
        "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n",
    )
    .unwrap();
    std::fs::write(tmp.path().join("outside.py"), "x = 1\n").unwrap();
    let mut server = initialized_server(&root);

    let result = call_tool(&mut server, "sentra_scan_code", json!({}));
    let payload = assert_tool_ok(&result);
    assert_eq!(payload["path"], ".");
    assert!(payload["files_scanned"].as_u64().unwrap() >= 1);
    let matches = payload["matches"].as_array().unwrap();
    assert!(matches.iter().any(|m| m["file"] == "src/config.py"));
    assert!(matches.iter().all(|m| {
        !m["snippet"]
            .as_str()
            .unwrap()
            .contains("AKIAIOSFODNN7EXAMPLE")
    }));

    let result = call_tool(&mut server, "sentra_scan_code", json!({ "path": "src" }));
    let payload = assert_tool_ok(&result);
    assert!(
        payload["matches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["file"] == "src/config.py")
    );

    let result = call_tool(
        &mut server,
        "sentra_scan_code",
        json!({ "path": "src/config.py" }),
    );
    let payload = assert_tool_ok(&result);
    assert_eq!(payload["files_scanned"], 1);
    assert_eq!(payload["matches"][0]["file"], "src/config.py");

    for (path, code) in [
        ("missing.rs", "path_not_found"),
        ("Z:/no/such/dir/", "path_not_found"),
        ("../outside.py", "path_outside_launch_root"),
    ] {
        let result = call_tool(&mut server, "sentra_scan_code", json!({ "path": path }));
        assert_tool_error(&result, code);
    }
    let absolute_outside = tmp.path().join("outside.py");
    let result = call_tool(
        &mut server,
        "sentra_scan_code",
        json!({ "path": absolute_outside.to_string_lossy() }),
    );
    assert_tool_error(&result, "path_outside_launch_root");

    std::fs::write(root.join("binary.bin"), [0xFFu8, 0xFE, 0x00]).unwrap();
    let result = call_tool(
        &mut server,
        "sentra_scan_code",
        json!({ "path": "binary.bin" }),
    );
    assert_tool_error(&result, "read_failed");
}

#[test]
fn codeql_ingest_reports_invalid_sarif_as_tool_error() {
    let tmp = TempDir::new("codeql");
    let mut server = initialized_server(tmp.path());
    let result = call_tool(
        &mut server,
        "sentra_codeql_ingest",
        json!({ "sarif_content": "not sarif" }),
    );
    assert_tool_error(&result, "sarif_ingest_failed");
    let result = call_tool(&mut server, "sentra_codeql_ingest", json!({}));
    assert_tool_error(&result, "invalid_argument");
}

#[test]
fn codeql_ingest_reports_parsed_candidates_not_admitted_findings() {
    // Regression: the tool reported `findings_admitted`, although the parsed results are neither
    // admitted as evidence nor stored.
    let tmp = TempDir::new("codeql-ok");
    let mut server = initialized_server(tmp.path());
    let sarif = json!({
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "CodeQL", "rules": [{ "id": "js/xss", "properties": { "security-severity": "6.1" } }] } },
            "results": [{
                "ruleId": "js/xss",
                "level": "warning",
                "message": { "text": "Cross-site scripting." },
                "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "app.js" }, "region": { "startLine": 3 } } }]
            }]
        }]
    });
    let result = call_tool(
        &mut server,
        "sentra_codeql_ingest",
        json!({ "sarif_content": sarif.to_string() }),
    );
    let payload = assert_tool_ok(&result);
    assert_eq!(payload["candidate_findings_parsed"], 1);
    assert_eq!(payload["persisted"], false);
    assert!(payload.get("findings_admitted").is_none());
}

#[test]
fn security_guidance_lookup_and_search() {
    let tmp = TempDir::new("guidance");
    let mut server = initialized_server(tmp.path());
    let result = call_tool(
        &mut server,
        "sentra_get_security_guidance",
        json!({ "topic": "api-security-testing" }),
    );
    let payload = assert_tool_ok(&result);
    assert_eq!(payload["found"], true);
    assert_eq!(payload["skill_id"], "api-security-testing");
    assert!(payload["playbook"].as_str().unwrap().contains("BOLA/IDOR"));

    let result = call_tool(
        &mut server,
        "sentra_get_security_guidance",
        json!({ "topic": "stride" }),
    );
    assert_eq!(assert_tool_ok(&result)["found"], true);

    let result = call_tool(&mut server, "sentra_get_security_guidance", json!({}));
    assert_tool_error(&result, "invalid_argument");
}

#[test]
fn generate_prompt_validates_role_workflow_and_skills() {
    let tmp = TempDir::new("prompt");
    let mut server = initialized_server(tmp.path());
    let result = call_tool(
        &mut server,
        "sentra_generate_prompt",
        json!({
            "role": "patch_author",
            "workflow": "patch-remediation",
            "scope": "crates/sentra-core/src/db.rs",
            "skills": ["golang-security"],
            "context": "PostgreSQL relational query interface"
        }),
    );
    let payload = assert_tool_ok(&result);
    assert_eq!(payload["role"], "patch_author");
    assert_eq!(payload["workflow"], "patch-remediation");
    assert_eq!(payload["scope"], "crates/sentra-core/src/db.rs");
    let system_prompt = payload["system_prompt"].as_str().unwrap();
    assert!(system_prompt.contains("Autonomous Remediation Application Security Engineer"));
    assert!(system_prompt.contains("Golang Security Best Practices"));
    assert!(system_prompt.contains("Activated Domain Security Guidelines"));
    let user_prompt = payload["user_prompt"].as_str().unwrap();
    assert!(user_prompt.contains("ADR-0004 Three-Tier Validation"));
    assert!(user_prompt.contains("PostgreSQL relational query interface"));
    let composite = payload["composite_prompt"].as_str().unwrap();
    assert!(composite.contains("SYSTEM:") && composite.contains("USER:"));

    // Aliases normalize; the role defaults from the workflow.
    let result = call_tool(
        &mut server,
        "sentra_generate_prompt",
        json!({ "workflow": "stride" }),
    );
    assert_eq!(assert_tool_ok(&result)["workflow"], "threat-model");

    for (args, code) in [
        (json!({ "workflow": "nope" }), "invalid_argument"),
        (json!({ "role": "wizard" }), "invalid_argument"),
        (json!({ "skills": ["no-such-skill"] }), "skill_not_found"),
        (json!({ "skills": "golang-security" }), "invalid_argument"),
    ] {
        let result = call_tool(&mut server, "sentra_generate_prompt", args);
        assert_tool_error(&result, code);
    }
}

#[test]
fn second_initialize_is_rejected_and_keeps_the_negotiated_revision() {
    let mut server = McpServer::new(SessionId::from_sequence(3));
    let first = server.handle_request(request(
        1,
        "initialize",
        Some(json!({ "protocolVersion": "2025-11-25", "capabilities": {} })),
    ));
    assert!(first.result.is_some());
    let again = server.handle_request(request(
        2,
        "initialize",
        Some(json!({ "protocolVersion": "2025-03-26", "capabilities": {} })),
    ));
    assert_eq!(
        again.error.expect("already initialized").code,
        McpErrorCode::InvalidRequest.code()
    );
    assert_eq!(server.negotiated_protocol_version(), Some("2025-11-25"));
    // Batches stay unavailable under the first negotiated revision.
    let batch = r#"[{"jsonrpc":"2.0","id":6,"method":"ping"}]"#;
    let out = process_transport_line(&mut server, batch, DEFAULT_MAX_LINE_BYTES)
        .unwrap()
        .unwrap();
    let parsed: Value = serde_json::from_str(&out).unwrap();
    assert!(parsed.get("error").is_some(), "{parsed}");
}

#[test]
fn generate_prompt_reports_the_persona_it_used() {
    use sentra_core::research::{AppSecPersona, ResearchRole};

    let tmp = TempDir::new("persona");
    let mut server = initialized_server(tmp.path());
    for (workflow, role) in [
        ("scout", ResearchRole::Scout),
        ("threat-model", ResearchRole::Scout),
        ("api-bola", ResearchRole::Analyst),
        ("patch-remediation", ResearchRole::PatchAuthor),
        ("skill-audit", ResearchRole::Analyst),
        ("verify", ResearchRole::IndependentVerifier),
        ("general", ResearchRole::Analyst),
    ] {
        let result = call_tool(
            &mut server,
            "sentra_generate_prompt",
            json!({ "workflow": workflow }),
        );
        let payload = assert_tool_ok(&result);
        assert_eq!(payload["role"], role.as_str(), "{workflow}");
        let persona = AppSecPersona::system_prompt_for_role(role);
        let first_line = persona.lines().next().unwrap();
        assert!(
            payload["system_prompt"]
                .as_str()
                .unwrap()
                .starts_with(first_line),
            "{workflow}"
        );
    }
    // A role that differs from the workflow's fixed persona is rejected...
    let result = call_tool(
        &mut server,
        "sentra_generate_prompt",
        json!({ "role": "verifier", "workflow": "threat-model" }),
    );
    assert_tool_error(&result, "invalid_argument");
    // ...while the general workflow applies it.
    let result = call_tool(
        &mut server,
        "sentra_generate_prompt",
        json!({ "role": "verifier", "workflow": "general" }),
    );
    assert_eq!(assert_tool_ok(&result)["role"], "independent_verifier");
}

#[test]
fn audit_rejects_empty_and_non_lockfile_content() {
    let tmp = TempDir::new("audit-garbage");
    let mut server = initialized_server(tmp.path());
    let result = call_tool(
        &mut server,
        "sentra_audit_dependencies",
        json!({ "lockfile_content": "" }),
    );
    assert_tool_error(&result, "invalid_argument");
    for name in ["Cargo.lock", "yarn.lock", "package-lock.json"] {
        let result = call_tool(
            &mut server,
            "sentra_audit_dependencies",
            json!({ "lockfile_content": "garbage[[[", "lockfile_name": name }),
        );
        assert_tool_error(&result, "lockfile_parse_failed");
    }
}
