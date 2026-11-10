//! Conformance and integration tests for Model Context Protocol (MCP over stdio) server
//! (REQ-F17, ADR-0005, EXTENSIONS.md § MCP, skills, and API).

use sentra_core::{
    DEFAULT_MAX_LINE_BYTES, McpErrorCode, McpRequest, McpServer, RequestId, SessionId,
    process_transport_line, verify_transport_allowed,
};

#[test]
fn test_mcp_handshake_initialize() {
    let mut server = McpServer::new(SessionId::from_sequence(1));
    assert!(!server.initialized);

    let init_req = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(1)),
        method: "initialize".to_string(),
        params: Some(serde_json::json!({
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        })),
    };

    let res = server.handle_request(init_req);
    assert_eq!(res.id, Some(RequestId::Number(1)));
    assert!(res.error.is_none());
    assert!(server.initialized);

    let result = res.result.expect("Initialize result missing");
    assert_eq!(result["protocolVersion"], "2026-07-28");
    assert_eq!(result["serverInfo"]["name"], "sentra-mcp");
    assert!(result["capabilities"]["tools"].is_object());
}

#[test]
fn test_uninitialized_server_fails_closed() {
    let mut server = McpServer::new(SessionId::from_sequence(2));
    assert!(!server.initialized);

    // Attempting tools/list before handshake
    let list_req = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(42)),
        method: "tools/list".to_string(),
        params: None,
    };

    let res = server.handle_request(list_req);
    assert!(res.result.is_none());
    let err = res.error.expect("Expected error on uninitialized call");
    assert_eq!(err.code, McpErrorCode::ServerNotInitialized.code());
}

#[test]
fn test_tools_list_returns_canonical_suite() {
    let mut server = McpServer::new(SessionId::from_sequence(3));
    server.initialized = true;

    let list_req = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::String("req-tools".to_string())),
        method: "tools/list".to_string(),
        params: None,
    };

    let res = server.handle_request(list_req);
    assert!(res.error.is_none());
    let tools = res.result.expect("Expected tools result")["tools"]
        .as_array()
        .expect("Expected tools array")
        .clone();

    assert_eq!(tools.len(), 10);
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();

    assert!(names.contains(&"sentra_discover_workspace"));
    assert!(names.contains(&"sentra_get_session_status"));
    assert!(names.contains(&"sentra_audit_dependencies"));
    assert!(names.contains(&"sentra_list_findings"));
    assert!(names.contains(&"sentra_propose_patch"));
    assert!(names.contains(&"sentra_request_approval"));
    assert!(names.contains(&"sentra_scan_code"));
    assert!(names.contains(&"sentra_codeql_ingest"));
    assert!(names.contains(&"sentra_get_security_guidance"));
    assert!(names.contains(&"sentra_install_skills"));

    for tool in &tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(tool["inputSchema"]["properties"].is_object());
    }
}

#[test]
fn test_tool_execution_discover_workspace() {
    let mut server = McpServer::new(SessionId::from_sequence(4));
    server.initialized = true;

    let call_req = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(10)),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({
            "name": "sentra_discover_workspace",
            "arguments": {
                "workspace_root": "."
            }
        })),
    };

    let res = server.handle_request(call_req);
    assert!(res.error.is_none());
    let result = res.result.expect("Expected result");
    assert_eq!(result["status"], "Discovered");
    assert_eq!(result["discovery_mode"], "metadata_only");
    assert_eq!(result["target_code_executed"], false);

    // Missing workspace_root argument must fail with InvalidParams
    let bad_call = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(11)),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({
            "name": "sentra_discover_workspace",
            "arguments": {}
        })),
    };
    let bad_res = server.handle_request(bad_call);
    assert_eq!(
        bad_res.error.expect("Expected error").code,
        McpErrorCode::InvalidParams.code()
    );
}

#[test]
fn test_tool_execution_audit_dependencies() {
    let mut server = McpServer::new(SessionId::from_sequence(5));
    server.initialized = true;

    let cargo_lock = r#"
version = 3

[[package]]
name = "atty"
version = "0.2.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

    let call_req = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(20)),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({
            "name": "sentra_audit_dependencies",
            "arguments": {
                "cargo_lock_content": cargo_lock
            }
        })),
    };

    let res = server.handle_request(call_req);
    assert!(res.error.is_none());
    let result = res.result.expect("Expected result");
    assert_eq!(result["packages_audited"], 1);
    assert_eq!(result["vulnerabilities_found"], 1);
    let matched = result["advisories_matched"]
        .as_array()
        .expect("Expected advisories array");
    assert!(matched.iter().any(|v| v == "RUSTSEC-2021-0145"));
}

#[test]
fn test_tool_execution_propose_patch() {
    let mut server = McpServer::new(SessionId::from_sequence(6));
    server.initialized = true;

    let diff = r#"--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
+// Fixed buffer length bounds check
"#;

    let call_req = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(30)),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({
            "name": "sentra_propose_patch",
            "arguments": {
                "base_revision": "git-commit-abc1234",
                "patch_diff": diff,
                "rationale": "Fixes CWE-120 buffer boundary violation"
            }
        })),
    };

    let res = server.handle_request(call_req);
    assert!(res.error.is_none());
    let result = res.result.expect("Expected result");
    assert_eq!(result["status"], "Proposed");
    assert_eq!(result["base_revision"], "git-commit-abc1234");
    assert_eq!(result["patch_applied_to_checkout"], false);
    assert!(result["patch_id"].is_string());
}

#[test]
fn test_external_agent_cannot_self_approve() {
    let mut server = McpServer::new(SessionId::from_sequence(7));
    server.initialized = true;

    // External agent attempts to request an approval ticket
    let call_req = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(40)),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({
            "name": "sentra_request_approval",
            "arguments": {
                "action_name": "git_checkout_mutation",
                "action_summary": "Mutate host repository files"
            }
        })),
    };

    let res = server.handle_request(call_req);
    assert!(res.error.is_none());
    let result = res.result.expect("Expected result");
    assert_eq!(result["status"], "PendingHumanReview");
    assert_eq!(result["authorized"], false);
    let ticket = result["approval_ticket"]
        .as_str()
        .expect("Expected ticket string");
    assert!(ticket.starts_with("approval-ticket-"));

    // Server must NOT have admitted this ticket automatically
    assert!(!server.human_approved_tickets.contains(ticket));
}

#[test]
fn test_sensitive_action_requires_human_admission() {
    let mut server = McpServer::new(SessionId::from_sequence(8));
    server.initialized = true;

    let fake_ticket = "approval-ticket-unapproved-agent-ticket";

    // Attempting sensitive action without human admission fails closed
    let unapproved_call = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(50)),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({
            "name": "sentra_apply_checkout_mutation",
            "arguments": {
                "approval_ticket": fake_ticket
            }
        })),
    };

    let res1 = server.handle_request(unapproved_call);
    assert!(res1.result.is_none());
    let err = res1.error.expect("Expected human approval error");
    assert_eq!(err.code, McpErrorCode::HumanApprovalRequired.code());

    // Operator human reviews and admits ticket
    server.admit_human_approval(fake_ticket);

    // Retrying with admitted ticket succeeds
    let approved_call = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(51)),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({
            "name": "sentra_apply_checkout_mutation",
            "arguments": {
                "approval_ticket": fake_ticket
            }
        })),
    };

    let res2 = server.handle_request(approved_call);
    assert!(res2.error.is_none());
    let result = res2.result.expect("Expected execution result");
    assert_eq!(result["status"], "Success");
    assert_eq!(result["approved_by_human"], true);
}

#[test]
fn test_transport_policy_gating() {
    // stdio is the authorized local transport (ADR-0005)
    assert!(verify_transport_allowed("stdio").is_ok());

    // Remote HTTP / HTTPS / TCP is strictly denied
    let http_err = verify_transport_allowed("http").unwrap_err();
    assert_eq!(http_err.code, McpErrorCode::PolicyDenied.code());

    let https_err = verify_transport_allowed("https").unwrap_err();
    assert_eq!(https_err.code, McpErrorCode::PolicyDenied.code());

    let tcp_err = verify_transport_allowed("tcp").unwrap_err();
    assert_eq!(tcp_err.code, McpErrorCode::PolicyDenied.code());
}

#[test]
fn test_stdio_transport_line_processing() {
    let mut server = McpServer::new(SessionId::from_sequence(9));

    // 1. Blank/whitespace lines produce Ok(None)
    assert_eq!(
        process_transport_line(&mut server, "   \n", DEFAULT_MAX_LINE_BYTES).unwrap(),
        None
    );

    // 2. Line exceeding quota fails with InvalidRequest error response
    let big_line = "a".repeat(150);
    let quota_resp = process_transport_line(&mut server, &big_line, 100)
        .unwrap()
        .expect("Expected error response");
    let parsed_quota: serde_json::Value =
        serde_json::from_str(&quota_resp).expect("Valid JSON error");
    assert_eq!(
        parsed_quota["error"]["code"],
        McpErrorCode::InvalidRequest.code()
    );

    // 3. Valid initialize line produces formatted single-line JSON
    let valid_init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let out = process_transport_line(&mut server, valid_init, DEFAULT_MAX_LINE_BYTES)
        .unwrap()
        .expect("Expected output response");

    assert!(!out.contains('\n') || out.ends_with('\n'));
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("Valid JSON response");
    assert_eq!(parsed["id"], 1);
    assert_eq!(parsed["result"]["protocolVersion"], "2026-07-28");

    // 4. Notification (no id) produces Ok(None)
    let notification = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let notif_out =
        process_transport_line(&mut server, notification, DEFAULT_MAX_LINE_BYTES).unwrap();
    assert_eq!(notif_out, None);

    // 5. Malformed JSON produces ParseError error response
    let malformed = r#"{"jsonrpc":"2.0", invalid_json"#;
    let parse_resp = process_transport_line(&mut server, malformed, DEFAULT_MAX_LINE_BYTES)
        .unwrap()
        .expect("Expected parse error response");
    let parsed_err: serde_json::Value =
        serde_json::from_str(&parse_resp).expect("Valid JSON error");
    assert_eq!(parsed_err["error"]["code"], McpErrorCode::ParseError.code());
}

#[test]
fn test_tool_execution_scan_code() {
    let mut server = McpServer::new(SessionId::from_sequence(11));
    server.initialized = true;

    let call_req = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(99)),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({
            "name": "sentra_scan_code",
            "arguments": {
                "path": "."
            }
        })),
    };

    let res = server.handle_request(call_req);
    assert!(res.error.is_none());
    let result = res.result.expect("Expected scan_code result");
    assert!(result["files_scanned"].is_number());
    assert!(result["signals_found"].is_number());
    assert!(result["matches"].is_array());
}

#[test]
fn test_mcp_get_security_guidance_and_install() {
    let mut server = McpServer::new(SessionId::from_sequence(12));
    server.initialized = true;

    // 1. Get guidance for api-security-testing
    let call_req = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(100)),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({
            "name": "sentra_get_security_guidance",
            "arguments": {
                "topic": "api-security-testing"
            }
        })),
    };
    let res = server.handle_request(call_req);
    assert!(res.error.is_none());
    let result = res.result.expect("Expected guidance result");
    assert_eq!(result["found"], true);
    assert_eq!(result["skill_id"], "api-security-testing");
    assert!(result["playbook"].as_str().unwrap().contains("BOLA/IDOR"));

    // 2. Search guidance by topic keyword
    let search_req = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(101)),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({
            "name": "sentra_get_security_guidance",
            "arguments": {
                "topic": "stride"
            }
        })),
    };
    let search_res = server.handle_request(search_req);
    assert!(search_res.error.is_none());
    let search_result = search_res.result.expect("Expected search result");
    assert_eq!(search_result["found"], true);

    // 3. Install skill to temporary directory via MCP
    let tmp = std::env::temp_dir().join(format!("sentra-mcp-install-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);
    let install_req = McpRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(RequestId::Number(102)),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({
            "name": "sentra_install_skills",
            "arguments": {
                "target": "claude",
                "skill": "api-security-testing",
                "workspace": tmp.to_str().unwrap()
            }
        })),
    };
    let install_res = server.handle_request(install_req);
    assert!(install_res.error.is_none());
    let install_result = install_res.result.expect("Expected install result");
    assert_eq!(install_result["status"], "Success");
    assert_eq!(install_result["target"], "claude");
    let _ = std::fs::remove_dir_all(&tmp);
}
