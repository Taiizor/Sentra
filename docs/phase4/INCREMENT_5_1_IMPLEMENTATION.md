# Phase 4 — Increment 5.1: Local Model Context Protocol (MCP over stdio) Server & Core Application Services Boundary

**Implementation Report**  
**Requirement References:** REQ-F17, ADR-0005, EXTENSIONS.md § MCP, skills, and API  
**Date:** 2026-11-08  
**Status:** Complete & Empirically Verified (Host Windows 11 MSVC & Linux Docker)

---

## 1. Executive Summary

Increment 5.1 delivers the local Model Context Protocol (MCP over stdio) server and shared application services boundary for Sentra, satisfying **REQ-F17**, **ADR-0005**, and **EXTENSIONS.md**.

The implementation establishes a compliant JSON-RPC 2.0 MCP server implementing the protocol specification revision `2026-07-28`. It exposes a canonical 6-tool suite reflecting core Sentra capabilities (`sentra_discover_workspace`, `sentra_get_session_status`, `sentra_audit_dependencies`, `sentra_list_findings`, `sentra_propose_patch`, `sentra_request_approval`). Crucially, the MCP server enforces strict authorization parity with the local CLI and Core Engine policies: external model-controlled agents calling `sentra_request_approval` receive a ticket in `PendingHumanReview` with `authorized: false` (external agents cannot self-approve; anti-collusion and confused deputy prevention). Sensitive actions fail closed with `HumanApprovalRequired` (-32003) unless an explicit human operator approval has been recorded via `admit_human_approval`.

Furthermore, transport policy gating (`verify_transport_allowed`) restricts communication strictly to `stdio`, fail-closing any remote HTTP/HTTPS/TCP transport in accordance with ADR-0005. The stdio transport processor (`process_transport_line`) provides supervised line-oriented processing with a 1 MiB line byte quota, notification ignoring without response, and embedded newline sanitization.

All code compiles under `#![forbid(unsafe_code)]` with zero Clippy warnings (`-D warnings`) and passes 10/10 new MCP integration tests on both Windows 11 host and Linux Docker environments.

---

## 2. Architecture & Design

### 2.1 JSON-RPC 2.0 and MCP Protocol Models (`crates/sentra-core/src/mcp/protocol.rs`, `error.rs`)

The MCP layer implements the standard JSON-RPC 2.0 framing and error specifications, augmented with domain-specific MCP error codes:

```
+-------------------------------------------------------------------------+
|                              JSON-RPC 2.0                               |
|                                                                         |
|  Request:  { "jsonrpc": "2.0", "id": 1, "method": "...", "params": ... }|
|  Response: { "jsonrpc": "2.0", "id": 1, "result": ... }                 |
|  Error:    { "jsonrpc": "2.0", "id": 1, "error": { "code", "message" } }|
+-------------------------------------------------------------------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
[Standard JSON-RPC Codes]                       [MCP Domain Codes]
-32700: ParseError                              -32001: ConnectionClosed
-32600: InvalidRequest                          -32002: PolicyDenied
-32601: MethodNotFound                          -32003: HumanApprovalRequired
-32602: InvalidParams                           -32004: ServerNotInitialized
-32603: InternalError                           -32005: QuotaExceeded
```

- **`RequestId`**: Represents either an integer or string request identifier per JSON-RPC 2.0 specifications.
- **`McpRequest` / `McpResponse`**: Strongly-typed request/response structures serialized with `serde`. Notifications (requests where `id: None`) are explicitly accommodated.
- **`ToolDefinition`**: Typed JSON schema representation for MCP tool discovery, including tool name, description, and JSON schema input properties.

### 2.2 Canonical Tool Suite (`canonical_tool_definitions`)

The server exposes 6 canonical tools mirroring the core services of Sentra:

| Canonical Tool Name | Core Requirement | Description | Input Schema |
|:---|:---|:---|:---|
| `sentra_discover_workspace` | `F-01` | Discovers target workspace metadata, excluding target scripts from execution | `workspace_root: string` |
| `sentra_get_session_status` | `F-14` | Inspects current research session lifecycle state and metrics | *(none)* |
| `sentra_audit_dependencies` | `F-07` | Audits Cargo.lock content against pinned advisory database | `cargo_lock_content: string` |
| `sentra_list_findings` | `F-05`, `F-06` | Lists security findings recorded within active session | *(none)* |
| `sentra_propose_patch` | `F-11` | Proposes unified diff patch candidate for verification | `base_revision`, `patch_diff`, `rationale` |
| `sentra_request_approval` | `S-02`, `S-10` | Requests human approval for restricted operations | `action_name`, `action_summary` |

### 2.3 Confused Deputy & Anti-Collusion Enforcement (`crates/sentra-core/src/mcp/server.rs`)

A central threat model concern in Model Context Protocol integrations is the *Confused Deputy* problem, where an LLM agent uses an MCP tool to trigger unauthorized actions on the host repository.

Sentra implements two strict safeguards:
1. **No External Self-Approval:** When an external agent invokes `sentra_request_approval`, the server generates a ticket and stores it under `pending_approval_requests`, returning:
   ```json
   {
     "approval_ticket": "approval-ticket-<sha256>",
     "status": "PendingHumanReview",
     "authorized": false,
     "message": "External agents cannot approve their own actions. Awaiting operator grant."
   }
   ```
   The ticket is **not** added to `human_approved_tickets`.
2. **Sensitive Action Gating:** Sensitive tools (e.g., `sentra_apply_checkout_mutation`) require an admitted `approval_ticket`. If the ticket is not present in `human_approved_tickets`, execution fails closed with `McpErrorCode::HumanApprovalRequired` (`-32003`). Only an explicit call to `server.admit_human_approval(ticket)` by the human operator authorizes execution.

### 2.4 Transport Security & Supervised Stdio Processing (`crates/sentra-core/src/mcp/transport.rs`)

In Phase 4, network transport is strictly restricted:
- **`verify_transport_allowed(transport)`**: Only `"stdio"` returns `Ok(())`. Remote protocols (`"http"`, `"https"`, `"tcp"`) return `Err(McpErrorCode::PolicyDenied)` (-32002).
- **`process_transport_line(server, line, max_line_bytes)`**:
  - Empty or whitespace lines yield `Ok(None)` without generating noise.
  - Lines exceeding `max_line_bytes` (default 1 MiB / `DEFAULT_MAX_LINE_BYTES`) are immediately rejected with `InvalidRequest` (-32600).
  - Malformed JSON is rejected with `ParseError` (-32700).
  - JSON-RPC notifications (`request.id.is_none()`) execute any state updates but return `Ok(None)`, complying with JSON-RPC 2.0 prohibition against responding to notifications.
  - Responses are formatted as single-line newline-delimited JSON strings, with any embedded newlines sanitized to prevent framing corruption.

---

## 3. Verification & Test Evidence

### 3.1 Test Coverage (`crates/sentra-core/tests/mcp_tests.rs`)

10 dedicated integration tests verify all protocol, authorization, and transport behaviors:

1. `test_mcp_handshake_initialize`: Verifies protocol version `"2026-07-28"`, `serverInfo.name` = `"sentra-mcp"`, and `capabilities.tools` map.
2. `test_uninitialized_server_fails_closed`: Verifies that invoking `tools/list` or `tools/call` before `initialize` returns `-32004` (`ServerNotInitialized`).
3. `test_tools_list_returns_canonical_suite`: Verifies all 6 canonical tools are returned with valid JSON schema properties.
4. `test_tool_execution_discover_workspace`: Validates `sentra_discover_workspace` metadata-only execution and `InvalidParams` error on missing argument.
5. `test_tool_execution_audit_dependencies`: Validates offline Cargo.lock auditing against pinned advisory database (RUSTSEC-2021-0145 match).
6. `test_tool_execution_propose_patch`: Validates patch candidate proposal with SHA-256 diff fingerprinting and non-applied status.
7. `test_external_agent_cannot_self_approve`: Asserts that external agents calling `sentra_request_approval` receive `PendingHumanReview` with `authorized: false`.
8. `test_sensitive_action_requires_human_admission`: Confirms that sensitive checkout mutation fails with `HumanApprovalRequired` (-32003) until `admit_human_approval` is invoked.
9. `test_transport_policy_gating`: Asserts that `stdio` succeeds while `http`, `https`, and `tcp` fail closed with `PolicyDenied`.
10. `test_stdio_transport_line_processing`: Tests single-line framing, 1 MiB line quota enforcement, notification handling, and parse error responses.

### 3.2 Dual-Platform Test Results

#### Host Windows 11 (MSVC):
```text
running 10 tests
test test_external_agent_cannot_self_approve ... ok
test test_mcp_handshake_initialize ... ok
test test_sensitive_action_requires_human_admission ... ok
test test_stdio_transport_line_processing ... ok
test test_tool_execution_audit_dependencies ... ok
test test_tool_execution_discover_workspace ... ok
test test_tool_execution_propose_patch ... ok
test test_tools_list_returns_canonical_suite ... ok
test test_transport_policy_gating ... ok
test test_uninitialized_server_fails_closed ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

#### Linux Docker Container (`scripts/docker-test.ps1 -Mode all`):
- `cargo fmt --all -- --check`: **Success (0 diffs)**
- `cargo check --workspace`: **Success**
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: **Success (0 warnings)**
- `cargo test --package sentra-core` across 20 independent suites: **20/20 suites passed, 10/10 in `mcp_tests` passed**.

---

## 4. Requirement Traceability Matrix

| Requirement | Implementation Artifact | Verification Result |
|:---|:---|:---|
| **REQ-F17** (Local Model Context Protocol Server) | `crates/sentra-core/src/mcp/server.rs`, `protocol.rs` | Handshake revision `2026-07-28`, tool dispatch verified |
| **ADR-0005** (Transport Security & Stdio Isolation) | `crates/sentra-core/src/mcp/transport.rs` (`verify_transport_allowed`) | Stdio approved; HTTP/HTTPS/TCP strictly denied |
| **EXTENSIONS.md § MCP Tools** | `crates/sentra-core/src/mcp/protocol.rs` (`canonical_tool_definitions`) | 6 canonical tools with typed JSON schemas |
| **REQ-S02 / REQ-S10** (Confused Deputy & Anti-Collusion) | `crates/sentra-core/src/mcp/server.rs` (`execute_tool`) | External self-approval prevented; human admission required |
| **Quota Management** | `crates/sentra-core/src/mcp/transport.rs` (`process_transport_line`) | 1 MiB line limit enforced |

---

## 5. Conclusion & Phase 4 Status

With the completion and empirical verification of Increment 5.1:
1. Phase 4 Increment 5.0 (Subprocess Plugin SDK & Adapter Protocol) and Increment 5.1 (Local MCP Server & Application Services Boundary) are fully realized.
2. The system maintains `#![forbid(unsafe_code)]`, zero external C/C++ dependencies in core, and strict fail-closed security invariants.
3. Phase 4 is ready for formal closure assessment.
