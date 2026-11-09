//! Integration tests for GitHub CodeQL Adapter, Taint Flow Extraction, and SARIF Ingestion (REQ-F05, REQ-F16).

#![forbid(unsafe_code)]

use sentra_core::{
    CodeQlAdapter, CodeQlLanguage, FindingSource, PluginCapability, PluginRequest, PluginResponse,
    Reachability, SessionId, Severity, TaskId, TimestampUtc, ingest_codeql_sarif_payload,
    probe_codeql_workspace,
};
use std::str::FromStr;

#[test]
fn test_codeql_language_detection_and_workspace_probing() {
    let ws = std::env::temp_dir().join(format!("sentra-codeql-probe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ws);
    std::fs::create_dir_all(&ws).expect("create_dir_all");

    // Create polyglot files
    std::fs::write(ws.join("index.ts"), "const x = 1;").unwrap();
    std::fs::write(ws.join("utils.js"), "function foo() {}").unwrap();
    std::fs::write(ws.join("script.py"), "print('hello')").unwrap();
    std::fs::write(ws.join("main.rs"), "fn main() {}").unwrap();
    std::fs::write(ws.join("go.mod"), "module example.com/app").unwrap();

    let probe = probe_codeql_workspace(&ws).expect("probe should succeed");
    assert_eq!(probe.detected_languages.len(), 4); // Javascript, Python, Rust, Go

    // Javascript has 2 files (index.ts, utils.js) so it should be primary
    assert_eq!(probe.primary_language, Some(CodeQlLanguage::Javascript));

    let create_cmd = probe.database_create_command.expect("create cmd");
    assert!(create_cmd.contains("codeql database create"));
    assert!(create_cmd.contains("--language=javascript"));

    let analyze_cmd = probe.database_analyze_command.expect("analyze cmd");
    assert!(analyze_cmd.contains("codeql database analyze"));
    assert!(analyze_cmd.contains("--format=sarif-latest"));

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_codeql_adapter_manifest_and_execution_protocol() {
    let adapter = CodeQlAdapter::new();
    assert_eq!(adapter.manifest.id, "org.sentra.adapter.codeql");
    assert!(
        adapter
            .manifest
            .declared_capabilities
            .contains(&PluginCapability::StaticAnalysis)
    );

    // 1. Handshake Initialize
    let init_ack = adapter.handle_request(&PluginRequest::Initialize { host_version: 1 });
    match init_ack {
        PluginResponse::InitializeAck { plugin_id, .. } => {
            assert_eq!(plugin_id, "org.sentra.adapter.codeql");
        }
        other => panic!("expected InitializeAck, got {other:?}"),
    }

    // 2. Probe
    let ws = std::env::temp_dir().join(format!("sentra-codeql-proto-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&ws);
    std::fs::create_dir_all(&ws).expect("create_dir_all");
    std::fs::write(ws.join("app.py"), "import os").unwrap();
    let probe_res = adapter.handle_request(&PluginRequest::Probe {
        workspace_root: ws.to_string_lossy().to_string(),
    });
    match probe_res {
        PluginResponse::ProbeResult {
            applicable,
            details,
            ..
        } => {
            assert!(applicable);
            assert!(details.contains("python"));
        }
        other => panic!("expected ProbeResult, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&ws);

    // 3. Plan
    let plan_res = adapter.handle_request(&PluginRequest::Plan {
        input_ref: "sha256:0123456789".to_string(),
    });
    match plan_res {
        PluginResponse::PlanResult {
            required_capabilities,
            ..
        } => {
            assert!(required_capabilities.contains(&PluginCapability::StaticAnalysis));
        }
        other => panic!("expected PlanResult, got {other:?}"),
    }
}

#[test]
fn test_codeql_sarif_ingestion_with_multi_hop_taint_flow() {
    const PATH_INJECTION_SARIF: &str = r#"{
      "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "CodeQL",
              "version": "2.19.0",
              "rules": [
                {
                  "id": "js/path-injection",
                  "name": "Uncontrolled data used in path expression",
                  "shortDescription": {
                    "text": "Accessing paths influenced by users can lead to path traversal."
                  },
                  "fullDescription": {
                    "text": "Writing or reading files using paths constructed from user-controlled inputs allows arbitrary file access."
                  },
                  "helpUri": "https://codeql.github.com/codeql-query-help/javascript/js-path-injection/",
                  "properties": {
                    "security-severity": "7.5",
                    "tags": ["security", "external/cwe/cwe-022"]
                  }
                }
              ]
            }
          },
          "results": [
            {
              "ruleId": "js/path-injection",
              "ruleIndex": 0,
              "level": "error",
              "message": {
                "text": "Path expression depends on a user-provided value."
              },
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": {
                      "uri": "src/routes/download.js"
                    },
                    "region": {
                      "startLine": 52,
                      "startColumn": 15,
                      "endLine": 52,
                      "endColumn": 45
                    }
                  }
                }
              ],
              "codeFlows": [
                {
                  "threadFlows": [
                    {
                      "locations": [
                        {
                          "location": {
                            "physicalLocation": {
                              "artifactLocation": { "uri": "src/routes/download.js" },
                              "region": { "startLine": 14, "startColumn": 20 }
                            },
                            "message": { "text": "source: req.query.filename" }
                          }
                        },
                        {
                          "location": {
                            "physicalLocation": {
                              "artifactLocation": { "uri": "src/routes/download.js" },
                              "region": { "startLine": 25, "startColumn": 9 }
                            },
                            "message": { "text": "let targetPath = path.resolve(baseDir, filename);" }
                          }
                        },
                        {
                          "location": {
                            "physicalLocation": {
                              "artifactLocation": { "uri": "src/routes/download.js" },
                              "region": { "startLine": 52, "startColumn": 15 }
                            },
                            "message": { "text": "sink: fs.createReadStream(targetPath)" }
                          }
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }"#;

    let session_id = SessionId::from_str("00000000-0000-0000-0000-000000000001").unwrap();
    let task_id = TaskId::new();
    let clock = TimestampUtc::now();

    let result = ingest_codeql_sarif_payload(PATH_INJECTION_SARIF, &session_id, task_id, clock)
        .expect("ingest should succeed");

    assert_eq!(result.total_sarif_results, 1);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.taint_traces_extracted, 1);
    assert_eq!(result.highest_severity, Some(Severity::High)); // 7.5 -> High

    let f = &result.findings[0];
    assert_eq!(
        f.source(),
        &FindingSource::StaticAnalysis {
            engine: "codeql".to_string(),
            rule_id: "js/path-injection".to_string(),
        }
    );
    assert_eq!(f.reachability(), Reachability::ReachableCallPath);

    let desc = f.description();
    assert!(desc.contains("CodeQL Interprocedural Taint Flow"));
    assert!(desc.contains("`🔴 SOURCE`"));
    assert!(desc.contains("req.query.filename"));
    assert!(desc.contains("`🟡 PROPAGATE`"));
    assert!(desc.contains("`💥 SINK`"));
    assert!(desc.contains("fs.createReadStream(targetPath)"));
}

#[test]
fn test_codeql_sarif_severity_fallback_and_no_taint_flow() {
    const HEURISTIC_SARIF: &str = r#"{
      "runs": [
        {
          "tool": {
            "driver": {
              "rules": []
            }
          },
          "results": [
            {
              "ruleId": "generic/hardcoded-secret",
              "level": "warning",
              "message": { "text": "Possible credential found in config." },
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": { "uri": "config.json" },
                    "region": { "startLine": 10 }
                  }
                }
              ]
            }
          ]
        }
      ]
    }"#;

    let session_id = SessionId::new();
    let task_id = TaskId::new();
    let clock = TimestampUtc::now();

    let result = ingest_codeql_sarif_payload(HEURISTIC_SARIF, &session_id, task_id, clock)
        .expect("ingest should succeed");

    assert_eq!(result.total_sarif_results, 1);
    assert_eq!(result.taint_traces_extracted, 0);
    assert_eq!(result.highest_severity, Some(Severity::Medium)); // warning fallback -> Medium

    let f = &result.findings[0];
    assert_eq!(f.reachability(), Reachability::SyntacticallyReferenced);
}

#[test]
fn test_codeql_corrupt_sarif_fails_closed() {
    let session_id = SessionId::new();
    let task_id = TaskId::new();
    let clock = TimestampUtc::now();

    let err =
        ingest_codeql_sarif_payload("{ invalid json ", &session_id, task_id, clock).unwrap_err();

    match err {
        sentra_core::CodeQlError::InvalidSarifPayload(_) => {}
        other => panic!("expected InvalidSarifPayload, got {other:?}"),
    }
}
