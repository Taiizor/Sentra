//! Integration and conformance tests for the Subprocess Plugin SDK and Adapter Protocol
//! (REQ-F16, Plugin Architecture Specification).

use sentra_core::{
    AdapterFamily, EgressPolicy, HostStatus, PluginCapability, PluginErrorKind, PluginHost,
    PluginManifest, PluginQuotas, PluginRequest, PluginResponse, SampleAdapter, SampleAdapterMode,
    SemverVersion, decode_frame, encode_frame,
};

fn create_valid_manifest() -> PluginManifest {
    PluginManifest {
        id: "org.sentra.adapter.sample".to_string(),
        name: "Sample Static Analysis Adapter".to_string(),
        version: SemverVersion::new(1, 0, 0),
        interface_version: 1,
        family: AdapterFamily::AnalysisTool,
        executable_path: "bin/sample-adapter".to_string(),
        declared_capabilities: vec![
            PluginCapability::SourceDiscovery,
            PluginCapability::StaticAnalysis,
        ],
        quotas: PluginQuotas {
            max_memory_mib: 512,
            max_execution_time_secs: 30,
            max_frame_bytes: 1_048_576,        // 1 MiB
            max_total_output_bytes: 5_242_880, // 5 MiB
        },
        egress_policy: EgressPolicy::StrictlyDenied,
    }
}

#[test]
fn test_plugin_manifest_validation() {
    let mut manifest = create_valid_manifest();
    assert!(manifest.validate().is_ok());

    // Empty ID rejected
    manifest.id = "".to_string();
    assert!(manifest.validate().is_err());

    // Empty executable path rejected
    manifest.id = "valid.id".to_string();
    manifest.executable_path = "".to_string();
    assert!(manifest.validate().is_err());

    // Zero frame bytes rejected
    manifest.executable_path = "bin/tool".to_string();
    manifest.quotas.max_frame_bytes = 0;
    assert!(manifest.validate().is_err());
}

#[test]
fn test_plugin_handshake_standard_conformance() {
    let manifest = create_valid_manifest();
    let mut host = PluginHost::new(manifest.clone()).expect("create host");
    assert_eq!(host.status, HostStatus::Uninitialized);

    let adapter = SampleAdapter::new(&manifest.id);

    // 1. Host creates initialize request
    let init_req = host.create_initialize_request();
    assert_eq!(init_req, PluginRequest::Initialize { host_version: 1 });

    // 2. Adapter handles request and returns ack
    let init_resp = adapter.handle_request(&init_req);

    // 3. Host negotiates handshake
    assert!(host.negotiate_handshake(&init_resp).is_ok());
    assert_eq!(host.status, HostStatus::Ready);
}

#[test]
fn test_plugin_incompatible_version_rejection() {
    let manifest = create_valid_manifest();
    let mut host = PluginHost::new(manifest.clone()).expect("create host");

    // Adapter responds with incompatible interface version 999
    let adapter = SampleAdapter::with_mode(&manifest.id, SampleAdapterMode::IncompatibleVersion);
    let init_req = host.create_initialize_request();
    let init_resp = adapter.handle_request(&init_req);

    let err = host.negotiate_handshake(&init_resp);
    assert!(matches!(
        err,
        Err(e) if matches!(e.kind(), PluginErrorKind::IncompatibleInterfaceVersion { expected: 1, received: 999 })
    ));
    assert!(host.is_quarantined());
}

#[test]
fn test_plugin_undeclared_capability_rejection() {
    let manifest = create_valid_manifest();
    let mut host = PluginHost::new(manifest.clone()).expect("create host");

    // Adapter responds with undeclared capability "unauthorized_root_exec"
    let adapter = SampleAdapter::with_mode(&manifest.id, SampleAdapterMode::UndeclaredCapability);
    let init_req = host.create_initialize_request();
    let init_resp = adapter.handle_request(&init_req);

    let err = host.negotiate_handshake(&init_resp);
    assert!(matches!(
        err,
        Err(e) if matches!(e.kind(), PluginErrorKind::UndeclaredCapability { .. })
    ));
    assert!(host.is_quarantined());
}

#[test]
fn test_plugin_dispatch_and_execution_lifecycle() {
    let manifest = create_valid_manifest();
    let mut host = PluginHost::new(manifest.clone()).expect("create host");
    let adapter = SampleAdapter::new(&manifest.id);

    // Handshake
    let init_resp = adapter.handle_request(&host.create_initialize_request());
    host.negotiate_handshake(&init_resp).expect("handshake");

    // Probe
    let probe_resp = adapter.handle_request(&PluginRequest::Probe {
        workspace_root: "/workspace".to_string(),
    });
    assert!(matches!(
        probe_resp,
        PluginResponse::ProbeResult {
            applicable: true,
            ..
        }
    ));

    // Plan
    let plan_resp = adapter.handle_request(&PluginRequest::Plan {
        input_ref: "sha256:input-manifest-1".to_string(),
    });
    assert!(matches!(plan_resp, PluginResponse::PlanResult { .. }));

    // Execute job
    let task_id = "task-uuid-101";
    assert!(
        host.prepare_execute(task_id, &PluginCapability::StaticAnalysis)
            .is_ok()
    );
    assert_eq!(host.status, HostStatus::Executing);

    let exec_resp = adapter.handle_request(&PluginRequest::Execute {
        task_id: task_id.to_string(),
        lease_id: "lease-1".to_string(),
        capability: PluginCapability::StaticAnalysis,
        arguments: serde_json::json!({ "rules": ["no-eval", "safe-regex"] }),
    });

    assert!(matches!(
        exec_resp,
        PluginResponse::ExecuteResult { exit_code: 0, .. }
    ));

    assert!(host.complete_execute().is_ok());
    assert_eq!(host.status, HostStatus::Ready);
}

#[test]
fn test_plugin_undeclared_capability_at_dispatch_rejected() {
    let manifest = create_valid_manifest();
    let mut host = PluginHost::new(manifest.clone()).expect("create host");
    let adapter = SampleAdapter::new(&manifest.id);

    let init_resp = adapter.handle_request(&host.create_initialize_request());
    host.negotiate_handshake(&init_resp).expect("handshake");

    // Manifest only declared SourceDiscovery and StaticAnalysis.
    // Dispatching FuzzExecution must fail closed!
    let err = host.prepare_execute("task-102", &PluginCapability::FuzzExecution);
    assert!(matches!(
        err,
        Err(e) if matches!(e.kind(), PluginErrorKind::UndeclaredCapability { .. })
    ));
}

#[test]
fn test_plugin_replay_protection() {
    let manifest = create_valid_manifest();
    let mut host = PluginHost::new(manifest.clone()).expect("create host");
    let adapter = SampleAdapter::new(&manifest.id);

    let init_resp = adapter.handle_request(&host.create_initialize_request());
    host.negotiate_handshake(&init_resp).expect("handshake");

    // First dispatch succeeds
    assert!(
        host.prepare_execute("task-replay-1", &PluginCapability::StaticAnalysis)
            .is_ok()
    );
    assert!(host.complete_execute().is_ok());

    // Duplicate dispatch with same task ID rejected by idempotency fence
    let err = host.prepare_execute("task-replay-1", &PluginCapability::StaticAnalysis);
    assert!(matches!(
        err,
        Err(e) if matches!(e.kind(), PluginErrorKind::ReplayRejected { .. })
    ));
}

#[test]
fn test_plugin_oversized_frame_quota_rejection() {
    let manifest = create_valid_manifest();
    let mut host = PluginHost::new(manifest.clone()).expect("create host");

    // Single frame larger than max_frame_bytes (1 MiB)
    let frame_len = 2_000_000;
    let err = host.record_output_frame(frame_len);
    assert!(matches!(
        err,
        Err(e) if matches!(e.kind(), PluginErrorKind::OutputQuotaExceeded { bytes, limit } if *bytes == 2_000_000 && *limit == 1_048_576)
    ));
    assert!(host.is_quarantined());
}

#[test]
fn test_plugin_process_crash_handling() {
    let manifest = create_valid_manifest();
    let mut host = PluginHost::new(manifest.clone()).expect("create host");
    let adapter = SampleAdapter::with_mode(&manifest.id, SampleAdapterMode::CrashDuringExecution);

    let init_resp = adapter.handle_request(&host.create_initialize_request());
    host.negotiate_handshake(&init_resp).expect("handshake");

    host.prepare_execute("task-crash-1", &PluginCapability::StaticAnalysis)
        .expect("dispatch");

    let resp = adapter.handle_request(&PluginRequest::Execute {
        task_id: "task-crash-1".to_string(),
        lease_id: "lease-crash".to_string(),
        capability: PluginCapability::StaticAnalysis,
        arguments: serde_json::json!({}),
    });

    assert!(matches!(resp, PluginResponse::Error { code: 139, .. }));

    // Host marks process crashed and transitions to Terminated
    let crash_err = host.handle_process_crash(Some(139));
    assert!(matches!(
        crash_err.kind(),
        PluginErrorKind::ProcessCrashDetected {
            exit_code: Some(139)
        }
    ));
    assert_eq!(host.status, HostStatus::Terminated);
}

#[test]
fn test_plugin_protocol_frame_encoding_and_decoding() {
    let req = PluginRequest::Probe {
        workspace_root: "/home/user/project".to_string(),
    };

    let encoded = encode_frame(&req).expect("encode frame");
    assert!(encoded.ends_with('\n'));
    assert!(!encoded[..encoded.len() - 1].contains('\n'));

    let decoded: PluginRequest = decode_frame(&encoded, 1024).expect("decode frame");
    assert_eq!(decoded, req);

    // Frame exceeding quota fails closed
    let err = decode_frame::<PluginRequest>(&encoded, 10);
    assert!(matches!(
        err,
        Err(e) if matches!(e.kind(), PluginErrorKind::OutputQuotaExceeded { .. })
    ));
}

#[test]
fn test_plugin_prompt_injection_containment() {
    let manifest = create_valid_manifest();
    let mut host = PluginHost::new(manifest.clone()).expect("create host");
    let adapter = SampleAdapter::new(&manifest.id);

    let init_resp = adapter.handle_request(&host.create_initialize_request());
    host.negotiate_handshake(&init_resp).expect("handshake");

    // Host dispatches job containing adversarial prompt injection payload
    let hostile_payload = "'; rm -rf /; cat /etc/passwd; DROP TABLE findings; --";
    host.prepare_execute("task-injection-1", &PluginCapability::StaticAnalysis)
        .expect("dispatch");

    let resp = adapter.handle_request(&PluginRequest::Execute {
        task_id: "task-injection-1".to_string(),
        lease_id: "lease-inj".to_string(),
        capability: PluginCapability::StaticAnalysis,
        arguments: serde_json::json!({ "untrusted_input": hostile_payload }),
    });

    // Response strictly treats payload as passive structured data without execution
    match resp {
        PluginResponse::ExecuteResult {
            exit_code, summary, ..
        } => {
            assert_eq!(exit_code, 0);
            assert!(summary.contains("Analysis complete on args"));
        }
        other => panic!("Expected ExecuteResult, got {other:?}"),
    }
}

#[test]
fn test_example_adapters_manifest_conformance() {
    let manifest_paths = [
        "../../examples/adapters/sentra-adapter-semgrep/manifest.json",
        "../../examples/adapters/sentra-adapter-snyk/manifest.json",
        "../../examples/adapters/sentra-adapter-ollama/manifest.json",
    ];

    for rel_path in manifest_paths {
        let manifest_content = std::fs::read_to_string(rel_path)
            .unwrap_or_else(|e| panic!("Failed to read {rel_path}: {e}"));
        let manifest: PluginManifest = serde_json::from_str(&manifest_content)
            .unwrap_or_else(|e| panic!("Failed to deserialize {rel_path}: {e}"));
        assert!(
            manifest.validate().is_ok(),
            "Manifest {rel_path} validation failed"
        );
        let host = PluginHost::new(manifest);
        assert!(host.is_ok(), "Host creation for {rel_path} failed");
    }
}

#[test]
fn test_plugin_discovery_and_driver_lifecycle() {
    use sentra_core::{PluginDriver, discover_plugins_in_dir};
    use std::path::PathBuf;

    let adapters_dir = PathBuf::from("../../examples/adapters");
    let plugins = discover_plugins_in_dir(&adapters_dir);
    assert!(
        plugins.len() >= 3,
        "Expected at least 3 plugins in examples/adapters, found {}",
        plugins.len()
    );

    let snyk = plugins
        .into_iter()
        .find(|p| p.manifest.id == "org.sentra.adapter.snyk")
        .expect("snyk adapter found");

    let mut driver = PluginDriver::new(snyk).expect("driver created");

    let repo_root = std::fs::canonicalize("../..").unwrap_or_else(|_| PathBuf::from("."));

    let bun_available = std::process::Command::new("bun")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if bun_available {
        // Probe
        let probe_out = driver.probe(&repo_root).expect("probe executed");
        assert!(probe_out.applicable);
        assert!(
            probe_out
                .capabilities
                .contains(&PluginCapability::DependencyAudit)
        );

        // Execute
        let exec_out = driver
            .execute(
                "task-test-lifecycle-1",
                PluginCapability::DependencyAudit,
                serde_json::json!({ "severity_threshold": "high" }),
            )
            .expect("execute completed");
        assert_eq!(exec_out.exit_code, 0);
        assert!(exec_out.summary.contains("Snyk audit detected"));
    }
}
