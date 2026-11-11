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
        workspace_root: None,
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
        Err(e) if matches!(e.kind(), PluginErrorKind::FrameTooLarge { bytes, limit } if *bytes == 2_000_000 && *limit == 1_048_576)
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
        workspace_root: None,
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
        Err(e) if matches!(e.kind(), PluginErrorKind::FrameTooLarge { .. })
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
        workspace_root: None,
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

    if bun_available() {
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
            .execute_in_workspace(
                &repo_root,
                "task-test-lifecycle-1",
                PluginCapability::DependencyAudit,
                serde_json::json!({ "severity_threshold": "high" }),
            )
            .expect("execute completed");
        assert_eq!(exec_out.exit_code, 0);
        assert!(exec_out.summary.contains("Snyk audit detected"));
        let session = driver.last_session().expect("session report");
        assert!(session.workspace_root.is_some());
    }
}

// ---------------------------------------------------------------------------
// Host hardening: manifests, discovery and hostile adapters in temp directories.
// ---------------------------------------------------------------------------

mod hardening {
    use std::{
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    use sentra_core::{
        DiscoveredPlugin, PluginCapability, PluginDriver, PluginErrorKind, PluginManifest,
        plugin::{
            ADAPTER_ENV_ALLOWLIST, CONTAINMENT_ENV, DiagnosticSeverity, PluginHost,
            adapter_environment, default_plugin_dir_from, is_valid_evidence_ref,
            resolve_adapter_command, resolve_plugin, run_contained, run_contained_observed,
            scan_plugin_dirs, split_command_line, validate_workspace_root,
        },
    };

    use super::bun_available;

    /// Temporary directory removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default();
            let dir = std::env::temp_dir().join(format!(
                "sentra-plugin-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self(std::fs::canonicalize(&dir).expect("canonical temp dir"))
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

    fn manifest_json(id: &str, executable: &str, secs: u32, frame: usize, total: usize) -> String {
        serde_json::json!({
            "id": id,
            "name": format!("Test adapter {id}"),
            "version": "1.0.0",
            "interface_version": 1,
            "family": "analysis_tool",
            "executable_path": executable,
            "declared_capabilities": ["static_analysis"],
            "quotas": {
                "max_memory_mib": 256,
                "max_execution_time_secs": secs,
                "max_frame_bytes": frame,
                "max_total_output_bytes": total
            },
            "egress_policy": "strictly_denied"
        })
        .to_string()
    }

    /// One Bun adapter whose behaviour is selected by `MODE`.
    const ADAPTER: &str = r#"import * as readline from "readline";
import * as fs from "fs";
import { spawn } from "child_process";
const ID = __ID__;
const MODE = __MODE__;
const HEARTBEAT = __HEARTBEAT__;
const MARKER = __MARKER__;
const emit = (frame: object) => process.stdout.write(JSON.stringify(frame) + "\n");
// Stdin-driven adapters exit as soon as the host closes stdin.
process.stdin.on("end", () => { if (MODE.startsWith("orphan")) process.exit(0); });
const ack = () => emit({ status: "initialize_ack", plugin_id: ID, interface_version: 1, capabilities: ["static_analysis"] });
readline.createInterface({ input: process.stdin }).on("line", (line: string) => {
  const req = JSON.parse(line);
  if (MODE === "silent") return;
  if (req.operation === "initialize") {
    if (MODE === "crash") process.exit(3);
    if (MODE === "stderr_flood") {
      // Synchronous writes, so every byte is in the pipe before the ack.
      // process.stderr.write may queue pipe writes inside the runtime and drop what
      // is still queued when the adapter exits, which no host can count.
      const chunk = Buffer.from("E".repeat(64 * 1024) + "\n");
      for (let i = 0; i < 32; i++) {
        for (let off = 0; off < chunk.length;) {
          try { off += fs.writeSync(2, chunk, off); } catch (e: any) { if (e?.code !== "EAGAIN") throw e; }
        }
      }
    }
    if (MODE === "huge_line") {
      process.stdout.write("A".repeat(8 * 1024 * 1024));
      setInterval(() => {}, 1000);
      return;
    }
    if (MODE.startsWith("orphan")) {
      // `detached: true` starts the child in a new session (`setsid`), outside the
      // adapter's process group (Node documents this; Bun did so on Linux in CI).
      const env = { ...process.env };
      if (MODE.includes("unmarked")) delete env[MARKER];
      const code = "setInterval(() => require('fs').writeFileSync(" + JSON.stringify(HEARTBEAT) + ", String(Date.now())), 50)";
      spawn(process.execPath, ["-e", code], { stdio: "ignore", detached: true, env }).unref();
      const started = Date.now();
      const wait = () => (fs.existsSync(HEARTBEAT) || Date.now() - started > 5000) ? (MODE.endsWith("_exit") ? ack() : undefined) : setTimeout(wait, 25);
      wait();
      return;
    }
    if (MODE === "grandchild") {
      const code = "setInterval(() => require('fs').writeFileSync(" + JSON.stringify(HEARTBEAT) + ", String(Date.now())), 50)";
      spawn(process.execPath, ["-e", code], { stdio: "ignore" });
      const started = Date.now();
      const wait = () => (fs.existsSync(HEARTBEAT) || Date.now() - started > 5000) ? ack() : setTimeout(wait, 25);
      wait();
      return;
    }
    ack();
  } else if (req.operation === "probe") {
    const details = MODE === "env_names" ? Object.keys(process.env).sort().join(",") : String(req.workspace_root);
    emit({ status: "probe_result", applicable: true, details, unsupported_reason: null });
  } else if (req.operation === "execute") {
    const taskId = MODE === "forged" ? "task-forged" : req.task_id;
    const refs = MODE === "bad_ref" ? ["../../outside/evidence"] : ["example:" + req.task_id];
    emit({ status: "execute_result", task_id: taskId, exit_code: 0, evidence_refs: refs, summary: "ws=" + String(req.workspace_root) });
  } else if (req.operation === "shutdown") {
    if (MODE === "grandchild" || MODE === "ignore_shutdown") return;
    emit({ status: "shutdown_ack" });
    process.exit(0);
  }
});
"#;

    struct Fixture {
        root: TempDir,
        heartbeat: PathBuf,
    }

    fn adapter(mode: &str, secs: u32, frame: usize, total: usize) -> (Fixture, DiscoveredPlugin) {
        let root = TempDir::new(mode);
        let dir = root.path().join("adapter");
        std::fs::create_dir_all(&dir).unwrap();
        let heartbeat = root.path().join("heartbeat.txt");
        let id = format!("test.adapter.{}", mode.replace('_', "-"));
        let script = ADAPTER
            .replace("__ID__", &serde_json::to_string(&id).unwrap())
            .replace("__MODE__", &serde_json::to_string(mode).unwrap())
            .replace(
                "__HEARTBEAT__",
                &serde_json::to_string(&heartbeat.to_string_lossy()).unwrap(),
            )
            .replace(
                "__MARKER__",
                &serde_json::to_string(CONTAINMENT_ENV).unwrap(),
            );
        std::fs::write(dir.join("adapter.ts"), script).unwrap();
        std::fs::write(
            dir.join("manifest.json"),
            manifest_json(&id, "bun adapter.ts", secs, frame, total),
        )
        .unwrap();
        let plugin = DiscoveredPlugin::from_manifest_file(dir.join("manifest.json")).unwrap();
        (Fixture { root, heartbeat }, plugin)
    }

    const MIB: usize = 1024 * 1024;

    #[test]
    fn silent_adapter_times_out_and_is_killed() {
        if !bun_available() {
            return;
        }
        let (fixture, plugin) = adapter("silent", 2, MIB, 10 * MIB);
        let mut driver = PluginDriver::new(plugin).unwrap();
        let started = Instant::now();
        let err = driver.probe(fixture.root.path()).unwrap_err();
        assert!(
            matches!(err.kind(), PluginErrorKind::Timeout { limit_secs: 2, .. }),
            "{err}"
        );
        assert_eq!(err.code(), "plugin_timeout");
        assert!(started.elapsed() < Duration::from_secs(10));
        let session = driver.last_session().unwrap();
        assert!(session.timed_out);
        assert!(session.killed_by_host);
    }

    #[test]
    fn crashing_adapter_reports_process_exit() {
        if !bun_available() {
            return;
        }
        let (fixture, plugin) = adapter("crash", 20, MIB, 10 * MIB);
        let mut driver = PluginDriver::new(plugin).unwrap();
        let err = driver.probe(fixture.root.path()).unwrap_err();
        assert!(
            matches!(err.kind(), PluginErrorKind::ProcessCrashDetected { .. }),
            "{err}"
        );
        assert_eq!(driver.last_session().unwrap().process_exit_code, Some(3));
    }

    #[test]
    fn stderr_flood_is_drained_and_counted() {
        if !bun_available() {
            return;
        }
        // 2 MiB of stderr used to deadlock the host above ~64 KiB. Every byte the
        // adapter wrote is counted, also what was still in the pipe when it exited.
        const FLOOD_BYTES: usize = 32 * (64 * 1024 + 1);
        let (fixture, plugin) = adapter("stderr_flood", 20, MIB, 10 * MIB);
        let mut driver = PluginDriver::new(plugin).unwrap();
        driver.probe(fixture.root.path()).expect("probe completes");
        let session = driver.last_session().unwrap();
        assert!(
            session.stderr_bytes >= FLOOD_BYTES,
            "{}",
            session.stderr_bytes
        );
        assert!(session.stderr_tail.len() <= sentra_core::plugin::STDERR_TAIL_BYTES);

        // The same stderr volume breaches a cumulative quota during the handshake. The
        // adapter acknowledges only after its last write returned, so at least the
        // flood minus the pipe's capacity (64 KiB by default; an unprivileged process
        // can enlarge it to 1 MiB on a default Linux) was drained by then: > 512 KiB.
        let (fixture, plugin) = adapter("stderr_flood", 20, 64 * 1024, MIB / 2);
        let mut driver = PluginDriver::new(plugin).unwrap();
        let err = driver.probe(fixture.root.path()).unwrap_err();
        assert!(
            matches!(err.kind(), PluginErrorKind::OutputQuotaExceeded { limit, .. } if *limit == MIB / 2),
            "{err}"
        );
    }

    #[test]
    fn newline_free_stream_is_cut_at_the_frame_limit() {
        if !bun_available() {
            return;
        }
        let (fixture, plugin) = adapter("huge_line", 20, 64 * 1024, MIB);
        let mut driver = PluginDriver::new(plugin).unwrap();
        let started = Instant::now();
        let err = driver.probe(fixture.root.path()).unwrap_err();
        assert!(
            matches!(err.kind(), PluginErrorKind::FrameTooLarge { limit, .. } if *limit == 64 * 1024),
            "{err}"
        );
        assert_eq!(err.code(), "plugin_frame_too_large");
        assert!(err.reason().contains("max_frame_bytes"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(15));
        assert!(driver.last_session().unwrap().killed_by_host);
    }

    #[test]
    fn adapter_ignoring_shutdown_and_its_children_are_killed() {
        if !bun_available() {
            return;
        }
        let (fixture, plugin) = adapter("grandchild", 20, MIB, 10 * MIB);
        let mut driver = PluginDriver::new(plugin).unwrap();
        let started = Instant::now();
        driver.probe(fixture.root.path()).expect("probe completes");
        // Bounded by the shutdown grace, not the 20 s session deadline.
        assert!(started.elapsed() < Duration::from_secs(12));
        assert!(driver.last_session().unwrap().killed_by_host);
        assert!(fixture.heartbeat.exists(), "grandchild never started");

        std::thread::sleep(Duration::from_millis(500));
        let before = std::fs::read_to_string(&fixture.heartbeat).unwrap_or_default();
        std::thread::sleep(Duration::from_millis(700));
        let after = std::fs::read_to_string(&fixture.heartbeat).unwrap_or_default();
        assert_eq!(before, after, "grandchild still writes its heartbeat");
    }

    /// Waits until the heartbeat file stops changing (the writer is dead).
    fn heartbeat_stopped(fixture: &Fixture) -> bool {
        writer_stopped(&fixture.heartbeat)
    }

    /// Waits until `file` stops changing (its writer is dead).
    fn writer_stopped(file: &Path) -> bool {
        std::thread::sleep(Duration::from_millis(500));
        let before = std::fs::read_to_string(file).unwrap_or_default();
        std::thread::sleep(Duration::from_millis(700));
        let after = std::fs::read_to_string(file).unwrap_or_default();
        before == after
    }

    #[test]
    fn detached_children_of_a_stdin_driven_adapter_die_on_timeout() {
        if !bun_available() {
            return;
        }
        // Audit repro: the adapter spawns a detached child, never answers and exits
        // on stdin EOF. Closing stdin before the tree kill used to orphan the child.
        let (fixture, plugin) = adapter("orphan_silent", 3, MIB, 10 * MIB);
        let mut driver = PluginDriver::new(plugin).unwrap();
        let err = driver.probe(fixture.root.path()).unwrap_err();
        assert_eq!(err.code(), "plugin_timeout", "{err}");
        let session = driver.last_session().unwrap();
        assert!(session.killed_by_host);
        assert_ne!(
            session.process_exit_code,
            Some(0),
            "adapter exited on EOF first"
        );
        assert!(fixture.heartbeat.exists(), "detached child never started");
        assert!(
            heartbeat_stopped(&fixture),
            "detached child survived the timeout"
        );
    }

    #[test]
    fn detached_children_without_the_marker_die_while_the_adapter_lives() {
        if !bun_available() {
            return;
        }
        // The detached child is started without the containment variable. It is still
        // killed while its parent, the adapter, is alive: Windows through the Job
        // Object, Linux and macOS through its parent process id. (Once its parent has
        // exited, such a child is not found on Unix; see docs/LIMITATIONS.md.)
        let (fixture, plugin) = adapter("orphan_unmarked_silent", 3, MIB, 10 * MIB);
        let mut driver = PluginDriver::new(plugin).unwrap();
        let err = driver.probe(fixture.root.path()).unwrap_err();
        assert_eq!(err.code(), "plugin_timeout", "{err}");
        assert!(driver.last_session().unwrap().killed_by_host);
        assert!(fixture.heartbeat.exists(), "detached child never started");
        assert!(
            heartbeat_stopped(&fixture),
            "unmarked detached child survived the timeout"
        );
    }

    #[test]
    fn detached_children_of_an_adapter_that_exits_by_itself_die() {
        if !bun_available() {
            return;
        }
        // The adapter acknowledges shutdown and exits on its own; its detached child
        // (a new session on Unix) must still be terminated: Job Object on Windows, the
        // containment variable on Linux and macOS.
        let (fixture, plugin) = adapter("orphan_exit", 20, MIB, 10 * MIB);
        let mut driver = PluginDriver::new(plugin).unwrap();
        driver.probe(fixture.root.path()).expect("probe completes");
        assert!(fixture.heartbeat.exists(), "detached child never started");
        assert!(
            heartbeat_stopped(&fixture),
            "detached child outlived the session"
        );
    }

    #[test]
    fn run_contained_kills_detached_children_left_behind() {
        if !bun_available() {
            return;
        }
        // The containment of `run_contained` (used for CodeQL) after a normal exit: the
        // program starts a detached child and exits 0 without waiting for it.
        let root = TempDir::new("contained");
        let heartbeat = root.path().join("heartbeat.txt");
        let script = r#"const { spawn } = require("child_process");
const fs = require("fs");
const HEARTBEAT = __HEARTBEAT__;
const code = "setInterval(() => require('fs').writeFileSync(" + JSON.stringify(HEARTBEAT) + ", String(Date.now())), 50)";
spawn(process.execPath, ["-e", code], { stdio: "ignore", detached: true }).unref();
const started = Date.now();
const wait = () => (fs.existsSync(HEARTBEAT) || Date.now() - started > 5000) ? process.exit(0) : setTimeout(wait, 25);
wait();
"#
        .replace(
            "__HEARTBEAT__",
            &serde_json::to_string(&heartbeat.to_string_lossy()).unwrap(),
        );
        std::fs::write(root.path().join("leave-child.js"), script).unwrap();
        let env = adapter_environment(std::env::vars_os());
        let bun = resolve_adapter_command(&["bun".to_string()], root.path(), &env)
            .unwrap()
            .program;
        let run = run_contained(
            &bun,
            &["leave-child.js".into()],
            root.path(),
            &env,
            Duration::from_secs(20),
            4096,
        )
        .unwrap();
        assert_eq!(run.exit_code, Some(0), "{run:?}");
        assert!(!run.timed_out);
        assert!(heartbeat.exists(), "detached child never started");
        assert!(
            writer_stopped(&heartbeat),
            "detached child outlived the contained run"
        );
    }

    #[test]
    fn run_contained_observed_calls_back_while_the_program_runs() {
        if !bun_available() {
            return;
        }
        // The CodeQL heartbeat is sent from this callback while a step runs.
        let root = TempDir::new("observed");
        let env = adapter_environment(std::env::vars_os());
        let bun = resolve_adapter_command(&["bun".to_string()], root.path(), &env)
            .unwrap()
            .program;
        let never = std::sync::atomic::AtomicBool::new(false);
        let mut poll_times = Vec::new();
        let started = Instant::now();
        let run = run_contained_observed(
            &bun,
            &["-e".into(), "setTimeout(() => {}, 1500)".into()],
            root.path(),
            &env,
            Duration::from_secs(20),
            4096,
            &never,
            &mut || poll_times.push(started.elapsed()),
        )
        .unwrap();
        assert_eq!(run.exit_code, Some(0), "{run:?}");
        assert!(started.elapsed() >= Duration::from_millis(1500));
        // The callback runs repeatedly while the program is still running, not only
        // once at the end. The loop sleeps 20 ms between polls, but the count is not
        // asserted: on GitHub's macOS runners a 20 ms sleep took about 90 ms (7 polls
        // in 600 ms), so only "several polls spread over the run" is checked.
        assert!(poll_times.len() >= 3, "{} polls", poll_times.len());
        let spread = *poll_times.last().unwrap() - poll_times[0];
        assert!(
            spread >= Duration::from_millis(500),
            "polls spread over {spread:?}"
        );
    }

    #[test]
    fn adapter_environment_is_reduced_to_the_allowlist() {
        if !bun_available() {
            return;
        }
        let (fixture, plugin) = adapter("env_names", 20, MIB, 10 * MIB);
        let mut driver = PluginDriver::new(plugin).unwrap();
        let report = driver.probe(fixture.root.path()).unwrap();
        let names: Vec<&str> = report
            .details
            .split(',')
            .filter(|name| !name.is_empty())
            .collect();
        // The only variable the host adds is its containment marker, on Linux and
        // macOS only; it carries no host data (see `CONTAINMENT_ENV`).
        let marked = cfg!(any(target_os = "linux", target_os = "macos"));
        assert_eq!(names.contains(&CONTAINMENT_ENV), marked, "{names:?}");
        let leaked: Vec<&str> = names
            .iter()
            .copied()
            .filter(|name| !(marked && *name == CONTAINMENT_ENV))
            .filter(|name| {
                !ADAPTER_ENV_ALLOWLIST
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(name))
            })
            .collect();
        assert!(leaked.is_empty(), "adapter saw extra variables: {leaked:?}");
        // The test process itself runs with Cargo variables that must not leak.
        assert!(
            std::env::var_os("CARGO_PKG_NAME").is_some() || std::env::var_os("CARGO").is_some()
        );
    }

    #[test]
    fn execute_carries_the_validated_workspace_root() {
        if !bun_available() {
            return;
        }
        let (fixture, plugin) = adapter("echo_ws", 20, MIB, 10 * MIB);
        let workspace = fixture.root.path().join("ws");
        std::fs::create_dir_all(&workspace).unwrap();
        let expected = validate_workspace_root(&workspace).unwrap();
        // `..` across real directories folds to the same root.
        let dotted = workspace.join(".").join("..").join("ws");
        assert_eq!(validate_workspace_root(&dotted).unwrap(), expected);
        let mut driver = PluginDriver::new(plugin).unwrap();
        let out = driver
            .execute_in_workspace(
                &workspace,
                "task-ws-1",
                PluginCapability::StaticAnalysis,
                serde_json::json!({}),
            )
            .unwrap();
        assert_eq!(out.summary, format!("ws={expected}"));
        assert_eq!(out.evidence_refs, vec!["example:task-ws-1".to_string()]);
        assert_eq!(
            driver.last_session().unwrap().workspace_root.as_deref(),
            Some(expected.as_str())
        );

        // Replay within the same driver is refused before a process starts.
        let err = driver
            .execute_in_workspace(
                &workspace,
                "task-ws-1",
                PluginCapability::StaticAnalysis,
                serde_json::json!({}),
            )
            .unwrap_err();
        assert!(matches!(err.kind(), PluginErrorKind::ReplayRejected { .. }));

        let missing = fixture.root.path().join("missing");
        let err = driver
            .execute_in_workspace(
                &missing,
                "task-ws-2",
                PluginCapability::StaticAnalysis,
                serde_json::json!({}),
            )
            .unwrap_err();
        assert_eq!(err.code(), "plugin_invalid_workspace");
    }

    #[test]
    fn forged_task_id_and_path_evidence_refs_are_rejected() {
        if !bun_available() {
            return;
        }
        for mode in ["forged", "bad_ref"] {
            let (fixture, plugin) = adapter(mode, 20, MIB, 10 * MIB);
            let mut driver = PluginDriver::new(plugin).unwrap();
            let err = driver
                .execute_in_workspace(
                    fixture.root.path(),
                    "task-real-1",
                    PluginCapability::StaticAnalysis,
                    serde_json::json!({}),
                )
                .unwrap_err();
            assert!(
                matches!(err.kind(), PluginErrorKind::ResultMismatch { .. }),
                "{mode}: {err}"
            );
        }
    }

    #[test]
    fn capability_fence_runs_before_spawning() {
        let root = TempDir::new("fence");
        let dir = root.path().join("adapter");
        std::fs::create_dir_all(&dir).unwrap();
        // The executable does not exist: only a pre-spawn check can answer first.
        std::fs::write(
            dir.join("manifest.json"),
            manifest_json("test.adapter.fence", "./missing-binary", 5, MIB, MIB),
        )
        .unwrap();
        let plugin = DiscoveredPlugin::from_manifest_file(dir.join("manifest.json")).unwrap();
        let mut driver = PluginDriver::new(plugin).unwrap();
        let err = driver
            .execute(
                "task-fence-1",
                PluginCapability::FuzzExecution,
                serde_json::json!({}),
            )
            .unwrap_err();
        assert!(matches!(
            err.kind(),
            PluginErrorKind::UndeclaredCapability { .. }
        ));
        assert!(driver.last_session().is_none());

        let err = driver
            .execute(
                "task-fence-2",
                PluginCapability::StaticAnalysis,
                serde_json::json!({}),
            )
            .unwrap_err();
        assert_eq!(err.code(), "plugin_executable_rejected");
    }

    #[test]
    fn executable_resolution_stays_inside_the_adapter_dir() {
        let root = TempDir::new("resolve");
        let dir = root.path().join("adapter");
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join("bin").join("tool.exe"), b"").unwrap();
        std::fs::write(root.path().join("outside.exe"), b"").unwrap();
        let argv = |line: &str| split_command_line(line).unwrap();

        for line in ["./bin/tool.exe --flag", "bin/tool.exe --flag"] {
            let resolved = resolve_adapter_command(&argv(line), &dir, &[]).unwrap();
            assert!(
                resolved
                    .program
                    .ends_with(Path::new("bin").join("tool.exe"))
            );
            assert!(resolved.program.is_absolute());
            assert_eq!(resolved.args, vec!["--flag".to_string()]);
        }
        let err = resolve_adapter_command(&argv("../outside.exe"), &dir, &[]).unwrap_err();
        assert_eq!(err.code(), "plugin_executable_rejected");
        let err = resolve_adapter_command(&argv("./nope.exe"), &dir, &[]).unwrap_err();
        assert_eq!(err.code(), "plugin_executable_rejected");
        // Bare names never resolve against the adapter dir or the current directory.
        let err = resolve_adapter_command(&argv("tool.exe"), &dir.join("bin"), &[]).unwrap_err();
        assert_eq!(err.code(), "plugin_executable_rejected");
    }

    #[test]
    fn command_lines_split_without_a_shell() {
        assert_eq!(
            split_command_line(r#""C:\Program Files\Tool\tool.exe" --rule 'a b' x"#).unwrap(),
            vec![r"C:\Program Files\Tool\tool.exe", "--rule", "a b", "x"]
        );
        assert_eq!(
            split_command_line("  bun   adapter.ts ").unwrap(),
            vec!["bun", "adapter.ts"]
        );
        assert!(split_command_line("\"unterminated").is_err());
    }

    #[test]
    fn environment_filter_keeps_only_allowlisted_names() {
        let vars = [
            ("PATH", "p"),
            ("OPENAI_API_KEY", "secret"),
            ("GITHUB_TOKEN", "secret"),
            ("HOME", "h"),
            ("SENTRA_AUDIT_CANARY_TOKEN", "secret"),
        ]
        .map(|(k, v)| (k.into(), v.into()));
        let kept: Vec<String> = adapter_environment(vars)
            .into_iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(kept, vec!["PATH".to_string(), "HOME".to_string()]);
    }

    fn write_manifest(dir: &Path, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("manifest.json"), body).unwrap();
    }

    #[test]
    fn discovery_reports_skipped_and_ambiguous_manifests() {
        let root = TempDir::new("discovery");
        let plugins = root.path().join("plugins");
        write_manifest(
            &plugins.join("good"),
            &manifest_json("test.good", "bun adapter.ts", 5, MIB, MIB),
        );
        // Documented plain-string custom capability parses.
        let custom = manifest_json("test.custom", "bun adapter.ts", 5, MIB, MIB).replace(
            "[\"static_analysis\"]",
            "[\"static_analysis\",\"my_custom_scan\"]",
        );
        write_manifest(&plugins.join("custom"), &custom);
        // Invalid capability string.
        let bad_cap = manifest_json("test.badcap", "bun adapter.ts", 5, MIB, MIB)
            .replace("[\"static_analysis\"]", "[\"Not A Capability!\"]");
        write_manifest(&plugins.join("badcap"), &bad_cap);
        write_manifest(&plugins.join("broken"), "{ not json");
        // Same id twice.
        write_manifest(
            &plugins.join("dup-a"),
            &manifest_json("test.dup", "bun adapter.ts", 5, MIB, MIB),
        );
        write_manifest(
            &plugins.join("dup-b"),
            &manifest_json("test.dup", "bun adapter.ts", 5, MIB, MIB),
        );
        // Unknown key is a warning only.
        let extra = manifest_json("test.extra", "bun adapter.ts", 5, MIB, MIB).replacen(
            '{',
            "{\"publisher\":\"x\",",
            1,
        );
        write_manifest(&plugins.join("extra"), &extra);

        let missing = root.path().join("missing");
        let scanned = scan_plugin_dirs(&[plugins.clone(), missing]);
        let ids: Vec<&str> = scanned
            .plugins
            .iter()
            .map(|p| p.manifest.id.as_str())
            .collect();
        assert_eq!(ids, vec!["test.custom", "test.extra", "test.good"]);
        assert!(
            scanned.plugins[0]
                .manifest
                .supports_capability(&PluginCapability::Custom("my_custom_scan".into()))
        );
        let codes: Vec<(&str, DiagnosticSeverity)> = scanned
            .diagnostics
            .iter()
            .map(|d| (d.code.as_str(), d.severity))
            .collect();
        for expected in [
            ("manifest_invalid", DiagnosticSeverity::Error),
            ("manifest_invalid_json", DiagnosticSeverity::Error),
            ("duplicate_plugin_id", DiagnosticSeverity::Error),
            ("manifest_unknown_field", DiagnosticSeverity::Warning),
            ("plugin_dir_not_found", DiagnosticSeverity::Error),
        ] {
            assert!(
                codes.contains(&expected),
                "missing {expected:?} in {codes:?}"
            );
        }
        assert!(scanned.has_errors());

        let err = resolve_plugin(std::slice::from_ref(&plugins), "test.dup").unwrap_err();
        match err.kind() {
            PluginErrorKind::DuplicatePluginId { manifest_paths, .. } => {
                assert_eq!(manifest_paths.len(), 2)
            }
            other => panic!("unexpected {other:?}"),
        }
        let err = resolve_plugin(std::slice::from_ref(&plugins), "test.none").unwrap_err();
        assert_eq!(err.code(), "plugin_not_found");
        assert!(resolve_plugin(std::slice::from_ref(&plugins), "test.good").is_ok());
    }

    #[test]
    fn root_manifest_reports_ignored_children() {
        let root = TempDir::new("rootmask");
        write_manifest(
            root.path(),
            &manifest_json("test.root", "bun adapter.ts", 5, MIB, MIB),
        );
        write_manifest(
            &root.path().join("child"),
            &manifest_json("test.child", "bun adapter.ts", 5, MIB, MIB),
        );
        let scanned = scan_plugin_dirs(&[root.path().to_path_buf()]);
        assert_eq!(scanned.plugins.len(), 1);
        assert!(
            scanned
                .diagnostics
                .iter()
                .any(|d| d.code == "nested_manifest_ignored")
        );
    }

    #[test]
    fn manifest_validation_is_strict() {
        let base: PluginManifest =
            serde_json::from_str(&manifest_json("test.ok", "bun adapter.ts", 5, MIB, MIB)).unwrap();
        assert!(base.validate().is_ok());
        let bad_id = PluginManifest {
            id: "org.example.\"quoted\"".into(),
            ..base.clone()
        };
        assert!(bad_id.validate().is_err());
        let bad_version = PluginManifest {
            interface_version: 2,
            ..base.clone()
        };
        assert!(bad_version.validate().is_err());
        let mut zero_time = base.clone();
        zero_time.quotas.max_execution_time_secs = 0;
        assert!(zero_time.validate().is_err());
        let mut huge_time = base.clone();
        huge_time.quotas.max_execution_time_secs = u32::MAX;
        assert_eq!(
            huge_time.quotas.execution_timeout(),
            Duration::from_secs(u64::from(sentra_core::plugin::MAX_EXECUTION_TIME_SECS))
        );
        // Capabilities serialize as plain strings; the legacy object form still reads.
        assert_eq!(
            serde_json::to_string(&PluginCapability::Custom("x.y".into())).unwrap(),
            "\"x.y\""
        );
        let legacy: PluginCapability = serde_json::from_str("{\"custom\":\"x.y\"}").unwrap();
        assert_eq!(legacy, PluginCapability::Custom("x.y".into()));
    }

    #[test]
    fn evidence_reference_grammar() {
        for ok in [
            "sha256:abc",
            "example:task-1",
            "snyk:snyk-audit-task-1.json",
        ] {
            assert!(is_valid_evidence_ref(ok), "{ok}");
        }
        for bad in [
            "../../outside/evidence",
            "file:///C:/Windows/win.ini",
            "sha256:a..b",
            "noscheme",
            "Upper:x",
            "x:",
        ] {
            assert!(!is_valid_evidence_ref(bad), "{bad}");
        }
        assert!(PluginHost::validate_execute_result("t-1", "t-2", &[]).is_err());
    }

    #[test]
    fn default_plugin_dir_is_explicit_and_never_relative() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| std::ffi::OsString::from(*v))
            }
        };
        let explicit = if cfg!(windows) {
            r"C:\ops\plugins"
        } else {
            "/ops/plugins"
        };
        let pairs: &'static [(&'static str, &'static str)] = if cfg!(windows) {
            &[("SENTRA_PLUGIN_DIR", r"C:\ops\plugins")]
        } else {
            &[("SENTRA_PLUGIN_DIR", "/ops/plugins")]
        };
        assert_eq!(
            default_plugin_dir_from(env(pairs)),
            Some(PathBuf::from(explicit))
        );
        // Relative overrides are ignored.
        let relative: &'static [(&'static str, &'static str)] = &[
            ("SENTRA_PLUGIN_DIR", "plugins"),
            ("APPDATA", "rel"),
            ("XDG_CONFIG_HOME", "rel"),
            ("HOME", "rel"),
        ];
        assert_eq!(default_plugin_dir_from(env(relative)), None);
        let platform: &'static [(&'static str, &'static str)] = if cfg!(windows) {
            &[("APPDATA", r"C:\Users\op\AppData\Roaming")]
        } else {
            &[("HOME", "/home/op")]
        };
        let dir = default_plugin_dir_from(env(platform)).unwrap();
        assert!(dir.ends_with(Path::new("sentra").join("plugins")));
    }
}

fn bun_available() -> bool {
    std::process::Command::new("bun")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
