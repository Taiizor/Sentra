use std::{
    ffi::OsString,
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use sentra_cli::{Command as CliCommand, parse, run, run_with_input};
use sentra_core::{
    CostUsd, OperatingMode, SecurityClassification, SessionId, SystemClock,
    persistence::{PersistenceRepository, SqliteConnectionManager},
};

fn args(words: &[&str]) -> Vec<OsString> {
    words.iter().map(OsString::from).collect()
}

#[test]
fn parses_typed_initialization_and_unicode_paths() {
    let parsed = parse(&args(&[
        "init",
        "--workspace",
        "workspace ü 空",
        "--database",
        "storage/local.db",
        "--json",
    ]))
    .unwrap_or_else(|_| panic!("valid grammar"));
    assert!(parsed.json);
    assert!(
        matches!(parsed.command, CliCommand::Init { workspace, database } if workspace == Path::new("workspace ü 空") && database == Path::new("storage/local.db"))
    );
}

#[test]
fn parses_status_default_workspace_and_explicit_session() {
    assert!(matches!(
        parse(&args(&["status", "--database", "local.db"]))
            .unwrap_or_else(|_| panic!())
            .command,
        CliCommand::Status {
            workspace: None,
            ..
        }
    ));
    let id = SessionId::new().to_string();
    assert!(
        matches!(parse(&args(&["session", "show", &id, "--workspace", "target", "--database", "local.db"])).unwrap_or_else(|_| panic!()).command, CliCommand::Session { id: parsed, .. } if parsed.to_string() == id)
    );
}

#[test]
fn rejects_unknown_commands_and_missing_or_duplicate_arguments() {
    for words in [
        vec!["scan"],
        vec!["execute"],
        vec!["approve"],
        vec!["init"],
        vec!["init", "--database", "x"],
        vec!["status"],
        vec!["status", "--database"],
        vec!["status", "--database", "x", "--database", "y"],
        vec![
            "status",
            "--database",
            "x",
            "--workspace",
            "a",
            "--workspace",
            "b",
        ],
        vec!["status", "--database", ""],
        vec!["status", "--database", "x", "--json", "--json"],
        vec!["--version", "unexpected"],
    ] {
        assert!(
            parse(&args(&words)).is_err(),
            "grammar must reject {words:?}"
        );
    }
}

#[test]
fn rejects_extra_positionals_unknown_flags_and_invalid_session_ids() {
    for words in [
        vec!["status", "extra", "--database", "x"],
        vec!["status", "--database", "x", "--force", "true"],
        vec!["session", "list", "--database", "x"],
        vec!["session", "show", "not-an-id", "--database", "x"],
        vec!["init", "--help", "unknown"],
    ] {
        assert!(parse(&args(&words)).is_err());
    }
    assert!(parse(&vec![OsString::from("--json"); 65]).is_err());
}

#[test]
fn help_and_version_are_predictable_and_need_no_filesystem_context() {
    for words in [
        vec![],
        vec!["--help"],
        vec!["help"],
        vec!["init", "--help"],
        vec!["status", "--help"],
        vec!["session", "--help"],
    ] {
        let response = run(&args(&words), Path::new(""));
        assert_eq!(response.exit_code, 0);
        assert!(
            response
                .stdout
                .contains("No scanning, AI or target execution")
        );
        assert!(response.stderr.is_empty());
    }
    let version = run(&args(&["--version"]), Path::new(""));
    assert_eq!(
        version.stdout,
        format!("sentra {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(
        run(&args(&["--json", "--help"]), Path::new("")).exit_code,
        0
    );
}

#[test]
fn parse_errors_do_not_echo_untrusted_arguments() {
    let response = run(
        &args(&["secret-token-sensitive-path", "--json"]),
        Path::new(""),
    );
    assert_eq!(response.exit_code, 2);
    assert!(response.stdout.is_empty());
    assert_eq!(
        response.stderr,
        "{\"schema_version\":1,\"error\":\"invalid_arguments\"}\n"
    );
    assert!(!format!("{response:?}").contains("secret-token"));
}

struct Fixture {
    root: PathBuf,
    workspace: PathBuf,
    db: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
        let root = temp.join(format!(
            "sentra-cli-{}-{}",
            std::process::id(),
            SessionId::new()
        ));
        fs::create_dir(&root).unwrap();
        let workspace = root.join("workspace ü Unicode 空 space");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(root.join("storage space")).unwrap();
        let db = root.join("storage space/local.db");
        Self {
            root,
            workspace,
            db,
        }
    }
    fn command(&self, name: &str) -> Vec<OsString> {
        vec![
            name.into(),
            "--workspace".into(),
            self.workspace.as_os_str().into(),
            "--database".into(),
            self.db.as_os_str().into(),
            "--json".into(),
        ]
    }
    fn invoke(&self, arguments: &[OsString]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sentra"))
            .args(arguments)
            .current_dir(&self.workspace)
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .env("OPENAI_API_KEY", "secret-not-consumed")
            .env("ANTHROPIC_API_KEY", "secret-not-consumed")
            .output()
            .unwrap()
    }
    fn init(&self) -> String {
        let output = self.invoke(&self.command("init"));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        session_id(&stdout)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let temp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let path = fs::canonicalize(&self.root).unwrap();
        assert!(path.starts_with(&temp) && path != temp);
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn session_id(json: &str) -> String {
    let field = "\"session_id\":\"";
    let start = json.find(field).unwrap() + field.len();
    let id = json[start..].split('"').next().unwrap();
    id.parse::<SessionId>().unwrap().to_string()
}

#[test]
fn binary_help_version_and_invalid_exit_codes() {
    let f = Fixture::new();
    for flag in ["--help", "--version"] {
        assert!(f.invoke(&args(&[flag])).status.success());
    }
    assert_eq!(f.invoke(&args(&["scan"])).status.code(), Some(2));
    assert_eq!(
        f.invoke(&args(&["init", "--workspace"])).status.code(),
        Some(2)
    );
    assert!(!f.db.exists());
}

#[test]
fn binary_init_repetition_status_and_session_keep_identity() {
    let f = Fixture::new();
    let id = f.init();
    let repeated = f.invoke(&f.command("init"));
    let stdout = String::from_utf8(repeated.stdout).unwrap();
    assert!(repeated.status.success());
    assert_eq!(session_id(&stdout), id);
    assert!(stdout.contains("\"created\":false"));
    let status = f.invoke(&args(&[
        "status",
        "--database",
        f.db.to_str().unwrap(),
        "--json",
    ]));
    assert!(status.status.success());
    assert_eq!(session_id(&String::from_utf8(status.stdout).unwrap()), id);
    let inspected = f.invoke(&args(&[
        "session",
        "show",
        &id,
        "--database",
        f.db.to_str().unwrap(),
        "--json",
    ]));
    assert!(inspected.status.success());
    assert_eq!(
        session_id(&String::from_utf8(inspected.stdout).unwrap()),
        id
    );
}

#[test]
fn status_uninitialized_is_distinct_from_error_and_creates_no_database() {
    let f = Fixture::new();
    let output = f.invoke(&f.command("status"));
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("\"initialized\":false")
    );
    assert!(!f.db.exists());
}

#[test]
fn binary_reports_corrupt_storage_as_error_without_leaking_data() {
    let f = Fixture::new();
    let bytes = b"sensitive-token-not-a-database";
    fs::write(&f.db, bytes).unwrap();
    for name in ["init", "status"] {
        let output = f.invoke(&f.command(name));
        assert_eq!(output.status.code(), Some(5));
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains("storage_or_service_failure"));
        assert!(!error.contains("sensitive-token"));
        assert!(!error.contains(f.root.to_str().unwrap()));
        assert!(!error.contains("secret-not-consumed"));
    }
    assert_eq!(fs::read(&f.db).unwrap(), bytes);
}

#[test]
fn binary_invalid_workspace_rejected_without_initializing_storage() {
    let f = Fixture::new();
    let output = f.invoke(&args(&[
        "init",
        "--workspace",
        f.root.join("missing").to_str().unwrap(),
        "--database",
        f.db.to_str().unwrap(),
    ]));
    assert_eq!(output.status.code(), Some(4));
    assert!(!f.db.exists());
}

#[test]
fn binary_storage_inside_target_is_rejected_without_modification() {
    let f = Fixture::new();
    let forbidden = f.workspace.join("sentra.db");
    let output = f.invoke(&args(&[
        "init",
        "--workspace",
        f.workspace.to_str().unwrap(),
        "--database",
        forbidden.to_str().unwrap(),
    ]));
    assert_eq!(output.status.code(), Some(4));
    assert!(!forbidden.exists());
    assert_eq!(fs::read_dir(&f.workspace).unwrap().count(), 0);
}

#[test]
fn binary_existing_identity_cannot_be_reassigned_to_another_workspace() {
    let f = Fixture::new();
    let id = f.init();
    let other = f.root.join("other");
    fs::create_dir(&other).unwrap();
    let output = f.invoke(&args(&[
        "init",
        "--workspace",
        other.to_str().unwrap(),
        "--database",
        f.db.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        session_id(&String::from_utf8(f.invoke(&f.command("status")).stdout).unwrap()),
        id
    );
}

#[test]
fn binary_unknown_session_is_not_a_success() {
    let f = Fixture::new();
    f.init();
    let output = f.invoke(&args(&[
        "session",
        "show",
        &SessionId::new().to_string(),
        "--database",
        f.db.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(output.status.code(), Some(7));
    assert!(output.stdout.is_empty());
}

#[test]
fn binary_orphan_wal_prevents_initialization_and_is_preserved() {
    let f = Fixture::new();
    let wal = PathBuf::from(format!("{}-wal", f.db.display()));
    fs::write(&wal, b"committed-recovery-sentinel").unwrap();
    let output = f.invoke(&f.command("init"));
    assert_eq!(output.status.code(), Some(6));
    assert!(!f.db.exists());
    assert_eq!(fs::read(wal).unwrap(), b"committed-recovery-sentinel");
}

#[test]
fn binary_does_not_invoke_target_scripts_or_read_git_configuration() {
    let f = Fixture::new();
    let marker = f.root.join("MUST_NOT_EXIST");
    let script = format!("@echo off\r\necho executed > \"{}\"\r\n", marker.display());
    fs::write(f.workspace.join("build.cmd"), script.as_bytes()).unwrap();
    fs::create_dir(f.workspace.join(".git")).unwrap();
    fs::write(
        f.workspace.join(".git/config"),
        b"[core]\nhooksPath=DO-NOT-READ\nAPI_KEY=target-secret",
    )
    .unwrap();
    let id = f.init();
    let output = f.invoke(&f.command("status"));
    assert!(!marker.exists());
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(session_id(&text), id);
    assert!(!text.contains("target-secret"));
    assert!(!text.contains("secret-not-consumed"));
    assert_eq!(
        fs::read(f.workspace.join("build.cmd")).unwrap(),
        script.as_bytes()
    );
    assert_eq!(fs::read_dir(&f.workspace).unwrap().count(), 2);
}

#[cfg(windows)]
#[test]
fn binary_rejects_symlink_workspace_without_touching_database() {
    let f = Fixture::new();
    let link = f.root.join("link");
    std::os::windows::fs::symlink_dir(&f.workspace, &link).expect(
        "Windows symlink fixture requires pre-existing Developer Mode; do not silently skip",
    );
    let output = f.invoke(&args(&[
        "init",
        "--workspace",
        link.to_str().unwrap(),
        "--database",
        f.db.to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(output.status.code(), Some(4));
    assert!(!f.db.exists());
    fs::remove_dir(link).unwrap();
}

#[test]
fn relative_paths_are_resolved_against_invocation_directory() {
    let f = Fixture::new();
    let arguments = vec![
        OsString::from("init"),
        "--workspace".into(),
        f.workspace.file_name().unwrap().into(),
        "--database".into(),
        "storage space/local.db".into(),
        "--json".into(),
    ];
    let result = run(&arguments, &f.root);
    assert_eq!(result.exit_code, 0);
    assert!(f.db.is_file());
}

#[test]
fn binary_recover_completes_interrupted_bootstrap() {
    let f = Fixture::new();
    let manager = SqliteConnectionManager::open(&f.db, &SystemClock).unwrap();
    let (_, authority) = PersistenceRepository::with_authority(manager.clone());
    let metadata = sentra_core::SessionMetadata::new(
        SessionId::new(),
        sentra_core::Clock::now(&SystemClock),
        fs::canonicalize(&f.workspace).unwrap().to_str().unwrap(),
        OperatingMode::ContinuousReview,
        "fixture-operator",
        "fixture-policy",
    )
    .unwrap();
    let expected_session_id = metadata.session_id.to_string();
    authority
        .register_session(
            &metadata,
            "fixture-revision",
            SecurityClassification::Internal,
            CostUsd::ZERO,
            sentra_core::EventId::new(),
            &SystemClock,
        )
        .unwrap();
    manager.shutdown().unwrap();

    // Verify sentra status fails closed with exit code 6 (incomplete_storage)
    let status_before = f.invoke(&f.command("status"));
    assert_eq!(status_before.status.code(), Some(6));

    // Execute sentra recover
    let recover_output = f.invoke(&f.command("recover"));
    assert_eq!(recover_output.status.code(), Some(0));
    let recover_text = String::from_utf8(recover_output.stdout).unwrap();
    assert!(recover_text.contains("\"command\":\"recover\""));
    assert!(recover_text.contains("\"initialized\":true"));
    assert!(recover_text.contains(&expected_session_id));

    // Verify subsequent sentra status succeeds cleanly with exit code 0
    let status_after = f.invoke(&f.command("status"));
    assert_eq!(status_after.status.code(), Some(0));
    let status_text = String::from_utf8(status_after.stdout).unwrap();
    assert!(status_text.contains(&expected_session_id));
}

#[test]
fn binary_recover_parses_arguments_and_fails_on_corrupt() {
    let f = Fixture::new();
    let corrupt_payload = b"not-a-valid-sqlite-database-file";
    fs::write(&f.db, corrupt_payload).unwrap();

    // Recover fails on corrupt database and preserves original bytes
    let output = f.invoke(&f.command("recover"));
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(fs::read(&f.db).unwrap(), corrupt_payload);

    // Parse tests
    assert!(matches!(
        parse(&args(&["recover", "--database", "local.db"]))
            .unwrap()
            .command,
        CliCommand::Recover {
            workspace: None,
            ..
        }
    ));
}

#[test]
fn binary_audit_reports_cargo_lock_vulnerabilities() {
    let f = Fixture::new();
    let _session_id = f.init();

    // Write a Cargo.lock with known vulnerable package atty 0.2.11
    let sample_lock = r#"# Generated by Cargo
version = 3

[[package]]
name = "atty"
version = "0.2.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
    fs::write(f.workspace.join("Cargo.lock"), sample_lock).unwrap();

    // 1. JSON output mode
    let audit_json = f.invoke(&f.command("audit"));
    assert_eq!(audit_json.status.code(), Some(0));
    let stdout_json = String::from_utf8(audit_json.stdout).unwrap();
    assert!(stdout_json.contains("\"packages_audited\":1"));
    assert!(stdout_json.contains("\"vulnerable_packages\":1"));
    assert!(stdout_json.contains("RUSTSEC-2021-0145"));
    assert!(stdout_json.contains("PRESENT_ONLY"));

    // 2. Human-readable text mode
    let audit_human = f.invoke(&args(&[
        "audit",
        "--workspace",
        f.workspace.to_str().unwrap(),
        "--database",
        f.db.to_str().unwrap(),
    ]));
    assert_eq!(audit_human.status.code(), Some(0));
    let stdout_human = String::from_utf8(audit_human.stdout).unwrap();
    assert!(stdout_human.contains("Sentra dependency audit: completed"));
    assert!(stdout_human.contains("Packages audited: 1"));
    assert!(stdout_human.contains("Vulnerable packages: 1"));
    assert!(stdout_human.contains("RUSTSEC-2021-0145"));
}

#[test]
fn binary_audit_uninitialized_database_fails_closed() {
    let f = Fixture::new();
    // Database has not been initialized yet
    let audit_out = f.invoke(&f.command("audit"));
    assert_eq!(audit_out.status.code(), Some(6)); // incomplete_storage
}

#[test]
fn binary_audit_parses_arguments() {
    assert!(matches!(
        parse(&args(&["audit", "--database", "local.db"]))
            .unwrap()
            .command,
        CliCommand::Audit {
            workspace: None,
            ..
        }
    ));
    assert!(matches!(
        parse(&args(&[
            "audit",
            "--workspace",
            "my_ws",
            "--database",
            "local.db",
            "--json"
        ]))
        .unwrap()
        .command,
        CliCommand::Audit {
            workspace: Some(ws),
            ..
        } if ws == Path::new("my_ws")
    ));
}

#[test]
fn diff_parses_arguments() {
    let res = parse(&args(&[
        "diff", "--base", "dir_a", "--head", "dir_b", "--json",
    ]))
    .unwrap();
    assert!(res.json);
    assert!(matches!(
        res.command,
        CliCommand::Diff { base, head } if base == Path::new("dir_a") && head == Path::new("dir_b")
    ));

    // Order reversed
    let res2 = parse(&args(&["diff", "--head", "dir_head", "--base", "dir_base"])).unwrap();
    assert!(!res2.json);
    assert!(matches!(
        res2.command,
        CliCommand::Diff { base, head } if base == Path::new("dir_base") && head == Path::new("dir_head")
    ));

    // Rejects missing arguments or duplicates
    assert!(parse(&args(&["diff", "--base", "a"])).is_err());
    assert!(parse(&args(&["diff", "--head", "b"])).is_err());
    assert!(
        parse(&args(&[
            "diff", "--base", "a", "--head", "b", "--base", "c"
        ]))
        .is_err()
    );
    assert!(parse(&args(&["diff", "--base", "a", "--head", "b", "--unknown"])).is_err());
}

#[test]
fn verify_audit_and_mcp_parse_arguments() {
    let mcp = parse(&args(&["mcp"])).unwrap();
    assert!(!mcp.json);
    assert!(matches!(mcp.command, CliCommand::Mcp));

    let mcp_json = parse(&args(&["mcp", "--json"])).unwrap();
    assert!(mcp_json.json);
    assert!(matches!(mcp_json.command, CliCommand::Mcp));

    assert!(parse(&args(&["mcp", "unexpected"])).is_err());

    let audit = parse(&args(&["verify-audit"])).unwrap();
    assert!(!audit.json);
    assert!(matches!(audit.command, CliCommand::VerifyAudit));

    let audit_json = parse(&args(&["verify-audit", "--json"])).unwrap();
    assert!(audit_json.json);
    assert!(matches!(audit_json.command, CliCommand::VerifyAudit));

    assert!(parse(&args(&["verify-audit", "--extra"])).is_err());
}

#[test]
fn diff_computes_directory_differences_human_and_json() {
    let temp = fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
    let temp_dir = temp.join(format!("sentra_diff_test_{}", SessionId::new()));
    fs::create_dir_all(&temp_dir).unwrap();
    let base = temp_dir.join("base");
    let head = temp_dir.join("head");
    fs::create_dir_all(&base).unwrap();
    fs::create_dir_all(&head).unwrap();

    fs::write(base.join("unchanged.txt"), "unchanged content\n").unwrap();
    fs::write(head.join("unchanged.txt"), "unchanged content\n").unwrap();

    fs::write(base.join("modified.rs"), "fn old() {}\n").unwrap();
    fs::write(head.join("modified.rs"), "fn new_func() {}\n").unwrap();

    fs::write(base.join("deleted.txt"), "goodbye\n").unwrap();
    fs::write(head.join("added.rs"), "fn added() {}\n").unwrap();

    // Human output
    let resp = run(
        &args(&[
            "diff",
            "--base",
            base.to_str().unwrap(),
            "--head",
            head.to_str().unwrap(),
        ]),
        Path::new(""),
    );
    assert_eq!(resp.exit_code, 0);
    assert!(resp.stdout.contains("Sentra snapshot diff: completed"));
    assert!(resp.stdout.contains("Files added: 1"));
    assert!(resp.stdout.contains("Files modified: 1"));
    assert!(resp.stdout.contains("Files deleted: 1"));
    assert!(resp.stdout.contains("Files unchanged: 1"));
    assert!(resp.stdout.contains("Rust files changed: 2"));
    assert!(resp.stdout.contains("Untrusted execution: disabled"));
    assert!(resp.stderr.is_empty());

    // JSON output
    let resp_json = run(
        &args(&[
            "diff",
            "--base",
            base.to_str().unwrap(),
            "--head",
            head.to_str().unwrap(),
            "--json",
        ]),
        Path::new(""),
    );
    assert_eq!(resp_json.exit_code, 0);
    assert!(resp_json.stdout.contains("\"command\":\"diff\""));
    assert!(resp_json.stdout.contains("\"schema_version\":1"));
    assert!(resp_json.stdout.contains("\"added_files\":1"));
    assert!(resp_json.stdout.contains("\"modified_files\":1"));
    assert!(resp_json.stdout.contains("\"deleted_files\":1"));
    assert!(resp_json.stdout.contains("\"unchanged_files\":1"));
    assert!(resp_json.stdout.contains("\"untrusted_execution\":false"));

    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn diff_invalid_workspace_fails_closed() {
    let resp = run(
        &args(&[
            "diff",
            "--base",
            "nonexistent_directory_base_xyz",
            "--head",
            "nonexistent_directory_head_xyz",
            "--json",
        ]),
        Path::new(""),
    );
    assert_eq!(resp.exit_code, 4);
    assert_eq!(
        resp.stderr,
        "{\"schema_version\":1,\"error\":\"invalid_workspace\"}\n"
    );
}

#[test]
fn verify_audit_executes_five_gates() {
    let resp = run(&args(&["verify-audit"]), Path::new(""));
    assert_eq!(resp.exit_code, 0);
    assert!(
        resp.stdout
            .contains("Sentra multi-user security audit: approved")
    );
    assert!(resp.stdout.contains("Tenant isolation: passed"));
    assert!(resp.stdout.contains("Worker egress containment: passed"));
    assert!(resp.stdout.contains("Cross-tenant worker reuse: passed"));
    assert!(resp.stdout.contains("Zero secret inheritance: passed"));
    assert!(resp.stdout.contains("Immutable audit trail: passed"));
    assert!(resp.stdout.contains("Untrusted execution: disabled"));

    let resp_json = run(&args(&["verify-audit", "--json"]), Path::new(""));
    assert_eq!(resp_json.exit_code, 0);
    assert!(resp_json.stdout.contains("\"command\":\"verify-audit\""));
    assert!(resp_json.stdout.contains("\"status\":\"approved\""));
    assert!(resp_json.stdout.contains("\"approved\":true"));
    assert!(resp_json.stdout.contains("\"gate_tenant_isolation\":true"));
    assert!(
        resp_json
            .stdout
            .contains("\"gate_worker_egress_containment\":true")
    );
    assert!(
        resp_json
            .stdout
            .contains("\"gate_cross_tenant_worker_reuse\":true")
    );
    assert!(
        resp_json
            .stdout
            .contains("\"gate_zero_secret_inheritance\":true")
    );
    assert!(
        resp_json
            .stdout
            .contains("\"gate_immutable_audit_trail\":true")
    );
}

#[test]
fn mcp_stdio_server_loop() {
    let input_lines = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1.0\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n"
    );
    let mut cursor = Cursor::new(input_lines.as_bytes());
    let resp = run_with_input(&args(&["mcp"]), Path::new(""), &mut cursor);
    assert_eq!(resp.exit_code, 0);
    assert!(resp.stderr.is_empty());

    let lines: Vec<&str> = resp.stdout.lines().collect();
    // Notification does not respond, so exactly 2 responses
    assert_eq!(lines.len(), 2);

    // Response 1: initialize result
    assert!(lines[0].contains("\"id\":1"));
    assert!(lines[0].contains("\"protocolVersion\":\"2026-07-28\""));
    assert!(lines[0].contains("\"name\":\"sentra-mcp\""));

    // Response 2: tools/list
    assert!(lines[1].contains("\"id\":2"));
    assert!(lines[1].contains("\"tools\""));
    assert!(lines[1].contains("session_status"));
}

#[test]
fn binary_mcp_and_diff_and_verify_audit_subprocesses() {
    // 1. Binary verify-audit
    let audit_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["verify-audit", "--json"])
        .output()
        .unwrap();
    assert!(audit_out.status.success());
    let audit_stdout = String::from_utf8(audit_out.stdout).unwrap();
    assert!(audit_stdout.contains("\"command\":\"verify-audit\""));
    assert!(audit_stdout.contains("\"status\":\"approved\""));

    // 2. Binary mcp over stdio pipe
    let mut mcp_child = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let init_req = "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"bin-test\",\"version\":\"1.0\"}}}\n";
    {
        let mut stdin = mcp_child.stdin.take().unwrap();
        stdin.write_all(init_req.as_bytes()).unwrap();
        // Drop stdin to send EOF
    }
    let mcp_out = mcp_child.wait_with_output().unwrap();
    assert!(mcp_out.status.success());
    let mcp_stdout = String::from_utf8(mcp_out.stdout).unwrap();
    assert!(mcp_stdout.contains("\"id\":99"));
    assert!(mcp_stdout.contains("\"protocolVersion\":\"2026-07-28\""));
    assert!(mcp_stdout.contains("\"name\":\"sentra-mcp\""));
}

#[test]
fn export_sarif_parses_arguments() {
    let res = parse(&args(&[
        "export",
        "sarif",
        "--database",
        "local.db",
        "--workspace",
        "my_ws",
        "--output",
        "out.sarif",
        "--json",
    ]))
    .unwrap();
    assert!(res.json);
    assert!(matches!(
        res.command,
        CliCommand::ExportSarif {
            workspace: Some(ws),
            database,
            output: Some(out),
        } if ws == Path::new("my_ws") && database == Path::new("local.db") && out == Path::new("out.sarif")
    ));

    // Default workspace and stdout output
    let res2 = parse(&args(&["export", "sarif", "--database", "local.db"])).unwrap();
    assert!(!res2.json);
    assert!(matches!(
        res2.command,
        CliCommand::ExportSarif {
            workspace: None,
            database,
            output: None,
        } if database == Path::new("local.db")
    ));

    // Reject missing subcommands or unknown formats
    assert!(parse(&args(&["export"])).is_err());
    assert!(parse(&args(&["export", "unknown", "--database", "local.db"])).is_err());
    assert!(parse(&args(&["export", "sarif"])).is_err());
    assert!(
        parse(&args(&[
            "export",
            "sarif",
            "--database",
            "local.db",
            "--database",
            "dup.db"
        ]))
        .is_err()
    );
}

#[test]
fn export_sarif_outputs_valid_oasis_sarif() {
    let f = Fixture::new();
    f.init();

    // Write vulnerable Cargo.lock
    let lockfile = r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "atty"
version = "0.2.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "52524bb7379625ca310543f1e8f48446b1f997ca92021c152ab74507ddfc4043"
"#;
    fs::write(f.workspace.join("Cargo.lock"), lockfile).unwrap();

    // 1. Output to stdout
    let resp = run(
        &args(&[
            "export",
            "sarif",
            "--workspace",
            f.workspace.to_str().unwrap(),
            "--database",
            f.db.to_str().unwrap(),
        ]),
        Path::new(""),
    );
    assert_eq!(resp.exit_code, 0);
    assert!(resp.stderr.is_empty());
    let sarif: sentra_core::SarifLog =
        serde_json::from_str(&resp.stdout).expect("valid SARIF JSON");
    assert_eq!(sarif.version, "2.1.0");
    assert_eq!(sarif.runs.len(), 1);
    assert_eq!(sarif.runs[0].results.len(), 1);
    assert_eq!(sarif.runs[0].results[0].rule_id, "RUSTSEC-2021-0145");

    // 2. Output to file
    let out_file = f.root.join("findings.sarif");
    let resp_file = run(
        &args(&[
            "export",
            "sarif",
            "--workspace",
            f.workspace.to_str().unwrap(),
            "--database",
            f.db.to_str().unwrap(),
            "--output",
            out_file.to_str().unwrap(),
            "--json",
        ]),
        Path::new(""),
    );
    assert_eq!(resp_file.exit_code, 0);
    assert!(resp_file.stdout.contains("\"command\":\"export sarif\""));
    assert!(resp_file.stdout.contains("\"status\":\"success\""));

    let file_content = fs::read_to_string(&out_file).unwrap();
    let parsed_file: sentra_core::SarifLog =
        serde_json::from_str(&file_content).expect("valid file SARIF");
    assert_eq!(parsed_file.runs[0].results[0].rule_id, "RUSTSEC-2021-0145");
}

#[test]
fn binary_export_sarif_subprocess() {
    let f = Fixture::new();
    f.init();

    let lockfile = r#"# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "atty"
version = "0.2.11"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "52524bb7379625ca310543f1e8f48446b1f997ca92021c152ab74507ddfc4043"
"#;
    fs::write(f.workspace.join("Cargo.lock"), lockfile).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "export",
            "sarif",
            "--workspace",
            f.workspace.to_str().unwrap(),
            "--database",
            f.db.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let sarif: sentra_core::SarifLog = serde_json::from_str(&stdout).unwrap();
    assert_eq!(sarif.runs[0].results.len(), 1);
    assert_eq!(sarif.runs[0].results[0].rule_id, "RUSTSEC-2021-0145");
}

#[test]
fn binary_scan_detects_secrets_and_outputs_human_and_json() {
    let f = Fixture::new();

    let sample_code = r#"
        const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
        function query(id) {
            return format!("SELECT * FROM users WHERE id = '{}'", id);
        }
    "#;
    fs::write(f.workspace.join("vuln.js"), sample_code).unwrap();

    // Human output
    let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["scan", "--workspace", f.workspace.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Sentra SAST scan: completed"));
    assert!(stdout.contains("SENTRA-SEC-001"));
    assert!(stdout.contains("SENTRA-SAST-001"));

    // JSON output
    let out_json = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "scan",
            "--workspace",
            f.workspace.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert!(out_json.status.success());
    let stdout_json = String::from_utf8(out_json.stdout).unwrap();
    assert!(stdout_json.contains("\"command\":\"scan\""));
    assert!(stdout_json.contains("\"signals_found\":2"));
}

#[test]
fn binary_scan_sarif_export() {
    let f = Fixture::new();

    let sample_code = format!(
        "const API_SECRET = \"{}\";\n",
        ["sk", "live", "1234567890abcdefghijklmnopqrstuvwxyz"].join("_")
    );
    fs::write(f.workspace.join("secret.ts"), sample_code).unwrap();
    let sarif_path = f.workspace.parent().unwrap().join("sast-results.sarif");

    let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "scan",
            "--workspace",
            f.workspace.to_str().unwrap(),
            "--sarif",
            sarif_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(out.status.success());
    assert!(sarif_path.exists());
    let content = fs::read_to_string(&sarif_path).unwrap();
    let sarif: sentra_core::SarifLog = serde_json::from_str(&content).unwrap();
    assert_eq!(sarif.runs[0].results.len(), 1);
    assert_eq!(sarif.runs[0].results[0].rule_id, "SENTRA-SEC-005");
    let _ = fs::remove_file(sarif_path);
}

#[test]
fn binary_sync_advisories_ingests_osv_feed() {
    let f = Fixture::new();

    let osv_feed = r#"[
        {
            "id": "GHSA-custom-test-001",
            "summary": "Custom test advisory",
            "affected": [
                {
                    "package": { "name": "sample-lib" },
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                { "introduced": "0" },
                                { "fixed": "2.0.0" }
                            ]
                        }
                    ]
                }
            ]
        }
    ]"#;
    let feed_path = f.workspace.parent().unwrap().join("feed.json");
    fs::write(&feed_path, osv_feed).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "sync-advisories",
            "--source",
            feed_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\"command\":\"sync-advisories\""));
    assert!(stdout.contains("\"advisories_ingested\":1"));
    let _ = fs::remove_file(feed_path);
}

#[test]
fn binary_propose_pr_generates_draft_proposals() {
    let f = Fixture::new();
    f.init();

    let pkg_lock = r#"{
        "name": "target-app",
        "lockfileVersion": 3,
        "packages": {
            "": { "name": "target-app" },
            "node_modules/lodash": {
                "version": "4.17.11"
            }
        }
    }"#;
    fs::write(f.workspace.join("package-lock.json"), pkg_lock).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "propose-pr",
            "--workspace",
            f.workspace.to_str().unwrap(),
            "--database",
            f.db.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("\"command\":\"propose-pr\""));
    assert!(stdout.contains("\"is_draft_only\":true"));
    assert!(stdout.contains("GHSA-p6mc-m468-83gw"));
    assert!(stdout.contains("gh pr create --draft"));
}

#[test]
fn binary_codeql_probe_and_sarif_ingest() {
    let f = Fixture::new();
    f.init();

    // 1. Test CodeQL Probe
    fs::write(
        f.workspace.join("service.py"),
        "import sys\nprint(sys.argv)",
    )
    .unwrap();
    let probe_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "codeql",
            "--workspace",
            f.workspace.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert!(probe_out.status.success());
    let probe_stdout = String::from_utf8(probe_out.stdout).unwrap();
    assert!(probe_stdout.contains("\"command\":\"codeql\""));
    assert!(probe_stdout.contains("\"mode\":\"probe\""));
    assert!(probe_stdout.contains("\"primary_language\":\"python\""));
    assert!(probe_stdout.contains("codeql database create"));

    // 2. Test CodeQL SARIF Ingest
    let sample_sarif = r#"{
      "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "CodeQL",
              "rules": [
                {
                  "id": "py/sql-injection",
                  "name": "SQL Injection",
                  "properties": { "security-severity": "8.5" }
                }
              ]
            }
          },
          "results": [
            {
              "ruleId": "py/sql-injection",
              "level": "error",
              "message": { "text": "SQL query formed from untrusted user input." },
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": { "uri": "service.py" },
                    "region": { "startLine": 12 }
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
                              "artifactLocation": { "uri": "service.py" },
                              "region": { "startLine": 5 }
                            },
                            "message": { "text": "source: sys.argv[1]" }
                          }
                        },
                        {
                          "location": {
                            "physicalLocation": {
                              "artifactLocation": { "uri": "service.py" },
                              "region": { "startLine": 12 }
                            },
                            "message": { "text": "sink: cursor.execute(query)" }
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

    let sarif_file = f.root.join("codeql-output.sarif");
    fs::write(&sarif_file, sample_sarif).unwrap();

    let ingest_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "codeql",
            "--sarif",
            sarif_file.to_str().unwrap(),
            "--workspace",
            f.workspace.to_str().unwrap(),
            "--database",
            f.db.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();

    assert!(ingest_out.status.success());
    let ingest_stdout = String::from_utf8(ingest_out.stdout).unwrap();
    assert!(ingest_stdout.contains("\"command\":\"codeql\""));
    assert!(ingest_stdout.contains("\"mode\":\"ingest\""));
    assert!(ingest_stdout.contains("\"total_sarif_results\":1"));
    assert!(ingest_stdout.contains("\"taint_traces_extracted\":1"));
    assert!(ingest_stdout.contains("\"highest_severity\":\"HIGH\""));
    assert!(ingest_stdout.contains("py/sql-injection"));
}

#[test]
fn binary_fleet_commands() {
    let status_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["fleet", "status", "--json"])
        .output()
        .unwrap();
    assert!(status_out.status.success());
    let status_str = String::from_utf8(status_out.stdout).unwrap();
    assert!(status_str.contains("\"command\":\"fleet status\""));
    assert!(status_str.contains("\"total_workers\":4"));
    assert!(status_str.contains("\"containment_ready\":true"));

    let list_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["fleet", "list", "--json"])
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list_str = String::from_utf8(list_out.stdout).unwrap();
    assert!(list_str.contains("\"command\":\"fleet list\""));
    assert!(list_str.contains("worker-x86-01"));
}

#[test]
fn binary_tenant_commands() {
    let f = Fixture::new();
    let init_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "init",
            "--workspace",
            f.workspace.to_str().unwrap(),
            "--database",
            f.db.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(init_out.status.success());

    let list_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "tenant",
            "list",
            "--database",
            f.db.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list_str = String::from_utf8(list_out.stdout).unwrap();
    assert!(list_str.contains("\"command\":\"tenant list\""));
    assert!(list_str.contains("sentra-internal"));

    let add_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "tenant",
            "add",
            "--id",
            "custom-corp",
            "--name",
            "Custom Corp Global",
            "--database",
            f.db.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(add_out.status.success());
    let add_str = String::from_utf8(add_out.stdout).unwrap();
    assert!(add_str.contains("\"command\":\"tenant add\""));
    assert!(add_str.contains("custom-corp"));

    let list_after = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "tenant",
            "list",
            "--database",
            f.db.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    let list_after_str = String::from_utf8(list_after.stdout).unwrap();
    assert!(list_after_str.contains("custom-corp"));
}

#[test]
fn binary_config_commands() {
    let f = Fixture::new();
    let set_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "config",
            "set",
            "--key",
            "ai_provider",
            "--value",
            "anthropic",
            "--database",
            f.db.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(set_out.status.success());
    let set_str = String::from_utf8(set_out.stdout).unwrap();
    assert!(set_str.contains("\"command\":\"config set\""));

    let show_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "config",
            "show",
            "--key",
            "ai_provider",
            "--database",
            f.db.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(show_out.status.success());
    let show_str = String::from_utf8(show_out.stdout).unwrap();
    assert!(show_str.contains("anthropic"));

    let test_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["config", "test", "--provider", "anthropic", "--json"])
        .output()
        .unwrap();
    assert!(test_out.status.success());
    let test_str = String::from_utf8(test_out.stdout).unwrap();
    assert!(test_str.contains("\"status\":\"connected\""));
}

#[test]
fn binary_scan_snippet() {
    let snippet_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "scan",
            "--snippet",
            "const awsKey = 'AKIAIOSFODNN7EXAMPLE';",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(snippet_out.status.success());
    let str_out = String::from_utf8(snippet_out.stdout).unwrap();
    assert!(str_out.contains("\"signals_found\":1"));
    assert!(str_out.contains("SENTRA-SEC-001"));
}

#[test]
fn binary_patch_apply_and_rollback() {
    let f = Fixture::new();
    let target_file = f.workspace.join("auth.ts");
    fs::write(&target_file, "function auth() {\n  let token = 'old';\n}\n").unwrap();

    let patch_file = f.root.join("fix.patch");
    let diff = "--- a/auth.ts\n+++ b/auth.ts\n@@ -2,1 +2,1 @@\n-  let token = 'old';\n+  let token = process.env.TOKEN;\n";
    fs::write(&patch_file, diff).unwrap();

    let backup_dir = f.root.join("backups");

    let apply_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "patch",
            "apply",
            "--patch",
            patch_file.to_str().unwrap(),
            "--workspace",
            f.workspace.to_str().unwrap(),
            "--target",
            "auth.ts",
            "--backup-dir",
            backup_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(apply_out.status.success());
    let apply_str = String::from_utf8(apply_out.stdout).unwrap();
    assert!(apply_str.contains("\"command\":\"patch apply\""));
    assert!(apply_str.contains("\"status\":\"success\""));

    let patched_content = fs::read_to_string(&target_file).unwrap();
    assert!(patched_content.contains("let token = process.env.TOKEN;"));

    // Find the backup file created
    let backup_entries = fs::read_dir(&backup_dir).unwrap().collect::<Vec<_>>();
    assert_eq!(backup_entries.len(), 1);
    let backup_path = backup_entries[0].as_ref().unwrap().path();

    let rollback_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "patch",
            "rollback",
            "--backup",
            backup_path.to_str().unwrap(),
            "--workspace",
            f.workspace.to_str().unwrap(),
            "--target",
            "auth.ts",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(rollback_out.status.success());
    let rollback_str = String::from_utf8(rollback_out.stdout).unwrap();
    assert!(rollback_str.contains("\"command\":\"patch rollback\""));

    let rolled_back_content = fs::read_to_string(&target_file).unwrap();
    assert!(rolled_back_content.contains("let token = 'old';"));
}

#[test]
fn binary_plugin_commands() {
    // 1. Plugin List (JSON)
    let list_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["plugin", "list", "--json"])
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list_str = String::from_utf8(list_out.stdout).unwrap();
    assert!(list_str.contains("\"command\":\"plugin\""));
    assert!(list_str.contains("\"action\":\"list\""));
    assert!(list_str.contains("org.sentra.adapter.snyk"));
    assert!(list_str.contains("org.sentra.adapter.semgrep"));
    assert!(list_str.contains("org.sentra.adapter.ollama"));

    let bun_available = Command::new("bun")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if bun_available {
        // 2. Plugin Probe (Human & JSON)
        let probe_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
            .args([
                "plugin",
                "probe",
                "--id",
                "org.sentra.adapter.snyk",
                "--workspace",
                "../..",
                "--json",
            ])
            .output()
            .unwrap();
        assert!(probe_out.status.success());
        let probe_str = String::from_utf8(probe_out.stdout).unwrap();
        assert!(probe_str.contains("\"plugin_id\":\"org.sentra.adapter.snyk\""));
        assert!(probe_str.contains("\"applicable\":true"));

        // 3. Plugin Run (Execute authorized capability)
        let run_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
            .args([
                "plugin",
                "run",
                "--id",
                "org.sentra.adapter.snyk",
                "--capability",
                "dependency_audit",
                "--json",
            ])
            .output()
            .unwrap();
        assert!(run_out.status.success());
        let run_str = String::from_utf8(run_out.stdout).unwrap();
        assert!(run_str.contains("\"action\":\"run\""));
        assert!(run_str.contains("\"capability\":\"dependency_audit\""));
        assert!(run_str.contains("\"exit_code\":0"));
    }

    // 4. Plugin Run (Undeclared capability rejected)
    let bad_run_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "plugin",
            "run",
            "--id",
            "org.sentra.adapter.snyk",
            "--capability",
            "fuzz_execution",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!bad_run_out.status.success());
}

#[test]
fn binary_skills_list_and_show() {
    let list_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["skills", "list"])
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list_str = String::from_utf8(list_out.stdout).unwrap();
    assert!(list_str.contains("api-security-testing"));
    assert!(list_str.contains("security-threat-model"));
    assert!(list_str.contains("auth-implementation-patterns"));

    let list_json = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["skills", "list", "--json"])
        .output()
        .unwrap();
    assert!(list_json.status.success());
    let json_str = String::from_utf8(list_json.stdout).unwrap();
    assert!(json_str.contains("\"id\": \"api-security-testing\""));

    let show_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["skills", "show", "api-security-testing"])
        .output()
        .unwrap();
    assert!(show_out.status.success());
    let show_str = String::from_utf8(show_out.stdout).unwrap();
    assert!(show_str.contains("name: api-security-testing"));
    assert!(show_str.contains("BOLA/IDOR"));
}

#[test]
fn binary_install_claude_and_antigravity_skills() {
    let f = Fixture::new();
    let tmp_path = f.workspace.to_str().unwrap();

    // 1. Install Claude skills into temporary workspace
    let install_claude = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "install",
            "claude",
            "--workspace",
            tmp_path,
            "--skill",
            "api-security-testing",
        ])
        .output()
        .unwrap();
    assert!(install_claude.status.success());
    let claude_skill = f
        .workspace
        .join(".claude")
        .join("skills")
        .join("api-security-testing")
        .join("SKILL.md");
    assert!(claude_skill.exists());
    let content = fs::read_to_string(&claude_skill).unwrap();
    assert!(content.contains("api-security-testing"));

    // 2. Install Antigravity skills with --json
    let install_agy = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "install",
            "antigravity",
            "--workspace",
            tmp_path,
            "--skill",
            "security-threat-model",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(install_agy.status.success());
    let agy_str = String::from_utf8(install_agy.stdout).unwrap();
    assert!(agy_str.contains("\"target\":\"antigravity\""));
    assert!(agy_str.contains("\"count\":1"));
    let agy_skill = f
        .workspace
        .join(".agents")
        .join("skills")
        .join("security-threat-model")
        .join("SKILL.md");
    assert!(agy_skill.exists());

    // 3. Install Cursor rules
    let install_cursor = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "install",
            "cursor",
            "--workspace",
            tmp_path,
            "--skill",
            "golang-security",
        ])
        .output()
        .unwrap();
    assert!(install_cursor.status.success());
    let cursor_rule = f
        .workspace
        .join(".cursor")
        .join("rules")
        .join("golang-security.mdc");
    assert!(cursor_rule.exists());

    // 4. Install Windsurf rules
    let install_windsurf = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "install",
            "windsurf",
            "--workspace",
            tmp_path,
            "--skill",
            "django-security",
        ])
        .output()
        .unwrap();
    assert!(install_windsurf.status.success());
    let windsurf_rule = f
        .workspace
        .join(".windsurf")
        .join("rules")
        .join("django-security.md");
    assert!(windsurf_rule.exists());

    // 5. Install Copilot instructions
    let install_copilot = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "install",
            "copilot",
            "--workspace",
            tmp_path,
            "--skill",
            "ci-cd-security",
        ])
        .output()
        .unwrap();
    assert!(install_copilot.status.success());
    let copilot_instr = f
        .workspace
        .join(".github")
        .join("instructions")
        .join("ci-cd-security.instructions.md");
    assert!(copilot_instr.exists());
    let copilot_root = f.workspace.join(".github").join("copilot-instructions.md");
    assert!(copilot_root.exists());
    let copilot_content = fs::read_to_string(&copilot_root).unwrap();
    assert!(copilot_content.contains("ci-cd-security"));

    // 6. Install Aider conventions
    let install_aider = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "install",
            "aider",
            "--workspace",
            tmp_path,
            "--skill",
            "api-security-testing",
        ])
        .output()
        .unwrap();
    assert!(install_aider.status.success());
    let aider_conventions = f.workspace.join("CONVENTIONS.md");
    assert!(aider_conventions.exists());
    let aider_content = fs::read_to_string(&aider_conventions).unwrap();
    assert!(aider_content.contains("api-security-testing"));

    // 6. Install Roo Code rules
    let install_roo = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "install",
            "roo",
            "--workspace",
            tmp_path,
            "--skill",
            "solidity-security",
        ])
        .output()
        .unwrap();
    assert!(install_roo.status.success());
    let roo_rule = f
        .workspace
        .join(".roo")
        .join("rules")
        .join("solidity-security.md");
    assert!(roo_rule.exists());

    // 7. Install Continue.dev rules
    let install_continue = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "install",
            "continue",
            "--workspace",
            tmp_path,
            "--skill",
            "springboot-security",
        ])
        .output()
        .unwrap();
    assert!(install_continue.status.success());
    let continue_rule = f
        .workspace
        .join(".continue")
        .join("rules")
        .join("springboot-security.md");
    assert!(continue_rule.exists());
}

#[test]
fn binary_prompt_generation() {
    // 1. Threat model prompt
    let tm_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["prompt", "threat-model", "--scope", "src/auth"])
        .output()
        .unwrap();
    assert!(tm_out.status.success());
    let tm_str = String::from_utf8(tm_out.stdout).unwrap();
    assert!(tm_str.contains("Mermaid"));
    assert!(tm_str.contains("STRIDE"));

    // 2. API BOLA prompt
    let bola_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "prompt",
            "api-bola",
            "--scope",
            "/api/v1/orders/:id",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(bola_out.status.success());
    let bola_str = String::from_utf8(bola_out.stdout).unwrap();
    assert!(
        bola_str.contains("\"workflow\": \"api-bola\"")
            || bola_str.contains("\"workflow\":\"api-bola\"")
    );
    assert!(bola_str.contains("BOLA/IDOR"));

    // 3. Patch synthesis prompt
    let patch_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["prompt", "patch-remediation", "--scope", "src/db.rs"])
        .output()
        .unwrap();
    assert!(patch_out.status.success());
    let patch_str = String::from_utf8(patch_out.stdout).unwrap();
    assert!(patch_str.contains("ADR-0004"));
    assert!(patch_str.contains("Tier 1"));
}
