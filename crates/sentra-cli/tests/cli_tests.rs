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

    // The advisory set is disclosed as the bundled sample, stamped with its curation date,
    // and staleness is measured against that date rather than the command's clock.
    let audit: serde_json::Value = serde_json::from_str(&stdout_json).unwrap();
    let pinned = sentra_core::AdvisoryDatabase::default_pinned();
    assert_eq!(audit["advisory_db_source"], "bundled_pinned_sample");
    assert_eq!(audit["advisory_db_records"], pinned.advisory_count());
    assert_eq!(audit["advisory_db_updated_at"], "2026-11-08T23:43:22.000Z");
    let expected_stale = pinned.is_stale(sentra_core::TimestampUtc::now(), 30);
    assert_eq!(audit["is_stale"], expected_stale);
    assert_eq!(
        audit["lockfiles_audited"],
        serde_json::json!(["Cargo.lock"])
    );
    assert_eq!(audit["lockfiles_unparsed"], serde_json::json!([]));
    assert_eq!(audit["findings"][0]["lockfile"], "Cargo.lock");

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
    assert!(stdout_human.contains("Advisory database: bundled pinned sample"));
    assert!(stdout_human.contains("not a synchronized OSV or RustSec feed"));
    assert!(stdout_human.contains("Lockfiles audited: Cargo.lock"));

    // Regression: a lockfile that could not be parsed was dropped silently. It is now
    // reported as not audited, and the parsed one is still audited.
    fs::write(f.workspace.join("package-lock.json"), "{ not json").unwrap();
    let partial = f.invoke(&f.command("audit"));
    assert_eq!(partial.status.code(), Some(0));
    let partial: serde_json::Value = serde_json::from_slice(&partial.stdout).unwrap();
    assert_eq!(
        partial["lockfiles_audited"],
        serde_json::json!(["Cargo.lock"])
    );
    assert_eq!(
        partial["lockfiles_unparsed"],
        serde_json::json!(["package-lock.json"])
    );
    assert_eq!(partial["packages_audited"], 1);

    // Regression: a yarn.lock truncated inside a block was listed as audited, with the
    // truncated entry skipped silently. It is now reported as not audited.
    fs::write(
        f.workspace.join("yarn.lock"),
        "express@^4.0.0:\n  version \"4.17.1\"\n\nlodash@^4.17.0:\n  resol",
    )
    .unwrap();
    let truncated = f.invoke(&f.command("audit"));
    assert_eq!(truncated.status.code(), Some(0));
    let truncated: serde_json::Value = serde_json::from_slice(&truncated.stdout).unwrap();
    assert_eq!(
        truncated["lockfiles_audited"],
        serde_json::json!(["Cargo.lock"])
    );
    assert_eq!(
        truncated["lockfiles_unparsed"],
        serde_json::json!(["package-lock.json", "yarn.lock"])
    );
    assert_eq!(truncated["packages_audited"], 1);
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
    assert!(matches!(
        mcp.command,
        CliCommand::Mcp {
            workspace: None,
            database: None
        }
    ));

    let mcp_json = parse(&args(&["mcp", "--json"])).unwrap();
    assert!(mcp_json.json);
    assert!(matches!(mcp_json.command, CliCommand::Mcp { .. }));

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

/// Parses the single JSON error document a failing in-process command prints on stderr.
fn error_json(stderr: &str) -> serde_json::Value {
    let mut lines = stderr.lines();
    let value = serde_json::from_str(lines.next().unwrap_or_default()).unwrap();
    assert_eq!(lines.next(), None, "one JSON document expected: {stderr}");
    value
}

/// Asserts the `not_implemented` failure shape shared by commands without a real
/// implementation: nothing on stdout, exit 5, and the same keys as other detailed errors.
fn assert_not_implemented(resp: &sentra_cli::Response, command: &str) {
    assert_eq!(resp.exit_code, 5, "stderr: {}", resp.stderr);
    assert!(resp.stdout.is_empty(), "stdout: {}", resp.stdout);
    let error = error_json(&resp.stderr);
    assert_eq!(error["schema_version"], 1);
    assert_eq!(error["error"], "not_implemented");
    assert_eq!(error["command"], command);
    assert!(error["message"].as_str().unwrap().contains("not"));
}

#[test]
fn help_describes_sample_based_and_unimplemented_commands_truthfully() {
    let help = sentra_cli::HELP;
    // Regression: claims the commands did not back.
    for claim in [
        "converts dependency and SAST findings",
        "ingests universal OSV JSON advisories into the advisory database",
        "packages verified vulnerabilities",
        "evaluates the 5 mandatory",
        "Config manages provider API credentials",
        "sync-advisories --source <directory-or-file> [--database <file>]",
    ] {
        assert!(!help.contains(claim), "help still claims {claim:?}");
    }
    assert!(help.contains("Export sarif runs the dependency audit (bundled advisory sample"));
    assert!(help.contains("SAST results are exported with scan --sarif"));
    assert!(help.contains("Nothing is downloaded or persisted"));
    assert!(help.contains("No branch, commit or pull request is created"));
    assert!(help.contains("Verify-audit is not implemented"));
    assert!(help.contains("Config test is not implemented"));
}

#[test]
fn verify_audit_fails_as_not_implemented() {
    // Regression: verify-audit used to assess a built-in fixture worker with gates
    // hard-coded to pass and report `approved` (exit 0).
    let resp_json = run(&args(&["verify-audit", "--json"]), Path::new(""));
    assert_not_implemented(&resp_json, "verify-audit");
    assert!(!resp_json.stderr.contains("approved"));

    let resp = run(&args(&["verify-audit"]), Path::new(""));
    assert_eq!(resp.exit_code, 5);
    assert!(resp.stdout.is_empty());
    assert!(resp.stderr.starts_with("error: not_implemented\n"));
    assert!(resp.stderr.contains("no worker registry"));
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
    assert!(lines[0].contains("\"protocolVersion\":\"2024-11-05\""));
    assert!(lines[0].contains("\"name\":\"sentra-mcp\""));

    // Response 2: tools/list
    assert!(lines[1].contains("\"id\":2"));
    assert!(lines[1].contains("\"tools\""));
    assert!(lines[1].contains("session_status"));
}

#[test]
fn binary_mcp_and_diff_and_verify_audit_subprocesses() {
    // 1. Binary verify-audit fails closed: nothing real to assess.
    let audit_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["verify-audit", "--json"])
        .output()
        .unwrap();
    assert_eq!(audit_out.status.code(), Some(5));
    assert!(audit_out.stdout.is_empty());
    let audit_error = stderr_json(&audit_out);
    assert_eq!(audit_error["error"], "not_implemented");
    assert_eq!(audit_error["command"], "verify-audit");

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
    assert!(mcp_stdout.contains("\"protocolVersion\":\"2024-11-05\""));
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
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["command"], "sync-advisories");
    assert_eq!(report["source_kind"], "file");
    assert_eq!(report["advisory_entries_parsed"], 1);
    assert_eq!(report["files_parsed"], 1);
    assert_eq!(report["files_skipped"], 0);
    // Regression: the parsed records were reported as "ingested" although nothing kept them.
    assert_eq!(report["persisted"], false);
    assert!(report.get("advisories_ingested").is_none());

    // A directory: top-level .json files are parsed, invalid ones are counted as skipped.
    let feed_dir = f.root.join("osv feed");
    fs::create_dir(&feed_dir).unwrap();
    fs::write(feed_dir.join("good.json"), osv_feed).unwrap();
    fs::write(feed_dir.join("broken.json"), "{ not osv").unwrap();
    fs::write(feed_dir.join("notes.txt"), "ignored").unwrap();
    let dir_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "sync-advisories",
            "--source",
            feed_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(dir_out.status.success());
    let dir_report: serde_json::Value = serde_json::from_slice(&dir_out.stdout).unwrap();
    assert_eq!(dir_report["source_kind"], "directory");
    assert_eq!(dir_report["advisory_entries_parsed"], 1);
    assert_eq!(dir_report["files_parsed"], 1);
    assert_eq!(dir_report["files_skipped"], 1);
    assert_eq!(dir_report["persisted"], false);

    let text_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["sync-advisories", "--source", feed_dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(text_out.status.success());
    let text = String::from_utf8(text_out.stdout).unwrap();
    assert!(text.contains("nothing was persisted"));
    assert!(text.contains("Files skipped (unreadable or invalid): 1"));

    // Regression: the help said invalid files are counted as skipped. That holds for a
    // directory only; a single invalid file fails, and the help now says so.
    let bad_file = feed_dir.join("broken.json");
    let bad_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "sync-advisories",
            "--source",
            bad_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_out.status.code(), Some(4));
    assert!(bad_out.stdout.is_empty());
    assert_eq!(stderr_json(&bad_out)["error"], "invalid_advisory_feed");
    assert!(sentra_cli::HELP.contains(
        "a single file that is not valid OSV JSON fails with invalid_advisory_feed (exit 4)"
    ));

    // Regression: --database was accepted and silently ignored. It now fails clearly and
    // writes nothing.
    let db_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "sync-advisories",
            "--source",
            feed_path.to_str().unwrap(),
            "--database",
            f.db.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(db_out.status.code(), Some(5));
    assert!(db_out.stdout.is_empty());
    let db_error = stderr_json(&db_out);
    assert_eq!(db_error["error"], "not_implemented");
    assert_eq!(db_error["command"], "sync-advisories");
    assert!(!f.db.exists());
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
    // A second lockfile, discovered first: each preview must name its own lockfile.
    let cargo_lock = "version = 3\n\n[[package]]\nname = \"atty\"\nversion = \"0.2.11\"\n";
    fs::write(f.workspace.join("Cargo.lock"), cargo_lock).unwrap();

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

    // The output says what it is: a local preview from the bundled advisory sample.
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["local_preview_only"], true);
    assert_eq!(report["pull_requests_created"], false);
    assert_eq!(report["patch_diffs_illustrative"], true);
    assert_eq!(report["advisory_db_source"], "bundled_pinned_sample");
    assert_eq!(report["proposals_count"], 2);

    // Regression: every preview named Cargo.lock and claimed a "canonical OSV/RustSec/GHSA"
    // match. Each now names the lockfile its package came from and the advisory sample.
    let proposals = report["proposals"].as_array().unwrap();
    let by_id = |id: &str| {
        proposals
            .iter()
            .find(|p| p["advisory_or_rule_id"] == id)
            .unwrap_or_else(|| panic!("no proposal for {id}"))
    };
    let lodash = by_id("GHSA-p6mc-m468-83gw");
    assert!(
        lodash["patch_diff"]
            .as_str()
            .unwrap()
            .starts_with("--- a/package-lock.json\n")
    );
    let atty = by_id("RUSTSEC-2021-0145");
    assert!(
        atty["patch_diff"]
            .as_str()
            .unwrap()
            .starts_with("--- a/Cargo.lock\n")
    );
    for proposal in proposals {
        let body = proposal["body_markdown"].as_str().unwrap();
        assert!(body.contains("matched against: Sentra's bundled pinned advisory sample"));
        assert!(body.contains("not a synchronized OSV, RustSec or GHSA feed"));
        assert!(!body.contains("canonical"));
        assert!(!body.contains("Reachability confirmed"));
    }

    // Human-readable output carries the same disclosure.
    let text_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "propose-pr",
            "--workspace",
            f.workspace.to_str().unwrap(),
            "--database",
            f.db.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(text_out.status.success());
    let text = String::from_utf8(text_out.stdout).unwrap();
    assert!(text.contains("Local preview only: no branch, commit or pull request was created"));
    assert!(text.contains("Advisory database: bundled pinned sample"));
    assert!(text.contains("Suggested command (not run"));
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
    // Regression: the parsed results were reported as "admitted" findings, although nothing is
    // admitted as evidence or stored.
    assert!(ingest_stdout.contains("\"candidate_findings_parsed\":1"));
    assert!(ingest_stdout.contains("\"findings_stored\":false"));
    assert!(!ingest_stdout.contains("admitted"));
    let ingest_text = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["codeql", "--sarif", sarif_file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(ingest_text.status.success());
    let ingest_text = String::from_utf8(ingest_text.stdout).unwrap();
    assert!(ingest_text.contains("Candidate findings parsed (not stored): 1"));
    assert!(!ingest_text.contains("admitted"));
}

#[test]
fn parses_codeql_analyze_and_import_grammar() {
    let base = [
        "codeql",
        "analyze",
        "--workspace",
        "ws",
        "--codeql",
        "D:/CodeQL/codeql.exe",
        "--work-dir",
        "work",
        "--pack-cache",
        "cache",
    ];
    let parsed = parse(&args(&base)).unwrap_or_else(|_| panic!("valid analyze"));
    let CliCommand::CodeqlAnalyze(analyze) = parsed.command else {
        panic!("expected codeql analyze");
    };
    assert!(!analyze.accept_terms);
    assert!(!analyze.allow_pack_download);
    assert!(analyze.languages.is_empty());
    assert_eq!(analyze.suite.as_str(), "code-scanning");
    assert_eq!(analyze.timeout_secs, 1800);
    assert_eq!(analyze.max_results, 5000);
    assert_eq!((analyze.threads, analyze.ram_mb), (None, None));

    let mut full: Vec<&str> = base.to_vec();
    full.extend([
        "--accept-codeql-terms",
        "--language",
        "TypeScript",
        "--language",
        "python",
        "--suite",
        "security-extended",
        "--threads",
        "4",
        "--ram",
        "8192",
        "--timeout-secs",
        "600",
        "--allow-pack-download",
        "--max-results",
        "10",
        "--json",
    ]);
    let parsed = parse(&args(&full)).unwrap_or_else(|_| panic!("valid analyze"));
    assert!(parsed.json);
    let CliCommand::CodeqlAnalyze(analyze) = parsed.command else {
        panic!("expected codeql analyze");
    };
    assert!(analyze.accept_terms && analyze.allow_pack_download);
    let languages: Vec<&str> = analyze.languages.iter().map(|l| l.as_str()).collect();
    assert_eq!(languages, ["javascript", "python"]);
    assert_eq!(analyze.suite.as_str(), "security-extended");
    assert_eq!((analyze.threads, analyze.ram_mb), (Some(4), Some(8192)));
    assert_eq!((analyze.timeout_secs, analyze.max_results), (600, 10));

    for extra in [
        vec!["--language", "cobol"],
        vec!["--suite", "everything"],
        vec!["--threads", "0"],
        vec!["--threads", "-1"],
        vec!["--ram", "100"],
        vec!["--timeout-secs", "0"],
        vec!["--timeout-secs", "86401"],
        vec!["--max-results", "0"],
        vec!["--max-results", "100001"],
        vec!["--accept-codeql-terms", "--accept-codeql-terms"],
        vec!["--workspace", "again"],
        vec!["--command", "make"],
        vec!["--build-mode", "autobuild"],
        vec!["--sarif", "x.sarif"],
        vec!["--threads"],
    ] {
        let mut words = base.to_vec();
        words.extend(extra.iter().copied());
        assert!(parse(&args(&words)).is_err(), "must reject {extra:?}");
    }
    for missing in ["--workspace", "--codeql", "--work-dir", "--pack-cache"] {
        let index = base.iter().position(|w| *w == missing).unwrap();
        let mut words = base.to_vec();
        words.drain(index..index + 2);
        assert!(parse(&args(&words)).is_err(), "must require {missing}");
    }

    let parsed = parse(&args(&[
        "codeql",
        "import",
        "--sarif",
        "r.sarif",
        "--workspace",
        "ws",
        "--max-results",
        "7",
    ]))
    .unwrap_or_else(|_| panic!("valid import"));
    assert!(matches!(
        parsed.command,
        CliCommand::CodeqlImport { ref sarif, ref workspace, max_results: 7 }
            if sarif == Path::new("r.sarif") && workspace == Path::new("ws")
    ));
    for words in [
        vec!["codeql", "import", "--sarif", "r.sarif"],
        vec!["codeql", "import", "--workspace", "ws"],
        vec![
            "codeql",
            "import",
            "--sarif",
            "r",
            "--workspace",
            "w",
            "--accept-codeql-terms",
        ],
        vec![
            "codeql",
            "import",
            "--sarif",
            "r",
            "--workspace",
            "w",
            "--codeql",
            "c",
        ],
        vec![
            "codeql",
            "import",
            "--sarif",
            "r",
            "--workspace",
            "w",
            "--database",
            "d",
        ],
    ] {
        assert!(parse(&args(&words)).is_err(), "must reject {words:?}");
    }
    // The legacy forms keep their grammar.
    assert!(matches!(
        parse(&args(&["codeql", "--workspace", "ws"]))
            .unwrap_or_else(|_| panic!())
            .command,
        CliCommand::Codeql { .. }
    ));
    assert!(matches!(
        parse(&args(&[
            "codeql",
            "--sarif",
            "r.sarif",
            "--workspace",
            "ws",
            "--database",
            "d"
        ]))
        .unwrap_or_else(|_| panic!())
        .command,
        CliCommand::Codeql { .. }
    ));
    assert!(matches!(
        parse(&args(&["codeql", "analyze", "--help"]))
            .unwrap_or_else(|_| panic!())
            .command,
        CliCommand::Help
    ));
}

#[test]
fn binary_codeql_import_normalizes_and_rejects() {
    let f = Fixture::new();
    let sarif = r#"{
      "version": "2.1.0",
      "runs": [{
        "tool": { "driver": { "name": "CodeQL", "semanticVersion": "2.27.4", "rules": [{
          "id": "js/sql-injection",
          "properties": { "security-severity": "8.8", "problem.severity": "error",
                          "tags": ["security", "external/cwe/cwe-089"] }
        }]}},
        "results": [
          { "ruleId": "js/sql-injection", "ruleIndex": 0, "message": { "text": "SQL built from input" },
            "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "src/db.js" },
                                                  "region": { "startLine": 7, "endLine": 9 } } }],
            "partialFingerprints": { "primaryLocationLineHash": "deadbeef:1" } },
          { "ruleId": "js/sql-injection", "message": { "text": "outside" },
            "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "../../etc/x.js" } } }] }
        ]
      }]
    }"#;
    let file = f.root.join("import.sarif");
    fs::write(&file, sarif).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["codeql", "import", "--sarif"])
        .arg(&file)
        .arg("--workspace")
        .arg(&f.workspace)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["command"], "codeql import");
    assert_eq!(report["codeql_version"], serde_json::Value::Null);
    assert_eq!(report["target_code_executed"], false);
    assert_eq!(report["results_total"], 2);
    assert_eq!(report["results_outside_workspace"], 1);
    assert_eq!(report["languages"][0]["language"], "javascript");
    assert_eq!(report["source_tool"]["version"], "2.27.4");
    let finding = &report["findings"][0];
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["cwe"], serde_json::json!(["CWE-89"]));
    assert_eq!(finding["path"], "src/db.js");
    assert_eq!(
        (finding["start_line"].as_u64(), finding["end_line"].as_u64()),
        (Some(7), Some(9))
    );
    assert_eq!(finding["fingerprint"], "deadbeef:1");

    let text = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["codeql", "import", "--sarif"])
        .arg(&file)
        .arg("--workspace")
        .arg(&f.workspace)
        .output()
        .unwrap();
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("Sentra did not run CodeQL"), "{text}");
    assert!(text.contains("src/db.js:7"), "{text}");

    let reject = |name: &str, content: Option<&str>, size: Option<u64>| {
        let path = f.root.join(name);
        match (content, size) {
            (Some(text), _) => fs::write(&path, text).unwrap(),
            (None, Some(len)) => fs::File::create(&path).unwrap().set_len(len).unwrap(),
            _ => {}
        }
        Command::new(env!("CARGO_BIN_EXE_sentra"))
            .args(["codeql", "import", "--sarif"])
            .arg(&path)
            .arg("--workspace")
            .arg(&f.workspace)
            .arg("--json")
            .output()
            .unwrap()
    };
    for (name, content, size, code, exit) in [
        (
            "semgrep.sarif",
            Some(r#"{"runs":[{"tool":{"driver":{"name":"Semgrep"}},"results":[]}]}"#),
            None,
            "sarif_not_codeql",
            4,
        ),
        ("broken.sarif", Some("{ nope"), None, "sarif_invalid", 4),
        (
            "big.sarif",
            None,
            Some(64 * 1024 * 1024 + 1),
            "sarif_too_large",
            4,
        ),
        ("missing.sarif", None, None, "io_error", 5),
    ] {
        let out = reject(name, content, size);
        assert_eq!(out.status.code(), Some(exit), "{name}");
        let err: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
        assert_eq!(err["error"], code, "{name}");
        assert!(out.stdout.is_empty());
    }
    let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["codeql", "import", "--sarif"])
        .arg(&file)
        .arg("--workspace")
        .arg(f.root.join("no-such-workspace"))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4));
}

#[test]
fn binary_fleet_commands() {
    let status_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["fleet", "status", "--json"])
        .output()
        .unwrap();
    assert!(status_out.status.success());
    let status: serde_json::Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(status["command"], "fleet status");
    // No worker registry source exists, so the registry is empty and containment is never
    // claimed as ready.
    assert_eq!(status["total_workers"], 0);
    assert_eq!(status["available_workers"], 0);
    assert_eq!(status["containment_ready"], false);
    assert_eq!(status["containment_status"], "no_workers");

    let text_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["fleet", "status"])
        .output()
        .unwrap();
    assert!(text_out.status.success());
    let text = String::from_utf8(text_out.stdout).unwrap();
    assert!(text.contains("Containment readiness: not ready (no workers registered)"));
    assert!(!text.contains("verified"));

    let list_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["fleet", "list", "--json"])
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list: serde_json::Value = serde_json::from_slice(&list_out.stdout).unwrap();
    assert_eq!(list["command"], "fleet list");
    assert_eq!(list["total"], 0);
    assert_eq!(list["workers"], serde_json::json!([]));
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
    assert_eq!(
        list_str,
        "{\"schema_version\":1,\"command\":\"tenant list\",\"total\":0,\"tenants\":[],\"untrusted_execution\":false}\n",
        "an empty registry is reported as empty; no demo tenants are seeded"
    );
    // Listing is read-only: the core store keeps its exact schema and stays usable.
    let status = f.invoke(&f.command("status"));
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );

    // A missing database path is listed as empty and is not created.
    let missing = f.root.join("storage space/missing.db");
    let missing_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "tenant",
            "list",
            "--database",
            missing.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(missing_out.status.success());
    assert!(
        String::from_utf8(missing_out.stdout)
            .unwrap()
            .contains("\"total\":0")
    );
    assert!(!missing.exists());

    // Adding a tenant to a core store is refused and leaves the store untouched.
    let core_before = fs::read(&f.db).unwrap();
    let refused = sentra(&[
        "tenant",
        "add",
        "--id",
        "custom-corp",
        "--name",
        "Custom Corp Global",
        "--database",
        f.db.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(refused.status.code(), Some(4));
    assert!(refused.stdout.is_empty());
    assert_eq!(
        String::from_utf8(refused.stderr).unwrap(),
        "{\"schema_version\":1,\"error\":\"invalid_storage_location\"}\n"
    );
    assert_eq!(fs::read(&f.db).unwrap(), core_before);
    let status_after = f.invoke(&f.command("status"));
    assert!(
        status_after.status.success(),
        "{}",
        String::from_utf8_lossy(&status_after.stderr)
    );

    // A dedicated tenant registry file is created and written as before.
    let registry = f.root.join("storage space/tenants.db");
    let add_out = sentra(&[
        "tenant",
        "add",
        "--id",
        "custom-corp",
        "--name",
        "Custom Corp Global",
        "--database",
        registry.to_str().unwrap(),
        "--json",
    ]);
    assert!(add_out.status.success());
    let add_str = String::from_utf8(add_out.stdout).unwrap();
    assert!(add_str.contains("\"command\":\"tenant add\""));
    assert!(add_str.contains("custom-corp"));

    let list_after = sentra(&[
        "tenant",
        "list",
        "--database",
        registry.to_str().unwrap(),
        "--json",
    ]);
    let list_after_str = String::from_utf8(list_after.stdout).unwrap();
    assert!(list_after_str.contains("custom-corp"));
    assert!(list_after_str.contains("\"total\":1"));
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

    // Regression: the help said the default database (data/sentra.db) is created if missing.
    // It is created only inside an existing directory; without `data/` both commands fail.
    let cwd = f.root.join("config-cwd");
    fs::create_dir(&cwd).unwrap();
    for config_args in [
        vec!["config", "show", "--json"],
        vec!["config", "set", "--key", "k", "--value", "v", "--json"],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
            .args(&config_args)
            .current_dir(&cwd)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(5), "{config_args:?}");
        assert_eq!(stderr_json(&out)["error"], "storage_or_service_failure");
        assert!(!cwd.join("data").exists());
    }
    fs::create_dir(cwd.join("data")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["config", "set", "--key", "k", "--value", "v", "--json"])
        .current_dir(&cwd)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(cwd.join("data").join("sentra.db").is_file());
    let help = sentra_cli::HELP;
    assert!(help.contains("sentra config show [--key <key>] [--database <file>] [--json]"));
    assert!(help.contains("but only inside an existing directory"));
    assert!(!help.contains("the file and table are created if missing)"));

    // Regression: config test printed a fixed "connected" result without contacting the
    // provider. It now fails as not implemented and never echoes the key.
    let test_out = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args([
            "config",
            "test",
            "--provider",
            "anthropic",
            "--api-key",
            "sk-test-not-echoed",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(test_out.status.code(), Some(5));
    assert!(test_out.stdout.is_empty());
    let test_error = stderr_json(&test_out);
    assert_eq!(test_error["error"], "not_implemented");
    assert_eq!(test_error["command"], "config test");
    assert!(!String::from_utf8_lossy(&test_out.stderr).contains("sk-test-not-echoed"));

    let resp = run(
        &args(&["config", "test", "--provider", "openai"]),
        Path::new(""),
    );
    assert_eq!(resp.exit_code, 5);
    assert!(resp.stdout.is_empty());
    assert!(resp.stderr.starts_with("error: not_implemented\n"));
    assert_not_implemented(
        &run(
            &args(&["config", "test", "--provider", "openai", "--json"]),
            Path::new(""),
        ),
        "config test",
    );
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
    let apply_json: serde_json::Value = serde_json::from_str(&apply_str).unwrap();
    assert_eq!(apply_json["dry_run"], false);
    assert_eq!(apply_json["hunks"], 1);
    assert_eq!(apply_json["already_patched"], false);
    assert_eq!(
        apply_json["audit_recorded"], false,
        "no --database means no audit event, reported honestly"
    );
    assert!(
        apply_json["backup_path"]
            .as_str()
            .unwrap()
            .ends_with(".bak")
    );

    let patched_content = fs::read_to_string(&target_file).unwrap();
    assert_eq!(
        patched_content,
        "function auth() {\n  let token = process.env.TOKEN;\n}\n"
    );

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
    assert!(rollback_str.contains("\"audit_recorded\":false"));

    let rolled_back_content = fs::read_to_string(&target_file).unwrap();
    assert_eq!(
        rolled_back_content,
        "function auth() {\n  let token = 'old';\n}\n"
    );
}

fn sentra(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(arguments)
        .output()
        .unwrap()
}

fn stdout_json(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout is one JSON document")
}

fn audit_records(f: &Fixture, session: &str) -> Vec<(String, serde_json::Value)> {
    let manager = SqliteConnectionManager::open_existing(&f.db, &SystemClock).unwrap();
    let (repository, _) = PersistenceRepository::with_authority(manager.clone());
    let records = repository
        .audit_events(session.parse::<SessionId>().unwrap(), 0, 1000)
        .unwrap()
        .into_iter()
        .map(|r| {
            let envelope: serde_json::Value = serde_json::from_str(&r.details_json).unwrap();
            (r.event_kind, envelope["event"].clone())
        })
        .collect();
    manager.shutdown().unwrap();
    records
}

const CARGO_LOCK_FIXTURE: &str = "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"time\"\nversion = \"0.2.10\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";

#[test]
fn binary_inventory_discovers_nested_lockfiles_read_only() {
    let f = Fixture::new();
    let ws = &f.workspace;
    fs::write(ws.join("Cargo.lock"), CARGO_LOCK_FIXTURE).unwrap();
    fs::create_dir_all(ws.join("tools/py")).unwrap();
    fs::write(ws.join("tools/py/requirements.txt"), "requests==2.31.0\n").unwrap();
    fs::write(ws.join("package-lock.json"), "{ broken json").unwrap();
    // Dependency and build directories are never entered.
    fs::create_dir_all(ws.join("node_modules/dep")).unwrap();
    fs::write(ws.join("node_modules/dep/Cargo.lock"), CARGO_LOCK_FIXTURE).unwrap();
    fs::create_dir_all(ws.join("target/debug")).unwrap();
    fs::write(ws.join("target/debug/Cargo.lock"), CARGO_LOCK_FIXTURE).unwrap();

    let ws_arg = ws.to_str().unwrap();
    let json = stdout_json(&sentra(&["inventory", "--workspace", ws_arg, "--json"]));
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["command"], "inventory");
    assert_eq!(json["untrusted_execution"], false);
    assert_eq!(json["truncated"], false);
    let expected_root = fs::canonicalize(ws).unwrap();
    let reported_root = PathBuf::from(json["workspace"].as_str().unwrap());
    assert_eq!(fs::canonicalize(reported_root).unwrap(), expected_root);
    assert!(!json["workspace"].as_str().unwrap().contains('\\'));

    let lockfiles = json["lockfiles"].as_array().unwrap();
    let paths: Vec<&str> = lockfiles
        .iter()
        .map(|l| l["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "Cargo.lock",
            "package-lock.json",
            "tools/py/requirements.txt"
        ]
    );
    assert_eq!(lockfiles[0]["kind"], "Cargo");
    assert_eq!(lockfiles[0]["ecosystem"], "crates.io");
    assert_eq!(lockfiles[0]["packages"], 2);
    assert!(lockfiles[0]["parse_error"].is_null());
    assert_eq!(lockfiles[1]["kind"], "PackageLock");
    assert_eq!(lockfiles[1]["ecosystem"], "npm");
    assert_eq!(lockfiles[1]["packages"], 0);
    assert!(lockfiles[1]["parse_error"].as_str().is_some());
    assert_eq!(lockfiles[2]["ecosystem"], "PyPI");
    assert_eq!(json["total_packages"], 3);
    let packages = json["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 3);
    assert_eq!(
        packages[0],
        serde_json::json!({"name":"serde","version":"1.0.200","ecosystem":"crates.io","lockfile":"Cargo.lock"})
    );
    assert_eq!(
        packages[2],
        serde_json::json!({"name":"requests","version":"2.31.0","ecosystem":"PyPI","lockfile":"tools/py/requirements.txt"})
    );

    // Depth 0 inspects root files only.
    let shallow = stdout_json(&sentra(&[
        "inventory",
        "--workspace",
        ws_arg,
        "--max-depth",
        "0",
        "--json",
    ]));
    assert_eq!(shallow["lockfiles"].as_array().unwrap().len(), 2);

    // Out-of-range depth and unknown workspaces fail closed with typed errors.
    let deep = sentra(&[
        "inventory",
        "--workspace",
        ws_arg,
        "--max-depth",
        "33",
        "--json",
    ]);
    assert_eq!(deep.status.code(), Some(2));
    let missing = f.root.join("missing");
    let invalid = sentra(&[
        "inventory",
        "--workspace",
        missing.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(invalid.status.code(), Some(4));
    assert_eq!(
        String::from_utf8(invalid.stderr).unwrap(),
        "{\"schema_version\":1,\"error\":\"invalid_workspace\"}\n"
    );
}

#[test]
fn binary_scan_file_name_selects_rules_and_labels_matches() {
    let go = "cmd := exec.Command(\"sh\", \"-c\", \"ls \" + userPath)";
    let labeled = stdout_json(&sentra(&[
        "scan",
        "--snippet",
        go,
        "--file-name",
        "main.go",
        "--json",
    ]));
    let matches = labeled["matches"].as_array().unwrap();
    assert!(matches.iter().any(|m| m["rule_id"] == "SENTRA-GO-002"));
    assert!(matches.iter().all(|m| m["file_path"] == "main.go"));

    // Without a file name, Go-only rules do not run on the snippet.
    let unlabeled = stdout_json(&sentra(&["scan", "--snippet", go, "--json"]));
    assert!(
        unlabeled["matches"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["rule_id"] != "SENTRA-GO-002")
    );

    // Stdin mode accepts the same label.
    let mut child = Command::new(env!("CARGO_BIN_EXE_sentra"))
        .args(["scan", "-", "--file-name", "main.go", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(go.as_bytes())
        .unwrap();
    let piped = stdout_json(&child.wait_with_output().unwrap());
    assert!(
        piped["matches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["rule_id"] == "SENTRA-GO-002" && m["file_path"] == "main.go")
    );

    // Names are bare basenames, and only label in-memory snippets.
    for words in [
        vec!["scan", "--snippet", "x", "--file-name", "../main.go"],
        vec!["scan", "--snippet", "x", "--file-name", "dir/main.go"],
        vec!["scan", "--snippet", "x", "--file-name", "a b.go"],
        vec!["scan", "--workspace", ".", "--file-name", "main.go"],
        vec![
            "scan",
            "--snippet",
            "x",
            "--file-name",
            "a.go",
            "--file-name",
            "b.go",
        ],
    ] {
        assert!(parse(&args(&words)).is_err(), "must reject {words:?}");
    }
    let long = "a".repeat(101);
    assert!(parse(&args(&["scan", "--snippet", "x", "--file-name", &long])).is_err());
    assert!(
        parse(&args(&[
            "scan",
            "--snippet",
            "x",
            "--file-name",
            &long[..100]
        ]))
        .is_ok()
    );
}

struct PatchCase {
    f: Fixture,
    target: PathBuf,
    patch: PathBuf,
    backups: PathBuf,
}

const AUTH_ORIGINAL: &str = "function auth() {\n  let token = 'old';\n  return token;\n}\n";
const AUTH_PATCHED: &str =
    "function auth() {\n  let token = process.env.TOKEN;\n  return token;\n}\n";
const AUTH_DIFF: &str = "--- a/src/auth.ts\n+++ b/src/auth.ts\n@@ -1,4 +1,4 @@\n function auth() {\n-  let token = 'old';\n+  let token = process.env.TOKEN;\n   return token;\n }\n";

impl PatchCase {
    fn new(diff: &str) -> Self {
        let f = Fixture::new();
        fs::create_dir_all(f.workspace.join("src")).unwrap();
        let target = f.workspace.join("src/auth.ts");
        fs::write(&target, AUTH_ORIGINAL).unwrap();
        let patch = f.root.join("fix.patch");
        fs::write(&patch, diff).unwrap();
        let backups = f.root.join("backups");
        Self {
            f,
            target,
            patch,
            backups,
        }
    }
    fn apply(&self, extra: &[&str]) -> Output {
        let mut arguments = vec![
            "patch",
            "apply",
            "--patch",
            self.patch.to_str().unwrap(),
            "--workspace",
            self.f.workspace.to_str().unwrap(),
            "--target",
            "src/auth.ts",
            "--backup-dir",
            self.backups.to_str().unwrap(),
        ];
        arguments.extend_from_slice(extra);
        arguments.push("--json");
        sentra(&arguments)
    }
}

#[test]
fn binary_patch_dry_run_validates_and_writes_nothing() {
    let case = PatchCase::new(AUTH_DIFF);
    let json = stdout_json(&case.apply(&["--dry-run"]));
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["command"], "patch apply");
    assert_eq!(json["status"], "success");
    assert_eq!(json["dry_run"], true);
    assert_eq!(json["target_path"], "src/auth.ts");
    assert_eq!(json["already_patched"], false);
    assert_eq!(json["hunks"], 1);
    assert_eq!(json["untrusted_execution"], false);
    assert!(json.get("backup_path").is_none());
    assert!(json.get("audit_recorded").is_none());
    assert_eq!(
        json["post_image_sha256"],
        sentra_core::sha256_digest(AUTH_PATCHED.as_bytes())
    );
    assert_eq!(fs::read_to_string(&case.target).unwrap(), AUTH_ORIGINAL);
    assert!(!case.backups.exists(), "a dry run creates no backup");

    // --dry-run belongs to apply only and may appear once.
    assert!(
        parse(&args(&[
            "patch",
            "apply",
            "--patch",
            "p",
            "--workspace",
            "w",
            "--dry-run",
            "--dry-run"
        ]))
        .is_err()
    );
    assert!(
        parse(&args(&[
            "patch",
            "rollback",
            "--backup",
            "b",
            "--workspace",
            "w",
            "--target",
            "t",
            "--dry-run"
        ]))
        .is_err()
    );
}

#[test]
fn binary_patch_that_does_not_apply_fails_closed_without_writes() {
    let stale = AUTH_DIFF.replace("   return token;", "   return other;");
    let case = PatchCase::new(&stale);
    for extra in [&["--dry-run"][..], &[][..]] {
        let output = case.apply(extra);
        assert_eq!(output.status.code(), Some(4));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "{\"schema_version\":1,\"error\":\"patch_does_not_apply\"}\n"
        );
    }
    assert_eq!(fs::read_to_string(&case.target).unwrap(), AUTH_ORIGINAL);
    assert!(!case.backups.exists());

    // Whitespace is never fuzzed: a re-indented pre-image does not match.
    let reindented = AUTH_DIFF.replace("-  let token = 'old';", "-    let token = 'old';");
    fs::write(&case.patch, reindented).unwrap();
    assert_eq!(case.apply(&[]).status.code(), Some(4));

    // Malformed diffs and unsafe targets get their own typed errors.
    fs::write(&case.patch, "not a diff\n").unwrap();
    let malformed = case.apply(&[]);
    assert_eq!(malformed.status.code(), Some(4));
    assert!(
        String::from_utf8(malformed.stderr)
            .unwrap()
            .contains("\"invalid_patch\"")
    );
    fs::write(&case.patch, AUTH_DIFF).unwrap();
    let escape = sentra(&[
        "patch",
        "apply",
        "--patch",
        case.patch.to_str().unwrap(),
        "--workspace",
        case.f.workspace.to_str().unwrap(),
        "--target",
        "../outside.ts",
        "--json",
    ]);
    assert_eq!(escape.status.code(), Some(4));
    assert!(
        String::from_utf8(escape.stderr)
            .unwrap()
            .contains("\"invalid_patch_target\"")
    );
    assert_eq!(fs::read_to_string(&case.target).unwrap(), AUTH_ORIGINAL);
}

#[test]
fn binary_patch_apply_and_rollback_record_core_audit_events() {
    let case = PatchCase::new(AUTH_DIFF);
    let session = case.f.init();
    let db = case.f.db.to_str().unwrap();

    let applied = stdout_json(&case.apply(&["--database", db]));
    assert_eq!(applied["audit_recorded"], true);
    assert_eq!(applied["already_patched"], false);
    assert_eq!(fs::read_to_string(&case.target).unwrap(), AUTH_PATCHED);
    let backup = applied["backup_path"].as_str().unwrap().to_string();

    // Re-applying is detected from the post-image at its own position.
    let again = stdout_json(&case.apply(&["--database", db]));
    assert_eq!(again["already_patched"], true);
    assert!(again["backup_path"].is_null());
    assert_eq!(fs::read_to_string(&case.target).unwrap(), AUTH_PATCHED);

    let rolled_back = stdout_json(&sentra(&[
        "patch",
        "rollback",
        "--backup",
        &backup,
        "--workspace",
        case.f.workspace.to_str().unwrap(),
        "--target",
        "src/auth.ts",
        "--database",
        db,
        "--json",
    ]));
    assert_eq!(rolled_back["audit_recorded"], true);
    assert_eq!(rolled_back["target_path"], "src/auth.ts");
    assert_eq!(fs::read_to_string(&case.target).unwrap(), AUTH_ORIGINAL);

    let events = audit_records(&case.f, &session);
    let patch_events: Vec<&(String, serde_json::Value)> = events
        .iter()
        .filter(|(kind, _)| kind.starts_with("Patch"))
        .collect();
    assert_eq!(patch_events.len(), 3);
    let (kind, details) = patch_events[0];
    assert_eq!(kind, "PatchApplied");
    assert_eq!(details["target_path"], "src/auth.ts");
    assert_eq!(details["already_patched"], false);
    assert_eq!(details["hunks"], 1);
    assert_eq!(
        details["patch_sha256"],
        sentra_core::sha256_digest(AUTH_DIFF.as_bytes())
    );
    assert_eq!(
        details["pre_image_sha256"],
        sentra_core::sha256_digest(AUTH_ORIGINAL.as_bytes())
    );
    assert_eq!(
        details["post_image_sha256"],
        sentra_core::sha256_digest(AUTH_PATCHED.as_bytes())
    );
    assert_eq!(patch_events[1].0, "PatchApplied");
    assert_eq!(patch_events[1].1["already_patched"], true);
    assert_eq!(patch_events[2].0, "PatchRolledBack");
    assert_eq!(
        patch_events[2].1["post_image_sha256"],
        sentra_core::sha256_digest(AUTH_ORIGINAL.as_bytes())
    );

    // The core store keeps its exact schema: core commands still succeed.
    let status = case.f.invoke(&case.f.command("status"));
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
}

#[test]
fn binary_patch_with_foreign_or_missing_store_does_not_touch_the_file() {
    let case = PatchCase::new(AUTH_DIFF);
    // Missing store: fails before any write.
    let missing = case.apply(&["--database", case.f.db.to_str().unwrap()]);
    assert_eq!(missing.status.code(), Some(6));
    assert_eq!(fs::read_to_string(&case.target).unwrap(), AUTH_ORIGINAL);
    assert!(!case.backups.exists());

    // A store that belongs to another workspace is rejected before any write.
    let other = case.f.root.join("other");
    fs::create_dir(&other).unwrap();
    let init = sentra(&[
        "init",
        "--workspace",
        other.to_str().unwrap(),
        "--database",
        case.f.db.to_str().unwrap(),
        "--json",
    ]);
    assert!(init.status.success());
    let mismatch = case.apply(&["--database", case.f.db.to_str().unwrap()]);
    assert_eq!(mismatch.status.code(), Some(4));
    assert_eq!(
        String::from_utf8(mismatch.stderr).unwrap(),
        "{\"schema_version\":1,\"error\":\"workspace_mismatch\"}\n"
    );
    assert_eq!(fs::read_to_string(&case.target).unwrap(), AUTH_ORIGINAL);
    assert!(!case.backups.exists());
}

/// The repository's example adapters, relative to the integration-test working
/// directory (`crates/sentra-cli`). They are only loaded through an explicit `--dir`.
const EXAMPLE_ADAPTERS: &str = "../../examples/adapters";

fn stderr_json(output: &Output) -> serde_json::Value {
    assert!(
        !output.status.success(),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stderr).expect("stderr is one JSON document")
}

#[test]
fn binary_plugin_commands() {
    // 1. Plugin List (JSON) from an explicit directory.
    let list_out = sentra(&["plugin", "list", "--dir", EXAMPLE_ADAPTERS, "--json"]);
    let list = stdout_json(&list_out);
    assert_eq!(list["command"], "plugin");
    assert_eq!(list["action"], "list");
    let ids: Vec<&str> = list["plugins"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    for id in [
        "org.sentra.adapter.snyk",
        "org.sentra.adapter.semgrep",
        "org.sentra.adapter.ollama",
    ] {
        assert!(ids.contains(&id), "{ids:?}");
    }
    let snyk = list["plugins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == "org.sentra.adapter.snyk")
        .unwrap();
    assert_eq!(snyk["enforced"]["egress_policy"], false);
    assert_eq!(snyk["enforced"]["max_memory_mib"], false);
    assert_eq!(snyk["enforced"]["max_execution_time_secs"], true);
    assert!(list["diagnostics"].is_array());

    if bun_available() {
        // 2. Plugin Probe (JSON)
        let probe_out = sentra(&[
            "plugin",
            "probe",
            "--id",
            "org.sentra.adapter.snyk",
            "--dir",
            EXAMPLE_ADAPTERS,
            "--workspace",
            "../..",
            "--json",
        ]);
        let probe = stdout_json(&probe_out);
        assert_eq!(probe["plugin_id"], "org.sentra.adapter.snyk");
        assert_eq!(probe["applicable"], true);

        // 3. Plugin Run passes the workspace to the adapter.
        let run_out = sentra(&[
            "plugin",
            "run",
            "--id",
            "org.sentra.adapter.snyk",
            "--dir",
            EXAMPLE_ADAPTERS,
            "--capability",
            "dependency_audit",
            "--workspace",
            "../..",
            "--json",
        ]);
        let run = stdout_json(&run_out);
        assert_eq!(run["action"], "run");
        assert_eq!(run["capability"], "dependency_audit");
        assert_eq!(run["exit_code"], 0);
        assert_eq!(
            run["adapter_reported"],
            serde_json::json!(["exit_code", "summary", "evidence_refs"])
        );
        let reported = run["workspace_root"].as_str().unwrap();
        assert_eq!(
            fs::canonicalize(reported).unwrap(),
            fs::canonicalize("../..").unwrap()
        );
    }

    // 4. Plugin Run (Undeclared capability rejected before the adapter starts).
    let bad_run_out = sentra(&[
        "plugin",
        "run",
        "--id",
        "org.sentra.adapter.snyk",
        "--dir",
        EXAMPLE_ADAPTERS,
        "--capability",
        "fuzz_execution",
        "--json",
    ]);
    assert_eq!(bad_run_out.status.code(), Some(5));
    assert_eq!(
        stderr_json(&bad_run_out)["error"],
        "plugin_undeclared_capability"
    );
}

#[test]
fn binary_plugin_discovery_is_explicit_and_rejects_duplicates() {
    let f = Fixture::new();
    let empty = f.root.join("empty-plugins");
    fs::create_dir(&empty).unwrap();
    let repo_root = fs::canonicalize("../..").unwrap();
    let plugin_cmd = |extra: &[&str], plugin_dir: Option<&Path>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_sentra"));
        // Run from the repository root, where examples/adapters exists.
        command.current_dir(&repo_root).arg("plugin").args(extra);
        for var in ["SENTRA_PLUGIN_DIR", "APPDATA", "HOME", "XDG_CONFIG_HOME"] {
            command.env_remove(var);
        }
        if let Some(dir) = plugin_dir {
            command.env("SENTRA_PLUGIN_DIR", dir);
        }
        command.output().unwrap()
    };

    // The default directory comes from SENTRA_PLUGIN_DIR; the cwd is never searched.
    let listed = stdout_json(&plugin_cmd(&["list", "--json"], Some(&empty)));
    assert_eq!(listed["count"], 0);
    assert_eq!(
        fs::canonicalize(listed["directories"][0].as_str().unwrap()).unwrap(),
        fs::canonicalize(&empty).unwrap()
    );
    let probe = plugin_cmd(
        &["probe", "--id", "org.sentra.adapter.snyk", "--json"],
        Some(&empty),
    );
    assert_eq!(probe.status.code(), Some(7));
    assert_eq!(stderr_json(&probe)["error"], "plugin_not_found");

    // Without SENTRA_PLUGIN_DIR or a platform config directory there is no default.
    let unavailable = plugin_cmd(&["list", "--json"], None);
    assert_eq!(unavailable.status.code(), Some(2));
    assert_eq!(stderr_json(&unavailable)["error"], "plugin_dir_unavailable");

    // Two manifests declaring the same id: both are excluded and reported.
    let plugins = f.root.join("plugins");
    write_plugin_manifest(&plugins.join("a"), "org.example.same", "A", "adapter.exe");
    write_plugin_manifest(&plugins.join("b"), "org.example.same", "B", "adapter.exe");
    let dir = plugins.to_str().unwrap();
    let listed = stdout_json(&sentra(&["plugin", "list", "--dir", dir, "--json"]));
    assert_eq!(listed["count"], 0);
    let codes: Vec<&str> = listed["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["code"].as_str().unwrap())
        .collect();
    assert_eq!(codes, ["duplicate_plugin_id", "duplicate_plugin_id"]);
    let human = sentra(&["plugin", "list", "--dir", dir]);
    assert!(String::from_utf8_lossy(&human.stdout).contains("[error] duplicate_plugin_id"));
    let ambiguous = sentra(&[
        "plugin",
        "probe",
        "--id",
        "org.example.same",
        "--dir",
        dir,
        "--json",
    ]);
    assert_eq!(ambiguous.status.code(), Some(4));
    assert_eq!(stderr_json(&ambiguous)["error"], "plugin_duplicate_id");
}

/// Backslashes, both quote kinds, a newline, a tab and a control character.
const PLUGIN_TRICKY: &str = "C:\\work\\repo \"quoted\" 'single'\nsecond line\ttab \u{1} end";

fn write_plugin_manifest(dir: &Path, id: &str, name: &str, executable_path: &str) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let manifest = serde_json::json!({
        "id": id,
        "name": name,
        "version": "1.2.3",
        "interface_version": 1,
        "family": "analysis_tool",
        "executable_path": executable_path,
        "declared_capabilities": ["static_analysis"],
        "quotas": {
            "max_memory_mib": 256,
            "max_execution_time_secs": 30,
            "max_frame_bytes": 1048576,
            "max_total_output_bytes": 10485760
        },
        "egress_policy": "strictly_denied"
    });
    let path = dir.join("manifest.json");
    fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
    path
}

#[test]
fn binary_plugin_list_json_escapes_manifest_strings() {
    let f = Fixture::new();
    let plugins = f.root.join("plugins");
    // Windows file names cannot hold `"`; the path still carries backslashes there.
    let adapter_dir = plugins.join(if cfg!(windows) {
        "adapter 'q' ü"
    } else {
        "adapter \"q\" 'q' ü"
    });
    let id = "org.example.escaped";
    let manifest = write_plugin_manifest(
        &adapter_dir,
        id,
        PLUGIN_TRICKY,
        "C:\\tools\\scan.exe --rule \"x\"",
    );
    // An id outside the manifest grammar is skipped and reported, not loaded.
    write_plugin_manifest(
        &plugins.join("invalid id"),
        "org.example.\"esc\\aped\"",
        PLUGIN_TRICKY,
        "scan.exe",
    );

    let output = sentra(&[
        "plugin",
        "list",
        "--dir",
        plugins.to_str().unwrap(),
        "--json",
    ]);
    let json = stdout_json(&output);
    assert_eq!(output.stdout.iter().filter(|b| **b == b'\n').count(), 1);
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["command"], "plugin");
    assert_eq!(json["action"], "list");
    assert_eq!(json["count"], 1);
    let entry = &json["plugins"][0];
    assert_eq!(entry["id"], id);
    assert_eq!(entry["name"], PLUGIN_TRICKY);
    assert_eq!(entry["version"], "1.2.3");
    assert_eq!(entry["family"], "analysis_tool");
    assert_eq!(entry["executable_path"], "C:/tools/scan.exe --rule \"x\"");
    assert_eq!(
        entry["capabilities"],
        serde_json::json!(["static_analysis"])
    );
    assert_eq!(entry["egress_policy"], "StrictlyDenied");
    assert_eq!(
        entry["quotas"],
        serde_json::json!({
            "max_memory_mib": 256,
            "max_execution_time_secs": 30,
            "max_frame_bytes": 1048576,
            "max_total_output_bytes": 10485760
        })
    );
    let diagnostics = json["diagnostics"].as_array().unwrap();
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(diagnostics[0]["severity"], "error");
    assert!(!diagnostics[0]["path"].as_str().unwrap().contains('\\'));
    let reported = entry["manifest_path"].as_str().unwrap();
    assert!(!reported.contains('\\'), "{reported}");
    assert_eq!(
        fs::canonicalize(reported).unwrap(),
        fs::canonicalize(&manifest).unwrap()
    );
}

fn bun_available() -> bool {
    Command::new("bun")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

const ESCAPE_ADAPTER: &str = r#"import * as readline from "readline";
const ID = __ID__;
const TEXT = __TEXT__;
const REFS = __REFS__;
const emit = (frame: object) => process.stdout.write(JSON.stringify(frame) + "\n");
readline.createInterface({ input: process.stdin }).on("line", (line: string) => {
  const req = JSON.parse(line);
  if (req.operation === "initialize") {
    emit({ status: "initialize_ack", plugin_id: ID, interface_version: 1, capabilities: ["static_analysis"] });
  } else if (req.operation === "probe") {
    emit({ status: "probe_result", applicable: false, details: TEXT, unsupported_reason: TEXT });
  } else if (req.operation === "execute") {
    emit({ status: "execute_result", task_id: req.task_id, exit_code: 0, evidence_refs: REFS, summary: TEXT });
  } else if (req.operation === "shutdown") {
    emit({ status: "shutdown_ack" });
    process.exit(0);
  } else {
    emit({ status: "error", code: 1, message: "unsupported operation" });
  }
});
"#;

#[test]
fn binary_plugin_probe_and_run_json_escape_adapter_strings() {
    if !bun_available() {
        eprintln!("skipped: the escape adapter needs bun on PATH");
        return;
    }
    let f = Fixture::new();
    let adapter_dir = f.root.join("adapter 'q' ü");
    let id = "org.example.escape";
    let manifest = write_plugin_manifest(&adapter_dir, id, PLUGIN_TRICKY, "bun run adapter.ts");
    let refs = [String::from("sha256:abc"), String::from("example:escape-1")];
    let script = ESCAPE_ADAPTER
        .replace("__ID__", &serde_json::to_string(id).unwrap())
        .replace("__TEXT__", &serde_json::to_string(PLUGIN_TRICKY).unwrap())
        .replace("__REFS__", &serde_json::to_string(&refs).unwrap());
    fs::write(adapter_dir.join("adapter.ts"), script).unwrap();
    let manifest_arg = manifest.to_str().unwrap();

    let probe_out = sentra(&[
        "plugin",
        "probe",
        "--manifest",
        manifest_arg,
        "--workspace",
        f.workspace.to_str().unwrap(),
        "--json",
    ]);
    let probe = stdout_json(&probe_out);
    assert_eq!(probe_out.stdout.iter().filter(|b| **b == b'\n').count(), 1);
    assert_eq!(probe["schema_version"], 1);
    assert_eq!(probe["command"], "plugin");
    assert_eq!(probe["action"], "probe");
    assert_eq!(probe["plugin_id"], id);
    assert_eq!(probe["name"], PLUGIN_TRICKY);
    assert_eq!(probe["applicable"], false);
    assert_eq!(probe["details"], PLUGIN_TRICKY);
    assert_eq!(probe["unsupported_reason"], PLUGIN_TRICKY);
    assert_eq!(
        probe["capabilities"],
        serde_json::json!(["static_analysis"])
    );

    let run_out = sentra(&[
        "plugin",
        "run",
        "--manifest",
        manifest_arg,
        "--capability",
        "static_analysis",
        "--workspace",
        f.workspace.to_str().unwrap(),
        "--json",
    ]);
    let run = stdout_json(&run_out);
    assert_eq!(run_out.stdout.iter().filter(|b| **b == b'\n').count(), 1);
    assert_eq!(run["schema_version"], 1);
    assert_eq!(run["command"], "plugin");
    assert_eq!(run["action"], "run");
    assert_eq!(run["plugin_id"], id);
    assert!(run["task_id"].as_str().unwrap().starts_with("task-"));
    assert_eq!(run["capability"], "static_analysis");
    assert_eq!(run["exit_code"], 0);
    assert_eq!(run["summary"], PLUGIN_TRICKY);
    assert_eq!(run["evidence_refs"], serde_json::json!(refs));
    assert_eq!(
        fs::canonicalize(run["workspace_root"].as_str().unwrap()).unwrap(),
        fs::canonicalize(&f.workspace).unwrap()
    );

    // Evidence refs outside the `<scheme>:<value>` label grammar are rejected.
    let forged_dir = f.root.join("forged adapter");
    let forged_manifest =
        write_plugin_manifest(&forged_dir, id, PLUGIN_TRICKY, "bun run adapter.ts");
    let forged = ESCAPE_ADAPTER
        .replace("__ID__", &serde_json::to_string(id).unwrap())
        .replace("__TEXT__", &serde_json::to_string(PLUGIN_TRICKY).unwrap())
        .replace(
            "__REFS__",
            &serde_json::to_string(&[PLUGIN_TRICKY]).unwrap(),
        );
    fs::write(forged_dir.join("adapter.ts"), forged).unwrap();
    let rejected = sentra(&[
        "plugin",
        "run",
        "--manifest",
        forged_manifest.to_str().unwrap(),
        "--capability",
        "static_analysis",
        "--workspace",
        f.workspace.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(rejected.status.code(), Some(5));
    let error = stderr_json(&rejected);
    assert_eq!(error["error"], "plugin_result_mismatch");
    assert!(error["reason"].is_string());
}

#[test]
fn binary_skills_list_and_show() {
    let list_out = sentra(&["skills", "list"]);
    assert!(list_out.status.success());
    let list_str = String::from_utf8(list_out.stdout).unwrap();
    assert!(list_str.contains("api-security-testing"));
    assert!(list_str.contains("security-threat-model"));
    assert!(list_str.contains("auth-implementation-patterns"));

    let list_json = sentra(&["skills", "list", "--json"]);
    assert_eq!(list_json.stdout.iter().filter(|b| **b == b'\n').count(), 1);
    let list = stdout_json(&list_json);
    assert_eq!(list["schema_version"], 1);
    assert_eq!(list["command"], "skills list");
    let skills = list["skills"].as_array().unwrap();
    assert_eq!(list["count"], skills.len());
    assert!(skills.iter().any(|s| s["id"] == "api-security-testing"));

    let show_out = sentra(&["skills", "show", "api-security-testing"]);
    assert!(show_out.status.success());
    let show_str = String::from_utf8(show_out.stdout).unwrap();
    assert!(show_str.contains("name: api-security-testing"));
    assert!(show_str.contains("BOLA/IDOR"));

    let show = stdout_json(&sentra(&["skills", "show", "golang-security", "--json"]));
    assert_eq!(show["schema_version"], 1);
    assert_eq!(show["command"], "skills show");
    assert_eq!(show["id"], "golang-security");
    let files: Vec<&str> = show["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    assert!(files.contains(&"SKILL.md") && files.contains(&"LICENSE"));
    assert!(files.contains(&"references/checklist.md"));

    let missing = sentra(&["skills", "show", "does-not-exist", "--json"]);
    assert_eq!(missing.status.code(), Some(7));
    assert_eq!(stderr_json(&missing)["error"], "skill_not_found");
}

/// Variables the skill installer and the MCP installer read to find user-scope
/// configuration. Every one is redirected or removed for child processes.
const REDIRECTED_HOME_VARS: [&str; 5] = [
    "USERPROFILE",
    "HOME",
    "APPDATA",
    "LOCALAPPDATA",
    "XDG_CONFIG_HOME",
];
const REMOVED_CONFIG_VARS: [&str; 8] = [
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "COPILOT_HOME",
    "KIMI_CODE_HOME",
    "CLINE_MCP_SETTINGS_PATH",
    "CLINE_DATA_DIR",
    "CLINE_DIR",
    "SENTRA_PLUGIN_DIR",
];

/// Runs the binary with the home and configuration directories redirected into
/// `f.root/home`, so no test ever reads or writes the real user configuration.
fn sandboxed(f: &Fixture, arguments: &[&str]) -> Output {
    let home = f.root.join("home");
    let mut command = Command::new(env!("CARGO_BIN_EXE_sentra"));
    command.args(arguments).current_dir(&f.workspace);
    for var in REDIRECTED_HOME_VARS {
        let dir = home.join(var.to_ascii_lowercase());
        fs::create_dir_all(&dir).unwrap();
        command.env(var, dir);
    }
    for var in REMOVED_CONFIG_VARS {
        command.env_remove(var);
    }
    command.output().unwrap()
}

fn sandbox_home(f: &Fixture) -> PathBuf {
    f.root
        .join("home")
        .join(if cfg!(windows) { "userprofile" } else { "home" })
}

#[test]
fn binary_install_skill_targets_use_documented_locations() {
    let f = Fixture::new();
    let ws = f.workspace.to_str().unwrap();
    let install = |target: &str, skill: &str| {
        let output = sandboxed(
            &f,
            &["install", target, "--workspace", ws, "--skill", skill],
        );
        assert!(
            output.status.success(),
            "{target}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    let skill_md = |parts: &[&str]| parts.iter().fold(f.workspace.clone(), |p, s| p.join(s));

    let text = install("claude", "api-security-testing");
    assert!(text.contains("Sentra AppSec skill installation: success"));
    assert!(text.contains("[created]"));
    for (path, bytes) in sentra_core::skills::skill_files("api-security-testing").unwrap() {
        let installed = f
            .workspace
            .join(".claude/skills/api-security-testing")
            .join(path);
        let on_disk = fs::read(&installed).unwrap();
        let normalize = |b: &[u8]| String::from_utf8_lossy(b).replace("\r\n", "\n");
        assert_eq!(normalize(&on_disk), normalize(bytes), "{path}");
    }

    // JSON output is built with serde, so Windows paths are escaped correctly.
    let agy = sandboxed(
        &f,
        &[
            "install",
            "antigravity",
            "--workspace",
            ws,
            "--skill",
            "security-threat-model",
            "--json",
        ],
    );
    let agy = stdout_json(&agy);
    assert_eq!(agy["target"], "antigravity");
    assert_eq!(agy["count"], 1);
    assert_eq!(agy["skills"], serde_json::json!(["security-threat-model"]));
    assert!(agy["file_count"].as_u64().unwrap() >= 1);
    assert!(skill_md(&[".agents", "skills", "security-threat-model", "SKILL.md"]).exists());

    install("cursor", "golang-security");
    assert!(skill_md(&[".cursor", "skills", "golang-security", "SKILL.md"]).exists());
    assert!(
        skill_md(&[
            ".cursor",
            "skills",
            "golang-security",
            "references",
            "checklist.md"
        ])
        .exists()
    );
    assert!(!f.workspace.join(".cursorrules").exists());

    install("windsurf", "django-security");
    assert!(skill_md(&[".agents", "skills", "django-security", "SKILL.md"]).exists());

    install("copilot", "ci-cd-security");
    assert!(skill_md(&[".github", "skills", "ci-cd-security", "SKILL.md"]).exists());
    assert!(!f.workspace.join(".github/copilot-instructions.md").exists());

    install("aider", "api-security-testing");
    assert!(skill_md(&[".agents", "skills", "api-security-testing", "SKILL.md"]).exists());
    let aider_conf = fs::read_to_string(f.workspace.join(".aider.conf.yml")).unwrap();
    assert!(aider_conf.contains(".agents/skills/api-security-testing/SKILL.md"));
    assert!(!f.workspace.join("CONVENTIONS.md").exists());

    install("roo", "solidity-security");
    assert!(skill_md(&[".roo", "skills", "solidity-security", "SKILL.md"]).exists());

    install("continue", "springboot-security");
    let rule = fs::read_to_string(
        f.workspace
            .join(".continue/rules/sentra-springboot-security.md"),
    )
    .unwrap();
    assert!(rule.contains("alwaysApply: false"));
    assert!(skill_md(&[".agents", "skills", "springboot-security", "SKILL.md"]).exists());

    // A rerun leaves identical files untouched.
    let rerun = install("claude", "api-security-testing");
    assert!(rerun.contains("Unchanged files:"));
    assert!(!rerun.contains("[created]"));
}

#[test]
fn binary_install_skill_errors_are_specific_and_write_nothing() {
    let f = Fixture::new();
    let ws = f.workspace.to_str().unwrap();

    let global = sandboxed(
        &f,
        &[
            "install",
            "claude",
            "--skill",
            "golang-security",
            "--global",
            "--json",
        ],
    );
    let report = stdout_json(&global);
    assert_eq!(report["scope"], "global");
    assert!(
        sandbox_home(&f)
            .join(".claude/skills/golang-security/SKILL.md")
            .exists()
    );

    let unknown = sandboxed(
        &f,
        &[
            "install",
            "claude",
            "--workspace",
            ws,
            "--skill",
            "golang-security,does-not-exist",
            "--json",
        ],
    );
    assert_eq!(unknown.status.code(), Some(7));
    let body = stderr_json(&unknown);
    assert_eq!(body["error"], "skill_not_found");
    assert_eq!(
        body["unknown_skills"],
        serde_json::json!(["does-not-exist"])
    );
    assert!(!f.workspace.join(".claude").exists());

    let cody = sandboxed(&f, &["install", "cody", "--workspace", ws, "--json"]);
    assert_eq!(cody.status.code(), Some(2));
    assert_eq!(stderr_json(&cody)["error"], "unsupported_target");

    let amazonq = sandboxed(&f, &["install", "amazonq", "--global", "--json"]);
    assert_eq!(amazonq.status.code(), Some(2));
    assert_eq!(stderr_json(&amazonq)["error"], "unsupported_scope");

    let bogus = sandboxed(
        &f,
        &["install", "not-an-agent", "--workspace", ws, "--json"],
    );
    assert_eq!(bogus.status.code(), Some(2));
    assert_eq!(stderr_json(&bogus)["error"], "invalid_target");

    // Aider loads every `read:` file into every chat, so --skill is required.
    let aider = sandboxed(&f, &["install", "aider", "--workspace", ws, "--json"]);
    assert_eq!(aider.status.code(), Some(2));
    assert_eq!(stderr_json(&aider)["error"], "skill_selection_required");
    assert!(!f.workspace.join(".aider.conf.yml").exists());

    for words in [
        &["install", "claude", "--mcp", "--skill", "golang-security"][..],
        &["install", "mcp", "claude", "--skill", "golang-security"],
    ] {
        let mut arguments = words.to_vec();
        arguments.extend(["--workspace", ws, "--json"]);
        let mixed = sandboxed(&f, &arguments);
        assert_eq!(mixed.status.code(), Some(2));
        let body = stderr_json(&mixed);
        assert_eq!(body["error"], "invalid_arguments");
        assert!(body["message"].as_str().unwrap().contains("--skill"));
    }
    let text = sandboxed(&f, &["install", "claude", "--mcp", "--skill", "x"]);
    assert!(String::from_utf8_lossy(&text.stderr).contains("--skill cannot be combined"));

    let missing_ws = f.root.join("missing");
    let missing = sandboxed(
        &f,
        &[
            "install",
            "claude",
            "--workspace",
            missing_ws.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(missing.status.code(), Some(2));
    assert_eq!(stderr_json(&missing)["error"], "workspace_not_found");
    assert!(!missing_ws.exists());

    // Aider config that cannot be edited losslessly: skills installed, snippet printed.
    fs::write(
        f.workspace.join(".aider.conf.yml"),
        "read: &anchor CONVENTIONS.md\n",
    )
    .unwrap();
    let aider = sandboxed(
        &f,
        &[
            "install",
            "aider",
            "--workspace",
            ws,
            "--skill",
            "golang-security",
        ],
    );
    assert_eq!(aider.status.code(), Some(6));
    assert!(String::from_utf8_lossy(&aider.stderr).contains("manual_config_edit_required"));
    assert!(String::from_utf8_lossy(&aider.stdout).contains("manual config edit required"));
    assert_eq!(
        fs::read_to_string(f.workspace.join(".aider.conf.yml")).unwrap(),
        "read: &anchor CONVENTIONS.md\n"
    );
}

#[test]
fn binary_prompt_generation() {
    // 1. Threat model prompt
    let tm_out = sentra(&["prompt", "threat-model", "--scope", "src/auth"]);
    assert!(tm_out.status.success());
    let tm_str = String::from_utf8(tm_out.stdout).unwrap();
    assert!(tm_str.contains("Mermaid"));
    assert!(tm_str.contains("STRIDE"));

    // 2. API BOLA prompt
    let bola = stdout_json(&sentra(&[
        "prompt",
        "api-bola",
        "--scope",
        "/api/v1/orders/:id",
        "--json",
    ]));
    assert_eq!(bola["workflow"], "api-bola");
    assert!(bola["user_prompt"].as_str().unwrap().contains("BOLA/IDOR"));

    // 3. Patch synthesis prompt
    let patch_out = sentra(&["prompt", "patch-remediation", "--scope", "src/db.rs"]);
    assert!(patch_out.status.success());
    let patch_str = String::from_utf8(patch_out.stdout).unwrap();
    assert!(patch_str.contains("ADR-0004"));
    assert!(patch_str.contains("Tier 1"));

    // 4. Scout prompt with JSON output
    let scout = stdout_json(&sentra(&[
        "prompt",
        "scout",
        "--scope",
        "crates/sentra-core",
        "--json",
    ]));
    assert_eq!(scout["workflow"], "scout");
    assert_eq!(scout["role"], "scout");
    assert!(
        scout["system_prompt"]
            .as_str()
            .unwrap()
            .contains("Senior Application Security Scout")
    );

    // 5. Dual-state verification prompt
    let verify_out = sentra(&["prompt", "verify", "--scope", "src/auth.rs"]);
    assert!(verify_out.status.success());
    let verify_str = String::from_utf8(verify_out.stdout).unwrap();
    assert!(verify_str.contains("Independent Dual-State Verification"));
    assert!(verify_str.contains("Independent AppSec Verification Oracle"));

    // 6. Skill injection keeps the workflow prompt, its schema and its rules.
    let skill = stdout_json(&sentra(&[
        "prompt",
        "patch-remediation",
        "--scope",
        "src/service.go",
        "--skills",
        "golang-security,golang-security",
        "--json",
    ]));
    assert_eq!(skill["skills"], serde_json::json!(["golang-security"]));
    let system = skill["system_prompt"].as_str().unwrap();
    assert!(system.contains("Golang Security Best Practices"));
    assert!(system.contains("Activated Domain Security Guidelines"));
    assert!(skill["expected_schema"].is_string());
    assert!(skill["user_prompt"].as_str().unwrap().contains("Tier 1"));

    let threat = stdout_json(&sentra(&[
        "prompt",
        "threat-model",
        "--skills",
        "stride-analysis-patterns",
        "--json",
    ]));
    assert!(threat["expected_schema"].is_string());
    assert!(
        threat["system_prompt"]
            .as_str()
            .unwrap()
            .contains("Evidence & Grounding Rules")
    );

    // 7. Unknown skill ids and workflows fail instead of being dropped.
    let bogus = sentra(&["prompt", "verify", "--skills", "bogus", "--json"]);
    assert_eq!(bogus.status.code(), Some(7));
    let body = stderr_json(&bogus);
    assert_eq!(body["error"], "skill_not_found");
    assert_eq!(body["unknown_skills"], serde_json::json!(["bogus"]));
    let human = sentra(&["prompt", "verify", "--skills", "bogus"]);
    assert_eq!(human.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&human.stderr).starts_with("error: skill_not_found"));
    let workflow = sentra(&["prompt", "nope", "--json"]);
    assert_eq!(workflow.status.code(), Some(2));
    assert_eq!(stderr_json(&workflow)["error"], "unknown_workflow");
}

fn mcp_entry_command(config: &Path, pointer: &str) -> serde_json::Value {
    let text = fs::read_to_string(config).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    value.pointer(pointer).cloned().unwrap_or_default()
}

#[test]
fn binary_install_mcp_config() {
    let f = Fixture::new();
    let ws = f.workspace.to_str().unwrap();

    // 1. `install mcp claude` writes the project-scope `.mcp.json`.
    let mcp_claude = sandboxed(&f, &["install", "mcp", "claude", "--workspace", ws]);
    assert!(
        mcp_claude.status.success(),
        "{}",
        String::from_utf8_lossy(&mcp_claude.stderr)
    );
    let human = String::from_utf8_lossy(&mcp_claude.stdout);
    assert!(human.contains("Sentra MCP server registration: created"));
    let claude_cfg = f.workspace.join(".mcp.json");
    let entry = mcp_entry_command(&claude_cfg, "/mcpServers/sentra");
    assert_eq!(entry["args"], serde_json::json!(["mcp"]));
    let command = entry["command"].as_str().unwrap();
    assert!(Path::new(command).is_absolute(), "{command}");
    assert_eq!(
        fs::canonicalize(command).unwrap(),
        fs::canonicalize(env!("CARGO_BIN_EXE_sentra")).unwrap()
    );
    assert!(!f.workspace.join(".claude/mcp.json").exists());

    // 2. `install cursor --mcp`
    let mcp_cursor = sandboxed(&f, &["install", "cursor", "--mcp", "--workspace", ws]);
    assert!(mcp_cursor.status.success());
    assert!(f.workspace.join(".cursor/mcp.json").exists());

    // 3. `mcp install zed` uses the flat command form under context_servers.
    let mcp_zed = sandboxed(&f, &["mcp", "install", "zed", "--workspace", ws]);
    assert!(mcp_zed.status.success());
    let zed = mcp_entry_command(
        &f.workspace.join(".zed/settings.json"),
        "/context_servers/sentra",
    );
    assert!(zed["command"].is_string());

    // 4. Continue reads `.continue/mcpServers/*.yaml` block files.
    let mcp_continue = sandboxed(&f, &["mcp", "install", "continue", "--workspace", ws]);
    assert!(mcp_continue.status.success());
    let continue_text =
        fs::read_to_string(f.workspace.join(".continue/mcpServers/sentra.yaml")).unwrap();
    assert!(continue_text.contains("mcpServers:"));
    assert!(continue_text.contains("- name: sentra"));
    assert!(!f.workspace.join(".continue/config.json").exists());

    // 5. Non-destructive merge with a backup of the original text.
    let initial_custom = "{\n  // user comment\n  \"mcpServers\": {\n    \"my-custom-tool\": {\n      \"command\": \"custom-binary\",\n      \"args\": [\"--port\", \"8080\"],\n    },\n  },\n}\n";
    fs::write(&claude_cfg, initial_custom).unwrap();
    let merge_out = sandboxed(
        &f,
        &["install", "mcp", "claude", "--workspace", ws, "--json"],
    );
    let merged = stdout_json(&merge_out);
    assert_eq!(merged["schema_version"], 1);
    assert_eq!(merged["action"], "updated");
    let backup = merged["backup_file"].as_str().unwrap();
    assert_eq!(fs::read_to_string(backup).unwrap(), initial_custom);
    let merged_content = fs::read_to_string(&claude_cfg).unwrap();
    assert!(merged_content.contains("// user comment"));
    assert!(merged_content.contains("custom-binary"));
    assert!(merged_content.contains("\"sentra\""));

    // 6. A rerun changes nothing.
    let rerun = stdout_json(&sandboxed(
        &f,
        &["install", "mcp", "claude", "--workspace", ws, "--json"],
    ));
    assert_eq!(rerun["action"], "unchanged");
    assert_eq!(fs::read_to_string(&claude_cfg).unwrap(), merged_content);

    // 7. Amp is its own target.
    let amp = sandboxed(&f, &["install", "mcp", "amp", "--workspace", ws]);
    assert!(amp.status.success());
    assert!(
        fs::read_to_string(f.workspace.join(".amp/settings.json"))
            .unwrap()
            .contains("amp.mcpServers")
    );

    // 8. `--command` overrides the registered executable.
    let custom = sandboxed(
        &f,
        &[
            "install",
            "mcp",
            "kiro",
            "--workspace",
            ws,
            "--command",
            "sentra-custom",
            "--json",
        ],
    );
    assert_eq!(stdout_json(&custom)["server_command"], "sentra-custom");
}

#[test]
fn binary_install_mcp_errors_never_rewrite_user_files() {
    let f = Fixture::new();
    let ws = f.workspace.to_str().unwrap();

    // Unparseable config: exit 4, untouched, snippet to add by hand.
    let claude_cfg = f.workspace.join(".mcp.json");
    fs::write(&claude_cfg, "{ broken").unwrap();
    let broken = sandboxed(
        &f,
        &["install", "mcp", "claude", "--workspace", ws, "--json"],
    );
    assert_eq!(broken.status.code(), Some(4));
    let body = stderr_json(&broken);
    assert_eq!(body["error"], "mcp_config_unparseable");
    assert_eq!(body["target"], "claude");
    assert!(
        body["manual_step"]["snippet"]
            .as_str()
            .unwrap()
            .contains("\"sentra\"")
    );
    assert_eq!(fs::read_to_string(&claude_cfg).unwrap(), "{ broken");
    assert!(!f.workspace.join(".mcp.json.bak").exists());
    let human = sandboxed(&f, &["install", "mcp", "claude", "--workspace", ws]);
    assert_eq!(human.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&human.stderr);
    assert!(stderr.starts_with("error: mcp_config_unparseable"));
    assert!(stderr.contains("Manual step:") && stderr.contains("----- snippet -----"));

    for (target, global, code) in [
        ("aider", false, "mcp_unsupported_target"),
        ("cody", false, "mcp_unsupported_target"),
        ("cline", false, "unsupported_scope"),
        ("roo", true, "unsupported_scope"),
        ("nope", false, "invalid_target"),
    ] {
        let mut arguments = vec!["install", "mcp", target, "--workspace", ws, "--json"];
        if global {
            arguments.push("--global");
        }
        let output = sandboxed(&f, &arguments);
        assert_eq!(output.status.code(), Some(2), "{target}");
        assert_eq!(stderr_json(&output)["error"], code, "{target}");
    }
    assert!(!f.workspace.join(".agents/mcp.json").exists());

    let missing = sandboxed(
        &f,
        &[
            "install",
            "mcp",
            "claude",
            "--workspace",
            f.root.join("missing").to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(missing.status.code(), Some(2));
    assert_eq!(stderr_json(&missing)["error"], "workspace_not_found");
    assert!(!f.root.join("missing").exists());

    let bad_command = sandboxed(
        &f,
        &[
            "install",
            "mcp",
            "cursor",
            "--workspace",
            ws,
            "--command",
            "./no/such/sentra",
            "--json",
        ],
    );
    assert_eq!(bad_command.status.code(), Some(2));
    assert_eq!(stderr_json(&bad_command)["error"], "mcp_command_not_found");

    // `all` reports skipped targets and stops with the broken file's exit code.
    let all = sandboxed(&f, &["install", "mcp", "all", "--workspace", ws, "--json"]);
    assert_eq!(all.status.code(), Some(4));
    let batch: serde_json::Value = serde_json::from_slice(&all.stdout).unwrap();
    assert_eq!(batch["target"], "all");
    assert_eq!(batch["success"], false);
    let skipped: Vec<&str> = batch["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["target"].as_str().unwrap())
        .collect();
    assert!(skipped.contains(&"aider") && skipped.contains(&"cline"));
    assert_eq!(batch["failed"][0]["target"], "claude");
    assert_eq!(fs::read_to_string(&claude_cfg).unwrap(), "{ broken");

    // With the broken file fixed, `all --global` succeeds inside the sandbox home.
    fs::remove_file(&claude_cfg).unwrap();
    let global = sandboxed(&f, &["install", "mcp", "all", "--global", "--json"]);
    let batch = stdout_json(&global);
    assert_eq!(batch["success"], true);
    assert!(sandbox_home(&f).join(".claude.json").exists());
    assert!(!sandbox_home(&f).join(".agents/mcp.json").exists());
}

fn mcp_session(arguments: &[&str], requests: &[&[u8]]) -> Vec<serde_json::Value> {
    let mut input = Vec::new();
    for request in requests {
        input.extend_from_slice(request);
        input.push(b'\n');
    }
    let mut cursor = Cursor::new(input);
    let resp = run_with_input(&args(arguments), Path::new(""), &mut cursor);
    assert_eq!(resp.exit_code, 0, "{}", resp.stderr);
    resp.stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

const MCP_INIT: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}";
const MCP_INITIALIZED: &[u8] = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";

#[test]
fn mcp_stdio_survives_bad_input_and_confines_tools() {
    let f = Fixture::new();
    let session = f.init();
    let ws = f.workspace.to_str().unwrap();
    let db = f.db.to_str().unwrap();

    // Invalid UTF-8 is a parse error, not the end of the session.
    let lines = mcp_session(
        &["mcp"],
        &[
            MCP_INIT,
            &[0x7B, 0xFF, 0xFE, 0x7D],
            b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}",
        ],
    );
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(lines[1]["error"]["code"], -32700);
    assert!(lines[1]["id"].is_null());
    assert_eq!(lines[2]["id"], 2);

    let lines = mcp_session(
        &["mcp", "--workspace", ws, "--database", db],
        &[
            MCP_INIT,
            MCP_INITIALIZED,
            b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"sentra_install_skills\",\"arguments\":{}}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"sentra_scan_code\",\"arguments\":{\"path\":\"..\"}}}",
            b"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"sentra_get_session_status\",\"arguments\":{}}}",
        ],
    );
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[1]["error"]["code"], -32602);
    assert_eq!(lines[2]["result"]["isError"], true);
    assert_eq!(
        lines[2]["result"]["structuredContent"]["error"],
        "path_outside_launch_root"
    );
    assert_eq!(lines[3]["result"]["isError"], false);
    assert_eq!(
        lines[3]["result"]["structuredContent"]["session_id"],
        session
    );

    let missing = run_with_input(
        &args(&[
            "mcp",
            "--workspace",
            f.root.join("missing").to_str().unwrap(),
        ]),
        Path::new(""),
        &mut Cursor::new(Vec::new()),
    );
    assert_eq!(missing.exit_code, 4);
    assert!(missing.stdout.is_empty());
}
