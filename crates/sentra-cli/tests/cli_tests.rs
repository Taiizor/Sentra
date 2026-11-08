use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use sentra_cli::{Command as CliCommand, parse, run};
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
        let root = std::env::temp_dir().join(format!(
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
