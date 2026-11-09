use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
};

use sentra_core::{
    CoreService, CoreServiceConfig, CostUsd, FailClosedBackend, OperatingMode, PolicyEngine,
    SecurityClassification, SessionId, SessionState, SystemClock,
    persistence::{PersistenceRepository, SqliteConnectionManager},
    service::{LocalWorkspace, LocalWorkspaceErrorKind},
};

struct Fixture {
    root: PathBuf,
    workspace: PathBuf,
    db: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let temp = fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
        let root = temp.join(format!(
            "sentra-local-core-{}-{}",
            std::process::id(),
            SessionId::new()
        ));
        fs::create_dir(&root).unwrap();
        let workspace = root.join("workspace Unicode ü 空 space");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(root.join("storage")).unwrap();
        let db = root.join("storage/local.db");
        Self {
            root,
            workspace,
            db,
        }
    }
    fn service(&self) -> (CoreService, SqliteConnectionManager) {
        let manager = SqliteConnectionManager::open(&self.db, &SystemClock).unwrap();
        let (repository, authority) = PersistenceRepository::with_authority(manager.clone());
        (
            CoreService::new(
                CoreServiceConfig::default(),
                repository,
                authority,
                PolicyEngine::new(),
                Arc::new(FailClosedBackend),
                Arc::new(SystemClock),
            ),
            manager,
        )
    }
    fn rows(&self) -> Vec<String> {
        let db = rusqlite::Connection::open(&self.db).unwrap();
        // Inspect every domain table, including raw values, to prove no logical
        // mutation during repeated initialization/status/session projection.
        let mut rows = Vec::new();
        for table in [
            "sessions",
            "session_security_snapshots",
            "audit_events",
            "approval_requests",
            "budget_reservations",
        ] {
            let mut statement = db
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let count = statement.column_count();
            let values = statement
                .query_map([], |r| {
                    Ok((0..count)
                        .map(|i| format!("{:?}", r.get_ref(i).unwrap()))
                        .collect::<Vec<_>>()
                        .join("|"))
                })
                .unwrap();
            rows.extend(values.map(|r| format!("{table}:{}", r.unwrap())));
        }
        rows
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let path = fs::canonicalize(&self.root).unwrap();
        assert!(path.starts_with(&parent) && path != parent);
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn initialized_identity_is_stable_and_inspection_changes_no_domain_rows() {
    let f = Fixture::new();
    let initial = LocalWorkspace::initialize(&f.workspace, &f.db).unwrap();
    assert!(initial.initialized && initial.created);
    let session = initial.session.unwrap();
    assert_eq!(session.state, sentra_core::SessionState::Scoped);
    assert_eq!(session.budget_limit, CostUsd::ZERO);
    let before = f.rows();
    let repeated = LocalWorkspace::initialize(&f.workspace, &f.db).unwrap();
    assert!(!repeated.created);
    assert_eq!(repeated.session.as_ref(), Some(&session));
    assert_eq!(
        LocalWorkspace::status(&f.workspace, &f.db).unwrap().session,
        Some(session.clone())
    );
    assert_eq!(
        LocalWorkspace::session(&f.workspace, &f.db, session.session_id)
            .unwrap()
            .session,
        Some(session)
    );
    assert_eq!(f.rows(), before);
}

#[test]
fn status_and_session_never_create_a_missing_database() {
    let f = Fixture::new();
    let status = LocalWorkspace::status(&f.workspace, &f.db).unwrap();
    assert!(!status.initialized && status.session.is_none());
    assert_eq!(
        LocalWorkspace::session(&f.workspace, &f.db, SessionId::new())
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::SessionNotFound
    );
    assert!(!f.db.exists());
}

#[test]
fn open_existing_cannot_create_or_adopt_an_empty_database() {
    let f = Fixture::new();
    assert!(SqliteConnectionManager::open_existing(&f.db, &SystemClock).is_err());
    assert!(!f.db.exists());
    fs::write(&f.db, b"").unwrap();
    assert!(SqliteConnectionManager::open_existing(&f.db, &SystemClock).is_err());
    assert_eq!(fs::metadata(&f.db).unwrap().len(), 0);
    assert!(LocalWorkspace::initialize(&f.workspace, &f.db).is_err());
    assert_eq!(fs::metadata(&f.db).unwrap().len(), 0);
}

#[test]
fn unrelated_sqlite_database_is_preserved() {
    let f = Fixture::new();
    let db = rusqlite::Connection::open(&f.db).unwrap();
    db.execute_batch(
        "CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('sentinel')",
    )
    .unwrap();
    drop(db);
    let before = fs::read(&f.db).unwrap();
    assert!(LocalWorkspace::initialize(&f.workspace, &f.db).is_err());
    assert!(LocalWorkspace::status(&f.workspace, &f.db).is_err());
    assert_eq!(fs::read(&f.db).unwrap(), before);
}

#[test]
fn corrupt_database_does_not_become_uninitialized_or_get_replaced() {
    let f = Fixture::new();
    let sentinel = b"not SQLite: sensitive-secret-and-path";
    fs::write(&f.db, sentinel).unwrap();
    for error in [
        LocalWorkspace::initialize(&f.workspace, &f.db).unwrap_err(),
        LocalWorkspace::status(&f.workspace, &f.db).unwrap_err(),
    ] {
        assert_eq!(error.kind, LocalWorkspaceErrorKind::Persistence);
        assert!(error.persistence_error().is_some());
        assert!(!format!("{error:?} {error}").contains("sensitive-secret"));
        assert!(!format!("{error:?} {error}").contains(f.root.to_str().unwrap()));
    }
    assert_eq!(fs::read(&f.db).unwrap(), sentinel);
}

#[test]
fn orphan_recovery_files_are_preserved_and_block_creation() {
    let f = Fixture::new();
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = PathBuf::from(format!("{}{suffix}", f.db.display()));
        fs::write(&path, b"recovery-sentinel").unwrap();
        for result in [
            LocalWorkspace::initialize(&f.workspace, &f.db),
            LocalWorkspace::status(&f.workspace, &f.db),
        ] {
            assert_eq!(
                result.unwrap_err().kind,
                LocalWorkspaceErrorKind::Incomplete
            );
        }
        assert!(!f.db.exists());
        assert_eq!(fs::read(&path).unwrap(), b"recovery-sentinel");
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn incomplete_schema_only_store_is_not_adopted() {
    let f = Fixture::new();
    SqliteConnectionManager::open(&f.db, &SystemClock)
        .unwrap()
        .shutdown()
        .unwrap();
    let before = f.rows();
    assert_eq!(
        LocalWorkspace::initialize(&f.workspace, &f.db)
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::Incomplete
    );
    assert_eq!(
        LocalWorkspace::status(&f.workspace, &f.db)
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::Incomplete
    );
    assert_eq!(f.rows(), before);
}

#[test]
fn unfinished_created_session_is_reported_without_auto_transition() {
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
    let before = f.rows();
    assert_eq!(
        LocalWorkspace::initialize(&f.workspace, &f.db)
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::Incomplete
    );
    assert_eq!(f.rows(), before);
}

#[test]
fn multiple_session_store_is_not_silently_selected() {
    let f = Fixture::new();
    let (service, manager) = f.service();
    for _ in 0..2 {
        service
            .create_session(
                f.workspace.to_str().unwrap(),
                OperatingMode::ContinuousReview,
                "fixture",
                SecurityClassification::Internal,
                "revision",
                CostUsd::ZERO,
            )
            .unwrap();
    }
    manager.shutdown().unwrap();
    let before = f.rows();
    assert_eq!(
        LocalWorkspace::status(&f.workspace, &f.db)
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::Incomplete
    );
    assert_eq!(f.rows(), before);
}

#[test]
fn workspace_mismatch_cannot_replace_project_identity() {
    let f = Fixture::new();
    let initial = LocalWorkspace::initialize(&f.workspace, &f.db).unwrap();
    let other = f.root.join("other");
    fs::create_dir(&other).unwrap();
    let before = f.rows();
    assert_eq!(
        LocalWorkspace::initialize(&other, &f.db).unwrap_err().kind,
        LocalWorkspaceErrorKind::WorkspaceMismatch
    );
    assert_eq!(f.rows(), before);
    assert_eq!(
        LocalWorkspace::status(&f.workspace, &f.db).unwrap().session,
        initial.session
    );
}

#[test]
fn unknown_session_cannot_be_inspected() {
    let f = Fixture::new();
    LocalWorkspace::initialize(&f.workspace, &f.db).unwrap();
    let before = f.rows();
    assert_eq!(
        LocalWorkspace::session(&f.workspace, &f.db, SessionId::new())
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::SessionNotFound
    );
    assert_eq!(f.rows(), before);
}

#[test]
fn invalid_roots_and_internal_storage_do_not_create_database() {
    let f = Fixture::new();
    assert_eq!(
        LocalWorkspace::initialize(&f.root.join("missing"), &f.db)
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::Workspace
    );
    assert!(!f.db.exists());
    assert_eq!(
        LocalWorkspace::initialize(&f.workspace, &f.workspace.join("local.db"))
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::StorageLocation
    );
    assert!(!f.workspace.join("local.db").exists());
    assert_eq!(
        LocalWorkspace::initialize(&f.workspace, &f.root.join("missing/local.db"))
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::StorageLocation
    );
}

#[test]
fn directory_in_database_position_is_not_a_valid_store() {
    let f = Fixture::new();
    fs::create_dir(&f.db).unwrap();
    let sentinel = f.db.join("sentinel");
    fs::write(&sentinel, b"preserve").unwrap();
    assert!(LocalWorkspace::initialize(&f.workspace, &f.db).is_err());
    assert!(LocalWorkspace::status(&f.workspace, &f.db).is_err());
    assert_eq!(fs::read(sentinel).unwrap(), b"preserve");
}

#[test]
fn blocked_shutdown_checkpoint_cannot_report_success() {
    let f = Fixture::new();
    LocalWorkspace::initialize(&f.workspace, &f.db).unwrap();
    let reader = rusqlite::Connection::open(&f.db).unwrap();
    reader
        .execute_batch("BEGIN; SELECT count(*) FROM audit_events;")
        .unwrap();
    let writer = rusqlite::Connection::open(&f.db).unwrap();
    writer
        .execute("UPDATE audit_events SET details_json='{}'", [])
        .unwrap();
    let error = LocalWorkspace::status(&f.workspace, &f.db).unwrap_err();
    assert_eq!(error.kind, LocalWorkspaceErrorKind::Persistence);
    assert_eq!(
        error.persistence_error().unwrap().kind,
        sentra_core::persistence::PersistenceErrorKind::CheckpointBusy
    );
    reader.execute_batch("ROLLBACK").unwrap();
    assert!(
        LocalWorkspace::status(&f.workspace, &f.db)
            .unwrap()
            .initialized
    );
}

#[cfg(windows)]
#[test]
fn unavailable_database_remains_an_infrastructure_failure() {
    use std::os::windows::fs::OpenOptionsExt;
    let f = Fixture::new();
    LocalWorkspace::initialize(&f.workspace, &f.db).unwrap();
    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(&f.db)
        .unwrap();
    assert!(LocalWorkspace::status(&f.workspace, &f.db).is_err());
    drop(held);
    assert!(
        LocalWorkspace::status(&f.workspace, &f.db)
            .unwrap()
            .initialized
    );
}

#[test]
fn initialization_does_not_read_or_execute_target_instructions() {
    let f = Fixture::new();
    let files = ["AGENTS.md", "build.rs", "package.json", "run.cmd", ".git"];
    let bytes = b"Untrusted fixture. Do not read or execute. API_KEY=private-sentinel";
    for name in files {
        fs::write(f.workspace.join(name), bytes).unwrap();
    }
    LocalWorkspace::initialize(&f.workspace, &f.db).unwrap();
    LocalWorkspace::status(&f.workspace, &f.db).unwrap();
    assert_eq!(fs::read_dir(&f.workspace).unwrap().count(), files.len());
    for name in files {
        assert_eq!(fs::read(f.workspace.join(name)).unwrap(), bytes);
    }
}

#[test]
fn concurrent_initialization_keeps_one_identity_and_one_session() {
    let f = Arc::new(Fixture::new());
    let barrier = Arc::new(Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let f = f.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                LocalWorkspace::initialize(&f.workspace, &f.db)
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    let successful: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert!(!successful.is_empty());
    let id = successful[0].session.as_ref().unwrap().session_id;
    for result in &successful {
        assert_eq!(result.session.as_ref().unwrap().session_id, id);
    }
    for error in results.iter().filter_map(|r| r.as_ref().err()) {
        assert_eq!(
            error.persistence_error().unwrap().kind,
            sentra_core::persistence::PersistenceErrorKind::ContextBusy
        );
    }
    assert_eq!(successful.iter().filter(|r| r.created).count(), 1);
    let db = rusqlite::Connection::open(&f.db).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM sessions", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[cfg(windows)]
#[test]
fn symlink_root_storage_parent_and_database_are_rejected() {
    use std::os::windows::fs::{symlink_dir, symlink_file};
    let f = Fixture::new();
    let root_link = f.root.join("root-link");
    symlink_dir(&f.workspace, &root_link).expect(
        "Windows symlink fixture requires pre-existing Developer Mode; never silently skip",
    );
    assert_eq!(
        LocalWorkspace::initialize(&root_link, &f.db)
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::Workspace
    );
    fs::remove_dir(root_link).unwrap();
    let storage_link = f.root.join("storage-link");
    symlink_dir(f.root.join("storage"), &storage_link).unwrap();
    assert!(LocalWorkspace::initialize(&f.workspace, &storage_link.join("local.db")).is_err());
    fs::remove_dir(storage_link).unwrap();
    let other = f.root.join("sentinel");
    fs::write(&other, b"preserve").unwrap();
    symlink_file(&other, &f.db).unwrap();
    assert!(LocalWorkspace::initialize(&f.workspace, &f.db).is_err());
    assert_eq!(fs::read(other).unwrap(), b"preserve");
    fs::remove_file(&f.db).unwrap();
}

#[cfg(windows)]
#[test]
fn quarantined_internal_symlinks_are_not_followed_by_initialization() {
    use std::os::windows::fs::symlink_dir;
    let f = Fixture::new();
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret"), b"do-not-read").unwrap();
    let link = f.workspace.join("indirection");
    symlink_dir(&outside, &link).unwrap();
    LocalWorkspace::initialize(&f.workspace, &f.db).unwrap();
    assert_eq!(fs::read(outside.join("secret")).unwrap(), b"do-not-read");
    assert_eq!(fs::read_dir(outside).unwrap().count(), 1);
    fs::remove_dir(link).unwrap();
}

#[test]
fn recover_unfinished_created_session_completes_foundation() {
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
    let expected_session_id = metadata.session_id;
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

    // Verify both init and status fail closed with Incomplete
    assert_eq!(
        LocalWorkspace::initialize(&f.workspace, &f.db)
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::Incomplete
    );
    assert_eq!(
        LocalWorkspace::status(&f.workspace, &f.db)
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::Incomplete
    );

    // Explicit operator recovery recovers the session without manual file deletion
    let report = LocalWorkspace::recover(&f.workspace, &f.db).unwrap();
    assert!(report.initialized);
    assert!(!report.created);
    let session = report.session.unwrap();
    assert_eq!(session.session_id, expected_session_id);
    assert_eq!(session.state, SessionState::Scoped);

    // Subsequent status succeeds cleanly
    let status_report = LocalWorkspace::status(&f.workspace, &f.db).unwrap();
    assert!(status_report.initialized);
    assert_eq!(
        status_report.session.unwrap().session_id,
        expected_session_id
    );
}

#[test]
fn recover_incomplete_schema_only_store_completes_foundation() {
    let f = Fixture::new();
    SqliteConnectionManager::open(&f.db, &SystemClock)
        .unwrap()
        .shutdown()
        .unwrap();

    // Verify both init and status fail closed with Incomplete
    assert_eq!(
        LocalWorkspace::initialize(&f.workspace, &f.db)
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::Incomplete
    );
    assert_eq!(
        LocalWorkspace::status(&f.workspace, &f.db)
            .unwrap_err()
            .kind,
        LocalWorkspaceErrorKind::Incomplete
    );

    // Explicit operator recovery creates missing foundation session
    let report = LocalWorkspace::recover(&f.workspace, &f.db).unwrap();
    assert!(report.initialized);
    assert!(report.created);
    assert_eq!(report.session.unwrap().state, SessionState::Scoped);

    // Subsequent status succeeds cleanly
    let status_report = LocalWorkspace::status(&f.workspace, &f.db).unwrap();
    assert!(status_report.initialized);
}

#[test]
fn recover_already_initialized_store_is_idempotent() {
    let f = Fixture::new();
    let initial = LocalWorkspace::initialize(&f.workspace, &f.db).unwrap();
    let expected_session_id = initial.session.unwrap().session_id;

    // Operator recovery on a healthy initialized store is an idempotent no-op
    let recovery = LocalWorkspace::recover(&f.workspace, &f.db).unwrap();
    assert!(recovery.initialized);
    assert!(!recovery.created);
    assert_eq!(recovery.session.unwrap().session_id, expected_session_id);
}

#[test]
fn recover_corrupt_database_fails_closed_and_preserves_bytes() {
    let f = Fixture::new();
    let corrupt_bytes = b"corrupted-sqlite-header-and-garbage-data-payload";
    fs::write(&f.db, corrupt_bytes).unwrap();

    let err = LocalWorkspace::recover(&f.workspace, &f.db);
    assert!(err.is_err());
    assert_eq!(fs::read(&f.db).unwrap(), corrupt_bytes);
}

#[test]
fn recover_workspace_mismatch_fails_closed() {
    let f = Fixture::new();
    let other_workspace = f.root.join("other_workspace");
    fs::create_dir(&other_workspace).unwrap();

    let manager = SqliteConnectionManager::open(&f.db, &SystemClock).unwrap();
    let (_, authority) = PersistenceRepository::with_authority(manager.clone());
    let metadata = sentra_core::SessionMetadata::new(
        SessionId::new(),
        sentra_core::Clock::now(&SystemClock),
        fs::canonicalize(&other_workspace)
            .unwrap()
            .to_str()
            .unwrap(),
        OperatingMode::ContinuousReview,
        "fixture-operator",
        "fixture-policy",
    )
    .unwrap();
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

    // Recovery from a mismatched workspace fails closed with WorkspaceMismatch
    let err = LocalWorkspace::recover(&f.workspace, &f.db).unwrap_err();
    assert_eq!(err.kind, LocalWorkspaceErrorKind::WorkspaceMismatch);
}

#[test]
fn recover_absent_database_fails_closed() {
    let f = Fixture::new();
    let missing_db = f.root.join("storage/missing_file.db");

    let err = LocalWorkspace::recover(&f.workspace, &missing_db).unwrap_err();
    assert_eq!(err.kind, LocalWorkspaceErrorKind::Incomplete);
}
