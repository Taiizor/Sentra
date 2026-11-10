//! Tests for Increment 2.1: Input Manifests, Source Snapshots, and SHA-256 Content Hashing (REQ-F01/F02).

use std::{
    fs,
    path::{Path, PathBuf},
};

use sentra_core::{
    SecurityClassification as Class, SessionId,
    common::crypto::{sha256_bytes, sha256_digest, sha256_prefixed},
    manifest::{OperationManifest, SourceFileRole, SourceSnapshot, SourceSnapshotEntry},
    workspace::WorkspaceBoundary,
};

#[cfg(any(windows, unix))]
use std::sync::Arc;

#[cfg(any(windows, unix))]
use sentra_core::{
    CostUsd, MockClock, OperatingMode, OperationAction, PolicyEngine, TaskId, TimestampUtc,
    manifest::{ManifestErrorKind, SnapshotLimits, capture_source_snapshot},
    persistence::{ManifestKind, PersistenceRepository, SqliteConnectionManager},
    service::{CoreService, CoreServiceConfig},
};

pub struct WorkspaceFixture {
    pub root: PathBuf,
    pub db_dir: PathBuf,
}

impl WorkspaceFixture {
    pub fn new() -> Self {
        let temp = fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
        let base = temp.join(format!(
            "sentra-manifest-test-{}-{}",
            std::process::id(),
            SessionId::new()
        ));
        let root = base.join("workspace");
        let db_dir = base.join("db");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&db_dir).unwrap();

        // Create standard test files
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::create_dir_all(root.join("tests")).unwrap();

        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        fs::write(root.join("Cargo.lock"), "# Lock file\n").unwrap();
        fs::write(
            root.join("src/lib.rs"),
            "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
        )
        .unwrap();
        fs::write(
            root.join("src/main.rs"),
            "fn main() { println!(\"Hello\"); }\n",
        )
        .unwrap();
        fs::write(
            root.join("docs/README.md"),
            "# Demo Project\nDocumentation here.\n",
        )
        .unwrap();
        fs::write(root.join("config.json"), "{\"enabled\": true}\n").unwrap();

        Self { root, db_dir }
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    #[cfg(any(windows, unix))]
    pub fn db_path(&self) -> PathBuf {
        self.db_dir.join("sentra-manifest-test.db")
    }
}

impl Drop for WorkspaceFixture {
    fn drop(&mut self) {
        if let Some(parent) = self.root.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}

impl Default for WorkspaceFixture {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(windows, unix))]
fn create_test_service(
    ws: &WorkspaceFixture,
) -> (
    CoreService,
    SessionId,
    PersistenceRepository,
    Arc<MockClock>,
) {
    let clock = Arc::new(MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000)));
    let db_path = ws.db_path();
    let manager = SqliteConnectionManager::open(&db_path, &*clock).unwrap();
    let (repo, authority) = PersistenceRepository::with_authority(manager);
    let policy_engine = PolicyEngine::new();
    let config = CoreServiceConfig::default();
    let backend = Arc::new(sentra_core::SyntheticFixtureBackend::new());

    let service = CoreService::new(
        config,
        repo.clone(),
        authority,
        policy_engine,
        backend,
        clock.clone(),
    );

    let session_id = service
        .create_session(
            ws.path().to_str().unwrap(),
            OperatingMode::ContinuousReview,
            "operator-test",
            Class::Internal,
            "git:head-rev-1",
            CostUsd::from_micro_usd(1_000_000),
        )
        .unwrap();

    (service, session_id, repo, clock)
}

// =========================================================================
// Platform-Independent Crypto and Data Model Tests
// =========================================================================

#[test]
fn test_sha256_nist_vectors() {
    // NIST Test Vector 1: Empty string
    assert_eq!(
        sha256_digest(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_prefixed(b""),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    // NIST Test Vector 2: "abc"
    assert_eq!(
        sha256_digest(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // NIST Test Vector 3: multi-block message
    let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(
        sha256_digest(input),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );

    // Verify raw bytes
    let raw = sha256_bytes(b"abc");
    assert_eq!(raw[0], 0xba);
    assert_eq!(raw[31], 0xad);
}

#[test]
fn test_source_snapshot_canonical_json_roundtrip() {
    let snap = SourceSnapshot {
        version: SourceSnapshot::SCHEMA_VERSION,
        session_id: "00000001-0000-0000-0000-000000000001".to_string(),
        root_label: "test-workspace".to_string(),
        entries: vec![
            SourceSnapshotEntry {
                path: "Cargo.toml".to_string(),
                size_bytes: 42,
                content_sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    .to_string(),
                role: SourceFileRole::CargoManifest,
            },
            SourceSnapshotEntry {
                path: "src/lib.rs".to_string(),
                size_bytes: 120,
                content_sha256: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
                    .to_string(),
                role: SourceFileRole::RustSource,
            },
        ],
        total_files: 2,
        total_bytes: 162,
        aggregate_digest: "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            .to_string(),
        created_at: "2026-11-08T18:00:00Z".to_string(),
    };

    let json = snap.to_canonical_json().unwrap();
    let roundtrip = SourceSnapshot::from_canonical_json(&json).unwrap();
    assert_eq!(roundtrip.version, snap.version);
    assert_eq!(roundtrip.session_id, snap.session_id);
    assert_eq!(roundtrip.entries, snap.entries);
    assert_eq!(roundtrip.aggregate_digest, snap.aggregate_digest);
}

#[test]
fn test_operation_manifest_canonical_json_roundtrip() {
    let manifest = OperationManifest {
        version: OperationManifest::SCHEMA_VERSION,
        session_id: "00000001-0000-0000-0000-000000000001".to_string(),
        task_id: "00000002-0000-0000-0000-000000000002".to_string(),
        action_name: "DISCOVER_METADATA".to_string(),
        action_digest: "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            .to_string(),
        source_snapshot_digest: Some(
            "sha256:248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1".to_string(),
        ),
        classification: "INTERNAL".to_string(),
        created_at: "2026-11-08T18:00:00Z".to_string(),
    };

    let json = manifest.to_canonical_json().unwrap();
    let roundtrip = OperationManifest::from_canonical_json(&json).unwrap();
    assert_eq!(roundtrip.version, manifest.version);
    assert_eq!(roundtrip.task_id, manifest.task_id);
    assert_eq!(roundtrip.action_name, manifest.action_name);
    assert_eq!(
        roundtrip.source_snapshot_digest,
        manifest.source_snapshot_digest
    );
    assert_eq!(roundtrip.classification, manifest.classification);
}

#[cfg(unix)]
#[test]
fn test_workspace_boundary_succeeds_on_unix_platform() {
    let ws = WorkspaceFixture::new();
    let session_id = SessionId::for_test_sequence(1);
    let boundary = WorkspaceBoundary::establish(ws.path(), session_id, Class::Internal).unwrap();
    assert_eq!(boundary.root().session_id(), session_id);
}

#[cfg(not(any(windows, unix)))]
#[test]
fn test_workspace_boundary_fails_closed_on_unsupported_platform() {
    let ws = WorkspaceFixture::new();
    let session_id = SessionId::for_test_sequence(1);
    let boundary_err =
        WorkspaceBoundary::establish(ws.path(), session_id, Class::Internal).unwrap_err();
    assert_eq!(
        boundary_err.kind,
        sentra_core::workspace::WorkspaceErrorKind::UnsupportedPlatform
    );
}

// =========================================================================
// Workspace Integration and Persistence Tests
// =========================================================================

#[cfg(any(windows, unix))]
#[test]
fn test_capture_source_snapshot_determinism() {
    let ws = WorkspaceFixture::new();
    let session_id = SessionId::for_test_sequence(1);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
    let boundary = WorkspaceBoundary::establish(ws.path(), session_id, Class::Internal).unwrap();
    let limits = SnapshotLimits::default();

    // Capture snapshot twice on identical tree
    let snap1 = capture_source_snapshot(&boundary, &limits, &clock).unwrap();
    let snap2 = capture_source_snapshot(&boundary, &limits, &clock).unwrap();

    assert_eq!(snap1.total_files, 6);
    assert_eq!(snap1.total_files, snap2.total_files);
    assert_eq!(snap1.total_bytes, snap2.total_bytes);
    assert_eq!(snap1.aggregate_digest, snap2.aggregate_digest);
    assert_eq!(snap1.entries, snap2.entries);
    assert!(snap1.aggregate_digest.starts_with("sha256:"));
}

#[cfg(any(windows, unix))]
#[test]
fn test_source_snapshot_sensitivity_to_content_change() {
    let ws = WorkspaceFixture::new();
    let session_id = SessionId::for_test_sequence(2);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
    let boundary = WorkspaceBoundary::establish(ws.path(), session_id, Class::Internal).unwrap();
    let limits = SnapshotLimits::default();

    let snap_before = capture_source_snapshot(&boundary, &limits, &clock).unwrap();

    // Mutate exactly one byte in src/lib.rs
    fs::write(
        ws.path().join("src/lib.rs"),
        "pub fn add(a: i32, b: i32) -> i32 { a - b }\n",
    )
    .unwrap();

    let snap_after = capture_source_snapshot(&boundary, &limits, &clock).unwrap();

    // Total files unchanged, but aggregate digest MUST change
    assert_eq!(snap_before.total_files, snap_after.total_files);
    assert_ne!(snap_before.aggregate_digest, snap_after.aggregate_digest);

    // Specifically verify lib.rs hash changed, while main.rs remained identical
    let lib_before = snap_before
        .entries
        .iter()
        .find(|e| e.path == "src/lib.rs")
        .unwrap();
    let lib_after = snap_after
        .entries
        .iter()
        .find(|e| e.path == "src/lib.rs")
        .unwrap();
    assert_ne!(lib_before.content_sha256, lib_after.content_sha256);

    let main_before = snap_before
        .entries
        .iter()
        .find(|e| e.path == "src/main.rs")
        .unwrap();
    let main_after = snap_after
        .entries
        .iter()
        .find(|e| e.path == "src/main.rs")
        .unwrap();
    assert_eq!(main_before.content_sha256, main_after.content_sha256);
}

#[cfg(any(windows, unix))]
#[test]
fn test_source_snapshot_sensitivity_to_file_addition_and_deletion() {
    let ws = WorkspaceFixture::new();
    let session_id = SessionId::for_test_sequence(3);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
    let boundary = WorkspaceBoundary::establish(ws.path(), session_id, Class::Internal).unwrap();
    let limits = SnapshotLimits::default();

    let snap_initial = capture_source_snapshot(&boundary, &limits, &clock).unwrap();

    // Add a file
    fs::write(ws.path().join("src/extra.rs"), "// extra code\n").unwrap();
    let snap_added = capture_source_snapshot(&boundary, &limits, &clock).unwrap();

    assert_eq!(snap_added.total_files, snap_initial.total_files + 1);
    assert_ne!(snap_initial.aggregate_digest, snap_added.aggregate_digest);

    // Delete the file
    fs::remove_file(ws.path().join("src/extra.rs")).unwrap();
    let snap_restored = capture_source_snapshot(&boundary, &limits, &clock).unwrap();

    assert_eq!(snap_restored.total_files, snap_initial.total_files);
    assert_eq!(
        snap_restored.aggregate_digest,
        snap_initial.aggregate_digest
    );
}

#[cfg(any(windows, unix))]
#[test]
fn test_source_snapshot_role_detection() {
    let ws = WorkspaceFixture::new();
    let session_id = SessionId::for_test_sequence(4);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
    let boundary = WorkspaceBoundary::establish(ws.path(), session_id, Class::Internal).unwrap();

    let snapshot = capture_source_snapshot(&boundary, &SnapshotLimits::default(), &clock).unwrap();

    let find_role = |path: &str| -> SourceFileRole {
        snapshot
            .entries
            .iter()
            .find(|e| e.path == path)
            .unwrap()
            .role
    };

    assert_eq!(find_role("Cargo.toml"), SourceFileRole::CargoManifest);
    assert_eq!(find_role("Cargo.lock"), SourceFileRole::CargoLock);
    assert_eq!(find_role("src/lib.rs"), SourceFileRole::RustSource);
    assert_eq!(find_role("src/main.rs"), SourceFileRole::RustSource);
    assert_eq!(find_role("docs/README.md"), SourceFileRole::Documentation);
    assert_eq!(find_role("config.json"), SourceFileRole::Configuration);
}

#[cfg(any(windows, unix))]
#[test]
fn test_path_normalization_uses_forward_slashes_consistently() {
    let ws = WorkspaceFixture::new();
    let session_id = SessionId::for_test_sequence(5);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
    let boundary = WorkspaceBoundary::establish(ws.path(), session_id, Class::Internal).unwrap();

    let snapshot = capture_source_snapshot(&boundary, &SnapshotLimits::default(), &clock).unwrap();

    for entry in &snapshot.entries {
        assert!(
            !entry.path.contains('\\'),
            "Path contains backslash instead of canonical forward slash: {}",
            entry.path
        );
    }
}

#[cfg(any(windows, unix))]
#[test]
fn test_git_directory_excluded_from_snapshot() {
    let ws = WorkspaceFixture::new();
    let git_dir = ws.path().join(".git");
    fs::create_dir_all(&git_dir).unwrap();
    fs::write(
        git_dir.join("config"),
        "[core]\nrepositoryformatversion = 0\n",
    )
    .unwrap();
    fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();

    let session_id = SessionId::for_test_sequence(6);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
    let boundary = WorkspaceBoundary::establish(ws.path(), session_id, Class::Internal).unwrap();

    let snapshot = capture_source_snapshot(&boundary, &SnapshotLimits::default(), &clock).unwrap();

    // Verify .git entries are completely excluded
    for entry in &snapshot.entries {
        assert!(
            !entry.path.starts_with(".git"),
            "Snapshot improperly included internal git file: {}",
            entry.path
        );
    }
}

#[cfg(any(windows, unix))]
#[test]
fn test_source_snapshot_file_size_limit_fails_closed() {
    let ws = WorkspaceFixture::new();
    // Write an 800-byte file
    fs::write(ws.path().join("large_file.txt"), vec![b'X'; 800]).unwrap();

    let session_id = SessionId::for_test_sequence(7);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
    let boundary = WorkspaceBoundary::establish(ws.path(), session_id, Class::Internal).unwrap();

    // Set max file size ceiling to 500 bytes
    let limits = SnapshotLimits {
        max_file_size_bytes: 500,
        ..Default::default()
    };

    let err = capture_source_snapshot(&boundary, &limits, &clock).unwrap_err();
    assert_eq!(err.kind(), ManifestErrorKind::FileTooLarge);
}

#[cfg(any(windows, unix))]
#[test]
fn test_source_snapshot_total_bytes_limit_fails_closed() {
    let ws = WorkspaceFixture::new();
    let session_id = SessionId::for_test_sequence(8);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
    let boundary = WorkspaceBoundary::establish(ws.path(), session_id, Class::Internal).unwrap();

    // Set max total bytes ceiling to 50 bytes (workspace files exceed 50 bytes)
    let limits = SnapshotLimits {
        max_total_bytes: 50,
        ..Default::default()
    };

    let err = capture_source_snapshot(&boundary, &limits, &clock).unwrap_err();
    assert_eq!(err.kind(), ManifestErrorKind::TotalBytesExceeded);
}

#[cfg(any(windows, unix))]
#[test]
fn test_source_snapshot_file_count_limit_fails_closed() {
    let ws = WorkspaceFixture::new();
    let session_id = SessionId::for_test_sequence(9);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
    let boundary = WorkspaceBoundary::establish(ws.path(), session_id, Class::Internal).unwrap();

    // Set max files ceiling to 2 (workspace has 6 files)
    let limits = SnapshotLimits {
        max_files: 2,
        ..Default::default()
    };

    let err = capture_source_snapshot(&boundary, &limits, &clock).unwrap_err();
    assert_eq!(err.kind(), ManifestErrorKind::FileCountExceeded);
}

#[cfg(any(windows, unix))]
#[test]
fn test_core_service_capture_and_persist_source_snapshot() {
    let ws = WorkspaceFixture::new();
    let (service, session_id, repo, _clock) = create_test_service(&ws);

    let (record, snapshot) = service.capture_source_snapshot(session_id, None).unwrap();

    assert_eq!(record.session_id, session_id);
    assert_eq!(record.manifest_kind, ManifestKind::SourceSnapshot);
    assert_eq!(record.content_digest, snapshot.aggregate_digest);
    assert!(record.content_digest.starts_with("sha256:"));

    // Verify retrieval from SQLite database
    let fetched = repo.get_manifest(record.manifest_id).unwrap().unwrap();
    assert_eq!(fetched.manifest_id, record.manifest_id);
    assert_eq!(fetched.content_digest, snapshot.aggregate_digest);

    // Verify round-trip deserialization from canonical JSON
    let roundtripped = SourceSnapshot::from_canonical_json(&fetched.canonical_json).unwrap();
    assert_eq!(roundtripped.aggregate_digest, snapshot.aggregate_digest);
    assert_eq!(roundtripped.total_files, snapshot.total_files);
    assert_eq!(roundtripped.entries, snapshot.entries);
}

#[cfg(any(windows, unix))]
#[test]
fn test_operation_manifest_creation_and_persistence() {
    let ws = WorkspaceFixture::new();
    let (service, session_id, repo, _clock) = create_test_service(&ws);

    let task_id = TaskId::for_test_sequence(101);
    let action = OperationAction::DiscoverMetadata {
        relative_path: "src".to_string(),
    };
    let source_digest = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    let op_record = service
        .create_operation_manifest(session_id, task_id, &action, Some(source_digest))
        .unwrap();

    assert_eq!(op_record.session_id, session_id);
    assert_eq!(op_record.manifest_kind, ManifestKind::Operation);
    assert!(op_record.content_digest.starts_with("sha256:"));

    let fetched = repo.get_manifest(op_record.manifest_id).unwrap().unwrap();
    let op_manifest = OperationManifest::from_canonical_json(&fetched.canonical_json).unwrap();

    assert_eq!(op_manifest.task_id, task_id.to_string());
    assert_eq!(op_manifest.action_name, "DISCOVER_METADATA");
    assert_eq!(
        op_manifest.source_snapshot_digest,
        Some(source_digest.to_string())
    );
}
