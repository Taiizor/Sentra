//! Integration tests for Increment 2.2: Bounded Evidence Storage, BlobStore, and Content Addressing (S-09).

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    thread,
};

use sentra_core::{
    BlobId, BlobStore, CoreService, CoreServiceConfig, EvidenceEnvelope, EvidenceId,
    EvidenceMetadata, FileSystemCasBlobStore, MockClock, PolicyEngine, SecurityClassification,
    SessionId, StorageErrorKind, StorageLimits, TaskId, TimestampUtc,
    persistence::{PersistenceRepository, SqliteConnectionManager},
};

struct StorageTestFixture {
    root: PathBuf,
}

impl StorageTestFixture {
    fn new() -> Self {
        let temp = fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
        let base = temp.join(format!(
            "sentra-storage-test-{}-{}",
            std::process::id(),
            SessionId::new()
        ));
        fs::create_dir_all(&base).unwrap();
        Self { root: base }
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn create_store(&self, limits: StorageLimits) -> FileSystemCasBlobStore {
        FileSystemCasBlobStore::new(self.path().join("cas_root"), limits).unwrap()
    }
}

#[allow(clippy::permissions_set_readonly_false)]
fn clear_readonly_recursive(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                clear_readonly_recursive(&path);
            } else if let Ok(meta) = entry.metadata() {
                let mut perms = meta.permissions();
                if perms.readonly() {
                    perms.set_readonly(false);
                    let _ = fs::set_permissions(&path, perms);
                }
            }
        }
    }
}

impl Drop for StorageTestFixture {
    fn drop(&mut self) {
        clear_readonly_recursive(&self.root);
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn sample_envelope(payload: &[u8], declared_sha256: Option<&str>) -> EvidenceEnvelope {
    let metadata = EvidenceMetadata {
        evidence_id: EvidenceId::for_test_sequence(1),
        session_id: SessionId::for_test_sequence(10),
        task_id: TaskId::for_test_sequence(20),
        producer_role: "security-scanner".to_string(),
        media_type: "application/json".to_string(),
        payload_length_bytes: payload.len() as u64,
        declared_sha256: declared_sha256.map(|s| s.to_string()),
        classification: SecurityClassification::Internal,
        created_at: TimestampUtc::from_epoch_secs(1_700_000_000),
    };
    EvidenceEnvelope::new(metadata, payload.to_vec())
}

#[test]
fn test_blob_id_derivation_and_formatting() {
    let data = b"hello sentra content addressed storage";
    let blob_id = BlobId::from_bytes(data);

    assert!(blob_id.as_str().starts_with("sha256:"));
    assert_eq!(blob_id.as_str().len(), "sha256:".len() + 64);
    assert_eq!(blob_id.hex_digest().len(), 64);

    // Verify FromStr roundtrip
    let parsed = BlobId::from_str(blob_id.as_str()).unwrap();
    assert_eq!(parsed, blob_id);

    // Verify Display
    assert_eq!(format!("{blob_id}"), blob_id.as_str());

    // Verify from_hex_digest
    let from_hex = BlobId::from_hex_digest(blob_id.hex_digest()).unwrap();
    assert_eq!(from_hex, blob_id);

    // Rejection of invalid identifiers
    assert!(BlobId::from_str("md5:12345").is_err());
    assert!(BlobId::from_str("sha256:short").is_err());
    assert!(
        BlobId::from_hex_digest(
            "UPPERCASE_NOT_ALLOWED_0000000000000000000000000000000000000000000000"
        )
        .is_err()
    );
}

#[test]
fn test_cas_put_get_roundtrip() {
    let fixture = StorageTestFixture::new();
    let store = fixture.create_store(StorageLimits::default());

    let payload = b"critical vulnerability findings report content";
    let blob_id = store.put(payload).unwrap();

    assert!(store.exists(&blob_id));

    let retrieved = store.get(&blob_id).unwrap();
    assert_eq!(retrieved, payload);

    let meta = store.metadata(&blob_id).unwrap();
    assert_eq!(meta.blob_id, blob_id);
    assert_eq!(meta.size_bytes, payload.len() as u64);

    let usage = store.usage().unwrap();
    assert_eq!(usage.total_blobs, 1);
    assert_eq!(usage.total_bytes, payload.len() as u64);
}

#[test]
fn test_cas_idempotent_deduplication() {
    let fixture = StorageTestFixture::new();
    let store = fixture.create_store(StorageLimits::default());

    let payload = b"identical repeated log trace";
    let blob_id_1 = store.put(payload).unwrap();
    let blob_id_2 = store.put(payload).unwrap();

    assert_eq!(blob_id_1, blob_id_2);

    let usage = store.usage().unwrap();
    assert_eq!(usage.total_blobs, 1);
    assert_eq!(usage.total_bytes, payload.len() as u64);
}

#[test]
fn test_cas_streaming_reader() {
    let fixture = StorageTestFixture::new();
    let store = fixture.create_store(StorageLimits::default());

    let payload = b"streaming read verification test payload content";
    let blob_id = store.put(payload).unwrap();

    let mut reader = store.open_reader(&blob_id).unwrap();
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();

    assert_eq!(buffer, payload);
}

#[test]
fn test_cas_blob_too_large_fails_closed() {
    let fixture = StorageTestFixture::new();
    let limits = StorageLimits {
        max_blob_size_bytes: 50,
        ..Default::default()
    };
    let store = fixture.create_store(limits);

    let oversized = vec![0x42; 60];
    let err = store.put(&oversized).unwrap_err();
    assert_eq!(err.kind(), StorageErrorKind::BlobTooLarge);

    // Verify staging directory is clean
    let staging_entries = fs::read_dir(store.root().join("staging")).unwrap().count();
    assert_eq!(staging_entries, 0);
}

#[test]
fn test_cas_total_storage_quota_fails_closed() {
    let fixture = StorageTestFixture::new();
    let limits = StorageLimits {
        max_total_storage_bytes: 120,
        ..Default::default()
    };
    let store = fixture.create_store(limits);

    // First blob: 80 bytes (succeeds)
    let blob1 = vec![0xaa; 80];
    let id1 = store.put(&blob1).unwrap();
    assert!(store.exists(&id1));

    // Second blob: 50 bytes (80 + 50 = 130 > 120, fails)
    let blob2 = vec![0xbb; 50];
    let err = store.put(&blob2).unwrap_err();
    assert_eq!(err.kind(), StorageErrorKind::TotalStorageExceeded);

    let usage = store.usage().unwrap();
    assert_eq!(usage.total_blobs, 1);
    assert_eq!(usage.total_bytes, 80);
}

#[test]
fn test_cas_blob_count_quota_fails_closed() {
    let fixture = StorageTestFixture::new();
    let limits = StorageLimits {
        max_blob_count: 2,
        ..Default::default()
    };
    let store = fixture.create_store(limits);

    let id1 = store.put(b"item 1").unwrap();
    let id2 = store.put(b"item 2").unwrap();
    assert!(store.exists(&id1));
    assert!(store.exists(&id2));

    let err = store.put(b"item 3").unwrap_err();
    assert_eq!(err.kind(), StorageErrorKind::BlobCountExceeded);
}

#[test]
fn test_cas_not_found_fails_closed() {
    let fixture = StorageTestFixture::new();
    let store = fixture.create_store(StorageLimits::default());

    let non_existent =
        BlobId::from_str("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();

    assert!(!store.exists(&non_existent));
    assert_eq!(
        store.get(&non_existent).unwrap_err().kind(),
        StorageErrorKind::NotFound
    );
    match store.open_reader(&non_existent) {
        Err(err) => assert_eq!(err.kind(), StorageErrorKind::NotFound),
        Ok(_) => panic!("expected NotFound error"),
    }
}

#[test]
fn test_cas_put_evidence_envelope_success() {
    let fixture = StorageTestFixture::new();
    let store = fixture.create_store(StorageLimits::default());

    let payload = b"{\"finding\": \"SQL_INJECTION\", \"line\": 42}";
    // SHA-256 for this exact payload
    let digest = sentra_core::common::crypto::sha256_digest(payload);
    let envelope = sample_envelope(payload, Some(&digest));

    let blob_id = store.put_evidence_envelope(&envelope).unwrap();
    assert_eq!(blob_id.hex_digest(), digest);

    let retrieved = store.get(&blob_id).unwrap();
    assert_eq!(retrieved, payload);
}

#[test]
fn test_cas_put_evidence_envelope_digest_mismatch_fails_closed() {
    let fixture = StorageTestFixture::new();
    let store = fixture.create_store(StorageLimits::default());

    let payload = b"{\"finding\": \"XSS\", \"line\": 10}";
    // Incorrect declared hash
    let forged_digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let envelope = sample_envelope(payload, Some(forged_digest));

    let err = store.put_evidence_envelope(&envelope).unwrap_err();
    assert_eq!(err.kind(), StorageErrorKind::DigestMismatch);
}

#[test]
fn test_cas_put_evidence_envelope_invalid_metadata_fails_closed() {
    let fixture = StorageTestFixture::new();
    let store = fixture.create_store(StorageLimits::default());

    let mut envelope = sample_envelope(b"payload", None);
    envelope.metadata.media_type = "invalid-no-slash".to_string();

    let err = store.put_evidence_envelope(&envelope).unwrap_err();
    assert_eq!(err.kind(), StorageErrorKind::ConfigurationError);
}

#[test]
fn test_cas_concurrent_threads_atomic_dedup() {
    let fixture = StorageTestFixture::new();
    let store = Arc::new(fixture.create_store(StorageLimits::default()));

    let payload = b"concurrent multi-threaded race payload content to deduplicate";
    let expected_id = BlobId::from_bytes(payload);

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let s = Arc::clone(&store);
            thread::spawn(move || s.put(payload).unwrap())
        })
        .collect();

    for handle in handles {
        let result_id = handle.join().unwrap();
        assert_eq!(result_id, expected_id);
    }

    // Verify only 1 blob was published
    let usage = store.usage().unwrap();
    assert_eq!(usage.total_blobs, 1);
    assert_eq!(usage.total_bytes, payload.len() as u64);

    // Verify staging directory is completely empty
    let staging_count = fs::read_dir(store.root().join("staging")).unwrap().count();
    assert_eq!(staging_count, 0);
}

#[test]
fn test_core_service_evidence_storage_integration() {
    let fixture = StorageTestFixture::new();
    let store = Arc::new(fixture.create_store(StorageLimits::default()));

    let clock = Arc::new(MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000)));
    let db_path = fixture.path().join("sentra-storage-test.db");
    let manager = SqliteConnectionManager::open(&db_path, &*clock).unwrap();
    let (repo, authority) = PersistenceRepository::with_authority(manager);
    let policy_engine = PolicyEngine::new();
    let config = CoreServiceConfig::default();
    let backend = Arc::new(sentra_core::SyntheticFixtureBackend::new());

    let service = CoreService::new(config, repo, authority, policy_engine, backend, clock)
        .with_blob_store(store);

    let payload = b"verified security finding report from core service";
    let envelope = sample_envelope(payload, None);

    let blob_id = service.store_evidence(&envelope).unwrap();
    assert!(blob_id.as_str().starts_with("sha256:"));

    let retrieved = service.get_evidence(&blob_id).unwrap();
    assert_eq!(retrieved, payload);
}

#[test]
fn test_core_service_evidence_storage_unconfigured_fails_closed() {
    let fixture = StorageTestFixture::new();
    let clock = Arc::new(MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000)));
    let db_path = fixture.path().join("sentra-unconfigured-test.db");
    let manager = SqliteConnectionManager::open(&db_path, &*clock).unwrap();
    let (repo, authority) = PersistenceRepository::with_authority(manager);
    let policy_engine = PolicyEngine::new();
    let config = CoreServiceConfig::default();
    let backend = Arc::new(sentra_core::SyntheticFixtureBackend::new());

    let service = CoreService::new(config, repo, authority, policy_engine, backend, clock);

    let envelope = sample_envelope(b"data", None);
    let err = service.store_evidence(&envelope).unwrap_err();
    assert_eq!(
        err.kind,
        sentra_core::service::ServiceErrorKind::InvalidState
    );
}
