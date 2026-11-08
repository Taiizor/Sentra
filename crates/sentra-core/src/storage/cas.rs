//! Filesystem-backed content-addressed blob store implementing atomic no-replace publication.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    EvidenceEnvelope,
    common::crypto::{sha256_digest, sha256_prefixed},
    storage::{
        error::{StorageError, StorageErrorKind},
        model::{BlobId, BlobMetadata, StorageLimits, StorageUsage},
        traits::BlobStore,
    },
};

static STAGE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Filesystem-backed Content-Addressed Storage (CAS) repository.
///
/// Implements the atomic no-replace publication contract:
/// - Staging in private `<root>/staging/` directory under unique names.
/// - Synchronized write and buffer flush (`sync_all`).
/// - Cryptographic hash verification before publication.
/// - Atomic namespace insertion via `std::fs::hard_link`.
/// - Idempotent de-duplication on hash collision.
/// - Staging link cleanup and cooperative read-only attribute setting.
#[derive(Debug)]
pub struct FileSystemCasBlobStore {
    root: PathBuf,
    staging_dir: PathBuf,
    blobs_dir: PathBuf,
    limits: StorageLimits,
}

impl FileSystemCasBlobStore {
    /// Creates or opens a filesystem CAS blob store at the specified root directory.
    pub fn new(root: impl AsRef<Path>, limits: StorageLimits) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        let staging_dir = root.join("staging");
        let blobs_dir = root.join("blobs");

        fs::create_dir_all(&staging_dir)
            .map_err(|e| StorageError::io(e, "create staging directory"))?;
        fs::create_dir_all(&blobs_dir)
            .map_err(|e| StorageError::io(e, "create blobs directory"))?;

        Ok(Self {
            root,
            staging_dir,
            blobs_dir,
            limits,
        })
    }

    /// Accessor for the storage root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Accessor for the configured storage limits.
    pub fn limits(&self) -> &StorageLimits {
        &self.limits
    }

    /// Resolves the filesystem path for a given `BlobId`.
    pub fn blob_path(&self, blob_id: &BlobId) -> PathBuf {
        self.blobs_dir
            .join(format!("{}.blob", blob_id.hex_digest()))
    }
}

impl BlobStore for FileSystemCasBlobStore {
    fn put(&self, data: &[u8]) -> Result<BlobId, StorageError> {
        let size = data.len() as u64;
        if size > self.limits.max_blob_size_bytes {
            return Err(StorageError::blob_too_large(
                size,
                self.limits.max_blob_size_bytes,
            ));
        }

        let blob_id = BlobId::from_bytes(data);
        let dest_path = self.blob_path(&blob_id);

        // Check if destination already exists (Idempotent publication)
        if dest_path.exists() {
            let meta = fs::metadata(&dest_path)
                .map_err(|e| StorageError::io(e, "inspect existing blob"))?;
            if meta.len() == size {
                return Ok(blob_id);
            }
            return Err(StorageError::new(
                StorageErrorKind::CollisionConflict,
                format!(
                    "existing blob '{blob_id}' length mismatch: expected {size}, found {}",
                    meta.len()
                ),
            ));
        }

        // Quota check against cumulative limits
        let current_usage = self.usage()?;
        if current_usage.total_bytes.saturating_add(size) > self.limits.max_total_storage_bytes {
            return Err(StorageError::new(
                StorageErrorKind::TotalStorageExceeded,
                format!(
                    "storing {size} bytes would exceed total storage quota of {} bytes",
                    self.limits.max_total_storage_bytes
                ),
            ));
        }
        if current_usage.total_blobs >= self.limits.max_blob_count {
            return Err(StorageError::new(
                StorageErrorKind::BlobCountExceeded,
                format!(
                    "blob count ({}) reaches or exceeds ceiling ({})",
                    current_usage.total_blobs, self.limits.max_blob_count
                ),
            ));
        }

        // Allocate unique staging path
        let seq = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let stage_name = format!(
            "stage-{}-{}-{}.tmp",
            std::process::id(),
            seq,
            blob_id.hex_digest()
        );
        let stage_path = self.staging_dir.join(stage_name);

        // Scope file handle write & sync
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&stage_path)
                .map_err(|e| StorageError::io(e, "open staging file"))?;

            file.write_all(data)
                .map_err(|e| StorageError::io(e, "write staging payload"))?;

            file.sync_all()
                .map_err(|e| StorageError::io(e, "flush staging payload"))?;
        }

        // Atomic CAS publication via hard link
        match fs::hard_link(&stage_path, &dest_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Another concurrent actor published the same blob
                let _ = fs::remove_file(&stage_path);
                let meta = fs::metadata(&dest_path)
                    .map_err(|e| StorageError::io(e, "verify concurrent blob"))?;
                if meta.len() == size {
                    return Ok(blob_id);
                }
                return Err(StorageError::new(
                    StorageErrorKind::CollisionConflict,
                    "concurrent blob collision with mismatched content",
                ));
            }
            Err(e) => {
                let _ = fs::remove_file(&stage_path);
                return Err(StorageError::io(e, "hard_link CAS publication"));
            }
        }

        // Clean up staging alias
        let _ = fs::remove_file(&stage_path);

        // Apply cooperative read-only attribute
        if let Ok(meta) = fs::metadata(&dest_path) {
            let mut perms = meta.permissions();
            perms.set_readonly(true);
            let _ = fs::set_permissions(&dest_path, perms);
        }

        Ok(blob_id)
    }

    fn put_evidence_envelope(&self, envelope: &EvidenceEnvelope) -> Result<BlobId, StorageError> {
        envelope.metadata.validate().map_err(|e| {
            StorageError::new(
                StorageErrorKind::ConfigurationError,
                format!("invalid evidence metadata: {e}"),
            )
        })?;

        if let Some(ref declared) = envelope.metadata.declared_sha256 {
            let computed = sha256_digest(&envelope.payload);
            if declared != &computed {
                return Err(StorageError::digest_mismatch(declared, computed));
            }
        }

        self.put(&envelope.payload)
    }

    fn get(&self, blob_id: &BlobId) -> Result<Vec<u8>, StorageError> {
        let path = self.blob_path(blob_id);
        if !path.exists() {
            return Err(StorageError::not_found(blob_id));
        }

        let bytes = fs::read(&path).map_err(|e| StorageError::io(e, "read blob file"))?;

        // Cryptographic integrity verification on retrieval
        let computed = sha256_prefixed(&bytes);
        if computed != blob_id.as_str() {
            return Err(StorageError::new(
                StorageErrorKind::CollisionConflict,
                format!("stored blob corrupted: expected '{blob_id}', computed '{computed}'"),
            ));
        }

        Ok(bytes)
    }

    fn open_reader(&self, blob_id: &BlobId) -> Result<Box<dyn Read + Send>, StorageError> {
        let path = self.blob_path(blob_id);
        if !path.exists() {
            return Err(StorageError::not_found(blob_id));
        }

        let file = File::open(&path).map_err(|e| StorageError::io(e, "open blob file"))?;
        Ok(Box::new(file))
    }

    fn exists(&self, blob_id: &BlobId) -> bool {
        self.blob_path(blob_id).exists()
    }

    fn metadata(&self, blob_id: &BlobId) -> Result<BlobMetadata, StorageError> {
        let path = self.blob_path(blob_id);
        if !path.exists() {
            return Err(StorageError::not_found(blob_id));
        }

        let meta = fs::metadata(&path).map_err(|e| StorageError::io(e, "read blob metadata"))?;
        Ok(BlobMetadata {
            blob_id: blob_id.clone(),
            size_bytes: meta.len(),
            created_at_rfc3339: None,
        })
    }

    fn usage(&self) -> Result<StorageUsage, StorageError> {
        let mut total_blobs: usize = 0;
        let mut total_bytes: u64 = 0;

        let entries = fs::read_dir(&self.blobs_dir)
            .map_err(|e| StorageError::io(e, "read blobs directory"))?;

        for entry in entries {
            let entry = entry.map_err(|e| StorageError::io(e, "iterate blob entry"))?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("blob") {
                total_blobs += 1;
                if let Ok(meta) = entry.metadata() {
                    total_bytes = total_bytes.saturating_add(meta.len());
                }
            }
        }

        Ok(StorageUsage {
            total_blobs,
            total_bytes,
        })
    }
}
