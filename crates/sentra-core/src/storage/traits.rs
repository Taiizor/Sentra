//! Traits defining the content-addressed blob storage interface.

use std::{fmt::Debug, io::Read};

use crate::{
    EvidenceEnvelope,
    storage::{
        error::StorageError,
        model::{BlobId, BlobMetadata, StorageUsage},
    },
};

/// Content-addressed immutable blob storage interface.
///
/// Implementations must uphold:
/// 1. Atomic no-replace CAS publication (`std::fs::hard_link`).
/// 2. Cryptographic SHA-256 content verification before publication.
/// 3. Idempotent publication of identical content.
/// 4. Strict resource quota enforcement (per-blob, total bytes, blob count).
pub trait BlobStore: Send + Sync + Debug {
    /// Stores raw byte payload into the CAS repository.
    ///
    /// Computes the SHA-256 digest, executes staging, atomic CAS publication,
    /// sets read-only attributes, and returns the canonical `BlobId`.
    fn put(&self, data: &[u8]) -> Result<BlobId, StorageError>;

    /// Stores an evidence envelope into the CAS repository.
    ///
    /// Validates envelope metadata, checks declared SHA-256 digest (if present),
    /// and persists payload bytes.
    fn put_evidence_envelope(&self, envelope: &EvidenceEnvelope) -> Result<BlobId, StorageError>;

    /// Retrieves the raw byte payload of a stored blob.
    fn get(&self, blob_id: &BlobId) -> Result<Vec<u8>, StorageError>;

    /// Opens a streaming reader for a stored blob.
    fn open_reader(&self, blob_id: &BlobId) -> Result<Box<dyn Read + Send>, StorageError>;

    /// Returns true if a blob exists in the store.
    fn exists(&self, blob_id: &BlobId) -> bool;

    /// Retrieves metadata for a stored blob.
    fn metadata(&self, blob_id: &BlobId) -> Result<BlobMetadata, StorageError>;

    /// Returns cumulative storage metrics.
    fn usage(&self) -> Result<StorageUsage, StorageError>;
}
