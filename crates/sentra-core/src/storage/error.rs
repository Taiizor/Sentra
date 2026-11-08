//! Typed errors for content-addressed storage and quota enforcement.

use std::{error::Error, fmt};

/// Specific categories of content-addressed storage failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageErrorKind {
    /// Staged payload exceeds the maximum permitted individual blob size.
    BlobTooLarge,
    /// Cumulative stored bytes exceeds configured storage quota.
    TotalStorageExceeded,
    /// Total number of stored blobs exceeds configured capacity.
    BlobCountExceeded,
    /// Computed cryptographic hash does not match expected or declared digest.
    DigestMismatch,
    /// Requested blob does not exist in the storage repository.
    NotFound,
    /// Existing destination blob has identical hash but mismatched length or corrupted content.
    CollisionConflict,
    /// Path containment violation or invalid staging directory.
    InvalidPath,
    /// Standard I/O error occurred during staging, flush, or publication.
    IoError,
    /// Invalid storage repository configuration.
    ConfigurationError,
}

/// Typed error returned by `BlobStore` operations.
#[derive(Debug)]
pub struct StorageError {
    kind: StorageErrorKind,
    message: String,
}

impl StorageError {
    /// Creates a new `StorageError`.
    pub fn new(kind: StorageErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Accessor for the error kind.
    pub fn kind(&self) -> StorageErrorKind {
        self.kind
    }

    /// Helper for `BlobTooLarge`.
    pub fn blob_too_large(size: u64, max: u64) -> Self {
        Self::new(
            StorageErrorKind::BlobTooLarge,
            format!("blob size {size} bytes exceeds maximum allowed {max} bytes"),
        )
    }

    /// Helper for `NotFound`.
    pub fn not_found(id: impl fmt::Display) -> Self {
        Self::new(
            StorageErrorKind::NotFound,
            format!("blob '{id}' not found in storage repository"),
        )
    }

    /// Helper for `DigestMismatch`.
    pub fn digest_mismatch(expected: impl fmt::Display, computed: impl fmt::Display) -> Self {
        Self::new(
            StorageErrorKind::DigestMismatch,
            format!("declared digest '{expected}' does not match computed digest '{computed}'"),
        )
    }

    /// Helper for wrapping `std::io::Error`.
    pub fn io(err: std::io::Error, operation: impl fmt::Display) -> Self {
        Self::new(
            StorageErrorKind::IoError,
            format!("I/O failure during {operation}: {err}"),
        )
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl Error for StorageError {}
