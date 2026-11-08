//! Data models, identifiers, quotas, and metrics for content-addressed storage.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{
    MAX_EVIDENCE_SIZE_BYTES,
    common::crypto::sha256_prefixed,
    storage::error::{StorageError, StorageErrorKind},
};

/// Content-addressed cryptographic identifier for an immutable blob.
///
/// Formatted strictly as `sha256:<64-char-hex>`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlobId(String);

impl BlobId {
    /// Computes the content `BlobId` from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Self {
        Self(sha256_prefixed(data))
    }

    /// Creates a `BlobId` from a verified 64-character lowercase hex digest.
    pub fn from_hex_digest(hex: &str) -> Result<Self, StorageError> {
        let hex = hex.trim();
        if hex.len() != 64
            || !hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(StorageError::new(
                StorageErrorKind::ConfigurationError,
                format!("invalid SHA-256 hex digest '{hex}'"),
            ));
        }
        Ok(Self(format!("sha256:{hex}")))
    }

    /// Accessor for the full string representation (including `sha256:` prefix).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the 64-character lowercase hex digest portion (excluding prefix).
    pub fn hex_digest(&self) -> &str {
        &self.0["sha256:".len()..]
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobId({})", self.0)
    }
}

impl FromStr for BlobId {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if !s.starts_with("sha256:") {
            return Err(StorageError::new(
                StorageErrorKind::ConfigurationError,
                format!("BlobId must start with 'sha256:', got '{s}'"),
            ));
        }
        let hex = &s["sha256:".len()..];
        if hex.len() != 64
            || !hex
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(StorageError::new(
                StorageErrorKind::ConfigurationError,
                format!("invalid SHA-256 hex part in BlobId '{s}'"),
            ));
        }
        Ok(Self(s.to_string()))
    }
}

/// Metadata describing a stored content-addressed blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobMetadata {
    /// Canonical content digest identifier.
    pub blob_id: BlobId,
    /// Exact payload length in bytes.
    pub size_bytes: u64,
    /// Emission or creation timestamp in RFC 3339 UTC format.
    pub created_at_rfc3339: Option<String>,
}

/// Resource quotas and safety limits for content-addressed storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageLimits {
    /// Maximum permitted size of an individual blob (default: 50 MiB).
    pub max_blob_size_bytes: u64,
    /// Maximum aggregate storage capacity in bytes (default: 1 GiB).
    pub max_total_storage_bytes: u64,
    /// Maximum number of stored blobs (default: 10,000).
    pub max_blob_count: usize,
}

impl Default for StorageLimits {
    fn default() -> Self {
        Self {
            max_blob_size_bytes: MAX_EVIDENCE_SIZE_BYTES,
            max_total_storage_bytes: 1024 * 1024 * 1024, // 1 GiB
            max_blob_count: 10_000,
        }
    }
}

/// Cumulative usage statistics for a storage repository.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StorageUsage {
    /// Total count of immutable blobs stored.
    pub total_blobs: usize,
    /// Total cumulative storage bytes consumed.
    pub total_bytes: u64,
}
