//! Error types for manifest capture, validation, and serialization.

use std::{error::Error, fmt, io};

/// Category of manifest error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestErrorKind {
    /// A single file exceeds the configured size ceiling.
    FileTooLarge,
    /// The aggregate size of files exceeds the configured quota.
    TotalBytesExceeded,
    /// Total file count exceeds the allowed limit.
    FileCountExceeded,
    /// Directory nesting depth exceeds the limit.
    DepthLimitExceeded,
    /// File cannot be read due to permission or I/O failure.
    IoError,
    /// File is a symlink or reparse point that was quarantined.
    QuarantinedPath,
    /// JSON serialization or deserialization failed.
    SerializationError,
    /// Manifest data is semantically or structurally invalid.
    InvalidManifest,
}

/// An error occurring during manifest creation, capture, or validation.
#[derive(Debug)]
pub struct ManifestError {
    kind: ManifestErrorKind,
    message: String,
}

impl ManifestError {
    /// Creates a new manifest error with a description.
    pub fn new(kind: ManifestErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Error category.
    pub fn kind(&self) -> ManifestErrorKind {
        self.kind
    }

    /// Diagnostic error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl Error for ManifestError {}

impl From<io::Error> for ManifestError {
    fn from(err: io::Error) -> Self {
        Self::new(ManifestErrorKind::IoError, err.to_string())
    }
}

impl From<serde_json::Error> for ManifestError {
    fn from(err: serde_json::Error) -> Self {
        Self::new(ManifestErrorKind::SerializationError, err.to_string())
    }
}
