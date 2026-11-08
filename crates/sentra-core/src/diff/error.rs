//! Error types for source snapshot diffing and revision invalidation.

use std::fmt;

/// Specific category of differential analysis or revision error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffErrorKind {
    /// Provided snapshot metadata or format is invalid.
    InvalidSnapshot(String),
    /// Content is non-UTF8 or binary and cannot produce unified line hunks.
    BinaryContent,
    /// Diff line or hunk count exceeded configured safety limits.
    LimitsExceeded(String),
    /// Revision mismatch between expected target and active workspace snapshot.
    RevisionMismatch {
        /// Revision expected by earlier authorization or session binding.
        expected: String,
        /// Actual revision detected during inspection.
        actual: String,
    },
    /// Finding absence was illegally used to mark a finding as resolved.
    AntiRegressionViolation(String),
    /// Filesystem or I/O error during content retrieval.
    Io(String),
}

/// Strongly typed error returned during snapshot diffing and hunk extraction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffError {
    /// Detailed classification of the failure.
    pub kind: DiffErrorKind,
}

impl DiffError {
    /// Constructs a new `DiffError` with the given kind.
    pub fn new(kind: DiffErrorKind) -> Self {
        Self { kind }
    }

    /// Constructs an invalid snapshot error.
    pub fn invalid_snapshot(msg: impl Into<String>) -> Self {
        Self::new(DiffErrorKind::InvalidSnapshot(msg.into()))
    }

    /// Constructs a limits exceeded error.
    pub fn limits_exceeded(msg: impl Into<String>) -> Self {
        Self::new(DiffErrorKind::LimitsExceeded(msg.into()))
    }

    /// Constructs a revision mismatch error.
    pub fn revision_mismatch(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::new(DiffErrorKind::RevisionMismatch {
            expected: expected.into(),
            actual: actual.into(),
        })
    }

    /// Constructs an anti-regression violation error.
    pub fn anti_regression(msg: impl Into<String>) -> Self {
        Self::new(DiffErrorKind::AntiRegressionViolation(msg.into()))
    }
}

impl fmt::Display for DiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            DiffErrorKind::InvalidSnapshot(msg) => write!(f, "Invalid snapshot: {msg}"),
            DiffErrorKind::BinaryContent => write!(f, "File content is binary"),
            DiffErrorKind::LimitsExceeded(msg) => write!(f, "Diff limit exceeded: {msg}"),
            DiffErrorKind::RevisionMismatch { expected, actual } => {
                write!(
                    f,
                    "Revision mismatch: expected '{expected}', found '{actual}'"
                )
            }
            DiffErrorKind::AntiRegressionViolation(msg) => {
                write!(f, "Anti-regression violation: {msg}")
            }
            DiffErrorKind::Io(msg) => write!(f, "I/O error during diff: {msg}"),
        }
    }
}

impl std::error::Error for DiffError {}
