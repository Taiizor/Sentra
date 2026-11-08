//! Error types for dependency advisory analysis and lockfile parsing (Requirement F-07).

use std::fmt;

/// Error kinds encountered during advisory evaluation or lockfile parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvisoryErrorKind {
    /// Lockfile content is malformed or unparseable.
    MalformedLockfile,
    /// Version string cannot be parsed as valid semantic versioning.
    InvalidVersion,
    /// Version requirement expression is malformed.
    InvalidVersionRequirement,
    /// Storage or I/O error reading lockfile.
    Io,
    /// Advisory database is corrupted or invalid.
    InvalidDatabase,
}

impl AdvisoryErrorKind {
    /// Returns the textual identifier for the error kind.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MalformedLockfile => "MALFORMED_LOCKFILE",
            Self::InvalidVersion => "INVALID_VERSION",
            Self::InvalidVersionRequirement => "INVALID_VERSION_REQUIREMENT",
            Self::Io => "IO",
            Self::InvalidDatabase => "INVALID_DATABASE",
        }
    }
}

/// Typed error returned during advisory auditing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdvisoryError {
    kind: AdvisoryErrorKind,
    message: String,
}

impl AdvisoryError {
    /// Creates a new advisory error.
    pub fn new(kind: AdvisoryErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Returns the kind of advisory error.
    pub fn kind(&self) -> AdvisoryErrorKind {
        self.kind
    }

    /// Returns the human-readable error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AdvisoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.as_str(), self.message)
    }
}

impl std::error::Error for AdvisoryError {}
