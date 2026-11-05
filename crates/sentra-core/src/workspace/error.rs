use std::{fmt, io, path::PathBuf};

use super::WorkspaceEntryKind;

/// Path syntax rejected before filesystem inspection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidPathReason {
    /// Parent components are rejected even if a lexical reduction stays inside root.
    ParentTraversal,
    /// NUL, ambiguous Win32 names, wildcard/control characters, or invalid encoding.
    InvalidName,
    /// An NTFS alternate data stream was requested.
    AlternateDataStream,
    /// A reserved DOS device name was requested.
    ReservedDevice,
    /// UNC, device namespaces, drive-relative and root-relative forms are unsupported.
    UnsupportedPrefix,
    /// The request exceeds the bounded path representation.
    PathTooLong,
}

/// The failed metadata operation; does not contain private absolute paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceOperation {
    /// Establishing the root observation.
    EstablishRoot,
    /// Resolving or revalidating an entry.
    Resolve,
    /// Enumerating a bounded directory.
    ReadDirectory,
    /// Validating discovery options.
    ValidateLimits,
}

/// Typed, payload-free cause of a workspace failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceErrorKind {
    /// Invalid caller syntax.
    InvalidPath(InvalidPathReason),
    /// The root is not an ordinary directory.
    RootNotDirectory,
    /// Canonical component containment did not hold.
    OutsideRoot,
    /// Indirection or an unsupported object must not be trusted.
    Quarantined(WorkspaceEntryKind),
    /// A before/after observation changed.
    PathChanged,
    /// A retained observation belongs to a different boundary instance.
    WrongBoundary,
    /// The current platform has no implemented safe metadata-open strategy.
    UnsupportedPlatform,
    /// A discovery option is zero, excessive, or enables unsupported content reads.
    InvalidLimits,
    /// Inspection failed; OS text and absolute filenames are deliberately omitted.
    Io {
        /// Standard-library error classification.
        kind: io::ErrorKind,
        /// Original numeric OS error, if available.
        os_code: Option<i32>,
    },
}

/// A conservative metadata failure with explicitly accessible relative context.
#[derive(Clone, PartialEq, Eq)]
pub struct WorkspaceError {
    /// Machine-readable reason.
    pub kind: WorkspaceErrorKind,
    /// Operation being attempted.
    pub operation: WorkspaceOperation,
    relative: Option<PathBuf>,
}

impl WorkspaceError {
    pub(super) fn new(kind: WorkspaceErrorKind, operation: WorkspaceOperation) -> Self {
        Self {
            kind,
            operation,
            relative: None,
        }
    }

    pub(super) fn io(error: io::Error, operation: WorkspaceOperation) -> Self {
        Self::new(
            WorkspaceErrorKind::Io {
                kind: error.kind(),
                os_code: error.raw_os_error(),
            },
            operation,
        )
    }

    pub(super) fn at(mut self, relative: &std::path::Path) -> Self {
        self.relative = Some(relative.to_path_buf());
        self
    }

    /// Untrusted relative context for an explicitly authorized diagnostic view.
    pub fn relative_path(&self) -> Option<&std::path::Path> {
        self.relative.as_deref()
    }
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "workspace {:?} rejected: {:?}",
            self.operation, self.kind
        )
    }
}

impl fmt::Debug for WorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for WorkspaceError {}
