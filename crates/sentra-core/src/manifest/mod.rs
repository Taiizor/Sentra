//! Immutable input manifests, canonical source snapshots, and content hashing (REQ-F01/F02).

mod capture;
mod error;
mod model;

pub use capture::capture_source_snapshot;
pub use error::{ManifestError, ManifestErrorKind};
pub use model::{
    OperationManifest, SnapshotLimits, SourceFileRole, SourceSnapshot, SourceSnapshotEntry,
};
