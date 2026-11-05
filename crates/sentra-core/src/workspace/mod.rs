//! Bounded, metadata-only observations of an explicitly selected local workspace.
//!
//! These types do not grant authorization. Callers must evaluate policy separately.
//! No file-content, execution, network, Git or package-manager API is provided.
//! A resolved path is a retained metadata observation, never a reusable path capability.

mod boundary;
mod discovery;
mod error;
mod model;
mod platform;

pub use boundary::{ResolvedWorkspacePath, WorkspaceBoundary, WorkspaceRoot};
pub use error::{InvalidPathReason, WorkspaceError, WorkspaceErrorKind, WorkspaceOperation};
pub use model::{
    DiscoveryLimits, DiscoveryResult, IncompleteReason, QuarantineReason, QuarantinedEntry,
    RepositoryMetadataKind, WorkspaceEntry, WorkspaceEntryKind,
};
