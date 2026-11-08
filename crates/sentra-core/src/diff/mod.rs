//! Source snapshot differential analysis, narrow Rust hunk extraction, and revision invalidation (REQ-F01, REQ-F02, REQ-F04).

/// Algorithms for diffing source snapshots and computing unified line hunks.
pub mod algorithm;
/// Error types for differential analysis.
pub mod error;
/// Revision fencing, patch approval invalidation, and anti-regression guards.
pub mod invalidation;
/// Data models for file deltas, diff summaries, and unified line hunks.
pub mod model;

pub use algorithm::{compare_snapshots, compute_line_diff};
pub use error::{DiffError, DiffErrorKind};
pub use invalidation::{
    RevisionBinding, reconcile_findings_anti_regression, validate_patch_approval_invalidation,
};
pub use model::{
    DiffHunk, DiffLine, DiffSummary, FileContentDiff, FileDelta, FileDeltaKind, HunkLimits,
    SnapshotDiff,
};
