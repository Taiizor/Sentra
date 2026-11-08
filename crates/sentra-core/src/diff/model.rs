//! Domain data models and schemas for source snapshot diffs and line hunks (REQ-F01/F02).

use serde::{Deserialize, Serialize};

use crate::manifest::SourceFileRole;

/// Classification of change applied to an individual file between two snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FileDeltaKind {
    /// File was created in head and did not exist in base.
    Added,
    /// File existed in base but has different content digest in head.
    Modified,
    /// File existed in base but was removed in head.
    Deleted,
    /// File was renamed from an existing path with identical content digest.
    Renamed {
        /// Previous relative path in the base snapshot.
        from_path: String,
    },
    /// File exists in both base and head with identical content digest.
    Unchanged,
}

impl FileDeltaKind {
    /// Returns a static string representation of the delta kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Modified => "modified",
            Self::Deleted => "deleted",
            Self::Renamed { .. } => "renamed",
            Self::Unchanged => "unchanged",
        }
    }
}

/// A single file difference record between two source snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDelta {
    /// Canonical workspace-relative path (in head for added/modified/renamed/unchanged, or in base for deleted).
    pub path: String,
    /// Type of change observed.
    pub kind: FileDeltaKind,
    /// File role classification.
    pub role: SourceFileRole,
    /// SHA-256 content digest in the base snapshot, if present.
    pub base_digest: Option<String>,
    /// SHA-256 content digest in the head snapshot, if present.
    pub head_digest: Option<String>,
    /// File length in bytes in the base snapshot, if present.
    pub base_size: Option<u64>,
    /// File length in bytes in the head snapshot, if present.
    pub head_size: Option<u64>,
}

/// Aggregate metrics and counts summarizing a snapshot difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DiffSummary {
    /// Total number of files present in base snapshot.
    pub total_files_base: usize,
    /// Total number of files present in head snapshot.
    pub total_files_head: usize,
    /// Number of newly added files.
    pub added_files: usize,
    /// Number of modified files.
    pub modified_files: usize,
    /// Number of deleted files.
    pub deleted_files: usize,
    /// Number of renamed files.
    pub renamed_files: usize,
    /// Number of unchanged files.
    pub unchanged_files: usize,
    /// Number of Rust source files (`*.rs`) that were added, modified, deleted, or renamed.
    pub rust_files_changed: usize,
    /// Net difference in byte length (`head_total_bytes - base_total_bytes`).
    pub net_bytes_delta: i64,
}

/// Complete differential analysis between two source snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotDiff {
    /// Schema version for snapshot diffs (always 1).
    pub schema_version: u32,
    /// Aggregate digest of base snapshot (`sha256:<64 hex>`).
    pub base_aggregate_digest: String,
    /// Aggregate digest of head snapshot (`sha256:<64 hex>`).
    pub head_aggregate_digest: String,
    /// File-level changes sorted deterministically by canonical path.
    pub deltas: Vec<FileDelta>,
    /// High-level metrics and statistics.
    pub summary: DiffSummary,
}

impl SnapshotDiff {
    /// Schema version for canonical snapshot diffs.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Filters deltas to only changed files (excluding unchanged).
    pub fn changed_deltas(&self) -> Vec<&FileDelta> {
        self.deltas
            .iter()
            .filter(|d| !matches!(d.kind, FileDeltaKind::Unchanged))
            .collect()
    }

    /// Filters deltas to only changed Rust source files (`*.rs`).
    pub fn changed_rust_files(&self) -> Vec<&FileDelta> {
        self.deltas
            .iter()
            .filter(|d| {
                d.role == SourceFileRole::RustSource && !matches!(d.kind, FileDeltaKind::Unchanged)
            })
            .collect()
    }
}

/// Individual line within a unified diff hunk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "text", rename_all = "snake_case")]
pub enum DiffLine {
    /// Context line unchanged between base and head.
    Context(String),
    /// Added line present in head but not base.
    Addition(String),
    /// Deleted line present in base but not head.
    Deletion(String),
}

/// Unified diff hunk containing line changes and surrounding bounded context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffHunk {
    /// 1-based starting line number in original base content.
    pub old_start: usize,
    /// Total count of lines from base content covered by this hunk.
    pub old_lines: usize,
    /// 1-based starting line number in new head content.
    pub new_start: usize,
    /// Total count of lines from head content covered by this hunk.
    pub new_lines: usize,
    /// Sequential diff lines comprising the hunk.
    pub lines: Vec<DiffLine>,
}

/// Narrow source difference for an individual text file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileContentDiff {
    /// Workspace-relative canonical path.
    pub path: String,
    /// Whether file is identified as non-UTF8 or binary.
    pub is_binary: bool,
    /// Bounded unified hunks for text files.
    pub hunks: Vec<DiffHunk>,
    /// Total count of added lines across all hunks.
    pub additions_count: usize,
    /// Total count of deleted lines across all hunks.
    pub deletions_count: usize,
}

/// Configuration limits for narrow hunk extraction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HunkLimits {
    /// Number of context lines before and after edits (default 3).
    pub context_lines: usize,
    /// Maximum number of hunks per file (default 50).
    pub max_hunks: usize,
    /// Maximum aggregate lines per file diff (default 2,000).
    pub max_diff_lines: usize,
}

impl Default for HunkLimits {
    fn default() -> Self {
        Self {
            context_lines: 3,
            max_hunks: 50,
            max_diff_lines: 2000,
        }
    }
}
