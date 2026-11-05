use std::{path::PathBuf, time::SystemTime};

use crate::{SecurityClassification, SessionId};

use super::{WorkspaceError, WorkspaceErrorKind, WorkspaceOperation};

/// Object type observed without following the final entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceEntryKind {
    /// Ordinary non-reparse file; this is not a content-access grant.
    File,
    /// Ordinary non-reparse directory.
    Directory,
    /// A symbolic link identified by a platform with sufficient metadata.
    SymbolicLink,
    /// Windows reparse point, including junctions; stable std cannot expose its tag.
    ReparsePoint,
    /// Device, special, unknown, offline, or recall-triggering object.
    Unsupported,
}

/// Repository metadata detected from a name only, never by running a tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepositoryMetadataKind {
    /// Opaque .git file or directory; children and contents are never inspected.
    Git,
    /// Cargo.toml file; its contents are not read or parsed in this increment.
    CargoManifest,
    /// Cargo.lock file; its contents are not read or parsed.
    CargoLock,
}

/// Metadata snapshot, carrying the source classification and no access authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceEntry {
    /// Untrusted workspace-relative name.
    pub relative_path: PathBuf,
    /// Observed ordinary object type.
    pub kind: WorkspaceEntryKind,
    /// File length from metadata; no file content has been read.
    pub size_bytes: u64,
    /// Modification time when the filesystem exposes it.
    pub modified: Option<SystemTime>,
    /// Name-only repository metadata classification.
    pub repository_metadata: Option<RepositoryMetadataKind>,
    /// Classification inherited from the workspace.
    pub classification: SecurityClassification,
}

/// Why an entry was excluded from usable observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuarantineReason {
    /// All indirections, including internal targets, are denied.
    Indirection(WorkspaceEntryKind),
    /// Unsupported device/special object.
    UnsupportedEntry,
    /// Access, path validation or observed mutation failure.
    InspectionFailed(WorkspaceErrorKind),
    /// A regular file exceeds the configured metadata file-length envelope.
    FileSizeLimit,
}

/// An excluded relative name. It cannot be converted to a resolved path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedEntry {
    /// Untrusted relative name, not a path capability.
    pub relative_path: PathBuf,
    /// Explicit exclusion reason.
    pub reason: QuarantineReason,
}

/// A reason the inventory is not complete; none means a clean security assessment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncompleteReason {
    /// At least one entry was quarantined or could not be inspected.
    Quarantined,
    /// More names exist than the global entry budget permits.
    EntryLimit,
    /// A directory could not be enumerated at the requested depth.
    DepthLimit,
    /// Sum of ordinary file lengths exceeded the configured envelope.
    TotalFileBytesLimit,
    /// Relative-name storage exceeded its explicit budget.
    InventoryBytesLimit,
    /// A directory changed or failed while being enumerated.
    DirectoryInspectionFailed,
}

/// Validated resource budgets; bounded setters are represented by public input fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryLimits {
    /// Maximum inspected child entries, including quarantined entries.
    pub max_entries: usize,
    /// Maximum child depth; zero inspects only the root and reports incompleteness.
    pub max_depth: usize,
    /// Maximum regular-file length to retain as usable metadata.
    pub max_file_bytes: u64,
    /// Maximum aggregate retained regular-file lengths, not content reads.
    pub max_total_file_bytes: u64,
    /// Maximum encoded-name budget, including pending directory buffers.
    pub max_inventory_bytes: usize,
    /// Content reads are unsupported; only zero is valid in this increment.
    pub max_metadata_content_bytes: usize,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_depth: 32,
            max_file_bytes: 100 * 1024 * 1024,
            max_total_file_bytes: 100 * 1024 * 1024,
            max_inventory_bytes: 16 * 1024 * 1024,
            max_metadata_content_bytes: 0,
        }
    }
}

impl DiscoveryLimits {
    /// Reject invalid/excessive budgets instead of silently clamping them.
    pub fn validate(&self) -> Result<(), WorkspaceError> {
        if self.max_entries == 0
            || self.max_entries > 100_000
            || self.max_depth > 128
            || self.max_file_bytes == 0
            || self.max_file_bytes > (1u64 << 40)
            || self.max_total_file_bytes == 0
            || self.max_total_file_bytes > (1u64 << 40)
            || self.max_inventory_bytes == 0
            || self.max_inventory_bytes > 128 * 1024 * 1024
            || self.max_metadata_content_bytes != 0
        {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::InvalidLimits,
                WorkspaceOperation::ValidateLimits,
            ));
        }
        Ok(())
    }
}

/// Bounded observations, explicitly distinct from a complete vulnerability assessment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryResult {
    /// Existing domain session identity supplied by the authorized caller.
    pub session_id: SessionId,
    /// Classification inherited without downgrading.
    pub classification: SecurityClassification,
    /// Ordinary entries; snapshots confer no access grant.
    pub entries: Vec<WorkspaceEntry>,
    /// Unusable entries, including denied indirections.
    pub quarantined: Vec<QuarantinedEntry>,
    /// Reasons for incomplete discovery, without duplicate reasons.
    pub incomplete_reasons: Vec<IncompleteReason>,
    /// Number of metadata admission attempts, including failed inspections.
    pub inspected_entries: usize,
    /// Sum of retained ordinary file lengths; not bytes read.
    pub total_file_bytes: u64,
    /// Conservative consumed name budget; retracted observations do not refund it.
    pub inventory_bytes: usize,
}

impl DiscoveryResult {
    /// Complete inventory within this metadata-only scope; never a security verdict.
    pub fn is_complete(&self) -> bool {
        self.incomplete_reasons.is_empty()
    }

    pub(super) fn incomplete(&mut self, reason: IncompleteReason) {
        if !self.incomplete_reasons.contains(&reason) {
            self.incomplete_reasons.push(reason);
        }
    }
}
