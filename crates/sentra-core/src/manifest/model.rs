//! Data models and schemas for immutable canonical manifests (REQ-F01/F02).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    common::crypto::{Sha256Stream, sha256_prefixed},
    manifest::error::{ManifestError, ManifestErrorKind},
};

/// Role or classification of a source file within a project snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFileRole {
    /// Rust source code (`*.rs`).
    RustSource,
    /// Cargo project manifest (`Cargo.toml`).
    CargoManifest,
    /// Cargo locked dependencies (`Cargo.lock`).
    CargoLock,
    /// Documentation (`*.md`, `*.txt`, `LICENSE*`, `README*`).
    Documentation,
    /// Structured configuration (`*.json`, `*.toml`, `*.yaml`, `*.yml`, `*.xml`).
    Configuration,
    /// Generic text or other source file.
    GenericSource,
    /// Binary or executable artifact.
    Binary,
    /// Explicitly ignored or unsupported file.
    Ignored,
}

impl SourceFileRole {
    /// Detects file role from a workspace-relative path.
    pub fn from_path(path: &Path) -> Self {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        if file_name.eq_ignore_ascii_case("Cargo.toml") {
            return Self::CargoManifest;
        }
        if file_name.eq_ignore_ascii_case("Cargo.lock") {
            return Self::CargoLock;
        }
        if file_name.to_lowercase().starts_with("license")
            || file_name.to_lowercase().starts_with("readme")
        {
            return Self::Documentation;
        }

        match path.extension().and_then(|ext| ext.to_str()) {
            Some(ext) => match ext.to_ascii_lowercase().as_str() {
                "rs" => Self::RustSource,
                "md" | "txt" | "rst" | "adoc" => Self::Documentation,
                "toml" | "json" | "yaml" | "yml" | "xml" => Self::Configuration,
                "c" | "cpp" | "h" | "hpp" | "py" | "js" | "ts" | "go" | "sh" => Self::GenericSource,
                "exe" | "dll" | "so" | "dylib" | "bin" | "o" | "a" | "pdb" => Self::Binary,
                _ => Self::GenericSource,
            },
            None => Self::GenericSource,
        }
    }

    /// Canonical string identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RustSource => "rust_source",
            Self::CargoManifest => "cargo_manifest",
            Self::CargoLock => "cargo_lock",
            Self::Documentation => "documentation",
            Self::Configuration => "configuration",
            Self::GenericSource => "generic_source",
            Self::Binary => "binary",
            Self::Ignored => "ignored",
        }
    }
}

/// A single file entry within a source snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshotEntry {
    /// Workspace-relative canonical path with forward slashes (e.g. `src/lib.rs`).
    pub path: String,
    /// Exact file length in bytes.
    pub size_bytes: u64,
    /// 64-character lowercase hexadecimal SHA-256 digest of the file bytes.
    pub content_sha256: String,
    /// Detected source file role.
    pub role: SourceFileRole,
}

/// Bounded limits for capturing source snapshots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotLimits {
    /// Maximum number of regular files allowed in a snapshot.
    pub max_files: usize,
    /// Maximum size of an individual file in bytes (default 10 MiB).
    pub max_file_size_bytes: u64,
    /// Maximum aggregate size of all files in bytes (default 100 MiB).
    pub max_total_bytes: u64,
    /// Maximum directory traversal depth.
    pub max_depth: usize,
}

impl Default for SnapshotLimits {
    fn default() -> Self {
        Self {
            max_files: 10_000,
            max_file_size_bytes: 10 * 1024 * 1024,
            max_total_bytes: 100 * 1024 * 1024,
            max_depth: 32,
        }
    }
}

/// An immutable source snapshot manifest representing frozen workspace state (REQ-F01/F02).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshot {
    /// Schema version of the snapshot structure (always 1).
    pub version: u32,
    /// Associated session identifier string.
    pub session_id: String,
    /// Human-readable workspace root descriptor or label.
    pub root_label: String,
    /// Sorted, deterministic file entries.
    pub entries: Vec<SourceSnapshotEntry>,
    /// Total number of files included in the snapshot.
    pub total_files: usize,
    /// Aggregate byte count of all snapshot files.
    pub total_bytes: u64,
    /// Deterministic aggregate cryptographic digest (`sha256:<64 hex>`).
    pub aggregate_digest: String,
    /// Snapshot creation timestamp (RFC 3339).
    pub created_at: String,
}

impl SourceSnapshot {
    /// Schema version for canonical source snapshots.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Computes the deterministic aggregate SHA-256 digest over sorted file entries.
    ///
    /// Framing algorithm: each entry is formatted as `"{path}:{size_bytes}:{content_sha256}:{role}\n"`.
    /// Entries MUST be sorted by path ascending before computing this digest.
    pub fn compute_aggregate_digest(entries: &[SourceSnapshotEntry]) -> String {
        let mut hasher = Sha256Stream::new();
        for entry in entries {
            let line = format!(
                "{}:{}:{}:{}\n",
                entry.path,
                entry.size_bytes,
                entry.content_sha256,
                entry.role.as_str()
            );
            hasher.update(line.as_bytes());
        }
        hasher.finalize_prefixed()
    }

    /// Serializes this snapshot into a canonical compact JSON string suitable for the `manifests` table.
    pub fn to_canonical_json(&self) -> Result<String, ManifestError> {
        serde_json::to_string(self)
            .map_err(|e| ManifestError::new(ManifestErrorKind::SerializationError, e.to_string()))
    }

    /// Deserializes a canonical JSON string into a `SourceSnapshot`.
    pub fn from_canonical_json(json: &str) -> Result<Self, ManifestError> {
        serde_json::from_str(json)
            .map_err(|e| ManifestError::new(ManifestErrorKind::InvalidManifest, e.to_string()))
    }
}

/// An operation manifest representing an approved action intent bound to a specific source state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationManifest {
    /// Schema version (always 1).
    pub version: u32,
    /// Bound session identifier string.
    pub session_id: String,
    /// Bound task identifier string.
    pub task_id: String,
    /// Action name (e.g. `EXECUTE_TOOL`, `INVOKE_PROVIDER`).
    pub action_name: String,
    /// Canonical structured action digest.
    pub action_digest: String,
    /// Cryptographic digest of the source snapshot upon which this operation was evaluated.
    pub source_snapshot_digest: Option<String>,
    /// Security classification string.
    pub classification: String,
    /// Manifest creation timestamp (RFC 3339).
    pub created_at: String,
}

impl OperationManifest {
    /// Schema version for operation manifests.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Serializes this manifest to canonical JSON.
    pub fn to_canonical_json(&self) -> Result<String, ManifestError> {
        serde_json::to_string(self)
            .map_err(|e| ManifestError::new(ManifestErrorKind::SerializationError, e.to_string()))
    }

    /// Computes the content digest for this operation manifest (`sha256:<hex>`).
    pub fn content_digest(&self) -> Result<String, ManifestError> {
        let json = self.to_canonical_json()?;
        Ok(sha256_prefixed(json.as_bytes()))
    }

    /// Deserializes from canonical JSON.
    pub fn from_canonical_json(json: &str) -> Result<Self, ManifestError> {
        serde_json::from_str(json)
            .map_err(|e| ManifestError::new(ManifestErrorKind::InvalidManifest, e.to_string()))
    }
}
