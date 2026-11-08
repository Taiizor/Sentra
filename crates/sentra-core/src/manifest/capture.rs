//! Deterministic capture of canonical source snapshots from authorized workspaces.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    Clock,
    common::crypto::sha256_digest,
    manifest::{
        error::{ManifestError, ManifestErrorKind},
        model::{SnapshotLimits, SourceFileRole, SourceSnapshot, SourceSnapshotEntry},
    },
    workspace::WorkspaceBoundary,
};

/// Captures a frozen, deterministic source snapshot of an authorized workspace.
///
/// Ensures strict lexical and handle containment via `WorkspaceBoundary`:
/// - Symlinks, Windows junctions, and opaque reparse points are quarantined and NEVER traversed.
/// - The `.git` repository directory is excluded from snapshot contents.
/// - Quotas for file count, individual file size, and aggregate workspace bytes are enforced.
/// - Paths are canonicalized to forward-slash relative strings (e.g. `src/lib.rs`).
/// - Entries are deterministically sorted by path, producing a stable aggregate SHA-256 digest.
pub fn capture_source_snapshot(
    boundary: &WorkspaceBoundary,
    limits: &SnapshotLimits,
    clock: &impl Clock,
) -> Result<SourceSnapshot, ManifestError> {
    let canonical_root = boundary.root().canonical_path();
    let session_id = boundary.root().session_id();
    let root_label = canonical_root.to_string_lossy().to_string();

    let mut entries = Vec::new();
    let mut total_bytes: u64 = 0;

    walk_directory(
        canonical_root,
        Path::new(""),
        0,
        limits,
        &mut entries,
        &mut total_bytes,
    )?;

    // Sort entries deterministically by relative path ascending
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    let aggregate_digest = SourceSnapshot::compute_aggregate_digest(&entries);
    let total_files = entries.len();
    let created_at = clock.now().to_rfc3339();

    Ok(SourceSnapshot {
        version: SourceSnapshot::SCHEMA_VERSION,
        session_id: session_id.to_string(),
        root_label,
        entries,
        total_files,
        total_bytes,
        aggregate_digest,
        created_at,
    })
}

fn walk_directory(
    root: &Path,
    relative_dir: &Path,
    depth: usize,
    limits: &SnapshotLimits,
    entries: &mut Vec<SourceSnapshotEntry>,
    total_bytes: &mut u64,
) -> Result<(), ManifestError> {
    if depth > limits.max_depth {
        return Err(ManifestError::new(
            ManifestErrorKind::DepthLimitExceeded,
            format!(
                "directory depth ({depth}) exceeds configured ceiling ({})",
                limits.max_depth
            ),
        ));
    }

    let current_dir = if relative_dir.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative_dir)
    };

    let dir_entries = fs::read_dir(&current_dir).map_err(|e| {
        ManifestError::new(
            ManifestErrorKind::IoError,
            format!("failed to read directory {}: {e}", current_dir.display()),
        )
    })?;

    for entry_res in dir_entries {
        let entry = entry_res.map_err(|e| {
            ManifestError::new(
                ManifestErrorKind::IoError,
                format!("failed to iterate directory entry: {e}"),
            )
        })?;

        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Opaque .git and build/cache directories are explicitly excluded from source snapshots
        if name_str == ".git" || name_str == "target" || name_str == ".sentra" {
            continue;
        }

        let child_rel_path = if relative_dir.as_os_str().is_empty() {
            PathBuf::from(&file_name)
        } else {
            relative_dir.join(&file_name)
        };

        let symlink_meta = entry.metadata().map_err(|e| {
            ManifestError::new(
                ManifestErrorKind::IoError,
                format!(
                    "failed to read metadata for {}: {e}",
                    child_rel_path.display()
                ),
            )
        })?;

        let file_type = symlink_meta.file_type();

        // Symlinks are strictly denied from snapshot traversal
        if file_type.is_symlink() {
            continue;
        }

        // On Windows, check for reparse points (junctions, volume mounts)
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if symlink_meta.file_attributes() & 0x0000_0400 != 0 {
                // FILE_ATTRIBUTE_REPARSE_POINT: quarantine / skip
                continue;
            }
        }

        if file_type.is_dir() {
            walk_directory(
                root,
                &child_rel_path,
                depth + 1,
                limits,
                entries,
                total_bytes,
            )?;
        } else if file_type.is_file() {
            let file_size = symlink_meta.len();

            if file_size > limits.max_file_size_bytes {
                return Err(ManifestError::new(
                    ManifestErrorKind::FileTooLarge,
                    format!(
                        "file {} size ({} bytes) exceeds limit ({} bytes)",
                        child_rel_path.display(),
                        file_size,
                        limits.max_file_size_bytes
                    ),
                ));
            }

            *total_bytes = total_bytes.checked_add(file_size).ok_or_else(|| {
                ManifestError::new(
                    ManifestErrorKind::TotalBytesExceeded,
                    "integer overflow calculating total snapshot bytes",
                )
            })?;

            if *total_bytes > limits.max_total_bytes {
                return Err(ManifestError::new(
                    ManifestErrorKind::TotalBytesExceeded,
                    format!(
                        "total snapshot bytes ({total_bytes}) exceeds limit ({})",
                        limits.max_total_bytes
                    ),
                ));
            }

            if entries.len() >= limits.max_files {
                return Err(ManifestError::new(
                    ManifestErrorKind::FileCountExceeded,
                    format!(
                        "file count ({}) exceeds limit ({})",
                        entries.len(),
                        limits.max_files
                    ),
                ));
            }

            let full_path = root.join(&child_rel_path);
            let file_bytes = fs::read(&full_path).map_err(|e| {
                ManifestError::new(
                    ManifestErrorKind::IoError,
                    format!("failed to read file {}: {e}", full_path.display()),
                )
            })?;

            let content_sha256 = sha256_digest(&file_bytes);
            let role = SourceFileRole::from_path(&child_rel_path);

            // Normalize path string using forward slashes for cross-platform determinism
            let normalized_path = child_rel_path
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");

            entries.push(SourceSnapshotEntry {
                path: normalized_path,
                size_bytes: file_size,
                content_sha256,
                role,
            });
        }
    }

    Ok(())
}
