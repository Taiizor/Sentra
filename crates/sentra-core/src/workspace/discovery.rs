use std::{fs, path::Path};

use super::{
    DiscoveryLimits, DiscoveryResult, IncompleteReason, QuarantineReason, QuarantinedEntry,
    RepositoryMetadataKind, ResolvedWorkspacePath, WorkspaceBoundary, WorkspaceEntryKind,
    WorkspaceError, WorkspaceErrorKind,
};

impl WorkspaceBoundary {
    /// Enumerate metadata only, after caller policy authorization. No bytes are read
    /// from target files, including manifests, .git pointers, hooks and build scripts.
    pub fn discover(&self, limits: &DiscoveryLimits) -> Result<DiscoveryResult, WorkspaceError> {
        limits.validate()?;
        let root = self.resolve(Path::new("."))?;
        let mut result = DiscoveryResult {
            session_id: self.root().session_id(),
            classification: self.root().classification(),
            entries: Vec::new(),
            quarantined: Vec::new(),
            incomplete_reasons: Vec::new(),
            inspected_entries: 0,
            total_file_bytes: 0,
            inventory_bytes: 0,
        };
        self.walk(&root, 0, limits, &mut result, &mut 0);
        result
            .entries
            .sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        result
            .quarantined
            .sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(result)
    }

    fn walk(
        &self,
        directory: &ResolvedWorkspacePath,
        depth: usize,
        limits: &DiscoveryLimits,
        result: &mut DiscoveryResult,
        buffered: &mut usize,
    ) {
        let pending_ancestor_names = *buffered;
        self.walk_inner(directory, depth, limits, result, buffered);
        // All unconsumed local names are dropped on every early-return path.
        *buffered = pending_ancestor_names;
    }

    fn walk_inner(
        &self,
        directory: &ResolvedWorkspacePath,
        depth: usize,
        limits: &DiscoveryLimits,
        result: &mut DiscoveryResult,
        buffered: &mut usize,
    ) {
        if stopped(result) {
            return;
        }
        let before = match self.inspect(directory) {
            Ok(entry) => entry,
            Err(error) => {
                directory_failure(directory.relative_path(), error.kind, result);
                return;
            }
        };
        // The retained handles remain live during read_dir. No child path is used
        // until no-follow resolution; DirEntry::metadata is deliberately not used.
        let mut iterator =
            match fs::read_dir(self.root().canonical_path().join(directory.relative_path())) {
                Ok(iterator) => iterator,
                Err(error) => {
                    directory_failure(
                        directory.relative_path(),
                        WorkspaceErrorKind::Io {
                            kind: error.kind(),
                            os_code: error.raw_os_error(),
                        },
                        result,
                    );
                    return;
                }
            };
        let remaining = limits.max_entries - result.inspected_entries;
        let mut names = Vec::new();
        let mut hit_entry_limit = false;
        // At most one extra name establishes incompleteness; it is never resolved.
        loop {
            match iterator.next() {
                None => break,
                Some(Err(error)) => {
                    directory_failure(
                        directory.relative_path(),
                        WorkspaceErrorKind::Io {
                            kind: error.kind(),
                            os_code: error.raw_os_error(),
                        },
                        result,
                    );
                    return;
                }
                Some(Ok(entry)) => {
                    if depth >= limits.max_depth {
                        result.incomplete(IncompleteReason::DepthLimit);
                        return;
                    }
                    if names.len() >= remaining {
                        // Delay this reason until collected names have been processed.
                        // Otherwise stopped() would discard every collected observation.
                        hit_entry_limit = true;
                        break;
                    }
                    let relative = directory.relative_path().join(entry.file_name());
                    let bytes = relative.as_os_str().as_encoded_bytes().len();
                    if buffered
                        .checked_add(bytes)
                        .and_then(|sum| sum.checked_add(result.inventory_bytes))
                        .is_none_or(|sum| sum > limits.max_inventory_bytes)
                    {
                        result.incomplete(IncompleteReason::InventoryBytesLimit);
                        return;
                    }
                    *buffered += bytes;
                    names.push(relative);
                }
            }
        }
        // A bounded directory buffer allows stable ordering for complete inventories.
        // Truncated inventories explicitly do not promise a stable subset under mutation.
        names.sort();
        for relative in names {
            let bytes = relative.as_os_str().as_encoded_bytes().len();
            *buffered -= bytes;
            if stopped(result) {
                return;
            }
            if result.inspected_entries == limits.max_entries {
                result.incomplete(IncompleteReason::EntryLimit);
                return;
            }
            if result
                .inventory_bytes
                .checked_add(bytes)
                .is_none_or(|sum| sum > limits.max_inventory_bytes)
            {
                result.incomplete(IncompleteReason::InventoryBytesLimit);
                return;
            }
            result.inventory_bytes += bytes;
            result.inspected_entries += 1;
            match self
                .resolve(&relative)
                .and_then(|resolved| self.inspect(&resolved).map(|entry| (resolved, entry)))
            {
                Err(error) => {
                    let reason = match error.kind {
                        WorkspaceErrorKind::Quarantined(
                            WorkspaceEntryKind::ReparsePoint | WorkspaceEntryKind::SymbolicLink,
                        ) => {
                            if let WorkspaceErrorKind::Quarantined(kind) = error.kind {
                                QuarantineReason::Indirection(kind)
                            } else {
                                unreachable!()
                            }
                        }
                        WorkspaceErrorKind::Quarantined(_) => QuarantineReason::UnsupportedEntry,
                        kind => QuarantineReason::InspectionFailed(kind),
                    };
                    result.quarantined.push(QuarantinedEntry {
                        relative_path: relative,
                        reason,
                    });
                    result.incomplete(IncompleteReason::Quarantined);
                }
                Ok((resolved, entry)) => {
                    if entry.kind == WorkspaceEntryKind::File {
                        if entry.size_bytes > limits.max_file_bytes {
                            result.quarantined.push(QuarantinedEntry {
                                relative_path: relative,
                                reason: QuarantineReason::FileSizeLimit,
                            });
                            result.incomplete(IncompleteReason::Quarantined);
                            continue;
                        }
                        if result
                            .total_file_bytes
                            .checked_add(entry.size_bytes)
                            .is_none_or(|sum| sum > limits.max_total_file_bytes)
                        {
                            result.incomplete(IncompleteReason::TotalFileBytesLimit);
                            return;
                        }
                        result.total_file_bytes += entry.size_bytes;
                    }
                    let descend = entry.kind == WorkspaceEntryKind::Directory
                        && entry.repository_metadata != Some(RepositoryMetadataKind::Git);
                    result.entries.push(entry);
                    if descend {
                        self.walk(&resolved, depth + 1, limits, result, buffered);
                    }
                }
            }
        }
        if hit_entry_limit {
            result.incomplete(IncompleteReason::EntryLimit);
        }
        match self.inspect(directory) {
            Ok(after) if before == after => {}
            Ok(_) => directory_failure(
                directory.relative_path(),
                WorkspaceErrorKind::PathChanged,
                result,
            ),
            Err(error) => directory_failure(directory.relative_path(), error.kind, result),
        }
    }
}

fn stopped(result: &DiscoveryResult) -> bool {
    result.incomplete_reasons.iter().any(|reason| {
        matches!(
            reason,
            IncompleteReason::EntryLimit
                | IncompleteReason::TotalFileBytesLimit
                | IncompleteReason::InventoryBytesLimit
        )
    })
}

fn directory_failure(relative: &Path, kind: WorkspaceErrorKind, result: &mut DiscoveryResult) {
    // Retract observations below an unstable directory; never leave a quarantined
    // directory in the usable inventory. Component containment, not string prefixes.
    result
        .entries
        .retain(|entry| !entry.relative_path.starts_with(relative));
    result.total_file_bytes = result.entries.iter().map(|entry| entry.size_bytes).sum();
    result
        .quarantined
        .retain(|entry| !entry.relative_path.starts_with(relative));
    result.quarantined.push(QuarantinedEntry {
        relative_path: relative.to_path_buf(),
        reason: QuarantineReason::InspectionFailed(kind),
    });
    result.incomplete(IncompleteReason::DirectoryInspectionFailed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SecurityClassification, SessionId};

    #[test]
    fn unstable_directory_retracts_its_subtree_without_string_prefix_collisions() {
        let entry = |relative: &str| super::super::WorkspaceEntry {
            relative_path: relative.into(),
            kind: WorkspaceEntryKind::File,
            size_bytes: 1,
            modified: None,
            repository_metadata: None,
            classification: SecurityClassification::Confidential,
        };
        let mut result = DiscoveryResult {
            session_id: SessionId::for_test_sequence(53),
            classification: SecurityClassification::Confidential,
            entries: vec![entry("dir/child"), entry("directory/keep")],
            quarantined: vec![],
            incomplete_reasons: vec![],
            inspected_entries: 2,
            total_file_bytes: 2,
            inventory_bytes: 23,
        };
        directory_failure(
            Path::new("dir"),
            WorkspaceErrorKind::PathChanged,
            &mut result,
        );
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].relative_path, Path::new("directory/keep"));
        assert_eq!(result.total_file_bytes, 1);
        assert!(!result.is_complete());
        directory_failure(Path::new(""), WorkspaceErrorKind::PathChanged, &mut result);
        assert!(result.entries.is_empty());
        assert_eq!(result.quarantined.len(), 1);
    }
}
