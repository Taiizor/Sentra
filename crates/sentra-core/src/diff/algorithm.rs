//! Pure-Rust algorithms for snapshot delta derivation and narrow line hunk diffing.

use std::{
    cmp::{max, min},
    collections::{BTreeMap, HashMap},
};

use crate::{
    diff::{
        error::DiffError,
        model::{
            DiffHunk, DiffLine, DiffSummary, FileContentDiff, FileDelta, FileDeltaKind, HunkLimits,
            SnapshotDiff,
        },
    },
    manifest::{SourceFileRole, SourceSnapshot, SourceSnapshotEntry},
};

/// Compares two canonical source snapshots and produces a deterministic differential delta report.
pub fn compare_snapshots(base: &SourceSnapshot, head: &SourceSnapshot) -> SnapshotDiff {
    let mut base_map = BTreeMap::new();
    for entry in &base.entries {
        base_map.insert(entry.path.as_str(), entry);
    }

    let mut head_map = BTreeMap::new();
    for entry in &head.entries {
        head_map.insert(entry.path.as_str(), entry);
    }

    let mut deltas = Vec::new();
    let mut candidate_deleted = Vec::new();
    let mut candidate_added = Vec::new();

    // Check base entries against head
    for (&path, &base_entry) in &base_map {
        match head_map.get(path) {
            Some(&head_entry) => {
                if base_entry.content_sha256 == head_entry.content_sha256 {
                    deltas.push(FileDelta {
                        path: path.to_string(),
                        kind: FileDeltaKind::Unchanged,
                        role: head_entry.role,
                        base_digest: Some(base_entry.content_sha256.clone()),
                        head_digest: Some(head_entry.content_sha256.clone()),
                        base_size: Some(base_entry.size_bytes),
                        head_size: Some(head_entry.size_bytes),
                    });
                } else {
                    deltas.push(FileDelta {
                        path: path.to_string(),
                        kind: FileDeltaKind::Modified,
                        role: head_entry.role,
                        base_digest: Some(base_entry.content_sha256.clone()),
                        head_digest: Some(head_entry.content_sha256.clone()),
                        base_size: Some(base_entry.size_bytes),
                        head_size: Some(head_entry.size_bytes),
                    });
                }
            }
            None => {
                candidate_deleted.push(base_entry);
            }
        }
    }

    // Identify candidate added entries
    for (&path, &head_entry) in &head_map {
        if !base_map.contains_key(path) {
            candidate_added.push(head_entry);
        }
    }

    // Detect file renames by matching identical content digests between deleted and added files
    let mut deleted_by_digest: HashMap<&str, Vec<&SourceSnapshotEntry>> = HashMap::new();
    for entry in &candidate_deleted {
        deleted_by_digest
            .entry(&entry.content_sha256)
            .or_default()
            .push(entry);
    }

    let mut added_by_digest: HashMap<&str, Vec<&SourceSnapshotEntry>> = HashMap::new();
    for entry in &candidate_added {
        added_by_digest
            .entry(&entry.content_sha256)
            .or_default()
            .push(entry);
    }

    let mut matched_deleted_paths = std::collections::HashSet::new();
    let mut matched_added_paths = std::collections::HashSet::new();

    for (digest, added_entries) in &added_by_digest {
        if let Some(del_entries) = deleted_by_digest.get(digest) {
            // If there is an unambiguous 1:1 match by digest, treat as rename
            if added_entries.len() == 1 && del_entries.len() == 1 {
                let from_entry = del_entries[0];
                let to_entry = added_entries[0];
                deltas.push(FileDelta {
                    path: to_entry.path.clone(),
                    kind: FileDeltaKind::Renamed {
                        from_path: from_entry.path.clone(),
                    },
                    role: to_entry.role,
                    base_digest: Some(from_entry.content_sha256.clone()),
                    head_digest: Some(to_entry.content_sha256.clone()),
                    base_size: Some(from_entry.size_bytes),
                    head_size: Some(to_entry.size_bytes),
                });
                matched_deleted_paths.insert(from_entry.path.as_str());
                matched_added_paths.insert(to_entry.path.as_str());
            }
        }
    }

    // Add remaining unmatched deleted entries
    for entry in candidate_deleted {
        if !matched_deleted_paths.contains(entry.path.as_str()) {
            deltas.push(FileDelta {
                path: entry.path.clone(),
                kind: FileDeltaKind::Deleted,
                role: entry.role,
                base_digest: Some(entry.content_sha256.clone()),
                head_digest: None,
                base_size: Some(entry.size_bytes),
                head_size: None,
            });
        }
    }

    // Add remaining unmatched added entries
    for entry in candidate_added {
        if !matched_added_paths.contains(entry.path.as_str()) {
            deltas.push(FileDelta {
                path: entry.path.clone(),
                kind: FileDeltaKind::Added,
                role: entry.role,
                base_digest: None,
                head_digest: Some(entry.content_sha256.clone()),
                base_size: None,
                head_size: Some(entry.size_bytes),
            });
        }
    }

    // Sort deterministically by path
    deltas.sort_by(|a, b| a.path.cmp(&b.path));

    let mut summary = DiffSummary {
        total_files_base: base.total_files,
        total_files_head: head.total_files,
        net_bytes_delta: (head.total_bytes as i64) - (base.total_bytes as i64),
        ..Default::default()
    };

    for delta in &deltas {
        match delta.kind {
            FileDeltaKind::Added => summary.added_files += 1,
            FileDeltaKind::Modified => summary.modified_files += 1,
            FileDeltaKind::Deleted => summary.deleted_files += 1,
            FileDeltaKind::Renamed { .. } => summary.renamed_files += 1,
            FileDeltaKind::Unchanged => summary.unchanged_files += 1,
        }
        if delta.role == SourceFileRole::RustSource
            && !matches!(delta.kind, FileDeltaKind::Unchanged)
        {
            summary.rust_files_changed += 1;
        }
    }

    SnapshotDiff {
        schema_version: SnapshotDiff::SCHEMA_VERSION,
        base_aggregate_digest: base.aggregate_digest.clone(),
        head_aggregate_digest: head.aggregate_digest.clone(),
        deltas,
        summary,
    }
}

/// Computes a bounded unified diff with context lines for text files (REQ-F02).
pub fn compute_line_diff(
    path: &str,
    old_text: &str,
    new_text: &str,
    limits: &HunkLimits,
) -> Result<FileContentDiff, DiffError> {
    // Null byte presence indicates binary content
    if old_text.contains('\0') || new_text.contains('\0') {
        return Ok(FileContentDiff {
            path: path.to_string(),
            is_binary: true,
            hunks: Vec::new(),
            additions_count: 0,
            deletions_count: 0,
        });
    }

    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();

    let edits = compute_lcs_edits(&old_lines, &new_lines);

    let mut hunks = Vec::new();
    let mut total_additions = 0;
    let mut total_deletions = 0;

    // Group edits into hunks with context lines
    let groups = group_edits_into_hunks(&edits, limits.context_lines);

    for (old_start, old_count, new_start, new_count, hunk_lines) in groups {
        if hunks.len() >= limits.max_hunks {
            return Err(DiffError::limits_exceeded(format!(
                "Max hunks limit ({}) reached for file '{}'",
                limits.max_hunks, path
            )));
        }

        let mut diff_lines = Vec::new();
        for edit in hunk_lines {
            match edit {
                RawEdit::Equal(text) => diff_lines.push(DiffLine::Context(text.to_string())),
                RawEdit::Insert(text) => {
                    diff_lines.push(DiffLine::Addition(text.to_string()));
                    total_additions += 1;
                }
                RawEdit::Delete(text) => {
                    diff_lines.push(DiffLine::Deletion(text.to_string()));
                    total_deletions += 1;
                }
            }
        }

        hunks.push(DiffHunk {
            old_start,
            old_lines: old_count,
            new_start,
            new_lines: new_count,
            lines: diff_lines,
        });
    }

    let total_diff_lines: usize = hunks.iter().map(|h| h.lines.len()).sum();
    if total_diff_lines > limits.max_diff_lines {
        return Err(DiffError::limits_exceeded(format!(
            "Total diff lines ({}) exceeded limit ({}) for file '{}'",
            total_diff_lines, limits.max_diff_lines, path
        )));
    }

    Ok(FileContentDiff {
        path: path.to_string(),
        is_binary: false,
        hunks,
        additions_count: total_additions,
        deletions_count: total_deletions,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RawEdit<'a> {
    Equal(&'a str),
    Delete(&'a str),
    Insert(&'a str),
}

fn compute_lcs_edits<'a>(old_lines: &[&'a str], new_lines: &[&'a str]) -> Vec<RawEdit<'a>> {
    let n = old_lines.len();
    let m = new_lines.len();

    // Fast path: find common prefix
    let mut prefix = 0;
    while prefix < n && prefix < m && old_lines[prefix] == new_lines[prefix] {
        prefix += 1;
    }

    // Fast path: find common suffix
    let mut suffix = 0;
    while suffix < (n - prefix)
        && suffix < (m - prefix)
        && old_lines[n - 1 - suffix] == new_lines[m - 1 - suffix]
    {
        suffix += 1;
    }

    let mut result = Vec::with_capacity(n + m);

    // Add prefix
    for &line in &old_lines[..prefix] {
        result.push(RawEdit::Equal(line));
    }

    let mid_old = &old_lines[prefix..n - suffix];
    let mid_new = &new_lines[prefix..m - suffix];

    // Compute dynamic programming table for middle portion
    let mid_n = mid_old.len();
    let mid_m = mid_new.len();

    if mid_n > 0 || mid_m > 0 {
        let mut dp = vec![vec![0u32; mid_m + 1]; mid_n + 1];

        for i in 0..mid_n {
            for j in 0..mid_m {
                if mid_old[i] == mid_new[j] {
                    dp[i + 1][j + 1] = dp[i][j] + 1;
                } else {
                    dp[i + 1][j + 1] = max(dp[i + 1][j], dp[i][j + 1]);
                }
            }
        }

        // Backtrack edit script
        let mut i = mid_n;
        let mut j = mid_m;
        let mut mid_edits = Vec::new();

        while i > 0 || j > 0 {
            if i > 0 && j > 0 && mid_old[i - 1] == mid_new[j - 1] {
                mid_edits.push(RawEdit::Equal(mid_old[i - 1]));
                i -= 1;
                j -= 1;
            } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
                mid_edits.push(RawEdit::Insert(mid_new[j - 1]));
                j -= 1;
            } else if i > 0 {
                mid_edits.push(RawEdit::Delete(mid_old[i - 1]));
                i -= 1;
            }
        }

        mid_edits.reverse();
        result.extend(mid_edits);
    }

    // Add suffix
    for &line in &old_lines[n - suffix..] {
        result.push(RawEdit::Equal(line));
    }

    result
}

type HunkGroup<'a> = (usize, usize, usize, usize, Vec<RawEdit<'a>>);

fn group_edits_into_hunks<'a>(edits: &[RawEdit<'a>], context: usize) -> Vec<HunkGroup<'a>> {
    let mut hunks = Vec::new();
    let mut edit_indices = Vec::new();

    // Identify positions of changes (non-Equal)
    for (idx, edit) in edits.iter().enumerate() {
        if !matches!(edit, RawEdit::Equal(_)) {
            edit_indices.push(idx);
        }
    }

    if edit_indices.is_empty() {
        return Vec::new();
    }

    // Cluster edits within 2 * context of each other
    let mut clusters: Vec<(usize, usize)> = Vec::new();
    let mut cluster_start = edit_indices[0].saturating_sub(context);
    let mut cluster_end = min(edits.len(), edit_indices[0] + context + 1);

    for &idx in &edit_indices[1..] {
        let current_start = idx.saturating_sub(context);
        let current_end = min(edits.len(), idx + context + 1);

        if current_start <= cluster_end {
            cluster_end = max(cluster_end, current_end);
        } else {
            clusters.push((cluster_start, cluster_end));
            cluster_start = current_start;
            cluster_end = current_end;
        }
    }
    clusters.push((cluster_start, cluster_end));

    // Calculate line numbers for each cluster
    for (start_idx, end_idx) in clusters {
        let mut old_line_no = 1;
        let mut new_line_no = 1;

        // Advance line counters up to start_idx
        for edit in &edits[..start_idx] {
            match edit {
                RawEdit::Equal(_) => {
                    old_line_no += 1;
                    new_line_no += 1;
                }
                RawEdit::Delete(_) => {
                    old_line_no += 1;
                }
                RawEdit::Insert(_) => {
                    new_line_no += 1;
                }
            }
        }

        let hunk_old_start = old_line_no;
        let hunk_new_start = new_line_no;
        let mut old_count = 0;
        let mut new_count = 0;
        let mut hunk_lines = Vec::new();

        for edit in &edits[start_idx..end_idx] {
            hunk_lines.push(edit.clone());
            match edit {
                RawEdit::Equal(_) => {
                    old_count += 1;
                    new_count += 1;
                }
                RawEdit::Delete(_) => {
                    old_count += 1;
                }
                RawEdit::Insert(_) => {
                    new_count += 1;
                }
            }
        }

        hunks.push((
            hunk_old_start,
            old_count,
            hunk_new_start,
            new_count,
            hunk_lines,
        ));
    }

    hunks
}
