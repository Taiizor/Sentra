//! Pure-Rust unified diff hunk application and atomic backup rollback engine.
//!
//! Provides strict workspace jail path verification, unified diff hunk matching with
//! whitespace-tolerant fallback, and deterministic rollback from backup snapshots.

use std::{fs, path::Path};

use crate::diff::error::{DiffError, DiffErrorKind};

/// Result of applying a diff hunk to in-memory content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatchOutcome {
    /// Resulting content after applying the patch.
    pub patched_content: String,
    /// Whether the replacement hunk was already present in the source.
    pub already_patched: bool,
}

/// Result of applying a patch to a workspace file on disk.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PatchFileResult {
    /// Relative or absolute path of the target file.
    pub target_path: String,
    /// Absolute path of the safety backup file created before patching.
    pub backup_path: Option<String>,
    /// Whether the file was already in the patched state.
    pub already_patched: bool,
}

/// Applies unified diff hunk lines to the provided source content.
///
/// Preserves the original line ending format (CRLF vs LF).
pub fn apply_hunk_to_content(
    original_content: &str,
    diff_text: &str,
) -> Result<PatchOutcome, DiffError> {
    let is_crlf = original_content.contains("\r\n");
    let norm_original = original_content.replace("\r\n", "\n");
    let diff_lines: Vec<&str> = diff_text.lines().collect();

    let mut minus_lines = Vec::new();
    let mut plus_lines = Vec::new();

    for line in diff_lines {
        let trimmed_line = line.trim_end_matches('\r');
        if trimmed_line.starts_with("---")
            || trimmed_line.starts_with("+++")
            || trimmed_line.starts_with("@@")
        {
            continue;
        }
        if let Some(stripped) = trimmed_line.strip_prefix('-') {
            minus_lines.push(stripped);
        } else if let Some(stripped) = trimmed_line.strip_prefix('+') {
            plus_lines.push(stripped);
        }
    }

    let target_block = minus_lines.join("\n").trim().to_string();
    let replacement_block = plus_lines.join("\n").trim().to_string();

    if target_block.is_empty() && replacement_block.is_empty() {
        return Err(DiffError::invalid_snapshot("Diff contains no hunk changes"));
    }

    // 1. Check if replacement is already in original (already patched)
    if !replacement_block.is_empty() && norm_original.contains(&replacement_block) {
        return Ok(PatchOutcome {
            patched_content: original_content.to_string(),
            already_patched: true,
        });
    }

    // 2. Exact block match
    if !target_block.is_empty() && norm_original.contains(&target_block) {
        let patched_norm = norm_original.replace(&target_block, &replacement_block);
        let final_content = if is_crlf {
            patched_norm.replace('\n', "\r\n")
        } else {
            patched_norm
        };
        return Ok(PatchOutcome {
            patched_content: final_content,
            already_patched: false,
        });
    }

    // 3. Fuzzy line-by-line fallback with whitespace tolerance
    if !minus_lines.is_empty() {
        let content_lines: Vec<&str> = norm_original.lines().collect();
        let mut match_start_idx = None;

        if content_lines.len() >= minus_lines.len() {
            for i in 0..=(content_lines.len() - minus_lines.len()) {
                let mut all_match = true;
                for (j, minus_line) in minus_lines.iter().enumerate() {
                    if content_lines[i + j].trim() != minus_line.trim() {
                        all_match = false;
                        break;
                    }
                }
                if all_match {
                    match_start_idx = Some(i);
                    break;
                }
            }
        }

        if let Some(start_idx) = match_start_idx {
            let leading_ws = content_lines[start_idx]
                .chars()
                .take_while(|c| c.is_whitespace() && *c != '\n' && *c != '\r')
                .collect::<String>();

            let mut new_lines = Vec::new();
            for (idx, line) in content_lines.iter().enumerate() {
                if idx == start_idx {
                    for plus in &plus_lines {
                        new_lines.push(format!("{}{}", leading_ws, plus.trim()));
                    }
                } else if idx > start_idx && idx < start_idx + minus_lines.len() {
                    // Skip replaced minus lines
                    continue;
                } else {
                    new_lines.push((*line).to_string());
                }
            }

            let patched_norm = new_lines.join("\n");
            let final_content = if is_crlf {
                patched_norm.replace('\n', "\r\n")
            } else {
                patched_norm
            };
            return Ok(PatchOutcome {
                patched_content: final_content,
                already_patched: false,
            });
        }
    }

    Err(DiffError::invalid_snapshot(
        "Target hunk lines not found in source file",
    ))
}

/// Applies a patch diff to a workspace file on disk with path traversal guards and atomic backup creation.
pub fn apply_patch_file(
    workspace_root: &Path,
    relative_target: &Path,
    diff_text: &str,
    backup_dir: Option<&Path>,
) -> Result<PatchFileResult, DiffError> {
    let canonical_ws = fs::canonicalize(workspace_root)
        .map_err(|e| DiffError::new(DiffErrorKind::Io(e.to_string())))?;

    let clean_rel = relative_target
        .to_str()
        .unwrap_or_default()
        .trim_start_matches("a/")
        .trim_start_matches("b/")
        .trim_start_matches('/')
        .trim_start_matches('\\');

    let full_target = canonical_ws.join(clean_rel);

    if !full_target.exists() {
        return Err(DiffError::invalid_snapshot(format!(
            "Target file does not exist: {}",
            full_target.display()
        )));
    }

    let canonical_target = fs::canonicalize(&full_target)
        .map_err(|e| DiffError::new(DiffErrorKind::Io(e.to_string())))?;

    // Strict path traversal containment check
    if !canonical_target.starts_with(&canonical_ws) {
        return Err(DiffError::invalid_snapshot(
            "Path traversal violation: target file escapes workspace root boundary",
        ));
    }

    let original_content = fs::read_to_string(&canonical_target)
        .map_err(|e| DiffError::new(DiffErrorKind::Io(e.to_string())))?;

    // Create backup file if backup directory is provided
    let backup_path = if let Some(b_dir) = backup_dir {
        fs::create_dir_all(b_dir).map_err(|e| DiffError::new(DiffErrorKind::Io(e.to_string())))?;
        let file_stem = canonical_target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file");
        let timestamp = crate::TimestampUtc::now().as_epoch_millis();
        let backup_file = b_dir.join(format!("{file_stem}_{timestamp}.bak"));
        fs::write(&backup_file, original_content.as_bytes())
            .map_err(|e| DiffError::new(DiffErrorKind::Io(e.to_string())))?;
        Some(backup_file.to_string_lossy().to_string())
    } else {
        None
    };

    let outcome = apply_hunk_to_content(&original_content, diff_text)?;

    if !outcome.already_patched {
        fs::write(&canonical_target, outcome.patched_content.as_bytes())
            .map_err(|e| DiffError::new(DiffErrorKind::Io(e.to_string())))?;
    }

    Ok(PatchFileResult {
        target_path: clean_rel.to_string(),
        backup_path,
        already_patched: outcome.already_patched,
    })
}

/// Deterministically rolls back a target file using an existing backup snapshot.
pub fn rollback_patch_file(
    workspace_root: &Path,
    relative_target: &Path,
    backup_file: &Path,
) -> Result<(), DiffError> {
    let canonical_ws = fs::canonicalize(workspace_root)
        .map_err(|e| DiffError::new(DiffErrorKind::Io(e.to_string())))?;

    let clean_rel = relative_target
        .to_str()
        .unwrap_or_default()
        .trim_start_matches("a/")
        .trim_start_matches("b/")
        .trim_start_matches('/')
        .trim_start_matches('\\');

    let full_target = canonical_ws.join(clean_rel);

    if !backup_file.exists() {
        return Err(DiffError::invalid_snapshot(format!(
            "Backup file does not exist: {}",
            backup_file.display()
        )));
    }

    let canonical_target = if full_target.exists() {
        fs::canonicalize(&full_target)
            .map_err(|e| DiffError::new(DiffErrorKind::Io(e.to_string())))?
    } else {
        full_target
    };

    if !canonical_target.starts_with(&canonical_ws) {
        return Err(DiffError::invalid_snapshot(
            "Path traversal violation: target file escapes workspace root boundary",
        ));
    }

    let backup_content = fs::read_to_string(backup_file)
        .map_err(|e| DiffError::new(DiffErrorKind::Io(e.to_string())))?;

    fs::write(&canonical_target, backup_content.as_bytes())
        .map_err(|e| DiffError::new(DiffErrorKind::Io(e.to_string())))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_hunk_exact() {
        let original = "fn main() {\n    let old = 1;\n    println!(\"{}\", old);\n}\n";
        let diff =
            "--- a/main.rs\n+++ b/main.rs\n@@ -2,1 +2,1 @@\n-    let old = 1;\n+    let new = 2;\n";
        let res = apply_hunk_to_content(original, diff).expect("patch should apply");
        assert!(!res.already_patched);
        assert!(res.patched_content.contains("let new = 2;"));
        assert!(!res.patched_content.contains("let old = 1;"));
    }

    #[test]
    fn test_apply_hunk_already_patched() {
        let original = "fn main() {\n    let new = 2;\n    println!(\"{}\", new);\n}\n";
        let diff =
            "--- a/main.rs\n+++ b/main.rs\n@@ -2,1 +2,1 @@\n-    let old = 1;\n+    let new = 2;\n";
        let res =
            apply_hunk_to_content(original, diff).expect("patch should detect already patched");
        assert!(res.already_patched);
        assert_eq!(res.patched_content, original);
    }

    #[test]
    fn test_apply_hunk_fuzzy_whitespace() {
        let original = "class Service {\n        let secret = \"hardcoded\";\n}";
        let diff = "- let secret = \"hardcoded\";\n+ let secret = process.env.SECRET;\n";
        let res = apply_hunk_to_content(original, diff)
            .expect("patch should apply with fuzzy whitespace");
        assert!(
            res.patched_content
                .contains("let secret = process.env.SECRET;")
        );
    }
}
