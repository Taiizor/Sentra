//! Filesystem primitives for the skill installer.
//!
//! Every write is change-detecting (identical content is left untouched),
//! atomic (temporary file in the destination directory, then rename), and
//! non-destructive (differing existing content is copied to a `<file>.bak`
//! backup that never overwrites an earlier, different backup).

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::skills::install_text::{normalize_newlines, same_text_ignoring_newlines};

/// Maximum number of numbered backup slots probed before giving up.
const MAX_BACKUP_SLOTS: u32 = 1000;

/// Outcome of writing one managed file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileStatus {
    /// The file did not exist and was created.
    Created,
    /// The file existed with different content and was replaced (after a backup).
    Updated,
    /// The file already had the expected content and was not touched.
    Unchanged,
}

impl FileStatus {
    /// Stable lower-case identifier used in JSON output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Unchanged => "unchanged",
        }
    }
}

/// Result of [`write_file_preserving`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WriteOutcome {
    pub status: FileStatus,
    pub backup: Option<PathBuf>,
}

/// Writes `contents` to `path` unless the file already holds exactly these bytes.
///
/// Existing differing content is backed up first; the write itself is atomic.
/// Refuses to replace directories and symbolic links.
#[cfg(test)]
pub(crate) fn write_file_preserving(path: &Path, contents: &[u8]) -> io::Result<WriteOutcome> {
    write_file_preserving_backed_up_as(path, contents, path)
}

/// Like [`write_file_preserving`], but differing existing content is backed up
/// to `<backup_stem>.bak` (`.bak.1`, ...) instead of next to `path`.
///
/// Skill files use this so backups land outside the directory an agent loads
/// as the skill (agents such as Amp search skill directories recursively).
pub(crate) fn write_file_preserving_backed_up_as(
    path: &Path,
    contents: &[u8],
    backup_stem: &Path,
) -> io::Result<WriteOutcome> {
    let existing = read_regular_file(path)?;
    if existing.as_deref() == Some(contents) {
        return Ok(WriteOutcome {
            status: FileStatus::Unchanged,
            backup: None,
        });
    }

    let parent = parent_dir(path)?;
    fs::create_dir_all(parent)?;

    let backup = match &existing {
        Some(bytes) => {
            fs::create_dir_all(parent_dir(backup_stem)?)?;
            Some(backup_existing(backup_stem, bytes)?)
        }
        None => None,
    };
    write_atomic(path, contents)?;

    Ok(WriteOutcome {
        status: if existing.is_some() {
            FileStatus::Updated
        } else {
            FileStatus::Created
        },
        backup,
    })
}

/// Reads `path` if it is a regular file. Returns `Ok(None)` when it does not exist.
pub(crate) fn read_regular_file(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to replace symbolic link {}; remove or resolve it first",
                path.display()
            ),
        )),
        Ok(meta) if meta.is_dir() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "expected a file but found a directory at {}",
                path.display()
            ),
        )),
        Ok(_) => fs::read(path).map(Some),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Copies `existing` into the first free (or identical) backup slot next to `path`
/// (the file itself or a backup stem): `<file>.bak`, then `<file>.bak.1`, `<file>.bak.2`, ...
pub(crate) fn backup_existing(path: &Path, existing: &[u8]) -> io::Result<PathBuf> {
    for slot in 0..MAX_BACKUP_SLOTS {
        let candidate = backup_slot(path, slot)?;
        match fs::read(&candidate) {
            Ok(bytes) if bytes == existing => return Ok(candidate),
            Ok(_) => continue,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&candidate)?;
                file.write_all(existing)?;
                file.sync_all()?;
                return Ok(candidate);
            }
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::other(format!(
        "no free backup slot for {} (tried {MAX_BACKUP_SLOTS})",
        path.display()
    )))
}

/// Atomically replaces `path` with `contents` (temporary file in the same directory + rename).
pub(crate) fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let parent = parent_dir(path)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| invalid_path(path))?
        .to_string_lossy();
    let tmp = parent.join(format!(
        ".{file_name}.sentra-tmp-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));

    let result = write_temp_then_rename(&tmp, path, contents);
    if result.is_err() {
        // Best-effort cleanup of the temporary file; the original error is returned.
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn write_temp_then_rename(tmp: &Path, path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    if let Ok(meta) = fs::metadata(path) {
        fs::set_permissions(tmp, meta.permissions())?;
    }
    fs::rename(tmp, path)
}

/// Action taken on an artifact written by an earlier Sentra installer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyAction {
    /// A `<!-- sentra-skill: <id> -->` block was removed from an always-on rule file.
    RemovedBlock,
    /// A stale per-skill file identical to the bundled playbook was deleted.
    RemovedFile,
    /// A Sentra marker block was found but differs from the bundled playbook; left in place.
    KeptModifiedBlock,
    /// A legacy per-skill file differs from the bundled playbook; left in place.
    KeptModifiedFile,
}

impl LegacyAction {
    /// Stable snake-case identifier used in JSON output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RemovedBlock => "removed_block",
            Self::RemovedFile => "removed_file",
            Self::KeptModifiedBlock => "kept_modified_block",
            Self::KeptModifiedFile => "kept_modified_file",
        }
    }

    /// Whether the artifact still needs a manual decision by the user.
    pub const fn needs_manual_review(self) -> bool {
        matches!(self, Self::KeptModifiedBlock | Self::KeptModifiedFile)
    }
}

/// One legacy artifact handled during installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyCleanup {
    /// File that contained the artifact.
    pub path: PathBuf,
    /// Skill the artifact belonged to.
    pub skill_id: &'static str,
    /// What the installer did.
    pub action: LegacyAction,
    /// Backup written before the file was modified or deleted, if any.
    pub backup: Option<PathBuf>,
}

/// Removes legacy `<!-- sentra-skill: <id> -->` blocks appended by earlier Sentra
/// versions to an always-on rule file (`.cursorrules`, `CONVENTIONS.md`, ...).
///
/// A block is removed only when the text after the marker matches the bundled
/// playbook exactly (line endings aside), so user-edited text is never dropped.
/// The file is backed up before it is rewritten; a file left holding only
/// whitespace is deleted (after the backup) so it no longer shadows other
/// instruction files.
pub(crate) fn remove_legacy_blocks(
    path: &Path,
    skills: &[(&'static str, &'static str)],
) -> io::Result<Vec<LegacyCleanup>> {
    // Only regular files are inspected: `.clinerules` may legitimately be a
    // directory, and symbolic links are never rewritten.
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return Ok(Vec::new()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    }
    let Ok(original) = String::from_utf8(fs::read(path)?) else {
        return Ok(Vec::new());
    };

    let mut text = original.clone();
    let mut actions = Vec::new();
    for &(skill_id, content) in skills {
        let marker = format!("<!-- sentra-skill: {skill_id} -->");
        if !text.contains(&marker) {
            continue;
        }
        let mut removed_any = false;
        while let Some(updated) = remove_one_block(&text, &marker, content) {
            text = updated;
            removed_any = true;
        }
        let action = if text.contains(&marker) {
            LegacyAction::KeptModifiedBlock
        } else {
            LegacyAction::RemovedBlock
        };
        if removed_any || action == LegacyAction::KeptModifiedBlock {
            actions.push((skill_id, action));
        }
    }

    if text == original {
        return Ok(actions
            .into_iter()
            .map(|(skill_id, action)| LegacyCleanup {
                path: path.to_path_buf(),
                skill_id,
                action,
                backup: None,
            })
            .collect());
    }

    let backup = backup_existing(path, original.as_bytes())?;
    if text.trim().is_empty() {
        fs::remove_file(path)?;
    } else {
        write_atomic(path, text.as_bytes())?;
    }
    Ok(actions
        .into_iter()
        .map(|(skill_id, action)| LegacyCleanup {
            path: path.to_path_buf(),
            skill_id,
            action,
            backup: (action == LegacyAction::RemovedBlock).then(|| backup.clone()),
        })
        .collect())
}

/// Deletes a legacy per-skill file when it is identical (line endings aside) to the
/// bundled playbook. Removes the containing directory too when `remove_empty_parent`
/// is set and the directory is left empty.
pub(crate) fn remove_legacy_file(
    path: &Path,
    skill_id: &'static str,
    content: &str,
    remove_empty_parent: bool,
) -> io::Result<Option<LegacyCleanup>> {
    let existing = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => fs::read(path)?,
        Ok(_) => return Ok(None),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    if !same_text_ignoring_newlines(&existing, content.as_bytes()) {
        return Ok(Some(LegacyCleanup {
            path: path.to_path_buf(),
            skill_id,
            action: LegacyAction::KeptModifiedFile,
            backup: None,
        }));
    }

    fs::remove_file(path)?;
    if remove_empty_parent && let Some(parent) = path.parent() {
        remove_dir_if_empty(parent)?;
    }
    Ok(Some(LegacyCleanup {
        path: path.to_path_buf(),
        skill_id,
        action: LegacyAction::RemovedFile,
        backup: None,
    }))
}

fn remove_dir_if_empty(dir: &Path) -> io::Result<()> {
    if fs::read_dir(dir)?.next().is_some() {
        return Ok(());
    }
    fs::remove_dir(dir)
}

/// Removes the first exact legacy block `"\n<marker>\n<content>\n"` (line endings
/// aside) following `marker`. Returns `None` when no exact block exists.
fn remove_one_block(text: &str, marker: &str, content: &str) -> Option<String> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let expected_tail = format!("{}\n", normalize_newlines(content));
    let expected: Vec<&str> = expected_tail.split_inclusive('\n').map(trim_eol).collect();

    for (index, line) in lines.iter().enumerate() {
        if trim_eol(line) != marker {
            continue;
        }
        let body_start = index + 1;
        let body_end = body_start + expected.len();
        if body_end > lines.len() {
            continue;
        }
        let matches = lines[body_start..body_end]
            .iter()
            .zip(&expected)
            .all(|(actual, wanted)| trim_eol(actual) == *wanted);
        if !matches {
            continue;
        }
        let start = if index > 0 && trim_eol(lines[index - 1]).is_empty() {
            index - 1
        } else {
            index
        };
        let mut out = String::with_capacity(text.len());
        for piece in lines[..start].iter().chain(&lines[body_end..]) {
            out.push_str(piece);
        }
        return Some(out);
    }
    None
}

fn trim_eol(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

fn backup_slot(path: &Path, slot: u32) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| invalid_path(path))?
        .to_string_lossy();
    let file = if slot == 0 {
        format!("{name}.bak")
    } else {
        format!("{name}.bak.{slot}")
    };
    Ok(parent_dir(path)?.join(file))
}

fn parent_dir(path: &Path) -> io::Result<&Path> {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| invalid_path(path))
}

fn invalid_path(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid destination path {}", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sentra-install-fs-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_is_idempotent_and_backs_up_changes() {
        let dir = temp_dir("write");
        let file = dir.join("a").join("SKILL.md");

        let first = write_file_preserving(&file, b"one").unwrap();
        assert_eq!(first.status, FileStatus::Created);
        let again = write_file_preserving(&file, b"one").unwrap();
        assert_eq!(again.status, FileStatus::Unchanged);

        let changed = write_file_preserving(&file, b"two").unwrap();
        assert_eq!(changed.status, FileStatus::Updated);
        let backup = changed.backup.unwrap();
        assert_eq!(fs::read(&backup).unwrap(), b"one");

        // A second change must not clobber the first backup.
        let third = write_file_preserving(&file, b"three").unwrap();
        let backup2 = third.backup.unwrap();
        assert_ne!(backup, backup2);
        assert_eq!(fs::read(&backup).unwrap(), b"one");
        assert_eq!(fs::read(&backup2).unwrap(), b"two");
        assert_eq!(fs::read(&file).unwrap(), b"three");

        let leftovers: Vec<_> = fs::read_dir(file.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains("sentra-tmp"))
            .collect();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn backups_can_live_outside_the_written_directory() {
        let dir = temp_dir("stem");
        let file = dir.join("skills").join("a").join("SKILL.md");
        let stem = dir
            .join("skills")
            .join(".sentra-backups")
            .join("a")
            .join("SKILL.md");
        write_file_preserving_backed_up_as(&file, b"one", &stem).unwrap();
        let changed = write_file_preserving_backed_up_as(&file, b"two", &stem).unwrap();
        assert_eq!(changed.status, FileStatus::Updated);
        let backup = changed.backup.unwrap();
        assert_eq!(backup, stem.with_file_name("SKILL.md.bak"));
        assert_eq!(fs::read(&backup).unwrap(), b"one");
        assert_eq!(fs::read_dir(file.parent().unwrap()).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_to_replace_directories() {
        let dir = temp_dir("dir");
        let target = dir.join(".clinerules");
        fs::create_dir_all(&target).unwrap();
        assert!(write_file_preserving(&target, b"x").is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn removes_only_exact_legacy_blocks() {
        let dir = temp_dir("blocks");
        let file = dir.join(".cursorrules");
        let content = "---\r\nname: a\r\n---\r\n# A\r\n";
        let original = format!(
            "user rule\n\n<!-- sentra-skill: a -->\n{content}\n\n<!-- sentra-skill: b -->\nedited\n"
        );
        fs::write(&file, &original).unwrap();

        let actions =
            remove_legacy_blocks(&file, &[("a", content), ("b", "# B original\n")]).unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].action, LegacyAction::RemovedBlock);
        assert_eq!(actions[1].action, LegacyAction::KeptModifiedBlock);
        let remaining = fs::read_to_string(&file).unwrap();
        assert_eq!(remaining, "user rule\n\n<!-- sentra-skill: b -->\nedited\n");
        let backup = actions[0].backup.clone().unwrap();
        assert_eq!(fs::read_to_string(backup).unwrap(), original);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn deletes_rule_file_left_empty_after_block_removal() {
        let dir = temp_dir("empty");
        let file = dir.join(".windsurfrules");
        fs::write(&file, "\n<!-- sentra-skill: a -->\n# A\n\n").unwrap();
        let actions = remove_legacy_blocks(&file, &[("a", "# A\n")]).unwrap();
        assert_eq!(actions[0].action, LegacyAction::RemovedBlock);
        assert!(!file.exists());
        assert!(actions[0].backup.as_ref().unwrap().exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_files_are_removed_only_when_identical() {
        let dir = temp_dir("files");
        let same = dir.join("x").join("SKILL.md");
        fs::create_dir_all(same.parent().unwrap()).unwrap();
        fs::write(&same, "a\r\nb\r\n").unwrap();
        let removed = remove_legacy_file(&same, "x", "a\nb\n", true)
            .unwrap()
            .unwrap();
        assert_eq!(removed.action, LegacyAction::RemovedFile);
        assert!(!same.parent().unwrap().exists());

        let edited = dir.join("y.md");
        fs::write(&edited, "mine").unwrap();
        let kept = remove_legacy_file(&edited, "y", "theirs", false)
            .unwrap()
            .unwrap();
        assert_eq!(kept.action, LegacyAction::KeptModifiedFile);
        assert!(edited.exists());
        assert!(
            remove_legacy_file(&dir.join("missing.md"), "z", "", false)
                .unwrap()
                .is_none()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
