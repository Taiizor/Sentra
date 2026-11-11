//! Positional unified-diff application and backup/rollback engine.
//!
//! A patch is applied only when every hunk's context and removed lines match the
//! target exactly at the position named by its `@@ -a,b +c,d @@` header, or within
//! a bounded line offset of it ([`MAX_HUNK_OFFSET_LINES`]). Either every hunk
//! applies or nothing is written. There is no whitespace fuzzing, no context
//! dropping and no re-indentation; the target's line endings and UTF-8 byte-order
//! mark are preserved, and added lines use the target's dominant line ending.
//!
//! A patch counts as already applied only when it does not apply forward and the
//! post-image of every hunk is found at its own position. When both the pre-image
//! and the post-image match equally well the state is ambiguous and is refused.
//!
//! Targets are resolved through [`WorkspaceBoundary`]: only ordinary files inside
//! the workspace are accepted, and no symbolic link or junction is followed.

use std::{
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use crate::{
    SecurityClassification, SessionId, TimestampUtc,
    common::sha256_digest,
    diff::error::{DiffError, DiffErrorKind},
    workspace::{WorkspaceBoundary, WorkspaceEntryKind, classify_entry_metadata},
};

/// Maximum number of lines a hunk may be found away from its header position.
pub const MAX_HUNK_OFFSET_LINES: usize = 200;
/// Maximum accepted unified diff size in bytes.
pub const MAX_PATCH_BYTES: usize = 4 * 1024 * 1024;
/// Maximum size in bytes of a patch target or rollback backup file.
pub const MAX_PATCH_TARGET_BYTES: u64 = 16 * 1024 * 1024;
/// Maximum number of hunks accepted in one patch.
pub const MAX_PATCH_HUNKS: usize = 2_000;

const UTF8_BOM: &str = "\u{feff}";
const MAX_HUNK_LINE_COUNT: usize = 10_000_000;

/// Result of applying a unified diff to in-memory content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatchOutcome {
    /// Resulting content; identical to the input when `already_patched` is true.
    pub patched_content: String,
    /// True only when the patch does not apply forward and every hunk's
    /// post-image is already present at its own position.
    pub already_patched: bool,
    /// Number of hunks in the patch.
    pub hunks: usize,
}

/// Result of applying (or dry-running) a patch against a workspace file.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PatchFileResult {
    /// Workspace-relative target path with forward slashes.
    pub target_path: String,
    /// Backup of the pre-image, when one was requested and the file changed.
    pub backup_path: Option<String>,
    /// Whether the file was already in the patched state (nothing was written).
    pub already_patched: bool,
    /// True when the patch was validated but nothing was written.
    pub dry_run: bool,
    /// Number of hunks in the patch.
    pub hunks: usize,
    /// SHA-256 (hex) of the unified diff text.
    pub patch_sha256: String,
    /// SHA-256 (hex) of the target bytes before the patch.
    pub pre_image_sha256: String,
    /// SHA-256 (hex) of the target bytes after the patch (or that would result).
    pub post_image_sha256: String,
}

/// Result of restoring a workspace file from a backup.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PatchRollbackResult {
    /// Workspace-relative target path with forward slashes.
    pub target_path: String,
    /// Backup file the content was restored from.
    pub restored_from: String,
    /// SHA-256 (hex) of the target bytes before the rollback.
    pub pre_image_sha256: String,
    /// SHA-256 (hex) of the restored target bytes.
    pub post_image_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum HunkLine {
    Context(String),
    Removed(String),
    Added(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Old,
    New,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Hunk {
    old_start: usize,
    old_count: usize,
    new_start: usize,
    new_count: usize,
    lines: Vec<HunkLine>,
    old_without_final_newline: bool,
    new_without_final_newline: bool,
}

impl Hunk {
    fn image(&self, side: Side) -> Vec<&str> {
        self.lines
            .iter()
            .filter_map(|line| match (line, side) {
                (HunkLine::Context(text), _)
                | (HunkLine::Removed(text), Side::Old)
                | (HunkLine::Added(text), Side::New) => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Zero-based index of the first image line; for an empty image, the index
    /// the insertion happens before (`-a,0` means "after line a").
    fn base_index(&self, side: Side) -> usize {
        let (start, count) = match side {
            Side::Old => (self.old_start, self.old_count),
            Side::New => (self.new_start, self.new_count),
        };
        if count == 0 { start } else { start - 1 }
    }

    fn unterminated(&self, side: Side) -> bool {
        match side {
            Side::Old => self.old_without_final_newline,
            Side::New => self.new_without_final_newline,
        }
    }

    fn ends_at_eof(&self) -> bool {
        self.old_without_final_newline || self.new_without_final_newline
    }

    fn header(&self) -> String {
        format!(
            "@@ -{},{} +{},{} @@",
            self.old_start, self.old_count, self.new_start, self.new_count
        )
    }
}

/// A parsed, single-file unified diff. Parsing never touches the filesystem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnifiedPatch {
    target: Option<String>,
    hunks: Vec<Hunk>,
    sha256: String,
}

#[derive(Clone, Copy)]
struct SourceLine<'a> {
    text: &'a str,
    eol: &'static str,
}

struct Placement {
    positions: Vec<usize>,
    distance: usize,
}

impl UnifiedPatch {
    /// Parse a unified diff for exactly one file. Header line counts are enforced,
    /// so body lines that start with `---` or `+++` are treated as content.
    pub fn parse(text: &str) -> Result<Self, DiffError> {
        if text.len() > MAX_PATCH_BYTES {
            return Err(DiffError::limits_exceeded(format!(
                "patch exceeds {MAX_PATCH_BYTES} bytes"
            )));
        }
        let mut lines = text.lines().peekable();
        let mut hunks: Vec<Hunk> = Vec::new();
        let mut old_header: Option<HeaderPath> = None;
        let mut new_header: Option<HeaderPath> = None;
        while let Some(raw) = lines.next() {
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            if line.starts_with("@@") {
                if hunks.len() >= MAX_PATCH_HUNKS {
                    return Err(DiffError::limits_exceeded(format!(
                        "patch has more than {MAX_PATCH_HUNKS} hunks"
                    )));
                }
                let hunk = parse_hunk(line, &mut lines)?;
                if let Some(previous) = hunks.last()
                    && hunk.old_start < previous.old_start + previous.old_count
                {
                    return Err(DiffError::invalid_patch(
                        "hunks overlap or are not in ascending order",
                    ));
                }
                hunks.push(hunk);
            } else if let Some(rest) = line.strip_prefix("--- ") {
                if !hunks.is_empty() || old_header.is_some() {
                    return Err(DiffError::invalid_patch(
                        "multi-file patches are not supported",
                    ));
                }
                old_header = Some(HeaderPath::parse(rest, "a/"));
            } else if let Some(rest) = line.strip_prefix("+++ ") {
                if !hunks.is_empty() || new_header.is_some() {
                    return Err(DiffError::invalid_patch(
                        "multi-file patches are not supported",
                    ));
                }
                new_header = Some(HeaderPath::parse(rest, "b/"));
            } else if line.starts_with("diff ") {
                if !hunks.is_empty() {
                    return Err(DiffError::invalid_patch(
                        "multi-file patches are not supported",
                    ));
                }
            } else if line.starts_with("GIT binary patch") || line.starts_with("Binary files ") {
                return Err(DiffError::invalid_patch("binary patches are not supported"));
            }
            // Any other line outside a hunk (index, mode, commit message, signature)
            // carries no hunk data and is ignored.
        }
        if matches!(old_header, Some(HeaderPath::DevNull))
            || matches!(new_header, Some(HeaderPath::DevNull))
        {
            return Err(DiffError::invalid_patch(
                "file creation and deletion patches are not supported",
            ));
        }
        if hunks.is_empty() {
            return Err(DiffError::invalid_patch("patch contains no hunks"));
        }
        let target = match (new_header, old_header) {
            (Some(HeaderPath::Path(path)), _) | (_, Some(HeaderPath::Path(path))) => Some(path),
            _ => None,
        };
        Ok(Self {
            target,
            hunks,
            sha256: sha256_digest(text.as_bytes()),
        })
    }

    /// Number of hunks.
    pub fn hunk_count(&self) -> usize {
        self.hunks.len()
    }

    /// Target path named by the `+++` (or `---`) header with any `b/` (`a/`) prefix
    /// removed. Untrusted text: callers must resolve it through a workspace boundary.
    pub fn target_path(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// SHA-256 (hex) of the exact diff text that was parsed.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Apply every hunk to `original` in memory, or report why the patch does not
    /// apply. The input is never partially modified.
    pub fn apply_to(&self, original: &str) -> Result<PatchOutcome, DiffError> {
        let (bom, body) = match original.strip_prefix(UTF8_BOM) {
            Some(rest) => (UTF8_BOM, rest),
            None => ("", original),
        };
        let lines = split_lines(body);
        let forward = self.locate_all(&lines, Side::Old);
        // An empty post-image (context-free deletion) matches anywhere, so it can
        // never prove that the patch is already applied.
        let reverse = if self.hunks.iter().all(|hunk| hunk.new_count > 0) {
            self.locate_all(&lines, Side::New)
        } else {
            Err(DiffError::does_not_apply(
                "the post-image of a context-free deletion cannot be verified",
            ))
        };
        let already_applied = match (&forward, &reverse) {
            (Ok(_), Err(_)) | (Err(_), Err(_)) => false,
            (Err(_), Ok(_)) => true,
            (Ok(f), Ok(r)) => match f.distance.cmp(&r.distance) {
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Equal => {
                    return Err(DiffError::does_not_apply(
                        "both the pre-image and the post-image of every hunk match; \
                         refusing to guess whether the patch is already applied",
                    ));
                }
            },
        };
        if already_applied {
            return Ok(PatchOutcome {
                patched_content: original.to_string(),
                already_patched: true,
                hunks: self.hunks.len(),
            });
        }
        let placement = forward?;
        Ok(PatchOutcome {
            patched_content: self.render(&lines, &placement.positions, bom),
            already_patched: false,
            hunks: self.hunks.len(),
        })
    }

    fn locate_all(&self, lines: &[SourceLine<'_>], side: Side) -> Result<Placement, DiffError> {
        let total = self.hunks.len();
        let mut positions = Vec::with_capacity(total);
        let mut offset: isize = 0;
        let mut min_start = 0usize;
        let mut distance = 0usize;
        for (index, hunk) in self.hunks.iter().enumerate() {
            let image = hunk.image(side);
            let base = hunk.base_index(side);
            let expected = base
                .checked_add_signed(offset)
                .unwrap_or(0)
                .min(lines.len());
            let found = locate(
                lines,
                &image,
                expected,
                min_start,
                hunk.ends_at_eof(),
                hunk.unterminated(side),
            )
            .ok_or_else(|| {
                DiffError::does_not_apply(format!(
                    "hunk {} of {total} ({}) does not match the target within {MAX_HUNK_OFFSET_LINES} lines of line {}",
                    index + 1,
                    hunk.header(),
                    expected + 1
                ))
            })?;
            distance += found.abs_diff(expected);
            offset = found as isize - base as isize;
            min_start = found + image.len();
            positions.push(found);
        }
        Ok(Placement {
            positions,
            distance,
        })
    }

    fn render(&self, lines: &[SourceLine<'_>], positions: &[usize], bom: &str) -> String {
        let eol = dominant_eol(lines);
        let mut out: Vec<(&str, &str)> = Vec::with_capacity(lines.len() + 16);
        let mut cursor = 0usize;
        for (hunk, &start) in self.hunks.iter().zip(positions) {
            out.extend(lines[cursor..start].iter().map(|l| (l.text, l.eol)));
            let mut index = start;
            for line in &hunk.lines {
                match line {
                    HunkLine::Context(_) => {
                        let original = lines[index];
                        out.push((original.text, original.eol));
                        index += 1;
                    }
                    HunkLine::Removed(_) => index += 1,
                    HunkLine::Added(text) => out.push((text.as_str(), eol)),
                }
            }
            if hunk.new_without_final_newline
                && let Some(last) = out.last_mut()
            {
                last.1 = "";
            }
            cursor = index;
        }
        out.extend(lines[cursor..].iter().map(|l| (l.text, l.eol)));
        // Only the final line of a file may lack a terminator.
        let count = out.len();
        let mut rendered = String::with_capacity(
            bom.len() + out.iter().map(|(t, e)| t.len() + e.len()).sum::<usize>() + count,
        );
        rendered.push_str(bom);
        for (index, (text, line_eol)) in out.into_iter().enumerate() {
            rendered.push_str(text);
            if line_eol.is_empty() && index + 1 < count {
                rendered.push_str(eol);
            } else {
                rendered.push_str(line_eol);
            }
        }
        rendered
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum HeaderPath {
    DevNull,
    Path(String),
    Unsupported,
}

impl HeaderPath {
    fn parse(rest: &str, git_prefix: &str) -> Self {
        // `diff -u` appends a tab and a timestamp after the name.
        let raw = rest.split('\t').next().unwrap_or_default().trim_end();
        if raw == "/dev/null" {
            return Self::DevNull;
        }
        let unquoted = if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
            let inner = &raw[1..raw.len() - 1];
            if inner.contains('\\') {
                // C-style escaped names are not decoded; the caller must pass --target.
                return Self::Unsupported;
            }
            inner
        } else {
            raw
        };
        let path = unquoted.strip_prefix(git_prefix).unwrap_or(unquoted);
        if path.is_empty() {
            Self::Unsupported
        } else {
            Self::Path(path.to_string())
        }
    }
}

fn parse_hunk<'a>(
    header: &str,
    lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
) -> Result<Hunk, DiffError> {
    let (old_start, old_count, new_start, new_count) = parse_hunk_header(header)?;
    let mut hunk = Hunk {
        old_start,
        old_count,
        new_start,
        new_count,
        lines: Vec::new(),
        old_without_final_newline: false,
        new_without_final_newline: false,
    };
    let mut old_seen = 0usize;
    let mut new_seen = 0usize;
    while old_seen < old_count || new_seen < new_count {
        let raw = lines.next().ok_or_else(|| {
            DiffError::invalid_patch(format!(
                "hunk {} ends before its header line counts are satisfied",
                hunk.header()
            ))
        })?;
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.starts_with('\\') {
            mark_missing_newline(&mut hunk)?;
            continue;
        }
        let entry = match line.chars().next() {
            Some(' ') => HunkLine::Context(line[1..].to_string()),
            Some('-') => HunkLine::Removed(line[1..].to_string()),
            Some('+') => HunkLine::Added(line[1..].to_string()),
            // Some tools strip the single space of an empty context line.
            None => HunkLine::Context(String::new()),
            Some(_) => {
                return Err(DiffError::invalid_patch(format!(
                    "unexpected line inside hunk {}",
                    hunk.header()
                )));
            }
        };
        let (uses_old, uses_new) = match entry {
            HunkLine::Context(_) => (true, true),
            HunkLine::Removed(_) => (true, false),
            HunkLine::Added(_) => (false, true),
        };
        if (uses_old && hunk.old_without_final_newline)
            || (uses_new && hunk.new_without_final_newline)
        {
            return Err(DiffError::invalid_patch(
                "content follows a \"No newline at end of file\" marker",
            ));
        }
        old_seen += usize::from(uses_old);
        new_seen += usize::from(uses_new);
        if old_seen > old_count || new_seen > new_count {
            return Err(DiffError::invalid_patch(format!(
                "hunk {} body does not match its header line counts",
                hunk.header()
            )));
        }
        hunk.lines.push(entry);
    }
    while lines.peek().is_some_and(|next| next.starts_with('\\')) {
        lines.next();
        mark_missing_newline(&mut hunk)?;
    }
    if !hunk
        .lines
        .iter()
        .any(|line| matches!(line, HunkLine::Removed(_) | HunkLine::Added(_)))
    {
        return Err(DiffError::invalid_patch(format!(
            "hunk {} contains no changes",
            hunk.header()
        )));
    }
    Ok(hunk)
}

fn mark_missing_newline(hunk: &mut Hunk) -> Result<(), DiffError> {
    match hunk.lines.last() {
        Some(HunkLine::Context(_)) => {
            hunk.old_without_final_newline = true;
            hunk.new_without_final_newline = true;
        }
        Some(HunkLine::Removed(_)) => hunk.old_without_final_newline = true,
        Some(HunkLine::Added(_)) => hunk.new_without_final_newline = true,
        None => {
            return Err(DiffError::invalid_patch(
                "\"No newline at end of file\" marker without a preceding line",
            ));
        }
    }
    Ok(())
}

fn parse_hunk_header(line: &str) -> Result<(usize, usize, usize, usize), DiffError> {
    let invalid = || DiffError::invalid_patch("malformed hunk header");
    if line.starts_with("@@@") {
        return Err(DiffError::invalid_patch("combined diffs are not supported"));
    }
    let rest = line.strip_prefix("@@ ").ok_or_else(invalid)?;
    let end = rest.find(" @@").ok_or_else(invalid)?;
    let mut ranges = rest[..end].split(' ');
    let old = ranges
        .next()
        .and_then(|r| r.strip_prefix('-'))
        .and_then(parse_range)
        .ok_or_else(invalid)?;
    let new = ranges
        .next()
        .and_then(|r| r.strip_prefix('+'))
        .and_then(parse_range)
        .ok_or_else(invalid)?;
    if ranges.next().is_some()
        || (old.1 > 0 && old.0 == 0)
        || (new.1 > 0 && new.0 == 0)
        || old.1 > MAX_HUNK_LINE_COUNT
        || new.1 > MAX_HUNK_LINE_COUNT
    {
        return Err(invalid());
    }
    Ok((old.0, old.1, new.0, new.1))
}

fn parse_range(text: &str) -> Option<(usize, usize)> {
    let number = |value: &str| {
        (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
            .then(|| value.parse::<usize>().ok())
            .flatten()
    };
    match text.split_once(',') {
        Some((start, count)) => Some((number(start)?, number(count)?)),
        None => Some((number(text)?, 1)),
    }
}

fn split_lines(content: &str) -> Vec<SourceLine<'_>> {
    content
        .split_inclusive('\n')
        .map(|piece| {
            if let Some(text) = piece.strip_suffix("\r\n") {
                SourceLine { text, eol: "\r\n" }
            } else if let Some(text) = piece.strip_suffix('\n') {
                SourceLine { text, eol: "\n" }
            } else {
                SourceLine {
                    text: piece,
                    eol: "",
                }
            }
        })
        .collect()
}

fn dominant_eol(lines: &[SourceLine<'_>]) -> &'static str {
    let crlf = lines.iter().filter(|l| l.eol == "\r\n").count();
    let lf = lines.iter().filter(|l| l.eol == "\n").count();
    if crlf > lf { "\r\n" } else { "\n" }
}

fn locate(
    lines: &[SourceLine<'_>],
    image: &[&str],
    expected: usize,
    min_start: usize,
    ends_at_eof: bool,
    unterminated: bool,
) -> Option<usize> {
    let fits = |start: usize| {
        let Some(end) = start.checked_add(image.len()) else {
            return false;
        };
        start >= min_start
            && end <= lines.len()
            && lines[start..end]
                .iter()
                .zip(image)
                .all(|(line, text)| line.text == *text)
            && (!ends_at_eof || end == lines.len())
            && (!unterminated || lines.last().is_some_and(|line| line.eol.is_empty()))
    };
    if image.is_empty() {
        // A context-free insertion has no content to search for; only the exact
        // header position is acceptable.
        return fits(expected).then_some(expected);
    }
    for delta in 0..=MAX_HUNK_OFFSET_LINES {
        if let Some(candidate) = expected.checked_add(delta)
            && fits(candidate)
        {
            return Some(candidate);
        }
        if delta > 0
            && let Some(candidate) = expected.checked_sub(delta)
            && fits(candidate)
        {
            return Some(candidate);
        }
    }
    None
}

/// Applies a unified diff to in-memory content (positional, exact context,
/// all-or-nothing). Preserves line endings and any UTF-8 byte-order mark.
pub fn apply_hunk_to_content(
    original_content: &str,
    diff_text: &str,
) -> Result<PatchOutcome, DiffError> {
    UnifiedPatch::parse(diff_text)?.apply_to(original_content)
}

/// A fully validated patch application that has not written anything yet.
#[derive(Debug)]
pub struct PatchPlan {
    target_path: String,
    absolute_target: PathBuf,
    original: Vec<u8>,
    outcome: PatchOutcome,
    patch_sha256: String,
    pre_image_sha256: String,
    post_image_sha256: String,
}

impl PatchPlan {
    /// Resolve the target inside the boundary (ordinary file, no indirection), read
    /// it with size limits and apply the patch in memory. Nothing is written.
    pub fn prepare(
        boundary: &WorkspaceBoundary,
        relative_target: &Path,
        patch: &UnifiedPatch,
    ) -> Result<Self, DiffError> {
        let (absolute_target, target_path) = resolve_workspace_file(boundary, relative_target)?;
        let original = read_regular_file(&absolute_target, MAX_PATCH_TARGET_BYTES)?;
        let text = std::str::from_utf8(&original)
            .map_err(|_| DiffError::new(DiffErrorKind::BinaryContent))?;
        let outcome = patch.apply_to(text)?;
        let pre_image_sha256 = sha256_digest(&original);
        let post_image_sha256 = sha256_digest(outcome.patched_content.as_bytes());
        Ok(Self {
            target_path,
            absolute_target,
            original,
            outcome,
            patch_sha256: patch.sha256().to_string(),
            pre_image_sha256,
            post_image_sha256,
        })
    }

    /// Workspace-relative target path with forward slashes.
    pub fn target_path(&self) -> &str {
        &self.target_path
    }

    /// In-memory outcome of the patch.
    pub fn outcome(&self) -> &PatchOutcome {
        &self.outcome
    }

    /// Result describing this plan without writing anything.
    pub fn dry_run_result(&self) -> PatchFileResult {
        self.result(None, true)
    }

    /// Write an optional backup of the pre-image, then the patched content. Refuses
    /// when the target changed since [`PatchPlan::prepare`]. Nothing is written when
    /// the file is already patched.
    pub fn commit(&self, backup_dir: Option<&Path>) -> Result<PatchFileResult, DiffError> {
        if self.outcome.already_patched {
            return Ok(self.result(None, false));
        }
        let current = read_regular_file(&self.absolute_target, MAX_PATCH_TARGET_BYTES)?;
        if current != self.original {
            return Err(DiffError::does_not_apply(
                "target changed after the patch was validated",
            ));
        }
        let backup_path = match backup_dir {
            Some(dir) => Some(write_backup(dir, &self.absolute_target, &self.original)?),
            None => None,
        };
        if let Err(error) = fs::write(
            &self.absolute_target,
            self.outcome.patched_content.as_bytes(),
        ) {
            // Best effort: a failed write may have truncated the file.
            let _ = fs::write(&self.absolute_target, &self.original);
            return Err(DiffError::io(&error));
        }
        Ok(self.result(backup_path.as_deref().map(display_path), false))
    }

    /// Restore the exact pre-image bytes (used when a step after the write fails).
    pub fn revert(&self) -> Result<(), DiffError> {
        if self.outcome.already_patched {
            return Ok(());
        }
        fs::write(&self.absolute_target, &self.original).map_err(|e| DiffError::io(&e))
    }

    fn result(&self, backup_path: Option<String>, dry_run: bool) -> PatchFileResult {
        PatchFileResult {
            target_path: self.target_path.clone(),
            backup_path,
            already_patched: self.outcome.already_patched,
            dry_run,
            hunks: self.outcome.hunks,
            patch_sha256: self.patch_sha256.clone(),
            pre_image_sha256: self.pre_image_sha256.clone(),
            post_image_sha256: self.post_image_sha256.clone(),
        }
    }
}

/// A validated restore of a workspace file from a backup that has not written yet.
#[derive(Debug)]
pub struct RollbackPlan {
    target_path: String,
    absolute_target: PathBuf,
    current: Vec<u8>,
    restored: Vec<u8>,
    restored_from: String,
}

impl RollbackPlan {
    /// Resolve the target inside the boundary and read both the target and the
    /// backup (an ordinary file, no indirection) with size limits.
    pub fn prepare(
        boundary: &WorkspaceBoundary,
        relative_target: &Path,
        backup_file: &Path,
    ) -> Result<Self, DiffError> {
        let (absolute_target, target_path) = resolve_workspace_file(boundary, relative_target)?;
        let restored = read_regular_file(backup_file, MAX_PATCH_TARGET_BYTES).map_err(|error| {
            DiffError::new(DiffErrorKind::InvalidBackup(match error.kind {
                DiffErrorKind::Io(message) => message,
                other => format!("{other:?}"),
            }))
        })?;
        let current = read_regular_file(&absolute_target, MAX_PATCH_TARGET_BYTES)?;
        Ok(Self {
            target_path,
            absolute_target,
            current,
            restored,
            restored_from: display_path(backup_file),
        })
    }

    /// Workspace-relative target path with forward slashes.
    pub fn target_path(&self) -> &str {
        &self.target_path
    }

    /// Write the backup content over the target, refusing when the target changed
    /// since [`RollbackPlan::prepare`].
    pub fn commit(&self) -> Result<PatchRollbackResult, DiffError> {
        let now = read_regular_file(&self.absolute_target, MAX_PATCH_TARGET_BYTES)?;
        if now != self.current {
            return Err(DiffError::invalid_target(
                "target changed after the rollback was validated",
            ));
        }
        if let Err(error) = fs::write(&self.absolute_target, &self.restored) {
            let _ = fs::write(&self.absolute_target, &self.current);
            return Err(DiffError::io(&error));
        }
        Ok(PatchRollbackResult {
            target_path: self.target_path.clone(),
            restored_from: self.restored_from.clone(),
            pre_image_sha256: sha256_digest(&self.current),
            post_image_sha256: sha256_digest(&self.restored),
        })
    }

    /// Restore the content the target had before the rollback.
    pub fn revert(&self) -> Result<(), DiffError> {
        fs::write(&self.absolute_target, &self.current).map_err(|e| DiffError::io(&e))
    }
}

/// Applies a patch to a workspace file: positional hunks with exact context,
/// all-or-nothing, an optional pre-image backup, and no symlink/junction traversal.
pub fn apply_patch_file(
    workspace_root: &Path,
    relative_target: &Path,
    diff_text: &str,
    backup_dir: Option<&Path>,
) -> Result<PatchFileResult, DiffError> {
    let boundary = establish(workspace_root)?;
    let patch = UnifiedPatch::parse(diff_text)?;
    PatchPlan::prepare(&boundary, relative_target, &patch)?.commit(backup_dir)
}

/// Restores a workspace file from a backup snapshot.
pub fn rollback_patch_file(
    workspace_root: &Path,
    relative_target: &Path,
    backup_file: &Path,
) -> Result<PatchRollbackResult, DiffError> {
    let boundary = establish(workspace_root)?;
    RollbackPlan::prepare(&boundary, relative_target, backup_file)?.commit()
}

/// Display form of an operator-supplied path; on Windows, separators become `/`
/// (a backslash is an ordinary file-name character elsewhere and is kept).
fn display_path(path: &Path) -> String {
    let text = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text
    }
}

fn establish(workspace_root: &Path) -> Result<WorkspaceBoundary, DiffError> {
    WorkspaceBoundary::establish(
        workspace_root,
        SessionId::new(),
        SecurityClassification::Internal,
    )
    .map_err(|error| {
        DiffError::invalid_target(format!("workspace root rejected ({:?})", error.kind))
    })
}

/// Workspace-relative target with only ordinary components, plus its display form.
fn normalize_relative(target: &Path) -> Result<(PathBuf, String), DiffError> {
    let mut relative = PathBuf::new();
    let mut parts = Vec::new();
    for component in target.components() {
        match component {
            Component::Normal(part) => {
                let text = part
                    .to_str()
                    .ok_or_else(|| DiffError::invalid_target("target path is not valid UTF-8"))?;
                relative.push(part);
                parts.push(text);
            }
            Component::CurDir => {}
            _ => {
                return Err(DiffError::invalid_target(
                    "target must be a workspace-relative path without '..' or a root",
                ));
            }
        }
    }
    if parts.is_empty() {
        return Err(DiffError::invalid_target("target path is empty"));
    }
    let display = parts.join("/");
    Ok((relative, display))
}

fn resolve_workspace_file(
    boundary: &WorkspaceBoundary,
    target: &Path,
) -> Result<(PathBuf, String), DiffError> {
    let (relative, display) = normalize_relative(target)?;
    {
        let resolved = boundary.resolve(&relative).map_err(|error| {
            DiffError::invalid_target(format!("'{display}' rejected ({:?})", error.kind))
        })?;
        let entry = boundary.inspect(&resolved).map_err(|error| {
            DiffError::invalid_target(format!("'{display}' rejected ({:?})", error.kind))
        })?;
        if entry.kind != WorkspaceEntryKind::File {
            return Err(DiffError::invalid_target(format!(
                "'{display}' is not an ordinary file"
            )));
        }
        // The resolved observation retains handles that deny writers on Windows;
        // it is dropped here, before any content access.
    }
    Ok((boundary.root().canonical_path().join(&relative), display))
}

fn read_regular_file(path: &Path, limit: u64) -> Result<Vec<u8>, DiffError> {
    let metadata = fs::symlink_metadata(path).map_err(|e| DiffError::io(&e))?;
    if classify_entry_metadata(&metadata) != WorkspaceEntryKind::File {
        return Err(DiffError::invalid_target(
            "path is not an ordinary file (links, junctions and devices are refused)",
        ));
    }
    if metadata.len() > limit {
        return Err(DiffError::limits_exceeded(format!(
            "file exceeds {limit} bytes"
        )));
    }
    let file = fs::File::open(path).map_err(|e| DiffError::io(&e))?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| DiffError::io(&e))?;
    if bytes.len() as u64 > limit {
        return Err(DiffError::limits_exceeded(format!(
            "file exceeds {limit} bytes"
        )));
    }
    Ok(bytes)
}

fn write_backup(dir: &Path, target: &Path, bytes: &[u8]) -> Result<PathBuf, DiffError> {
    fs::create_dir_all(dir).map_err(|e| DiffError::io(&e))?;
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let stamp = TimestampUtc::now().as_epoch_millis();
    for attempt in 0..100u32 {
        let file_name = if attempt == 0 {
            format!("{name}_{stamp}.bak")
        } else {
            format!("{name}_{stamp}_{attempt}.bak")
        };
        let path = dir.join(file_name);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(DiffError::io(&error));
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(DiffError::io(&error)),
        }
    }
    Err(DiffError::new(DiffErrorKind::Io(
        "no unique backup file name is available".to_string(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(original: &str, diff: &str) -> Result<PatchOutcome, DiffError> {
        apply_hunk_to_content(original, diff)
    }

    fn does_not_apply(result: Result<PatchOutcome, DiffError>) -> bool {
        matches!(
            result,
            Err(DiffError {
                kind: DiffErrorKind::PatchDoesNotApply(_)
            })
        )
    }

    fn invalid(result: Result<PatchOutcome, DiffError>) -> bool {
        matches!(
            result,
            Err(DiffError {
                kind: DiffErrorKind::InvalidPatch(_)
            })
        )
    }

    const MAIN: &str = "fn main() {\n    let old = 1;\n    println!(\"{}\", old);\n}\n";
    const MAIN_DIFF: &str = "--- a/main.rs\n+++ b/main.rs\n@@ -1,3 +1,3 @@\n fn main() {\n-    let old = 1;\n+    let new = 2;\n     println!(\"{}\", old);\n";

    #[test]
    fn applies_hunk_at_header_position_with_exact_context() {
        let res = apply(MAIN, MAIN_DIFF).expect("patch should apply");
        assert!(!res.already_patched);
        assert_eq!(res.hunks, 1);
        assert_eq!(
            res.patched_content,
            "fn main() {\n    let new = 2;\n    println!(\"{}\", old);\n}\n"
        );
    }

    #[test]
    fn reports_already_patched_only_when_post_image_is_in_place() {
        let patched = apply(MAIN, MAIN_DIFF).unwrap().patched_content;
        let res = apply(&patched, MAIN_DIFF).expect("already patched");
        assert!(res.already_patched);
        assert_eq!(res.patched_content, patched);

        // The '+' text appearing elsewhere no longer counts as "already patched".
        let unrelated = format!("{MAIN}// let new = 2;\n");
        let res = apply(&unrelated, MAIN_DIFF).expect("applies forward");
        assert!(!res.already_patched);
    }

    #[test]
    fn whitespace_differences_are_not_fuzzed_or_reindented() {
        let original = "class Service {\n        let secret = \"hardcoded\";\n}";
        let diff =
            "@@ -2,1 +2,1 @@\n- let secret = \"hardcoded\";\n+ let secret = process.env.SECRET;\n";
        assert!(does_not_apply(apply(original, diff)));
    }

    #[test]
    fn context_mismatch_does_not_apply() {
        let diff = "@@ -1,3 +1,3 @@\n fn main() {\n-    let old = 1;\n+    let new = 2;\n     println!(\"{}\", other);\n";
        assert!(does_not_apply(apply(MAIN, diff)));
    }

    #[test]
    fn hunk_is_found_within_bounded_offset_and_only_there_is_replaced() {
        let mut original = String::new();
        for i in 0..20 {
            original.push_str(&format!("line {i}\n"));
        }
        original.push_str("target();\n");
        original.push_str("tail\n");
        original.push_str("target();\n");
        // Header says line 3, real position is line 21; context pins the first occurrence.
        let diff = "@@ -3,2 +3,2 @@\n line 19\n-target();\n+fixed();\n";
        let res = apply(&original, diff).expect("applies with offset");
        assert!(
            res.patched_content
                .contains("line 19\nfixed();\ntail\ntarget();\n")
        );
        assert_eq!(res.patched_content.matches("target();").count(), 1);
    }

    #[test]
    fn offset_beyond_the_bound_does_not_apply() {
        let mut original = String::new();
        for i in 0..(MAX_HUNK_OFFSET_LINES + 50) {
            original.push_str(&format!("filler {i}\n"));
        }
        original.push_str("needle\n");
        let diff = "@@ -1,1 +1,1 @@\n-needle\n+found\n";
        assert!(does_not_apply(apply(&original, diff)));
    }

    #[test]
    fn multiple_hunks_apply_all_or_nothing() {
        let original = "a\nb\nc\nd\ne\nf\ng\nh\n";
        let good = "@@ -1,2 +1,2 @@\n-a\n+A\n b\n@@ -7,2 +7,2 @@\n g\n-h\n+H\n";
        let res = apply(original, good).expect("both hunks apply");
        assert_eq!(res.hunks, 2);
        assert_eq!(res.patched_content, "A\nb\nc\nd\ne\nf\ng\nH\n");

        let second_fails = "@@ -1,2 +1,2 @@\n-a\n+A\n b\n@@ -7,2 +7,2 @@\n g\n-x\n+H\n";
        assert!(does_not_apply(apply(original, second_fails)));
    }

    #[test]
    fn crlf_line_endings_are_preserved_for_kept_and_added_lines() {
        let original = "one\r\ntwo\r\nthree\r\n";
        let diff = "@@ -1,3 +1,4 @@\n one\n-two\n+TWO\n+two-and-a-half\n three\n";
        let res = apply(original, diff).expect("applies");
        assert_eq!(
            res.patched_content,
            "one\r\nTWO\r\ntwo-and-a-half\r\nthree\r\n"
        );
    }

    #[test]
    fn crlf_patch_text_applies_to_lf_file() {
        let original = "one\ntwo\n";
        let diff = "@@ -1,2 +1,2 @@\r\n one\r\n-two\r\n+2\r\n";
        assert_eq!(apply(original, diff).unwrap().patched_content, "one\n2\n");
    }

    #[test]
    fn missing_final_newline_markers_are_honoured() {
        let original = "a\nb";
        let diff = "@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n\\ No newline at end of file\n";
        assert_eq!(apply(original, diff).unwrap().patched_content, "a\nc");

        let add_newline = "@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+c\n";
        assert_eq!(
            apply(original, add_newline).unwrap().patched_content,
            "a\nc\n"
        );

        // The marker claims the old file ends without a newline; this one does not.
        assert!(does_not_apply(apply("a\nb\n", diff)));
    }

    #[test]
    fn body_lines_that_look_like_headers_are_content() {
        let original = "SELECT 1;\n-- old comment\nSELECT 2;\n";
        let diff = "--- a/q.sql\n+++ b/q.sql\n@@ -1,3 +1,3 @@\n SELECT 1;\n--- old comment\n+++ new comment\n SELECT 2;\n";
        let res = apply(original, diff).expect("applies");
        assert_eq!(
            res.patched_content,
            "SELECT 1;\n++ new comment\nSELECT 2;\n"
        );
    }

    #[test]
    fn empty_context_lines_without_a_leading_space_are_accepted() {
        let original = "a\n\nb\n";
        let diff = "@@ -1,3 +1,3 @@\n a\n\n-b\n+c\n";
        assert_eq!(apply(original, diff).unwrap().patched_content, "a\n\nc\n");
    }

    #[test]
    fn context_free_insertion_uses_exact_position_and_refuses_ambiguity() {
        let original = "a\nb\n";
        let diff = "@@ -1,0 +2,1 @@\n+x\n";
        let res = apply(original, diff).expect("insert after line 1");
        assert_eq!(res.patched_content, "a\nx\nb\n");
        // Re-applying is ambiguous: the insertion point exists and so does the line.
        assert!(does_not_apply(apply(&res.patched_content, diff)));
    }

    #[test]
    fn context_free_deletion_is_never_reported_as_already_applied() {
        let diff = "@@ -2,1 +1,0 @@\n-b\n";
        let res = apply("a\nb\nc\n", diff).expect("deletes line 2");
        assert_eq!(res.patched_content, "a\nc\n");
        // The removed line is gone, but an empty post-image proves nothing.
        assert!(does_not_apply(apply(&res.patched_content, diff)));
        assert!(does_not_apply(apply("unrelated\n", diff)));
    }

    #[test]
    fn byte_order_mark_is_preserved() {
        let original = "\u{feff}a\nb\n";
        let diff = "@@ -1,2 +1,2 @@\n a\n-b\n+c\n";
        assert_eq!(
            apply(original, diff).unwrap().patched_content,
            "\u{feff}a\nc\n"
        );
    }

    #[test]
    fn malformed_or_unsupported_patches_are_invalid() {
        assert!(invalid(apply("a\n", "")));
        assert!(invalid(apply("a\n", "-a\n+b\n")));
        assert!(invalid(apply("a\n", "@@ -1 +1 @@\n-a\n")));
        assert!(invalid(apply("a\n", "@@ -1,2 +1,1 @@\n-a\n+b\n")));
        assert!(invalid(apply("a\n", "@@ -x,1 +1,1 @@\n-a\n+b\n")));
        assert!(invalid(apply("a\n", "@@ -1,1 +1,1 @@\n a\n")));
        assert!(invalid(apply(
            "a\n",
            "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n--- a/y\n+++ b/y\n@@ -1 +1 @@\n-a\n+b\n"
        )));
        assert!(invalid(apply(
            "a\n",
            "--- /dev/null\n+++ b/x\n@@ -0,0 +1 @@\n+a\n"
        )));
        assert!(invalid(apply(
            "a\n",
            "diff --git a/x b/x\nGIT binary patch\n"
        )));
        assert!(invalid(apply("a\n", "@@@ -1 -1 +1 @@@\n-a\n+b\n")));
    }

    #[test]
    fn target_path_comes_from_headers() {
        let patch = UnifiedPatch::parse(MAIN_DIFF).unwrap();
        assert_eq!(patch.target_path(), Some("main.rs"));
        assert_eq!(patch.hunk_count(), 1);
        assert_eq!(patch.sha256(), sha256_digest(MAIN_DIFF.as_bytes()));
        let stamped = UnifiedPatch::parse(
            "--- src/a.rs\t2024-01-01 00:00:00\n+++ src/a.rs\t2024-01-02 00:00:00\n@@ -1 +1 @@\n-a\n+b\n",
        )
        .unwrap();
        assert_eq!(stamped.target_path(), Some("src/a.rs"));
    }
}
