//! Safe std-only Windows metadata opens. No target content is opened for reading.

use std::{
    fs::{self, File, Metadata},
    path::{Component, Path, PathBuf},
};

use super::{
    InvalidPathReason, WorkspaceEntryKind, WorkspaceError, WorkspaceErrorKind, WorkspaceOperation,
};

pub(super) const MAX_PATH_BYTES: usize = 32_768;
pub(super) const MAX_COMPONENTS: usize = 128;

fn invalid(reason: InvalidPathReason, operation: WorkspaceOperation) -> WorkspaceError {
    WorkspaceError::new(WorkspaceErrorKind::InvalidPath(reason), operation)
}

pub(super) fn validate_syntax(
    path: &Path,
    operation: WorkspaceOperation,
) -> Result<(), WorkspaceError> {
    if path.as_os_str().is_empty() {
        return Err(invalid(InvalidPathReason::InvalidName, operation));
    }
    if path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || path.components().count() > MAX_COMPONENTS
    {
        return Err(invalid(InvalidPathReason::PathTooLong, operation));
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        let prefix = path.components().next();
        match prefix {
            Some(Component::Prefix(p))
                if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
                    && path.is_absolute() => {}
            Some(Component::Prefix(_)) => {
                return Err(invalid(InvalidPathReason::UnsupportedPrefix, operation));
            }
            _ if path.has_root() => {
                return Err(invalid(InvalidPathReason::UnsupportedPrefix, operation));
            }
            _ => {}
        }
    }
    for part in path.components() {
        match part {
            Component::ParentDir => {
                return Err(invalid(InvalidPathReason::ParentTraversal, operation));
            }
            Component::Normal(name) => {
                let name = name
                    .to_str()
                    .ok_or_else(|| invalid(InvalidPathReason::InvalidName, operation))?;
                if name.contains(':') {
                    return Err(invalid(InvalidPathReason::AlternateDataStream, operation));
                }
                if name.is_empty()
                    || name.ends_with(['.', ' '])
                    || name
                        .chars()
                        .any(|c| c.is_control() || "<>\"|?*".contains(c))
                {
                    return Err(invalid(InvalidPathReason::InvalidName, operation));
                }
                let base = name
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(' ')
                    .to_uppercase();
                let device = matches!(
                    base.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                ) || ["COM", "LPT"].iter().any(|prefix| {
                    base.strip_prefix(prefix).is_some_and(|suffix| {
                        matches!(
                            suffix,
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        )
                    })
                });
                if device {
                    return Err(invalid(InvalidPathReason::ReservedDevice, operation));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// A retained object handle, not an inode/file-index identity assertion.
pub(super) struct Pin {
    pub file: File,
    pub observed: Metadata,
}

pub(super) fn validate_pins(
    pins: &[Pin],
    operation: WorkspaceOperation,
) -> Result<(), WorkspaceError> {
    for pin in pins {
        let current = pin
            .file
            .metadata()
            .map_err(|e| WorkspaceError::io(e, operation))?;
        if !same_admission(&pin.observed, &current) {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::PathChanged,
                operation,
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn classify_attributes(
    attributes: u32,
    file: bool,
    directory: bool,
) -> WorkspaceEntryKind {
    // FILE_ATTRIBUTE_REPARSE_POINT must win even if std reports a file/directory.
    if attributes & 0x400 != 0 {
        return WorkspaceEntryKind::ReparsePoint;
    }
    // DEVICE, OFFLINE, RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS are not ordinary data.
    if attributes & (0x40 | 0x1000 | 0x40000 | 0x400000) != 0 {
        return WorkspaceEntryKind::Unsupported;
    }
    match (file, directory) {
        (true, false) => WorkspaceEntryKind::File,
        (false, true) => WorkspaceEntryKind::Directory,
        _ => WorkspaceEntryKind::Unsupported,
    }
}

pub(super) fn kind(metadata: &Metadata) -> WorkspaceEntryKind {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        classify_attributes(
            metadata.file_attributes(),
            metadata.is_file(),
            metadata.is_dir(),
        )
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        WorkspaceEntryKind::Unsupported
    }
}

pub(super) fn same_observation(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        left.file_attributes() == right.file_attributes()
            && left.creation_time() == right.creation_time()
            && left.last_write_time() == right.last_write_time()
            && left.len() == right.len()
            && kind(left) == kind(right)
    }
    #[cfg(not(windows))]
    {
        let _ = (left, right);
        false
    }
}

fn same_admission(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Changes to unrelated children of an ancestor are not object replacement.
        // Directory inventory mutation is checked separately around enumeration.
        if kind(left) == WorkspaceEntryKind::Directory
            && kind(right) == WorkspaceEntryKind::Directory
        {
            return left.file_attributes() == right.file_attributes()
                && left.creation_time() == right.creation_time();
        }
    }
    same_observation(left, right)
}

pub(super) fn pin(path: &Path, operation: WorkspaceOperation) -> Result<Pin, WorkspaceError> {
    #[cfg(windows)]
    {
        pin_checked(path, operation, || {})
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err(WorkspaceError::new(
            WorkspaceErrorKind::UnsupportedPlatform,
            operation,
        ))
    }
}

#[cfg(windows)]
fn pin_checked(
    path: &Path,
    operation: WorkspaceOperation,
    before_open: impl FnOnce(),
) -> Result<Pin, WorkspaceError> {
    {
        use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
        let before = fs::symlink_metadata(path).map_err(|e| WorkspaceError::io(e, operation))?;
        let observed_kind = kind(&before);
        if !matches!(
            observed_kind,
            WorkspaceEntryKind::File | WorkspaceEntryKind::Directory
        ) {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::Quarantined(observed_kind),
                operation,
            ));
        }
        // FILE_READ_ATTRIBUTES; FILE_SHARE_READ only; OPEN_REPARSE_POINT | BACKUP_SEMANTICS.
        // Safe std passes these flags to Windows; no unsafe FFI or content-read access.
        // Attribute-only access is NOT a writer-exclusion or immutable-snapshot guarantee.
        before_open();
        let file = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(0x1)
            .custom_flags(0x0020_0000 | 0x0200_0000)
            .open(path)
            .map_err(|e| WorkspaceError::io(e, operation))?;
        let observed = file
            .metadata()
            .map_err(|e| WorkspaceError::io(e, operation))?;
        let after = fs::symlink_metadata(path).map_err(|e| WorkspaceError::io(e, operation))?;
        if !same_admission(&before, &observed) || !same_admission(&observed, &after) {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::PathChanged,
                operation,
            ));
        }
        Ok(Pin { file, observed })
    }
}

/// Retain ancestors while inspecting the next component; never canonicalize first.
pub(super) fn pin_absolute(
    path: &Path,
    operation: WorkspaceOperation,
) -> Result<Vec<Pin>, WorkspaceError> {
    validate_syntax(path, operation)?;
    if !path.is_absolute() {
        return Err(invalid(InvalidPathReason::UnsupportedPrefix, operation));
    }
    let mut current = PathBuf::new();
    let mut pins = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir | Component::Normal(_) => {
                current.push(component.as_os_str());
                pins.push(pin(&current, operation)?);
            }
            Component::CurDir => {}
            Component::ParentDir => unreachable!("validated syntax"),
        }
    }
    Ok(pins)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn reparse_and_unknown_attributes_override_ordinary_types() {
        for (file, directory) in [(true, false), (false, true), (false, false)] {
            assert_eq!(
                classify_attributes(0x400, file, directory),
                WorkspaceEntryKind::ReparsePoint
            );
        }
        for flag in [0x40, 0x1000, 0x40000, 0x400000] {
            assert_eq!(
                classify_attributes(flag, true, false),
                WorkspaceEntryKind::Unsupported
            );
        }
        assert_eq!(
            classify_attributes(0, false, false),
            WorkspaceEntryKind::Unsupported
        );
    }

    #[test]
    fn replacement_by_symlink_between_check_and_open_is_rejected() {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
        fs::create_dir_all(&parent).unwrap();
        let parent = fs::canonicalize(parent).unwrap();
        let owned = parent.join(format!("pin-race-{}", std::process::id()));
        fs::create_dir(&owned).unwrap();
        let leaf = owned.join("leaf");
        let target = owned.join("outside-fixture");
        fs::write(&leaf, b"old").unwrap();
        fs::write(&target, b"never read").unwrap();
        let result = pin_checked(&leaf, WorkspaceOperation::Resolve, || {
            fs::remove_file(&leaf).unwrap();
            std::os::windows::fs::symlink_file(&target, &leaf)
                .expect("Windows symlink prerequisite");
        });
        // Unlink only the owned link; never remove the linked target recursively.
        fs::remove_file(&leaf).unwrap();
        fs::remove_file(&target).unwrap();
        fs::remove_dir(&owned).unwrap();
        assert!(matches!(
            result.err().unwrap().kind,
            WorkspaceErrorKind::PathChanged
        ));
    }
}
