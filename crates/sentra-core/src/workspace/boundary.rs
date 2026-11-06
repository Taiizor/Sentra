use std::{
    ffi::OsString,
    fmt, fs,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use crate::{SecurityClassification, SessionId};

use super::{
    RepositoryMetadataKind, WorkspaceEntry, WorkspaceEntryKind, WorkspaceError, WorkspaceErrorKind,
    WorkspaceOperation,
    platform::{self, Pin},
};

struct RootState {
    canonical: PathBuf,
    // Retain every root ancestor, not just a caller-controlled string or fingerprint.
    pins: Vec<Pin>,
    session_id: SessionId,
    classification: SecurityClassification,
}

/// A canonical root with retained metadata handles and in-process instance identity.
#[derive(Clone)]
pub struct WorkspaceRoot(Arc<RootState>);

impl WorkspaceRoot {
    /// Canonical root for an explicitly authorized view; not an access grant.
    pub fn canonical_path(&self) -> &Path {
        &self.0.canonical
    }

    /// Existing session identity associated with this boundary.
    pub fn session_id(&self) -> SessionId {
        self.0.session_id
    }

    /// Classification inherited by every inventory record.
    pub fn classification(&self) -> SecurityClassification {
        self.0.classification
    }
}

impl fmt::Debug for WorkspaceRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WorkspaceRoot([redacted])")
    }
}

/// Retained metadata observation; has no public constructor or content-open API.
pub struct ResolvedWorkspacePath {
    root: WorkspaceRoot,
    relative: PathBuf,
    pins: Vec<Pin>,
    // Exact bounded child names, independent of delayed/coarse directory mtimes.
    children: Option<Vec<OsString>>,
}

impl ResolvedWorkspacePath {
    /// Untrusted relative name, never a reusable filesystem authority.
    pub fn relative_path(&self) -> &Path {
        &self.relative
    }
}

impl fmt::Debug for ResolvedWorkspacePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResolvedWorkspacePath([redacted metadata observation])")
    }
}

/// Metadata-only boundary. Establishing it does not approve any policy action.
#[derive(Clone, Debug)]
pub struct WorkspaceBoundary {
    root: WorkspaceRoot,
}

impl WorkspaceBoundary {
    /// Establish a local Windows root, rejecting indirection in all its ancestors.
    /// Callers must separately authorize metadata processing of the selected root.
    pub fn establish(
        path: &Path,
        session_id: SessionId,
        classification: SecurityClassification,
    ) -> Result<Self, WorkspaceError> {
        let operation = WorkspaceOperation::EstablishRoot;
        platform::validate_syntax(path, operation)?;
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| WorkspaceError::io(e, operation))?
                .join(path)
        };
        let pins = platform::pin_absolute(&absolute, operation)?;
        if pins
            .last()
            .is_none_or(|pin| platform::kind(&pin.observed) != WorkspaceEntryKind::Directory)
        {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::RootNotDirectory,
                operation,
            ));
        }
        let canonical =
            fs::canonicalize(&absolute).map_err(|e| WorkspaceError::io(e, operation))?;
        platform::validate_syntax(&canonical, operation)?;
        platform::validate_pins(&pins, operation)?;
        Ok(Self {
            root: WorkspaceRoot(Arc::new(RootState {
                canonical,
                pins,
                session_id,
                classification,
            })),
        })
    }

    /// Established root; cloning it retains the existing handles and instance identity.
    pub fn root(&self) -> &WorkspaceRoot {
        &self.root
    }

    fn relative_input(&self, input: &Path) -> Result<PathBuf, WorkspaceError> {
        let operation = WorkspaceOperation::Resolve;
        platform::validate_syntax(input, operation)?;
        if !input.is_absolute() {
            return Ok(input
                .components()
                .filter(|c| !matches!(c, Component::CurDir))
                .collect());
        }
        #[cfg(windows)]
        {
            use std::path::Prefix;
            let drive = |path: &Path| match path.components().next() {
                Some(Component::Prefix(prefix)) => match prefix.kind() {
                    Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                        Some(letter.to_ascii_uppercase())
                    }
                    _ => None,
                },
                _ => None,
            };
            if drive(input) != drive(&self.root.0.canonical) {
                return Err(WorkspaceError::new(
                    WorkspaceErrorKind::OutsideRoot,
                    operation,
                ));
            }
        }
        // Let the actual filesystem canonicalize the supplied root prefix. Never
        // lowercase paths: NTFS directories can have case-sensitive semantics.
        let root_len = self.root.0.canonical.components().count();
        if input.components().count() < root_len {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::OutsideRoot,
                operation,
            ));
        }
        let prefix: PathBuf = input.components().take(root_len).collect();
        let prefix_pins = platform::pin_absolute(&prefix, operation)?;
        let canonical = fs::canonicalize(&prefix).map_err(|e| WorkspaceError::io(e, operation))?;
        platform::validate_pins(&prefix_pins, operation)?;
        if canonical != self.root.0.canonical {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::OutsideRoot,
                operation,
            ));
        }
        Ok(input.components().skip(root_len).collect())
    }

    /// Resolve only ordinary entries, retaining component handles until dropped.
    /// No symlink or junction is accepted even when its target would be internal.
    pub fn resolve(&self, input: &Path) -> Result<ResolvedWorkspacePath, WorkspaceError> {
        let relative = self.relative_input(input)?;
        self.resolve_relative(&relative)
            .map_err(|e| e.at(&relative))
    }

    fn resolve_relative(&self, relative: &Path) -> Result<ResolvedWorkspacePath, WorkspaceError> {
        let operation = WorkspaceOperation::Resolve;
        platform::validate_pins(&self.root.0.pins, operation)?;
        let root_pin = self.root.0.pins.last().expect("established directory root");
        let current_root = root_pin
            .file
            .metadata()
            .map_err(|e| WorkspaceError::io(e, operation))?;
        if platform::kind(&current_root) != WorkspaceEntryKind::Directory {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::PathChanged,
                operation,
            ));
        }
        let mut pins = Vec::new();
        let mut current = self.root.0.canonical.clone();
        // Reopen the namespace root with no-follow metadata access, not just its handle.
        pins.push(platform::pin(&current, operation)?);
        for component in relative.components() {
            if !matches!(component, Component::Normal(_)) {
                return Err(WorkspaceError::new(
                    WorkspaceErrorKind::OutsideRoot,
                    operation,
                ));
            }
            if platform::kind(&pins.last().expect("root pin").observed)
                != WorkspaceEntryKind::Directory
            {
                return Err(WorkspaceError::new(
                    WorkspaceErrorKind::OutsideRoot,
                    operation,
                ));
            }
            current.push(component);
            pins.push(platform::pin(&current, operation)?);
        }
        let canonical = fs::canonicalize(&current).map_err(|e| WorkspaceError::io(e, operation))?;
        canonical
            .strip_prefix(&self.root.0.canonical)
            .map_err(|_| WorkspaceError::new(WorkspaceErrorKind::OutsideRoot, operation))?;
        platform::validate_pins(&pins, operation)?;
        let children = directory_names(
            &current,
            relative,
            &pins.last().expect("entry pin").observed,
        )?;
        platform::validate_pins(&pins, operation)?;
        Ok(ResolvedWorkspacePath {
            root: self.root.clone(),
            relative: relative.to_path_buf(),
            pins,
            children,
        })
    }

    /// Revalidate a retained observation and return metadata only; never content.
    pub fn inspect(
        &self,
        resolved: &ResolvedWorkspacePath,
    ) -> Result<WorkspaceEntry, WorkspaceError> {
        let operation = WorkspaceOperation::Resolve;
        if !Arc::ptr_eq(&self.root.0, &resolved.root.0) {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::WrongBoundary,
                operation,
            ));
        }
        let pin = resolved.pins.last().expect("resolved metadata pin");
        let metadata = pin
            .file
            .metadata()
            .map_err(|e| WorkspaceError::io(e, operation).at(&resolved.relative))?;
        let current = self.resolve_relative(&resolved.relative)?;
        if !platform::same_observation(&pin.observed, &metadata)
            || resolved.children != current.children
            || !platform::same_observation(
                &metadata,
                &current.pins.last().expect("current pin").observed,
            )
        {
            return Err(
                WorkspaceError::new(WorkspaceErrorKind::PathChanged, operation)
                    .at(&resolved.relative),
            );
        }
        let kind = platform::kind(&metadata);
        let name = resolved.relative.file_name().and_then(|name| name.to_str());
        let repository_metadata = match (name, kind) {
            (Some(name), _) if name.eq_ignore_ascii_case(".git") => {
                Some(RepositoryMetadataKind::Git)
            }
            (Some("Cargo.toml"), WorkspaceEntryKind::File) => {
                Some(RepositoryMetadataKind::CargoManifest)
            }
            (Some("Cargo.lock"), WorkspaceEntryKind::File) => {
                Some(RepositoryMetadataKind::CargoLock)
            }
            _ => None,
        };
        Ok(WorkspaceEntry {
            relative_path: resolved.relative.clone(),
            kind,
            size_bytes: if kind == WorkspaceEntryKind::File {
                metadata.len()
            } else {
                0
            },
            modified: metadata.modified().ok(),
            repository_metadata,
            classification: self.root.classification(),
        })
    }
}

/// Name-only inventory: no child metadata, content or symlink target is opened.
/// Git metadata remains opaque. Exceeding either hard bound rejects observation.
fn directory_names(
    path: &Path,
    relative: &Path,
    metadata: &fs::Metadata,
) -> Result<Option<Vec<OsString>>, WorkspaceError> {
    if platform::kind(metadata) != WorkspaceEntryKind::Directory
        || relative
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case(".git"))
    {
        return Ok(None);
    }
    let operation = WorkspaceOperation::ReadDirectory;
    let mut names = Vec::new();
    let mut bytes = 0usize;
    for entry in fs::read_dir(path).map_err(|e| WorkspaceError::io(e, operation))? {
        let name = entry
            .map_err(|e| WorkspaceError::io(e, operation))?
            .file_name();
        bytes = bytes
            .checked_add(name.as_encoded_bytes().len())
            .ok_or_else(|| WorkspaceError::new(WorkspaceErrorKind::InvalidLimits, operation))?;
        if names.len() >= 20_000 || bytes > 4 * 1024 * 1024 {
            return Err(WorkspaceError::new(
                WorkspaceErrorKind::InvalidLimits,
                operation,
            ));
        }
        names.push(name);
    }
    names.sort_unstable();
    Ok(Some(names))
}
