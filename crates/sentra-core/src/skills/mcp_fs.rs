//! Data-safe file I/O for MCP client configuration updates.
//!
//! Every write follows the same protocol:
//! 1. the file is read as bytes and decoded strictly (UTF-8, optional BOM);
//!    UTF-16, invalid UTF-8 and NUL bytes are reported instead of guessed;
//! 2. symlinked configuration files (dotfile managers) are resolved so the
//!    link itself is never replaced by a regular file;
//! 3. before replacing an existing file, its exact original bytes are copied
//!    to `<file>.bak` (or `<file>.bak.N` when an older, different backup
//!    already exists);
//! 4. the new content is written to a temporary file in the same directory,
//!    flushed, given the original permissions, and atomically renamed over the
//!    target, after re-checking that nobody changed the file in the meantime.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// A configuration file read for editing.
#[derive(Debug)]
pub(crate) struct Loaded {
    /// Path the caller asked for (reported to the user).
    pub(crate) requested: PathBuf,
    /// Symlink-resolved path that is actually written.
    pub(crate) real: PathBuf,
    /// Exact original bytes, or `None` when the file does not exist.
    pub(crate) original: Option<Vec<u8>>,
    /// Decoded text without a byte-order mark (empty when missing).
    pub(crate) text: String,
    /// Whether the original started with a UTF-8 byte-order mark.
    pub(crate) bom: bool,
}

/// Why a configuration file could not be loaded.
#[derive(Debug)]
pub(crate) enum LoadError {
    Io(io::Error),
    NotAFile,
    Utf16,
    InvalidUtf8,
    NulBytes,
}

/// Result of committing new content.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Written {
    Created,
    Updated { backup: PathBuf },
    Unchanged,
}

/// Why new content could not be committed.
#[derive(Debug)]
pub(crate) enum CommitError {
    /// The file changed on disk after it was read; the edit must be redone.
    Concurrent,
    /// The existing file is marked read-only.
    ReadOnly,
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

/// Removes Windows verbatim prefixes (`\\?\C:\` and `\\?\UNC\`) that
/// `fs::canonicalize` produces and that most agents cannot spawn.
pub(crate) fn simplify_path(path: PathBuf) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path;
    };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        let bytes = rest.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\'
        {
            return PathBuf::from(rest);
        }
    }
    path
}

fn decode(bytes: &[u8]) -> Result<(String, bool), LoadError> {
    if bytes.starts_with(b"\xFF\xFE") || bytes.starts_with(b"\xFE\xFF") {
        return Err(LoadError::Utf16);
    }
    let (body, bom) = match bytes.strip_prefix(UTF8_BOM) {
        Some(rest) => (rest, true),
        None => (bytes, false),
    };
    let text = std::str::from_utf8(body).map_err(|_| LoadError::InvalidUtf8)?;
    if text.contains('\0') {
        return Err(LoadError::NulBytes);
    }
    Ok((text.to_owned(), bom))
}

/// Reads `path` for editing.
pub(crate) fn load(path: &Path) -> Result<Loaded, LoadError> {
    let real = match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            simplify_path(fs::canonicalize(path).map_err(LoadError::Io)?)
        }
        Ok(_) => path.to_path_buf(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Loaded {
                requested: path.to_path_buf(),
                real: path.to_path_buf(),
                original: None,
                text: String::new(),
                bom: false,
            });
        }
        Err(error) => return Err(LoadError::Io(error)),
    };
    let meta = fs::metadata(&real).map_err(LoadError::Io)?;
    if !meta.is_file() {
        return Err(LoadError::NotAFile);
    }
    let bytes = fs::read(&real).map_err(LoadError::Io)?;
    let (text, bom) = decode(&bytes)?;
    Ok(Loaded {
        requested: path.to_path_buf(),
        real,
        original: Some(bytes),
        text,
        bom,
    })
}

fn io_error(operation: &'static str, path: &Path) -> impl FnOnce(io::Error) -> CommitError + use<> {
    let path = path.to_path_buf();
    move |source| CommitError::Io {
        operation,
        path,
        source,
    }
}

fn temp_path(target: &Path) -> PathBuf {
    let name = target.file_name().map_or_else(
        || "config".into(),
        |name| name.to_string_lossy().into_owned(),
    );
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    target.with_file_name(format!(".{name}.sentra-{}-{nanos}.tmp", std::process::id()))
}

/// Writes `bytes` to `target` through a temporary file and an atomic rename.
fn atomic_write(
    target: &Path,
    bytes: &[u8],
    permissions: Option<fs::Permissions>,
) -> Result<(), CommitError> {
    let temp = temp_path(target);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(io_error("create temporary file", &temp))?;
        file.write_all(bytes)
            .map_err(io_error("write temporary file", &temp))?;
        file.sync_all()
            .map_err(io_error("flush temporary file", &temp))?;
        drop(file);
        if let Some(permissions) = permissions {
            fs::set_permissions(&temp, permissions)
                .map_err(io_error("copy file permissions", &temp))?;
        }
        fs::rename(&temp, target).map_err(io_error("replace configuration file", target))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    #[cfg(unix)]
    if result.is_ok()
        && let Some(parent) = target.parent()
        && let Ok(directory) = fs::File::open(parent)
    {
        let _ = directory.sync_all();
    }
    result
}

/// Chooses (and writes, if needed) a backup holding `original`.
fn write_backup(
    real: &Path,
    original: &[u8],
    permissions: &fs::Permissions,
) -> Result<PathBuf, CommitError> {
    let name = real.file_name().map_or_else(
        || "config".into(),
        |name| name.to_string_lossy().into_owned(),
    );
    for index in 0..100u32 {
        let candidate = if index == 0 {
            real.with_file_name(format!("{name}.bak"))
        } else {
            real.with_file_name(format!("{name}.bak.{index}"))
        };
        match fs::read(&candidate) {
            Ok(existing) if existing == original => return Ok(candidate),
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                atomic_write(&candidate, original, Some(permissions.clone()))?;
                return Ok(candidate);
            }
            Err(source) => {
                return Err(CommitError::Io {
                    operation: "inspect existing backup",
                    path: candidate,
                    source,
                });
            }
        }
    }
    Err(CommitError::Io {
        operation: "choose a backup file name",
        path: real.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "100 different backups already exist",
        ),
    })
}

/// Encodes `text` with the original byte-order mark convention.
pub(crate) fn encode(loaded: &Loaded, text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(text.len() + 3);
    if loaded.bom {
        bytes.extend_from_slice(UTF8_BOM);
    }
    bytes.extend_from_slice(text.as_bytes());
    bytes
}

/// Commits `text` for a previously loaded file.
pub(crate) fn commit(loaded: &Loaded, text: &str) -> Result<Written, CommitError> {
    let bytes = encode(loaded, text);
    if loaded.original.as_deref() == Some(bytes.as_slice()) {
        return Ok(Written::Unchanged);
    }
    if let Some(parent) = loaded.real.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(io_error("create configuration directory", parent))?;
    }
    match &loaded.original {
        Some(original) => {
            let meta = fs::metadata(&loaded.real)
                .map_err(io_error("inspect configuration file", &loaded.real))?;
            if meta.permissions().readonly() {
                return Err(CommitError::ReadOnly);
            }
            let current = fs::read(&loaded.real)
                .map_err(io_error("re-read configuration file", &loaded.real))?;
            if &current != original {
                return Err(CommitError::Concurrent);
            }
            let backup = write_backup(&loaded.real, original, &meta.permissions())?;
            // Re-check right before the rename to narrow the race window.
            let current = fs::read(&loaded.real)
                .map_err(io_error("re-read configuration file", &loaded.real))?;
            if &current != original {
                return Err(CommitError::Concurrent);
            }
            atomic_write(&loaded.real, &bytes, Some(meta.permissions()))?;
            Ok(Written::Updated { backup })
        }
        None => {
            if fs::symlink_metadata(&loaded.real).is_ok() {
                return Err(CommitError::Concurrent);
            }
            atomic_write(&loaded.real, &bytes, None)?;
            Ok(Written::Created)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbatim_prefixes_are_removed() {
        assert_eq!(
            simplify_path(PathBuf::from(r"\\?\C:\bin\sentra.exe")),
            PathBuf::from(r"C:\bin\sentra.exe")
        );
        assert_eq!(
            simplify_path(PathBuf::from(r"\\?\UNC\server\share\s.exe")),
            PathBuf::from(r"\\server\share\s.exe")
        );
        assert_eq!(
            simplify_path(PathBuf::from("/usr/bin/sentra")),
            PathBuf::from("/usr/bin/sentra")
        );
    }

    #[test]
    fn decoding_is_strict() {
        assert!(matches!(decode(b"\xFF\xFE{\0}\0"), Err(LoadError::Utf16)));
        assert!(matches!(decode(b"{\xC3\x28}"), Err(LoadError::InvalidUtf8)));
        assert!(matches!(decode(b"{\0}"), Err(LoadError::NulBytes)));
        assert_eq!(decode(b"\xEF\xBB\xBF{}").unwrap(), ("{}".to_owned(), true));
    }
}
