//! Bounded, read-only lockfile inventory across a workspace tree.
//!
//! Lockfiles are discovered recursively under an already validated workspace root.
//! Well-known dependency, build, VCS and IDE directories are skipped; symbolic
//! links, junctions and other reparse points are never followed; the walk is limited
//! by depth, visited-entry count, lockfile count and per-lockfile size. Lockfiles are
//! parsed with the pure-Rust parsers in this module. Nothing is executed and nothing
//! is written. Parse failures are reported per lockfile, never hidden.

use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{
    advisory::{
        cargo_lock::PackageRecord,
        deno_lock::DENO_JSR_SOURCE,
        multi_lock::{LockfileKind, parse_lockfile_content},
    },
    workspace::{WorkspaceEntryKind, classify_entry_metadata},
};

/// Default recursion depth below the workspace root.
pub const DEFAULT_INVENTORY_MAX_DEPTH: usize = 6;
/// Largest accepted recursion depth.
pub const MAX_INVENTORY_DEPTH: usize = 32;

/// Directory names that are never entered (compared ASCII case-insensitively).
pub const SKIPPED_DIRECTORY_NAMES: [&str; 17] = [
    ".git",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    "out",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".gradle",
    ".idea",
    ".vscode",
    "bin",
    "obj",
];

const BINARY_BUN_LOCKFILE: &str = "bun.lockb";

/// Resource bounds for one inventory walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventoryLimits {
    /// Directory levels below the root that are entered (0 = root files only).
    pub max_depth: usize,
    /// Maximum directory entries examined before the walk stops (`truncated`).
    pub max_entries: usize,
    /// Maximum lockfiles recorded before the walk stops (`truncated`).
    pub max_lockfiles: usize,
    /// Lockfiles larger than this are reported with a parse error, not read.
    pub max_lockfile_bytes: u64,
    /// Maximum package rows returned; counts still include every parsed package.
    pub max_packages: usize,
}

impl Default for InventoryLimits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_INVENTORY_MAX_DEPTH,
            max_entries: 200_000,
            max_lockfiles: 512,
            max_lockfile_bytes: 32 * 1024 * 1024,
            max_packages: 100_000,
        }
    }
}

/// One discovered lockfile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InventoryLockfile {
    /// Workspace-relative path with forward slashes.
    pub path: String,
    /// Detected lockfile format.
    pub kind: LockfileKind,
    /// OSV ecosystem of the format's packages.
    pub ecosystem: &'static str,
    /// Distinct `(name, version)` packages parsed from this lockfile.
    pub packages: usize,
    /// Why the lockfile could not be read or parsed; `None` when it parsed.
    pub parse_error: Option<String>,
}

/// One package recorded by a lockfile. Presence only; no vulnerability verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InventoryPackage {
    /// Package name as written in the lockfile.
    pub name: String,
    /// Raw version string as written in the lockfile.
    pub version: String,
    /// OSV ecosystem name (`JSR` for Deno JSR packages, which OSV does not cover).
    pub ecosystem: &'static str,
    /// Workspace-relative path of the lockfile that records it.
    pub lockfile: String,
}

/// Inventory result. Ordering is deterministic: lockfiles by path, packages by
/// lockfile path, then name, then version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceInventory {
    /// Discovered lockfiles, including ones that failed to parse.
    pub lockfiles: Vec<InventoryLockfile>,
    /// Package rows, at most `max_packages`.
    pub packages: Vec<InventoryPackage>,
    /// Total distinct packages parsed across all lockfiles.
    pub total_packages: usize,
    /// True when an entry, lockfile or package limit cut the result short.
    pub truncated: bool,
}

struct Candidate {
    relative: String,
    absolute: PathBuf,
    kind: LockfileKind,
    binary_bun: bool,
}

/// Walk `root` (which the caller must already have validated as a workspace
/// boundary) and parse every supported lockfile found within `limits`.
pub fn collect_lockfile_inventory(root: &Path, limits: &InventoryLimits) -> WorkspaceInventory {
    let mut truncated = false;
    let candidates = discover(root, limits, &mut truncated);
    let mut lockfiles = Vec::with_capacity(candidates.len());
    let mut packages = Vec::new();
    let mut total_packages = 0usize;
    for candidate in candidates {
        let ecosystem = candidate.kind.osv_ecosystem();
        let parsed = if candidate.binary_bun {
            Err(
                "binary bun.lockb lockfiles are not supported; a text bun.lock is required"
                    .to_string(),
            )
        } else {
            read_lockfile(&candidate.absolute, limits.max_lockfile_bytes).and_then(|content| {
                parse_lockfile_content(candidate.kind, &content).map_err(|e| e.to_string())
            })
        };
        let (count, parse_error) = match parsed {
            Ok(records) => {
                let rows = distinct_rows(records, candidate.kind);
                let count = rows.len();
                total_packages += count;
                for (name, version, row_ecosystem) in rows {
                    if packages.len() >= limits.max_packages {
                        truncated = true;
                        break;
                    }
                    packages.push(InventoryPackage {
                        name,
                        version,
                        ecosystem: row_ecosystem,
                        lockfile: candidate.relative.clone(),
                    });
                }
                (count, None)
            }
            Err(message) => (0, Some(message)),
        };
        lockfiles.push(InventoryLockfile {
            path: candidate.relative,
            kind: candidate.kind,
            ecosystem,
            packages: count,
            parse_error,
        });
    }
    WorkspaceInventory {
        lockfiles,
        packages,
        total_packages,
        truncated,
    }
}

/// Local code recorded in a lockfile (Cargo workspace/path members, which have no
/// `source`, and npm-family `workspace:`/`file:`/`link:`/`portal:` packages) is the
/// project itself, not a registry dependency, and is not listed.
fn is_local_package(record: &PackageRecord, kind: LockfileKind) -> bool {
    match kind {
        LockfileKind::Cargo => record.source.is_none(),
        LockfileKind::PackageLock
        | LockfileKind::Yarn
        | LockfileKind::Pnpm
        | LockfileKind::Bun
        | LockfileKind::Deno => ["workspace:", "file:", "link:", "portal:"]
            .iter()
            .any(|protocol| record.raw_version.starts_with(protocol)),
        _ => false,
    }
}

fn distinct_rows(
    records: Vec<PackageRecord>,
    kind: LockfileKind,
) -> BTreeSet<(String, String, &'static str)> {
    records
        .into_iter()
        .filter(|record| !is_local_package(record, kind))
        .map(|record| {
            let ecosystem = if kind == LockfileKind::Deno
                && record.source.as_deref() == Some(DENO_JSR_SOURCE)
            {
                "JSR"
            } else {
                kind.osv_ecosystem()
            };
            (record.name, record.raw_version, ecosystem)
        })
        .collect()
}

fn read_lockfile(path: &Path, limit: u64) -> Result<String, String> {
    let too_large = || format!("lockfile exceeds the {limit}-byte inventory limit");
    let metadata = fs::symlink_metadata(path).map_err(|_| "lockfile could not be read")?;
    if classify_entry_metadata(&metadata) != WorkspaceEntryKind::File {
        return Err("lockfile is not an ordinary file".to_string());
    }
    if metadata.len() > limit {
        return Err(too_large());
    }
    let file = fs::File::open(path).map_err(|_| "lockfile could not be read")?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "lockfile could not be read")?;
    if bytes.len() as u64 > limit {
        return Err(too_large());
    }
    String::from_utf8(bytes).map_err(|_| "lockfile is not valid UTF-8".to_string())
}

fn is_ordinary(path: &Path, expected: WorkspaceEntryKind) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| classify_entry_metadata(&metadata) == expected)
}

fn discover(root: &Path, limits: &InventoryLimits, truncated: &mut bool) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut visited = 0usize;
    // (absolute directory, workspace-relative prefix, depth)
    let mut pending: Vec<(PathBuf, String, usize)> = vec![(root.to_path_buf(), String::new(), 0)];
    'walk: while let Some((directory, prefix, depth)) = pending.pop() {
        let Ok(reader) = fs::read_dir(&directory) else {
            continue;
        };
        let mut entries = Vec::new();
        for entry in reader {
            let Ok(entry) = entry else { continue };
            visited += 1;
            if visited > limits.max_entries {
                *truncated = true;
                break 'walk;
            }
            // file_type() does not follow links; junctions report as symbolic links.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            entries.push((name, file_type.is_dir(), file_type.is_file()));
        }
        entries.sort();
        let has_text_bun_lock = entries
            .iter()
            .any(|(name, _, is_file)| *is_file && name == "bun.lock");
        let mut subdirectories = Vec::new();
        for (name, is_dir, is_file) in entries {
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let absolute = directory.join(&name);
            if is_dir {
                if depth < limits.max_depth
                    && !SKIPPED_DIRECTORY_NAMES
                        .iter()
                        .any(|skip| skip.eq_ignore_ascii_case(&name))
                    && is_ordinary(&absolute, WorkspaceEntryKind::Directory)
                {
                    subdirectories.push((absolute, relative, depth + 1));
                }
                continue;
            }
            if !is_file {
                continue;
            }
            let (kind, binary_bun) = if name == BINARY_BUN_LOCKFILE {
                if has_text_bun_lock {
                    continue;
                }
                (LockfileKind::Bun, true)
            } else {
                match LockfileKind::detect_from_filename(&name) {
                    Some(kind) => (kind, false),
                    None => continue,
                }
            };
            if !is_ordinary(&absolute, WorkspaceEntryKind::File) {
                continue;
            }
            if candidates.len() >= limits.max_lockfiles {
                *truncated = true;
                break 'walk;
            }
            candidates.push(Candidate {
                relative,
                absolute,
                kind,
                binary_bun,
            });
        }
        // Depth-first; reversed so that the lexicographically first directory is next.
        pending.extend(subdirectories.into_iter().rev());
    }
    candidates.sort_by(|a, b| a.relative.cmp(&b.relative));
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "sentra-inventory-{name}-{}-{}",
            std::process::id(),
            crate::SessionId::new()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    const CARGO_LOCK: &str = "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"my-workspace-crate\"\nversion = \"0.1.0\"\n";

    #[test]
    fn discovers_nested_lockfiles_skips_dependency_dirs_and_respects_depth() {
        let root = scratch("walk");
        fs::write(root.join("Cargo.lock"), CARGO_LOCK).unwrap();
        fs::create_dir_all(root.join("web")).unwrap();
        fs::write(root.join("web/requirements.txt"), "requests==2.31.0\n").unwrap();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::write(root.join("node_modules/pkg/Cargo.lock"), CARGO_LOCK).unwrap();
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("a/b/go.sum"), "not a go.sum line\n").unwrap();

        let inventory = collect_lockfile_inventory(&root, &InventoryLimits::default());
        let paths: Vec<&str> = inventory
            .lockfiles
            .iter()
            .map(|l| l.path.as_str())
            .collect();
        assert_eq!(paths, ["Cargo.lock", "a/b/go.sum", "web/requirements.txt"]);
        assert!(!inventory.truncated);
        let cargo = &inventory.lockfiles[0];
        assert_eq!(cargo.ecosystem, "crates.io");
        assert_eq!(
            cargo.packages, 1,
            "duplicate rows are counted once; the source-less workspace crate is local code"
        );
        assert!(
            !inventory
                .packages
                .iter()
                .any(|p| p.name == "my-workspace-crate")
        );
        assert!(inventory.packages.iter().any(|p| p.name == "requests"
            && p.ecosystem == "PyPI"
            && p.lockfile == "web/requirements.txt"));

        let shallow = collect_lockfile_inventory(
            &root,
            &InventoryLimits {
                max_depth: 1,
                ..InventoryLimits::default()
            },
        );
        let paths: Vec<&str> = shallow.lockfiles.iter().map(|l| l.path.as_str()).collect();
        assert_eq!(paths, ["Cargo.lock", "web/requirements.txt"]);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn reports_parse_errors_and_limits_per_lockfile() {
        let root = scratch("errors");
        fs::write(root.join("package-lock.json"), "{ not json").unwrap();
        fs::write(root.join("bun.lockb"), [0u8, 1, 2]).unwrap();
        let inventory = collect_lockfile_inventory(&root, &InventoryLimits::default());
        assert_eq!(inventory.lockfiles.len(), 2);
        assert!(
            inventory
                .lockfiles
                .iter()
                .all(|l| l.parse_error.is_some() && l.packages == 0)
        );
        assert_eq!(inventory.total_packages, 0);

        fs::write(root.join("Cargo.lock"), CARGO_LOCK).unwrap();
        let limited = collect_lockfile_inventory(
            &root,
            &InventoryLimits {
                max_lockfile_bytes: 8,
                ..InventoryLimits::default()
            },
        );
        let cargo = limited
            .lockfiles
            .iter()
            .find(|l| l.path == "Cargo.lock")
            .unwrap();
        assert!(cargo.parse_error.as_deref().unwrap().contains("limit"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn truncation_is_reported() {
        let root = scratch("truncate");
        fs::write(root.join("Cargo.lock"), CARGO_LOCK).unwrap();
        fs::write(root.join("requirements.txt"), "a==1\nb==2\n").unwrap();
        let inventory = collect_lockfile_inventory(
            &root,
            &InventoryLimits {
                max_packages: 1,
                ..InventoryLimits::default()
            },
        );
        assert!(inventory.truncated);
        assert_eq!(inventory.packages.len(), 1);
        assert_eq!(inventory.total_packages, 3);
        fs::remove_dir_all(&root).unwrap();
    }
}
