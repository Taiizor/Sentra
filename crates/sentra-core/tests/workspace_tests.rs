//! Maintainer-owned synthetic fixtures only. Never run discovered target code.
#![cfg(windows)]

use std::{
    fs,
    io::Write,
    os::windows::fs::{symlink_dir, symlink_file},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use sentra_core::{SecurityClassification, SessionId, workspace::*};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    base: PathBuf,
    repo: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/workspace-fixtures");
        fs::create_dir_all(&parent).unwrap();
        let parent = fs::canonicalize(parent).unwrap();
        let base = parent.join(format!(
            "fixture-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&base).unwrap();
        let repo = base.join("Workspace Ω with spaces");
        fs::create_dir(&repo).unwrap();
        Self { base, repo }
    }

    fn file(&self, name: &str, bytes: &[u8]) {
        let path = self.repo.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn boundary(&self) -> WorkspaceBoundary {
        WorkspaceBoundary::establish(
            &self.repo,
            SessionId::for_test_sequence(53),
            SecurityClassification::Confidential,
        )
        .unwrap()
    }
}

// The fixture root is known, absolute and under the workspace's ignored target directory.
// Unlink reparse entries themselves; never recursively delete through their targets.
fn remove_owned(path: &Path, parent: &Path) {
    use std::os::windows::fs::MetadataExt;
    assert!(path.is_absolute() && path.starts_with(parent) && path != parent);
    let metadata = fs::symlink_metadata(path).unwrap();
    if metadata.file_attributes() & 0x400 != 0 {
        if metadata.file_attributes() & 0x10 != 0 {
            fs::remove_dir(path).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
    } else if metadata.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            remove_owned(&entry.unwrap().path(), parent);
        }
        fs::remove_dir(path).unwrap();
    } else {
        fs::remove_file(path).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        remove_owned(&self.base, self.base.parent().unwrap());
    }
}

fn assert_indirection(error: WorkspaceError) {
    assert!(matches!(
        error.kind,
        WorkspaceErrorKind::Quarantined(
            WorkspaceEntryKind::ReparsePoint | WorkspaceEntryKind::SymbolicLink
        )
    ));
}

#[test]
fn workspace_valid_root_is_canonical_and_session_classified() {
    let f = Fixture::new();
    let boundary = f.boundary();
    assert_eq!(
        boundary.root().canonical_path(),
        fs::canonicalize(&f.repo).unwrap()
    );
    assert_eq!(
        boundary.root().session_id(),
        SessionId::for_test_sequence(53)
    );
    assert_eq!(
        boundary.root().classification(),
        SecurityClassification::Confidential
    );
    assert!(
        boundary
            .discover(&DiscoveryLimits::default())
            .unwrap()
            .is_complete()
    );
}

#[test]
fn workspace_missing_root_and_file_root_fail_typed() {
    let f = Fixture::new();
    f.file("file", b"x");
    let establish = |p: &Path| {
        WorkspaceBoundary::establish(
            p,
            SessionId::for_test_sequence(1),
            SecurityClassification::Internal,
        )
    };
    assert_eq!(
        establish(Path::new("")).unwrap_err().kind,
        WorkspaceErrorKind::InvalidPath(InvalidPathReason::InvalidName)
    );
    assert!(matches!(
        establish(&f.repo.join("missing")).unwrap_err().kind,
        WorkspaceErrorKind::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        }
    ));
    assert_eq!(
        establish(&f.repo.join("file")).unwrap_err().kind,
        WorkspaceErrorKind::RootNotDirectory
    );
}

#[test]
fn workspace_root_dot_is_canonicalized_without_changing_process_cwd() {
    let f = Fixture::new();
    let root = f.repo.join(".");
    let boundary = WorkspaceBoundary::establish(
        &root,
        SessionId::for_test_sequence(1),
        SecurityClassification::Internal,
    )
    .unwrap();
    assert_eq!(
        boundary.root().canonical_path(),
        fs::canonicalize(&f.repo).unwrap()
    );
}

#[test]
fn workspace_relative_root_is_resolved_against_actual_cwd() {
    let cwd = std::env::current_dir().unwrap();
    let boundary = WorkspaceBoundary::establish(
        Path::new("."),
        SessionId::for_test_sequence(1),
        SecurityClassification::Internal,
    )
    .unwrap();
    assert_eq!(
        boundary.root().canonical_path(),
        fs::canonicalize(cwd).unwrap()
    );
}

#[test]
fn workspace_relative_absolute_dot_and_repeated_separators() {
    let f = Fixture::new();
    f.file("src/δ file.rs", b"fixture");
    let boundary = f.boundary();
    for path in [
        PathBuf::from("src/δ file.rs"),
        PathBuf::from("./src//./δ file.rs"),
        f.repo.join("src/δ file.rs"),
    ] {
        let resolved = boundary.resolve(&path).unwrap();
        assert_eq!(resolved.relative_path(), Path::new("src/δ file.rs"));
        assert_eq!(boundary.inspect(&resolved).unwrap().size_bytes, 7);
    }
}

#[test]
fn workspace_absolute_case_alias_uses_filesystem_semantics() {
    let f = Fixture::new();
    f.file("MixedCase.rs", b"case");
    let boundary = f.boundary();
    let upper = f.repo.to_str().unwrap().to_uppercase();
    // Ω changes case under Unicode; canonicalization, not a home-grown fold, decides.
    let resolved = boundary
        .resolve(&PathBuf::from(upper).join("mixedcase.RS"))
        .unwrap();
    assert_eq!(boundary.inspect(&resolved).unwrap().size_bytes, 4);
}

#[test]
fn workspace_outside_sibling_and_string_prefix_collision_are_rejected() {
    let f = Fixture::new();
    let outside = f.base.join("Workspace Ω with spaces extra");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret"), b"outside").unwrap();
    let boundary = f.boundary();
    assert_eq!(
        boundary.resolve(&outside.join("secret")).unwrap_err().kind,
        WorkspaceErrorKind::OutsideRoot
    );
}

#[test]
fn workspace_parent_components_are_never_lexically_excused() {
    let f = Fixture::new();
    f.file("dir/file", b"x");
    let boundary = f.boundary();
    for path in ["..", "../outside", "dir/../dir/file", "dir/../../outside"] {
        assert_eq!(
            boundary.resolve(Path::new(path)).unwrap_err().kind,
            WorkspaceErrorKind::InvalidPath(InvalidPathReason::ParentTraversal)
        );
    }
}

#[test]
fn workspace_unc_devices_and_ambiguous_prefixes_fail_before_access() {
    let f = Fixture::new();
    let boundary = f.boundary();
    for path in [
        r"\\never-contact.invalid\share\source",
        r"\\?\UNC\never-contact.invalid\share",
        r"\\.\pipe\secret",
        r"\root-relative",
        "C:relative",
    ] {
        assert_eq!(
            boundary.resolve(Path::new(path)).unwrap_err().kind,
            WorkspaceErrorKind::InvalidPath(InvalidPathReason::UnsupportedPrefix)
        );
    }
    let drive_root = f.base.ancestors().last().unwrap();
    assert_eq!(
        boundary.resolve(drive_root).unwrap_err().kind,
        WorkspaceErrorKind::OutsideRoot
    );
    let root_text = boundary.root().canonical_path().to_str().unwrap();
    let other_drive = if root_text.contains("E:") { 'Z' } else { 'E' };
    let outside = format!("{other_drive}:/never/lookup/these/components/for/outside/root");
    assert_eq!(
        boundary.resolve(Path::new(&outside)).unwrap_err().kind,
        WorkspaceErrorKind::OutsideRoot
    );
}

#[test]
fn workspace_nul_ads_reserved_names_and_win32_aliases_fail_closed() {
    let f = Fixture::new();
    let boundary = f.boundary();
    for path in [
        "bad\0name",
        "file.",
        "file ",
        "bad?name",
        "COM1.txt",
        "nul",
        "LPT².log",
        "CONIN$",
        "con .txt",
        "file::$DATA",
    ] {
        assert!(
            matches!(
                boundary.resolve(Path::new(path)).unwrap_err().kind,
                WorkspaceErrorKind::InvalidPath(_)
            ),
            "{path:?}"
        );
    }
}

#[test]
fn workspace_missing_leaf_is_not_a_valid_future_path() {
    let f = Fixture::new();
    let boundary = f.boundary();
    let error = boundary.resolve(Path::new("not-created")).unwrap_err();
    assert!(matches!(
        error.kind,
        WorkspaceErrorKind::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        }
    ));
    assert_eq!(error.relative_path(), Some(Path::new("not-created")));
}

#[test]
fn workspace_ordinary_diagnostics_redact_absolute_and_relative_payloads() {
    let f = Fixture::new();
    let boundary = f.boundary();
    let error = boundary
        .resolve(Path::new("PRIVATE_PATH_CANARY"))
        .unwrap_err();
    let logs = format!(
        "{error} {error:?} {boundary:?} {:?}",
        boundary.resolve(Path::new(".")).unwrap()
    );
    assert!(!logs.contains("PRIVATE_PATH_CANARY"));
    assert!(!logs.contains(f.repo.to_str().unwrap()));
}

#[test]
fn workspace_observation_is_bound_to_root_instance_not_equal_path_string() {
    let f = Fixture::new();
    f.file("file", b"x");
    let a = f.boundary();
    let b = f.boundary();
    let observed = a.resolve(Path::new("file")).unwrap();
    assert_eq!(
        b.inspect(&observed).unwrap_err().kind,
        WorkspaceErrorKind::WrongBoundary
    );
    assert!(a.clone().inspect(&observed).is_ok());
}

#[test]
fn workspace_retained_handles_deny_observed_rename_attempts() {
    let f = Fixture::new();
    f.file("dir/file", b"x");
    let boundary = f.boundary();
    let resolved = boundary.resolve(Path::new("dir/file")).unwrap();
    assert!(fs::rename(f.repo.join("dir"), f.repo.join("renamed")).is_err());
    assert!(fs::rename(&f.repo, f.base.join("replaced-root")).is_err());
    assert!(boundary.inspect(&resolved).is_ok());
    drop(resolved);
    drop(boundary);
    fs::rename(f.repo.join("dir"), f.repo.join("renamed")).unwrap();
}

#[test]
fn workspace_preexisting_writer_changes_invalidate_retained_observation() {
    let f = Fixture::new();
    f.file("file", b"x");
    let mut writer = fs::OpenOptions::new()
        .append(true)
        .open(f.repo.join("file"))
        .unwrap();
    let boundary = f.boundary();
    let observed = boundary.resolve(Path::new("file")).unwrap();
    writer.write_all(b"updated").unwrap();
    drop(writer);
    assert_eq!(
        boundary.inspect(&observed).unwrap_err().kind,
        WorkspaceErrorKind::PathChanged
    );
    assert_eq!(
        boundary
            .inspect(&boundary.resolve(Path::new("file")).unwrap())
            .unwrap()
            .size_bytes,
        8
    );
}

#[test]
fn workspace_metadata_changed_after_resolution_is_rejected() {
    let f = Fixture::new();
    f.file("file", b"x");
    let boundary = f.boundary();
    let resolved = boundary.resolve(Path::new("file")).unwrap();
    let path = f.repo.join("file");
    let original = fs::metadata(&path).unwrap().permissions();
    let mut changed = original.clone();
    changed.set_readonly(true);
    fs::set_permissions(&path, changed).unwrap();
    let result = boundary.inspect(&resolved);
    fs::set_permissions(&path, original).unwrap();
    assert_eq!(result.unwrap_err().kind, WorkspaceErrorKind::PathChanged);
}

#[test]
fn workspace_directory_change_invalidates_retained_observation() {
    let f = Fixture::new();
    f.file("dir/original", b"old");
    let boundary = f.boundary();
    let observed = boundary.resolve(Path::new("dir")).unwrap();
    f.file("dir/new", b"new");
    assert_eq!(
        boundary.inspect(&observed).unwrap_err().kind,
        WorkspaceErrorKind::PathChanged
    );
}

#[test]
#[cfg(windows)]
fn workspace_directory_child_change_is_detected_with_identical_timestamp() {
    use std::{
        fs::{FileTimes, OpenOptions},
        os::windows::fs::OpenOptionsExt,
    };
    let f = Fixture::new();
    f.file("dir/original", b"old");
    // Attribute-only access is compatible with retained no-delete metadata pins.
    let directory = OpenOptions::new()
        .access_mode(0x100)
        .share_mode(7)
        .custom_flags(0x0200_0000)
        .open(f.repo.join("dir"))
        .unwrap();
    let original_time = directory.metadata().unwrap().modified().unwrap();
    let boundary = f.boundary();
    let observed = boundary.resolve(Path::new("dir")).unwrap();
    f.file("dir/new", b"new");
    directory
        .set_times(FileTimes::new().set_modified(original_time))
        .unwrap();
    assert_eq!(
        directory.metadata().unwrap().modified().unwrap(),
        original_time
    );
    assert_eq!(
        boundary.inspect(&observed).unwrap_err().kind,
        WorkspaceErrorKind::PathChanged
    );
}

#[test]
fn workspace_file_symlink_internal_target_is_quarantined() {
    let f = Fixture::new();
    f.file("real", b"x");
    symlink_file(f.repo.join("real"), f.repo.join("link"))
        .expect("Windows file symlink prerequisite");
    let boundary = f.boundary();
    assert_indirection(boundary.resolve(Path::new("link")).unwrap_err());
    let result = boundary.discover(&DiscoveryLimits::default()).unwrap();
    assert_eq!(result.quarantined.len(), 1);
    assert!(!result.is_complete());
}

#[test]
fn workspace_file_symlink_external_target_is_quarantined() {
    let f = Fixture::new();
    fs::write(f.base.join("outside"), b"secret").unwrap();
    symlink_file(f.base.join("outside"), f.repo.join("link"))
        .expect("Windows file symlink prerequisite");
    let boundary = f.boundary();
    assert_indirection(boundary.resolve(Path::new("link")).unwrap_err());
}

#[test]
fn workspace_internal_directory_symlink_is_not_traversed() {
    let f = Fixture::new();
    f.file("real/child", b"x");
    symlink_dir(f.repo.join("real"), f.repo.join("link"))
        .expect("Windows directory symlink prerequisite");
    let boundary = f.boundary();
    assert_indirection(boundary.resolve(Path::new("link/child")).unwrap_err());
    let result = boundary.discover(&DiscoveryLimits::default()).unwrap();
    assert!(
        result
            .entries
            .iter()
            .all(|e| !e.relative_path.starts_with("link"))
    );
}

#[test]
fn workspace_external_directory_symlink_hides_outside_metadata() {
    let f = Fixture::new();
    let outside = f.base.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("HOST_CANARY"), b"x").unwrap();
    symlink_dir(&outside, f.repo.join("link")).expect("Windows directory symlink prerequisite");
    let result = f.boundary().discover(&DiscoveryLimits::default()).unwrap();
    assert!(result.entries.is_empty());
    assert_eq!(result.quarantined.len(), 1);
}

#[test]
fn workspace_nested_and_cyclic_symlinks_terminate_without_following() {
    let f = Fixture::new();
    fs::create_dir(f.repo.join("dir")).unwrap();
    symlink_dir(&f.repo, f.repo.join("dir/cycle")).expect("Windows directory symlink prerequisite");
    symlink_dir(f.repo.join("dir/cycle"), f.repo.join("nested")).unwrap();
    let result = f.boundary().discover(&DiscoveryLimits::default()).unwrap();
    assert_eq!(result.inspected_entries, 3);
    assert_eq!(result.quarantined.len(), 2);
    assert_eq!(result.entries.len(), 1);
}

#[test]
fn workspace_replacement_with_symlink_before_resolution_is_rejected() {
    let f = Fixture::new();
    f.file("replace", b"old");
    f.file("target", b"new");
    let boundary = f.boundary();
    fs::remove_file(f.repo.join("replace")).unwrap();
    symlink_file(f.repo.join("target"), f.repo.join("replace"))
        .expect("Windows file symlink prerequisite");
    assert_indirection(boundary.resolve(Path::new("replace")).unwrap_err());
}

#[test]
fn workspace_root_and_root_ancestor_symlinks_are_rejected() {
    let f = Fixture::new();
    fs::create_dir(f.repo.join("dir")).unwrap();
    let alias = f.base.join("alias");
    symlink_dir(&f.repo, &alias).expect("Windows directory symlink prerequisite");
    for root in [alias.clone(), alias.join("dir")] {
        assert_indirection(
            WorkspaceBoundary::establish(
                &root,
                SessionId::for_test_sequence(1),
                SecurityClassification::Internal,
            )
            .unwrap_err(),
        );
    }
}

#[test]
fn workspace_discovery_normal_nested_and_empty_directories() {
    let f = Fixture::new();
    f.file("src/lib.rs", b"inert");
    fs::create_dir(f.repo.join("empty")).unwrap();
    let result = f.boundary().discover(&DiscoveryLimits::default()).unwrap();
    assert!(result.is_complete());
    assert_eq!(result.inspected_entries, 3);
    assert_eq!(result.entries.len(), 3);
    assert_eq!(result.total_file_bytes, 5);
}

#[test]
fn workspace_git_directory_is_opaque_including_case_alias() {
    let f = Fixture::new();
    f.file(".GiT/hooks/post-checkout", b"never execute");
    f.file(".GiT/config", b"credential = SECRET");
    f.file("Cargo.toml", b"invalid inert bytes");
    let result = f.boundary().discover(&DiscoveryLimits::default()).unwrap();
    assert!(result.is_complete());
    assert_eq!(result.entries.len(), 2);
    assert_eq!(
        result.entries[0].repository_metadata,
        Some(RepositoryMetadataKind::Git)
    );
    assert_eq!(
        result.entries[1].repository_metadata,
        Some(RepositoryMetadataKind::CargoManifest)
    );
}

#[test]
fn workspace_git_pointer_and_invalid_manifests_are_not_read() {
    let f = Fixture::new();
    f.file(".git", b"gitdir: //never-contact.invalid/private");
    f.file("Cargo.toml", &[0xff, 0xfe, 0]);
    f.file("Cargo.lock", b"unparsed");
    let result = f.boundary().discover(&DiscoveryLimits::default()).unwrap();
    assert!(result.is_complete());
    assert_eq!(result.entries.len(), 3);
    assert!(
        result
            .entries
            .iter()
            .all(|e| e.repository_metadata.is_some())
    );
}

#[test]
fn workspace_no_discovered_build_hook_script_or_executable_is_run() {
    let f = Fixture::new();
    let marker = f.base.join("EXECUTION_CANARY");
    let payload = format!(
        "[IO.File]::WriteAllText('{}', 'executed')",
        marker.display()
    );
    for name in [
        "build.rs",
        "hook.ps1",
        "configure.bat",
        "package.json",
        "target.exe",
        "Makefile",
        "module.ts",
    ] {
        f.file(name, payload.as_bytes());
    }
    let result = f.boundary().discover(&DiscoveryLimits::default()).unwrap();
    assert!(result.is_complete());
    assert_eq!(result.entries.len(), 7);
    assert!(!marker.exists());
}

#[test]
fn workspace_depth_limits_report_partial_instead_of_clean() {
    let f = Fixture::new();
    f.file("a/b/file", b"x");
    let boundary = f.boundary();
    for depth in [0, 1, 2] {
        let result = boundary
            .discover(&DiscoveryLimits {
                max_depth: depth,
                ..Default::default()
            })
            .unwrap();
        assert!(!result.is_complete());
        assert!(
            result
                .incomplete_reasons
                .contains(&IncompleteReason::DepthLimit)
        );
        assert!(
            result
                .entries
                .iter()
                .all(|e| e.relative_path.components().count() <= depth)
        );
    }
    assert!(
        boundary
            .discover(&DiscoveryLimits {
                max_depth: 3,
                ..Default::default()
            })
            .unwrap()
            .is_complete()
    );
}

#[test]
fn workspace_entry_limit_distinguishes_exact_capacity_from_overflow() {
    let f = Fixture::new();
    f.file("a", b"x");
    f.file("b", b"x");
    let boundary = f.boundary();
    let limits = DiscoveryLimits {
        max_entries: 2,
        ..Default::default()
    };
    assert!(boundary.discover(&limits).unwrap().is_complete());
    f.file("c", b"x");
    let result = boundary.discover(&limits).unwrap();
    assert_eq!(result.inspected_entries, 2);
    assert_eq!(result.entries.len(), 2);
    assert_eq!(
        result.incomplete_reasons,
        vec![IncompleteReason::EntryLimit]
    );
}

#[test]
fn workspace_nested_entries_cannot_exceed_global_budget() {
    let f = Fixture::new();
    f.file("a/child", b"x");
    f.file("b", b"x");
    let result = f
        .boundary()
        .discover(&DiscoveryLimits {
            max_entries: 2,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(result.inspected_entries, 2);
    assert_eq!(result.entries.len(), 2);
    assert!(!result.is_complete());
}

#[test]
fn workspace_inventory_byte_limit_stops_with_explicit_status() {
    let f = Fixture::new();
    f.file("long-name", b"x");
    let result = f
        .boundary()
        .discover(&DiscoveryLimits {
            max_inventory_bytes: 2,
            ..Default::default()
        })
        .unwrap();
    assert!(result.entries.is_empty());
    assert_eq!(
        result.incomplete_reasons,
        vec![IncompleteReason::InventoryBytesLimit]
    );
}

#[test]
fn workspace_file_size_limit_quarantines_without_content_read() {
    let f = Fixture::new();
    f.file("large", b"1234");
    let result = f
        .boundary()
        .discover(&DiscoveryLimits {
            max_file_bytes: 3,
            ..Default::default()
        })
        .unwrap();
    assert!(result.entries.is_empty());
    assert_eq!(
        result.quarantined[0].reason,
        QuarantineReason::FileSizeLimit
    );
    assert!(!result.is_complete());
}

#[test]
fn workspace_total_file_length_limit_reports_incomplete() {
    let f = Fixture::new();
    f.file("a", b"12");
    f.file("b", b"34");
    let result = f
        .boundary()
        .discover(&DiscoveryLimits {
            max_total_file_bytes: 3,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(result.total_file_bytes, 2);
    assert_eq!(result.entries.len(), 1);
    assert_eq!(
        result.incomplete_reasons,
        vec![IncompleteReason::TotalFileBytesLimit]
    );
}

#[test]
fn workspace_limits_and_content_read_requests_are_validated() {
    for limits in [
        DiscoveryLimits {
            max_entries: 0,
            ..Default::default()
        },
        DiscoveryLimits {
            max_entries: 100_001,
            ..Default::default()
        },
        DiscoveryLimits {
            max_depth: 129,
            ..Default::default()
        },
        DiscoveryLimits {
            max_file_bytes: 0,
            ..Default::default()
        },
        DiscoveryLimits {
            max_file_bytes: u64::MAX,
            ..Default::default()
        },
        DiscoveryLimits {
            max_total_file_bytes: 0,
            ..Default::default()
        },
        DiscoveryLimits {
            max_inventory_bytes: 0,
            ..Default::default()
        },
        DiscoveryLimits {
            max_metadata_content_bytes: 1,
            ..Default::default()
        },
    ] {
        assert_eq!(
            limits.validate().unwrap_err().kind,
            WorkspaceErrorKind::InvalidLimits
        );
    }
}

#[test]
fn workspace_classification_is_preserved_and_does_not_issue_grants() {
    let f = Fixture::new();
    f.file("metadata", b"x");
    let boundary = WorkspaceBoundary::establish(
        &f.repo,
        SessionId::for_test_sequence(1),
        SecurityClassification::Restricted,
    )
    .unwrap();
    let result = boundary.discover(&DiscoveryLimits::default()).unwrap();
    assert_eq!(result.classification, SecurityClassification::Restricted);
    assert!(
        result
            .entries
            .iter()
            .all(|e| e.classification == SecurityClassification::Restricted)
    );
    // No policy decision, grant, content handle or execution capability is returned.
}

#[test]
fn workspace_oversized_path_is_rejected_before_io() {
    let f = Fixture::new();
    let boundary = f.boundary();
    assert_eq!(
        boundary
            .resolve(Path::new(&"x".repeat(32_769)))
            .unwrap_err()
            .kind,
        WorkspaceErrorKind::InvalidPath(InvalidPathReason::PathTooLong)
    );
}

#[test]
#[ignore = "requires owned junction fixture; run experiments/phase1/workspace/Validate.ps1"]
fn workspace_windows_junction_is_quarantined_without_target_traversal() {
    let fixture = PathBuf::from(
        std::env::var_os("SENTRA_WORKSPACE_TEST_FIXTURE").expect("fixture runner is required"),
    );
    let boundary = WorkspaceBoundary::establish(
        &fixture.join("junction-repo"),
        SessionId::for_test_sequence(1),
        SecurityClassification::Internal,
    )
    .unwrap();
    for relative in [
        "junction",
        "junction/HOST_CANARY",
        "internal-junction",
        "internal-junction/INTERNAL_CANARY",
    ] {
        assert_indirection(boundary.resolve(Path::new(relative)).unwrap_err());
    }
    let result = boundary.discover(&DiscoveryLimits::default()).unwrap();
    assert_eq!(result.entries.len(), 1);
    assert_eq!(
        result.entries[0].repository_metadata,
        Some(RepositoryMetadataKind::Git)
    );
    assert_eq!(result.quarantined.len(), 2);
    assert!(!result.is_complete());
}

#[test]
#[ignore = "requires owned deny-ACL fixture; run experiments/phase1/workspace/Validate.ps1"]
fn workspace_windows_permission_denied_is_not_accepted() {
    let fixture = PathBuf::from(
        std::env::var_os("SENTRA_WORKSPACE_TEST_FIXTURE").expect("fixture runner is required"),
    );
    let boundary = WorkspaceBoundary::establish(
        &fixture.join("denied-repo"),
        SessionId::for_test_sequence(1),
        SecurityClassification::Internal,
    )
    .unwrap();
    for relative in ["denied", "denied-directory"] {
        let result = boundary.resolve(Path::new(relative));
        assert!(result.is_err(), "expected access denial for {relative}");
        let error = result.unwrap_err();
        assert!(matches!(
            error.kind,
            WorkspaceErrorKind::Io {
                kind: std::io::ErrorKind::PermissionDenied,
                ..
            }
        ));
    }
    let result = boundary.discover(&DiscoveryLimits::default()).unwrap();
    assert!(result.entries.is_empty());
    assert_eq!(result.quarantined.len(), 2);
    assert!(!result.is_complete());
}

#[test]
#[ignore = "explicit 10,000-file benchmark; run experiments/phase1/workspace/Validate.ps1"]
fn workspace_scale_10000_file_measurement() {
    let f = Fixture::new();
    for n in 0..10_000 {
        let name = match n % 3 {
            0 => format!("flat-δ-{n:05}.txt"),
            1 => format!("nested Ω/file-{n:05}.txt"),
            _ => format!("nested Ω/deeper/file-{n:05}.txt"),
        };
        f.file(&name, b"trusted synthetic text fixture\n");
    }
    let boundary = f.boundary();
    let start = Instant::now();
    let result = boundary
        .discover(&DiscoveryLimits {
            max_entries: 10_002,
            ..Default::default()
        })
        .unwrap();
    let elapsed = start.elapsed();
    assert!(result.is_complete());
    assert_eq!(
        result
            .entries
            .iter()
            .filter(|entry| entry.kind == WorkspaceEntryKind::File)
            .count(),
        10_000
    );
    assert_eq!(result.entries.len(), 10_002);
    assert_eq!(result.inspected_entries, 10_002);
    assert!(
        elapsed.as_secs_f64() <= 30.0,
        "discovery exceeded the Q-05 timing gate"
    );
    println!(
        "DISCOVERY_METRICS entries=10000 elapsed_ms={} bytes={} complete=true",
        elapsed.as_millis(),
        result.total_file_bytes
    );
}
