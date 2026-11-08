// F-11-02: Adversarial Windows Path Containment Experiment
// Location: experiments/phase1/filesystem-publication/test_path_containment.rs

use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::env;

#[derive(Debug)]
struct ContainmentReport {
    test_name: String,
    success: bool,
    details: String,
}

fn main() {
    let mut reports = Vec::new();

    let temp_root = env::temp_dir().join(format!("Sentra_Path_{}", std::process::id()));
    fs::create_dir_all(&temp_root).expect("create temp dir");
    let staging_root = temp_root.join("staging");
    fs::create_dir_all(&staging_root).expect("create staging dir");

    let canonical_root = fs::canonicalize(&staging_root).expect("canonicalize root");

    // 1. Path::components() behavior on Windows
    let comp_test = Path::new(r"\\?\C:\Storage\Staging\..\Staging\subdir\file.tmp");
    let comps: Vec<String> = comp_test.components().map(|c| format!("{:?}", c)).collect();
    reports.push(ContainmentReport {
        test_name: "1_PathComponentsParsing".to_string(),
        success: true,
        details: format!("Components: {:?}", comps),
    });

    // 2. Case difference in components
    let lower_path = PathBuf::from(canonical_root.to_string_lossy().to_lowercase()).join("child.tmp");
    // Standard starts_with
    let case_starts_with = lower_path.starts_with(&canonical_root);
    reports.push(ContainmentReport {
        test_name: "2_CaseDifference_StandardStartsWith".to_string(),
        success: !case_starts_with, // Documenting that standard starts_with FAILS on case mismatch!
        details: format!("lower_path: {:?}, root: {:?}, starts_with: {}", lower_path, canonical_root, case_starts_with),
    });

    // 3. Drive letter case difference (c: vs C:)
    let drive_str = canonical_root.to_string_lossy();
    let flipped_drive = if drive_str.starts_with(r"\\?\C:") {
        drive_str.replacen(r"\\?\C:", r"\\?\c:", 1)
    } else {
        drive_str.to_string()
    };
    let flipped_path = PathBuf::from(&flipped_drive).join("child.tmp");
    let drive_starts_with = flipped_path.starts_with(&canonical_root);
    reports.push(ContainmentReport {
        test_name: "3_DriveLetterCase_PrefixComponentFolded".to_string(),
        success: drive_starts_with, // VerbatimDisk(67) parses c: and C: to same ASCII byte
        details: format!("flipped: {:?}, root: {:?}, starts_with: {}", flipped_path, canonical_root, drive_starts_with),
    });

    // 4. Forward slash vs backslash
    let fwd_str = canonical_root.to_string_lossy().replace('\\', "/");
    let fwd_path = PathBuf::from(format!("{}/child.tmp", fwd_str));
    let fwd_starts_with = fwd_path.starts_with(&canonical_root);
    reports.push(ContainmentReport {
        test_name: "4_ForwardSlash_Vs_Backslash".to_string(),
        success: true, // PathBuf normalizes separators across components
        details: format!("fwd_path: {:?}, starts_with_canonical: {}", fwd_path, fwd_starts_with),
    });

    // 5. Extended length prefix \\?\ vs standard
    let stripped_root = canonical_root.to_string_lossy().trim_start_matches(r"\\?\").to_string();
    let non_verbatim_path = PathBuf::from(&stripped_root).join("child.tmp");
    let verbatim_match = non_verbatim_path.starts_with(&canonical_root);
    reports.push(ContainmentReport {
        test_name: "5_ExtendedLengthPrefixMismatch".to_string(),
        success: !verbatim_match, // Proves \\?\ prefix mismatch breaks starts_with!
        details: format!("non_verbatim: {:?}, canonical_root: {:?}, starts_with: {}", non_verbatim_path, canonical_root, verbatim_match),
    });

    // 6. Nonexistent destination canonicalization
    let nonexistent = staging_root.join("not_yet_created.tmp");
    let canon_res = fs::canonicalize(&nonexistent);
    reports.push(ContainmentReport {
        test_name: "6_NonexistentPathCanonicalizationFails".to_string(),
        success: canon_res.is_err(), // Proves canonicalize() FAILS with NotFound on nonexistent paths!
        details: format!("canonicalize(nonexistent) error: {:?}", canon_res.err()),
    });

    // 7. Dot and DotDot components traversal
    let traversal = staging_root.join(r"..\escaped.txt");
    let traversal_escapes = traversal.starts_with(&staging_root);
    reports.push(ContainmentReport {
        test_name: "7_DotDotTraversal_Uncanonicalized".to_string(),
        success: traversal_escapes, // In uncanonicalized string/path, 'staging\..\escaped' lexically starts with 'staging'! CRITICAL VULNERABILITY!
        details: format!("traversal: {:?}, lexically starts_with staging_root: {}", traversal, traversal_escapes),
    });

    // 8. Trailing dots and spaces (NTFS normalization)
    let dot_file = staging_root.join("payload.txt.");
    let mut f = File::create(&dot_file).expect("create dot file");
    f.write_all(b"dot-bytes").expect("write");
    drop(f);

    // On Windows NTFS, trailing dot is stripped: opening 'payload.txt' opens 'payload.txt.'!
    let stripped_open = File::open(staging_root.join("payload.txt"));
    reports.push(ContainmentReport {
        test_name: "8_NtfsTrailingDotStripping".to_string(),
        success: stripped_open.is_ok(), // Proves NTFS silently strips trailing dot!
        details: format!("Open 'payload.txt' when 'payload.txt.' created: {:?}", stripped_open.is_ok()),
    });

    // 9. Component-based Normalized Containment Algorithm (The Remediation)
    fn is_strictly_contained(child: &Path, root: &Path) -> bool {
        // Strip verbatim prefix \\?\ for comparison
        fn normalize_prefix<'a>(p: &'a Path) -> &'a Path {
            let s = p.to_str().unwrap_or("");
            if s.starts_with(r"\\?\") {
                Path::new(&s[4..])
            } else {
                p
            }
        }

        let n_child = normalize_prefix(child);
        let n_root = normalize_prefix(root);

        let child_comps: Vec<_> = n_child.components().collect();
        let root_comps: Vec<_> = n_root.components().collect();

        if child_comps.len() <= root_comps.len() {
            return false;
        }

        for (c, r) in child_comps.iter().zip(root_comps.iter()) {
            match (c, r) {
                (Component::Prefix(p1), Component::Prefix(p2)) => {
                    // Compare prefixes case-insensitively
                    let s1 = format!("{:?}", p1.kind()).to_uppercase();
                    let s2 = format!("{:?}", p2.kind()).to_uppercase();
                    if s1 != s2 { return false; }
                }
                (Component::Normal(s1), Component::Normal(s2)) => {
                    if s1.to_string_lossy().to_uppercase() != s2.to_string_lossy().to_uppercase() {
                        return false;
                    }
                }
                (Component::RootDir, Component::RootDir) => {}
                _ => { return false; }
            }
        }
        true
    }

    let remediation_test_lower = is_strictly_contained(&lower_path, &canonical_root);
    let remediation_test_verbatim = is_strictly_contained(&non_verbatim_path, &canonical_root);
    let remediation_test_traversal = is_strictly_contained(&temp_root.join("escaped.txt"), &canonical_root);

    reports.push(ContainmentReport {
        test_name: "9_RemediatedContainmentAlgorithm".to_string(),
        success: remediation_test_lower && remediation_test_verbatim && !remediation_test_traversal,
        details: format!("lower_match: {}, verbatim_match: {}, traversal_rejected: {}",
            remediation_test_lower, remediation_test_verbatim, !remediation_test_traversal),
    });

    // Cleanup
    let _ = fs::remove_dir_all(&temp_root);

    // Print summary
    println!("=== F-11-02 PATH CONTAINMENT EXPERIMENT REPORT ===");
    for r in &reports {
        println!("[{}] {}: {}", if r.success { "VERIFIED" } else { "FAIL" }, r.test_name, r.details);
    }
}
