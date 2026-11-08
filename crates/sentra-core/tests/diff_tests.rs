//! Exhaustive integration tests for Source Snapshot Diffing, Narrow Hunk Extraction,
//! Revision Invalidation, and Anti-Regression Guards (REQ-F01, REQ-F02, REQ-F04).

use sentra_core::{
    Confidence, DiffErrorKind, DiffLine, FileDeltaKind, Finding, FindingId, FindingSource,
    FindingStatus, HunkLimits, Reachability, RevisionBinding, SessionId, Severity, SourceFileRole,
    SourceSnapshot, SourceSnapshotEntry, TaskId, TimestampUtc, compare_snapshots,
    compute_line_diff, reconcile_findings_anti_regression, validate_patch_approval_invalidation,
};

fn make_entry(path: &str, size_bytes: u64, content: &str) -> SourceSnapshotEntry {
    use sentra_core::sha256_prefixed;
    let digest = sha256_prefixed(content.as_bytes());
    SourceSnapshotEntry {
        path: path.to_string(),
        size_bytes,
        content_sha256: digest,
        role: SourceFileRole::from_path(std::path::Path::new(path)),
    }
}

fn make_snapshot(session_id: &str, entries: Vec<SourceSnapshotEntry>) -> SourceSnapshot {
    let mut sorted = entries;
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    let total_files = sorted.len();
    let total_bytes = sorted.iter().map(|e| e.size_bytes).sum();
    let aggregate_digest = SourceSnapshot::compute_aggregate_digest(&sorted);

    SourceSnapshot {
        version: SourceSnapshot::SCHEMA_VERSION,
        session_id: session_id.to_string(),
        root_label: "test-workspace".to_string(),
        entries: sorted,
        total_files,
        total_bytes,
        aggregate_digest,
        created_at: "2026-11-08T22:00:00Z".to_string(),
    }
}

#[test]
fn test_snapshot_diff_added_modified_deleted_unchanged() {
    let base = make_snapshot(
        "session-1",
        vec![
            make_entry("src/main.rs", 100, "fn main() { println!(\"v1\"); }"),
            make_entry("src/util.rs", 50, "pub fn helper() -> bool { true }"),
            make_entry("Cargo.toml", 80, "[package]\nname = \"demo\"\n"),
            make_entry("README.md", 40, "# Demo project\n"),
        ],
    );

    let head = make_snapshot(
        "session-1",
        vec![
            // Modified
            make_entry(
                "src/main.rs",
                110,
                "fn main() { println!(\"v2 modified\"); }",
            ),
            // Deleted src/util.rs
            // Added src/helper.rs
            make_entry("src/helper.rs", 60, "pub fn new_helper() -> i32 { 42 }"),
            // Unchanged Cargo.toml and README.md
            make_entry("Cargo.toml", 80, "[package]\nname = \"demo\"\n"),
            make_entry("README.md", 40, "# Demo project\n"),
        ],
    );

    let diff = compare_snapshots(&base, &head);

    assert_eq!(diff.summary.total_files_base, 4);
    assert_eq!(diff.summary.total_files_head, 4);
    assert_eq!(diff.summary.added_files, 1);
    assert_eq!(diff.summary.modified_files, 1);
    assert_eq!(diff.summary.deleted_files, 1);
    assert_eq!(diff.summary.unchanged_files, 2);
    assert_eq!(diff.summary.renamed_files, 0);
    // Rust files changed: main.rs (modified), util.rs (deleted), helper.rs (added) -> 3
    assert_eq!(diff.summary.rust_files_changed, 3);

    let changed = diff.changed_deltas();
    assert_eq!(changed.len(), 3);

    let helper_delta = diff
        .deltas
        .iter()
        .find(|d| d.path == "src/helper.rs")
        .unwrap();
    assert_eq!(helper_delta.kind, FileDeltaKind::Added);
    assert_eq!(helper_delta.role, SourceFileRole::RustSource);

    let main_delta = diff
        .deltas
        .iter()
        .find(|d| d.path == "src/main.rs")
        .unwrap();
    assert_eq!(main_delta.kind, FileDeltaKind::Modified);

    let util_delta = diff
        .deltas
        .iter()
        .find(|d| d.path == "src/util.rs")
        .unwrap();
    assert_eq!(util_delta.kind, FileDeltaKind::Deleted);
}

#[test]
fn test_snapshot_diff_detects_file_renames() {
    let content = "pub fn shared_constant() -> &'static str { \"immutable\" }";
    let base = make_snapshot(
        "session-1",
        vec![make_entry("src/old_path.rs", content.len() as u64, content)],
    );

    let head = make_snapshot(
        "session-1",
        vec![make_entry("src/new_path.rs", content.len() as u64, content)],
    );

    let diff = compare_snapshots(&base, &head);

    assert_eq!(diff.summary.renamed_files, 1);
    assert_eq!(diff.summary.added_files, 0);
    assert_eq!(diff.summary.deleted_files, 0);
    assert_eq!(diff.summary.rust_files_changed, 1);

    let renamed = diff
        .deltas
        .iter()
        .find(|d| d.path == "src/new_path.rs")
        .unwrap();
    assert_eq!(
        renamed.kind,
        FileDeltaKind::Renamed {
            from_path: "src/old_path.rs".to_string()
        }
    );
    assert_eq!(renamed.base_digest, renamed.head_digest);
}

#[test]
fn test_narrow_line_diff_computation_with_context() {
    let old_text = "line 1\nline 2\nline 3\nline 4 target\nline 5\nline 6\nline 7\n";
    let new_text = "line 1\nline 2\nline 3\nline 4 REPLACED\nline 5\nline 6\nline 7\n";

    let limits = HunkLimits {
        context_lines: 2,
        max_hunks: 10,
        max_diff_lines: 100,
    };

    let diff = compute_line_diff("src/test.rs", old_text, new_text, &limits).expect("diff");

    assert!(!diff.is_binary);
    assert_eq!(diff.additions_count, 1);
    assert_eq!(diff.deletions_count, 1);
    assert_eq!(diff.hunks.len(), 1);

    let hunk = &diff.hunks[0];
    // With 2 context lines: lines 2 and 3 before, line 4 edit, lines 5 and 6 after -> 5 lines
    assert_eq!(hunk.old_start, 2);
    assert_eq!(hunk.old_lines, 5);
    assert_eq!(hunk.new_start, 2);
    assert_eq!(hunk.new_lines, 5);

    assert!(
        hunk.lines
            .iter()
            .any(|l| matches!(l, DiffLine::Deletion(t) if t == "line 4 target"))
    );
    assert!(
        hunk.lines
            .iter()
            .any(|l| matches!(l, DiffLine::Addition(t) if t == "line 4 REPLACED"))
    );
}

#[test]
fn test_binary_file_diff_handling() {
    let old_binary = "header\0binary_data_1";
    let new_binary = "header\0binary_data_2";

    let diff = compute_line_diff(
        "target/output.bin",
        old_binary,
        new_binary,
        &HunkLimits::default(),
    )
    .expect("diff");

    assert!(diff.is_binary);
    assert!(diff.hunks.is_empty());
    assert_eq!(diff.additions_count, 0);
    assert_eq!(diff.deletions_count, 0);
}

#[test]
fn test_diff_limits_exceeded_fails_closed() {
    let mut old_builder = String::new();
    let mut new_builder = String::new();

    // Generate 10 widely spaced edit points
    for i in 0..10 {
        old_builder.push_str(&format!("context_{i}_1\ncontext_{i}_2\ncontext_{i}_3\nold_{i}\ncontext_{i}_4\ncontext_{i}_5\ncontext_{i}_6\n"));
        new_builder.push_str(&format!("context_{i}_1\ncontext_{i}_2\ncontext_{i}_3\nnew_{i}\ncontext_{i}_4\ncontext_{i}_5\ncontext_{i}_6\n"));
    }

    let limits = HunkLimits {
        context_lines: 1,
        max_hunks: 3, // Allowed only 3 hunks
        max_diff_lines: 1000,
    };

    let err = compute_line_diff("src/big.rs", &old_builder, &new_builder, &limits).unwrap_err();
    assert!(matches!(err.kind, DiffErrorKind::LimitsExceeded(_)));
}

#[test]
fn test_f01_revision_binding_and_invalidation() {
    let binding = RevisionBinding::new("git:commit-abc", "sha256:1111222233334444");

    // Exact match succeeds
    assert!(
        binding
            .verify_alignment("git:commit-abc", "sha256:1111222233334444")
            .is_ok()
    );

    // Mismatched revision fails
    let err_rev = binding
        .verify_alignment("git:commit-def", "sha256:1111222233334444")
        .unwrap_err();
    assert!(matches!(
        err_rev.kind,
        DiffErrorKind::RevisionMismatch { .. }
    ));

    // Mismatched aggregate digest fails
    let err_dig = binding
        .verify_alignment("git:commit-abc", "sha256:9999888877776666")
        .unwrap_err();
    assert!(matches!(
        err_dig.kind,
        DiffErrorKind::RevisionMismatch { .. }
    ));
}

#[test]
fn test_f04_patch_approval_invalidated_on_revision_change() {
    // Approved revision against candidate revision
    assert!(validate_patch_approval_invalidation("rev-100", "rev-100").is_ok());

    let err = validate_patch_approval_invalidation("rev-100", "rev-101-mutated").unwrap_err();
    assert!(matches!(
        err.kind,
        DiffErrorKind::RevisionMismatch { expected, actual } if expected == "rev-100" && actual == "rev-101-mutated"
    ));
}

#[test]
fn test_f04_absence_in_later_scan_cannot_resolve_finding() {
    let now = TimestampUtc::now();
    let finding1 = Finding::new_candidate(
        FindingId::new(),
        SessionId::new(),
        TaskId::new(),
        "SQL injection vulnerability",
        "Raw string concat in query",
        Severity::High,
        Confidence::Confirmed,
        Reachability::PresentOnly,
        FindingSource::StaticAnalysis {
            engine: "analyzer".to_string(),
            rule_id: "sec-sql-01".to_string(),
        },
        None,
        None,
        now,
    );

    let finding2 = Finding::new_candidate(
        FindingId::new(),
        SessionId::new(),
        TaskId::new(),
        "XSS vulnerability in renderer",
        "Unsanitized input in HTML output",
        Severity::Medium,
        Confidence::Confirmed,
        Reachability::PresentOnly,
        FindingSource::StaticAnalysis {
            engine: "analyzer".to_string(),
            rule_id: "sec-xss-02".to_string(),
        },
        None,
        None,
        now,
    );

    let previous_findings = vec![finding1.clone(), finding2.clone()];
    // Next scan only detected finding1. finding2 was absent.
    let current_findings = vec![finding1.clone()];

    let reconciled = reconcile_findings_anti_regression(
        &previous_findings,
        &current_findings,
        "commit-head-v2",
        now,
    );

    // Invariant: absence in later scan CANNOT drop finding or resolve it as fixed!
    assert_eq!(reconciled.len(), 2);

    let absent_finding = reconciled.iter().find(|f| f.id() == finding2.id()).unwrap();
    // Status must NOT be Candidate or Validated; it must be marked Inconclusive with justification
    assert_eq!(absent_finding.status(), FindingStatus::Inconclusive);
    assert_eq!(absent_finding.history().len(), 1);
    assert!(
        absent_finding.history()[0]
            .reason
            .contains("absence alone cannot resolve a vulnerability")
    );
}

#[test]
fn test_diff_serialization_roundtrip() {
    let base = make_snapshot(
        "session-1",
        vec![make_entry("src/lib.rs", 100, "pub fn old() {}")],
    );
    let head = make_snapshot(
        "session-1",
        vec![make_entry("src/lib.rs", 120, "pub fn new() {}")],
    );

    let diff = compare_snapshots(&base, &head);
    let json = serde_json::to_string(&diff).expect("serialize");
    let recovered: sentra_core::SnapshotDiff = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(recovered.schema_version, diff.schema_version);
    assert_eq!(recovered.summary, diff.summary);
    assert_eq!(recovered.deltas.len(), diff.deltas.len());
    assert_eq!(recovered.deltas[0].kind, FileDeltaKind::Modified);
}
