//! Integration tests for automated remediation PR proposals (REQ-F11, REQ-F18).

use sentra_core::{
    Advisory, AdvisoryMatch, Reachability, RemediationPrPackage, Severity,
    domain::finding::{Confidence, Finding, FindingSource, TargetLocation},
    domain::id::{FindingId, SessionId, TaskId},
    domain::time::TimestampUtc,
};

#[test]
fn test_remediation_pr_from_advisory_match() {
    let advisory = Advisory {
        id: "GHSA-p6mc-m468-83gw".to_string(),
        package: "lodash".to_string(),
        title: "Prototype Pollution in lodash".to_string(),
        description: "lodash versions prior to 4.17.21 are vulnerable to Prototype Pollution."
            .to_string(),
        severity: Severity::Critical,
        affected_version_reqs: vec!["< 4.17.21".to_string()],
        patched_versions: vec!["4.17.21".to_string()],
        published_at: "2020-07-16T00:00:00Z".to_string(),
        aliases: vec!["CVE-2020-8203".to_string()],
    };

    let advisory_match = AdvisoryMatch {
        advisory,
        package: "lodash".to_string(),
        installed_version: "4.17.15".to_string(),
        reachability: Reachability::PresentOnly,
        recommended_patch: Some("4.17.21".to_string()),
    };

    let base_sha = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
    let pkg = RemediationPrPackage::from_advisory_match(&advisory_match, "package.json", base_sha);

    assert!(pkg.proposal_id.starts_with("prop-"));
    assert_eq!(pkg.branch_name, "sentra/remediate-ghsa-p6mc-m468-83gw");
    assert!(pkg.title.contains("GHSA-p6mc-m468-83gw"));
    assert!(pkg.title.contains("lodash"));
    assert!(pkg.title.contains("4.17.15 to 4.17.21"));
    assert!(pkg.commit_message.contains("fix(deps): bump lodash"));
    assert!(pkg.patch_diff.contains("--- a/package.json"));
    assert!(pkg.patch_diff.contains("+++ b/package.json"));
    assert!(pkg.patch_diff.contains("4.17.21"));
    assert!(pkg.body_markdown.contains("GHSA-p6mc-m468-83gw"));
    assert!(pkg.body_markdown.contains("CVE-2020-8203"));
    assert!(pkg.body_markdown.contains("CRITICAL"));
    assert!(pkg.body_markdown.contains("PRESENT_ONLY"));
    assert!(pkg.gh_command.starts_with("gh pr create --draft"));
    assert!(pkg.is_draft_only);
}

#[test]
fn test_remediation_pr_from_static_finding() {
    let now = TimestampUtc::now();
    let finding = Finding::new_candidate(
        FindingId::new(),
        SessionId::new(),
        TaskId::new(),
        "Hardcoded AWS Access Key ID in config.rs",
        "Found hardcoded AWS access key ID in line 42",
        Severity::Critical,
        Confidence::High,
        Reachability::SyntacticallyReferenced,
        FindingSource::StaticAnalysis {
            engine: "sentra-sast".to_string(),
            rule_id: "SENTRA-SEC-001".to_string(),
        },
        Some(TargetLocation {
            path: "src/config.rs".to_string(),
            start_line: Some(42),
            end_line: Some(42),
        }),
        None,
        now,
    );

    let pkg =
        RemediationPrPackage::from_finding(&finding, "1234567890abcdef1234567890abcdef12345678");

    assert!(pkg.proposal_id.starts_with("prop-"));
    assert_eq!(pkg.branch_name, "sentra/fix-sentra-sec-001");
    assert!(pkg.title.contains("SENTRA-SEC-001"));
    assert!(pkg.body_markdown.contains("SENTRA-SEC-001"));
    assert!(pkg.patch_diff.contains("--- a/src/config.rs"));
    assert!(pkg.patch_diff.contains("@@ -42,1 +42,1 @@"));
    assert!(pkg.is_draft_only);
}
