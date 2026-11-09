//! Conformance and integration tests for continuous hosted integrations and webhook intake
//! (REQ-F18, THREAT_MODEL T-11, Hosted Integration Specification).

use sentra_core::{
    DeliveryLedger, DraftPrProposal, EventKind, ForkSecurityProfile, HostedCredentials,
    HostedPermission, HostedProvider, PrAction, ProposalStatus, StaleHeadGuard, TimestampUtc,
    WebhookErrorKind, WebhookIntake, hmac_sha256_hex,
};

fn sample_github_push_json(repo: &str, before: &str, after: &str) -> String {
    format!(
        r#"{{
  "ref": "refs/heads/main",
  "before": "{before}",
  "after": "{after}",
  "forced": false,
  "repository": {{
    "full_name": "{repo}",
    "clone_url": "https://github.com/{repo}.git",
    "fork": false
  }},
  "commits": [
    {{
      "id": "{after}",
      "message": "fix: security patch"
    }}
  ]
}}"#
    )
}

fn sample_github_pr_json(base_repo: &str, head_repo: &str, is_fork: bool) -> String {
    format!(
        r#"{{
  "action": "opened",
  "number": 42,
  "repository": {{
    "full_name": "{base_repo}",
    "clone_url": "https://github.com/{base_repo}.git",
    "fork": false
  }},
  "pull_request": {{
    "base": {{
      "ref": "main",
      "sha": "1111111111111111111111111111111111111111",
      "repo": {{
        "full_name": "{base_repo}",
        "fork": false
      }}
    }},
    "head": {{
      "ref": "security-fix",
      "sha": "2222222222222222222222222222222222222222",
      "repo": {{
        "full_name": "{head_repo}",
        "fork": {is_fork}
      }}
    }}
  }}
}}"#
    )
}

fn sample_gitlab_push_json(repo: &str, before: &str, after: &str) -> String {
    format!(
        r#"{{
  "ref": "refs/heads/main",
  "before": "{before}",
  "after": "{after}",
  "total_commits_count": 1,
  "project": {{
    "path_with_namespace": "{repo}",
    "git_http_url": "https://gitlab.com/{repo}.git"
  }}
}}"#
    )
}

fn sample_gitlab_mr_json(repo: &str, source_proj_id: i64, target_proj_id: i64) -> String {
    format!(
        r#"{{
  "project": {{
    "path_with_namespace": "{repo}",
    "git_http_url": "https://gitlab.com/{repo}.git"
  }},
  "object_attributes": {{
    "iid": 101,
    "action": "open",
    "target_branch": "main",
    "source_branch": "patch-branch",
    "source_project_id": {source_proj_id},
    "target_project_id": {target_proj_id},
    "last_commit": {{
      "id": "3333333333333333333333333333333333333333"
    }},
    "target": {{
      "default_branch": "4444444444444444444444444444444444444444"
    }}
  }}
}}"#
    )
}

#[test]
fn test_github_push_webhook_authenticated() {
    let secret = b"my-secure-github-webhook-secret-token";
    let mut intake = WebhookIntake::new().with_github_secret(secret.to_vec());

    let before = "0000000000000000000000000000000000000000";
    let after = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let body = sample_github_push_json("sentra-org/sentra-core", before, after);

    let sig = format!("sha256={}", hmac_sha256_hex(secret, body.as_bytes()));
    let now = TimestampUtc::now();

    let event = intake
        .process_github_webhook(
            Some("delivery-001"),
            Some("push"),
            Some(&sig),
            body.as_bytes(),
            now,
        )
        .expect("Valid push webhook must be accepted");

    assert_eq!(event.event_id, "delivery-001");
    assert_eq!(event.provider, HostedProvider::GitHub);
    assert_eq!(event.repository_name, "sentra-org/sentra-core");
    assert!(!event.is_fork);

    match event.payload {
        EventKind::Push(payload) => {
            assert_eq!(payload.ref_name, "refs/heads/main");
            assert_eq!(payload.before_sha, before);
            assert_eq!(payload.after_sha, after);
            assert_eq!(payload.commit_count, 1);
            assert!(!payload.is_forced);
        }
        other => panic!("Expected EventKind::Push, got {other:?}"),
    }
}

#[test]
fn test_github_forged_signature_rejected() {
    let secret = b"my-secure-github-webhook-secret-token";
    let mut intake = WebhookIntake::new().with_github_secret(secret.to_vec());

    let body = sample_github_push_json(
        "sentra-org/sentra-core",
        "0000000000000000000000000000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    let bad_sig = "sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let now = TimestampUtc::now();

    let err = intake
        .process_github_webhook(
            Some("delivery-forged"),
            Some("push"),
            Some(bad_sig),
            body.as_bytes(),
            now,
        )
        .unwrap_err();

    assert_eq!(err.kind(), WebhookErrorKind::InvalidSignature);
}

#[test]
fn test_github_missing_signature_rejected() {
    let secret = b"my-secure-github-webhook-secret-token";
    let mut intake = WebhookIntake::new().with_github_secret(secret.to_vec());

    let body = sample_github_push_json(
        "sentra-org/sentra-core",
        "0000000000000000000000000000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    let now = TimestampUtc::now();

    let err = intake
        .process_github_webhook(
            Some("delivery-nosig"),
            Some("push"),
            None,
            body.as_bytes(),
            now,
        )
        .unwrap_err();

    assert_eq!(err.kind(), WebhookErrorKind::InvalidSignature);
}

#[test]
fn test_github_delivery_replay_rejected() {
    let secret = b"replay-secret";
    let mut intake = WebhookIntake::new().with_github_secret(secret.to_vec());

    let body = sample_github_push_json(
        "sentra-org/sentra-core",
        "0000000000000000000000000000000000000000",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    let sig = format!("sha256={}", hmac_sha256_hex(secret, body.as_bytes()));
    let now = TimestampUtc::now();

    // First delivery succeeds
    let first = intake.process_github_webhook(
        Some("delivery-replay-test"),
        Some("push"),
        Some(&sig),
        body.as_bytes(),
        now,
    );
    assert!(first.is_ok());

    // Duplicate delivery with identical delivery ID must fail closed
    let replay_err = intake
        .process_github_webhook(
            Some("delivery-replay-test"),
            Some("push"),
            Some(&sig),
            body.as_bytes(),
            now,
        )
        .unwrap_err();

    assert_eq!(replay_err.kind(), WebhookErrorKind::ReplayDetected);
}

#[test]
fn test_github_pull_request_with_fork_detection() {
    let mut intake = WebhookIntake::new();
    let now = TimestampUtc::now();

    // 1. Same repo PR (not a fork)
    let internal_body = sample_github_pr_json("upstream/repo", "upstream/repo", false);
    let event1 = intake
        .process_github_webhook(
            Some("delivery-pr-internal"),
            Some("pull_request"),
            None,
            internal_body.as_bytes(),
            now,
        )
        .unwrap();
    assert!(!event1.is_fork);

    // 2. Fork repo PR
    let fork_body = sample_github_pr_json("upstream/repo", "attacker-fork/repo", true);
    let event2 = intake
        .process_github_webhook(
            Some("delivery-pr-fork"),
            Some("pull_request"),
            None,
            fork_body.as_bytes(),
            now,
        )
        .unwrap();

    assert!(event2.is_fork);
    match event2.payload {
        EventKind::PullRequest(pr) => {
            assert_eq!(pr.pr_number, 42);
            assert_eq!(pr.action, PrAction::Opened);
            assert_eq!(pr.base_sha, "1111111111111111111111111111111111111111");
            assert_eq!(pr.head_sha, "2222222222222222222222222222222222222222");
            assert!(pr.is_fork);
        }
        other => panic!("Expected EventKind::PullRequest, got {other:?}"),
    }
}

#[test]
fn test_github_ping_event() {
    let mut intake = WebhookIntake::new();
    let body = r#"{"zen":"Keep it logically awesome.","repository":{"full_name":"org/repo"}}"#;
    let now = TimestampUtc::now();

    let event = intake
        .process_github_webhook(
            Some("delivery-ping"),
            Some("ping"),
            None,
            body.as_bytes(),
            now,
        )
        .unwrap();

    assert_eq!(event.payload, EventKind::Ping);
    assert_eq!(event.repository_name, "org/repo");
}

#[test]
fn test_gitlab_push_webhook_authenticated() {
    let secret = "gitlab-secret-token-xyz";
    let mut intake = WebhookIntake::new().with_gitlab_secret(secret);

    let before = "1234567890123456789012345678901234567890";
    let after = "abcdefabcdefabcdefabcdefabcdefabcdefabcd";
    let body = sample_gitlab_push_json("gitlab-org/project", before, after);
    let now = TimestampUtc::now();

    let event = intake
        .process_gitlab_webhook(
            Some("gitlab-uuid-001"),
            Some("Push Hook"),
            Some(secret),
            body.as_bytes(),
            now,
        )
        .expect("Valid GitLab webhook must succeed");

    assert_eq!(event.provider, HostedProvider::GitLab);
    assert_eq!(event.repository_name, "gitlab-org/project");
    assert!(!event.is_fork);

    match event.payload {
        EventKind::Push(payload) => {
            assert_eq!(payload.ref_name, "refs/heads/main");
            assert_eq!(payload.before_sha, before);
            assert_eq!(payload.after_sha, after);
            assert_eq!(payload.commit_count, 1);
        }
        other => panic!("Expected EventKind::Push, got {other:?}"),
    }
}

#[test]
fn test_gitlab_invalid_token_rejected() {
    let secret = "correct-gitlab-token";
    let mut intake = WebhookIntake::new().with_gitlab_secret(secret);

    let body = sample_gitlab_push_json(
        "gitlab-org/project",
        "1234567890123456789012345678901234567890",
        "abcdefabcdefabcdefabcdefabcdefabcdefabcd",
    );
    let now = TimestampUtc::now();

    let err = intake
        .process_gitlab_webhook(
            Some("gitlab-uuid-bad"),
            Some("Push Hook"),
            Some("wrong-token"),
            body.as_bytes(),
            now,
        )
        .unwrap_err();

    assert_eq!(err.kind(), WebhookErrorKind::InvalidSignature);
}

#[test]
fn test_gitlab_merge_request_fork_detection() {
    let mut intake = WebhookIntake::new();
    let now = TimestampUtc::now();

    // Source project id (999) != Target project id (100) -> Fork!
    let body = sample_gitlab_mr_json("gitlab-org/project", 999, 100);
    let event = intake
        .process_gitlab_webhook(
            Some("gitlab-uuid-mr"),
            Some("Merge Request Hook"),
            None,
            body.as_bytes(),
            now,
        )
        .unwrap();

    assert!(event.is_fork);
    match event.payload {
        EventKind::PullRequest(mr) => {
            assert_eq!(mr.pr_number, 101);
            assert_eq!(mr.action, PrAction::Opened);
            assert_eq!(mr.head_sha, "3333333333333333333333333333333333333333");
            assert_eq!(mr.base_sha, "4444444444444444444444444444444444444444");
            assert!(mr.is_fork);
        }
        other => panic!("Expected EventKind::PullRequest, got {other:?}"),
    }
}

#[test]
fn test_repository_allowlist_enforcement() {
    let mut intake = WebhookIntake::new();
    intake.allow_repository("authorized-owner/authorized-repo");

    let now = TimestampUtc::now();

    // Authorized repository push
    let good_body = sample_github_push_json(
        "authorized-owner/authorized-repo",
        "0000000000000000000000000000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    assert!(
        intake
            .process_github_webhook(
                Some("delivery-good"),
                Some("push"),
                None,
                good_body.as_bytes(),
                now
            )
            .is_ok()
    );

    // Unauthorized repository push
    let bad_body = sample_github_push_json(
        "rogue-owner/unauthorized-repo",
        "0000000000000000000000000000000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let err = intake
        .process_github_webhook(
            Some("delivery-bad"),
            Some("push"),
            None,
            bad_body.as_bytes(),
            now,
        )
        .unwrap_err();

    assert_eq!(err.kind(), WebhookErrorKind::PolicyDenied);
}

#[test]
fn test_malformed_commit_sha_rejected() {
    let mut intake = WebhookIntake::new();
    let now = TimestampUtc::now();

    // Non-hex characters in SHA
    let bad_body = sample_github_push_json(
        "owner/repo",
        "0000000000000000000000000000000000000000",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    );
    let err = intake
        .process_github_webhook(
            Some("delivery-badsha"),
            Some("push"),
            None,
            bad_body.as_bytes(),
            now,
        )
        .unwrap_err();

    assert_eq!(err.kind(), WebhookErrorKind::InvalidRevision);
}

#[test]
fn test_timestamp_drift_freshness_window() {
    let mut ledger = DeliveryLedger::new(300, 100);

    let now = TimestampUtc::now();
    // 10 minutes (600 seconds) in the past exceeds 300s freshness tolerance
    let past = TimestampUtc::from_epoch_millis(now.as_epoch_millis().saturating_sub(600_000));

    let err = ledger
        .record_delivery("event-old", HostedProvider::GitHub, Some(past), now)
        .unwrap_err();

    assert_eq!(err.kind(), WebhookErrorKind::TimestampDriftDetected);

    // Within tolerance (60s in the past) succeeds
    let recent = TimestampUtc::from_epoch_millis(now.as_epoch_millis().saturating_sub(60_000));
    assert!(
        ledger
            .record_delivery("event-recent", HostedProvider::GitHub, Some(recent), now)
            .is_ok()
    );
}

#[test]
fn test_fork_security_profile_strict_zero_secrets() {
    let fork_profile = ForkSecurityProfile::for_fork();
    assert!(fork_profile.is_fork);
    assert!(!fork_profile.secrets_permitted);

    // Attempting secrets access fails closed with ForkSecretAccessDenied
    let err = fork_profile.check_secrets_access().unwrap_err();
    assert_eq!(err.kind(), WebhookErrorKind::ForkSecretAccessDenied);

    // Credentials filtering strictly zeros out all tokens for fork workloads
    let creds = HostedCredentials::new(
        Some("read-token-123".to_string()),
        Some("write-token-456".to_string()),
    );
    let worker_creds = creds.filter_for_worker(&fork_profile);
    assert!(worker_creds.read_token.is_none());
    assert!(worker_creds.write_token.is_none());
}

#[test]
fn test_fork_permission_fencing() {
    let fork_profile = ForkSecurityProfile::for_fork();

    // Read and Analysis are permitted
    assert!(
        fork_profile
            .check_permission(HostedPermission::AcquireSource)
            .is_ok()
    );
    assert!(
        fork_profile
            .check_permission(HostedPermission::RunAnalysis)
            .is_ok()
    );

    // Status checks, PR creation, and public disclosure are strictly denied to forks
    let err_status = fork_profile
        .check_permission(HostedPermission::PublishStatusCheck)
        .unwrap_err();
    assert_eq!(err_status.kind(), WebhookErrorKind::ForkSecretAccessDenied);

    let err_pr = fork_profile
        .check_permission(HostedPermission::ProposeDraftPr)
        .unwrap_err();
    assert_eq!(err_pr.kind(), WebhookErrorKind::ForkSecretAccessDenied);

    let err_disc = fork_profile
        .check_permission(HostedPermission::PublicDisclosure)
        .unwrap_err();
    assert_eq!(err_disc.kind(), WebhookErrorKind::ForkSecretAccessDenied);
}

#[test]
fn test_internal_branch_worker_credentials_filtering() {
    let internal_profile = ForkSecurityProfile::for_internal_branch();
    assert!(!internal_profile.is_fork);
    assert!(internal_profile.secrets_permitted);

    let creds = HostedCredentials::new(
        Some("read-token-123".to_string()),
        Some("write-token-456".to_string()),
    );

    // Write tokens are NEVER passed to workers, even for internal branches (Hosted Security Criteria)
    let worker_creds = creds.filter_for_worker(&internal_profile);
    assert_eq!(worker_creds.read_token, Some("read-token-123".to_string()));
    assert!(worker_creds.write_token.is_none());
}

#[test]
fn test_draft_pr_proposal_creation_and_binding() {
    let base = "1111111111111111111111111111111111111111";
    let head = "2222222222222222222222222222222222222222";
    let diff = "+// verified patch candidate";

    let proposal = DraftPrProposal::new(
        "org/repo",
        base,
        head,
        diff,
        "Fixes buffer boundary violation",
    )
    .expect("Valid proposal must construct");

    assert_eq!(proposal.target_repo, "org/repo");
    assert_eq!(proposal.base_sha, base);
    assert_eq!(proposal.verified_head_sha, head);
    assert_eq!(proposal.status, ProposalStatus::DraftProposed);
    assert!(proposal.is_draft_only);
    assert!(proposal.human_approval_ticket.is_none());

    // Publication without human approval must fail closed
    let err = proposal.assert_can_publish().unwrap_err();
    assert_eq!(err.kind(), WebhookErrorKind::HumanApprovalRequired);
}

#[test]
fn test_draft_pr_proposal_human_approval_lifecycle() {
    let base = "1111111111111111111111111111111111111111";
    let head = "2222222222222222222222222222222222222222";
    let diff = "+// patch diff";

    let mut proposal =
        DraftPrProposal::new("org/repo", base, head, diff, "Fixes use-after-free").unwrap();

    // Operator admits human review ticket
    proposal.admit_human_approval("ticket-human-grant-789");
    assert_eq!(proposal.status, ProposalStatus::ApprovedByHuman);
    assert_eq!(
        proposal.human_approval_ticket,
        Some("ticket-human-grant-789".to_string())
    );

    // Publication is now authorized
    assert!(proposal.assert_can_publish().is_ok());
}

#[test]
fn test_stale_head_divergence_rejected() {
    let verified_head = "2222222222222222222222222222222222222222";
    let force_pushed_head = "3333333333333333333333333333333333333333";

    // Branch head moved/force-pushed after analysis began
    let err = StaleHeadGuard::verify_head_freshness(force_pushed_head, verified_head).unwrap_err();
    assert_eq!(err.kind(), WebhookErrorKind::StaleHeadDivergence);

    // Matching head succeeds
    assert!(StaleHeadGuard::verify_head_freshness(verified_head, verified_head).is_ok());
}

#[test]
fn test_missing_merge_base_rejected() {
    // Missing merge base
    let err_none = StaleHeadGuard::verify_merge_base(None).unwrap_err();
    assert_eq!(err_none.kind(), WebhookErrorKind::MissingMergeBase);

    let err_empty = StaleHeadGuard::verify_merge_base(Some("   ")).unwrap_err();
    assert_eq!(err_empty.kind(), WebhookErrorKind::MissingMergeBase);

    // Valid merge base succeeds
    let valid_base = "4444444444444444444444444444444444444444";
    assert_eq!(
        StaleHeadGuard::verify_merge_base(Some(valid_base)).unwrap(),
        valid_base
    );
}

#[test]
fn test_stale_verification_blocks_publication() {
    let bundle_sha = "2222222222222222222222222222222222222222";
    let current_sha = "5555555555555555555555555555555555555555";

    // Target revision diverged after bundle was computed -> publication blocked
    let err =
        StaleHeadGuard::verify_verification_bundle_freshness(bundle_sha, current_sha).unwrap_err();
    assert_eq!(
        err.kind(),
        WebhookErrorKind::StaleVerificationBlocksPublication
    );

    // Same revision succeeds
    assert!(StaleHeadGuard::verify_verification_bundle_freshness(bundle_sha, bundle_sha).is_ok());
}

#[test]
fn test_autonomous_merge_permanently_prohibited() {
    // Attempting autonomous merge must fail closed (Governance Policy)
    let err = StaleHeadGuard::assert_no_autonomous_merge(true).unwrap_err();
    assert_eq!(err.kind(), WebhookErrorKind::PolicyDenied);

    // Non-merge (draft only) succeeds
    assert!(StaleHeadGuard::assert_no_autonomous_merge(false).is_ok());
}
