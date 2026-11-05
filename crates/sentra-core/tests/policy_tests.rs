use sentra_core::{
    common::MockClock,
    domain::{classification::SecurityClassification, id::SessionId, time::TimestampUtc},
    policy::{
        action::OperationAction,
        approval::ApprovalAuthority,
        budget::CostUsd,
        decision::{DenialReason, PolicyDecision},
        engine::PolicyEngine,
    },
    session::{metadata::SessionMetadata, state::OperatingMode},
};

fn create_test_session() -> SessionMetadata {
    SessionMetadata::new(
        SessionId::new(),
        TimestampUtc::from_epoch_secs(1_700_000_000),
        "/workspace/test-project",
        OperatingMode::DeepSecurityResearch,
        "operator_tester",
        "sha256:target_revision_rev1",
    )
    .expect("valid session metadata")
}

fn registered_engine(session: &SessionMetadata) -> (PolicyEngine, ApprovalAuthority) {
    let (engine, authority) = PolicyEngine::with_authority(Default::default());
    authority
        .set_session_context(session, "target-rev-1", SecurityClassification::Public)
        .unwrap();
    (engine, authority)
}

#[test]
fn test_default_deny_unknown_operation() {
    let session = create_test_session();
    let (engine, _authority) = registered_engine(&session);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    let unknown_action = OperationAction::UnknownOperation {
        operation_name: "DROP_DATABASE".to_string(),
    };

    let decision = engine.evaluate(
        &session,
        SecurityClassification::Public,
        &unknown_action,
        None,
        &clock,
    );

    assert_eq!(
        decision,
        PolicyDecision::Denied {
            reason: DenialReason::UnknownOperation("DROP_DATABASE".to_string()),
        }
    );
}

#[test]
fn test_safe_operation_auto_granted_for_non_restricted() {
    let session = create_test_session();
    let (engine, _authority) = registered_engine(&session);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    let safe_action = OperationAction::DiscoverMetadata {
        relative_path: "src/lib.rs".to_string(),
    };

    // Public, Internal, Confidential -> Granted
    for classification in [
        SecurityClassification::Public,
        SecurityClassification::Internal,
        SecurityClassification::Confidential,
    ] {
        let decision = engine.evaluate(&session, classification, &safe_action, None, &clock);
        assert_eq!(decision, PolicyDecision::Granted);
    }

    // Export internal report (is_external: false) -> Granted
    let internal_export = OperationAction::ExportReport {
        destination: "artifacts/report.json".to_string(),
        is_external: false,
        destination_classification: None,
    };
    let decision = engine.evaluate(
        &session,
        SecurityClassification::Internal,
        &internal_export,
        None,
        &clock,
    );
    assert_eq!(decision, PolicyDecision::Granted);

    // AI model invocation within auto-budget ($0.50 <= $1.00) -> Granted
    let cheap_ai = OperationAction::InvokeProvider {
        model_id: "mock-fast".to_string(),
        estimated_cost: CostUsd::from_usd_f64(0.50).unwrap(),
    };
    let decision = engine.evaluate(
        &session,
        SecurityClassification::Internal,
        &cheap_ai,
        None,
        &clock,
    );
    assert_eq!(decision, PolicyDecision::Granted);
}

#[test]
fn test_restricted_classification_always_requires_approval() {
    let session = create_test_session();
    let (engine, _authority) = registered_engine(&session);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    // Even read-only discover action requires human approval when data is Restricted
    let action = OperationAction::DiscoverMetadata {
        relative_path: "secrets/keys.pem".to_string(),
    };

    let decision = engine.evaluate(
        &session,
        SecurityClassification::Restricted,
        &action,
        None,
        &clock,
    );

    assert!(decision.is_needs_approval());
    if let PolicyDecision::NeedsApproval { request } = decision {
        assert_eq!(request.session_id, session.session_id);
        assert_eq!(request.action_digest, action.action_digest());
    } else {
        panic!("expected NeedsApproval");
    }
}

#[test]
fn test_sensitive_actions_require_approval() {
    let session = create_test_session();
    let (engine, _authority) = registered_engine(&session);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    // 1. Tool execution (even on public code)
    let tool_action = OperationAction::ExecuteTool {
        tool_id: "semgrep".to_string(),
        untrusted: false,
        arguments: vec!["--config=auto".to_string()],
    };
    assert!(
        engine
            .evaluate(
                &session,
                SecurityClassification::Public,
                &tool_action,
                None,
                &clock
            )
            .is_needs_approval()
    );

    // 2. Checkout modification (S-10)
    let modify_action = OperationAction::ModifyCheckout {
        file_count: 2,
        target_paths: vec!["src/main.rs".to_string(), "Cargo.toml".to_string()],
    };
    assert!(
        engine
            .evaluate(
                &session,
                SecurityClassification::Public,
                &modify_action,
                None,
                &clock
            )
            .is_needs_approval()
    );

    // 3. External report export
    let export_external = OperationAction::ExportReport {
        destination: "https://remote.server/api/v1".to_string(),
        is_external: true,
        destination_classification: None,
    };
    assert!(
        engine
            .evaluate(
                &session,
                SecurityClassification::Public,
                &export_external,
                None,
                &clock
            )
            .is_needs_approval()
    );

    // 4. Cost exceeding auto-budget ceiling ($2.50 > $1.00)
    let expensive_ai = OperationAction::InvokeProvider {
        model_id: "mock-expensive".to_string(),
        estimated_cost: CostUsd::from_usd_f64(2.50).unwrap(),
    };
    assert!(
        engine
            .evaluate(
                &session,
                SecurityClassification::Public,
                &expensive_ai,
                None,
                &clock
            )
            .is_needs_approval()
    );
}

#[test]
fn test_approval_grant_lifecycle_and_single_use_replay_prevention() {
    let session = create_test_session();
    let (engine, authority) = registered_engine(&session);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    let action = OperationAction::ExecuteTool {
        tool_id: "rust-analyzer".to_string(),
        untrusted: true,
        arguments: vec!["check".to_string()],
    };

    // First evaluation: NeedsApproval
    let decision = engine.evaluate(
        &session,
        SecurityClassification::Internal,
        &action,
        None,
        &clock,
    );

    let request = match decision {
        PolicyDecision::NeedsApproval { request } => request,
        other => panic!("expected NeedsApproval, got {:?}", other),
    };

    // Human operator grants approval
    let grant = authority
        .issue_grant(&request.request_id, "human_lead_auditor", &clock)
        .unwrap();

    // Second evaluation with grant: Granted!
    let granted_decision = engine.evaluate(
        &session,
        SecurityClassification::Internal,
        &action,
        Some(&grant),
        &clock,
    );
    assert_eq!(granted_decision, PolicyDecision::Granted);

    // Third evaluation: Replaying the EXACT SAME grant must be DENIED! (Single-use replay protection)
    let replayed_decision = engine.evaluate(
        &session,
        SecurityClassification::Internal,
        &action,
        Some(&grant),
        &clock,
    );

    assert!(matches!(
        replayed_decision,
        PolicyDecision::Denied {
            reason: DenialReason::ApprovalReused(_)
        }
    ));
}

#[test]
fn test_approval_grant_expiry() {
    let session = create_test_session();
    let (engine, authority) = registered_engine(&session);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    let action = OperationAction::ModifyCheckout {
        file_count: 1,
        target_paths: vec!["Cargo.lock".to_string()],
    };

    let decision = engine.evaluate(
        &session,
        SecurityClassification::Internal,
        &action,
        None,
        &clock,
    );

    let request = match decision {
        PolicyDecision::NeedsApproval { request } => request,
        other => panic!("expected NeedsApproval, got {:?}", other),
    };

    let grant = authority
        .issue_grant(&request.request_id, "human_lead_auditor", &clock)
        .unwrap();

    // Advance clock past expiration window (3600 seconds = 1 hour, advance 4000 seconds)
    clock.advance_seconds(4000);

    let expired_decision = engine.evaluate(
        &session,
        SecurityClassification::Internal,
        &action,
        Some(&grant),
        &clock,
    );

    assert!(matches!(
        expired_decision,
        PolicyDecision::Denied {
            reason: DenialReason::ExpiredApprovalGrant(_)
        }
    ));
}

#[test]
fn test_approval_grant_mismatch_rejections() {
    let session = create_test_session();
    let (engine, authority) = registered_engine(&session);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    let action = OperationAction::ExecuteTool {
        tool_id: "linter".to_string(),
        untrusted: false,
        arguments: vec![],
    };

    let decision = engine.evaluate(
        &session,
        SecurityClassification::Internal,
        &action,
        None,
        &clock,
    );
    let request = match decision {
        PolicyDecision::NeedsApproval { request } => request,
        other => panic!("expected NeedsApproval, got {:?}", other),
    };

    let grant = authority
        .issue_grant(&request.request_id, "operator_admin", &clock)
        .unwrap();
    let mut bad_action_grant = grant.clone();
    bad_action_grant.action_digest = "modified operation".into();
    let mut bad_rev_grant = grant.clone();
    bad_rev_grant.target_revision = "different-revision".into();
    let mut bad_session_grant = grant.clone();
    bad_session_grant.session_id = SessionId::new();
    for bad in [bad_action_grant, bad_rev_grant, bad_session_grant] {
        assert!(matches!(
            engine.evaluate(
                &session,
                SecurityClassification::Internal,
                &action,
                Some(&bad),
                &clock
            ),
            PolicyDecision::Denied {
                reason: DenialReason::InvalidApprovalGrant(_)
            }
        ));
    }
    assert!(
        engine
            .evaluate(
                &session,
                SecurityClassification::Internal,
                &action,
                Some(&grant),
                &clock
            )
            .is_granted()
    );
}

#[test]
fn test_revoked_approval_request() {
    let session = create_test_session();
    let (engine, authority) = registered_engine(&session);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
    let action = OperationAction::DiscoverMetadata {
        relative_path: "metadata".into(),
    };
    let request = engine
        .broker()
        .request_approval(&session, SecurityClassification::Internal, &action, &clock)
        .unwrap();
    let grant = authority
        .issue_grant(&request.request_id, "operator_admin", &clock)
        .unwrap();
    assert!(authority.revoke_request(&request.request_id).unwrap());
    assert!(matches!(
        engine.broker().verify_and_consume(
            Some(&grant),
            &session,
            SecurityClassification::Internal,
            &action,
            &clock
        ),
        Err(DenialReason::InvalidApprovalGrant(_))
    ));
}

#[test]
fn test_capability_vs_policy_authorization_separation() {
    // Architectural Invariant:
    // A runner possessing a capability (e.g., container execution) != Policy allows execution.
    // Policy allowing execution != Runner has capability.

    struct MockBackend {
        available_capabilities: Vec<&'static str>,
    }

    impl MockBackend {
        fn has_capability(&self, cap: &str) -> bool {
            self.available_capabilities.contains(&cap)
        }
    }

    let session = create_test_session();
    let (engine, _authority) = registered_engine(&session);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    let privileged_backend = MockBackend {
        available_capabilities: vec!["vm_exec", "fs_write", "network_egress"],
    };

    let restricted_action = OperationAction::ModifyCheckout {
        file_count: 1,
        target_paths: vec!["sensitive.rs".to_string()],
    };

    // Case 1: Backend has capability ("fs_write"), but policy denies without approval!
    assert!(privileged_backend.has_capability("fs_write"));
    let policy_decision = engine.evaluate(
        &session,
        SecurityClassification::Internal,
        &restricted_action,
        None,
        &clock,
    );
    assert!(policy_decision.is_needs_approval());

    // Case 2: Policy grants permission (e.g. read metadata), but backend lacks capability ("hyperv_isolation")
    let uncapable_backend = MockBackend {
        available_capabilities: vec!["stdio_only"],
    };
    let read_action = OperationAction::DiscoverMetadata {
        relative_path: "Cargo.toml".to_string(),
    };
    let read_decision = engine.evaluate(
        &session,
        SecurityClassification::Public,
        &read_action,
        None,
        &clock,
    );
    assert_eq!(read_decision, PolicyDecision::Granted);
    assert!(!uncapable_backend.has_capability("hyperv_isolation"));
}
