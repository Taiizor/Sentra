use sentra_core::{
    common::{Clock, MockClock},
    domain::{classification::SecurityClassification, id::SessionId, time::TimestampUtc},
    policy::{
        action::OperationAction,
        approval::{ApprovalBroker, ApprovalGrant, ApprovalRequest},
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

#[test]
fn test_default_deny_unknown_operation() {
    let engine = PolicyEngine::new();
    let session = create_test_session();
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
    let engine = PolicyEngine::new();
    let session = create_test_session();
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
    let engine = PolicyEngine::new();
    let session = create_test_session();
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
    let engine = PolicyEngine::new();
    let session = create_test_session();
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
        file_count: 3,
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
    let engine = PolicyEngine::new();
    let session = create_test_session();
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
    let grant = ApprovalGrant::new(
        request.request_id,
        session.session_id,
        "human_lead_auditor",
        clock.now(),
        &request.action_digest,
        &request.target_revision,
        "token_single_use_abc",
    );

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
    let engine = PolicyEngine::new();
    let session = create_test_session();
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

    let grant = ApprovalGrant::new(
        request.request_id,
        session.session_id,
        "operator_admin",
        clock.now(),
        &request.action_digest,
        &request.target_revision,
        "token_time_travel",
    );

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
    let engine = PolicyEngine::new();
    let session = create_test_session();
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

    // 1. Action digest mismatch
    let bad_action_grant = ApprovalGrant::new(
        request.request_id,
        session.session_id,
        "operator_admin",
        clock.now(),
        "action:exec:different_tool",
        &request.target_revision,
        "token_1",
    );
    assert!(matches!(
        engine.evaluate(
            &session,
            SecurityClassification::Internal,
            &action,
            Some(&bad_action_grant),
            &clock
        ),
        PolicyDecision::Denied {
            reason: DenialReason::ApprovalMismatched(_)
        }
    ));

    // 2. Target revision mismatch
    let bad_rev_grant = ApprovalGrant::new(
        request.request_id,
        session.session_id,
        "operator_admin",
        clock.now(),
        &request.action_digest,
        "sha256:different_revision",
        "token_2",
    );
    assert!(matches!(
        engine.evaluate(
            &session,
            SecurityClassification::Internal,
            &action,
            Some(&bad_rev_grant),
            &clock
        ),
        PolicyDecision::Denied {
            reason: DenialReason::ApprovalMismatched(_)
        }
    ));

    // 3. Session mismatch
    let bad_session_grant = ApprovalGrant::new(
        request.request_id,
        SessionId::new(),
        "operator_admin",
        clock.now(),
        &request.action_digest,
        &request.target_revision,
        "token_3",
    );
    assert!(matches!(
        engine.evaluate(
            &session,
            SecurityClassification::Internal,
            &action,
            Some(&bad_session_grant),
            &clock
        ),
        PolicyDecision::Denied {
            reason: DenialReason::ApprovalMismatched(_)
        }
    ));
}

#[test]
fn test_revoked_approval_request() {
    let broker = ApprovalBroker::new();
    let session_id = SessionId::new();
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    let request = ApprovalRequest::new(
        session_id,
        "operator_admin",
        "action:exec:tool",
        "rev1",
        "Test request",
        None,
        clock.now(),
        3600,
    );
    let req_id = broker.submit_request(request.clone());

    // Revoke the request
    assert!(broker.revoke_request(&req_id));

    // Submitting a grant for revoked request is rejected
    let grant = ApprovalGrant::new(
        req_id,
        session_id,
        "operator_admin",
        clock.now(),
        &request.action_digest,
        &request.target_revision,
        "token_revoked",
    );

    let verify_result = broker.verify_and_consume(&grant, &clock);
    assert!(matches!(
        verify_result,
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

    let engine = PolicyEngine::new();
    let session = create_test_session();
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    let privileged_backend = MockBackend {
        available_capabilities: vec!["vm_exec", "fs_write", "network_egress"],
    };

    let restricted_action = OperationAction::ModifyCheckout {
        file_count: 5,
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
