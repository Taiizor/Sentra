use std::{
    sync::{Arc, Barrier},
    thread,
};

use sentra_core::{
    common::MockClock,
    domain::{
        classification::SecurityClassification,
        error::DomainError,
        id::{Identifier, SessionId},
        time::TimestampUtc,
    },
    policy::{
        action::OperationAction,
        approval::{ApprovalAuthority, ApprovalBroker},
        budget::{BudgetPolicyConfig, CostUsd},
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

fn registered_engine(
    session: &SessionMetadata,
    config: BudgetPolicyConfig,
) -> (PolicyEngine, ApprovalAuthority) {
    let (engine, authority) = PolicyEngine::with_authority(config);
    authority
        .set_session_context(session, "target-rev-1", SecurityClassification::Public)
        .unwrap();
    (engine, authority)
}

// ============================================================================
// 1. Action Digest & Canonicalization Tests
// ============================================================================

#[test]
fn test_action_digest_argument_delimiter_injection_resistance() {
    // Delimiter collision test:
    // Without length-prefixed encoding, ["a,b", "c"] and ["a", "b,c"] would produce identical digests!
    let action_1 = OperationAction::ExecuteTool {
        tool_id: "test-tool".to_string(),
        untrusted: true,
        arguments: vec!["a,b".to_string(), "c".to_string()],
    };

    let action_2 = OperationAction::ExecuteTool {
        tool_id: "test-tool".to_string(),
        untrusted: true,
        arguments: vec!["a".to_string(), "b,c".to_string()],
    };

    let action_3 = OperationAction::ExecuteTool {
        tool_id: "test-tool".to_string(),
        untrusted: true,
        arguments: vec!["a".to_string(), "b".to_string(), "c".to_string()],
    };

    let digest_1 = action_1.action_digest();
    let digest_2 = action_2.action_digest();
    let digest_3 = action_3.action_digest();

    assert_ne!(
        digest_1, digest_2,
        "Length prefixing must distinguish ['a,b', 'c'] from ['a', 'b,c']"
    );
    assert_ne!(
        digest_1, digest_3,
        "Length prefixing must distinguish ['a,b', 'c'] from ['a', 'b', 'c']"
    );
    assert_ne!(
        digest_2, digest_3,
        "Length prefixing must distinguish ['a', 'b,c'] from ['a', 'b', 'c']"
    );
}

#[test]
fn test_action_digest_modify_checkout_target_binding_and_canonical_sorting() {
    // 1. Changing target paths must produce different digests even with identical file_count
    let action_a = OperationAction::ModifyCheckout {
        file_count: 2,
        target_paths: vec!["src/lib.rs".to_string(), "Cargo.toml".to_string()],
    };

    let action_b = OperationAction::ModifyCheckout {
        file_count: 2,
        target_paths: vec![
            "src/lib.rs".to_string(),
            ".github/workflows/ci.yml".to_string(),
        ],
    };

    assert_ne!(
        action_a.action_digest(),
        action_b.action_digest(),
        "Changing target paths must produce distinct action digests"
    );

    // 2. Order permutation must produce identical canonical digests (deterministic sorting)
    let action_c = OperationAction::ModifyCheckout {
        file_count: 2,
        target_paths: vec!["Cargo.toml".to_string(), "src/lib.rs".to_string()],
    };

    assert_eq!(
        action_a.action_digest(),
        action_c.action_digest(),
        "Target path ordering must be canonicalized deterministically"
    );
}

// ============================================================================
// 2. UUID Production/Test Separation and Format Tests
// ============================================================================

#[test]
fn test_uuid_version_variant_and_production_fail_closed() {
    let id = Identifier::new_deterministic(0x1234_5678, 42);

    // Version must be 4
    assert_eq!(
        id.version(),
        4,
        "UUID version bits must indicate version 4 (random/pseudo-random)"
    );

    // Variant must be 2 (binary 10xx, RFC 4122 / Leach-Salz variant 1)
    assert_eq!(
        id.variant(),
        2,
        "UUID variant bits must indicate RFC 4122 variant 1"
    );

    // In safe std without external dependencies, production random generation MUST fail closed
    let prod_result = Identifier::generate_production_v4();
    assert!(
        matches!(prod_result, Err(DomainError::EntropySourceUnavailable(_))),
        "Production CSPRNG generation must fail closed rather than returning predictable sequential values"
    );

    let session_prod = SessionId::generate_production();
    assert!(matches!(
        session_prod,
        Err(DomainError::EntropySourceUnavailable(_))
    ));
}

// ============================================================================
// 3. Concurrency & Atomic Single-Use Grant Consumption Tests
// ============================================================================

#[test]
fn test_concurrent_single_use_approval_consumption_exact_winner() {
    let (broker, authority) = ApprovalBroker::with_authority();
    let broker = Arc::new(broker);
    let session = create_test_session();
    authority
        .set_session_context(&session, "target-rev-1", SecurityClassification::Internal)
        .unwrap();
    let now = TimestampUtc::from_epoch_secs(1_700_000_000);
    let clock = MockClock::new(now);
    let action = OperationAction::ExecuteTool {
        tool_id: "test-tool".into(),
        untrusted: true,
        arguments: vec!["foo".into()],
    };
    let request = broker
        .request_approval(&session, SecurityClassification::Internal, &action, &clock)
        .unwrap();
    let grant = authority
        .issue_grant(&request.request_id, "operator_admin", &clock)
        .unwrap();
    const THREAD_COUNT: usize = 20;
    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    let mut handles = Vec::new();
    for _ in 0..THREAD_COUNT {
        let broker = Arc::clone(&broker);
        let grant = grant.clone();
        let session = session.clone();
        let action = action.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            broker.verify_and_consume(
                Some(&grant),
                &session,
                SecurityClassification::Internal,
                &action,
                &MockClock::new(now),
            )
        }));
    }
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(DenialReason::ApprovalReused(_))))
            .count(),
        THREAD_COUNT - 1
    );
}

#[test]
fn test_failed_validation_does_not_consume_grant() {
    let session = create_test_session();
    let (engine, authority) = registered_engine(&session, Default::default());
    let broker = engine.broker();
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
    let action = OperationAction::ExecuteTool {
        tool_id: "test-tool".into(),
        untrusted: true,
        arguments: vec![],
    };
    let request = broker
        .request_approval(&session, SecurityClassification::Internal, &action, &clock)
        .unwrap();
    let grant = authority
        .issue_grant(&request.request_id, "operator_admin", &clock)
        .unwrap();
    let mut bad = grant.clone();
    bad.target_revision = "wrong_revision".into();
    assert!(matches!(
        broker.verify_and_consume(
            Some(&bad),
            &session,
            SecurityClassification::Internal,
            &action,
            &clock
        ),
        Err(DenialReason::InvalidApprovalGrant(_))
    ));
    assert_eq!(
        broker.verify_and_consume(
            Some(&grant),
            &session,
            SecurityClassification::Internal,
            &action,
            &clock
        ),
        Ok(())
    );
}

// ============================================================================
// 4. Security Classification & Information Flow Tests
// ============================================================================

#[test]
fn test_bell_lapadula_flow_enforcement_prevents_write_down() {
    let session = create_test_session();
    let (engine, _authority) = registered_engine(&session, Default::default());
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    // Attempt to export Confidential data to a destination marked Public
    let write_down_action = OperationAction::ExportReport {
        destination: "public_export.json".to_string(),
        is_external: false,
        destination_classification: Some(SecurityClassification::Public),
    };

    let decision = engine.evaluate(
        &session,
        SecurityClassification::Confidential,
        &write_down_action,
        None,
        &clock,
    );

    assert_eq!(
        decision,
        PolicyDecision::Denied {
            reason: DenialReason::ClassificationExceeded {
                classification: SecurityClassification::Confidential,
                detail:
                    "data at classification [CONFIDENTIAL] cannot flow down to [PUBLIC] under Bell-LaPadula rules"
                        .to_string(),
            }
        }
    );
}

#[test]
fn test_classification_check_never_accidentally_grants_unknown_operation() {
    let session = create_test_session();
    let (engine, _authority) = registered_engine(&session, Default::default());
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    // Unknown operation with Public data must STILL be denied immediately (Default-Deny priority)
    let unknown_action = OperationAction::UnknownOperation {
        operation_name: "RAW_DISK_READ".to_string(),
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
            reason: DenialReason::UnknownOperation("RAW_DISK_READ".to_string())
        }
    );
}

// ============================================================================
// 5. Model-Call Budget & Fixed-Point Currency Representation Tests
// ============================================================================

#[test]
fn test_cost_usd_rejects_nan_infinity_and_negative_amounts() {
    // NaN
    assert!(matches!(
        CostUsd::from_usd_f64(f64::NAN),
        Err(DomainError::InvalidCost(_))
    ));

    // Infinity
    assert!(matches!(
        CostUsd::from_usd_f64(f64::INFINITY),
        Err(DomainError::InvalidCost(_))
    ));
    assert!(matches!(
        CostUsd::from_usd_f64(f64::NEG_INFINITY),
        Err(DomainError::InvalidCost(_))
    ));

    // Negative
    assert!(matches!(
        CostUsd::from_usd_f64(-0.001),
        Err(DomainError::InvalidCost(_))
    ));

    // Valid zero and positive
    assert_eq!(CostUsd::from_usd_f64(0.0).unwrap(), CostUsd::ZERO);
    let one_dollar = CostUsd::from_usd_f64(1.0).unwrap();
    assert_eq!(one_dollar, CostUsd::ONE);
    assert_eq!(one_dollar.as_micro_usd(), 1_000_000);
}

#[test]
fn test_cost_usd_fixed_point_exact_arithmetic() {
    // 0.10 + 0.20 must equal 0.30 exactly without IEEE-754 binary floating point epsilon
    let c1 = CostUsd::from_cents(10);
    let c2 = CostUsd::from_cents(20);
    let sum = c1.checked_add(c2).expect("addition overflow check");
    assert_eq!(sum, CostUsd::from_cents(30));
    assert_eq!(sum.as_micro_usd(), 300_000);

    // Subtraction
    let diff = sum.checked_sub(c1).unwrap();
    assert_eq!(diff, c2);

    // Underflow check
    assert_eq!(c1.checked_sub(c2), None);
}

#[test]
fn test_budget_threshold_boundary_precision() {
    let config = BudgetPolicyConfig {
        max_auto_budget: CostUsd::from_micro_usd(1_000_000), // Exactly $1.000000
        ..Default::default()
    };
    let session = create_test_session();
    let (engine, _authority) = registered_engine(&session, config);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    // At or below threshold: Granted
    let at_threshold = OperationAction::InvokeProvider {
        model_id: "test-model".to_string(),
        estimated_cost: CostUsd::from_micro_usd(1_000_000),
    };
    assert_eq!(
        engine.evaluate(
            &session,
            SecurityClassification::Internal,
            &at_threshold,
            None,
            &clock
        ),
        PolicyDecision::Granted
    );

    // 1 micro-dollar above threshold: NeedsApproval
    let above_threshold = OperationAction::InvokeProvider {
        model_id: "test-model".to_string(),
        estimated_cost: CostUsd::from_micro_usd(1_000_001),
    };
    assert!(
        engine
            .evaluate(
                &session,
                SecurityClassification::Internal,
                &above_threshold,
                None,
                &clock
            )
            .is_needs_approval()
    );
}
