use std::{
    sync::{Arc, Barrier, Mutex},
    thread,
};

use sentra_core::{
    common::{Clock, MockClock},
    domain::{
        classification::SecurityClassification,
        error::DomainError,
        id::{Identifier, SessionId},
        time::TimestampUtc,
    },
    policy::{
        action::OperationAction,
        approval::{ApprovalBroker, ApprovalGrant, ApprovalRequest},
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
    // Spin up 20 threads simultaneously trying to consume the exact same approval grant
    let broker = Arc::new(ApprovalBroker::new());
    let session_id = SessionId::new();
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    let request = ApprovalRequest::new(
        session_id,
        "operator_admin",
        "action:exec:tool:args=[3#foo]",
        "rev_commit_1",
        "Sensitive analysis approval",
        None,
        clock.now(),
        3600,
    );
    let req_id = broker.submit_request(request.clone());

    let grant = ApprovalGrant::new(
        req_id,
        session_id,
        "operator_admin",
        clock.now(),
        &request.action_digest,
        &request.target_revision,
        "token_concurrent_race_test",
    );

    const THREAD_COUNT: usize = 20;
    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    let success_count = Arc::new(Mutex::new(0usize));
    let reused_count = Arc::new(Mutex::new(0usize));
    let other_error_count = Arc::new(Mutex::new(0usize));

    let mut handles = Vec::new();

    for _ in 0..THREAD_COUNT {
        let broker_clone = Arc::clone(&broker);
        let grant_clone = grant.clone();
        let barrier_clone = Arc::clone(&barrier);
        let success_clone = Arc::clone(&success_count);
        let reused_clone = Arc::clone(&reused_count);
        let other_clone = Arc::clone(&other_error_count);
        let clock_now = clock.now();

        handles.push(thread::spawn(move || {
            // Synchronize all threads at the starting line
            barrier_clone.wait();

            // All threads race to consume the grant simultaneously
            let clock_inst = MockClock::new(clock_now);
            match broker_clone.verify_and_consume(&grant_clone, &clock_inst) {
                Ok(()) => {
                    let mut cnt = success_clone.lock().unwrap();
                    *cnt += 1;
                }
                Err(DenialReason::ApprovalReused(_)) => {
                    let mut cnt = reused_clone.lock().unwrap();
                    *cnt += 1;
                }
                Err(_) => {
                    let mut cnt = other_clone.lock().unwrap();
                    *cnt += 1;
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("thread join failed");
    }

    let successes = *success_count.lock().unwrap();
    let reuses = *reused_count.lock().unwrap();
    let others = *other_error_count.lock().unwrap();

    assert_eq!(
        successes, 1,
        "Exactly ONE concurrent thread must succeed in consuming the grant"
    );
    assert_eq!(
        reuses,
        THREAD_COUNT - 1,
        "All other concurrent threads must receive ApprovalReused"
    );
    assert_eq!(others, 0, "No other error must occur");
}

#[test]
fn test_failed_validation_does_not_consume_grant() {
    let broker = ApprovalBroker::new();
    let session_id = SessionId::new();
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));

    let request = ApprovalRequest::new(
        session_id,
        "operator_admin",
        "action:exec:tool",
        "rev_a",
        "Test request",
        None,
        clock.now(),
        3600,
    );
    let req_id = broker.submit_request(request.clone());

    // 1. Attempt consumption with wrong target revision
    let bad_grant = ApprovalGrant::new(
        req_id,
        session_id,
        "operator_admin",
        clock.now(),
        &request.action_digest,
        "wrong_revision",
        "token_valid_key",
    );
    let fail_result = broker.verify_and_consume(&bad_grant, &clock);
    assert!(matches!(
        fail_result,
        Err(DenialReason::ApprovalMismatched(_))
    ));

    // 2. Since validation failed, the grant must NOT be consumed!
    // A corrected grant with the right target revision should now succeed!
    let good_grant = ApprovalGrant::new(
        req_id,
        session_id,
        "operator_admin",
        clock.now(),
        &request.action_digest,
        "rev_a",
        "token_valid_key",
    );
    let success_result = broker.verify_and_consume(&good_grant, &clock);
    assert_eq!(
        success_result,
        Ok(()),
        "Corrected grant must succeed because previous failure did not consume it"
    );
}

// ============================================================================
// 4. Security Classification & Information Flow Tests
// ============================================================================

#[test]
fn test_bell_lapadula_flow_enforcement_prevents_write_down() {
    let engine = PolicyEngine::new();
    let session = create_test_session();
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
    let engine = PolicyEngine::new();
    let session = create_test_session();
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
    let engine = PolicyEngine::with_config(config);
    let session = create_test_session();
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
