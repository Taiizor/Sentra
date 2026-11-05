//! Targeted 5.3.1 authorization regression fixtures; no target operation is dispatched.
use std::{
    collections::BTreeSet,
    sync::{Arc, Barrier},
    thread,
};

use sentra_core::{
    ApprovalAuthority, ApprovalBroker, ApprovalGrant, ApprovalId, BudgetPolicyConfig, Clock,
    CostUsd, DenialReason, MockClock, OperatingMode, OperationAction, PolicyDecision, PolicyEngine,
    SecurityClassification as Class, SessionId, SessionMetadata, TimestampUtc,
};

struct Harness {
    engine: PolicyEngine,
    authority: ApprovalAuthority,
    session: SessionMetadata,
    clock: MockClock,
    action: OperationAction,
}

impl Harness {
    fn new() -> Self {
        Self::action(OperationAction::DiscoverMetadata {
            relative_path: "approved-metadata".into(),
        })
    }
    fn action(action: OperationAction) -> Self {
        let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_000));
        let session = SessionMetadata::new(
            SessionId::for_test_sequence(531),
            clock.now(),
            "/authorized/workspace-A",
            OperatingMode::ContinuousReview,
            "operator-A",
            "policy-v1",
        )
        .unwrap();
        let (engine, authority) = PolicyEngine::with_authority(BudgetPolicyConfig::default());
        authority
            .set_session_context(&session, "target-revision-A", Class::Public)
            .unwrap();
        Self {
            engine,
            authority,
            session,
            clock,
            action,
        }
    }
    fn grant(&self) -> ApprovalGrant {
        let PolicyDecision::NeedsApproval { request } = self.engine.evaluate(
            &self.session,
            Class::Restricted,
            &self.action,
            None,
            &self.clock,
        ) else {
            panic!("approval must be required")
        };
        self.authority
            .issue_grant(&request.request_id, "trusted-human", &self.clock)
            .unwrap()
    }
    fn consume(&self, grant: &ApprovalGrant) -> Result<(), DenialReason> {
        self.engine.broker().verify_and_consume(
            Some(grant),
            &self.session,
            Class::Restricted,
            &self.action,
            &self.clock,
        )
    }
    fn evaluate(&self, grant: &ApprovalGrant) -> PolicyDecision {
        self.engine.evaluate(
            &self.session,
            Class::Restricted,
            &self.action,
            Some(grant),
            &self.clock,
        )
    }
}

#[test]
fn exact_issued_operation_authorizes_once_through_policy_and_broker() {
    let h = Harness::new();
    let grant = h.grant();
    assert!(h.evaluate(&grant).is_granted());
    assert!(matches!(
        h.consume(&grant),
        Err(DenialReason::ApprovalReused(_))
    ));
    assert!(matches!(
        h.evaluate(&grant),
        PolicyDecision::Denied {
            reason: DenialReason::ApprovalReused(_)
        }
    ));
}

#[test]
fn original_a_to_b_probe_denies_then_allows_a_exactly_once() {
    let h = Harness::new();
    let grant = h.grant();
    let b = OperationAction::DiscoverMetadata {
        relative_path: "different-metadata".into(),
    };
    assert!(matches!(
        h.engine
            .evaluate(&h.session, Class::Restricted, &b, Some(&grant), &h.clock),
        PolicyDecision::Denied {
            reason: DenialReason::ApprovalMismatched(_)
        }
    ));
    assert!(matches!(
        h.engine.broker().verify_and_consume(
            Some(&grant),
            &h.session,
            Class::Restricted,
            &b,
            &h.clock
        ),
        Err(DenialReason::ApprovalMismatched(_))
    ));
    assert!(h.engine.broker().get_request(&grant.request_id).is_some());
    assert!(h.evaluate(&grant).is_granted());
    assert!(h.evaluate(&grant).is_denied());
}

fn tool(id: &str, untrusted: bool, args: &[&str]) -> OperationAction {
    OperationAction::ExecuteTool {
        tool_id: id.into(),
        untrusted,
        arguments: args.iter().map(|s| (*s).into()).collect(),
    }
}
fn provider(id: &str, cost: u64) -> OperationAction {
    OperationAction::InvokeProvider {
        model_id: id.into(),
        estimated_cost: CostUsd::from_micro_usd(cost),
    }
}
fn export(destination: &str, external: bool, classification: Option<Class>) -> OperationAction {
    OperationAction::ExportReport {
        destination: destination.into(),
        is_external: external,
        destination_classification: classification,
    }
}
fn modify(paths: &[&str]) -> OperationAction {
    OperationAction::ModifyCheckout {
        file_count: paths.len(),
        target_paths: paths.iter().map(|s| (*s).into()).collect(),
    }
}

#[test]
fn every_operation_parameter_change_is_denied_without_consuming_matching_grant() {
    let discover = || OperationAction::DiscoverMetadata {
        relative_path: "metadata-A".into(),
    };
    let cases = vec![
        (discover(), tool("tool", true, &[])),
        (
            discover(),
            OperationAction::DiscoverMetadata {
                relative_path: "metadata-B".into(),
            },
        ),
        (tool("A", true, &["a"]), tool("B", true, &["a"])),
        (tool("A", true, &["a"]), tool("A", false, &["a"])),
        (tool("A", true, &["a"]), tool("A", true, &["b"])),
        (tool("A", true, &["a", "b"]), tool("A", true, &["b", "a"])),
        (
            tool("A", true, &["a,b", "c"]),
            tool("A", true, &["a", "b,c"]),
        ),
        (tool("A", true, &[]), tool("A", true, &[""])),
        (provider("A", 10), provider("B", 10)),
        (provider("A", 10), provider("A", 11)),
        (export("A", true, None), export("B", true, None)),
        (export("A", true, None), export("A", false, None)),
        (
            export("A", true, None),
            export("A", true, Some(Class::Restricted)),
        ),
        (
            export("A", true, Some(Class::Restricted)),
            export("A", true, Some(Class::Confidential)),
        ),
        (modify(&["a"]), modify(&["b"])),
        (modify(&["a"]), modify(&["a", "b"])),
    ];
    for (approved, changed) in cases {
        let h = Harness::action(approved);
        let grant = h.grant();
        assert_ne!(h.action.action_digest(), changed.action_digest());
        assert!(
            h.engine
                .evaluate(
                    &h.session,
                    Class::Restricted,
                    &changed,
                    Some(&grant),
                    &h.clock
                )
                .is_denied()
        );
        assert!(
            h.engine
                .broker()
                .verify_and_consume(
                    Some(&grant),
                    &h.session,
                    Class::Restricted,
                    &changed,
                    &h.clock
                )
                .is_err()
        );
        assert_eq!(h.consume(&grant), Ok(()));
    }
}

#[test]
fn checkout_target_order_is_canonical_but_target_set_is_bound() {
    let h = Harness::action(modify(&["b", "a"]));
    let grant = h.grant();
    let reordered = modify(&["a", "b"]);
    assert_eq!(h.action.action_digest(), reordered.action_digest());
    assert!(
        h.engine
            .evaluate(
                &h.session,
                Class::Restricted,
                &reordered,
                Some(&grant),
                &h.clock
            )
            .is_granted()
    );
}

#[test]
fn canonical_framing_handles_delimiters_unicode_empty_args_and_optional_fields() {
    let values = [
        "tool",
        "7#tool:untrusted=true:args=[",
        "δ,[]:#",
        "NONE:dst_class=RESTRICTED",
    ];
    let args: &[&[&str]] = &[&[], &[""], &["a,b", "c"], &["a", "b,c"], &["δ"], &["", ""]];
    let mut encodings = BTreeSet::new();
    for value in values {
        for untrusted in [false, true] {
            for arguments in args {
                assert!(encodings.insert(tool(value, untrusted, arguments).action_digest()));
            }
        }
        for cost in [0, 1, u64::MAX] {
            assert!(encodings.insert(provider(value, cost).action_digest()));
        }
        for external in [false, true] {
            for class in [None, Some(Class::Public), Some(Class::Restricted)] {
                assert!(encodings.insert(export(value, external, class).action_digest()));
            }
        }
        assert!(
            encodings.insert(
                OperationAction::DiscoverMetadata {
                    relative_path: value.into()
                }
                .action_digest()
            )
        );
        assert!(encodings.insert(modify(&[value]).action_digest()));
    }
}

#[test]
fn different_registered_session_cannot_use_a_grant_even_with_same_target() {
    let h = Harness::new();
    let grant = h.grant();
    let mut other = h.session.clone();
    other.session_id = SessionId::for_test_sequence(532);
    h.authority
        .set_session_context(&other, "target-revision-A", Class::Public)
        .unwrap();
    assert!(
        h.engine
            .evaluate(&other, Class::Restricted, &h.action, Some(&grant), &h.clock)
            .is_denied()
    );
    assert!(
        h.engine
            .broker()
            .verify_and_consume(Some(&grant), &other, Class::Restricted, &h.action, &h.clock)
            .is_err()
    );
    assert_eq!(h.consume(&grant), Ok(()));
}

#[test]
fn caller_metadata_cannot_replace_registered_workspace_actor_policy_or_mode() {
    let h = Harness::new();
    let grant = h.grant();
    let mut variants = Vec::new();
    let mut s = h.session.clone();
    s.workspace_root = "/other/repository".into();
    variants.push(s);
    let mut s = h.session.clone();
    s.operator_id = "another-actor".into();
    variants.push(s);
    let mut s = h.session.clone();
    s.policy_digest = "different-policy".into();
    variants.push(s);
    let mut s = h.session.clone();
    s.operating_mode = OperatingMode::DeepSecurityResearch;
    variants.push(s);
    let mut s = h.session.clone();
    s.created_at_utc = s.created_at_utc.add_seconds(1);
    variants.push(s);
    for different in variants {
        assert!(
            h.engine
                .evaluate(
                    &different,
                    Class::Restricted,
                    &h.action,
                    Some(&grant),
                    &h.clock
                )
                .is_denied()
        );
        assert!(
            h.engine
                .broker()
                .verify_and_consume(
                    Some(&grant),
                    &different,
                    Class::Restricted,
                    &h.action,
                    &h.clock
                )
                .is_err()
        );
    }
    assert_eq!(h.consume(&grant), Ok(()));
}

#[test]
fn trusted_target_revision_change_invalidates_grant_even_after_aba_restore() {
    let h = Harness::new();
    let grant = h.grant();
    for revision in ["target-revision-B", "target-revision-A"] {
        h.authority
            .set_session_context(&h.session, revision, Class::Public)
            .unwrap();
        assert!(h.evaluate(&grant).is_denied());
        assert!(h.consume(&grant).is_err());
    }
    let fresh = h.grant();
    assert!(h.evaluate(&fresh).is_granted());
}

#[test]
fn trusted_workspace_rebinding_invalidates_original_target_grant() {
    let h = Harness::new();
    let grant = h.grant();
    let mut changed = h.session.clone();
    changed.workspace_root = "/authorized/workspace-B".into();
    h.authority
        .set_session_context(&changed, "target-revision-A", Class::Public)
        .unwrap();
    assert!(
        h.engine
            .evaluate(
                &changed,
                Class::Restricted,
                &h.action,
                Some(&grant),
                &h.clock
            )
            .is_denied()
    );
    assert!(
        h.engine
            .broker()
            .verify_and_consume(
                Some(&grant),
                &changed,
                Class::Restricted,
                &h.action,
                &h.clock
            )
            .is_err()
    );
}

#[test]
fn stale_pending_request_cannot_be_issued_after_trusted_context_change() {
    let h = Harness::new();
    let request = h
        .engine
        .broker()
        .request_approval(&h.session, Class::Restricted, &h.action, &h.clock)
        .unwrap();
    h.authority
        .set_session_context(&h.session, "target-revision-B", Class::Public)
        .unwrap();
    assert!(matches!(
        h.authority
            .issue_grant(&request.request_id, "trusted-human", &h.clock),
        Err(DenialReason::ApprovalMismatched(_))
    ));
    let fresh = h.grant();
    assert!(h.evaluate(&fresh).is_granted());
}

#[test]
fn classification_is_bound_and_presented_grant_cannot_take_automatic_fallback() {
    let h = Harness::new();
    let grant = h.grant();
    assert!(
        h.engine
            .evaluate(&h.session, Class::Public, &h.action, Some(&grant), &h.clock)
            .is_denied()
    );
    assert!(
        h.engine
            .broker()
            .verify_and_consume(Some(&grant), &h.session, Class::Public, &h.action, &h.clock)
            .is_err()
    );
    assert_eq!(h.consume(&grant), Ok(()));
}

#[test]
fn trusted_classification_floor_blocks_caller_downgrade_without_a_grant() {
    let h = Harness::new();
    h.authority
        .set_session_context(&h.session, "target-revision-A", Class::Restricted)
        .unwrap();
    assert!(
        h.engine
            .evaluate(&h.session, Class::Public, &h.action, None, &h.clock)
            .is_denied()
    );
    let grant = h.grant();
    assert!(h.evaluate(&grant).is_granted());
}

#[test]
fn every_public_grant_field_is_integrity_checked_without_consuming_original() {
    let h = Harness::new();
    let grant = h.grant();
    let mut changed = Vec::new();
    let mut g = grant.clone();
    g.request_id = ApprovalId::from_sequence(99_999);
    changed.push(g);
    let mut g = grant.clone();
    g.session_id = SessionId::for_test_sequence(999);
    changed.push(g);
    let mut g = grant.clone();
    g.action_digest = "other action".into();
    changed.push(g);
    let mut g = grant.clone();
    g.target_revision = "other revision".into();
    changed.push(g);
    let mut g = grant.clone();
    g.workspace_root = "other workspace".into();
    changed.push(g);
    let mut g = grant.clone();
    g.classification = Class::Public;
    changed.push(g);
    let mut g = grant.clone();
    g.granted_by_actor = "forged human".into();
    changed.push(g);
    let mut g = grant.clone();
    g.granted_at_utc = g.granted_at_utc.add_seconds(1);
    changed.push(g);
    let mut g = grant.clone();
    g.token = "forged token".into();
    changed.push(g);
    for bad in changed {
        assert!(h.evaluate(&bad).is_denied());
        assert!(h.consume(&bad).is_err());
    }
    assert_eq!(h.consume(&grant), Ok(()));
}

#[test]
fn copying_all_visible_grant_fields_cannot_forge_broker_provenance() {
    let h = Harness::new();
    let grant = h.grant();
    let mut forged = ApprovalGrant::new(
        grant.request_id,
        grant.session_id,
        &grant.granted_by_actor,
        grant.granted_at_utc,
        &grant.action_digest,
        &grant.target_revision,
        &grant.token,
    );
    forged.workspace_root = grant.workspace_root.clone();
    forged.classification = grant.classification;
    assert_ne!(forged, grant);
    assert!(h.evaluate(&forged).is_denied());
    assert!(h.consume(&forged).is_err());
    assert_eq!(h.consume(&grant), Ok(()));
}

#[test]
fn known_request_id_without_registered_issuance_is_not_authorization() {
    let h = Harness::new();
    let request = h
        .engine
        .broker()
        .request_approval(&h.session, Class::Restricted, &h.action, &h.clock)
        .unwrap();
    let mut forged = ApprovalGrant::new(
        request.request_id,
        request.session_id,
        "trusted-human",
        h.clock.now(),
        &request.action_digest,
        &request.target_revision,
        format!("approval:{}", request.request_id),
    );
    forged.workspace_root = request.workspace_root.clone();
    forged.classification = request.classification;
    assert!(h.evaluate(&forged).is_denied());
    assert!(h.consume(&forged).is_err());
    let grant = h
        .authority
        .issue_grant(&request.request_id, "trusted-human", &h.clock)
        .unwrap();
    assert_eq!(h.consume(&grant), Ok(()));
}

#[test]
fn grant_from_another_broker_is_not_accepted() {
    let a = Harness::new();
    let b = Harness::new();
    let grant = a.grant();
    assert!(b.evaluate(&grant).is_denied());
    assert!(b.consume(&grant).is_err());
    assert_eq!(a.consume(&grant), Ok(()));
}

#[test]
fn changing_request_display_metadata_cannot_change_issued_binding_or_expiry() {
    let h = Harness::new();
    let request = h
        .engine
        .broker()
        .request_approval(&h.session, Class::Restricted, &h.action, &h.clock)
        .unwrap();
    let mut display = h.engine.broker().get_request(&request.request_id).unwrap();
    display.action_digest = "tampered".into();
    display.workspace_root = "other-root".into();
    display.target_revision = "other-revision".into();
    display.expires_at_utc = TimestampUtc::from_epoch_millis(u64::MAX);
    let grant = h
        .authority
        .issue_grant(&request.request_id, "trusted-human", &h.clock)
        .unwrap();
    assert_eq!(grant.action_digest, request.action_digest);
    assert_eq!(grant.workspace_root, request.workspace_root);
    assert_eq!(grant.target_revision, request.target_revision);
    h.clock.set_time(request.expires_at_utc);
    assert!(matches!(
        h.consume(&grant),
        Err(DenialReason::ExpiredApprovalGrant(_))
    ));
}

#[test]
fn expiry_is_exclusive_for_issuance_and_consumption_with_existing_clock() {
    let h = Harness::new();
    let grant = h.grant();
    h.clock.advance_seconds(3600);
    assert!(matches!(
        h.evaluate(&grant),
        PolicyDecision::Denied {
            reason: DenialReason::ExpiredApprovalGrant(_)
        }
    ));
    assert!(matches!(
        h.consume(&grant),
        Err(DenialReason::ExpiredApprovalGrant(_))
    ));
    let other = Harness::new();
    let request = other
        .engine
        .broker()
        .request_approval(
            &other.session,
            Class::Restricted,
            &other.action,
            &other.clock,
        )
        .unwrap();
    other.clock.advance_seconds(3600);
    assert!(matches!(
        other
            .authority
            .issue_grant(&request.request_id, "trusted-human", &other.clock),
        Err(DenialReason::ExpiredApprovalGrant(_))
    ));
}

#[test]
fn clock_before_issue_or_creation_cannot_authorize_future_receipts() {
    let h = Harness::new();
    let grant = h.grant();
    h.clock
        .set_time(TimestampUtc::from_epoch_secs(1_699_999_999));
    assert!(h.evaluate(&grant).is_denied());
    assert!(h.consume(&grant).is_err());
}

#[test]
fn missing_context_and_missing_required_grant_fail_closed() {
    let h = Harness::new();
    let grant = h.grant();
    let unconfigured = PolicyEngine::new();
    assert!(
        unconfigured
            .evaluate(&h.session, Class::Public, &h.action, None, &h.clock)
            .is_denied()
    );
    assert!(
        unconfigured
            .broker()
            .verify_and_consume(
                Some(&grant),
                &h.session,
                Class::Restricted,
                &h.action,
                &h.clock
            )
            .is_err()
    );
    assert!(matches!(
        h.engine.broker().verify_and_consume(
            None,
            &h.session,
            Class::Restricted,
            &h.action,
            &h.clock
        ),
        Err(DenialReason::MissingApprovalGrant(_))
    ));
    assert!(
        !h.engine
            .evaluate(&h.session, Class::Restricted, &h.action, None, &h.clock)
            .is_granted()
    );
    assert_eq!(h.consume(&grant), Ok(()));
}

#[test]
fn malformed_required_context_is_rejected_without_replacing_valid_context() {
    let h = Harness::new();
    let grant = h.grant();
    for field in ["root", "actor", "policy", "session", "revision"] {
        let mut s = h.session.clone();
        let mut revision = "target-revision-A";
        match field {
            "root" => s.workspace_root.clear(),
            "actor" => s.operator_id.clear(),
            "policy" => s.policy_digest.clear(),
            "session" => s.session_id = SessionId::from_bytes([0; 16]),
            _ => revision = "",
        }
        assert!(
            h.authority
                .set_session_context(&s, revision, Class::Public)
                .is_err()
        );
    }
    assert_eq!(h.consume(&grant), Ok(()));
}

#[test]
fn malformed_operations_cannot_request_or_consume_approval() {
    let h = Harness::new();
    let grant = h.grant();
    for action in [
        OperationAction::DiscoverMetadata {
            relative_path: "".into(),
        },
        tool("", true, &[]),
        tool("tool", true, &["bad\0arg"]),
        provider("", 0),
        export("", false, None),
        OperationAction::ModifyCheckout {
            file_count: 2,
            target_paths: vec!["one".into()],
        },
    ] {
        assert!(
            h.engine
                .evaluate(&h.session, Class::Restricted, &action, None, &h.clock)
                .is_denied()
        );
        assert!(
            h.engine
                .broker()
                .request_approval(&h.session, Class::Restricted, &action, &h.clock)
                .is_err()
        );
        assert!(
            h.engine
                .broker()
                .verify_and_consume(
                    Some(&grant),
                    &h.session,
                    Class::Restricted,
                    &action,
                    &h.clock
                )
                .is_err()
        );
    }
    assert_eq!(h.consume(&grant), Ok(()));
}

#[test]
fn duplicate_issuance_revocation_and_unknown_request_are_denied() {
    let h = Harness::new();
    let grant = h.grant();
    assert!(
        h.authority
            .issue_grant(&grant.request_id, "trusted-human", &h.clock)
            .is_err()
    );
    assert!(
        h.authority
            .issue_grant(
                &ApprovalId::from_sequence(999_999),
                "trusted-human",
                &h.clock
            )
            .is_err()
    );
    assert!(h.authority.revoke_request(&grant.request_id).unwrap());
    assert!(h.evaluate(&grant).is_denied());
    assert!(h.consume(&grant).is_err());
}

#[test]
fn diagnostics_do_not_disclose_receipt_payloads_or_tokens() {
    let h = Harness::new();
    let grant = h.grant();
    let mut bad = grant.clone();
    bad.token = "TOKEN_CANARY".into();
    bad.action_digest = "PRIVATE_ACTION_CANARY".into();
    let error = h.consume(&bad).unwrap_err();
    let debug = format!("{bad:?} {error:?} {error} {:?} {:?}", h.engine, h.authority);
    assert!(!debug.contains("TOKEN_CANARY"));
    assert!(!debug.contains("PRIVATE_ACTION_CANARY"));
}

#[test]
fn broker_engine_and_authority_preserve_send_sync_contract() {
    fn check<T: Send + Sync>() {}
    check::<ApprovalBroker>();
    check::<PolicyEngine>();
    check::<ApprovalAuthority>();
    check::<ApprovalGrant>();
}

#[test]
fn concurrency_two_matching_and_six_mismatching_attempts_repeat_64_rounds() {
    for _ in 0..64 {
        let h = Harness::new();
        let grant = h.grant();
        let broker = h.engine.broker().clone();
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for index in 0..8 {
            let barrier = Arc::clone(&barrier);
            let broker = broker.clone();
            let grant = grant.clone();
            let session = h.session.clone();
            let mut action = h.action.clone();
            if index >= 2 {
                action = OperationAction::DiscoverMetadata {
                    relative_path: "wrong-metadata".into(),
                };
            }
            let now = h.clock.now();
            handles.push(thread::spawn(move || {
                barrier.wait();
                (
                    index,
                    broker.verify_and_consume(
                        Some(&grant),
                        &session,
                        Class::Restricted,
                        &action,
                        &MockClock::new(now),
                    ),
                )
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            results.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(
                    |(i, result)| *i < 2 && matches!(result, Err(DenialReason::ApprovalReused(_)))
                )
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|(i, result)| *i >= 2
                    && matches!(result, Err(DenialReason::ApprovalMismatched(_))))
                .count(),
            6
        );
    }
    println!("CONCURRENCY rounds=64 matching_successes=64 matching_replays=64 mismatches=384");
}

#[test]
fn concurrency_only_mismatches_then_legitimate_matching_attempt_repeat_32_rounds() {
    for _ in 0..32 {
        let h = Harness::new();
        let grant = h.grant();
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let broker = h.engine.broker().clone();
            let grant = grant.clone();
            let session = h.session.clone();
            let barrier = Arc::clone(&barrier);
            let now = h.clock.now();
            handles.push(thread::spawn(move || {
                barrier.wait();
                broker.verify_and_consume(
                    Some(&grant),
                    &session,
                    Class::Restricted,
                    &OperationAction::DiscoverMetadata {
                        relative_path: "wrong-metadata".into(),
                    },
                    &MockClock::new(now),
                )
            }));
        }
        for handle in handles {
            assert!(matches!(
                handle.join().unwrap(),
                Err(DenialReason::ApprovalMismatched(_))
            ));
        }
        assert!(h.evaluate(&grant).is_granted());
        assert!(h.evaluate(&grant).is_denied());
    }
    println!("CONCURRENCY rounds=32 mismatches=256 legitimate_successes=32");
}
