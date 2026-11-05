//! Original A-to-B regression, using real broker issuance and trusted session setup.
//! No filesystem operation or sensitive action is dispatched by this probe.
#![forbid(unsafe_code)]

use sentra_core::{
    DenialReason, MockClock, OperatingMode, OperationAction, PolicyDecision, PolicyEngine,
    SecurityClassification, SessionId, SessionMetadata, TimestampUtc,
};

fn main() {
    let now = TimestampUtc::from_epoch_secs(1_700_000_000);
    let clock = MockClock::new(now);
    let session = SessionMetadata::new(
        SessionId::for_test_sequence(53),
        now,
        "synthetic-workspace",
        OperatingMode::ContinuousReview,
        "synthetic-operator",
        "synthetic-revision",
    )
    .unwrap();
    let (engine, authority) = PolicyEngine::with_authority(Default::default());
    authority
        .set_session_context(
            &session,
            "synthetic-target-revision",
            SecurityClassification::Restricted,
        )
        .unwrap();
    let approved = OperationAction::DiscoverMetadata {
        relative_path: "approved-metadata".into(),
    };
    let different = OperationAction::DiscoverMetadata {
        relative_path: "different-metadata".into(),
    };
    let PolicyDecision::NeedsApproval { request } = engine.evaluate(
        &session,
        SecurityClassification::Restricted,
        &approved,
        None,
        &clock,
    ) else {
        panic!("restricted request must require approval");
    };
    let grant = authority
        .issue_grant(&request.request_id, "synthetic-human", &clock)
        .unwrap();
    assert_ne!(approved.action_digest(), different.action_digest());
    let decision = engine.evaluate(
        &session,
        SecurityClassification::Restricted,
        &different,
        Some(&grant),
        &clock,
    );
    if !matches!(
        decision,
        PolicyDecision::Denied {
            reason: DenialReason::ApprovalMismatched(_)
        }
    ) {
        println!("POLICY_CONTEXT_BINDING=Failed: grant for metadata A accepted for metadata B");
        std::process::exit(1);
    }
    assert!(
        engine
            .evaluate(
                &session,
                SecurityClassification::Restricted,
                &approved,
                Some(&grant),
                &clock
            )
            .is_granted()
    );
    assert!(matches!(
        engine.evaluate(
            &session,
            SecurityClassification::Restricted,
            &approved,
            Some(&grant),
            &clock
        ),
        PolicyDecision::Denied {
            reason: DenialReason::ApprovalReused(_)
        }
    ));
    println!(
        "POLICY_CONTEXT_BINDING=Passed: mismatched metadata action rejected; matching action accepted once; replay rejected"
    );
}
