//! Reproduce the preexisting approval context gap without filesystem access or dispatch.
//! Exit 1 reports a failed S-02 expectation, not an executed sensitive operation.
#![forbid(unsafe_code)]

use sentra_core::{
    ApprovalGrant, MockClock, OperatingMode, OperationAction, PolicyDecision, PolicyEngine,
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
    let engine = PolicyEngine::new();
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
    let grant = ApprovalGrant::new(
        request.request_id,
        request.session_id,
        "synthetic-human",
        now,
        &request.action_digest,
        &request.target_revision,
        "synthetic-token",
    );
    assert_ne!(approved.action_digest(), different.action_digest());
    let decision = engine.evaluate(
        &session,
        SecurityClassification::Restricted,
        &different,
        Some(&grant),
        &clock,
    );
    if decision == PolicyDecision::Granted {
        println!("POLICY_CONTEXT_BINDING=Failed: grant for metadata A accepted for metadata B");
        std::process::exit(1);
    }
    println!("POLICY_CONTEXT_BINDING=Passed: mismatched metadata action rejected");
}
