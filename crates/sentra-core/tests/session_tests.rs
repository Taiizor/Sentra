use sentra_core::{
    common::{Clock, MockClock},
    domain::{DomainError, SessionId, SessionTransitionError, TimestampUtc},
    session::{
        machine::SessionStateMachine,
        metadata::SessionMetadata,
        state::{AssessmentCompleteness, OperatingMode, SessionState},
    },
};

fn create_valid_metadata() -> SessionMetadata {
    SessionMetadata::new(
        SessionId::new(),
        TimestampUtc::from_epoch_secs(1_700_000_000),
        "E:/MyProject/Mix/GitHub/Sentra",
        OperatingMode::DeepSecurityResearch,
        "operator_admin",
        "sha256:policy_abc123",
    )
    .expect("valid metadata")
}

#[test]
fn test_metadata_validation() {
    let now = TimestampUtc::from_epoch_secs(1_700_000_000);
    let id = SessionId::new();

    // Empty workspace root
    assert!(matches!(
        SessionMetadata::new(
            id,
            now,
            "   ",
            OperatingMode::ContinuousReview,
            "op1",
            "hash1"
        ),
        Err(DomainError::InvalidMetadata(_))
    ));

    // Empty operator id
    assert!(matches!(
        SessionMetadata::new(
            id,
            now,
            "/root",
            OperatingMode::ContinuousReview,
            "  ",
            "hash1"
        ),
        Err(DomainError::InvalidMetadata(_))
    ));

    // Empty policy digest
    assert!(matches!(
        SessionMetadata::new(id, now, "/root", OperatingMode::ContinuousReview, "op1", ""),
        Err(DomainError::InvalidMetadata(_))
    ));

    // Valid
    let meta = SessionMetadata::new(
        id,
        now,
        "/root",
        OperatingMode::ContinuousReview,
        "op1",
        "hash1",
    );
    assert!(meta.is_ok());
    let m = meta.unwrap();
    assert_eq!(m.workspace_root, "/root");
    assert_eq!(m.operator_id, "op1");
    assert_eq!(m.policy_digest, "hash1");
    assert_eq!(m.completeness, AssessmentCompleteness::Partial);
}

#[test]
fn test_complete_9x9_transition_matrix() {
    let all_states = [
        SessionState::Created,
        SessionState::Scoped,
        SessionState::Planned,
        SessionState::Running,
        SessionState::WaitingForApproval,
        SessionState::Paused,
        SessionState::Completed,
        SessionState::Failed,
        SessionState::Cancelled,
    ];

    let is_valid = |from: SessionState, to: SessionState| -> bool {
        match (from, to) {
            // Self-transitions are never allowed
            (a, b) if a == b => false,

            // Terminal states can never transition
            (SessionState::Completed, _)
            | (SessionState::Failed, _)
            | (SessionState::Cancelled, _) => false,

            // From Created
            (SessionState::Created, SessionState::Scoped)
            | (SessionState::Created, SessionState::Cancelled)
            | (SessionState::Created, SessionState::Failed) => true,

            // From Scoped
            (SessionState::Scoped, SessionState::Planned)
            | (SessionState::Scoped, SessionState::Cancelled)
            | (SessionState::Scoped, SessionState::Failed) => true,

            // From Planned
            (SessionState::Planned, SessionState::Running)
            | (SessionState::Planned, SessionState::WaitingForApproval)
            | (SessionState::Planned, SessionState::Cancelled)
            | (SessionState::Planned, SessionState::Failed) => true,

            // From WaitingForApproval
            (SessionState::WaitingForApproval, SessionState::Running)
            | (SessionState::WaitingForApproval, SessionState::Cancelled)
            | (SessionState::WaitingForApproval, SessionState::Failed) => true,

            // From Running
            (SessionState::Running, SessionState::WaitingForApproval)
            | (SessionState::Running, SessionState::Paused)
            | (SessionState::Running, SessionState::Completed)
            | (SessionState::Running, SessionState::Cancelled)
            | (SessionState::Running, SessionState::Failed) => true,

            // From Paused
            (SessionState::Paused, SessionState::Running)
            | (SessionState::Paused, SessionState::Cancelled)
            | (SessionState::Paused, SessionState::Failed) => true,

            _ => false,
        }
    };

    for from in all_states {
        for to in all_states {
            let expected = is_valid(from, to);
            assert_eq!(
                from.can_transition_to(to),
                expected,
                "Transition rule mismatch: {:?} -> {:?}, expected {}",
                from,
                to,
                expected
            );
        }
    }
}

#[test]
fn test_terminal_states_are_permanent() {
    let terminals = [
        SessionState::Completed,
        SessionState::Failed,
        SessionState::Cancelled,
    ];

    let all_states = [
        SessionState::Created,
        SessionState::Scoped,
        SessionState::Planned,
        SessionState::Running,
        SessionState::WaitingForApproval,
        SessionState::Paused,
        SessionState::Completed,
        SessionState::Failed,
        SessionState::Cancelled,
    ];

    for terminal in terminals {
        assert!(terminal.is_terminal());
        assert!(!terminal.is_active());

        for target in all_states {
            assert!(
                !terminal.can_transition_to(target),
                "Terminal state {:?} must not transition to {:?}",
                terminal,
                target
            );
        }
    }
}

#[test]
fn test_state_machine_valid_lifecycle_and_audit_emission() {
    let metadata = create_valid_metadata();
    let mut sm = SessionStateMachine::new(metadata);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_100));

    assert_eq!(sm.state(), SessionState::Created);
    assert_eq!(sm.sequence_counter(), 0);

    // 1. Created -> Scoped
    clock.advance_seconds(10);
    let evt1 = sm
        .transition_to(
            SessionState::Scoped,
            "operator_admin",
            "Workspace scanned",
            &clock,
        )
        .expect("transition to Scoped");
    assert_eq!(sm.state(), SessionState::Scoped);
    assert_eq!(sm.sequence_counter(), 1);
    assert_eq!(evt1.sequence_number, 1);
    assert_eq!(evt1.session_id, sm.session_id());
    assert_eq!(evt1.timestamp_utc, clock.now());

    // 2. Scoped -> Planned
    clock.advance_seconds(10);
    let evt2 = sm
        .transition_to(
            SessionState::Planned,
            "operator_admin",
            "Tasks planned",
            &clock,
        )
        .expect("transition to Planned");
    assert_eq!(sm.state(), SessionState::Planned);
    assert_eq!(sm.sequence_counter(), 2);
    assert_eq!(evt2.sequence_number, 2);

    // 3. Planned -> Running
    clock.advance_seconds(10);
    let evt3 = sm
        .transition_to(
            SessionState::Running,
            "operator_admin",
            "Execution started",
            &clock,
        )
        .expect("transition to Running");
    assert_eq!(sm.state(), SessionState::Running);
    assert_eq!(sm.sequence_counter(), 3);
    assert_eq!(evt3.sequence_number, 3);

    // 4. Running -> WaitingForApproval
    clock.advance_seconds(10);
    let evt4 = sm
        .transition_to(
            SessionState::WaitingForApproval,
            "operator_admin",
            "Approval required for sensitive tool",
            &clock,
        )
        .expect("transition to WaitingForApproval");
    assert_eq!(sm.state(), SessionState::WaitingForApproval);
    assert_eq!(sm.sequence_counter(), 4);
    assert_eq!(evt4.sequence_number, 4);

    // 5. WaitingForApproval -> Running
    clock.advance_seconds(10);
    let evt5 = sm
        .transition_to(
            SessionState::Running,
            "operator_admin",
            "Approval granted",
            &clock,
        )
        .expect("transition to Running");
    assert_eq!(sm.state(), SessionState::Running);
    assert_eq!(sm.sequence_counter(), 5);
    assert_eq!(evt5.sequence_number, 5);

    // 6. Running -> Paused
    clock.advance_seconds(10);
    let evt6 = sm
        .transition_to(
            SessionState::Paused,
            "operator_admin",
            "Operator requested pause",
            &clock,
        )
        .expect("transition to Paused");
    assert_eq!(sm.state(), SessionState::Paused);
    assert_eq!(sm.sequence_counter(), 6);
    assert_eq!(evt6.sequence_number, 6);

    // 7. Paused -> Running
    clock.advance_seconds(10);
    let evt7 = sm
        .transition_to(
            SessionState::Running,
            "operator_admin",
            "Operator resumed execution",
            &clock,
        )
        .expect("transition to Running");
    assert_eq!(sm.state(), SessionState::Running);
    assert_eq!(sm.sequence_counter(), 7);
    assert_eq!(evt7.sequence_number, 7);

    // 8. Running -> Completed (Terminal)
    clock.advance_seconds(10);
    let evt8 = sm
        .transition_to(
            SessionState::Completed,
            "operator_admin",
            "All tasks finished successfully",
            &clock,
        )
        .expect("transition to Completed");
    assert_eq!(sm.state(), SessionState::Completed);
    assert_eq!(sm.sequence_counter(), 8);
    assert_eq!(evt8.sequence_number, 8);
    assert!(sm.state().is_terminal());
}

#[test]
fn test_state_machine_invalid_transition_invariants() {
    let metadata = create_valid_metadata();
    let mut sm = SessionStateMachine::new(metadata);
    let clock = MockClock::new(TimestampUtc::from_epoch_secs(1_700_000_100));

    // Attempt illegal jump: Created -> Completed
    let result = sm.transition_to(
        SessionState::Completed,
        "operator_admin",
        "Illegal jump",
        &clock,
    );
    assert_eq!(
        result,
        Err(SessionTransitionError {
            from: SessionState::Created,
            attempted_to: SessionState::Completed,
        })
    );
    // Invariant: State and sequence counter MUST NOT change
    assert_eq!(sm.state(), SessionState::Created);
    assert_eq!(sm.sequence_counter(), 0);

    // Move to Scoped
    assert!(
        sm.transition_to(SessionState::Scoped, "operator_admin", "Scan done", &clock)
            .is_ok()
    );
    assert_eq!(sm.sequence_counter(), 1);

    // Attempt illegal transition: Scoped -> Running (skipping Planned)
    let bad_run = sm.transition_to(SessionState::Running, "operator_admin", "Skip plan", &clock);
    assert_eq!(
        bad_run,
        Err(SessionTransitionError {
            from: SessionState::Scoped,
            attempted_to: SessionState::Running,
        })
    );
    assert_eq!(sm.state(), SessionState::Scoped);
    assert_eq!(sm.sequence_counter(), 1);

    // Terminate session with failure
    assert!(
        sm.transition_to(
            SessionState::Failed,
            "operator_admin",
            "Fatal crash",
            &clock
        )
        .is_ok()
    );
    assert_eq!(sm.state(), SessionState::Failed);
    assert_eq!(sm.sequence_counter(), 2);

    // Terminal state invariant: Cannot transition out of Failed to ANY state
    let restart = sm.transition_to(SessionState::Running, "operator_admin", "Restart", &clock);
    assert_eq!(
        restart,
        Err(SessionTransitionError {
            from: SessionState::Failed,
            attempted_to: SessionState::Running,
        })
    );
    assert_eq!(sm.state(), SessionState::Failed);
    assert_eq!(sm.sequence_counter(), 2);
}
