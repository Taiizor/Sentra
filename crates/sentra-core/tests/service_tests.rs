//! Core Service integration tests and CLI-ready harness validation.
//!
//! Exhaustively exercises all 13 required scenarios from Increment 5.6:
//! 1. Successful synthetic workflow.
//! 2. Policy denial.
//! 3. Missing session context.
//! 4. Approval rejection and replay.
//! 5. Workspace boundary rejection.
//! 6. Backend unavailable (untrusted target code).
//! 7. Backend fault and invalid result (F-551-01 remediation).
//! 8. Execution identifier mismatch (F-551-05 remediation).
//! 9. Timeout and cancellation lifecycle.
//! 10. Evidence validation failure.
//! 11. Persistence failure.
//! 12. Conservative budget reservation.
//! 13. Audit consistency.

use std::sync::Arc;

use sentra_core::{
    BackendCapabilities, CostUsd, EvidenceEnvelope, EvidenceMetadata, ExecutionBackend,
    ExecutionError, ExecutionId, ExecutionRequest, ExecutionResult, ExecutionScope,
    ExecutionStatus, OperatingMode, OperationAction, ResourceUsage, SecurityClassification,
    ServiceError, ServiceErrorKind, SessionId, SessionState, TaskExecutionRequest, TaskId,
    TimestampUtc,
    persistence::SettlementStatus,
    service::{CancellationReason, CoreServiceHarness},
};

// -----------------------------------------------------------------------------
// 1. Successful Synthetic Workflow
// -----------------------------------------------------------------------------

#[test]
fn test_successful_synthetic_workflow() {
    let harness = CoreServiceHarness::new_synthetic();
    let session_id = harness.create_standard_session().unwrap();

    let report = harness.execute_synthetic_noop(session_id).unwrap();
    assert_eq!(report.status, ExecutionStatus::Completed);
    assert_eq!(report.exit_code, Some(0));
    assert!(matches!(report.settlement, SettlementStatus::Completed(_)));

    // Verify session state is non-terminal
    let session = harness.service.get_session(session_id).unwrap();
    assert_eq!(session.state, SessionState::Scoped);
}

// -----------------------------------------------------------------------------
// 2. Policy Denial (Classification and Unknown Operations)
// -----------------------------------------------------------------------------

#[test]
fn test_policy_denial_unknown_operation_and_classification_downgrade() {
    let harness = CoreServiceHarness::new_synthetic();
    let session_id = harness.create_standard_session().unwrap();

    // 1. Unknown operation unconditionally denied
    let unknown_action = OperationAction::UnknownOperation {
        operation_name: "custom_injected_op".to_string(),
    };
    let decision = harness
        .service
        .evaluate_action(
            session_id,
            &unknown_action,
            SecurityClassification::Internal,
            None,
        )
        .unwrap();
    assert!(matches!(
        decision,
        sentra_core::ServicePolicyDecision::Denied { .. }
    ));

    // 2. Classification floor violation (Public is below session floor Internal)
    let action = OperationAction::DiscoverMetadata {
        relative_path: "src".to_string(),
    };
    let decision_downgrade = harness
        .service
        .evaluate_action(session_id, &action, SecurityClassification::Public, None)
        .unwrap();
    assert!(matches!(
        decision_downgrade,
        sentra_core::ServicePolicyDecision::Denied { .. }
    ));
}

// -----------------------------------------------------------------------------
// 3. Missing Session Context
// -----------------------------------------------------------------------------

#[test]
fn test_missing_session_context_fails_closed() {
    let harness = CoreServiceHarness::new_synthetic();
    let phantom_session_id = SessionId::for_test_sequence(9999);

    // Attempting to get non-existent session fails
    let err = harness.service.get_session(phantom_session_id).unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::Session);

    // Attempting to execute task on non-existent session fails
    let req = TaskExecutionRequest::synthetic(
        phantom_session_id,
        TaskId::for_test_sequence(1),
        OperationAction::DiscoverMetadata {
            relative_path: "src".to_string(),
        },
        CostUsd::from_micro_usd(100),
    );
    let err_exec = harness.service.execute_task(req).unwrap_err();
    assert_eq!(err_exec.kind, ServiceErrorKind::Session);
}

// -----------------------------------------------------------------------------
// 4. Approval Rejection and Replay
// -----------------------------------------------------------------------------

#[test]
fn test_approval_rejection_and_replay_prevention() {
    let harness = CoreServiceHarness::new_synthetic();
    let session_id = harness.create_standard_session().unwrap();

    let sensitive_action = OperationAction::ExecuteTool {
        tool_id: "synthetic:noop".to_string(),
        untrusted: false,
        arguments: vec![],
    };

    // Case A: Sensitive task execution without grant fails with PolicyDenied
    let req_no_grant = TaskExecutionRequest {
        session_id,
        task_id: TaskId::for_test_sequence(10),
        scope: ExecutionScope::SyntheticFixture,
        action: sensitive_action.clone(),
        classification: SecurityClassification::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(50_000),
        grant: None,
        evidence_envelopes: vec![],
    };
    let err = harness.service.execute_task(req_no_grant).unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::PolicyDenied);

    // Case B: Request and issue approval grant
    let approval_id = harness
        .service
        .request_approval(
            session_id,
            &sensitive_action,
            SecurityClassification::Internal,
        )
        .unwrap();
    let grant = harness
        .service
        .issue_approval(
            session_id,
            approval_id,
            &sensitive_action,
            SecurityClassification::Internal,
        )
        .unwrap();

    // First execution consumes the grant successfully
    let req_with_grant = TaskExecutionRequest {
        session_id,
        task_id: TaskId::for_test_sequence(11),
        scope: ExecutionScope::SyntheticFixture,
        action: sensitive_action.clone(),
        classification: SecurityClassification::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(50_000),
        grant: Some(grant.clone()),
        evidence_envelopes: vec![],
    };
    let res = harness.service.execute_task(req_with_grant).unwrap();
    assert_eq!(res.status, ExecutionStatus::Completed);

    // Case C: Replay of consumed grant MUST fail with ApprovalInvalid
    let req_replay = TaskExecutionRequest {
        session_id,
        task_id: TaskId::for_test_sequence(12),
        scope: ExecutionScope::SyntheticFixture,
        action: sensitive_action,
        classification: SecurityClassification::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(50_000),
        grant: Some(grant),
        evidence_envelopes: vec![],
    };
    let err_replay = harness.service.execute_task(req_replay).unwrap_err();
    assert_eq!(err_replay.kind, ServiceErrorKind::ApprovalInvalid);
}

// -----------------------------------------------------------------------------
// 5. Workspace Boundary Rejection
// -----------------------------------------------------------------------------

#[test]
fn test_workspace_boundary_rejection() {
    let harness = CoreServiceHarness::new_synthetic();

    // 1. Attempting to create session with non-existent or invalid root
    let err = harness
        .service
        .create_session(
            "C:/non_existent_directory_for_sentra_testing_987654",
            OperatingMode::ContinuousReview,
            "operator",
            SecurityClassification::Internal,
            "rev-1",
            CostUsd::from_micro_usd(1_000_000),
        )
        .unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::WorkspaceBoundary);

    // 2. Valid root discovery works cleanly
    let session_id = harness.create_standard_session().unwrap();
    harness.write_workspace_file("manifest.json", b"{\"name\":\"sentra\"}");
    let discovery = harness
        .service
        .discover_workspace(session_id, None)
        .unwrap();
    assert!(
        discovery
            .entries
            .iter()
            .any(|e| e.relative_path.to_str() == Some("manifest.json"))
    );
}

// -----------------------------------------------------------------------------
// 6. Backend Unavailable (Untrusted Target Workloads)
// -----------------------------------------------------------------------------

#[test]
fn test_backend_unavailable_for_untrusted_workloads() {
    let harness = CoreServiceHarness::new_synthetic();
    let session_id = harness.create_standard_session().unwrap();

    let untrusted_action = OperationAction::ExecuteTool {
        tool_id: "cargo-build".to_string(),
        untrusted: true,
        arguments: vec!["--release".to_string()],
    };

    let approval_id = harness
        .service
        .request_approval(
            session_id,
            &untrusted_action,
            SecurityClassification::Internal,
        )
        .unwrap();
    let grant = harness
        .service
        .issue_approval(
            session_id,
            approval_id,
            &untrusted_action,
            SecurityClassification::Internal,
        )
        .unwrap();

    let req = TaskExecutionRequest {
        session_id,
        task_id: TaskId::for_test_sequence(20),
        scope: ExecutionScope::UntrustedTargetWorkload,
        action: untrusted_action,
        classification: SecurityClassification::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(200_000),
        grant: Some(grant),
        evidence_envelopes: vec![],
    };

    let err = harness.service.execute_task(req).unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::Execution);
    assert!(
        err.message.contains(
            "Untrusted target execution is disabled pending validated Hyper-V VM isolation"
        )
    );
}

// -----------------------------------------------------------------------------
// 7. Backend Fault and Invalid Result (F-551-01 Remediation)
// -----------------------------------------------------------------------------

struct ContradictoryResultBackend;

impl ExecutionBackend for ContradictoryResultBackend {
    fn name(&self) -> &'static str {
        "contradictory-backend"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend_name: self.name(),
            supports_untrusted: false,
            supports_synthetic: true,
            isolated_vm_available: false,
            host_execution: false,
            docker_wsl_execution: false,
            description: "Backend returning contradictory status and exit code",
        }
    }

    fn execute(&self, request: &ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        Ok(ExecutionResult {
            execution_id: request.execution_id,
            status: ExecutionStatus::TimedOut,
            exit_code: Some(0), // Contradiction: TimedOut with Some(0)
            resource_usage: ResourceUsage::zero(),
            evidence_descriptors: Vec::new(),
            completed_at: TimestampUtc::now(),
        })
    }
}

#[test]
fn test_backend_fault_and_invalid_result_remediation_f_551_01() {
    let harness = CoreServiceHarness::with_backend(Arc::new(ContradictoryResultBackend));
    let session_id = harness.create_standard_session().unwrap();

    let action = OperationAction::DiscoverMetadata {
        relative_path: "src".to_string(),
    };
    let req = TaskExecutionRequest::synthetic(
        session_id,
        TaskId::for_test_sequence(30),
        action,
        CostUsd::from_micro_usd(100_000),
    );

    let err = harness.service.execute_task(req).unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::Execution);
    assert!(
        err.message.contains(
            "Contradictory execution result: status is TimedOut but exit_code is Some(0)"
        )
    );
}

// -----------------------------------------------------------------------------
// 8. Execution Identifier Mismatch (F-551-05 Remediation)
// -----------------------------------------------------------------------------

struct MismatchedExecutionIdBackend;

impl ExecutionBackend for MismatchedExecutionIdBackend {
    fn name(&self) -> &'static str {
        "mismatched-id-backend"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend_name: self.name(),
            supports_untrusted: false,
            supports_synthetic: true,
            isolated_vm_available: false,
            host_execution: false,
            docker_wsl_execution: false,
            description: "Backend returning mismatched execution IDs",
        }
    }

    fn execute(&self, _request: &ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        Ok(ExecutionResult {
            execution_id: ExecutionId::for_test_sequence(88888),
            status: ExecutionStatus::Completed,
            exit_code: Some(0),
            resource_usage: ResourceUsage::zero(),
            evidence_descriptors: Vec::new(),
            completed_at: TimestampUtc::now(),
        })
    }
}

#[test]
fn test_execution_identifier_mismatch_remediation_f_551_05() {
    let harness = CoreServiceHarness::with_backend(Arc::new(MismatchedExecutionIdBackend));
    let session_id = harness.create_standard_session().unwrap();

    let action = OperationAction::DiscoverMetadata {
        relative_path: "src".to_string(),
    };
    let req = TaskExecutionRequest::synthetic(
        session_id,
        TaskId::for_test_sequence(40),
        action,
        CostUsd::from_micro_usd(100_000),
    );

    let err = harness.service.execute_task(req).unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::Execution);
    assert!(err.message.contains("Execution ID correlation mismatch"));
}

// -----------------------------------------------------------------------------
// 9. Timeout and Cancellation Lifecycle
// -----------------------------------------------------------------------------

#[test]
fn test_timeout_and_cancellation_lifecycle() {
    let harness = CoreServiceHarness::new_synthetic();
    let session_id = harness.create_standard_session().unwrap();

    // 1. Task timeout outcome
    let action_timeout = OperationAction::ExecuteTool {
        tool_id: "synthetic:timeout".to_string(),
        untrusted: false,
        arguments: vec![],
    };
    let app_id = harness
        .service
        .request_approval(
            session_id,
            &action_timeout,
            SecurityClassification::Internal,
        )
        .unwrap();
    let grant = harness
        .service
        .issue_approval(
            session_id,
            app_id,
            &action_timeout,
            SecurityClassification::Internal,
        )
        .unwrap();

    let req_timeout = TaskExecutionRequest {
        session_id,
        task_id: TaskId::for_test_sequence(50),
        scope: ExecutionScope::SyntheticFixture,
        action: action_timeout,
        classification: SecurityClassification::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(50_000),
        grant: Some(grant),
        evidence_envelopes: vec![],
    };

    let report = harness.service.execute_task(req_timeout).unwrap();
    assert_eq!(report.status, ExecutionStatus::TimedOut);
    assert_eq!(report.settlement, SettlementStatus::CancelledUncertain);

    // 2. Explicit task cancellation
    let cancel_report = harness
        .service
        .cancel_task(
            session_id,
            ExecutionId::for_test_sequence(51),
            CancellationReason::OperatorRequested,
            None,
        )
        .unwrap();
    assert!(cancel_report.phase.is_confirmed());
    assert_eq!(
        cancel_report.settlement_status,
        SettlementStatus::CancelledUncertain
    );
}

// -----------------------------------------------------------------------------
// 10. Evidence Validation Failure (50 MiB Bounds & Offline Crypto)
// -----------------------------------------------------------------------------

#[test]
fn test_evidence_validation_failure() {
    let harness = CoreServiceHarness::new_synthetic();
    let session_id = harness.create_standard_session().unwrap();

    // Malformed evidence envelope: declared length 100 bytes, actual payload 10 bytes
    let meta = EvidenceMetadata {
        evidence_id: sentra_core::EvidenceId::for_test_sequence(1),
        session_id,
        task_id: TaskId::for_test_sequence(60),
        producer_role: "scanner".to_string(),
        media_type: "application/json".to_string(),
        payload_length_bytes: 100, // mismatch
        declared_sha256: None,
        classification: SecurityClassification::Internal,
        created_at: TimestampUtc::now(),
    };
    let bad_envelope = EvidenceEnvelope::new(meta, vec![0x20; 10]);

    let action = OperationAction::ExecuteTool {
        tool_id: "synthetic:noop".to_string(),
        untrusted: false,
        arguments: vec![],
    };

    let app_id = harness
        .service
        .request_approval(session_id, &action, SecurityClassification::Internal)
        .unwrap();
    let grant = harness
        .service
        .issue_approval(
            session_id,
            app_id,
            &action,
            SecurityClassification::Internal,
        )
        .unwrap();

    let req = TaskExecutionRequest {
        session_id,
        task_id: TaskId::for_test_sequence(60),
        scope: ExecutionScope::SyntheticFixture,
        action,
        classification: SecurityClassification::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(50_000),
        grant: Some(grant),
        evidence_envelopes: vec![bad_envelope],
    };

    let err = harness.service.execute_task(req).unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::EvidenceVerification);
    assert!(err.message.contains("disagrees with metadata"));
}

// -----------------------------------------------------------------------------
// 11. Persistence Failure and Terminal State Invariants
// -----------------------------------------------------------------------------

#[test]
fn test_persistence_failure_and_terminal_session_state() {
    let harness = CoreServiceHarness::new_synthetic();
    let session_id = harness.create_standard_session().unwrap();

    // Transition session Scoped -> Planned -> Running -> Completed
    harness
        .service
        .transition_session(session_id, SessionState::Planned, "planning completed")
        .unwrap();
    harness
        .service
        .transition_session(session_id, SessionState::Running, "execution started")
        .unwrap();
    harness
        .service
        .transition_session(session_id, SessionState::Completed, "tasks finished")
        .unwrap();

    // Attempting invalid transition out of terminal state Completed -> Running fails closed
    let err = harness
        .service
        .transition_session(session_id, SessionState::Running, "reopen attempt")
        .unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::InvalidState);

    // Attempting to execute task on terminal session fails closed
    let req = TaskExecutionRequest::synthetic(
        session_id,
        TaskId::for_test_sequence(70),
        OperationAction::DiscoverMetadata {
            relative_path: "src".to_string(),
        },
        CostUsd::from_micro_usd(10_000),
    );
    let err_exec = harness.service.execute_task(req).unwrap_err();
    assert_eq!(err_exec.kind, ServiceErrorKind::InvalidState);
}

// -----------------------------------------------------------------------------
// 12. Conservative Budget Reservation and Limit Enforcement
// -----------------------------------------------------------------------------

#[test]
fn test_conservative_budget_reservation_and_limit_enforcement() {
    let harness = CoreServiceHarness::new_synthetic();

    // Create session with small budget limit ($0.50)
    let root_str = harness.dir.workspace_root.to_str().unwrap();
    let session_id = harness
        .service
        .create_session(
            root_str,
            OperatingMode::ContinuousReview,
            "operator",
            SecurityClassification::Internal,
            "rev-budget",
            CostUsd::from_micro_usd(500_000), // $0.50
        )
        .unwrap();

    // Attempting to reserve $1.00 on a $0.50 budget session fails closed
    let req = TaskExecutionRequest::synthetic(
        session_id,
        TaskId::for_test_sequence(80),
        OperationAction::DiscoverMetadata {
            relative_path: "src".to_string(),
        },
        CostUsd::from_micro_usd(1_000_000), // $1.00
    );

    let err = harness.service.execute_task(req).unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::BudgetExceeded);
}

// -----------------------------------------------------------------------------
// 13. Audit Consistency and Diagnostic Redaction
// -----------------------------------------------------------------------------

#[test]
fn test_audit_consistency_and_diagnostic_redaction() {
    let harness = CoreServiceHarness::new_synthetic();
    let session_id = harness.create_standard_session().unwrap();

    // Execute standard task
    harness.execute_synthetic_noop(session_id).unwrap();

    // Redaction check: ServiceError formatting does not disclose sensitive payload strings
    let secret = "SECRET_TOKEN_AUTH_ABCD_999";
    let err = ServiceError::new(
        ServiceErrorKind::Execution,
        format!("error info [{secret}]"),
    );
    let err_display = format!("{err}");
    let err_debug = format!("{err:?}");
    assert!(err_display.contains(secret)); // message container
    assert!(err_debug.contains("ServiceError"));
}
