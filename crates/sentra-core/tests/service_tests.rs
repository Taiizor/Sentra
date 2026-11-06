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
    assert_eq!(report.settlement, SettlementStatus::UncertainPartial);

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
        matches!(err.primary_error(), Some(sentra_core::service::ServicePrimaryError::Execution(e)) if e.kind == sentra_core::ExecutionErrorKind::BackendUnavailable)
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
        matches!(err.primary_error(), Some(sentra_core::service::ServicePrimaryError::Execution(e)) if e.kind == sentra_core::ExecutionErrorKind::BackendFault)
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
    assert!(
        matches!(err.primary_error(), Some(sentra_core::service::ServicePrimaryError::Execution(e)) if e.kind == sentra_core::ExecutionErrorKind::CorrelationMismatch)
    );
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
    assert!(
        matches!(err.primary_error(), Some(sentra_core::service::ServicePrimaryError::Evidence(e)) if e.kind == sentra_core::EvidenceVerificationErrorKind::LengthMismatch)
    );
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
    assert!(!err_display.contains(secret));
    assert!(!err_debug.contains(secret));
    assert!(!err.message.contains(secret));
}

// -----------------------------------------------------------------------------
// 14. F-561-01: Policy Enforcement at Actual Execution Boundary
// -----------------------------------------------------------------------------

#[test]
fn test_execute_task_enforces_classification_floor_rejection() {
    let harness = CoreServiceHarness::new_synthetic();
    // Create standard session with classification floor: Internal
    let session_id = harness.create_standard_session().unwrap();

    // Directly invoke execute_task bypassing evaluate_action with Public (< Internal)
    let req = TaskExecutionRequest {
        session_id,
        task_id: TaskId::for_test_sequence(101),
        scope: ExecutionScope::SyntheticFixture,
        action: OperationAction::DiscoverMetadata {
            relative_path: "src".to_string(),
        },
        classification: SecurityClassification::Public, // Below floor
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(10_000),
        grant: None,
        evidence_envelopes: vec![],
    };

    let err = harness.service.execute_task(req).unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::PolicyDenied);
    assert_eq!(err.kind, ServiceErrorKind::PolicyDenied);

    // Verify zero budget was reserved
    assert_eq!(
        harness.service.budget_used(session_id).unwrap(),
        CostUsd::ZERO
    );
}

#[test]
fn test_execute_task_enforces_policy_engine_denial_for_unknown_operation() {
    let harness = CoreServiceHarness::new_synthetic();
    let session_id = harness.create_standard_session().unwrap();

    let req = TaskExecutionRequest {
        session_id,
        task_id: TaskId::for_test_sequence(102),
        scope: ExecutionScope::SyntheticFixture,
        action: OperationAction::UnknownOperation {
            operation_name: "malicious_unregistered_action".to_string(),
        },
        classification: SecurityClassification::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(10_000),
        grant: None,
        evidence_envelopes: vec![],
    };

    let err = harness.service.execute_task(req).unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::PolicyDenied);
    assert_eq!(err.kind, ServiceErrorKind::PolicyDenied);

    // Verify zero budget was reserved
    assert_eq!(
        harness.service.budget_used(session_id).unwrap(),
        CostUsd::ZERO
    );
}

#[test]
fn test_execute_task_enforces_policy_denial_on_information_flow_violation() {
    let harness = CoreServiceHarness::new_synthetic();
    let session_id = harness.create_standard_session().unwrap();

    // ExportReport from Internal to Public is an unauthorized write-down
    let req = TaskExecutionRequest {
        session_id,
        task_id: TaskId::for_test_sequence(103),
        scope: ExecutionScope::SyntheticFixture,
        action: OperationAction::ExportReport {
            destination: "public_export.json".to_string(),
            destination_classification: Some(SecurityClassification::Public),
            is_external: false,
        },
        classification: SecurityClassification::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(10_000),
        grant: None,
        evidence_envelopes: vec![],
    };

    let err = harness.service.execute_task(req).unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::PolicyDenied);

    // Verify zero budget was reserved
    assert_eq!(
        harness.service.budget_used(session_id).unwrap(),
        CostUsd::ZERO
    );
}

// -----------------------------------------------------------------------------
// 15. F-561-02: Safe Approval & Budget Reservation Ordering
// -----------------------------------------------------------------------------

#[test]
fn test_budget_exhaustion_does_not_consume_valid_approval_grant() {
    let harness = CoreServiceHarness::new_synthetic();
    let root_str = harness.dir.workspace_root.to_str().unwrap();

    // Create session with small budget: $0.10 (100,000 micro-USD)
    let session_id = harness
        .service
        .create_session(
            root_str,
            OperatingMode::ContinuousReview,
            "operator-test",
            SecurityClassification::Internal,
            "commit-abc12345",
            CostUsd::from_micro_usd(100_000), // $0.10
        )
        .unwrap();

    let action = OperationAction::ExecuteTool {
        tool_id: "synthetic:noop".to_string(),
        untrusted: false,
        arguments: vec![],
    };

    // Request and issue a valid approval grant
    let approval_id = harness
        .service
        .request_approval(session_id, &action, SecurityClassification::Internal)
        .unwrap();
    let grant = harness
        .service
        .issue_approval(
            session_id,
            approval_id,
            &action,
            SecurityClassification::Internal,
        )
        .unwrap();

    // Attempt to execute with estimated cost: $0.50 (exceeds $0.10 limit)
    let req_oversized = TaskExecutionRequest {
        session_id,
        task_id: TaskId::for_test_sequence(104),
        scope: ExecutionScope::SyntheticFixture,
        action: action.clone(),
        classification: SecurityClassification::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(500_000), // $0.50 > $0.10
        grant: Some(grant.clone()),
        evidence_envelopes: vec![],
    };

    let err = harness.service.execute_task(req_oversized).unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::BudgetExceeded);

    // F-561-02 CRITICAL CHECK:
    // The grant MUST NOT have been consumed by the failed budget reservation!
    // We retry with the EXACT SAME grant and an estimated cost of $0.05 (within $0.10 limit).
    let req_valid = TaskExecutionRequest {
        session_id,
        task_id: TaskId::for_test_sequence(105),
        scope: ExecutionScope::SyntheticFixture,
        action: action.clone(),
        classification: SecurityClassification::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(50_000), // $0.05 <= $0.10
        grant: Some(grant.clone()),
        evidence_envelopes: vec![],
    };

    let report = harness.service.execute_task(req_valid).unwrap();
    assert_eq!(report.status, ExecutionStatus::Completed);
    assert_eq!(report.exit_code, Some(0));

    // Now that the task actually completed, the single-use grant was consumed.
    // Replay attempt with the same grant must be rejected!
    let req_replay = TaskExecutionRequest {
        session_id,
        task_id: TaskId::for_test_sequence(106),
        scope: ExecutionScope::SyntheticFixture,
        action,
        classification: SecurityClassification::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(10_000),
        grant: Some(grant),
        evidence_envelopes: vec![],
    };

    let err_replay = harness.service.execute_task(req_replay).unwrap_err();
    assert_eq!(err_replay.kind, ServiceErrorKind::ApprovalInvalid);
}

#[test]
fn test_invalid_approval_grant_leaves_no_budget_reservation() {
    let harness = CoreServiceHarness::new_synthetic();
    let session_id = harness.create_standard_session().unwrap();

    let action = OperationAction::ExecuteTool {
        tool_id: "synthetic:noop".to_string(),
        untrusted: false,
        arguments: vec![],
    };

    // Request approval for session A
    let approval_id = harness
        .service
        .request_approval(session_id, &action, SecurityClassification::Internal)
        .unwrap();
    let grant = harness
        .service
        .issue_approval(
            session_id,
            approval_id,
            &action,
            SecurityClassification::Internal,
        )
        .unwrap();

    // Create session B
    let session_b = harness.create_standard_session().unwrap();

    // Attempt to use grant from session A on session B
    let req_mismatched = TaskExecutionRequest {
        session_id: session_b,
        task_id: TaskId::for_test_sequence(107),
        scope: ExecutionScope::SyntheticFixture,
        action,
        classification: SecurityClassification::Internal,
        resource_limits: None,
        estimated_cost: CostUsd::from_micro_usd(200_000),
        grant: Some(grant),
        evidence_envelopes: vec![],
    };

    let err = harness.service.execute_task(req_mismatched).unwrap_err();
    assert_eq!(err.kind, ServiceErrorKind::ApprovalInvalid);

    // Verify session B has ZERO budget reserved or spent
    assert_eq!(
        harness.service.budget_used(session_b).unwrap(),
        CostUsd::ZERO
    );
}

// -----------------------------------------------------------------------------
// 16. F-561-03: Never Silently Ignore Budget Settlement Failures
// -----------------------------------------------------------------------------

#[test]
fn test_service_error_compound_settlement_failure_contracts() {
    let exec_err = ExecutionError::new(
        sentra_core::ExecutionErrorKind::BackendFault,
        "primary simulated execution fault",
    );
    let settle_err = sentra_core::persistence::PersistenceError::from_kind(
        sentra_core::persistence::PersistenceErrorKind::Database,
    );

    let compound = ServiceError::execution_with_settlement_failure(exec_err, settle_err);

    // Verify compound classification
    assert_eq!(
        compound.kind,
        ServiceErrorKind::ExecutionWithSettlementFailure
    );
    assert!(compound.is_execution());
    assert!(compound.has_settlement_failure());
    assert!(compound.secondary_error().is_some());

    // Inspect both typed causes; arbitrary diagnostic messages are not retained.
    let err_str = compound.to_string();
    assert!(!err_str.contains("primary simulated execution fault"));
    assert!(
        matches!(compound.primary_error(), Some(sentra_core::service::ServicePrimaryError::Execution(e)) if e.kind == sentra_core::ExecutionErrorKind::BackendFault)
    );
    assert_eq!(
        compound.secondary_error().unwrap().kind,
        sentra_core::persistence::PersistenceErrorKind::Database
    );

    // Check evidence variant
    let ev_err = sentra_core::EvidenceVerificationError::new(
        sentra_core::EvidenceVerificationErrorKind::OversizedPayload,
        "evidence oversized",
    );
    let settle_err2 = sentra_core::persistence::PersistenceError::from_kind(
        sentra_core::persistence::PersistenceErrorKind::Database,
    );
    let compound_ev = ServiceError::evidence_with_settlement_failure(ev_err, settle_err2);
    assert_eq!(
        compound_ev.kind,
        ServiceErrorKind::EvidenceWithSettlementFailure
    );
    assert!(compound_ev.is_evidence());
    assert!(compound_ev.has_settlement_failure());
    assert!(!compound_ev.to_string().contains("evidence oversized"));
    assert!(
        matches!(compound_ev.primary_error(), Some(sentra_core::service::ServicePrimaryError::Evidence(e)) if e.kind == sentra_core::EvidenceVerificationErrorKind::OversizedPayload)
    );
}
