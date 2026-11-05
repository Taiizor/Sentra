//! Execution engine and fail-closed boundary integration tests.

use std::sync::Arc;

use sentra_core::{
    BackendCapabilities, CostUsd, ExecutionBackend, ExecutionEngine, ExecutionError,
    ExecutionErrorKind, ExecutionId, ExecutionRequest, ExecutionResult, ExecutionScope,
    ExecutionStatus, FailClosedBackend, OperationAction, ResourceLimits, ResourceUsage,
    SecurityClassification, SessionId, SyntheticFixtureBackend, TaskId, TimestampUtc,
};

fn sample_request(scope: ExecutionScope, action_name: &str) -> ExecutionRequest {
    ExecutionRequest {
        execution_id: ExecutionId::for_test_sequence(1),
        session_id: SessionId::for_test_sequence(100),
        task_id: TaskId::for_test_sequence(200),
        scope,
        action: OperationAction::ExecuteTool {
            tool_id: action_name.to_string(),
            untrusted: scope.is_untrusted(),
            arguments: vec!["--check".to_string()],
        },
        target_revision: "git-commit-abc1234567890".to_string(),
        resource_limits: ResourceLimits::default(),
        classification: SecurityClassification::Internal,
        created_at: TimestampUtc::now(),
    }
}

#[test]
fn untrusted_workload_rejected_by_default_fail_closed_backend() {
    let backend = FailClosedBackend::new();
    let request = sample_request(
        ExecutionScope::UntrustedTargetWorkload,
        "cargo-build-target",
    );

    let result = backend.execute(&request);
    assert!(result.is_err());
    let err: ExecutionError = result.unwrap_err();
    assert_eq!(err.kind, ExecutionErrorKind::BackendUnavailable);
    assert!(err.is_unavailable());
    assert!(
        err.message.contains(
            "Untrusted target execution is disabled pending validated Hyper-V VM isolation"
        )
    );
}

#[test]
fn no_host_docker_or_wsl2_fallback_declared_in_capabilities() {
    // FailClosedBackend capability audit
    let fail_closed = FailClosedBackend::new();
    let caps: BackendCapabilities = fail_closed.capabilities();
    assert_eq!(caps.backend_name, "fail-closed");
    assert!(!caps.supports_untrusted);
    assert!(!caps.supports_synthetic);
    assert!(!caps.isolated_vm_available);
    assert!(!caps.host_execution);
    assert!(!caps.docker_wsl_execution);

    // SyntheticFixtureBackend capability audit
    let synthetic = SyntheticFixtureBackend::new();
    let syn_caps: BackendCapabilities = synthetic.capabilities();
    assert_eq!(syn_caps.backend_name, "synthetic-fixture");
    assert!(!syn_caps.supports_untrusted);
    assert!(syn_caps.supports_synthetic);
    assert!(!syn_caps.isolated_vm_available);
    assert!(!syn_caps.host_execution);
    assert!(!syn_caps.docker_wsl_execution);
}

#[test]
fn synthetic_fixture_scope_validation_and_execution() {
    let backend = SyntheticFixtureBackend::new();

    // 1. synthetic:noop
    let req_noop = sample_request(ExecutionScope::SyntheticFixture, "synthetic:noop");
    let res_noop: ExecutionResult = backend.execute(&req_noop).unwrap();
    let _usage: ResourceUsage = res_noop.resource_usage;
    assert_eq!(res_noop.status, ExecutionStatus::Completed);
    assert_eq!(res_noop.exit_code, Some(0));
    assert!(res_noop.status.is_success());
    assert_eq!(res_noop.status.as_str(), "COMPLETED");

    // 2. synthetic:failure
    let req_fail = sample_request(ExecutionScope::SyntheticFixture, "synthetic:failure");
    let res_fail = backend.execute(&req_fail).unwrap();
    assert_eq!(res_fail.status, ExecutionStatus::Failed);
    assert_eq!(res_fail.exit_code, Some(1));
    assert!(!res_fail.status.is_success());

    // 3. synthetic:timeout
    let req_timeout = sample_request(ExecutionScope::SyntheticFixture, "synthetic:timeout");
    let res_timeout = backend.execute(&req_timeout).unwrap();
    assert_eq!(res_timeout.status, ExecutionStatus::TimedOut);
    assert_eq!(res_timeout.exit_code, None);
    assert!(!res_timeout.status.is_success());

    // 4. synthetic:cancelled
    let req_cancelled = sample_request(ExecutionScope::SyntheticFixture, "synthetic:cancelled");
    let res_cancelled = backend.execute(&req_cancelled).unwrap();
    assert_eq!(res_cancelled.status, ExecutionStatus::Cancelled);
    assert_eq!(res_cancelled.exit_code, None);

    // 5. synthetic:evidence
    let req_ev = sample_request(ExecutionScope::SyntheticFixture, "synthetic:evidence");
    let res_ev = backend.execute(&req_ev).unwrap();
    assert_eq!(res_ev.status, ExecutionStatus::Completed);
    assert_eq!(res_ev.evidence_descriptors.len(), 1);

    // 6. Unknown synthetic action rejected
    let req_unknown = sample_request(
        ExecutionScope::SyntheticFixture,
        "synthetic:arbitrary_command",
    );
    let err = backend.execute(&req_unknown).unwrap_err();
    assert_eq!(err.kind, ExecutionErrorKind::InvalidRequest);
}

#[test]
fn synthetic_backend_strictly_rejects_untrusted_workload() {
    let backend = SyntheticFixtureBackend::new();
    // Attempting to pass UntrustedTargetWorkload to SyntheticFixtureBackend MUST fail closed
    let req = sample_request(
        ExecutionScope::UntrustedTargetWorkload,
        "synthetic:noop", // even with a synthetic action name!
    );
    let err = backend.execute(&req).unwrap_err();
    assert_eq!(err.kind, ExecutionErrorKind::BackendUnavailable);
    assert!(err.is_unavailable());
    assert!(
        err.message
            .contains("Untrusted target execution is disabled")
    );
}

#[test]
fn invalid_and_forged_execution_requests_fail_validation() {
    let mut req = sample_request(ExecutionScope::SyntheticFixture, "synthetic:noop");

    // Empty revision
    req.target_revision = "".to_string();
    assert_eq!(
        req.validate().unwrap_err().kind,
        ExecutionErrorKind::InvalidRequest
    );

    // Revision with whitespace only
    req.target_revision = "   ".to_string();
    assert_eq!(
        req.validate().unwrap_err().kind,
        ExecutionErrorKind::InvalidRequest
    );

    // Revision with newline / control char
    req.target_revision = "revision\nwith-newline".to_string();
    assert_eq!(
        req.validate().unwrap_err().kind,
        ExecutionErrorKind::InvalidRequest
    );

    // Restore revision, test zero timeout
    req.target_revision = "valid-rev".to_string();
    req.resource_limits.timeout_millis = 0;
    assert_eq!(
        req.validate().unwrap_err().kind,
        ExecutionErrorKind::InvalidRequest
    );

    // Excessive timeout (> 1 hr)
    req.resource_limits.timeout_millis = 3_600_001;
    assert_eq!(
        req.validate().unwrap_err().kind,
        ExecutionErrorKind::InvalidRequest
    );

    // Zero memory limit
    req.resource_limits.timeout_millis = 60_000;
    req.resource_limits.max_memory_bytes = 0;
    assert_eq!(
        req.validate().unwrap_err().kind,
        ExecutionErrorKind::InvalidRequest
    );

    // Zero output limit
    req.resource_limits.max_memory_bytes = 1024 * 1024;
    req.resource_limits.max_output_bytes = 0;
    assert_eq!(
        req.validate().unwrap_err().kind,
        ExecutionErrorKind::InvalidRequest
    );
}

#[test]
fn execution_engine_dispatch_untrusted_workload_intercepted() {
    let engine = ExecutionEngine::fail_closed();
    let req_untrusted =
        sample_request(ExecutionScope::UntrustedTargetWorkload, "target-build-hook");

    let err = engine.dispatch(&req_untrusted).unwrap_err();
    assert_eq!(err.kind, ExecutionErrorKind::BackendUnavailable);

    // Synthetic scope on FailClosedBackend fails with UnsupportedScope
    let req_synth = sample_request(ExecutionScope::SyntheticFixture, "synthetic:noop");
    let err_synth = engine.dispatch(&req_synth).unwrap_err();
    assert_eq!(err_synth.kind, ExecutionErrorKind::UnsupportedScope);

    // Engine with SyntheticFixtureBackend succeeds on synthetic fixture
    let synth_engine = ExecutionEngine::new(Arc::new(SyntheticFixtureBackend::new()));
    let res = synth_engine.dispatch(&req_synth).unwrap();
    assert_eq!(res.status, ExecutionStatus::Completed);

    // Engine with SyntheticFixtureBackend still strictly blocks untrusted workload
    let err_blocked = synth_engine.dispatch(&req_untrusted).unwrap_err();
    assert_eq!(err_blocked.kind, ExecutionErrorKind::BackendUnavailable);
}

#[test]
fn execution_scope_predicates_and_formatting() {
    let synth = ExecutionScope::SyntheticFixture;
    assert!(synth.is_synthetic());
    assert!(!synth.is_untrusted());
    assert_eq!(synth.as_str(), "SYNTHETIC_FIXTURE");
    assert_eq!(format!("{synth}"), "SYNTHETIC_FIXTURE");

    let untrusted = ExecutionScope::UntrustedTargetWorkload;
    assert!(untrusted.is_untrusted());
    assert!(!untrusted.is_synthetic());
    assert_eq!(untrusted.as_str(), "UNTRUSTED_TARGET_WORKLOAD");
    assert_eq!(format!("{untrusted}"), "UNTRUSTED_TARGET_WORKLOAD");
}

#[test]
fn conservative_budget_accounting_on_uncertain_execution_outcome() {
    use sentra_core::persistence::SettlementStatus;

    // Simulate an execution task where an upper bound of $5.00 was reserved
    let reserved_cost = CostUsd::from_micro_usd(5_000_000);

    // 1. Task timed out -> outcome is uncertain
    let timed_out_status = SettlementStatus::CancelledUncertain;
    assert_eq!(timed_out_status.actual_cost(), None);
    assert!(timed_out_status.is_cancelled());
    assert!(timed_out_status.is_terminal());
    // Since actual_cost is None, the conservative reservation ($5.00) remains held

    // 2. Task encountered backend failure mid-execution with unknown progress
    let partial_status = SettlementStatus::UncertainPartial;
    assert_eq!(partial_status.actual_cost(), None);
    assert!(!partial_status.is_cancelled());
    assert!(!partial_status.is_terminal());
    // In both cases, the conservative budget invariant is preserved: zero budget is released

    // 3. Successful execution with verified evidence releases unconsumed difference
    let completed_status = SettlementStatus::Completed(CostUsd::from_micro_usd(1_200_000));
    assert_eq!(
        completed_status.actual_cost(),
        Some(CostUsd::from_micro_usd(1_200_000))
    );
    assert!(completed_status.is_terminal());
    assert!(completed_status.actual_cost().unwrap().as_micro_usd() <= reserved_cost.as_micro_usd());
}
