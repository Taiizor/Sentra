//! Comprehensive integration tests for Verification Bundles, Disposable Worker Containment,
//! and 20-Case Change Corpus Evaluation (REQ-F12, REQ-F13, REQ-F14).

use sentra_core::{
    AttemptDenominator, EgressPolicy, FindingId, PatchVerificationOutcome, SessionId, TaskId,
    TestRunEvidence, TimestampUtc, VerificationBundle, VerificationInput, WorkerErrorKind,
    WorkerProfile, evaluate_corpus, reference_20_case_corpus,
};

#[test]
fn test_verification_bundle_original_fails_patched_passes() {
    let now = TimestampUtc::now();
    let finding_id = FindingId::new();
    let session_id = SessionId::new();
    let task_id = TaskId::new();

    let original_test = TestRunEvidence::failed(
        "test_sql_injection_reproduction",
        1,
        "thread 'main' panicked at 'assert!(is_safe)': query injected",
        45,
        now,
    );

    let patched_test = TestRunEvidence::passed(
        "test_sql_injection_reproduction",
        "test test_sql_injection_reproduction ... ok",
        35,
        now,
    );

    let regression_tests = vec![
        TestRunEvidence::passed("test_user_login", "ok", 20, now),
        TestRunEvidence::passed("test_password_hash", "ok", 15, now),
    ];

    let denominator = AttemptDenominator::default();

    let bundle = VerificationBundle::evaluate_and_build(VerificationInput {
        finding_id,
        session_id,
        task_id,
        base_revision: "commit-base-1".to_string(),
        head_revision: "commit-head-patch-1".to_string(),
        original_test,
        patched_test,
        regression_tests,
        patch_summary: "Parameterized user input in query builder".to_string(),
        denominator,
        now,
    });

    assert!(bundle.is_verified());
    assert_eq!(bundle.outcome, PatchVerificationOutcome::Verified);
    assert_eq!(bundle.denominator.total_attempts, 1);
    assert_eq!(bundle.denominator.successful_verifications, 1);
    assert_eq!(bundle.denominator.success_rate(), 1.0);
    assert!(bundle.bundle_id.starts_with("sha256:"));
}

#[test]
fn test_verification_bundle_original_did_not_fail_rejected() {
    let now = TimestampUtc::now();
    // Flawed reproduction test: original unpatched code passes the test
    let original_test = TestRunEvidence::passed("test_reproduction", "ok", 30, now);
    let patched_test = TestRunEvidence::passed("test_reproduction", "ok", 30, now);

    let bundle = VerificationBundle::evaluate_and_build(VerificationInput {
        finding_id: FindingId::new(),
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        base_revision: "base".to_string(),
        head_revision: "head".to_string(),
        original_test,
        patched_test,
        regression_tests: vec![],
        patch_summary: "Some patch".to_string(),
        denominator: AttemptDenominator::default(),
        now,
    });

    assert!(!bundle.is_verified());
    assert_eq!(bundle.outcome, PatchVerificationOutcome::OriginalDidNotFail);
    assert_eq!(bundle.denominator.no_fix_outcomes, 1);
}

#[test]
fn test_verification_bundle_patch_did_not_pass_rejected() {
    let now = TimestampUtc::now();
    let original_test = TestRunEvidence::failed("test_reproduction", 1, "failed", 30, now);
    // Ineffective patch: test still fails after applying patch
    let patched_test = TestRunEvidence::failed("test_reproduction", 1, "still failed", 30, now);

    let bundle = VerificationBundle::evaluate_and_build(VerificationInput {
        finding_id: FindingId::new(),
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        base_revision: "base".to_string(),
        head_revision: "head".to_string(),
        original_test,
        patched_test,
        regression_tests: vec![],
        patch_summary: "Ineffective patch".to_string(),
        denominator: AttemptDenominator::default(),
        now,
    });

    assert!(!bundle.is_verified());
    assert_eq!(bundle.outcome, PatchVerificationOutcome::PatchDidNotPass);
    assert_eq!(bundle.denominator.no_fix_outcomes, 1);
}

#[test]
fn test_verification_bundle_regression_break_rejected() {
    let now = TimestampUtc::now();
    let original_test = TestRunEvidence::failed("test_reproduction", 1, "failed", 30, now);
    let patched_test = TestRunEvidence::passed("test_reproduction", "ok", 30, now);

    // Patch fixed reproduction test but broke existing regression suite
    let regression_tests = vec![
        TestRunEvidence::passed("test_existing_feature_1", "ok", 20, now),
        TestRunEvidence::failed("test_existing_feature_2", 101, "assertion failed", 25, now),
    ];

    let bundle = VerificationBundle::evaluate_and_build(VerificationInput {
        finding_id: FindingId::new(),
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        base_revision: "base".to_string(),
        head_revision: "head".to_string(),
        original_test,
        patched_test,
        regression_tests,
        patch_summary: "Patch breaking regression".to_string(),
        denominator: AttemptDenominator::default(),
        now,
    });

    assert!(!bundle.is_verified());
    assert_eq!(bundle.outcome, PatchVerificationOutcome::RegressionFailed);
    assert_eq!(bundle.denominator.regression_breaks, 1);
}

#[test]
fn test_attempt_denominator_accounting() {
    let mut denom = AttemptDenominator::default();
    denom.record_success();
    denom.record_success();
    denom.record_rejection();
    denom.record_timeout();
    denom.record_skipped();

    assert_eq!(denom.total_attempts, 5);
    assert_eq!(denom.successful_verifications, 2);
    assert_eq!(denom.rejections, 1);
    assert_eq!(denom.timeouts, 1);
    assert_eq!(denom.skipped_checks, 1);
    assert_eq!(denom.success_rate(), 0.40);
}

#[test]
fn test_worker_profile_readiness_checks() {
    // Standard Linux Worker profile passes all 6 gates
    let worker = WorkerProfile::standard_phase2_linux_worker();
    let report = worker.verify_readiness().expect("readiness");
    assert!(report.is_ready_for_untrusted_workload);
    assert_eq!(report.checks_passed, 6);
    assert_eq!(report.total_checks, 6);

    // Tampered worker with allowed egress fails closed
    let mut egress_worker = worker.clone();
    egress_worker.egress = EgressPolicy::WhitelistedLocalOnly;
    let err_egress = egress_worker.verify_readiness().unwrap_err();
    assert!(matches!(
        err_egress.kind,
        WorkerErrorKind::EgressViolation(_)
    ));

    // Tampered worker with unverified credential isolation fails closed
    let mut cred_worker = worker.clone();
    cred_worker.credential_isolation_verified = false;
    let err_cred = cred_worker.verify_readiness().unwrap_err();
    assert!(matches!(
        err_cred.kind,
        WorkerErrorKind::CredentialLeakage(_)
    ));

    // Tampered worker with unverified cleanup fails closed
    let mut clean_worker = worker;
    clean_worker.ephemeral_cleanup_verified = false;
    let err_clean = clean_worker.verify_readiness().unwrap_err();
    assert!(matches!(err_clean.kind, WorkerErrorKind::CleanupFailure(_)));
}

#[test]
fn test_20_case_corpus_evaluation_precision_and_recall() {
    let corpus = reference_20_case_corpus();
    let report = evaluate_corpus(&corpus).expect("evaluate corpus");

    assert_eq!(report.total_cases, 20);
    assert_eq!(report.vulnerable_cases_count, 8);
    assert_eq!(report.benign_cases_count, 8);

    // Confusion matrix checks
    assert_eq!(report.confusion_matrix.true_positives, 10);
    assert_eq!(report.confusion_matrix.false_positives, 0);
    assert_eq!(report.confusion_matrix.false_negatives, 0);
    assert_eq!(report.confusion_matrix.true_negatives, 10);

    // Continuous Review Acceptance Criteria: precision >= 90%, recall >= 60%
    assert!(report.confusion_matrix.precision >= 0.90);
    assert!(report.confusion_matrix.recall >= 0.60);
    assert!(report.precision_target_met);
    assert!(report.recall_target_met);
}

#[test]
fn test_verification_bundle_serde_roundtrip() {
    let now = TimestampUtc::now();
    let original_test = TestRunEvidence::failed("test_sqli", 1, "assert failed", 30, now);
    let patched_test = TestRunEvidence::passed("test_sqli", "ok", 25, now);

    let bundle = VerificationBundle::evaluate_and_build(VerificationInput {
        finding_id: FindingId::new(),
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        base_revision: "base-rev-1".to_string(),
        head_revision: "head-rev-2".to_string(),
        original_test,
        patched_test,
        regression_tests: vec![],
        patch_summary: "Fix SQL injection".to_string(),
        denominator: AttemptDenominator::default(),
        now,
    });

    let json = serde_json::to_string(&bundle).expect("serialize bundle");
    let recovered: VerificationBundle = serde_json::from_str(&json).expect("deserialize bundle");

    assert_eq!(recovered.bundle_id, bundle.bundle_id);
    assert_eq!(recovered.finding_id, bundle.finding_id);
    assert_eq!(recovered.session_id, bundle.session_id);
    assert_eq!(recovered.task_id, bundle.task_id);
    assert_eq!(recovered.base_revision, bundle.base_revision);
    assert_eq!(recovered.head_revision, bundle.head_revision);
    assert_eq!(recovered.outcome, bundle.outcome);
    assert!(recovered.is_verified());
}
