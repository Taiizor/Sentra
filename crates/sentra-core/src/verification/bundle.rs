//! Verification bundle data models and attempt denominator accounting (REQ-F14, Roadmap Phase 2 Acceptance Criteria).

use serde::{Deserialize, Serialize};

use crate::{
    common::crypto::sha256_prefixed,
    domain::{FindingId, SessionId, TaskId, TimestampUtc},
};

/// Execution status of an individual test invocation within the verification harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestStatus {
    /// Test completed with exit code 0 and all assertions passing.
    Passed,
    /// Test failed with non-zero exit code or an assertion failure.
    Failed,
    /// Test timed out before finishing.
    TimedOut,
    /// Test execution was cancelled or aborted.
    Cancelled,
}

impl TestStatus {
    /// Returns the static string representation.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Evidentiary record of a concrete test harness run on a target codebase.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestRunEvidence {
    /// Test identifier or harness command (e.g. `test_auth_bypass`).
    pub test_name: String,
    /// Observed execution outcome.
    pub status: TestStatus,
    /// OS process exit code, if terminated normally.
    pub exit_code: Option<i32>,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Measured execution duration in milliseconds.
    pub duration_ms: u64,
    /// Execution timestamp.
    pub executed_at: TimestampUtc,
}

impl TestRunEvidence {
    /// Constructs a passing test run evidence record.
    pub fn passed(
        test_name: impl Into<String>,
        stdout: impl Into<String>,
        duration_ms: u64,
        now: TimestampUtc,
    ) -> Self {
        Self {
            test_name: test_name.into(),
            status: TestStatus::Passed,
            exit_code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
            duration_ms,
            executed_at: now,
        }
    }

    /// Constructs a failing test run evidence record.
    pub fn failed(
        test_name: impl Into<String>,
        exit_code: i32,
        stderr: impl Into<String>,
        duration_ms: u64,
        now: TimestampUtc,
    ) -> Self {
        Self {
            test_name: test_name.into(),
            status: TestStatus::Failed,
            exit_code: Some(exit_code),
            stdout: String::new(),
            stderr: stderr.into(),
            duration_ms,
            executed_at: now,
        }
    }
}

/// Strict attempt denominator accounting (Roadmap Phase 2 Acceptance Criteria).
///
/// Records every attempt, rejection, timeout, skipped check, and no-fix outcome
/// so verification rates cannot be inflated by omitting failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AttemptDenominator {
    /// Total number of verification attempts initiated.
    pub total_attempts: u32,
    /// Number of attempts rejected by policy, syntax, or pre-flight checks.
    pub rejections: u32,
    /// Number of attempts that exceeded their execution time ceiling.
    pub timeouts: u32,
    /// Number of checks skipped due to unbuildable targets or missing prerequisites.
    pub skipped_checks: u32,
    /// Number of attempts where the patch did not fix the failing test.
    pub no_fix_outcomes: u32,
    /// Number of attempts that broke existing regression tests.
    pub regression_breaks: u32,
    /// Number of attempts that achieved verified patch status (original fails, patched passes, no regressions).
    pub successful_verifications: u32,
}

impl AttemptDenominator {
    /// Records a successful verification.
    pub fn record_success(&mut self) {
        self.total_attempts += 1;
        self.successful_verifications += 1;
    }

    /// Records a rejection.
    pub fn record_rejection(&mut self) {
        self.total_attempts += 1;
        self.rejections += 1;
    }

    /// Records a timeout.
    pub fn record_timeout(&mut self) {
        self.total_attempts += 1;
        self.timeouts += 1;
    }

    /// Records a skipped check.
    pub fn record_skipped(&mut self) {
        self.total_attempts += 1;
        self.skipped_checks += 1;
    }

    /// Records a patch that did not fix the target failure.
    pub fn record_no_fix(&mut self) {
        self.total_attempts += 1;
        self.no_fix_outcomes += 1;
    }

    /// Records a patch that broke an existing regression test.
    pub fn record_regression_break(&mut self) {
        self.total_attempts += 1;
        self.regression_breaks += 1;
    }

    /// Calculates success rate as a fraction between 0.0 and 1.0.
    pub fn success_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            0.0
        } else {
            self.successful_verifications as f64 / self.total_attempts as f64
        }
    }
}

/// Final verdict of an end-to-end patch verification workflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchVerificationOutcome {
    /// Fully verified: original target failed test, patched target passed test, and all regressions passed.
    Verified,
    /// Verification failed because original unpatched target did not fail the reproduction test.
    OriginalDidNotFail,
    /// Verification failed because patched target did not pass the reproduction test.
    PatchDidNotPass,
    /// Verification failed because the patch introduced a regression into existing passing tests.
    RegressionFailed,
    /// Verification timed out during execution.
    TimedOut,
    /// Verification rejected by policy or resource bounds.
    Rejected,
}

/// Cryptographically bound verification bundle proving patch efficacy (REQ-F14).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationBundle {
    /// Deterministic bundle digest identifier (`sha256:...`).
    pub bundle_id: String,
    /// Target finding identifier being addressed.
    pub finding_id: FindingId,
    /// Associated session identifier.
    pub session_id: SessionId,
    /// Associated task identifier.
    pub task_id: TaskId,
    /// Base commit or snapshot revision.
    pub base_revision: String,
    /// Candidate patch head revision.
    pub head_revision: String,
    /// Test evidence on the original unpatched codebase (MUST be Failed).
    pub original_test_evidence: TestRunEvidence,
    /// Test evidence on the patched codebase (MUST be Passed).
    pub patched_test_evidence: TestRunEvidence,
    /// Test evidence for existing regression test suite (ALL MUST be Passed).
    pub regression_evidence: Vec<TestRunEvidence>,
    /// Unified diff or description of the applied patch.
    pub patch_summary: String,
    /// Attempt denominator accounting for the verification campaign.
    pub denominator: AttemptDenominator,
    /// Final verification outcome verdict.
    pub outcome: PatchVerificationOutcome,
    /// Bundle creation timestamp.
    pub created_at: TimestampUtc,
}

impl VerificationBundle {
    /// Evaluates and constructs a verification bundle enforcing strict original-fails/patched-passes rules.
    pub fn evaluate_and_build(
        finding_id: FindingId,
        session_id: SessionId,
        task_id: TaskId,
        base_revision: impl Into<String>,
        head_revision: impl Into<String>,
        original_test: TestRunEvidence,
        patched_test: TestRunEvidence,
        regression_tests: Vec<TestRunEvidence>,
        patch_summary: impl Into<String>,
        mut denominator: AttemptDenominator,
        now: TimestampUtc,
    ) -> Self {
        let base_rev = base_revision.into();
        let head_rev = head_revision.into();
        let patch_sum = patch_summary.into();

        let outcome = if original_test.status != TestStatus::Failed {
            denominator.record_no_fix();
            PatchVerificationOutcome::OriginalDidNotFail
        } else if patched_test.status != TestStatus::Passed {
            denominator.record_no_fix();
            PatchVerificationOutcome::PatchDidNotPass
        } else if regression_tests.iter().any(|r| r.status != TestStatus::Passed) {
            denominator.record_regression_break();
            PatchVerificationOutcome::RegressionFailed
        } else {
            denominator.record_success();
            PatchVerificationOutcome::Verified
        };

        let bundle_seed = format!(
            "{}:{}:{}:{}:{}:{:?}",
            finding_id, session_id, task_id, base_rev, head_rev, outcome
        );
        let bundle_id = sha256_prefixed(bundle_seed.as_bytes());

        Self {
            bundle_id,
            finding_id,
            session_id,
            task_id,
            base_revision: base_rev,
            head_revision: head_rev,
            original_test_evidence: original_test,
            patched_test_evidence: patched_test,
            regression_evidence: regression_tests,
            patch_summary: patch_sum,
            denominator,
            outcome,
            created_at: now,
        }
    }

    /// Whether this bundle achieves verified status under Phase 2 acceptance criteria.
    pub fn is_verified(&self) -> bool {
        self.outcome == PatchVerificationOutcome::Verified
    }
}
