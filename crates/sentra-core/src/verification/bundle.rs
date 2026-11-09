//! Verification bundle data models and attempt denominator accounting (REQ-F14, Verification Specification).

use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Serialize, Deserialize)]
struct TestRunEvidencePayload {
    test_name: String,
    status: TestStatus,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    duration_ms: u64,
    executed_at: String,
}

impl Serialize for TestRunEvidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let payload = TestRunEvidencePayload {
            test_name: self.test_name.clone(),
            status: self.status,
            exit_code: self.exit_code,
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            duration_ms: self.duration_ms,
            executed_at: self.executed_at.to_string(),
        };
        payload.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TestRunEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let payload = TestRunEvidencePayload::deserialize(deserializer)?;
        let executed_at =
            TimestampUtc::from_str(&payload.executed_at).map_err(serde::de::Error::custom)?;
        Ok(Self {
            test_name: payload.test_name,
            status: payload.status,
            exit_code: payload.exit_code,
            stdout: payload.stdout,
            stderr: payload.stderr,
            duration_ms: payload.duration_ms,
            executed_at,
        })
    }
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

/// Strict attempt denominator accounting (Independent Verification Specification).
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
#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Serialize, Deserialize)]
struct VerificationBundlePayload {
    bundle_id: String,
    finding_id: String,
    session_id: String,
    task_id: String,
    base_revision: String,
    head_revision: String,
    original_test_evidence: TestRunEvidence,
    patched_test_evidence: TestRunEvidence,
    regression_evidence: Vec<TestRunEvidence>,
    patch_summary: String,
    denominator: AttemptDenominator,
    outcome: PatchVerificationOutcome,
    created_at: String,
}

impl Serialize for VerificationBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let payload = VerificationBundlePayload {
            bundle_id: self.bundle_id.clone(),
            finding_id: self.finding_id.to_string(),
            session_id: self.session_id.to_string(),
            task_id: self.task_id.to_string(),
            base_revision: self.base_revision.clone(),
            head_revision: self.head_revision.clone(),
            original_test_evidence: self.original_test_evidence.clone(),
            patched_test_evidence: self.patched_test_evidence.clone(),
            regression_evidence: self.regression_evidence.clone(),
            patch_summary: self.patch_summary.clone(),
            denominator: self.denominator,
            outcome: self.outcome,
            created_at: self.created_at.to_string(),
        };
        payload.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VerificationBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let payload = VerificationBundlePayload::deserialize(deserializer)?;
        let finding_id =
            FindingId::from_str(&payload.finding_id).map_err(serde::de::Error::custom)?;
        let session_id =
            SessionId::from_str(&payload.session_id).map_err(serde::de::Error::custom)?;
        let task_id = TaskId::from_str(&payload.task_id).map_err(serde::de::Error::custom)?;
        let created_at =
            TimestampUtc::from_str(&payload.created_at).map_err(serde::de::Error::custom)?;

        Ok(Self {
            bundle_id: payload.bundle_id,
            finding_id,
            session_id,
            task_id,
            base_revision: payload.base_revision,
            head_revision: payload.head_revision,
            original_test_evidence: payload.original_test_evidence,
            patched_test_evidence: payload.patched_test_evidence,
            regression_evidence: payload.regression_evidence,
            patch_summary: payload.patch_summary,
            denominator: payload.denominator,
            outcome: payload.outcome,
            created_at,
        })
    }
}

/// Input parameters for evaluating and building a patch verification bundle.
#[derive(Clone, Debug)]
pub struct VerificationInput {
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
    /// Test evidence on the original unpatched codebase.
    pub original_test: TestRunEvidence,
    /// Test evidence on the patched codebase.
    pub patched_test: TestRunEvidence,
    /// Test evidence for the existing regression test suite.
    pub regression_tests: Vec<TestRunEvidence>,
    /// Unified diff or summary of the applied patch.
    pub patch_summary: String,
    /// Cumulative attempt denominator.
    pub denominator: AttemptDenominator,
    /// Evaluation timestamp.
    pub now: TimestampUtc,
}

impl VerificationBundle {
    /// Evaluates and constructs a verification bundle enforcing strict original-fails/patched-passes rules.
    pub fn evaluate_and_build(input: VerificationInput) -> Self {
        let mut denominator = input.denominator;

        let outcome = if input.original_test.status != TestStatus::Failed {
            denominator.record_no_fix();
            PatchVerificationOutcome::OriginalDidNotFail
        } else if input.patched_test.status != TestStatus::Passed {
            denominator.record_no_fix();
            PatchVerificationOutcome::PatchDidNotPass
        } else if input
            .regression_tests
            .iter()
            .any(|r| r.status != TestStatus::Passed)
        {
            denominator.record_regression_break();
            PatchVerificationOutcome::RegressionFailed
        } else {
            denominator.record_success();
            PatchVerificationOutcome::Verified
        };

        let bundle_seed = format!(
            "{}:{}:{}:{}:{}:{:?}",
            input.finding_id,
            input.session_id,
            input.task_id,
            input.base_revision,
            input.head_revision,
            outcome
        );
        let bundle_id = sha256_prefixed(bundle_seed.as_bytes());

        Self {
            bundle_id,
            finding_id: input.finding_id,
            session_id: input.session_id,
            task_id: input.task_id,
            base_revision: input.base_revision,
            head_revision: input.head_revision,
            original_test_evidence: input.original_test,
            patched_test_evidence: input.patched_test,
            regression_evidence: input.regression_tests,
            patch_summary: input.patch_summary,
            denominator,
            outcome,
            created_at: input.now,
        }
    }

    /// Whether this bundle achieves verified status under verification acceptance criteria.
    pub fn is_verified(&self) -> bool {
        self.outcome == PatchVerificationOutcome::Verified
    }
}
