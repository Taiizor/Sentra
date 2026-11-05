//! Domain and resource models for execution requests, results, and capabilities.

use crate::{
    ExecutionId, OperationAction, SecurityClassification, SessionId, TaskId, TimestampUtc,
    execution::{
        error::{ExecutionError, ExecutionErrorKind},
        scope::ExecutionScope,
    },
};

/// Maximum permissible execution timeout: 1 hour (3,600,000 milliseconds).
pub const MAX_EXECUTION_TIMEOUT_MILLIS: u64 = 3_600_000;
/// Default execution timeout: 60 seconds (60,000 milliseconds).
pub const DEFAULT_EXECUTION_TIMEOUT_MILLIS: u64 = 60_000;
/// Maximum output payload buffer: 10 MiB.
pub const MAX_OUTPUT_LIMIT_BYTES: u64 = 10 * 1024 * 1024;
/// Maximum memory limit: 8 GiB.
pub const MAX_MEMORY_LIMIT_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Resource quotas and bounds enforced during execution dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Execution timeout in milliseconds.
    pub timeout_millis: u64,
    /// Maximum allowed memory allocation in bytes.
    pub max_memory_bytes: u64,
    /// Maximum stdout/stderr output capture size in bytes.
    pub max_output_bytes: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout_millis: DEFAULT_EXECUTION_TIMEOUT_MILLIS,
            max_memory_bytes: 512 * 1024 * 1024, // 512 MiB
            max_output_bytes: 1024 * 1024,       // 1 MiB
        }
    }
}

impl ResourceLimits {
    /// Validates that resource limits are positive and within allowable system ceilings.
    pub fn validate(&self) -> Result<(), ExecutionError> {
        if self.timeout_millis == 0 || self.timeout_millis > MAX_EXECUTION_TIMEOUT_MILLIS {
            return Err(ExecutionError::new(
                ExecutionErrorKind::InvalidRequest,
                format!(
                    "timeout_millis must be between 1 and {MAX_EXECUTION_TIMEOUT_MILLIS}, got {}",
                    self.timeout_millis
                ),
            ));
        }
        if self.max_memory_bytes == 0 || self.max_memory_bytes > MAX_MEMORY_LIMIT_BYTES {
            return Err(ExecutionError::new(
                ExecutionErrorKind::InvalidRequest,
                format!(
                    "max_memory_bytes must be between 1 and {MAX_MEMORY_LIMIT_BYTES}, got {}",
                    self.max_memory_bytes
                ),
            ));
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > MAX_OUTPUT_LIMIT_BYTES {
            return Err(ExecutionError::new(
                ExecutionErrorKind::InvalidRequest,
                format!(
                    "max_output_bytes must be between 1 and {MAX_OUTPUT_LIMIT_BYTES}, got {}",
                    self.max_output_bytes
                ),
            ));
        }
        Ok(())
    }
}

/// Measured resource consumption of an execution task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceUsage {
    /// Real elapsed execution time in milliseconds.
    pub duration_millis: u64,
    /// Peak observed memory footprint in bytes.
    pub peak_memory_bytes: u64,
    /// Total bytes written to standard output and error.
    pub output_bytes: u64,
}

impl ResourceUsage {
    /// Zero resource usage record for immediate rejection or failure before start.
    pub const fn zero() -> Self {
        Self {
            duration_millis: 0,
            peak_memory_bytes: 0,
            output_bytes: 0,
        }
    }
}

/// Final outcome category of an executed task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Completed normally with a zero exit code and expected evidence.
    Completed,
    /// Non-zero exit code or application-level failure inside worker.
    Failed,
    /// Exceeded assigned wall-clock timeout limit before completion.
    TimedOut,
    /// Cancelled explicitly by controller, operator, or session termination.
    Cancelled,
}

impl ExecutionStatus {
    /// Returns true if this status represents successful completion.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Completed)
    }

    /// Canonical string identifier for audit logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::TimedOut => "TIMED_OUT",
            Self::Cancelled => "CANCELLED",
        }
    }
}

/// Declared capabilities and availability profile of an execution backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendCapabilities {
    /// Identifier name of the backend.
    pub backend_name: &'static str,
    /// Whether this backend is authorized and capable of executing untrusted project code.
    pub supports_untrusted: bool,
    /// Whether this backend supports curated synthetic test fixtures.
    pub supports_synthetic: bool,
    /// Whether hardware-assisted Hyper-V VM worker isolation is active and verified.
    pub isolated_vm_available: bool,
    /// Whether direct host process execution is permitted (must be strictly false).
    pub host_execution: bool,
    /// Whether Docker or WSL2 container execution is used (must be strictly false).
    pub docker_wsl_execution: bool,
    /// Human-readable description of backend status and boundaries.
    pub description: &'static str,
}

/// Fully validated execution dispatch request.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecutionRequest {
    /// Unique identifier for this dispatch attempt.
    pub execution_id: ExecutionId,
    /// Authoritative research session context.
    pub session_id: SessionId,
    /// Specific task identity within the session DAG.
    pub task_id: TaskId,
    /// Explicit security scope (synthetic fixture vs untrusted target code).
    pub scope: ExecutionScope,
    /// Concrete typed operation to be performed.
    pub action: OperationAction,
    /// Verified target checkout commit/tree revision.
    pub target_revision: String,
    /// Assigned resource quotas and limits.
    pub resource_limits: ResourceLimits,
    /// Target data classification level.
    pub classification: SecurityClassification,
    /// Dispatch submission timestamp.
    pub created_at: TimestampUtc,
}

impl ExecutionRequest {
    /// Performs exhaustive validation on request parameters prior to backend dispatch.
    pub fn validate(&self) -> Result<(), ExecutionError> {
        let rev = self.target_revision.trim();
        if rev.is_empty() || rev.chars().any(char::is_control) {
            return Err(ExecutionError::new(
                ExecutionErrorKind::InvalidRequest,
                "target_revision must be non-empty and contain no control characters",
            ));
        }
        self.resource_limits.validate()?;
        Ok(())
    }
}

/// Result returned from execution dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionResult {
    /// Execution attempt identifier.
    pub execution_id: ExecutionId,
    /// Terminal lifecycle status.
    pub status: ExecutionStatus,
    /// Process exit code, if a process was executed and returned an exit status.
    pub exit_code: Option<i32>,
    /// Measured resource utilization.
    pub resource_usage: ResourceUsage,
    /// Descriptors of evidence artifacts generated during execution.
    pub evidence_descriptors: Vec<String>,
    /// Completion timestamp.
    pub completed_at: TimestampUtc,
}

impl ExecutionResult {
    /// Centralized result-validation contract remediating F-551-01 and F-551-05.
    ///
    /// Exhaustively validates backend result consistency against the originating request:
    /// 1. Correlation check: `result.execution_id == request.execution_id`.
    /// 2. Completed consistency: `ExecutionStatus::Completed` must have consistent successful outcome
    ///    (`exit_code == Some(0)` or `None`; never a non-zero exit code).
    /// 3. Failed consistency: `ExecutionStatus::Failed` must not report `exit_code == Some(0)`.
    /// 4. TimedOut consistency: `ExecutionStatus::TimedOut` must not report `exit_code == Some(0)`.
    /// 5. Cancelled consistency: `ExecutionStatus::Cancelled` must not report `exit_code == Some(0)`.
    /// 6. Temporal consistency: `completed_at` must not precede `request.created_at`.
    pub fn validate_for_request(&self, request: &ExecutionRequest) -> Result<(), ExecutionError> {
        // F-551-05: Correlation check
        if self.execution_id != request.execution_id {
            return Err(ExecutionError::correlation_mismatch(
                request.execution_id,
                self.execution_id,
            ));
        }

        // Temporal order check: completion cannot occur before request creation
        if self.completed_at < request.created_at {
            return Err(ExecutionError::new(
                ExecutionErrorKind::BackendFault,
                format!(
                    "Contradictory execution result: completed_at ({}) precedes request created_at ({})",
                    self.completed_at, request.created_at
                ),
            ));
        }

        // F-551-01: Exhaustive status and exit code consistency
        match self.status {
            ExecutionStatus::Completed => {
                if let Some(code) = self.exit_code
                    && code != 0
                {
                    return Err(ExecutionError::new(
                        ExecutionErrorKind::BackendFault,
                        format!(
                            "Contradictory execution result: status is Completed but exit_code is non-zero ({code})"
                        ),
                    ));
                }
            }
            ExecutionStatus::Failed => {
                if self.exit_code == Some(0) {
                    return Err(ExecutionError::new(
                        ExecutionErrorKind::BackendFault,
                        "Contradictory execution result: status is Failed but exit_code is Some(0)",
                    ));
                }
            }
            ExecutionStatus::TimedOut => {
                if self.exit_code == Some(0) {
                    return Err(ExecutionError::new(
                        ExecutionErrorKind::BackendFault,
                        "Contradictory execution result: status is TimedOut but exit_code is Some(0)",
                    ));
                }
            }
            ExecutionStatus::Cancelled => {
                if self.exit_code == Some(0) {
                    return Err(ExecutionError::new(
                        ExecutionErrorKind::BackendFault,
                        "Contradictory execution result: status is Cancelled but exit_code is Some(0)",
                    ));
                }
            }
        }

        Ok(())
    }
}
