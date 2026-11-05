//! Typed execution error models.

use std::fmt;

/// Categories of execution errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionErrorKind {
    /// Scope is not supported by the execution backend (e.g. untrusted target execution).
    UnsupportedScope,
    /// The requested backend is not available, running, or configured.
    BackendUnavailable,
    /// The operation was denied by policy or missing required authorization.
    PolicyDenied,
    /// The execution timed out before completion.
    Timeout,
    /// The execution was explicitly cancelled.
    Cancelled,
    /// Request parameters, resource bounds, or context are invalid.
    InvalidRequest,
    /// An internal execution fault occurred within the backend.
    BackendFault,
    /// Recording the execution audit event failed.
    AuditFailure,
    /// Execution correlation identifier mismatch between request and result (remediates F-551-05).
    CorrelationMismatch,
}

/// Redacted typed execution error.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecutionError {
    /// Categorical kind of execution failure.
    pub kind: ExecutionErrorKind,
    /// Safe, diagnostic message (does not disclose sensitive payload data).
    pub message: String,
}

impl ExecutionError {
    /// Constructs a new execution error with a category and safe message.
    pub fn new(kind: ExecutionErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Helper for untrusted target workloads rejected due to unvalidated Hyper-V isolation.
    pub fn untrusted_workload_disabled() -> Self {
        Self::new(
            ExecutionErrorKind::BackendUnavailable,
            "Untrusted target execution is disabled pending validated Hyper-V VM isolation (ADR-0004)",
        )
    }

    /// Whether this error represents an unavailable or unconfigured backend.
    pub fn is_unavailable(&self) -> bool {
        matches!(self.kind, ExecutionErrorKind::BackendUnavailable)
    }

    /// Whether this error was caused by a policy or authorization denial.
    pub fn is_policy_denied(&self) -> bool {
        matches!(self.kind, ExecutionErrorKind::PolicyDenied)
    }

    /// Helper for execution identifier correlation mismatch (remediates F-551-05).
    pub fn correlation_mismatch(
        expected: crate::ExecutionId,
        received: crate::ExecutionId,
    ) -> Self {
        Self::new(
            ExecutionErrorKind::CorrelationMismatch,
            format!("Execution ID correlation mismatch: expected {expected}, received {received}"),
        )
    }

    /// Whether this error represents an execution ID correlation mismatch.
    pub fn is_correlation_mismatch(&self) -> bool {
        matches!(self.kind, ExecutionErrorKind::CorrelationMismatch)
    }

    /// Whether this error represents an internal backend fault or contradictory result.
    pub fn is_backend_fault(&self) -> bool {
        matches!(self.kind, ExecutionErrorKind::BackendFault)
    }
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "execution error [{:?}]: {}", self.kind, self.message)
    }
}

impl fmt::Debug for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecutionError")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .finish()
    }
}

impl std::error::Error for ExecutionError {}
