//! Typed error hierarchy for the Sentra Core Service layer.

use std::fmt;

use crate::{
    DomainError, EvidenceVerificationError, ExecutionError, persistence::PersistenceError,
    workspace::WorkspaceError,
};

/// Categories of high-level Core Service errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceErrorKind {
    /// Session lifecycle or state machine error.
    Session,
    /// Workspace boundary or path traversal violation.
    WorkspaceBoundary,
    /// PolicyEngine default-deny or security classification denial.
    PolicyDenied,
    /// Operation requires operator approval before execution.
    NeedsApproval,
    /// Approval grant is invalid, expired, replayed, or context-mismatched.
    ApprovalInvalid,
    /// Session cost budget reservation exceeded.
    BudgetExceeded,
    /// Task execution failure, backend unavailability, or backend fault.
    Execution,
    /// Evidence structural bounds, length mismatch, or media-type validation error.
    EvidenceVerification,
    /// SQLite transactional persistence or recovery failure.
    Persistence,
    /// Invalid session or task state for requested operation.
    InvalidState,
    /// Task cancellation or lifecycle error.
    Cancellation,
    /// Task execution failed, and subsequent conservative budget settlement also failed (remediates F-561-03).
    ExecutionWithSettlementFailure,
    /// Evidence envelope verification failed, and subsequent conservative budget settlement also failed (remediates F-561-03).
    EvidenceWithSettlementFailure,
}

/// Redacted typed Core Service error.
///
/// Ensures diagnostic strings never expose confidential workspace contents,
/// secret authorization tokens, or raw evidence payloads.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceError {
    /// Categorical kind of service failure.
    pub kind: ServiceErrorKind,
    /// Safe diagnostic message without sensitive leakage.
    pub message: String,
    /// Secondary persistence or settlement error, if an error occurred during post-failure cleanup (remediates F-561-03).
    pub secondary_error: Option<String>,
}

impl ServiceError {
    /// Constructs a new service error.
    pub fn new(kind: ServiceErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            secondary_error: None,
        }
    }

    /// Helper for session errors.
    pub fn session(msg: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::Session, msg)
    }

    /// Helper for workspace boundary violations.
    pub fn workspace(err: WorkspaceError) -> Self {
        Self::new(ServiceErrorKind::WorkspaceBoundary, err.to_string())
    }

    /// Helper for policy denials.
    pub fn policy_denied(msg: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::PolicyDenied, msg)
    }

    /// Helper for operations requiring human approval.
    pub fn needs_approval(approval_id: crate::ApprovalId) -> Self {
        Self::new(
            ServiceErrorKind::NeedsApproval,
            format!("Operation requires human approval (ApprovalId: {approval_id})"),
        )
    }

    /// Helper for approval validation errors.
    pub fn approval_invalid(msg: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::ApprovalInvalid, msg)
    }

    /// Helper for budget limit breaches.
    pub fn budget_exceeded(msg: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::BudgetExceeded, msg)
    }

    /// Helper for execution backend errors.
    pub fn execution(err: ExecutionError) -> Self {
        Self::new(ServiceErrorKind::Execution, err.to_string())
    }

    /// Helper for evidence verification errors.
    pub fn evidence(err: EvidenceVerificationError) -> Self {
        Self::new(ServiceErrorKind::EvidenceVerification, err.to_string())
    }

    /// Helper for persistence errors.
    pub fn persistence(err: PersistenceError) -> Self {
        Self::new(ServiceErrorKind::Persistence, err.to_string())
    }

    /// Helper for invalid state errors.
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::InvalidState, msg)
    }

    /// Helper for cancellation errors.
    pub fn cancellation(msg: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::Cancellation, msg)
    }

    /// Helper for execution failure compounded by settlement failure (remediates F-561-03).
    pub fn execution_with_settlement_failure(
        exec_err: ExecutionError,
        settle_err: PersistenceError,
    ) -> Self {
        Self {
            kind: ServiceErrorKind::ExecutionWithSettlementFailure,
            message: format!("{exec_err}; secondary settlement failure: {settle_err}"),
            secondary_error: Some(settle_err.to_string()),
        }
    }

    /// Helper for evidence verification failure compounded by settlement failure (remediates F-561-03).
    pub fn evidence_with_settlement_failure(
        ev_err: EvidenceVerificationError,
        settle_err: PersistenceError,
    ) -> Self {
        Self {
            kind: ServiceErrorKind::EvidenceWithSettlementFailure,
            message: format!("{ev_err}; secondary settlement failure: {settle_err}"),
            secondary_error: Some(settle_err.to_string()),
        }
    }

    /// Whether this error represents an execution failure (standalone or with settlement failure).
    pub fn is_execution(&self) -> bool {
        matches!(
            self.kind,
            ServiceErrorKind::Execution | ServiceErrorKind::ExecutionWithSettlementFailure
        )
    }

    /// Whether this error represents an evidence verification failure (standalone or with settlement failure).
    pub fn is_evidence(&self) -> bool {
        matches!(
            self.kind,
            ServiceErrorKind::EvidenceVerification
                | ServiceErrorKind::EvidenceWithSettlementFailure
        )
    }

    /// Whether this error was accompanied by a secondary budget settlement failure.
    pub fn has_settlement_failure(&self) -> bool {
        matches!(
            self.kind,
            ServiceErrorKind::ExecutionWithSettlementFailure
                | ServiceErrorKind::EvidenceWithSettlementFailure
        )
    }

    /// Returns the secondary persistence/settlement error message, if present.
    pub fn secondary_error(&self) -> Option<&str> {
        self.secondary_error.as_deref()
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref sec) = self.secondary_error {
            write!(
                f,
                "service error [{:?}]: {} (secondary: {})",
                self.kind, self.message, sec
            )
        } else {
            write!(f, "service error [{:?}]: {}", self.kind, self.message)
        }
    }
}

impl fmt::Debug for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceError")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .field("secondary_error", &self.secondary_error)
            .finish()
    }
}

impl std::error::Error for ServiceError {}

impl From<DomainError> for ServiceError {
    fn from(err: DomainError) -> Self {
        Self::new(ServiceErrorKind::Session, err.to_string())
    }
}

impl From<WorkspaceError> for ServiceError {
    fn from(err: WorkspaceError) -> Self {
        Self::workspace(err)
    }
}

impl From<ExecutionError> for ServiceError {
    fn from(err: ExecutionError) -> Self {
        Self::execution(err)
    }
}

impl From<EvidenceVerificationError> for ServiceError {
    fn from(err: EvidenceVerificationError) -> Self {
        Self::evidence(err)
    }
}

impl From<PersistenceError> for ServiceError {
    fn from(err: PersistenceError) -> Self {
        Self::persistence(err)
    }
}
