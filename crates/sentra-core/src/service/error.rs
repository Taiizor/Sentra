//! Typed, payload-free service diagnostics. Free-form backend details are not retained.
use crate::{
    DomainError, EvidenceVerificationError, ExecutionError, ExecutionStatus,
    persistence::PersistenceError, workspace::WorkspaceError,
};
use std::fmt;

/// Stable service-level category; primary and secondary sources remain separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceErrorKind {
    /// Session lifecycle validation failed.
    Session,
    /// Filesystem boundary rejected.
    WorkspaceBoundary,
    /// Trusted policy denied admission.
    PolicyDenied,
    /// Explicit approval is required.
    NeedsApproval,
    /// Grant binding or lifecycle rejected.
    ApprovalInvalid,
    /// Session budget exhausted.
    BudgetExceeded,
    /// Execution adapter or result validation failed.
    Execution,
    /// Evidence verification failed.
    EvidenceVerification,
    /// Persistence failed.
    Persistence,
    /// Session is ineligible.
    InvalidState,
    /// Cancellation failed.
    Cancellation,
    /// Execution error and conservative settlement both failed.
    ExecutionWithSettlementFailure,
    /// Evidence error and conservative settlement both failed.
    EvidenceWithSettlementFailure,
    /// A non-success validated execution outcome and settlement both failed.
    OutcomeWithSettlementFailure,
}

/// Validated non-success result, distinct from adapter/validation errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionOutcomeError {
    /// Original failed, timed-out or cancelled status.
    pub status: ExecutionStatus,
    /// Numeric exit code without any target output.
    pub exit_code: Option<i32>,
}
impl fmt::Display for ExecutionOutcomeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "execution outcome {:?} (exit={:?})",
            self.status, self.exit_code
        )
    }
}
impl std::error::Error for ExecutionOutcomeError {}

/// Typed primary cause; stored execution/evidence messages are sanitized on ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServicePrimaryError {
    /// Adapter or result validation error, with original kind.
    Execution(ExecutionError),
    /// Evidence validation error, with original kind.
    Evidence(EvidenceVerificationError),
    /// Persistence category and numeric SQLite/rollback diagnostics.
    Persistence(PersistenceError),
    /// Validated non-success terminal result.
    Outcome(ExecutionOutcomeError),
}

/// Diagnostic-safe service error; no raw backend text, paths or approval material.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceError {
    /// Service-level classification.
    pub kind: ServiceErrorKind,
    /// Generic payload-free summary, retained for source compatibility.
    pub message: String,
    primary: Option<ServicePrimaryError>,
    secondary: Option<PersistenceError>,
}
impl ServiceError {
    /// Free-form input is deliberately discarded: it may originate in untrusted data.
    pub fn new(kind: ServiceErrorKind, _message: impl Into<String>) -> Self {
        Self {
            message: format!("Service {kind:?}"),
            kind,
            primary: None,
            secondary: None,
        }
    }
    /// Session error.
    pub fn session(msg: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::Session, msg)
    }
    /// Boundary error. Relative path payload is not retained.
    pub fn workspace(_err: WorkspaceError) -> Self {
        Self::new(ServiceErrorKind::WorkspaceBoundary, "")
    }
    /// Policy denial.
    pub fn policy_denied(msg: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::PolicyDenied, msg)
    }
    /// Approval required; identifiers are not diagnostic proof of authority.
    pub fn needs_approval(_id: crate::ApprovalId) -> Self {
        Self::new(ServiceErrorKind::NeedsApproval, "")
    }
    /// Approval rejection.
    pub fn approval_invalid(msg: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::ApprovalInvalid, msg)
    }
    /// Budget denial.
    pub fn budget_exceeded(msg: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::BudgetExceeded, msg)
    }
    /// Ineligible state.
    pub fn invalid_state(msg: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::InvalidState, msg)
    }
    /// Cancellation error.
    pub fn cancellation(msg: impl Into<String>) -> Self {
        Self::new(ServiceErrorKind::Cancellation, msg)
    }
    /// Preserve typed execution kind, discard arbitrary backend message even for struct literals.
    pub fn execution(err: ExecutionError) -> Self {
        let mut value = Self::new(ServiceErrorKind::Execution, "");
        value.primary = Some(ServicePrimaryError::Execution(ExecutionError::new(
            err.kind,
            "Execution rejected",
        )));
        value
    }
    /// Preserve typed evidence kind without untrusted metadata.
    pub fn evidence(err: EvidenceVerificationError) -> Self {
        let mut value = Self::new(ServiceErrorKind::EvidenceVerification, "");
        value.primary = Some(ServicePrimaryError::Evidence(
            EvidenceVerificationError::new(err.kind, "Evidence rejected"),
        ));
        value
    }
    /// Preserve numeric persistence information.
    pub fn persistence(err: PersistenceError) -> Self {
        let mut value = Self::new(ServiceErrorKind::Persistence, "");
        value.primary = Some(ServicePrimaryError::Persistence(err));
        value
    }
    /// Retain both typed causes without conflating their categories.
    pub fn execution_with_settlement_failure(
        primary: ExecutionError,
        secondary: PersistenceError,
    ) -> Self {
        let mut value = Self::execution(primary);
        value.kind = ServiceErrorKind::ExecutionWithSettlementFailure;
        value.secondary = Some(secondary);
        value
    }
    /// Retain both typed causes without retaining confidential evidence text.
    pub fn evidence_with_settlement_failure(
        primary: EvidenceVerificationError,
        secondary: PersistenceError,
    ) -> Self {
        let mut value = Self::evidence(primary);
        value.kind = ServiceErrorKind::EvidenceWithSettlementFailure;
        value.secondary = Some(secondary);
        value
    }
    /// Preserve the original terminal outcome when its settlement also fails.
    pub fn outcome_with_settlement_failure(
        status: ExecutionStatus,
        exit_code: Option<i32>,
        secondary: PersistenceError,
    ) -> Self {
        let mut value = Self::new(ServiceErrorKind::OutcomeWithSettlementFailure, "");
        value.primary = Some(ServicePrimaryError::Outcome(ExecutionOutcomeError {
            status,
            exit_code,
        }));
        value.secondary = Some(secondary);
        value
    }
    /// Typed primary source; never contains arbitrary diagnostic text.
    pub fn primary_error(&self) -> Option<&ServicePrimaryError> {
        self.primary.as_ref()
    }
    /// Typed secondary persistence source, independently inspectable.
    pub fn secondary_error(&self) -> Option<&PersistenceError> {
        self.secondary.as_ref()
    }
    /// Execution failure, including a validated non-success outcome.
    pub fn is_execution(&self) -> bool {
        matches!(
            self.kind,
            ServiceErrorKind::Execution
                | ServiceErrorKind::ExecutionWithSettlementFailure
                | ServiceErrorKind::OutcomeWithSettlementFailure
        )
    }
    /// Evidence failure.
    pub fn is_evidence(&self) -> bool {
        matches!(
            self.kind,
            ServiceErrorKind::EvidenceVerification
                | ServiceErrorKind::EvidenceWithSettlementFailure
        )
    }
    /// Whether conservative settlement also failed.
    pub fn has_settlement_failure(&self) -> bool {
        self.secondary.is_some()
    }
}
impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "service {:?} (primary={:?}, secondary={:?})",
            self.kind, self.primary, self.secondary
        )
    }
}
impl fmt::Debug for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.primary.as_ref()? {
            ServicePrimaryError::Execution(e) => Some(e),
            ServicePrimaryError::Evidence(e) => Some(e),
            ServicePrimaryError::Persistence(e) => Some(e),
            ServicePrimaryError::Outcome(e) => Some(e),
        }
    }
}
impl From<DomainError> for ServiceError {
    fn from(_err: DomainError) -> Self {
        Self::session("")
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
