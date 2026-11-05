use std::fmt;

use crate::{
    domain::{EventId, SessionId, TimestampUtc},
    session::state::SessionState,
};

/// Represents an immutable audit trail event recording operational state, policy decisions,
/// and approval lifecycles for security auditability (S-09, DATA_MODEL.md).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// Unique identifier for this audit event.
    pub event_id: EventId,
    /// Associated session identifier.
    pub session_id: SessionId,
    /// Strictly monotonic sequence number within the session.
    pub sequence_number: u64,
    /// Accurate UTC timestamp when the event was recorded.
    pub timestamp_utc: TimestampUtc,
    /// Actor or component responsible for triggering the event.
    pub actor: String,
    /// Specific category and structured payload of the event.
    pub kind: AuditEventKind,
    /// Human-readable explanation or additional audit metadata.
    pub details: String,
}

impl AuditEvent {
    /// Creates a new immutable audit event.
    pub fn new(
        session_id: SessionId,
        sequence_number: u64,
        timestamp_utc: TimestampUtc,
        actor: impl Into<String>,
        kind: AuditEventKind,
        details: impl Into<String>,
    ) -> Self {
        Self {
            event_id: EventId::new(),
            session_id,
            sequence_number,
            timestamp_utc,
            actor: actor.into(),
            kind,
            details: details.into(),
        }
    }
}

/// The specific category and payload of an audit trail event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEventKind {
    /// Session was created.
    SessionCreated {
        /// Canonical workspace root path.
        workspace_root: String,
        /// Operating mode chosen for this session.
        operating_mode: String,
    },
    /// Session transitioned between lifecycle states.
    StateTransition {
        /// The previous session state.
        from: SessionState,
        /// The new session state.
        to: SessionState,
        /// Reason explaining the state transition.
        reason: String,
    },
    /// Project scope or file discovery completed.
    ScopeChanged {
        /// Canonical workspace root path.
        canonical_root: String,
        /// Number of discovered files within boundary.
        file_count: usize,
    },
    /// Policy engine evaluated an operation.
    PolicyEvaluated {
        /// Name of the operation action evaluated.
        action: String,
        /// Result of the evaluation (Granted, Denied, NeedsApproval).
        decision: String,
        /// Denial reason explanation if rejected.
        denial_reason: Option<String>,
    },
    /// A sensitive operation requested human approval.
    ApprovalRequested {
        /// Unique identifier for the approval request.
        request_id: String,
        /// Cryptographic digest of the action requiring approval.
        action_digest: String,
        /// Target code revision or commit hash.
        target_revision: String,
    },
    /// A human approval grant was submitted and accepted.
    ApprovalGranted {
        /// Unique identifier of the granted request.
        request_id: String,
        /// Actor who granted the approval.
        granted_by: String,
        /// Action digest verified by the grant.
        action_digest: String,
    },
    /// A human approval request was denied or revoked.
    ApprovalDenied {
        /// Unique identifier of the denied request.
        request_id: String,
        /// Actor who denied the request.
        actor: String,
        /// Explanation for the denial.
        reason: String,
    },
    /// The session was cancelled by operator request.
    SessionCancelled {
        /// Reason for cancellation.
        reason: String,
    },
    /// The session encountered a terminal failure.
    SessionFailed {
        /// Error message describing the terminal failure.
        error_message: String,
    },
}

impl fmt::Display for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] Seq:{} Session:{} Actor:{} Kind:{:?} Details:{}",
            self.timestamp_utc,
            self.sequence_number,
            self.session_id,
            self.actor,
            self.kind,
            self.details
        )
    }
}
