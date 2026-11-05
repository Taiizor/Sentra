use crate::domain::{SessionId, TimestampUtc, error::DomainError};
use crate::session::state::{AssessmentCompleteness, OperatingMode};

/// Metadata describing a Sentra research session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionMetadata {
    /// Unique session identifier.
    pub session_id: SessionId,
    /// UTC timestamp when the session was created.
    pub created_at_utc: TimestampUtc,
    /// Absolute or canonical path to the authorized project workspace root.
    pub workspace_root: String,
    /// The authorized research operating mode (ContinuousReview or DeepSecurityResearch).
    pub operating_mode: OperatingMode,
    /// Identity of the operator who created the session.
    pub operator_id: String,
    /// Cryptographic digest of the effective policy configuration applied to this session.
    pub policy_digest: String,
    /// Assessment completeness state separating operational completion from security coverage.
    pub completeness: AssessmentCompleteness,
}

impl SessionMetadata {
    /// Constructs and validates a new SessionMetadata record.
    pub fn new(
        session_id: SessionId,
        created_at_utc: TimestampUtc,
        workspace_root: impl Into<String>,
        operating_mode: OperatingMode,
        operator_id: impl Into<String>,
        policy_digest: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let ws_root = workspace_root.into();
        if ws_root.trim().is_empty() {
            return Err(DomainError::InvalidMetadata(
                "workspace_root cannot be empty".to_string(),
            ));
        }

        let op_id = operator_id.into();
        if op_id.trim().is_empty() {
            return Err(DomainError::InvalidMetadata(
                "operator_id cannot be empty".to_string(),
            ));
        }

        let p_digest = policy_digest.into();
        if p_digest.trim().is_empty() {
            return Err(DomainError::InvalidMetadata(
                "policy_digest cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            session_id,
            created_at_utc,
            workspace_root: ws_root,
            operating_mode,
            operator_id: op_id,
            policy_digest: p_digest,
            completeness: AssessmentCompleteness::Partial, // Default until terminal completion
        })
    }
}
