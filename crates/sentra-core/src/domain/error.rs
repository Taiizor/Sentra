use std::fmt;

use crate::session::state::SessionState;

/// Errors arising across the Sentra Core Engine domain model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// Provided identifier string or byte sequence is malformed.
    InvalidIdentifier(String),
    /// Timestamp value or string representation is out of range or malformed.
    InvalidTimestamp(String),
    /// Session metadata contains empty, invalid, or conflicting values.
    InvalidMetadata(String),
    /// An illegal session state transition was attempted.
    InvalidTransition(SessionTransitionError),
    /// An operation violated security policy invariants.
    PolicyViolation(String),
    /// Human approval was rejected, mismatched, or expired.
    ApprovalRejected(String),
    /// An operation action payload was malformed.
    ActionMalformed(String),
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier(msg) => write!(f, "invalid identifier: {msg}"),
            Self::InvalidTimestamp(msg) => write!(f, "invalid timestamp: {msg}"),
            Self::InvalidMetadata(msg) => write!(f, "invalid metadata: {msg}"),
            Self::InvalidTransition(err) => write!(f, "invalid state transition: {err}"),
            Self::PolicyViolation(msg) => write!(f, "policy violation: {msg}"),
            Self::ApprovalRejected(msg) => write!(f, "approval rejected: {msg}"),
            Self::ActionMalformed(msg) => write!(f, "malformed action: {msg}"),
        }
    }
}

impl std::error::Error for DomainError {}

/// Typed error returned when an illegal session state transition is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTransitionError {
    /// The originating state of the session before the attempted transition.
    pub from: SessionState,
    /// The target state that was rejected by the state machine rules.
    pub attempted_to: SessionState,
}

impl fmt::Display for SessionTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "illegal session transition from {:?} to {:?}",
            self.from, self.attempted_to
        )
    }
}

impl std::error::Error for SessionTransitionError {}

impl From<SessionTransitionError> for DomainError {
    fn from(err: SessionTransitionError) -> Self {
        Self::InvalidTransition(err)
    }
}
