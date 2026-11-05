use std::fmt;

use crate::domain::classification::SecurityClassification;
use crate::policy::approval::ApprovalRequest;

/// The evaluated outcome of a policy authorization request.
#[derive(Clone, Debug, PartialEq)]
pub enum PolicyDecision {
    /// Operation is authorized to proceed.
    Granted,
    /// Operation is explicitly rejected.
    Denied {
        /// Typed denial reason detailing why the operation was rejected.
        reason: DenialReason,
    },
    /// Operation requires human approval before proceeding.
    NeedsApproval {
        /// Approval request object capturing action details and required grant parameters.
        request: ApprovalRequest,
    },
}

impl PolicyDecision {
    /// Returns true if the policy decision is `Granted`.
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted)
    }

    /// Returns true if the policy decision is `Denied`.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    /// Returns true if the policy decision is `NeedsApproval`.
    pub fn is_needs_approval(&self) -> bool {
        matches!(self, Self::NeedsApproval { .. })
    }
}

/// Explicit and auditable reasons for policy denial.
#[derive(Clone, Debug, PartialEq)]
pub enum DenialReason {
    /// Operation name is unknown or unsupported (Default-Deny).
    UnknownOperation(String),
    /// Session or actor lacks requisite authorization role.
    MissingAuthorization(String),
    /// Data classification exceeds destination or boundary allowance.
    ClassificationExceeded {
        /// The security classification level that was exceeded.
        classification: SecurityClassification,
        /// Detail explaining the classification violation.
        detail: String,
    },
    /// Action is sensitive and no human approval grant was provided.
    MissingApprovalGrant(String),
    /// Provided approval grant token or signature is invalid.
    InvalidApprovalGrant(String),
    /// Provided approval grant has expired.
    ExpiredApprovalGrant(String),
    /// Provided approval grant has already been used (replay prevention).
    ApprovalReused(String),
    /// Provided approval grant does not match action digest or target revision.
    ApprovalMismatched(String),
    /// Operation cost would exceed authorized auto-budget ceiling.
    BudgetExceeded {
        /// The requested USD amount.
        requested_usd: f64,
        /// The active policy limit in USD.
        limit_usd: f64,
    },
    /// Path escapes the authorized canonical workspace root.
    PathTraversalAttempt(String),
    /// Backend or runner does not provide the required capability.
    CapabilityUnavailable(String),
}

impl fmt::Display for DenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOperation(op) => write!(f, "unknown or unsupported operation: {op}"),
            Self::MissingAuthorization(msg) => write!(f, "missing authorization: {msg}"),
            Self::ClassificationExceeded {
                classification,
                detail,
            } => {
                write!(
                    f,
                    "classification limit exceeded for [{classification}]: {detail}"
                )
            }
            Self::MissingApprovalGrant(action) => {
                write!(
                    f,
                    "sensitive action '{action}' requires explicit human approval"
                )
            }
            Self::InvalidApprovalGrant(msg) => write!(f, "invalid approval grant: {msg}"),
            Self::ExpiredApprovalGrant(msg) => write!(f, "approval grant expired: {msg}"),
            Self::ApprovalReused(msg) => write!(
                f,
                "approval grant already consumed (replay prevented): {msg}"
            ),
            Self::ApprovalMismatched(msg) => {
                write!(f, "approval grant does not match action or revision: {msg}")
            }
            Self::BudgetExceeded {
                requested_usd,
                limit_usd,
            } => {
                write!(
                    f,
                    "budget exceeded: requested ${requested_usd:.2} exceeds limit ${limit_usd:.2}"
                )
            }
            Self::PathTraversalAttempt(path) => {
                write!(f, "path traversal attempt rejected: {path}")
            }
            Self::CapabilityUnavailable(cap) => {
                write!(f, "execution backend lacks required capability: {cap}")
            }
        }
    }
}
