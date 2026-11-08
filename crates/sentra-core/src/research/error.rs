//! Typed errors for deep security research campaigns and role enforcement.

use std::fmt;

/// Specific category of research campaign or role violation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResearchErrorKind {
    /// Attempted action is not permitted for the assigned role.
    RoleCapabilityViolation {
        /// Role name that attempted the capability.
        role: String,
        /// Capability that was forbidden.
        capability: String,
    },
    /// Patch author attempted to independently verify or approve their own patch (REQ-S08).
    PatchAuthorCannotVerifySelf,
    /// Model-controlled roles attempted to approve peer work (Roadmap Phase 3 Anti-Collusion).
    PeerApprovalForbidden {
        /// Proposing role name.
        proposer_role: String,
        /// Approving role name.
        approver_role: String,
    },
    /// A duplicate hypothesis was proposed for an already investigated target.
    DuplicateHypothesis {
        /// Identifier of the existing duplicate hypothesis.
        existing_id: String,
        /// Canonical fingerprint string.
        fingerprint: String,
    },
    /// Child task spawning exceeded the maximum allowed research tree depth.
    MaxDepthExceeded {
        /// Attempted tree depth.
        current_depth: u32,
        /// Configured depth limit.
        max_depth: u32,
    },
    /// Concurrent task count exceeded the configured ceiling.
    ConcurrencyLimitExceeded {
        /// Active running task count.
        active_tasks: u32,
        /// Concurrency limit ceiling.
        limit: u32,
    },
    /// Total campaign budget exhausted or insufficient for requested reservation.
    BudgetExhausted {
        /// Requested budget in micro-USD.
        requested: u64,
        /// Available budget in micro-USD.
        available: u64,
    },
    /// Operation attempted on a campaign that is already stopped or completed.
    CampaignAlreadyFinished {
        /// Status string of the finished campaign.
        status: String,
    },
    /// Referenced research task identifier was not found.
    TaskNotFound {
        /// Missing task identifier.
        task_id: String,
    },
    /// Secret canary was detected in another task's context or output.
    SecretIsolationBreach {
        /// Canary token detected.
        canary: String,
    },
}

/// Strongly-typed error occurring during research campaigns or role validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchError {
    kind: ResearchErrorKind,
    message: String,
}

impl ResearchError {
    /// Creates a new research error.
    pub fn new(kind: ResearchErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Returns the specific error kind.
    pub fn kind(&self) -> &ResearchErrorKind {
        &self.kind
    }

    /// Helper for role capability violation.
    pub fn role_capability_violation(role: impl Into<String>, cap: impl Into<String>) -> Self {
        let r = role.into();
        let c = cap.into();
        Self::new(
            ResearchErrorKind::RoleCapabilityViolation {
                role: r.clone(),
                capability: c.clone(),
            },
            format!("Role '{r}' is not permitted to perform '{c}'"),
        )
    }

    /// Helper for patch author self-verification violation.
    pub fn patch_author_cannot_verify() -> Self {
        Self::new(
            ResearchErrorKind::PatchAuthorCannotVerifySelf,
            "Patch author is strictly forbidden from independently verifying or approving their own patch",
        )
    }

    /// Helper for peer approval anti-collusion violation.
    pub fn peer_approval_forbidden(
        proposer: impl Into<String>,
        approver: impl Into<String>,
    ) -> Self {
        let p = proposer.into();
        let a = approver.into();
        Self::new(
            ResearchErrorKind::PeerApprovalForbidden {
                proposer_role: p.clone(),
                approver_role: a.clone(),
            },
            format!("Role '{a}' cannot approve work proposed by peer role '{p}'"),
        )
    }

    /// Helper for duplicate hypothesis.
    pub fn duplicate_hypothesis(
        existing: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        let e = existing.into();
        let f = fingerprint.into();
        Self::new(
            ResearchErrorKind::DuplicateHypothesis {
                existing_id: e.clone(),
                fingerprint: f.clone(),
            },
            format!("Hypothesis matches existing hypothesis '{e}' (fingerprint: {f})"),
        )
    }

    /// Helper for max depth exceeded.
    pub fn max_depth_exceeded(current: u32, max: u32) -> Self {
        Self::new(
            ResearchErrorKind::MaxDepthExceeded {
                current_depth: current,
                max_depth: max,
            },
            format!("Task depth {current} exceeds maximum campaign depth limit {max}"),
        )
    }

    /// Helper for concurrency limit exceeded.
    pub fn concurrency_limit_exceeded(active: u32, limit: u32) -> Self {
        Self::new(
            ResearchErrorKind::ConcurrencyLimitExceeded {
                active_tasks: active,
                limit,
            },
            format!("Active task count {active} reached concurrency ceiling {limit}"),
        )
    }

    /// Helper for budget exhaustion.
    pub fn budget_exhausted(requested: u64, available: u64) -> Self {
        Self::new(
            ResearchErrorKind::BudgetExhausted {
                requested,
                available,
            },
            format!(
                "Requested budget {requested} micro-USD exceeds available {available} micro-USD"
            ),
        )
    }
}

impl fmt::Display for ResearchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ResearchError {}
